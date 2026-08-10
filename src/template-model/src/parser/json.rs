use crate::ir::*;
use crate::parser::builder::{Builder, TemplateSections};
use crate::parser::value::{ParseValue, ValueKind};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::str::from_utf8;

fn build_line_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut offsets = vec![0usize]; // line 1 starts at byte 0
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' {
            offsets.push(i + 1);
        }
    }
    offsets
}

fn offset_to_line_col(line_offsets: &[usize], offset: usize) -> (u32, u32) {
    let line_idx = line_offsets.binary_search(&offset).unwrap_or_else(|i| i.saturating_sub(1));
    let col = offset - line_offsets[line_idx] + 1;
    (line_idx as u32 + 1, col as u32)
}

/// A borrowed view over a `serde_json::Value` implementing the format-agnostic
/// [`ParseValue`] so the shared [`Builder`] can construct the IR.
#[derive(Clone, Copy)]
struct JsonValue<'a>(&'a serde_json::Value);

impl<'a> ParseValue for JsonValue<'a> {
    fn kind(&self) -> ValueKind {
        match self.0 {
            serde_json::Value::Null => ValueKind::Null,
            serde_json::Value::Bool(_) => ValueKind::Bool,
            serde_json::Value::Number(_) => ValueKind::Number,
            serde_json::Value::String(_) => ValueKind::String,
            serde_json::Value::Array(_) => ValueKind::Array,
            serde_json::Value::Object(_) => ValueKind::Object,
        }
    }

    fn as_coerced_str(&self) -> Option<String> {
        match self.0 {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            serde_json::Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<Vec<Self>> {
        self.0.as_array().map(|arr| arr.iter().map(JsonValue).collect())
    }

    fn as_object(&self) -> Option<Vec<(String, Self)>> {
        self.0.as_object().map(|map| map.iter().map(|(k, v)| (k.clone(), JsonValue(v))).collect())
    }

    fn as_integer(&self) -> Option<i64> {
        self.0.as_i64()
    }

    fn describe_scalar(&self) -> String {
        match self.0 {
            serde_json::Value::Null => "null".to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::String(s) => format!("'{}'", s),
            // Composites are handled by describe_value; unreachable for scalars.
            other => other.to_string(),
        }
    }

    fn scalar_node(&self) -> Node {
        match self.0 {
            serde_json::Value::Null => Node::Null,
            serde_json::Value::Bool(b) => Node::Bool(*b),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Node::Int(i)
                } else {
                    Node::Float(n.as_f64().unwrap_or(0.0))
                }
            }
            serde_json::Value::String(s) => Node::String(s.clone()),
            // Composites are built by Builder::build; unreachable for scalars.
            _ => Node::Null,
        }
    }
}

/// Records the span of a container (`{`/`[`) opening at `offset` when it is an
/// element of the enclosing array, keyed at the element's current indexed path.
/// A no-op when the enclosing context is an object (the element's key already
/// anchored it) or when there is no enclosing container. First writer wins, so a
/// nested container does not overwrite the outer element's own opening position.
fn record_array_element_span(
    line_offsets: &[usize],
    path_stack: &[String],
    in_array: &[bool],
    path_to_span: &mut HashMap<String, SourceSpan>,
    offset: usize,
) {
    if in_array.last() != Some(&true) {
        return;
    }
    let full_path = path_stack.iter().filter(|s| !s.is_empty()).cloned().collect::<Vec<_>>().join("/");
    if full_path.is_empty() {
        return;
    }
    let (line, col) = offset_to_line_col(line_offsets, offset);
    path_to_span.entry(full_path).or_insert(SourceSpan {
        start_line: line,
        start_column: col,
        end_line: line,
        end_column: col + 1,
    });
}

/// Walks the raw bytes once, assigning source spans to every path and
/// detecting duplicate object keys. Duplicates are diagnosed here - rather
/// than in a second walker - because this scan already tracks the full path of
/// every key, which anchors each duplicate at the entry it duplicates.
fn scan_json_byte_spans(
    _arena: &mut Arena,
    span_index: &mut SourceSpanIndex,
    bytes: &[u8],
    diagnostics: &mut Vec<ParseDefect>,
) {
    let line_offsets = build_line_offsets(bytes);
    let mut path_stack: Vec<String> = Vec::new();
    let mut path_to_span: HashMap<String, SourceSpan> = HashMap::new();
    let mut in_array: Vec<bool> = Vec::new();
    let mut array_idx: Vec<usize> = Vec::new();
    // Every key committed so far in each open object, with its first occurrence's
    // span and whether that occurrence has been diagnosed. A duplicated key is
    // flagged at *every* occurrence — the first duplicate retroactively flags the
    // original occurrence too, so a reader sees all the colliding definitions.
    let mut seen_keys: Vec<HashMap<String, (SourceSpan, bool)>> = Vec::new();

    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => {
                // A container that is itself an array element carries no key to anchor
                // it, so record its span at the opening brace - mirroring how a scalar
                // array element is recorded below. Without this a diagnostic on an
                // object element (e.g. an `Fn::If` branch) has no span of its own and
                // walks up to the enclosing array instead of the element.
                record_array_element_span(&line_offsets, &path_stack, &in_array, &mut path_to_span, i);
                in_array.push(false);
                array_idx.push(0);
                path_stack.push(String::new());
                seen_keys.push(HashMap::new());
                i += 1;
            }
            b'}' => {
                path_stack.pop();
                in_array.pop();
                array_idx.pop();
                seen_keys.pop();
                i += 1;
            }
            b'[' => {
                record_array_element_span(&line_offsets, &path_stack, &in_array, &mut path_to_span, i);
                in_array.push(true);
                array_idx.push(0);
                path_stack.push("0".to_string());
                i += 1;
            }
            b']' => {
                path_stack.pop();
                in_array.pop();
                array_idx.pop();
                i += 1;
            }
            b',' => {
                if let Some(true) = in_array.last()
                    && let Some(idx) = array_idx.last_mut()
                {
                    *idx += 1;
                    if let Some(top) = path_stack.last_mut() {
                        *top = idx.to_string();
                    }
                }
                i += 1;
            }
            b'"' => {
                let start = i;
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' {
                        i += 1;
                        if i >= bytes.len() {
                            break;
                        }
                    }
                    i += 1;
                }
                let end = i;
                i += 1;
                let mut j = i;
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == b':' {
                    let key = String::from_utf8_lossy(&bytes[start + 1..end]).to_string();
                    if let Some(top) = path_stack.last_mut() {
                        *top = key.clone();
                    }
                    let full_path = path_stack.iter().filter(|s| !s.is_empty()).cloned().collect::<Vec<_>>().join("/");
                    let (sl, sc) = offset_to_line_col(&line_offsets, start);
                    let (el, ec) = offset_to_line_col(&line_offsets, end);
                    // Key identity uses the decoded string so escaped and literal
                    // spellings collide exactly as serde_json deduplicates them.
                    let decoded = decode_json_key(&bytes[start..=end]);
                    let key_span = SourceSpan {
                        start_line: sl,
                        start_column: sc,
                        end_line: sl,
                        end_column: sc + (end - start) as u32,
                    };
                    if let Some(keys) = seen_keys.last_mut() {
                        match keys.get_mut(&decoded) {
                            // Duplicate: flag it at this occurrence, and — the first
                            // time — retroactively at the original occurrence too.
                            Some((first_span, emitted)) => {
                                if !*emitted {
                                    *emitted = true;
                                    diagnostics.push(crate::make_parse_defect_at(
                                        "F0000",
                                        format!("Duplicate key '{}'", decoded),
                                        *first_span,
                                        &full_path,
                                    ));
                                }
                                diagnostics.push(crate::make_parse_defect_at(
                                    "F0000",
                                    format!("Duplicate key '{}'", decoded),
                                    key_span,
                                    &full_path,
                                ));
                            }
                            None => {
                                keys.insert(decoded, (key_span, false));
                            }
                        }
                    }
                    path_to_span.insert(
                        full_path,
                        SourceSpan { start_line: sl, start_column: sc, end_line: el, end_column: ec },
                    );
                } else if let Some(true) = in_array.last() {
                    // Record spans for array string values to enable precise diagnostics
                    let full_path = path_stack.iter().filter(|s| !s.is_empty()).cloned().collect::<Vec<_>>().join("/");
                    if !full_path.is_empty() {
                        let (sl, sc) = offset_to_line_col(&line_offsets, start);
                        let (el, ec) = offset_to_line_col(&line_offsets, end);
                        path_to_span.entry(full_path).or_insert(SourceSpan {
                            start_line: sl,
                            start_column: sc,
                            end_line: el,
                            end_column: ec,
                        });
                    }
                }
            }
            _ => {
                i += 1;
            }
        }
    }

    for (path, span) in path_to_span {
        span_index.insert(path, span);
    }
}

/// Decode a JSON string token (including its surrounding double quotes) into the
/// string it represents, so that escaped and literal spellings of the same key
/// compare equal. The quoted byte range is itself valid JSON, so `serde_json`
/// performs exactly the same unescaping (`\uXXXX`, surrogate pairs, `\n`, `\"`,
/// `\\`, …) it applies when building the parsed object - the same key identity
/// CloudFormation sees. Falls back to a lossy view only if the token is not
/// decodable, which cannot happen once the full document has parsed successfully.
fn decode_json_key(quoted: &[u8]) -> String {
    from_utf8(quoted)
        .ok()
        .and_then(|s| serde_json::from_str::<String>(s).ok())
        .unwrap_or_else(|| String::from_utf8_lossy(quoted).to_string())
}

/// Pre-parse scan for duplicate keys in JSON. serde_json silently deduplicates,
/// so we must scan raw bytes before parsing.
pub fn parse_json(bytes: &[u8]) -> Result<TemplateIR, ParseError> {
    let text = from_utf8(bytes).map_err(|e| ParseError {
        message: format!("Invalid UTF-8: {}", e),
        line: None,
        column: None,
    })?;

    let value: serde_json::Value = serde_json::from_str(text).map_err(|e| ParseError {
        message: format!("JSON parse error: {}", e),
        line: Some(e.line() as u32),
        column: Some(e.column() as u32),
    })?;

    if !value.is_object() {
        return Err(ParseError {
            message: "Template root must be a JSON object".into(),
            line: Some(1),
            column: Some(1),
        });
    }

    let mut builder = Builder::new();
    let root = builder.build_map(&JsonValue(&value), "");

    let sections = TemplateSections::extract(&builder.arena, root);

    debug!(
        "JSON IR built: {} resources, {} parameters, {} mappings, {} conditions, {} outputs, {} span index entries",
        builder.arena.as_map(sections.resources).map(|m| m.len()).unwrap_or(0),
        builder.arena.as_map(sections.parameters).map(|m| m.len()).unwrap_or(0),
        builder.arena.as_map(sections.mappings).map(|m| m.len()).unwrap_or(0),
        builder.arena.as_map(sections.conditions).map(|m| m.len()).unwrap_or(0),
        builder.arena.as_map(sections.outputs).map(|m| m.len()).unwrap_or(0),
        builder.span_index.len()
    );
    if !builder.diagnostics.is_empty() {
        warn!("{} parse diagnostics from JSON (duplicate keys, malformed intrinsics)", builder.diagnostics.len());
    }

    for path in builder.global_index.keys() {
        builder.span_index.entry(path.clone()).or_insert(UNKNOWN_SPAN);
    }

    scan_json_byte_spans(&mut builder.arena, &mut builder.span_index, bytes, &mut builder.diagnostics);
    info!("JSON span assignment complete: {} entries", builder.span_index.len());

    Ok(sections.into_ir(builder))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_json_template() {
        let input = r#"{
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "MyBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": "my-bucket"
                    }
                }
            }
        }"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        assert_eq!(ir.format_version.as_deref(), Some("2010-09-09"));
        assert_ne!(ir.resources, NULL_REF);
        let res_map = ir.arena.as_map(ir.resources).unwrap();
        assert_eq!(res_map.len(), 1);
        assert_eq!(res_map[0].0, "MyBucket");
    }

    #[test]
    fn parse_all_intrinsic_forms() {
        let input = r#"{
            "Resources": {
                "R": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "A": {"Ref": "Param"},
                        "B": {"Fn::GetAtt": ["Res", "Attr"]},
                        "C": {"Fn::GetAtt": "Res.Attr"},
                        "D": {"Fn::Sub": "hello ${X}"},
                        "E": {"Fn::Sub": ["hello ${X}", {"X": "val"}]},
                        "F": {"Fn::Join": ["-", ["a", "b"]]},
                        "G": {"Fn::Select": [0, ["a", "b"]]},
                        "H": {"Fn::If": ["Cond", "yes", "no"]},
                        "I": {"Fn::FindInMap": ["Map", "K1", "K2"]},
                        "J": {"Fn::Base64": "data"},
                        "K": {"Fn::And": [{"Condition": "A"}, {"Condition": "B"}]},
                        "L": {"Fn::Or": [{"Condition": "A"}, {"Condition": "B"}]},
                        "M": {"Fn::Not": [{"Condition": "A"}]},
                        "N": {"Fn::Equals": ["a", "b"]}
                    }
                }
            }
        }"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        assert!(ir.arena.len() > 10);
    }

    #[test]
    fn parse_getatt_string_form() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"A":{"Fn::GetAtt":"MyResource.MyAttribute"}}}}}"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let props_ref = ir.arena.map_get(res[0].1, "Properties").unwrap();
        let a_ref = ir.arena.map_get(props_ref, "A").unwrap();
        match ir.arena.node(a_ref) {
            Node::Intrinsic(IntrinsicFn::GetAtt(r, a)) => {
                assert_eq!(r, "MyResource");
                assert_eq!(a, "MyAttribute");
            }
            other => panic!("Expected GetAtt, got {:?}", other),
        }
    }

    #[test]
    fn global_index_contains_expected_paths() {
        let input = r#"{"Resources":{"MyBucket":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":"test"}}}}"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        assert!(ir.global_index.contains_key("Resources/MyBucket/Properties/BucketName"));
    }

    /// A container-valued array element (an object/array, not a scalar) is anchored at
    /// its opening brace, so a diagnostic on an `Fn::If` branch object lands on that
    /// branch rather than walking up to the enclosing array. Scalar array elements are
    /// anchored likewise. Both are keyed with the element index.
    #[test]
    fn array_element_container_spans_are_recorded() {
        // Each token on its own line so line numbers are unambiguous.
        let input = concat!(
            "{\n",                               // 1
            "  \"Resources\": {\n",              // 2
            "    \"R\": {\n",                    // 3
            "      \"Type\": \"T\",\n",          // 4
            "      \"Properties\": {\n",         // 5
            "        \"Key\": {\n",              // 6
            "          \"Fn::If\": [\n",         // 7
            "            \"Cond\",\n",           // 8  (index 0, scalar)
            "            { \"Ref\": \"A\" },\n", // 9  (index 1, object)
            "            { \"Ref\": \"B\" }\n",  // 10 (index 2, object)
            "          ]\n",
            "        }\n",
            "      }\n",
            "    }\n",
            "  }\n",
            "}\n",
        );
        let ir = parse_json(input.as_bytes()).unwrap();
        let line = |path: &str| ir.span_index.get(path).map(|s| s.start_line);
        // Object-valued branch elements are anchored at their own `{`.
        assert_eq!(line("Resources/R/Properties/Key/Fn::If/1"), Some(9));
        assert_eq!(line("Resources/R/Properties/Key/Fn::If/2"), Some(10));
        // The scalar branch element is anchored too.
        assert_eq!(line("Resources/R/Properties/Key/Fn::If/0"), Some(8));
    }

    #[test]
    fn parse_get_stack_output_builds_intrinsic() {
        let input = r#"{"Resources":{"R":{"Type":"AWS::SNS::Topic","Properties":{"DisplayName":{"Fn::GetStackOutput":{"StackName":"s","OutputName":"o","Region":"us-east-1"}}}}}}"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let props_ref = ir.arena.map_get(res[0].1, "Properties").unwrap();
        let name_ref = ir.arena.map_get(props_ref, "DisplayName").unwrap();
        match ir.arena.node(name_ref) {
            Node::Intrinsic(IntrinsicFn::GetStackOutput(args)) => {
                let keys: Vec<&str> = args.iter().map(|(k, _)| k.as_str()).collect();
                assert_eq!(keys, ["StackName", "OutputName", "Region"]);
            }
            other => panic!("Expected GetStackOutput, got {:?}", other),
        }
        assert!(ir.diagnostics.iter().all(|d| d.rule_id != "E1033"), "well-formed call must not emit E1033");
    }

    #[test]
    fn parse_get_stack_output_missing_required_emits_e1033() {
        let input = r#"{"Resources":{"R":{"Type":"AWS::SNS::Topic","Properties":{"DisplayName":{"Fn::GetStackOutput":{"StackName":"s"}}}}}}"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        let e1033: Vec<&str> =
            ir.diagnostics.iter().filter(|d| d.rule_id == "E1033").map(|d| d.message.as_str()).collect();
        assert_eq!(e1033, ["'OutputName' is a required property"]);
    }

    #[test]
    fn parse_get_stack_output_additional_property_emits_e1033() {
        let input = r#"{"Resources":{"R":{"Type":"AWS::SNS::Topic","Properties":{"DisplayName":{"Fn::GetStackOutput":{"StackName":"s","OutputName":"o","Bad":"v"}}}}}}"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        let e1033: Vec<&str> =
            ir.diagnostics.iter().filter(|d| d.rule_id == "E1033").map(|d| d.message.as_str()).collect();
        assert_eq!(e1033, ["Additional properties are not allowed ('Bad' was unexpected)"]);
    }

    #[test]
    fn parse_get_stack_output_non_object_emits_e1033_and_falls_through() {
        let input = r#"{"Resources":{"R":{"Type":"AWS::SNS::Topic","Properties":{"DisplayName":{"Fn::GetStackOutput":"invalid"}}}}}"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        let e1033: Vec<&str> =
            ir.diagnostics.iter().filter(|d| d.rule_id == "E1033").map(|d| d.message.as_str()).collect();
        assert_eq!(e1033, ["'invalid' is not of type 'object'"]);
        // A malformed (non-object) argument cannot form the intrinsic, so the node
        // stays a plain map rather than becoming an IntrinsicFn::GetStackOutput.
        let res = ir.arena.as_map(ir.resources).unwrap();
        let props_ref = ir.arena.map_get(res[0].1, "Properties").unwrap();
        let name_ref = ir.arena.map_get(props_ref, "DisplayName").unwrap();
        assert!(matches!(ir.arena.node(name_ref), Node::Map(_)), "non-object arg should remain a plain map");
    }

    #[test]
    fn parse_get_stack_output_in_parameter_default_does_not_emit_e1033() {
        // CloudFormation never evaluates intrinsics in a parameter Default, so a
        // malformed call there is reported by the Default-must-be-a-string check
        // (E2001), not by the function's own argument validation.
        let input = r#"{"Parameters":{"P":{"Type":"String","Default":{"Fn::GetStackOutput":{"StackName":"s"}}}},"Resources":{"R":{"Type":"AWS::SNS::Topic","Properties":{"DisplayName":{"Ref":"P"}}}}}"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        assert!(
            ir.diagnostics.iter().all(|d| d.rule_id != "E1033"),
            "E1033 must not fire for a function used in a parameter Default"
        );
    }

    #[test]
    fn parse_get_stack_output_in_resource_metadata_emits_e1033() {
        // CloudFormation evaluates intrinsics in a resource's Metadata block too, so
        // a malformed call there is validated exactly as in Properties.
        let input = r#"{"Resources":{"R":{"Type":"AWS::SNS::Topic","Metadata":{"M":{"Fn::GetStackOutput":{"StackName":"s"}}}}}}"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        let e1033: Vec<&str> =
            ir.diagnostics.iter().filter(|d| d.rule_id == "E1033").map(|d| d.message.as_str()).collect();
        assert_eq!(e1033, ["'OutputName' is a required property"]);
    }

    #[test]
    fn parse_get_stack_output_nested_in_join_does_not_emit_e1033() {
        // Nested inside another function, the argument shape is the enclosing
        // function's concern; E1033 only fires at a direct property position.
        let input = r#"{"Resources":{"R":{"Type":"AWS::SNS::Topic","Properties":{"DisplayName":{"Fn::Join":["-",["x",{"Fn::GetStackOutput":{"StackName":"s"}}]]}}}}}"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        assert!(
            ir.diagnostics.iter().all(|d| d.rule_id != "E1033"),
            "E1033 must not fire for a call nested inside another function"
        );
    }

    #[test]
    fn parse_empty_resources() {
        let input = r#"{"Resources":{}}"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        assert_eq!(res.len(), 0);
    }

    #[test]
    fn parse_invalid_json() {
        let result = parse_json(b"not json at all");
        result.unwrap_err();
    }

    /// JSON object keys are preserved in source order (not alphabetized).
    #[test]
    fn json_object_key_order_preserved() {
        let input = r#"{"Resources":{"Zebra":{"Type":"AWS::S3::Bucket"},"Apple":{"Type":"AWS::S3::Bucket"},"Mango":{"Type":"AWS::S3::Bucket"}}}"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let names: Vec<&str> = res.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, vec!["Zebra", "Apple", "Mango"], "JSON keys must stay in source order");
    }

    /// A numeric Ref value is coerced to its string form (matching CloudFormation),
    /// not rejected with a type error.
    #[test]
    fn numeric_ref_value_is_coerced() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"A":{"Ref":123}}}}}"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let props = ir.arena.map_get(res[0].1, "Properties").unwrap();
        let a = ir.arena.map_get(props, "A").unwrap();
        match ir.arena.node(a) {
            Node::Intrinsic(IntrinsicFn::Ref(t)) => assert_eq!(t, "123"),
            other => panic!("Expected coerced Ref(\"123\"), got {:?}", other),
        }
        assert!(ir.diagnostics.iter().all(|d| d.rule_id != "F1101"), "numeric Ref must not raise F1101");
    }

    /// CDK-generated bootstrap-version assertion: `Fn::Not` wrapping
    /// `Fn::Contains` is the canonical pattern in every CDK-synthesized
    /// template's `Rules` block. Both intrinsics return boolean per the
    /// CloudFormation spec, so the parser must accept the nesting.
    #[test]
    fn fn_not_accepts_fn_contains_argument_no_f0014() {
        let input = r#"{
            "Parameters": {
                "BootstrapVersion": {"Type": "String"}
            },
            "Resources": {
                "B": {"Type": "AWS::S3::Bucket"}
            },
            "Rules": {
                "CheckBootstrapVersion": {
                    "Assertions": [{
                        "Assert": {
                            "Fn::Not": [{
                                "Fn::Contains": [
                                    ["1", "2", "3", "4", "5"],
                                    {"Ref": "BootstrapVersion"}
                                ]
                            }]
                        }
                    }]
                }
            }
        }"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        let shape_errors: Vec<_> = ir.diagnostics.iter().filter(|d| d.rule_id == "E8005").collect();
        assert!(shape_errors.is_empty(), "Expected no E8005 for Fn::Not(Fn::Contains), got: {:?}", shape_errors);
    }

    #[test]
    fn fn_and_accepts_rules_section_boolean_intrinsics_no_shape_error() {
        let input = r#"{
            "Resources": {"B": {"Type": "AWS::S3::Bucket"}},
            "Rules": {
                "R": {
                    "Assertions": [{
                        "Assert": {
                            "Fn::And": [
                                {"Fn::Contains": [["a"], {"Ref": "P"}]},
                                {"Fn::EachMemberEquals": [{"Ref": "P"}, "x"]},
                                {"Fn::EachMemberIn": [{"Ref": "P"}, {"Ref": "Q"}]}
                            ]
                        }
                    }]
                }
            }
        }"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        let shape_errors: Vec<_> = ir.diagnostics.iter().filter(|d| d.rule_id == "E8004").collect();
        assert!(
            shape_errors.is_empty(),
            "Expected no E8004 for Fn::And of rule-section booleans, got: {:?}",
            shape_errors
        );
    }

    #[test]
    fn fn_not_with_string_argument_produces_e8005() {
        let input = r#"{
            "Resources": {"B": {"Type": "AWS::S3::Bucket"}},
            "Conditions": {
                "Bad": {"Fn::Not": ["definitely-not-boolean"]}
            }
        }"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        assert!(
            ir.diagnostics.iter().any(|d| d.rule_id == "E8005"
                && d.message.contains("Fn::Not")
                && d.message.contains("is not of type 'boolean'")),
            "Expected E8005 for Fn::Not with string arg, got: {:?}",
            ir.diagnostics
        );
    }

    #[test]
    fn fn_not_with_non_boolean_intrinsic_produces_e8005() {
        let input = r#"{
            "Resources": {"B": {"Type": "AWS::S3::Bucket"}},
            "Conditions": {
                "Bad": {"Fn::Not": [{"Fn::Sub": "hello"}]}
            }
        }"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        assert!(
            ir.diagnostics.iter().any(|d| d.rule_id == "E8005" && d.message.contains("Fn::Not")),
            "Expected E8005 for Fn::Not wrapping Fn::Sub, got: {:?}",
            ir.diagnostics
        );
    }

    /// A literal duplicate string key is flagged at *both* occurrences — the
    /// original and the duplicate — the baseline the escaped-key case must match.
    #[test]
    fn literal_duplicate_string_key_flags_both_occurrences() {
        let input = r#"{"A":1,"A":2}"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        let f0000: Vec<(&str, u32)> = ir
            .diagnostics
            .iter()
            .filter(|d| d.rule_id == "F0000")
            .map(|d| (d.message.as_str(), d.span.start_column))
            .collect();
        assert_eq!(f0000, [("Duplicate key 'A'", 2), ("Duplicate key 'A'", 8)]);
    }

    /// The `A` escape decodes to `A`, so an escaped key and its literal
    /// twin are the same key and must collide exactly like the literal
    /// duplicate above, flagged at both occurrences.
    #[test]
    fn escaped_duplicate_string_key_flags_both_occurrences() {
        let input = r#"{"\u0041":1,"A":2}"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        let f0000: Vec<&str> =
            ir.diagnostics.iter().filter(|d| d.rule_id == "F0000").map(|d| d.message.as_str()).collect();
        assert_eq!(f0000, ["Duplicate key 'A'", "Duplicate key 'A'"]);
    }

    /// Distinct keys that merely contain escape sequences must NOT be flagged as
    /// duplicates - decoding must not collapse genuinely different keys.
    #[test]
    fn escaped_distinct_string_keys_emit_no_f0000() {
        let input = r#"{"\u0041":1,"\u0042":2}"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        assert!(
            ir.diagnostics.iter().all(|d| d.rule_id != "F0000"),
            "distinct escaped keys (A vs B) must not be treated as duplicates"
        );
    }

    #[test]
    fn unknown_fn_prefix_far_from_any_function_is_data_not_w1103() {
        // `Fn::Bogus` is not a near-miss of any real function, so it is treated
        // as a data key: no parse warning - the schema validator reports the
        // type mismatch where one exists.
        let input =
            r#"{"Resources":{"R":{"Type":"AWS::SNS::Topic","Properties":{"TopicName":{"Fn::Bogus":"hello"}}}}}"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        assert!(
            ir.diagnostics.iter().all(|d| d.rule_id != "W1103"),
            "far-from-any-function keys are data: {:?}",
            ir.diagnostics.iter().filter(|d| d.rule_id == "W1103").collect::<Vec<_>>()
        );
    }

    #[test]
    fn unknown_fn_typo_emits_w1103() {
        let input =
            r#"{"Resources":{"R":{"Type":"AWS::SNS::Topic","Properties":{"TopicName":{"Fn::GetAttt":["R","Arn"]}}}}}"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        let w1103: Vec<&str> =
            ir.diagnostics.iter().filter(|d| d.rule_id == "W1103").map(|d| d.message.as_str()).collect();
        assert_eq!(w1103, ["'Fn::GetAttt' is not a supported function - did you mean 'Fn::GetAtt'?"]);
    }

    #[test]
    fn fn_foreach_iterator_key_does_not_emit_w1103() {
        let input =
            r#"{"Resources":{"Fn::ForEach::Buckets":[["Id",["a","b"],{"Bucket${Id}":{"Type":"AWS::S3::Bucket"}}]]}}"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        assert!(
            ir.diagnostics.iter().all(|d| d.rule_id != "W1103"),
            "Fn::ForEach::<id> must not trigger W1103, got: {:?}",
            ir.diagnostics.iter().filter(|d| d.rule_id == "W1103").collect::<Vec<_>>()
        );
    }

    #[test]
    fn non_fn_prefix_single_key_object_does_not_emit_w1103() {
        // A single-key object whose key doesn't start with "Fn::" is a normal map
        // (e.g. a tag value), not an intrinsic attempt - must not trigger W1103.
        let input = r#"{"Resources":{"R":{"Type":"AWS::SNS::Topic","Properties":{"TopicName":{"NotAnFn":"val"}}}}}"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        assert!(ir.diagnostics.iter().all(|d| d.rule_id != "W1103"), "Non-Fn:: single-key map must not trigger W1103");
    }

    /// Both front-ends funnel through the shared shape validation, so a JSON
    /// template reports the same section shape defects as its YAML equivalent.
    #[test]
    fn section_shape_defects_match_across_formats() {
        let json_input = r#"{
            "Description": {"bad": true},
            "Transform": {"Name": "AWS::Include", "Parameters": {"Location": "s3://b/k.yaml"}},
            "Conditions": [],
            "Resources": {"R": {"Type": "AWS::S3::Bucket"}}
        }"#;
        let ir = parse_json(json_input.as_bytes()).unwrap();
        let messages = |rule_id: &str| -> Vec<String> {
            ir.diagnostics.iter().filter(|d| d.rule_id == rule_id).map(|d| d.message.clone()).collect()
        };
        assert_eq!(ir.transforms, ["AWS::Include"], "object-form transform contributes its Name");
        assert_eq!(messages("F1004"), ["Description must be a string, got an object"]);
        assert_eq!(messages("E8001"), ["Conditions section must be an object, got a list"]);
        assert_eq!(messages("E1005"), Vec::<String>::new(), "a well-formed transform object is not a defect");
    }
}
