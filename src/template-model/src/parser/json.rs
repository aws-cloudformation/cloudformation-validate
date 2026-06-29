use crate::ir::*;
use crate::parser::builder::{Builder, TemplateSections};
use crate::parser::value::{ParseValue, ValueKind};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
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

fn scan_json_byte_spans(_arena: &mut Arena, span_index: &mut SourceSpanIndex, bytes: &[u8]) {
    let line_offsets = build_line_offsets(bytes);
    let mut path_stack: Vec<String> = Vec::new();
    let mut path_to_span: HashMap<String, SourceSpan> = HashMap::new();
    let mut in_array: Vec<bool> = Vec::new();
    let mut array_idx: Vec<usize> = Vec::new();

    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => {
                in_array.push(false);
                array_idx.push(0);
                path_stack.push(String::new());
                i += 1;
            }
            b'}' => {
                path_stack.pop();
                in_array.pop();
                array_idx.pop();
                i += 1;
            }
            b'[' => {
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

/// Pre-parse scan for duplicate keys in JSON. serde_json silently deduplicates,
/// so we must scan raw bytes before parsing.
fn detect_duplicate_keys(bytes: &[u8]) -> Vec<diagnostics::Diagnostic> {
    let line_offsets = build_line_offsets(bytes);
    let mut diagnostics = Vec::new();
    let mut key_stacks: Vec<HashMap<String, usize>> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => {
                key_stacks.push(HashMap::new());
                i += 1;
            }
            b'}' => {
                key_stacks.pop();
                i += 1;
            }
            b'[' | b']' | b',' | b':' => {
                i += 1;
            }
            b'"' => {
                let start = i;
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i += 1;
                        if i >= bytes.len() {
                            break;
                        }
                    } else if bytes[i] == b'"' {
                        break;
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
                    if let Some(current) = key_stacks.last_mut() {
                        match current.entry(key) {
                            Entry::Occupied(occupied) => {
                                let (sl, sc) = offset_to_line_col(&line_offsets, start);
                                diagnostics.push(crate::make_parse_diagnostic(
                                    "F0000",
                                    format!("Duplicate key '{}'", occupied.key()),
                                    SourceSpan {
                                        start_line: sl,
                                        start_column: sc,
                                        end_line: sl,
                                        end_column: sc + (end - start) as u32,
                                    },
                                ));
                            }
                            Entry::Vacant(vacant) => {
                                vacant.insert(start);
                            }
                        }
                    }
                }
            }
            _ => {
                i += 1;
            }
        }
    }
    diagnostics
}

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
    builder.diagnostics = detect_duplicate_keys(bytes);
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

    scan_json_byte_spans(&mut builder.arena, &mut builder.span_index, bytes);
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
        let f0014: Vec<_> = ir.diagnostics.iter().filter(|d| d.rule_id == "F0014").collect();
        assert!(f0014.is_empty(), "Expected no F0014 for Fn::Not(Fn::Contains), got: {:?}", f0014);
    }

    #[test]
    fn fn_and_accepts_rules_section_boolean_intrinsics_no_f0014() {
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
        let f0014: Vec<_> = ir.diagnostics.iter().filter(|d| d.rule_id == "F0014").collect();
        assert!(f0014.is_empty(), "Expected no F0014 for Fn::And of rule-section booleans, got: {:?}", f0014);
    }

    /// Genuinely-invalid input is still rejected — bare strings and
    /// non-boolean-producing intrinsics like Fn::Sub remain a condition-function
    /// error.
    #[test]
    fn fn_not_with_string_argument_still_produces_f0014() {
        let input = r#"{
            "Resources": {"B": {"Type": "AWS::S3::Bucket"}},
            "Conditions": {
                "Bad": {"Fn::Not": ["definitely-not-boolean"]}
            }
        }"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        assert!(
            ir.diagnostics.iter().any(|d| d.rule_id == "F0014"
                && d.message.contains("Fn::Not")
                && d.message.contains("is not of type 'boolean'")),
            "Expected F0014 for Fn::Not with string arg, got: {:?}",
            ir.diagnostics
        );
    }

    #[test]
    fn fn_not_with_non_boolean_intrinsic_still_produces_f0014() {
        let input = r#"{
            "Resources": {"B": {"Type": "AWS::S3::Bucket"}},
            "Conditions": {
                "Bad": {"Fn::Not": [{"Fn::Sub": "hello"}]}
            }
        }"#;
        let ir = parse_json(input.as_bytes()).unwrap();
        assert!(
            ir.diagnostics.iter().any(|d| d.rule_id == "F0014" && d.message.contains("Fn::Not")),
            "Expected F0014 for Fn::Not wrapping Fn::Sub, got: {:?}",
            ir.diagnostics
        );
    }
}
