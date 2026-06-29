use crate::consts::*;
use crate::ir::*;
use crate::parser::builder::{Builder, TemplateSections};
use crate::parser::value::{ParseValue, ValueKind};
use log::{debug, info, warn};
use std::collections::{BTreeMap, HashMap};
use std::mem;
use std::str::from_utf8;
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser, Tag};
use yaml_rust2::scanner::Marker;
use yaml_rust2::yaml::{Hash, Yaml};

/// Output of the YAML event-stream load: the document tree, source spans for each
/// path, and any duplicate-key diagnostics found during the load.
struct LoadedYaml {
    docs: Vec<Yaml>,
    span_map: HashMap<String, (u32, u32)>,
    dup_key_diagnostics: Vec<diagnostics::Diagnostic>,
}

/// Converts YAML shorthand tags (!Ref, !Sub, etc.) into map-form intrinsics.
struct CfnYamlLoader {
    docs: Vec<Yaml>,
    doc_stack: Vec<(Yaml, usize)>,
    key_stack: Vec<Yaml>,
    anchor_map: BTreeMap<usize, Yaml>,
    /// Stack of tags to apply when sequences/mappings complete.
    /// Each entry is (tag_name, stack_depth_when_set).
    /// A stack is needed because nested tags (e.g. `!Or [!Equals [...]]`)
    /// would otherwise overwrite the outer tag.
    pending_tags: Vec<(String, usize)>,
    path_stack: Vec<String>,
    array_idx_stack: Vec<usize>,
    span_map: HashMap<String, (u32, u32)>,
    /// Source position of the key currently awaiting its value, one entry per open
    /// mapping (parallel to `key_stack`). Used to anchor duplicate-key diagnostics.
    key_marks: Vec<Option<(u32, u32)>>,
    /// `yaml_rust2` silently keeps the last value for a duplicate key, so duplicates
    /// are detected here at load time — matching how the JSON front-end pre-scans for
    /// them. One diagnostic per occurrence after the first, like the JSON path.
    dup_key_diagnostics: Vec<diagnostics::Diagnostic>,
}

impl CfnYamlLoader {
    fn new() -> Self {
        Self {
            docs: Vec::new(),
            doc_stack: Vec::new(),
            key_stack: Vec::new(),
            anchor_map: BTreeMap::new(),
            pending_tags: Vec::new(),
            path_stack: Vec::new(),
            array_idx_stack: Vec::new(),
            span_map: HashMap::new(),
            key_marks: Vec::new(),
            dup_key_diagnostics: Vec::new(),
        }
    }

    fn load(text: &str) -> Result<LoadedYaml, String> {
        let mut loader = Self::new();
        let mut parser = Parser::new_from_str(text);
        parser.load(&mut loader, true).map_err(|e| format!("{}", e))?;
        Ok(LoadedYaml { docs: loader.docs, span_map: loader.span_map, dup_key_diagnostics: loader.dup_key_diagnostics })
    }

    fn current_path(&self) -> String {
        self.path_stack.join("/")
    }

    /// Maps a `!`-handle YAML tag to the bare intrinsic name it denotes, or `None`
    /// for tags that are not CloudFormation intrinsics.
    fn cfn_tag_name(tag: &Option<Tag>) -> Option<String> {
        let tag = tag.as_ref()?;
        if tag.handle != "!" {
            return None;
        }
        SHORT_TAG_TO_FN_KEY.iter().find(|(short, _)| *short == tag.suffix).map(|_| tag.suffix.clone())
    }

    /// Wraps `value` in the single-key mapping `{ Fn::X: value }` that the shared
    /// builder recognizes, given the bare intrinsic name from a `!Tag`.
    fn wrap_with_tag(tag_name: &str, value: Yaml) -> Yaml {
        let Some((_, fn_key)) = SHORT_TAG_TO_FN_KEY.iter().find(|(short, _)| *short == tag_name) else {
            return value;
        };
        let mut hash = Hash::new();
        hash.insert(Yaml::String(fn_key.to_string()), value);
        Yaml::Hash(hash)
    }

    fn insert_new_node(&mut self, node: (Yaml, usize), _mark: Marker) {
        let (mut node_val, aid) = node;
        if let Some((_, depth)) = self.pending_tags.last()
            && self.doc_stack.len() == *depth
        {
            let (tag_name, _) = self.pending_tags.pop().unwrap();
            let wrapped = Self::wrap_with_tag(&tag_name, node_val);
            node_val = wrapped;
        }

        if aid > 0 {
            self.anchor_map.insert(aid, node_val.clone());
        }

        if self.doc_stack.is_empty() {
            self.doc_stack.push((node_val, 0));
            return;
        }

        let parent = self.doc_stack.last_mut().unwrap();
        match parent.0 {
            Yaml::Array(ref mut v) => v.push(node_val),
            Yaml::Hash(ref mut h) => {
                let cur_key = self.key_stack.last_mut().unwrap();
                if cur_key == &Yaml::BadValue {
                    *cur_key = node_val;
                } else {
                    let key = mem::replace(cur_key, Yaml::BadValue);
                    let key_mark = self.key_marks.last_mut().and_then(|m| m.take());
                    // A returned old value means this key already existed: yaml_rust2
                    // would silently overwrite it, so flag the duplicate (one per
                    // occurrence after the first, like the JSON pre-scan).
                    if h.insert(key.clone(), node_val).is_some()
                        && let Some(name) = yaml_key_as_string(&key)
                    {
                        let span = key_mark
                            .map(|(line, col)| SourceSpan {
                                start_line: line,
                                start_column: col,
                                end_line: line,
                                end_column: col + name.len() as u32,
                            })
                            .unwrap_or(UNKNOWN_SPAN);
                        self.dup_key_diagnostics.push(crate::make_parse_diagnostic(
                            "F0000",
                            format!("Duplicate key '{}'", name),
                            span,
                        ));
                    }
                }
            }
            _ => unreachable!(),
        }
    }
}

impl MarkedEventReceiver for CfnYamlLoader {
    fn on_event(&mut self, ev: Event, mark: Marker) {
        match ev {
            Event::DocumentStart | Event::Nothing | Event::StreamStart | Event::StreamEnd => {}
            Event::DocumentEnd => match self.doc_stack.len() {
                0 => self.docs.push(Yaml::BadValue),
                1 => self.docs.push(self.doc_stack.pop().unwrap().0),
                _ => {}
            },
            Event::SequenceStart(aid, ref tag) => {
                if let Some(tag_name) = Self::cfn_tag_name(tag) {
                    self.pending_tags.push((tag_name, self.doc_stack.len()));
                }
                self.doc_stack.push((Yaml::Array(Vec::new()), aid));
                self.array_idx_stack.push(0);
            }
            Event::SequenceEnd => {
                self.array_idx_stack.pop();
                let node = self.doc_stack.pop().unwrap();
                self.insert_new_node(node, mark);
            }
            Event::MappingStart(aid, ref tag) => {
                if let Some(tag_name) = Self::cfn_tag_name(tag) {
                    self.pending_tags.push((tag_name, self.doc_stack.len()));
                }
                self.doc_stack.push((Yaml::Hash(Hash::new()), aid));
                self.key_stack.push(Yaml::BadValue);
                self.key_marks.push(None);
            }
            Event::MappingEnd => {
                self.key_stack.pop();
                self.key_marks.pop();
                if !self.path_stack.is_empty() {
                    let parent_is_array =
                        self.doc_stack.last().map(|(y, _)| matches!(y, Yaml::Array(_))).unwrap_or(false);
                    if !parent_is_array {
                        self.path_stack.pop();
                    }
                }
                let node = self.doc_stack.pop().unwrap();
                self.insert_new_node(node, mark);
            }
            Event::Scalar(v, style, aid, ref tag) => {
                let cfn_tag = Self::cfn_tag_name(tag);
                let node = if style != yaml_rust2::scanner::TScalarStyle::Plain {
                    Yaml::String(v.clone())
                } else {
                    Yaml::from_str(&v)
                };

                if let Some(parent) = self.doc_stack.last() {
                    if matches!(parent.0, Yaml::Hash(_)) {
                        let cur_key = self.key_stack.last().unwrap();
                        if cur_key == &Yaml::BadValue {
                            let mapping_depth = self.key_stack.len();
                            if self.path_stack.len() >= mapping_depth {
                                self.path_stack.truncate(mapping_depth - 1);
                            }
                            self.path_stack.push(v.clone());
                            let path = self.current_path();
                            // mark.line() and mark.col() are 0-based
                            self.span_map.insert(path, (mark.line() as u32 + 1, mark.col() as u32 + 1));
                            // Remember this key's position so a later duplicate of it
                            // can be anchored at the offending occurrence.
                            if let Some(slot) = self.key_marks.last_mut() {
                                *slot = Some((mark.line() as u32 + 1, mark.col() as u32 + 1));
                            }
                        }
                    } else if matches!(parent.0, Yaml::Array(_))
                        && let Some(idx) = self.array_idx_stack.last_mut()
                    {
                        *idx += 1;
                    }
                }

                if let Some(tag_name) = cfn_tag {
                    let wrapped = Self::wrap_with_tag(&tag_name, node);
                    self.insert_new_node((wrapped, aid), mark);
                } else {
                    self.insert_new_node((node, aid), mark);
                }
            }
            Event::Alias(id) => {
                let n = self.anchor_map.get(&id).cloned().unwrap_or(Yaml::BadValue);
                self.insert_new_node((n, 0), mark);
            }
        }
    }
}

/// A borrowed view over a `yaml_rust2::Yaml` implementing the format-agnostic
/// [`ParseValue`] so the shared [`Builder`] can construct the IR.
///
/// A YAML mapping key may be a non-string scalar; such entries are dropped by
/// [`ParseValue::as_object`] since CloudFormation section/property keys are strings.
#[derive(Clone, Copy)]
struct YamlValue<'a>(&'a Yaml);

impl<'a> ParseValue for YamlValue<'a> {
    fn kind(&self) -> ValueKind {
        match self.0 {
            Yaml::Null | Yaml::BadValue => ValueKind::Null,
            Yaml::Boolean(_) => ValueKind::Bool,
            Yaml::Integer(_) | Yaml::Real(_) => ValueKind::Number,
            Yaml::String(_) => ValueKind::String,
            Yaml::Array(_) => ValueKind::Array,
            Yaml::Hash(_) => ValueKind::Object,
            // Aliases are resolved to their anchored value at load time, so a
            // surviving Alias is a dangling reference; treat as null.
            Yaml::Alias(_) => ValueKind::Null,
        }
    }

    fn as_coerced_str(&self) -> Option<String> {
        match self.0 {
            Yaml::String(s) => Some(s.clone()),
            Yaml::Integer(i) => Some(i.to_string()),
            Yaml::Real(s) => Some(s.clone()),
            Yaml::Boolean(b) => Some(b.to_string()),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<Vec<Self>> {
        self.0.as_vec().map(|arr| arr.iter().map(YamlValue).collect())
    }

    fn as_object(&self) -> Option<Vec<(String, Self)>> {
        self.0
            .as_hash()
            .map(|hash| hash.iter().filter_map(|(k, v)| yaml_key_as_string(k).map(|ks| (ks, YamlValue(v)))).collect())
    }

    fn as_integer(&self) -> Option<i64> {
        match self.0 {
            Yaml::Integer(i) => Some(*i),
            _ => None,
        }
    }

    fn describe_scalar(&self) -> String {
        match self.0 {
            Yaml::Null | Yaml::BadValue => "null".to_string(),
            Yaml::Boolean(b) => b.to_string(),
            Yaml::Integer(i) => i.to_string(),
            Yaml::Real(r) => r.clone(),
            Yaml::String(s) => format!("'{}'", s),
            Yaml::Alias(_) => "null".to_string(),
            // Composites are handled by describe_value; unreachable for scalars.
            Yaml::Array(_) | Yaml::Hash(_) => String::new(),
        }
    }

    fn scalar_node(&self) -> Node {
        match self.0 {
            Yaml::Null | Yaml::BadValue | Yaml::Alias(_) => Node::Null,
            Yaml::Boolean(b) => Node::Bool(*b),
            Yaml::Integer(i) => Node::Int(*i),
            Yaml::Real(s) => Node::Float(s.parse().unwrap_or(0.0)),
            Yaml::String(s) => Node::String(s.clone()),
            // Composites are built by Builder::build; unreachable for scalars.
            Yaml::Array(_) | Yaml::Hash(_) => Node::Null,
        }
    }
}

/// A mapping key coerced to its string form (CloudFormation keys are strings, but
/// YAML permits integer/bool scalar keys).
fn yaml_key_as_string(y: &Yaml) -> Option<String> {
    match y {
        Yaml::String(s) => Some(s.clone()),
        Yaml::Integer(i) => Some(i.to_string()),
        Yaml::Real(s) => Some(s.clone()),
        Yaml::Boolean(b) => Some(b.to_string()),
        _ => None,
    }
}

pub fn parse_yaml(bytes: &[u8]) -> Result<TemplateIR, ParseError> {
    let text = from_utf8(bytes).map_err(|e| ParseError {
        message: format!("Invalid UTF-8: {}", e),
        line: None,
        column: None,
    })?;

    let LoadedYaml { docs, span_map: raw_spans, dup_key_diagnostics } = CfnYamlLoader::load(text)
        .map_err(|e| ParseError { message: format!("YAML parse error: {}", e), line: None, column: None })?;

    if docs.is_empty() {
        return Err(ParseError { message: "Empty YAML document".into(), line: Some(1), column: Some(1) });
    }

    if docs[0].as_hash().is_none() {
        return Err(ParseError {
            message: "Template root must be a YAML mapping".into(),
            line: Some(1),
            column: Some(1),
        });
    }

    let mut builder = Builder::new();
    builder.diagnostics = dup_key_diagnostics;
    let root = builder.build_map(&YamlValue(&docs[0]), "");

    let sections = TemplateSections::extract(&builder.arena, root);

    for (path, (line, col)) in &raw_spans {
        builder.span_index.insert(
            path.clone(),
            SourceSpan {
                start_line: *line,
                start_column: *col,
                end_line: *line,
                end_column: *col + path.rsplit('/').next().unwrap_or(path).len() as u32,
            },
        );
    }
    info!("YAML span assignment complete: {} entries from marker tracking", builder.span_index.len());

    debug!(
        "YAML IR built: {} resources, {} parameters, {} mappings, {} conditions, {} outputs, {} span entries",
        builder.arena.as_map(sections.resources).map(|m| m.len()).unwrap_or(0),
        builder.arena.as_map(sections.parameters).map(|m| m.len()).unwrap_or(0),
        builder.arena.as_map(sections.mappings).map(|m| m.len()).unwrap_or(0),
        builder.arena.as_map(sections.conditions).map(|m| m.len()).unwrap_or(0),
        builder.arena.as_map(sections.outputs).map(|m| m.len()).unwrap_or(0),
        builder.span_index.len()
    );
    if !builder.diagnostics.is_empty() {
        warn!("{} parse diagnostics from YAML (malformed intrinsics)", builder.diagnostics.len());
    }

    Ok(sections.into_ir(builder))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_yaml() {
        let input = "AWSTemplateFormatVersion: \"2010-09-09\"\nResources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: my-bucket\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        assert_eq!(ir.format_version.as_deref(), Some("2010-09-09"));
        assert_eq!(ir.arena.as_map(ir.resources).unwrap().len(), 1);
    }

    #[test]
    fn parse_tag_form_ref() {
        let input = "Resources:\n  R:\n    Type: T\n    Properties:\n      VpcId: !Ref myVpcId\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let props = ir.arena.map_get(res[0].1, "Properties").unwrap();
        let v = ir.arena.map_get(props, "VpcId").unwrap();
        match ir.arena.node(v) {
            Node::Intrinsic(IntrinsicFn::Ref(t)) => assert_eq!(t, "myVpcId"),
            o => panic!("Expected Ref, got {:?}", o),
        }
    }

    #[test]
    fn parse_tag_form_getatt() {
        let input = "Resources:\n  R:\n    Type: T\n    Properties:\n      Role: !GetAtt LambdaRole.Arn\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let props = ir.arena.map_get(res[0].1, "Properties").unwrap();
        let v = ir.arena.map_get(props, "Role").unwrap();
        match ir.arena.node(v) {
            Node::Intrinsic(IntrinsicFn::GetAtt(r, a)) => {
                assert_eq!(r, "LambdaRole");
                assert_eq!(a, "Arn");
            }
            o => panic!("Expected GetAtt, got {:?}", o),
        }
    }

    #[test]
    fn parse_if_intrinsic() {
        let input = "Resources:\n  R:\n    Type: T\n    Properties:\n      Val:\n        Fn::If:\n          - IsProd\n          - prod\n          - dev\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let props = ir.arena.map_get(res[0].1, "Properties").unwrap();
        let v = ir.arena.map_get(props, "Val").unwrap();
        match ir.arena.node(v) {
            Node::Intrinsic(IntrinsicFn::If(c, _, _)) => assert_eq!(c, "IsProd"),
            o => panic!("Expected If, got {:?}", o),
        }
    }

    #[test]
    fn parse_invalid_yaml() {
        parse_yaml(b"{{invalid").unwrap_err();
    }

    #[test]
    fn yaml_json_equivalence() {
        let y = parse_yaml(b"Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: test\n")
            .unwrap();
        let j = super::super::json::parse_json(
            br#"{"Resources":{"B":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":"test"}}}}"#,
        )
        .unwrap();
        assert_eq!(y.arena.as_map(y.resources).unwrap().len(), j.arena.as_map(j.resources).unwrap().len());
    }

    #[test]
    fn parse_inline_ref_in_flow_sequence() {
        let input = "Conditions:\n  C:\n    Fn::Equals: [!Ref Env, Prod]\nResources:\n  R:\n    Type: T\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let conds = ir.arena.as_map(ir.conditions).unwrap();
        match ir.arena.node(conds[0].1) {
            Node::Intrinsic(IntrinsicFn::Equals(a, _)) => match ir.arena.node(*a) {
                Node::Intrinsic(IntrinsicFn::Ref(t)) => assert_eq!(t, "Env"),
                o => panic!("Expected Ref, got {:?}", o),
            },
            o => panic!("Expected Equals, got {:?}", o),
        }
    }

    #[test]
    fn parse_sub_block_scalar() {
        let input = "Resources:\n  R:\n    Type: T\n    Properties:\n      UserData: !Sub |\n        yum install pkg\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let props = ir.arena.map_get(res[0].1, "Properties").unwrap();
        let v = ir.arena.map_get(props, "UserData").unwrap();
        match ir.arena.node(v) {
            Node::Intrinsic(IntrinsicFn::Sub(t, _)) => assert!(t.contains("yum")),
            o => panic!("Expected Sub, got {:?}", o),
        }
    }

    /// YAML object keys are preserved in source order, matching the JSON parser.
    #[test]
    fn yaml_object_key_order_preserved() {
        let input = "Resources:\n  Zebra:\n    Type: AWS::S3::Bucket\n  Apple:\n    Type: AWS::S3::Bucket\n  Mango:\n    Type: AWS::S3::Bucket\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let names: Vec<&str> = res.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, vec!["Zebra", "Apple", "Mango"]);
    }

    /// Full-form `Fn::Not: [{Fn::Contains: ...}]` in YAML must not produce
    /// a type error — `Fn::Contains` is a boolean-producing Rules-section
    /// intrinsic, not a non-boolean expression.
    #[test]
    fn fn_not_accepts_fn_contains_argument_no_f0014() {
        let input = "Parameters:\n  BootstrapVersion:\n    Type: String\nResources:\n  B:\n    Type: AWS::S3::Bucket\nRules:\n  CheckBootstrapVersion:\n    Assertions:\n      - Assert:\n          Fn::Not:\n            - Fn::Contains:\n                - [\"1\", \"2\", \"3\", \"4\", \"5\"]\n                - Ref: BootstrapVersion\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let f0014: Vec<_> = ir.diagnostics.iter().filter(|d| d.rule_id == "F0014").collect();
        assert!(f0014.is_empty(), "Expected no F0014 for Fn::Not(Fn::Contains), got: {:?}", f0014);
    }

    #[test]
    fn fn_not_with_string_argument_still_produces_f0014() {
        let input = "Resources:\n  B:\n    Type: AWS::S3::Bucket\nConditions:\n  Bad:\n    Fn::Not:\n      - definitely-not-boolean\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        assert!(
            ir.diagnostics.iter().any(|d| d.rule_id == "F0014"
                && d.message.contains("Fn::Not")
                && d.message.contains("is not of type 'boolean'")),
            "Expected F0014 for Fn::Not with string arg, got: {:?}",
            ir.diagnostics
        );
    }
}
