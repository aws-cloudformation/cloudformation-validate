use crate::consts::*;
use crate::ir::*;
use log::{debug, info, warn};
use std::collections::{BTreeMap, HashMap};
use std::mem;
use std::str::from_utf8;
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser, Tag};
use yaml_rust2::scanner::Marker;
use yaml_rust2::yaml::{Hash, Yaml};

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
        }
    }

    fn load(text: &str) -> Result<(Vec<Yaml>, HashMap<String, (u32, u32)>), String> {
        let mut loader = Self::new();
        let mut parser = Parser::new_from_str(text);
        parser
            .load(&mut loader, true)
            .map_err(|e| format!("{}", e))?;
        Ok((loader.docs, loader.span_map))
    }

    fn current_path(&self) -> String {
        self.path_stack.join("/")
    }

    fn cfn_tag_name(tag: &Option<Tag>) -> Option<String> {
        let tag = tag.as_ref()?;
        if tag.handle == "!" {
            let name = &tag.suffix;
            match name.as_str() {
                "Ref" | "GetAtt" | "Sub" | "Join" | "Select" | "If" | "FindInMap" | "Split"
                | "Base64" | "Cidr" | "GetAZs" | "ImportValue" | "Transform" | "And" | "Or"
                | "Not" | "Equals" | "Condition" | "ToJsonString" | "Length" | "ForEach" => {
                    Some(name.clone())
                }
                _ => None,
            }
        } else {
            None
        }
    }

    fn wrap_with_tag(tag_name: &str, value: Yaml) -> Yaml {
        let key = match tag_name {
            "Ref" => FN_REF,
            "GetAtt" => FN_GET_ATT,
            "Sub" => FN_SUB,
            "Join" => FN_JOIN,
            "Select" => FN_SELECT,
            "If" => FN_IF,
            "FindInMap" => FN_FIND_IN_MAP,
            "Split" => FN_SPLIT,
            "Base64" => FN_BASE64,
            "Cidr" => FN_CIDR,
            "GetAZs" => FN_GET_AZS,
            "ImportValue" => FN_IMPORT_VALUE,
            "Transform" => FN_TRANSFORM,
            "And" => FN_AND,
            "Or" => FN_OR,
            "Not" => FN_NOT,
            "Equals" => FN_EQUALS,
            "Condition" => FN_CONDITION,
            "ToJsonString" => FN_TO_JSON_STRING,
            "Length" => FN_LENGTH,
            "ForEach" => FN_FOR_EACH,
            _ => return value,
        };
        let mut hash = Hash::new();
        hash.insert(Yaml::String(key.to_string()), value);
        Yaml::Hash(hash)
    }

    fn insert_new_node(&mut self, node: (Yaml, usize), _mark: Marker) {
        let (mut node_val, aid) = node;
        if let Some((_, depth)) = self.pending_tags.last()
            && self.doc_stack.len() == *depth {
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
                    h.insert(key, node_val);
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
            }
            Event::MappingEnd => {
                self.key_stack.pop();
                if !self.path_stack.is_empty() {
                    let parent_is_array = self
                        .doc_stack
                        .last()
                        .map(|(y, _)| matches!(y, Yaml::Array(_)))
                        .unwrap_or(false);
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
                            self.span_map
                                .insert(path, (mark.line() as u32 + 1, mark.col() as u32 + 1));
                        }
                    } else if matches!(parent.0, Yaml::Array(_))
                        && let Some(idx) = self.array_idx_stack.last_mut() {
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

pub fn parse_yaml(bytes: &[u8]) -> Result<TemplateIR, ParseError> {
    let text = from_utf8(bytes).map_err(|e| ParseError {
        message: format!("Invalid UTF-8: {}", e),
        line: None,
        column: None,
    })?;

    let (docs, raw_spans) = CfnYamlLoader::load(text).map_err(|e| ParseError {
        message: format!("YAML parse error: {}", e),
        line: None,
        column: None,
    })?;

    if docs.is_empty() {
        return Err(ParseError {
            message: "Empty YAML document".into(),
            line: Some(1),
            column: Some(1),
        });
    }

    let hash = docs[0].as_hash().ok_or_else(|| ParseError {
        message: "Template root must be a YAML mapping".into(),
        line: Some(1),
        column: Some(1),
    })?;

    let mut builder = YamlBuilder {
        arena: Arena::new(),
        global_index: GlobalIndex::new(),
        span_index: SourceSpanIndex::new(),
        diagnostics: Vec::new(),
    };
    let root = builder.build_hash(hash, "");

    let parameters = builder
        .arena
        .map_get(root, SECTION_PARAMETERS)
        .unwrap_or(NULL_REF);
    let mappings = builder
        .arena
        .map_get(root, SECTION_MAPPINGS)
        .unwrap_or(NULL_REF);
    let conditions = builder
        .arena
        .map_get(root, SECTION_CONDITIONS)
        .unwrap_or(NULL_REF);
    let resources = builder
        .arena
        .map_get(root, SECTION_RESOURCES)
        .unwrap_or(NULL_REF);
    let outputs = builder
        .arena
        .map_get(root, SECTION_OUTPUTS)
        .unwrap_or(NULL_REF);
    let rules = builder
        .arena
        .map_get(root, SECTION_RULES)
        .unwrap_or(NULL_REF);
    let template_metadata = builder
        .arena
        .map_get(root, SECTION_METADATA)
        .unwrap_or(NULL_REF);
    let globals = builder
        .arena
        .map_get(root, SECTION_GLOBALS)
        .unwrap_or(NULL_REF);
    let format_version = builder
        .arena
        .map_get(root, SECTION_FORMAT_VERSION)
        .and_then(|r| builder.arena.as_str(r).map(|s| s.to_string()));
    let description = builder
        .arena
        .map_get(root, SECTION_DESCRIPTION)
        .and_then(|r| builder.arena.as_str(r).map(|s| s.to_string()));
    let transforms = extract_transforms(&builder.arena, root);
    let raw_top_level_keys = builder
        .arena
        .as_map(root)
        .map(|entries| entries.iter().map(|(k, _)| k.clone()).collect())
        .unwrap_or_default();

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
    info!(
        "YAML span assignment complete: {} entries from marker tracking",
        builder.span_index.len()
    );

    debug!(
        "YAML IR built: {} resources, {} parameters, {} mappings, {} conditions, {} outputs, {} span entries",
        builder
            .arena
            .as_map(resources)
            .map(|m| m.len())
            .unwrap_or(0),
        builder
            .arena
            .as_map(parameters)
            .map(|m| m.len())
            .unwrap_or(0),
        builder.arena.as_map(mappings).map(|m| m.len()).unwrap_or(0),
        builder
            .arena
            .as_map(conditions)
            .map(|m| m.len())
            .unwrap_or(0),
        builder.arena.as_map(outputs).map(|m| m.len()).unwrap_or(0),
        builder.span_index.len()
    );
    if !builder.diagnostics.is_empty() {
        warn!(
            "{} parse diagnostics from YAML (malformed intrinsics)",
            builder.diagnostics.len()
        );
    }

    Ok(TemplateIR {
        arena: builder.arena,
        global_index: builder.global_index,
        span_index: builder.span_index,
        parameters,
        mappings,
        conditions,
        resources,
        outputs,
        rules,
        template_metadata,
        format_version,
        description,
        transforms,
        raw_top_level_keys,
        diagnostics: builder.diagnostics,
        globals,
    })
}

struct YamlBuilder {
    arena: Arena,
    global_index: GlobalIndex,
    span_index: SourceSpanIndex,
    diagnostics: Vec<diagnostics::Diagnostic>,
}

/// Describe a YAML value's type/content for diagnostic messages.
fn describe_yaml_value(val: &Yaml) -> String {
    match val {
        Yaml::Null | Yaml::BadValue => "null".to_string(),
        Yaml::Boolean(b) => format!("{}", b),
        Yaml::Integer(i) => i.to_string(),
        Yaml::Real(r) => r.clone(),
        Yaml::String(s) => format!("'{}'", s),
        Yaml::Array(arr) => {
            let items: Vec<String> = arr.iter().map(describe_yaml_value).collect();
            format!("[{}]", items.join(", "))
        }
        Yaml::Hash(h) => {
            let entries: Vec<String> = h
                .iter()
                .map(|(k, v)| {
                    let ks = k
                        .as_str()
                        .map(|s| format!("'{}'", s))
                        .unwrap_or_else(|| "?".to_string());
                    format!("{}: {}", ks, describe_yaml_value(v))
                })
                .collect();
            format!("{{{}}}", entries.join(", "))
        }
        Yaml::Alias(_) => "<alias>".to_string(),
    }
}

/// Return `Some(reason)` if `val` is NOT a well-formed boolean condition
/// element (input to Fn::And / Fn::Or / Fn::Not). Valid elements are
/// single-key mappings whose key is `Condition` or a boolean-producing
/// intrinsic function.
fn condition_element_error_yaml(val: &Yaml) -> Option<String> {
    if matches!(val, Yaml::Null | Yaml::BadValue) {
        return Some("null is not of type 'boolean'".to_string());
    }
    let Some(hash) = val.as_hash() else {
        return Some(format!(
            "{} is not of type 'boolean'",
            describe_yaml_value(val)
        ));
    };
    if hash.len() != 1 {
        return Some(format!(
            "{} is not of type 'boolean'",
            describe_yaml_value(val)
        ));
    }
    let key = hash.keys().next().and_then(|k| k.as_str()).unwrap_or("");
    if BOOLEAN_FN_KEYS.contains(&key) {
        None
    } else {
        Some(format!(
            "{} is not of type 'boolean'",
            describe_yaml_value(val)
        ))
    }
}

/// Return `Some(reason)` if `val` is NOT valid as an Fn::Equals argument.
/// Valid: string, number, or a single-key mapping whose key is one of the
/// intrinsic functions that may resolve to a string value.
fn equals_argument_error_yaml(val: &Yaml) -> Option<String> {
    if matches!(val, Yaml::Null | Yaml::BadValue) {
        return Some("null is not of type 'string'".to_string());
    }
    if matches!(val, Yaml::String(_) | Yaml::Integer(_) | Yaml::Real(_)) {
        return None;
    }
    if let Some(hash) = val.as_hash()
        && hash.len() == 1 {
            let key = hash.keys().next().and_then(|k| k.as_str()).unwrap_or("");
            if EQUALS_ARG_FN_KEYS.contains(&key) {
                return None;
            }
        }
    Some(format!(
        "{} is not of type 'string'",
        describe_yaml_value(val)
    ))
}

impl YamlBuilder {
    fn build_yaml(&mut self, yaml: &Yaml, path: &str) -> NodeRef {
        match yaml {
            Yaml::Null | Yaml::BadValue => self.arena.alloc(SpannedNode {
                node: Node::Null,
                span: UNKNOWN_SPAN,
                path: path.into(),
            }),
            Yaml::Boolean(b) => self.arena.alloc(SpannedNode {
                node: Node::Bool(*b),
                span: UNKNOWN_SPAN,
                path: path.into(),
            }),
            Yaml::Integer(i) => self.arena.alloc(SpannedNode {
                node: Node::Int(*i),
                span: UNKNOWN_SPAN,
                path: path.into(),
            }),
            Yaml::Real(s) => self.arena.alloc(SpannedNode {
                node: Node::Float(s.parse().unwrap_or(0.0)),
                span: UNKNOWN_SPAN,
                path: path.into(),
            }),
            Yaml::String(s) => self.arena.alloc(SpannedNode {
                node: Node::String(s.clone()),
                span: UNKNOWN_SPAN,
                path: path.into(),
            }),
            Yaml::Array(arr) => {
                let c: Vec<NodeRef> = arr
                    .iter()
                    .enumerate()
                    .map(|(i, v)| self.build_yaml(v, &format!("{}/{}", path, i)))
                    .collect();
                self.arena.alloc(SpannedNode {
                    node: Node::List(c),
                    span: UNKNOWN_SPAN,
                    path: path.into(),
                })
            }
            Yaml::Hash(hash) => self.build_hash(hash, path),
            Yaml::Alias(_) => self.arena.alloc(SpannedNode {
                node: Node::Null,
                span: UNKNOWN_SPAN,
                path: path.into(),
            }),
        }
    }

    fn build_hash(&mut self, hash: &Hash, path: &str) -> NodeRef {
        if hash.len() == 1 {
            let (k, v) = hash.iter().next().unwrap();
            if let Some(ks) = yaml_as_string(k)
                && let Some(r) = self.try_intrinsic(&ks, v, path) {
                    return r;
                }
        }
        let entries: Vec<(String, NodeRef)> = hash
            .iter()
            .filter_map(|(k, v)| {
                let key = yaml_as_string(k)?;
                let cp = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{}/{}", path, key)
                };
                let cr = self.build_yaml(v, &cp);
                self.global_index.insert(cp.clone(), cr);
                self.span_index.entry(cp).or_insert(UNKNOWN_SPAN);
                Some((key, cr))
            })
            .collect();
        self.arena.alloc(SpannedNode {
            node: Node::Map(entries),
            span: UNKNOWN_SPAN,
            path: path.into(),
        })
    }

    fn intrinsic_error(&mut self, fn_name: &str, message: &str) {
        self.diagnostics.push(crate::make_parse_diagnostic(
            "F1101",
            rules_crate::Severity::Fatal,
            format!("{}: {}", fn_name, message),
            UNKNOWN_SPAN,
        ));
    }

    /// Emit a structural diagnostic for Fn::Equals, Fn::And, Fn::Or, Fn::Not.
    /// CloudFormation rejects templates with these defects at deploy time.
    fn condition_fn_error(&mut self, fn_name: &str, message: &str) {
        self.diagnostics.push(crate::make_parse_diagnostic(
            "F0014",
            rules_crate::Severity::Fatal,
            format!("{}: {}", fn_name, message),
            UNKNOWN_SPAN,
        ));
    }

    /// Emit a structural diagnostic for Fn::If.
    fn fn_if_structural_error(&mut self, message: &str) {
        self.diagnostics.push(crate::make_parse_diagnostic(
            "F0013",
            rules_crate::Severity::Fatal,
            format!("{}: {}", FN_IF, message),
            UNKNOWN_SPAN,
        ));
    }

    fn try_intrinsic(&mut self, key: &str, val: &Yaml, path: &str) -> Option<NodeRef> {
        let i = match key {
            FN_REF => {
                let Some(s) = yaml_as_string(val) else {
                    if matches!(val, Yaml::Hash(_)) {
                        // Value is an intrinsic (e.g. Fn::Sub in LanguageExtensions) —
                        // cannot resolve statically. Fall through to plain map.
                        return None;
                    }
                    self.intrinsic_error(FN_REF, "Ref value must be a string");
                    return None;
                };
                IntrinsicFn::Ref(s)
            }
            FN_GET_ATT => {
                match val {
                    Yaml::Array(a) if a.len() == 2 => {
                        let Some(r) = yaml_as_string(&a[0]) else {
                            if matches!(&a[0], Yaml::Hash(_)) {
                                // Dynamic resource name (e.g. !Sub in ForEach) —
                                // cannot resolve statically. Fall through to plain map.
                                return None;
                            }
                            self.intrinsic_error(FN_GET_ATT, "Fn::GetAtt value must be a two-element string array or a dotted string");
                            return None;
                        };
                        let Some(attr) = yaml_as_string(&a[1]) else {
                            if matches!(&a[1], Yaml::Hash(_)) {
                                // Dynamic attribute name (e.g. {"Ref": "Property"} in ForEach) —
                                // cannot resolve statically. Fall through to plain map.
                                return None;
                            }
                            self.intrinsic_error(FN_GET_ATT, "Fn::GetAtt value must be a two-element string array or a dotted string");
                            return None;
                        };
                        IntrinsicFn::GetAtt(r, attr)
                    }
                    Yaml::String(s) => {
                        let Some((r, a)) = s.split_once('.') else {
                            self.intrinsic_error(FN_GET_ATT, "Fn::GetAtt value must be a two-element string array or a dotted string");
                            return None;
                        };
                        IntrinsicFn::GetAtt(r.into(), a.into())
                    }
                    _ => {
                        self.intrinsic_error(FN_GET_ATT, "Fn::GetAtt value must be a two-element string array or a dotted string");
                        return None;
                    }
                }
            }
            FN_SUB => match val {
                Yaml::String(s) => IntrinsicFn::Sub(s.clone(), None),
                Yaml::Array(a) if !a.is_empty() => {
                    let Some(t) = yaml_as_string(&a[0]) else {
                        self.intrinsic_error(
                            FN_SUB,
                            "Fn::Sub value must be a string or a [string, object] array",
                        );
                        return None;
                    };
                    let subs = if a.len() > 1 {
                        match a[1].as_hash() {
                            Some(h) => Some(
                                h.iter()
                                    .filter_map(|(k, v)| {
                                        let ks = yaml_as_string(k)?;
                                        let r = self
                                            .build_yaml(v, &format!("{}/Fn::Sub/1/{}", path, ks));
                                        Some((ks, r))
                                    })
                                    .collect(),
                            ),
                            None => {
                                self.diagnostics.push(crate::make_parse_diagnostic(
                                    "F0010",
                                    rules_crate::Severity::Fatal,
                                    "Fn::Sub second argument must be a map with string keys"
                                        .to_string(),
                                    UNKNOWN_SPAN,
                                ));
                                None
                            }
                        }
                    } else {
                        None
                    };
                    IntrinsicFn::Sub(t, subs)
                }
                Yaml::Hash(_) => {
                    // Value is an intrinsic (e.g. Fn::Transform) — cannot validate
                    // statically. Fall through to build as a plain map node.
                    return None;
                }
                _ => {
                    self.intrinsic_error(
                        FN_SUB,
                        "Fn::Sub value must be a string or a [string, object] array",
                    );
                    return None;
                }
            },
            FN_JOIN => {
                let Some(a) = val.as_vec() else {
                    if matches!(val, Yaml::Hash(_)) {
                        // Value is an intrinsic — cannot validate statically.
                        return None;
                    }
                    self.intrinsic_error(FN_JOIN, "Fn::Join value must be an array");
                    return None;
                };
                if a.len() != 2 {
                    // Wrong element count — fall through to plain map so downstream
                    // rules (E1021) can report with proper resource context.
                    return None;
                }
                if !matches!(&a[0], Yaml::String(_) | Yaml::Hash(_)) {
                    self.diagnostics.push(crate::make_parse_diagnostic(
                        "W1102",
                        rules_crate::Severity::Warn,
                        "Fn::Join: delimiter (first argument) must be a string or an intrinsic function".to_string(),
                        UNKNOWN_SPAN,
                    ));
                }
                let d = self.build_yaml(&a[0], &format!("{}/Fn::Join/0", path));
                let v = self.build_yaml(&a[1], &format!("{}/Fn::Join/1", path));
                IntrinsicFn::Join(d, v)
            }
            FN_SELECT => {
                let Some(a) = val.as_vec() else {
                    if matches!(val, Yaml::Hash(_)) {
                        // Value is an intrinsic — cannot validate statically.
                        return None;
                    }
                    // Non-array value (e.g. string) — fall through to plain map so
                    // downstream rules (E1017) can report with proper resource context.
                    return None;
                };
                if a.len() != 2 {
                    // Wrong element count — fall through to plain map so downstream
                    // rules (E1017) can report with proper resource context.
                    return None;
                }
                if !matches!(&a[0], Yaml::Integer(_) | Yaml::Hash(_)) {
                    self.diagnostics.push(crate::make_parse_diagnostic(
                        "W1102",
                        rules_crate::Severity::Warn,
                        "Fn::Select: index (first argument) must be an integer or an intrinsic function".to_string(),
                        UNKNOWN_SPAN,
                    ));
                }
                let i = self.build_yaml(&a[0], &format!("{}/Fn::Select/0", path));
                let l = self.build_yaml(&a[1], &format!("{}/Fn::Select/1", path));
                IntrinsicFn::Select(i, l)
            }
            FN_IF => {
                let Some(a) = val.as_vec() else {
                    let kind = if matches!(val, Yaml::Null | Yaml::BadValue) {
                        "null".to_string()
                    } else {
                        format!("{} is not of type 'array'", describe_yaml_value(val))
                    };
                    self.fn_if_structural_error(&kind);
                    return None;
                };
                if a.len() != 3 {
                    self.fn_if_structural_error(&format!(
                        "must have exactly 3 elements, got {}",
                        a.len()
                    ));
                    return None;
                }
                let t = self.build_yaml(&a[1], &format!("{}/Fn::If/1", path));
                let f = self.build_yaml(&a[2], &format!("{}/Fn::If/2", path));
                match yaml_as_string(&a[0]) {
                    Some(c) => IntrinsicFn::If(c, t, f),
                    None => {
                        let cond = self.build_yaml(&a[0], &format!("{}/Fn::If/0", path));
                        IntrinsicFn::IfExpr(cond, t, f)
                    }
                }
            }
            FN_FIND_IN_MAP => {
                let Some(a) = val.as_vec() else {
                    self.intrinsic_error(FN_FIND_IN_MAP, "Fn::FindInMap value must be an array");
                    return None;
                };
                if a.len() != 3 && a.len() != 4 {
                    self.intrinsic_error(
                        FN_FIND_IN_MAP,
                        &format!(
                            "Fn::FindInMap value must be a 3 or 4-element array, got {}",
                            a.len()
                        ),
                    );
                    return None;
                }
                let map_name_ref = self.build_yaml(&a[0], &format!("{}/Fn::FindInMap/0", path));
                let k1 = self.build_yaml(&a[1], &format!("{}/Fn::FindInMap/1", path));
                let k2 = self.build_yaml(&a[2], &format!("{}/Fn::FindInMap/2", path));
                let default_ref = if a.len() == 4 {
                    a[3].as_hash()
                        .and_then(|h| h.get(&Yaml::String("DefaultValue".into())))
                        .map(|dv| {
                            self.build_yaml(dv, &format!("{}/Fn::FindInMap/3/DefaultValue", path))
                        })
                } else {
                    None
                };
                IntrinsicFn::FindInMap(map_name_ref, k1, k2, default_ref)
            }
            FN_SPLIT => {
                let Some(a) = val.as_vec() else {
                    self.intrinsic_error(FN_SPLIT, "Fn::Split value must be an array");
                    return None;
                };
                if a.len() != 2 {
                    self.intrinsic_error(
                        FN_SPLIT,
                        &format!("Fn::Split value must be a 2-element array, got {}", a.len()),
                    );
                    return None;
                }
                if !matches!(&a[0], Yaml::String(_) | Yaml::Hash(_)) {
                    self.diagnostics.push(crate::make_parse_diagnostic(
                        "W1102",
                        rules_crate::Severity::Warn,
                        "Fn::Split: delimiter (first argument) must be a string or an intrinsic function".to_string(),
                        UNKNOWN_SPAN,
                    ));
                }
                let d = self.build_yaml(&a[0], &format!("{}/Fn::Split/0", path));
                let s = self.build_yaml(&a[1], &format!("{}/Fn::Split/1", path));
                IntrinsicFn::Split(d, s)
            }
            FN_BASE64 => {
                let c = self.build_yaml(val, &format!("{}/Fn::Base64", path));
                IntrinsicFn::Base64(c)
            }
            FN_CIDR => {
                let Some(a) = val.as_vec() else {
                    self.intrinsic_error(FN_CIDR, "Fn::Cidr value must be an array");
                    return None;
                };
                if a.len() != 3 {
                    self.intrinsic_error(
                        FN_CIDR,
                        &format!("Fn::Cidr value must be a 3-element array, got {}", a.len()),
                    );
                    return None;
                }
                let x = self.build_yaml(&a[0], &format!("{}/Fn::Cidr/0", path));
                let y = self.build_yaml(&a[1], &format!("{}/Fn::Cidr/1", path));
                let z = self.build_yaml(&a[2], &format!("{}/Fn::Cidr/2", path));
                IntrinsicFn::Cidr(x, y, z)
            }
            FN_GET_AZS => {
                let c = self.build_yaml(val, &format!("{}/Fn::GetAZs", path));
                IntrinsicFn::GetAZs(c)
            }
            FN_IMPORT_VALUE => {
                let c = self.build_yaml(val, &format!("{}/Fn::ImportValue", path));
                IntrinsicFn::ImportValue(c)
            }
            FN_TRANSFORM => {
                let Some(h) = val.as_hash() else {
                    self.intrinsic_error(FN_TRANSFORM, "Fn::Transform value must be an object");
                    return None;
                };
                let Some(name_val) = h.get(&Yaml::String("Name".into())) else {
                    self.intrinsic_error(FN_TRANSFORM, "Fn::Transform must have a 'Name' key");
                    return None;
                };
                let Some(n) = name_val.as_str() else {
                    self.intrinsic_error(FN_TRANSFORM, "Fn::Transform 'Name' must be a string");
                    return None;
                };
                let n = n.to_string();
                let p2 = h
                    .get(&Yaml::String("Parameters".into()))
                    .and_then(|v| v.as_hash())
                    .map(|ph| {
                        ph.iter()
                            .filter_map(|(k, v)| {
                                let ks = yaml_as_string(k)?;
                                let r = self.build_yaml(
                                    v,
                                    &format!("{}/Fn::Transform/Parameters/{}", path, ks),
                                );
                                Some((ks, r))
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                IntrinsicFn::Transform(n, p2)
            }
            FN_AND => {
                let Some(a) = val.as_vec() else {
                    self.condition_fn_error(
                        FN_AND,
                        &format!("{} is not of type 'array'", describe_yaml_value(val)),
                    );
                    return None;
                };
                if a.len() < 2 {
                    self.condition_fn_error(
                        FN_AND,
                        &format!("expected minimum item count: 2, found: {}", a.len()),
                    );
                    return None;
                }
                if a.len() > 10 {
                    self.condition_fn_error(
                        FN_AND,
                        &format!("expected maximum item count: 10, found: {}", a.len()),
                    );
                    return None;
                }
                for (idx, elem) in a.iter().enumerate() {
                    if let Some(reason) = condition_element_error_yaml(elem) {
                        self.condition_fn_error(FN_AND, &format!("element {}: {}", idx, reason));
                    }
                }
                let c: Vec<NodeRef> = a
                    .iter()
                    .enumerate()
                    .map(|(i, v)| self.build_yaml(v, &format!("{}/{}/{}", path, FN_AND, i)))
                    .collect();
                IntrinsicFn::And(c)
            }
            FN_OR => {
                let Some(a) = val.as_vec() else {
                    self.condition_fn_error(
                        FN_OR,
                        &format!("{} is not of type 'array'", describe_yaml_value(val)),
                    );
                    return None;
                };
                if a.len() < 2 {
                    self.condition_fn_error(
                        FN_OR,
                        &format!("expected minimum item count: 2, found: {}", a.len()),
                    );
                    return None;
                }
                if a.len() > 10 {
                    self.condition_fn_error(
                        FN_OR,
                        &format!("expected maximum item count: 10, found: {}", a.len()),
                    );
                    return None;
                }
                for (idx, elem) in a.iter().enumerate() {
                    if let Some(reason) = condition_element_error_yaml(elem) {
                        self.condition_fn_error(FN_OR, &format!("element {}: {}", idx, reason));
                    }
                }
                let c: Vec<NodeRef> = a
                    .iter()
                    .enumerate()
                    .map(|(i, v)| self.build_yaml(v, &format!("{}/{}/{}", path, FN_OR, i)))
                    .collect();
                IntrinsicFn::Or(c)
            }
            FN_NOT => {
                let Some(a) = val.as_vec() else {
                    self.condition_fn_error(
                        FN_NOT,
                        &format!("{} is not of type 'array'", describe_yaml_value(val)),
                    );
                    return None;
                };
                if a.len() != 1 {
                    self.condition_fn_error(
                        FN_NOT,
                        &format!("must have exactly 1 element, got {}", a.len()),
                    );
                    return None;
                }
                if let Some(reason) = condition_element_error_yaml(&a[0]) {
                    self.condition_fn_error(FN_NOT, &format!("element 0: {}", reason));
                }
                let c = self.build_yaml(&a[0], &format!("{}/{}/0", path, FN_NOT));
                IntrinsicFn::Not(c)
            }
            FN_EQUALS => {
                let Some(a) = val.as_vec() else {
                    self.condition_fn_error(
                        FN_EQUALS,
                        &format!("{} is not of type 'array'", describe_yaml_value(val)),
                    );
                    return None;
                };
                if a.len() != 2 {
                    let bound = if a.len() < 2 { "minimum" } else { "maximum" };
                    self.condition_fn_error(
                        FN_EQUALS,
                        &format!("expected {} item count: 2, found: {}", bound, a.len()),
                    );
                    return None;
                }
                for (idx, elem) in a.iter().enumerate() {
                    if let Some(reason) = equals_argument_error_yaml(elem) {
                        self.condition_fn_error(
                            FN_EQUALS,
                            &format!("argument {}: {}", idx, reason),
                        );
                    }
                }
                let x = self.build_yaml(&a[0], &format!("{}/{}/0", path, FN_EQUALS));
                let y = self.build_yaml(&a[1], &format!("{}/{}/1", path, FN_EQUALS));
                IntrinsicFn::Equals(x, y)
            }
            FN_TO_JSON_STRING => {
                let c = self.build_yaml(val, &format!("{}/Fn::ToJsonString", path));
                IntrinsicFn::ToJsonString(c)
            }
            FN_LENGTH => {
                let c = self.build_yaml(val, &format!("{}/Fn::Length", path));
                IntrinsicFn::Length(c)
            }
            FN_FOR_EACH => {
                let Some(a) = val.as_vec() else {
                    self.intrinsic_error(FN_FOR_EACH, "Fn::ForEach value must be an array");
                    return None;
                };
                if a.len() != 4 {
                    self.intrinsic_error(
                        FN_FOR_EACH,
                        &format!(
                            "Fn::ForEach value must be a 4-element array, got {}",
                            a.len()
                        ),
                    );
                    return None;
                }
                let Some(uid) = yaml_as_string(&a[0]) else {
                    self.intrinsic_error(
                        FN_FOR_EACH,
                        "Fn::ForEach first argument must be a string (unique ID)",
                    );
                    return None;
                };
                let Some(ident) = yaml_as_string(&a[1]) else {
                    self.intrinsic_error(
                        FN_FOR_EACH,
                        "Fn::ForEach second argument must be a string (identifier)",
                    );
                    return None;
                };
                let coll = self.build_yaml(&a[2], &format!("{}/Fn::ForEach/2", path));
                let body = self.build_yaml(&a[3], &format!("{}/Fn::ForEach/3", path));
                IntrinsicFn::ForEach(uid, ident, coll, body)
            }
            FN_VALUE_OF => {
                let Some(a) = val.as_vec() else {
                    self.intrinsic_error(FN_VALUE_OF, "Fn::ValueOf value must be an array");
                    return None;
                };
                if a.len() != 2 {
                    self.intrinsic_error(
                        FN_VALUE_OF,
                        &format!(
                            "Fn::ValueOf value must be a 2-element array, got {}",
                            a.len()
                        ),
                    );
                    return None;
                }
                let Some(s0) = yaml_as_string(&a[0]) else {
                    self.intrinsic_error(
                        FN_VALUE_OF,
                        "Fn::ValueOf first argument must be a string",
                    );
                    return None;
                };
                let Some(s1) = yaml_as_string(&a[1]) else {
                    self.intrinsic_error(
                        FN_VALUE_OF,
                        "Fn::ValueOf second argument must be a string",
                    );
                    return None;
                };
                IntrinsicFn::ValueOf(s0, s1)
            }
            FN_VALUE_OF_ALL => {
                let Some(a) = val.as_vec() else {
                    self.intrinsic_error(FN_VALUE_OF_ALL, "Fn::ValueOfAll value must be an array");
                    return None;
                };
                if a.len() != 2 {
                    self.intrinsic_error(
                        FN_VALUE_OF_ALL,
                        &format!(
                            "Fn::ValueOfAll value must be a 2-element array, got {}",
                            a.len()
                        ),
                    );
                    return None;
                }
                let Some(s0) = yaml_as_string(&a[0]) else {
                    self.intrinsic_error(
                        FN_VALUE_OF_ALL,
                        "Fn::ValueOfAll first argument must be a string",
                    );
                    return None;
                };
                let Some(s1) = yaml_as_string(&a[1]) else {
                    self.intrinsic_error(
                        FN_VALUE_OF_ALL,
                        "Fn::ValueOfAll second argument must be a string",
                    );
                    return None;
                };
                IntrinsicFn::ValueOfAll(s0, s1)
            }
            FN_REF_ALL => {
                let Some(s) = yaml_as_string(val) else {
                    self.intrinsic_error(FN_REF_ALL, "Fn::RefAll value must be a string");
                    return None;
                };
                IntrinsicFn::RefAll(s)
            }
            FN_CONTAINS => {
                let Some(a) = val.as_vec() else {
                    self.intrinsic_error(FN_CONTAINS, "Fn::Contains value must be an array");
                    return None;
                };
                if a.len() != 2 {
                    self.intrinsic_error(
                        FN_CONTAINS,
                        &format!(
                            "Fn::Contains value must be a 2-element array, got {}",
                            a.len()
                        ),
                    );
                    return None;
                }
                let list = self.build_yaml(&a[0], &format!("{}/Fn::Contains/0", path));
                let value = self.build_yaml(&a[1], &format!("{}/Fn::Contains/1", path));
                IntrinsicFn::Contains(list, value)
            }
            FN_EACH_MEMBER_EQUALS => {
                let Some(a) = val.as_vec() else {
                    self.intrinsic_error(
                        FN_EACH_MEMBER_EQUALS,
                        "Fn::EachMemberEquals value must be an array",
                    );
                    return None;
                };
                if a.len() != 2 {
                    self.intrinsic_error(
                        FN_EACH_MEMBER_EQUALS,
                        &format!(
                            "Fn::EachMemberEquals value must be a 2-element array, got {}",
                            a.len()
                        ),
                    );
                    return None;
                }
                let list = self.build_yaml(&a[0], &format!("{}/Fn::EachMemberEquals/0", path));
                let value = self.build_yaml(&a[1], &format!("{}/Fn::EachMemberEquals/1", path));
                IntrinsicFn::EachMemberEquals(list, value)
            }
            FN_EACH_MEMBER_IN => {
                let Some(a) = val.as_vec() else {
                    self.intrinsic_error(
                        FN_EACH_MEMBER_IN,
                        "Fn::EachMemberIn value must be an array",
                    );
                    return None;
                };
                if a.len() != 2 {
                    self.intrinsic_error(
                        FN_EACH_MEMBER_IN,
                        &format!(
                            "Fn::EachMemberIn value must be a 2-element array, got {}",
                            a.len()
                        ),
                    );
                    return None;
                }
                let list1 = self.build_yaml(&a[0], &format!("{}/Fn::EachMemberIn/0", path));
                let list2 = self.build_yaml(&a[1], &format!("{}/Fn::EachMemberIn/1", path));
                IntrinsicFn::EachMemberIn(list1, list2)
            }
            FN_CONDITION => {
                let Some(s) = yaml_as_string(val) else {
                    self.intrinsic_error(FN_CONDITION, "Condition value must be a string");
                    return None;
                };
                IntrinsicFn::Ref(format!("Condition:{}", s))
            }
            _ => return None,
        };
        Some(self.arena.alloc(SpannedNode {
            node: Node::Intrinsic(i),
            span: UNKNOWN_SPAN,
            path: path.into(),
        }))
    }
}

fn yaml_as_string(y: &Yaml) -> Option<String> {
    match y {
        Yaml::String(s) => Some(s.clone()),
        Yaml::Integer(i) => Some(i.to_string()),
        Yaml::Real(s) => Some(s.clone()),
        Yaml::Boolean(b) => Some(b.to_string()),
        _ => None,
    }
}

fn extract_transforms(arena: &Arena, root: NodeRef) -> Vec<String> {
    let Some(t) = arena.map_get(root, SECTION_TRANSFORM) else {
        return vec![];
    };
    match arena.node(t) {
        Node::String(s) => vec![s.clone()],
        Node::List(items) => items
            .iter()
            .filter_map(|r| arena.as_str(*r).map(|s| s.to_string()))
            .collect(),
        _ => vec![],
    }
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
        let input =
            "Resources:\n  R:\n    Type: T\n    Properties:\n      Role: !GetAtt LambdaRole.Arn\n";
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
        let y = parse_yaml(b"Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: test\n").unwrap();
        let j = super::super::json::parse_json(
            br#"{"Resources":{"B":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":"test"}}}}"#,
        )
        .unwrap();
        assert_eq!(
            y.arena.as_map(y.resources).unwrap().len(),
            j.arena.as_map(j.resources).unwrap().len()
        );
    }

    #[test]
    fn parse_inline_ref_in_flow_sequence() {
        let input =
            "Conditions:\n  C:\n    Fn::Equals: [!Ref Env, Prod]\nResources:\n  R:\n    Type: T\n";
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

    /// Full-form `Fn::Not: [{Fn::Contains: ...}]` in YAML must not produce
    /// a type error — `Fn::Contains` is a boolean-producing Rules-section
    /// intrinsic, not a non-boolean expression.
    #[test]
    fn fn_not_accepts_fn_contains_argument_no_f0014() {
        let input = "Parameters:\n  BootstrapVersion:\n    Type: String\nResources:\n  B:\n    Type: AWS::S3::Bucket\nRules:\n  CheckBootstrapVersion:\n    Assertions:\n      - Assert:\n          Fn::Not:\n            - Fn::Contains:\n                - [\"1\", \"2\", \"3\", \"4\", \"5\"]\n                - Ref: BootstrapVersion\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let f0014: Vec<_> = ir
            .diagnostics
            .iter()
            .filter(|d| d.rule_id == "F0014")
            .collect();
        assert!(
            f0014.is_empty(),
            "Expected no F0014 for Fn::Not(Fn::Contains), got: {:?}",
            f0014
        );
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
