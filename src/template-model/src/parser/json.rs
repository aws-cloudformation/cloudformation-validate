use crate::consts::*;
use crate::ir::*;
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

struct JsonBuilder {
    arena: Arena,
    global_index: GlobalIndex,
    span_index: SourceSpanIndex,
    diagnostics: Vec<diagnostics::Diagnostic>,
}

/// Describe a JSON value's type/content for diagnostic messages.
fn describe_json_value(val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => format!("{}", b),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => format!("'{}'", s),
        serde_json::Value::Array(_) => format!("{}", val),
        serde_json::Value::Object(_) => format!("{}", val),
    }
}

/// Return `Some(reason)` if `val` is NOT a well-formed boolean condition
/// element (input to Fn::And / Fn::Or / Fn::Not). A valid element is a
/// single-key object whose key is `Condition` or a boolean-producing
/// intrinsic function. Returns `None` when valid.
fn condition_element_error(val: &serde_json::Value) -> Option<String> {
    if val.is_null() {
        return Some("null is not of type 'boolean'".to_string());
    }
    let Some(obj) = val.as_object() else {
        return Some(format!("{} is not of type 'boolean'", describe_json_value(val)));
    };
    if obj.len() != 1 {
        return Some(format!("{} is not of type 'boolean'", describe_json_value(val)));
    }
    let key = obj.keys().next().map(String::as_str).unwrap_or("");
    if BOOLEAN_FN_KEYS.contains(&key) {
        None
    } else {
        Some(format!("{} is not of type 'boolean'", describe_json_value(val)))
    }
}

/// Return `Some(reason)` if `val` is NOT valid as an Fn::Equals argument.
/// Valid: string, number, or a single-key mapping whose key is one of the
/// intrinsic functions that may resolve to a string value.
fn equals_argument_error(val: &serde_json::Value) -> Option<String> {
    if val.is_null() {
        return Some("null is not of type 'string'".to_string());
    }
    if val.is_string() || val.is_number() || val.is_boolean() {
        return None;
    }
    if let Some(obj) = val.as_object()
        && obj.len() == 1
    {
        let key = obj.keys().next().map(String::as_str).unwrap_or("");
        if EQUALS_ARG_FN_KEYS.contains(&key) {
            return None;
        }
    }
    Some(format!("{} is not of type 'string'", describe_json_value(val)))
}

impl JsonBuilder {
    fn build_value(&mut self, val: &serde_json::Value, path: &str) -> NodeRef {
        match val {
            serde_json::Value::Null => {
                self.arena.alloc(SpannedNode { node: Node::Null, span: UNKNOWN_SPAN, path: path.to_string() })
            }
            serde_json::Value::Bool(b) => {
                self.arena.alloc(SpannedNode { node: Node::Bool(*b), span: UNKNOWN_SPAN, path: path.to_string() })
            }
            serde_json::Value::Number(n) => {
                let node = if let Some(i) = n.as_i64() { Node::Int(i) } else { Node::Float(n.as_f64().unwrap_or(0.0)) };
                self.arena.alloc(SpannedNode { node, span: UNKNOWN_SPAN, path: path.to_string() })
            }
            serde_json::Value::String(s) => self.arena.alloc(SpannedNode {
                node: Node::String(s.clone()),
                span: UNKNOWN_SPAN,
                path: path.to_string(),
            }),
            serde_json::Value::Array(arr) => {
                let children: Vec<NodeRef> = arr
                    .iter()
                    .enumerate()
                    .map(|(i, v)| {
                        let child_path = format!("{}/{}", path, i);
                        self.build_value(v, &child_path)
                    })
                    .collect();
                self.arena.alloc(SpannedNode { node: Node::List(children), span: UNKNOWN_SPAN, path: path.to_string() })
            }
            serde_json::Value::Object(map) => self.build_map(map, path),
        }
    }

    fn build_map(&mut self, map: &serde_json::Map<String, serde_json::Value>, path: &str) -> NodeRef {
        if map.len() == 1 {
            let (key, val) = map.iter().next().unwrap();
            if let Some(intrinsic) = self.try_build_intrinsic(key, val, path) {
                return intrinsic;
            }
        }

        if map.len() == 1
            && let Some(cond_name) = map.get(FN_CONDITION)
            && let serde_json::Value::String(name) = cond_name
        {
            let span = UNKNOWN_SPAN;
            return self.arena.alloc(SpannedNode {
                node: Node::Intrinsic(IntrinsicFn::Ref(format!("Condition:{}", name))),
                span,
                path: path.to_string(),
            });
        }

        let entries: Vec<(String, NodeRef)> = map
            .iter()
            .map(|(key, val)| {
                let child_path = if path.is_empty() { key.clone() } else { format!("{}/{}", path, key) };
                let child_ref = self.build_value(val, &child_path);
                self.global_index.insert(child_path.clone(), child_ref);
                (key.clone(), child_ref)
            })
            .collect();

        self.arena.alloc(SpannedNode { node: Node::Map(entries), span: UNKNOWN_SPAN, path: path.to_string() })
    }

    fn intrinsic_error(&mut self, fn_name: &str, message: &str) {
        self.diagnostics.push(crate::make_parse_diagnostic("F1101", format!("{}: {}", fn_name, message), UNKNOWN_SPAN));
    }

    fn intrinsic_type_error(&mut self, fn_name: &str, message: &str) {
        self.diagnostics.push(crate::make_parse_diagnostic("W1102", format!("{}: {}", fn_name, message), UNKNOWN_SPAN));
    }

    /// Emit a structural diagnostic for Fn::Equals, Fn::And, Fn::Or, Fn::Not.
    /// CloudFormation rejects templates with these defects at deploy time
    fn condition_fn_error(&mut self, fn_name: &str, message: &str) {
        self.diagnostics.push(crate::make_parse_diagnostic("F0014", format!("{}: {}", fn_name, message), UNKNOWN_SPAN));
    }

    /// Emit a structural diagnostic for Fn::If. CloudFormation rejects
    /// malformed Fn::If at deploy time; classified as Fatal.
    fn fn_if_structural_error(&mut self, message: &str) {
        self.diagnostics.push(crate::make_parse_diagnostic("F0013", format!("{}: {}", FN_IF, message), UNKNOWN_SPAN));
    }

    fn try_build_intrinsic(&mut self, key: &str, val: &serde_json::Value, path: &str) -> Option<NodeRef> {
        match key {
            FN_REF => {
                let target = match val.as_str() {
                    Some(s) => s.to_string(),
                    None => {
                        if val.is_object() {
                            // Value is an intrinsic (e.g. Fn::Sub in LanguageExtensions) —
                            // cannot resolve statically. Fall through to plain map.
                            return None;
                        }
                        self.intrinsic_error(FN_REF, "Ref value must be a string");
                        return None;
                    }
                };
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::Ref(target)),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_GET_ATT => {
                let intrinsic = match val {
                    serde_json::Value::Array(arr) if arr.len() == 2 => {
                        let resource = match arr[0].as_str() {
                            Some(s) => s.to_string(),
                            None => {
                                if arr[0].is_object() {
                                    // Dynamic resource name (e.g. Fn::Sub in ForEach) —
                                    // cannot resolve statically. Fall through to plain map.
                                    return None;
                                }
                                self.intrinsic_error(
                                    FN_GET_ATT,
                                    "Fn::GetAtt value must be a two-element string array or a dotted string",
                                );
                                return None;
                            }
                        };
                        let attr = match arr[1].as_str() {
                            Some(s) => s.to_string(),
                            None => {
                                if arr[1].is_object() {
                                    // Dynamic attribute name (e.g. {"Ref": "Property"} in ForEach) —
                                    // cannot resolve statically. Fall through to plain map.
                                    return None;
                                }
                                self.intrinsic_error(
                                    FN_GET_ATT,
                                    "Fn::GetAtt value must be a two-element string array or a dotted string",
                                );
                                return None;
                            }
                        };
                        IntrinsicFn::GetAtt(resource, attr)
                    }
                    serde_json::Value::String(s) => match s.split_once('.') {
                        Some((resource, attr)) => IntrinsicFn::GetAtt(resource.to_string(), attr.to_string()),
                        None => {
                            self.intrinsic_error(
                                FN_GET_ATT,
                                "Fn::GetAtt value must be a two-element string array or a dotted string",
                            );
                            return None;
                        }
                    },
                    _ => {
                        self.intrinsic_error(
                            FN_GET_ATT,
                            "Fn::GetAtt value must be a two-element string array or a dotted string",
                        );
                        return None;
                    }
                };
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(intrinsic),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_SUB => {
                let intrinsic = match val {
                    serde_json::Value::String(s) => IntrinsicFn::Sub(s.clone(), None),
                    serde_json::Value::Array(arr) if !arr.is_empty() => {
                        let template = match arr[0].as_str() {
                            Some(s) => s.to_string(),
                            None => {
                                self.intrinsic_error(
                                    FN_SUB,
                                    "Fn::Sub value must be a string or a [string, object] array",
                                );
                                return None;
                            }
                        };
                        let subs = if arr.len() > 1 {
                            if let serde_json::Value::Object(m) = &arr[1] {
                                let entries: Vec<(String, NodeRef)> = m
                                    .iter()
                                    .map(|(k, v)| {
                                        let p = format!("{}/Fn::Sub/1/{}", path, k);
                                        let r = self.build_value(v, &p);
                                        (k.clone(), r)
                                    })
                                    .collect();
                                Some(entries)
                            } else {
                                self.diagnostics.push(crate::make_parse_diagnostic(
                                    "F0010",
                                    "Fn::Sub second argument must be a map with string keys".to_string(),
                                    UNKNOWN_SPAN,
                                ));
                                None
                            }
                        } else {
                            None
                        };
                        IntrinsicFn::Sub(template, subs)
                    }
                    serde_json::Value::Object(_) => {
                        // Value is an intrinsic (e.g. Fn::Transform) — cannot validate
                        // statically. Fall through to build as a plain map node.
                        return None;
                    }
                    _ => {
                        self.intrinsic_error(FN_SUB, "Fn::Sub value must be a string or a [string, object] array");
                        return None;
                    }
                };
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(intrinsic),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_JOIN => {
                let arr = match val.as_array() {
                    Some(a) => a,
                    None => {
                        if val.is_object() {
                            // Value is an intrinsic — cannot validate statically.
                            return None;
                        }
                        self.intrinsic_error(FN_JOIN, "Fn::Join value must be an array");
                        return None;
                    }
                };
                if arr.len() != 2 {
                    // Wrong element count — fall through to plain map so downstream
                    // rules (E1021) can report with proper resource context.
                    return None;
                }
                if !arr[0].is_string() && !arr[0].is_object() {
                    self.intrinsic_type_error(FN_JOIN, "Fn::Join delimiter (first element) must be a string");
                }
                let delim = self.build_value(&arr[0], &format!("{}/Fn::Join/0", path));
                let values = self.build_value(&arr[1], &format!("{}/Fn::Join/1", path));
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::Join(delim, values)),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_SELECT => {
                let arr = match val.as_array() {
                    Some(a) => a,
                    None => {
                        if val.is_object() {
                            // Value is an intrinsic — cannot validate statically.
                            return None;
                        }
                        // Non-array value — fall through to plain map so downstream
                        // rules (E1017) can report with proper resource context.
                        return None;
                    }
                };
                if arr.len() != 2 {
                    // Wrong element count — fall through to plain map so downstream
                    // rules (E1017) can report with proper resource context.
                    return None;
                }
                if !arr[0].is_number() && !arr[0].is_object() {
                    self.intrinsic_type_error(FN_SELECT, "Fn::Select index (first element) must be an integer");
                }
                let idx = self.build_value(&arr[0], &format!("{}/Fn::Select/0", path));
                let list = self.build_value(&arr[1], &format!("{}/Fn::Select/1", path));
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::Select(idx, list)),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_IF => {
                let arr = match val.as_array() {
                    Some(a) => a,
                    None => {
                        let kind = if val.is_null() {
                            "null".to_string()
                        } else {
                            format!("{} is not of type 'array'", describe_json_value(val))
                        };
                        self.fn_if_structural_error(&kind);
                        return None;
                    }
                };
                if arr.len() != 3 {
                    self.fn_if_structural_error(&format!("must have exactly 3 elements, got {}", arr.len()));
                    return None;
                }
                let if_true = self.build_value(&arr[1], &format!("{}/Fn::If/1", path));
                let if_false = self.build_value(&arr[2], &format!("{}/Fn::If/2", path));
                match arr[0].as_str() {
                    Some(cond) => Some(self.arena.alloc(SpannedNode {
                        node: Node::Intrinsic(IntrinsicFn::If(cond.to_string(), if_true, if_false)),
                        span: UNKNOWN_SPAN,
                        path: path.to_string(),
                    })),
                    None => {
                        let cond_node = self.build_value(&arr[0], &format!("{}/Fn::If/0", path));
                        Some(self.arena.alloc(SpannedNode {
                            node: Node::Intrinsic(IntrinsicFn::IfExpr(cond_node, if_true, if_false)),
                            span: UNKNOWN_SPAN,
                            path: path.to_string(),
                        }))
                    }
                }
            }
            FN_FIND_IN_MAP => {
                let arr = match val.as_array() {
                    Some(a) => a,
                    None => {
                        self.intrinsic_error(FN_FIND_IN_MAP, "Fn::FindInMap value must be an array");
                        return None;
                    }
                };
                // Support both 3-arg and 4-arg (with DefaultValue) forms
                if arr.len() != 3 && arr.len() != 4 {
                    self.intrinsic_error(
                        FN_FIND_IN_MAP,
                        &format!("Fn::FindInMap requires 3 or 4 elements, got {}", arr.len()),
                    );
                    return None;
                }
                let map_name_ref = self.build_value(&arr[0], &format!("{}/Fn::FindInMap/0", path));
                let k1 = self.build_value(&arr[1], &format!("{}/Fn::FindInMap/1", path));
                let k2 = self.build_value(&arr[2], &format!("{}/Fn::FindInMap/2", path));
                let default_ref = if arr.len() == 4 {
                    arr[3]
                        .as_object()
                        .and_then(|obj| obj.get("DefaultValue"))
                        .map(|dv| self.build_value(dv, &format!("{}/Fn::FindInMap/3/DefaultValue", path)))
                } else {
                    None
                };
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::FindInMap(map_name_ref, k1, k2, default_ref)),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_SPLIT => {
                let arr = match val.as_array() {
                    Some(a) => a,
                    None => {
                        self.intrinsic_error(FN_SPLIT, "Fn::Split value must be an array");
                        return None;
                    }
                };
                if arr.len() != 2 {
                    self.intrinsic_error(
                        FN_SPLIT,
                        &format!("Fn::Split requires exactly 2 elements, got {}", arr.len()),
                    );
                    return None;
                }
                if !arr[0].is_string() && !arr[0].is_object() {
                    self.intrinsic_type_error(FN_SPLIT, "Fn::Split delimiter must be a string");
                }
                let delim = self.build_value(&arr[0], &format!("{}/Fn::Split/0", path));
                let src = self.build_value(&arr[1], &format!("{}/Fn::Split/1", path));
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::Split(delim, src)),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_BASE64 => {
                let child = self.build_value(val, &format!("{}/Fn::Base64", path));
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::Base64(child)),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_CIDR => {
                let arr = match val.as_array() {
                    Some(a) => a,
                    None => {
                        self.intrinsic_error(FN_CIDR, "Fn::Cidr value must be an array");
                        return None;
                    }
                };
                if arr.len() != 3 {
                    self.intrinsic_error(FN_CIDR, &format!("Fn::Cidr requires exactly 3 elements, got {}", arr.len()));
                    return None;
                }
                if let Some(n) = arr[1].as_i64()
                    && (!(1..=256).contains(&n))
                {
                    self.intrinsic_type_error(FN_CIDR, "Fn::Cidr count (second element) must be between 1 and 256");
                }
                if let Some(n) = arr[2].as_i64()
                    && (!(1..=128).contains(&n))
                {
                    self.intrinsic_type_error(FN_CIDR, "Fn::Cidr cidrBits (third element) must be between 1 and 128");
                }
                let a = self.build_value(&arr[0], &format!("{}/Fn::Cidr/0", path));
                let b = self.build_value(&arr[1], &format!("{}/Fn::Cidr/1", path));
                let c = self.build_value(&arr[2], &format!("{}/Fn::Cidr/2", path));
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::Cidr(a, b, c)),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_GET_AZS => {
                let child = self.build_value(val, &format!("{}/Fn::GetAZs", path));
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::GetAZs(child)),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_IMPORT_VALUE => {
                let child = self.build_value(val, &format!("{}/Fn::ImportValue", path));
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::ImportValue(child)),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_TRANSFORM => {
                let obj = match val.as_object() {
                    Some(o) => o,
                    None => {
                        self.intrinsic_error(FN_TRANSFORM, "Fn::Transform value must be an object");
                        return None;
                    }
                };
                let name_val = match obj.get("Name") {
                    Some(v) => v,
                    None => {
                        self.intrinsic_error(FN_TRANSFORM, "Fn::Transform requires a 'Name' property");
                        return None;
                    }
                };
                let name = match name_val.as_str() {
                    Some(s) => s.to_string(),
                    None => {
                        self.intrinsic_error(FN_TRANSFORM, "Fn::Transform 'Name' must be a string");
                        return None;
                    }
                };
                let params = if let Some(serde_json::Value::Object(p)) = obj.get("Parameters") {
                    p.iter()
                        .map(|(k, v)| {
                            let p2 = format!("{}/Fn::Transform/Parameters/{}", path, k);
                            let r = self.build_value(v, &p2);
                            (k.clone(), r)
                        })
                        .collect()
                } else {
                    vec![]
                };
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::Transform(name, params)),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_AND => {
                let arr = match val.as_array() {
                    Some(a) => a,
                    None => {
                        self.condition_fn_error(
                            FN_AND,
                            &format!("{} is not of type 'array'", describe_json_value(val)),
                        );
                        return None;
                    }
                };
                if arr.len() < 2 {
                    self.condition_fn_error(FN_AND, &format!("expected minimum item count: 2, found: {}", arr.len()));
                    return None;
                }
                if arr.len() > 10 {
                    self.condition_fn_error(FN_AND, &format!("expected maximum item count: 10, found: {}", arr.len()));
                    return None;
                }
                for (idx, elem) in arr.iter().enumerate() {
                    if let Some(reason) = condition_element_error(elem) {
                        self.condition_fn_error(FN_AND, &format!("element {}: {}", idx, reason));
                    }
                }
                let children: Vec<NodeRef> = arr
                    .iter()
                    .enumerate()
                    .map(|(i, v)| self.build_value(v, &format!("{}/{}/{}", path, FN_AND, i)))
                    .collect();
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::And(children)),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_OR => {
                let arr = match val.as_array() {
                    Some(a) => a,
                    None => {
                        self.condition_fn_error(FN_OR, &format!("{} is not of type 'array'", describe_json_value(val)));
                        return None;
                    }
                };
                if arr.len() < 2 {
                    self.condition_fn_error(FN_OR, &format!("expected minimum item count: 2, found: {}", arr.len()));
                    return None;
                }
                if arr.len() > 10 {
                    self.condition_fn_error(FN_OR, &format!("expected maximum item count: 10, found: {}", arr.len()));
                    return None;
                }
                for (idx, elem) in arr.iter().enumerate() {
                    if let Some(reason) = condition_element_error(elem) {
                        self.condition_fn_error(FN_OR, &format!("element {}: {}", idx, reason));
                    }
                }
                let children: Vec<NodeRef> = arr
                    .iter()
                    .enumerate()
                    .map(|(i, v)| self.build_value(v, &format!("{}/{}/{}", path, FN_OR, i)))
                    .collect();
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::Or(children)),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_NOT => {
                let arr = match val.as_array() {
                    Some(a) => a,
                    None => {
                        self.condition_fn_error(
                            FN_NOT,
                            &format!("{} is not of type 'array'", describe_json_value(val)),
                        );
                        return None;
                    }
                };
                if arr.len() != 1 {
                    self.condition_fn_error(FN_NOT, &format!("must have exactly 1 element, got {}", arr.len()));
                    return None;
                }
                if let Some(reason) = condition_element_error(&arr[0]) {
                    self.condition_fn_error(FN_NOT, &format!("element 0: {}", reason));
                }
                let child = self.build_value(&arr[0], &format!("{}/{}/0", path, FN_NOT));
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::Not(child)),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_EQUALS => {
                let arr = match val.as_array() {
                    Some(a) => a,
                    None => {
                        self.condition_fn_error(
                            FN_EQUALS,
                            &format!("{} is not of type 'array'", describe_json_value(val)),
                        );
                        return None;
                    }
                };
                if arr.len() != 2 {
                    let bound = if arr.len() < 2 { "minimum" } else { "maximum" };
                    self.condition_fn_error(
                        FN_EQUALS,
                        &format!("expected {} item count: 2, found: {}", bound, arr.len()),
                    );
                    return None;
                }
                for (idx, elem) in arr.iter().enumerate() {
                    if let Some(reason) = equals_argument_error(elem) {
                        self.condition_fn_error(FN_EQUALS, &format!("argument {}: {}", idx, reason));
                    }
                }
                let a = self.build_value(&arr[0], &format!("{}/{}/0", path, FN_EQUALS));
                let b = self.build_value(&arr[1], &format!("{}/{}/1", path, FN_EQUALS));
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::Equals(a, b)),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_TO_JSON_STRING => {
                let child = self.build_value(val, &format!("{}/Fn::ToJsonString", path));
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::ToJsonString(child)),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_LENGTH => {
                let child = self.build_value(val, &format!("{}/Fn::Length", path));
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::Length(child)),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_FOR_EACH => {
                let arr = match val.as_array() {
                    Some(a) => a,
                    None => {
                        self.intrinsic_error(FN_FOR_EACH, "Fn::ForEach value must be an array");
                        return None;
                    }
                };
                if arr.len() != 4 {
                    self.intrinsic_error(
                        FN_FOR_EACH,
                        &format!("Fn::ForEach requires exactly 4 elements, got {}", arr.len()),
                    );
                    return None;
                }
                let unique_id = match arr[0].as_str() {
                    Some(s) => s.to_string(),
                    None => {
                        self.intrinsic_error(FN_FOR_EACH, "Fn::ForEach first element must be a string");
                        return None;
                    }
                };
                let identifier = match arr[1].as_str() {
                    Some(s) => s.to_string(),
                    None => {
                        self.intrinsic_error(FN_FOR_EACH, "Fn::ForEach second element must be a string");
                        return None;
                    }
                };
                let collection = self.build_value(&arr[2], &format!("{}/Fn::ForEach/2", path));
                let body = self.build_value(&arr[3], &format!("{}/Fn::ForEach/3", path));
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::ForEach(unique_id, identifier, collection, body)),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_VALUE_OF => {
                let arr = match val.as_array() {
                    Some(a) => a,
                    None => {
                        self.intrinsic_error(FN_VALUE_OF, "Fn::ValueOf value must be an array");
                        return None;
                    }
                };
                if arr.len() != 2 {
                    self.intrinsic_error(
                        FN_VALUE_OF,
                        &format!("Fn::ValueOf requires exactly 2 elements, got {}", arr.len()),
                    );
                    return None;
                }
                let first = match arr[0].as_str() {
                    Some(s) => s.to_string(),
                    None => {
                        self.intrinsic_error(FN_VALUE_OF, "Fn::ValueOf first element must be a string");
                        return None;
                    }
                };
                let second = match arr[1].as_str() {
                    Some(s) => s.to_string(),
                    None => {
                        self.intrinsic_error(FN_VALUE_OF, "Fn::ValueOf second element must be a string");
                        return None;
                    }
                };
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::ValueOf(first, second)),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_VALUE_OF_ALL => {
                let arr = match val.as_array() {
                    Some(a) => a,
                    None => {
                        self.intrinsic_error(FN_VALUE_OF_ALL, "Fn::ValueOfAll value must be an array");
                        return None;
                    }
                };
                if arr.len() != 2 {
                    self.intrinsic_error(
                        FN_VALUE_OF_ALL,
                        &format!("Fn::ValueOfAll requires exactly 2 elements, got {}", arr.len()),
                    );
                    return None;
                }
                let first = match arr[0].as_str() {
                    Some(s) => s.to_string(),
                    None => {
                        self.intrinsic_error(FN_VALUE_OF_ALL, "Fn::ValueOfAll first element must be a string");
                        return None;
                    }
                };
                let second = match arr[1].as_str() {
                    Some(s) => s.to_string(),
                    None => {
                        self.intrinsic_error(FN_VALUE_OF_ALL, "Fn::ValueOfAll second element must be a string");
                        return None;
                    }
                };
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::ValueOfAll(first, second)),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_REF_ALL => {
                let s = match val.as_str() {
                    Some(s) => s.to_string(),
                    None => {
                        self.intrinsic_error(FN_REF_ALL, "Fn::RefAll value must be a string");
                        return None;
                    }
                };
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::RefAll(s)),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_CONTAINS => {
                let arr = match val.as_array() {
                    Some(a) => a,
                    None => {
                        self.intrinsic_error(FN_CONTAINS, "Fn::Contains value must be an array");
                        return None;
                    }
                };
                if arr.len() != 2 {
                    self.intrinsic_error(
                        FN_CONTAINS,
                        &format!("Fn::Contains requires exactly 2 elements, got {}", arr.len()),
                    );
                    return None;
                }
                let a = self.build_value(&arr[0], &format!("{}/Fn::Contains/0", path));
                let b = self.build_value(&arr[1], &format!("{}/Fn::Contains/1", path));
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::Contains(a, b)),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_EACH_MEMBER_EQUALS => {
                let arr = match val.as_array() {
                    Some(a) => a,
                    None => {
                        self.intrinsic_error(FN_EACH_MEMBER_EQUALS, "Fn::EachMemberEquals value must be an array");
                        return None;
                    }
                };
                if arr.len() != 2 {
                    self.intrinsic_error(
                        FN_EACH_MEMBER_EQUALS,
                        &format!("Fn::EachMemberEquals requires exactly 2 elements, got {}", arr.len()),
                    );
                    return None;
                }
                let a = self.build_value(&arr[0], &format!("{}/Fn::EachMemberEquals/0", path));
                let b = self.build_value(&arr[1], &format!("{}/Fn::EachMemberEquals/1", path));
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::EachMemberEquals(a, b)),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            FN_EACH_MEMBER_IN => {
                let arr = match val.as_array() {
                    Some(a) => a,
                    None => {
                        self.intrinsic_error(FN_EACH_MEMBER_IN, "Fn::EachMemberIn value must be an array");
                        return None;
                    }
                };
                if arr.len() != 2 {
                    self.intrinsic_error(
                        FN_EACH_MEMBER_IN,
                        &format!("Fn::EachMemberIn requires exactly 2 elements, got {}", arr.len()),
                    );
                    return None;
                }
                let a = self.build_value(&arr[0], &format!("{}/Fn::EachMemberIn/0", path));
                let b = self.build_value(&arr[1], &format!("{}/Fn::EachMemberIn/1", path));
                Some(self.arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::EachMemberIn(a, b)),
                    span: UNKNOWN_SPAN,
                    path: path.to_string(),
                }))
            }
            _ => None,
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

    let obj = value.as_object().ok_or_else(|| ParseError {
        message: "Template root must be a JSON object".into(),
        line: Some(1),
        column: Some(1),
    })?;

    let mut builder = JsonBuilder {
        arena: Arena::new(),
        global_index: GlobalIndex::new(),
        span_index: SourceSpanIndex::new(),
        diagnostics: detect_duplicate_keys(bytes),
    };

    let root = builder.build_map(obj, "");

    let parameters = builder.arena.map_get(root, SECTION_PARAMETERS).unwrap_or(NULL_REF);
    let mappings = builder.arena.map_get(root, SECTION_MAPPINGS).unwrap_or(NULL_REF);
    let conditions = builder.arena.map_get(root, SECTION_CONDITIONS).unwrap_or(NULL_REF);
    let resources = builder.arena.map_get(root, SECTION_RESOURCES).unwrap_or(NULL_REF);
    let outputs = builder.arena.map_get(root, SECTION_OUTPUTS).unwrap_or(NULL_REF);
    let rules = builder.arena.map_get(root, SECTION_RULES).unwrap_or(NULL_REF);
    let template_metadata = builder.arena.map_get(root, SECTION_METADATA).unwrap_or(NULL_REF);
    let globals = builder.arena.map_get(root, SECTION_GLOBALS).unwrap_or(NULL_REF);

    let format_version = builder
        .arena
        .map_get(root, SECTION_FORMAT_VERSION)
        .and_then(|r| builder.arena.as_str(r).map(|s| s.to_string()));

    let description =
        builder.arena.map_get(root, SECTION_DESCRIPTION).and_then(|r| builder.arena.as_str(r).map(|s| s.to_string()));

    let transforms = extract_transforms(&builder.arena, root);
    let raw_top_level_keys =
        builder.arena.as_map(root).map(|entries| entries.iter().map(|(k, _)| k.clone()).collect()).unwrap_or_default();

    debug!(
        "JSON IR built: {} resources, {} parameters, {} mappings, {} conditions, {} outputs, {} span index entries",
        builder.arena.as_map(resources).map(|m| m.len()).unwrap_or(0),
        builder.arena.as_map(parameters).map(|m| m.len()).unwrap_or(0),
        builder.arena.as_map(mappings).map(|m| m.len()).unwrap_or(0),
        builder.arena.as_map(conditions).map(|m| m.len()).unwrap_or(0),
        builder.arena.as_map(outputs).map(|m| m.len()).unwrap_or(0),
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

fn extract_transforms(arena: &Arena, root: NodeRef) -> Vec<String> {
    let Some(t_ref) = arena.map_get(root, SECTION_TRANSFORM) else {
        return vec![];
    };
    match arena.node(t_ref) {
        Node::String(s) => vec![s.clone()],
        Node::List(items) => items.iter().filter_map(|r| arena.as_str(*r).map(|s| s.to_string())).collect(),
        _ => vec![],
    }
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

    /// Genuinely-invalid input still produces F0014 — bare strings and
    /// non-boolean-producing intrinsics like Fn::Sub remain rejected.
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
