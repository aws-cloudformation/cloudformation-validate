//! Format-agnostic IR construction shared by the JSON and YAML front-ends.
//!
//! [`Builder`] walks a [`ParseValue`] tree (a `serde_json::Value` or a `Yaml`) and
//! produces arena [`Node`]s, recognizing CloudFormation intrinsic functions. Both
//! parsers funnel through this one implementation, so JSON and YAML cannot diverge
//! on which intrinsics they accept, what they reject, or what diagnostics they emit.
//!
//! Diagnostic spans are filled in later from source-position scans (JSON byte scan,
//! YAML marker tracking), so every node is allocated with `UNKNOWN_SPAN` here.

use crate::consts::*;
use crate::ir::*;
use crate::parser::value::{ParseValue, ValueKind};

/// Shared mutable state accumulated while building the IR.
pub struct Builder {
    pub arena: Arena,
    pub global_index: GlobalIndex,
    pub span_index: SourceSpanIndex,
    pub diagnostics: Vec<Diagnostic>,
}

impl Builder {
    pub fn new() -> Self {
        Self {
            arena: Arena::new(),
            global_index: GlobalIndex::new(),
            span_index: SourceSpanIndex::new(),
            diagnostics: Vec::new(),
        }
    }

    fn alloc(&mut self, node: Node, path: &str) -> NodeRef {
        self.arena.alloc(SpannedNode { node, span: UNKNOWN_SPAN, path: path.to_string() })
    }

    /// The anchor path for a diagnostic on an intrinsic node: the function key
    /// under the builder path, or the bare function name at the template root.
    fn intrinsic_anchor(path: &str, fn_name: &str) -> String {
        if path.is_empty() { fn_name.to_string() } else { format!("{}/{}", path, fn_name) }
    }

    /// A structural defect CloudFormation rejects at deploy time (fatal). The
    /// message is prefixed with the function name, so callers pass only the
    /// reason. Anchored at the function node so downstream span and entity
    /// resolution can attribute it.
    fn structural_error(&mut self, fn_name: &str, reason: &str, path: &str) {
        self.diagnostics.push(crate::make_parse_diagnostic_at(
            "F1101",
            format!("{}: {}", fn_name, reason),
            UNKNOWN_SPAN,
            &Self::intrinsic_anchor(path, fn_name),
        ));
    }

    /// An intrinsic argument has the wrong scalar type, but the template is not
    /// structurally rejected (warning). Prefixed with the function name and
    /// anchored at the function node.
    fn type_warning(&mut self, fn_name: &str, reason: &str, path: &str) {
        self.diagnostics.push(crate::make_parse_diagnostic_at(
            "W1102",
            format!("{}: {}", fn_name, reason),
            UNKNOWN_SPAN,
            &Self::intrinsic_anchor(path, fn_name),
        ));
    }

    /// `Fn::Sub`'s second argument must be a variable map (fatal).
    fn sub_map_error(&mut self, path: &str) {
        self.diagnostics.push(crate::make_parse_diagnostic_at(
            "F0010",
            "Fn::Sub second argument must be a map with string keys".to_string(),
            UNKNOWN_SPAN,
            &format!("{}/1", Self::intrinsic_anchor(path, FN_SUB)),
        ));
    }

    /// A malformed boolean condition function — `Fn::And`/`Or`/`Not`/`Equals`
    /// (fatal). Anchored at the function node so it lands where a property-level
    /// error would.
    fn condition_fn_error(&mut self, fn_name: &str, reason: &str, path: &str) {
        self.diagnostics.push(crate::make_parse_diagnostic_at(
            "F0014",
            format!("{}: {}", fn_name, reason),
            UNKNOWN_SPAN,
            &format!("{}/{}", path, fn_name),
        ));
    }

    /// A malformed `Fn::GetStackOutput` argument (error). No function-name prefix —
    /// the message uses standard JSON-Schema wording.
    /// Anchored at `at_path` (the function node, or a specific offending key) so it
    /// lands exactly where the offending value is written.
    fn get_stack_output_error(&mut self, message: String, at_path: &str) {
        self.diagnostics.push(crate::make_parse_diagnostic_at("E1033", message, UNKNOWN_SPAN, at_path));
    }

    /// A malformed `Fn::If` (fatal). Anchored at the `Fn::If` node.
    fn fn_if_error(&mut self, reason: &str, path: &str) {
        self.diagnostics.push(crate::make_parse_diagnostic_at(
            "F0013",
            format!("{}: {}", FN_IF, reason),
            UNKNOWN_SPAN,
            &format!("{}/{}", path, FN_IF),
        ));
    }

    /// Builds the arena node for any value, recognizing intrinsics in single-key maps.
    pub fn build<V: ParseValue>(&mut self, val: &V, path: &str) -> NodeRef {
        match val.kind() {
            ValueKind::Array => {
                let items = val.as_array().unwrap_or_default();
                let children: Vec<NodeRef> =
                    items.iter().enumerate().map(|(i, child)| self.build(child, &format!("{}/{}", path, i))).collect();
                self.alloc(Node::List(children), path)
            }
            ValueKind::Object => self.build_map(val, path),
            _ => self.alloc(val.scalar_node(), path),
        }
    }

    /// Builds an object node, first attempting to recognize a single-key intrinsic.
    pub fn build_map<V: ParseValue>(&mut self, val: &V, path: &str) -> NodeRef {
        let entries = val.as_object().unwrap_or_default();
        if entries.len() == 1
            && let Some(node) = self.try_intrinsic(&entries[0].0, &entries[0].1, path)
        {
            return node;
        }

        let built: Vec<(String, NodeRef)> = entries
            .iter()
            .map(|(key, child)| {
                let child_path = if path.is_empty() { key.clone() } else { format!("{}/{}", path, key) };
                let child_ref = self.build(child, &child_path);
                self.global_index.insert(child_path.clone(), child_ref);
                self.span_index.entry(child_path).or_insert(UNKNOWN_SPAN);
                (key.clone(), child_ref)
            })
            .collect();
        self.alloc(Node::Map(built), path)
    }

    /// Recognizes `key` as a CloudFormation intrinsic and builds its node, or returns
    /// `None` to fall through to a plain map. `None` is also returned for malformed
    /// uses that downstream rules report with better resource context (so the node is
    /// kept as a plain map) — those cases are commented inline.
    fn try_intrinsic<V: ParseValue>(&mut self, key: &str, val: &V, path: &str) -> Option<NodeRef> {
        let intrinsic = match key {
            FN_REF => IntrinsicFn::Ref(self.required_string(val, FN_REF, path)?),
            FN_GET_ATT => self.build_get_att(val, path)?,
            FN_SUB => self.build_sub(val, path)?,
            // Join rejects a scalar value (it requires an array); Select stays
            // silent on a non-list value, which is reported downstream once the
            // value resolves.
            FN_JOIN => {
                self.build_two_arg_pair(val, path, FN_JOIN, true, Self::check_join_delimiter, IntrinsicFn::Join)?
            }
            FN_SELECT => {
                self.build_two_arg_pair(val, path, FN_SELECT, false, Self::check_select_index, IntrinsicFn::Select)?
            }
            FN_IF => return self.build_if(val, path),
            FN_FIND_IN_MAP => self.build_find_in_map(val, path)?,
            FN_SPLIT => self.build_split(val, path)?,
            FN_BASE64 => IntrinsicFn::Base64(self.build(val, &format!("{}/{}", path, FN_BASE64))),
            FN_CIDR => self.build_cidr(val, path)?,
            FN_GET_AZS => IntrinsicFn::GetAZs(self.build(val, &format!("{}/{}", path, FN_GET_AZS))),
            FN_IMPORT_VALUE => IntrinsicFn::ImportValue(self.build(val, &format!("{}/{}", path, FN_IMPORT_VALUE))),
            FN_GET_STACK_OUTPUT => self.build_get_stack_output(val, path)?,
            FN_TRANSFORM => self.build_transform(val, path)?,
            FN_AND => self.build_bool_list(val, path, FN_AND, 2, 10, IntrinsicFn::And)?,
            FN_OR => self.build_bool_list(val, path, FN_OR, 2, 10, IntrinsicFn::Or)?,
            FN_NOT => self.build_not(val, path)?,
            FN_EQUALS => self.build_equals(val, path)?,
            FN_TO_JSON_STRING => IntrinsicFn::ToJsonString(self.build(val, &format!("{}/{}", path, FN_TO_JSON_STRING))),
            FN_LENGTH => IntrinsicFn::Length(self.build(val, &format!("{}/{}", path, FN_LENGTH))),
            FN_FOR_EACH => self.build_for_each(val, path)?,
            FN_VALUE_OF => self.build_value_of(val, FN_VALUE_OF, IntrinsicFn::ValueOf, path)?,
            FN_VALUE_OF_ALL => self.build_value_of(val, FN_VALUE_OF_ALL, IntrinsicFn::ValueOfAll, path)?,
            FN_REF_ALL => IntrinsicFn::RefAll(self.required_string(val, FN_REF_ALL, path)?),
            FN_CONTAINS => self.build_strict_pair(val, path, FN_CONTAINS, IntrinsicFn::Contains)?,
            FN_EACH_MEMBER_EQUALS => {
                self.build_strict_pair(val, path, FN_EACH_MEMBER_EQUALS, IntrinsicFn::EachMemberEquals)?
            }
            FN_EACH_MEMBER_IN => self.build_strict_pair(val, path, FN_EACH_MEMBER_IN, IntrinsicFn::EachMemberIn)?,
            FN_CONDITION => {
                IntrinsicFn::Ref(format!("{}{}", CONDITION_REF_PREFIX, self.required_string(val, FN_CONDITION, path)?))
            }
            _ => {
                if key.starts_with(FN_PREFIX) && !key.starts_with(FN_FOR_EACH_KEY_PREFIX) {
                    self.diagnostics.push(crate::make_parse_diagnostic_at(
                        "W1103",
                        format!("'{}' is not a supported function", key),
                        UNKNOWN_SPAN,
                        &format!("{}/{}", path, key),
                    ));
                }
                return None;
            }
        };
        Some(self.alloc(Node::Intrinsic(intrinsic), path))
    }

    /// Coerces `val` to a string for a required-string argument, emitting a fatal
    /// structural error if it is a non-scalar. An object value yields `None`
    /// *without* a diagnostic so a wrapping intrinsic (e.g. `Ref` whose value is an
    /// `Fn::Sub` under LanguageExtensions) falls through to a plain map and resolves
    /// dynamically.
    fn required_string<V: ParseValue>(&mut self, val: &V, fn_name: &str, path: &str) -> Option<String> {
        match val.as_coerced_str() {
            Some(s) => Some(s),
            None => {
                if !val.is_object() {
                    self.structural_error(fn_name, &format!("{} value must be a string", fn_name), path);
                }
                None
            }
        }
    }

    fn build_get_att<V: ParseValue>(&mut self, val: &V, path: &str) -> Option<IntrinsicFn> {
        const MSG: &str = "Fn::GetAtt value must be a two-element string array or a dotted string";
        match val.kind() {
            ValueKind::Array => {
                let arr = val.as_array().unwrap_or_default();
                if arr.len() != 2 {
                    self.structural_error(FN_GET_ATT, MSG, path);
                    return None;
                }
                // An object element is a dynamic resource/attribute name (e.g. Fn::Sub
                // in ForEach); fall through to a plain map rather than reject.
                let resource = self.getatt_segment(&arr[0], path)?;
                let attr = self.getatt_segment(&arr[1], path)?;
                Some(IntrinsicFn::GetAtt(resource, attr))
            }
            ValueKind::String => {
                let s = val.as_coerced_str().unwrap_or_default();
                match s.split_once('.') {
                    Some((resource, attr)) => Some(IntrinsicFn::GetAtt(resource.to_string(), attr.to_string())),
                    None => {
                        self.structural_error(FN_GET_ATT, MSG, path);
                        None
                    }
                }
            }
            _ => {
                self.structural_error(FN_GET_ATT, MSG, path);
                None
            }
        }
    }

    /// One element of `Fn::GetAtt`'s array form: a string (coerced) names a
    /// resource/attribute; an object is dynamic (returns `None`, no diagnostic);
    /// anything else is rejected with a fatal structural error.
    fn getatt_segment<V: ParseValue>(&mut self, val: &V, path: &str) -> Option<String> {
        if val.is_object() {
            return None;
        }
        match val.as_coerced_str() {
            Some(s) => Some(s),
            None => {
                self.structural_error(
                    FN_GET_ATT,
                    "Fn::GetAtt value must be a two-element string array or a dotted string",
                    path,
                );
                None
            }
        }
    }

    fn build_sub<V: ParseValue>(&mut self, val: &V, path: &str) -> Option<IntrinsicFn> {
        const MSG: &str = "Fn::Sub value must be a string or a [string, object] array";
        match val.kind() {
            ValueKind::String => Some(IntrinsicFn::Sub(val.as_coerced_str().unwrap_or_default(), None)),
            ValueKind::Array => {
                let arr = val.as_array().unwrap_or_default();
                if arr.is_empty() {
                    self.structural_error(FN_SUB, MSG, path);
                    return None;
                }
                let Some(template) = arr[0].as_coerced_str() else {
                    self.structural_error(FN_SUB, MSG, path);
                    return None;
                };
                let subs = if arr.len() > 1 {
                    match arr[1].as_object() {
                        Some(entries) => Some(
                            entries
                                .iter()
                                .map(|(k, v)| {
                                    let r = self.build(v, &format!("{}/{}/1/{}", path, FN_SUB, k));
                                    (k.clone(), r)
                                })
                                .collect(),
                        ),
                        None => {
                            self.sub_map_error(path);
                            None
                        }
                    }
                } else {
                    None
                };
                Some(IntrinsicFn::Sub(template, subs))
            }
            // An object value is a wrapping intrinsic (e.g. Fn::Transform); fall
            // through to a plain map so it resolves dynamically.
            ValueKind::Object => None,
            _ => {
                self.structural_error(FN_SUB, MSG, path);
                None
            }
        }
    }

    /// `Fn::Join`/`Fn::Select`: exactly two arguments, each built as a child.
    /// `check` warns on the first argument's scalar type without rejecting the node.
    /// An object value is a dynamic wrapping intrinsic and always falls through to a
    /// plain map; wrong arity likewise falls through (both have dedicated downstream
    /// arity rules). A non-object, non-array scalar value is rejected as a fatal
    /// structural error only when `reject_scalar` is set (Join requires an array;
    /// Select's non-list value is reported later, when the value resolves).
    fn build_two_arg_pair<V: ParseValue>(
        &mut self,
        val: &V,
        path: &str,
        fn_name: &str,
        reject_scalar: bool,
        check: fn(&mut Self, &V, &str),
        ctor: fn(NodeRef, NodeRef) -> IntrinsicFn,
    ) -> Option<IntrinsicFn> {
        let Some(arr) = val.as_array() else {
            if reject_scalar && !val.is_object() {
                self.structural_error(fn_name, &format!("{} value must be an array", fn_name), path);
            }
            return None;
        };
        if arr.len() != 2 {
            return None;
        }
        check(self, &arr[0], path);
        let first = self.build(&arr[0], &format!("{}/{}/0", path, fn_name));
        let second = self.build(&arr[1], &format!("{}/{}/1", path, fn_name));
        Some(ctor(first, second))
    }

    /// `Fn::Contains`/`Fn::EachMemberEquals`/`Fn::EachMemberIn`: exactly two
    /// arguments. Unlike Join/Select these have no downstream arity rule, so a
    /// non-array value or wrong arity is rejected here as a fatal structural error.
    fn build_strict_pair<V: ParseValue>(
        &mut self,
        val: &V,
        path: &str,
        fn_name: &str,
        ctor: fn(NodeRef, NodeRef) -> IntrinsicFn,
    ) -> Option<IntrinsicFn> {
        let Some(arr) = val.as_array() else {
            self.structural_error(fn_name, &format!("{} value must be an array", fn_name), path);
            return None;
        };
        if arr.len() != 2 {
            self.structural_error(
                fn_name,
                &format!("{} requires exactly 2 elements, got {}", fn_name, arr.len()),
                path,
            );
            return None;
        }
        let first = self.build(&arr[0], &format!("{}/{}/0", path, fn_name));
        let second = self.build(&arr[1], &format!("{}/{}/1", path, fn_name));
        Some(ctor(first, second))
    }

    fn check_join_delimiter<V: ParseValue>(&mut self, first: &V, path: &str) {
        if !matches!(first.kind(), ValueKind::String | ValueKind::Object) {
            self.type_warning(FN_JOIN, "delimiter (first argument) must be a string or an intrinsic function", path);
        }
    }

    fn check_select_index<V: ParseValue>(&mut self, first: &V, path: &str) {
        // CloudFormation coerces a numeric string index — the official
        // Fn::Select documentation itself uses `"1"` — so only a value that is
        // neither a number, an intrinsic, nor an integer-valued string is
        // reported.
        let is_integer_string = matches!(first.kind(), ValueKind::String)
            && first.as_coerced_str().is_some_and(|s| crate::coercion::coerce_str_to_integer(&s).is_some());
        if !matches!(first.kind(), ValueKind::Number | ValueKind::Object) && !is_integer_string {
            self.type_warning(FN_SELECT, "index (first argument) must be an integer or an intrinsic function", path);
        }
    }

    fn build_if<V: ParseValue>(&mut self, val: &V, path: &str) -> Option<NodeRef> {
        let Some(arr) = val.as_array() else {
            let reason =
                if val.is_null() { "null".to_string() } else { format!("{} is not of type 'array'", val.describe()) };
            self.fn_if_error(&reason, path);
            return None;
        };
        if arr.len() != 3 {
            self.fn_if_error(&format!("must have exactly 3 elements, got {}", arr.len()), path);
            return None;
        }
        let if_true = self.build(&arr[1], &format!("{}/{}/1", path, FN_IF));
        let if_false = self.build(&arr[2], &format!("{}/{}/2", path, FN_IF));
        let intrinsic = match arr[0].as_coerced_str() {
            Some(cond) => IntrinsicFn::If(cond, if_true, if_false),
            None => {
                let cond_node = self.build(&arr[0], &format!("{}/{}/0", path, FN_IF));
                IntrinsicFn::IfExpr(cond_node, if_true, if_false)
            }
        };
        Some(self.alloc(Node::Intrinsic(intrinsic), path))
    }

    fn build_find_in_map<V: ParseValue>(&mut self, val: &V, path: &str) -> Option<IntrinsicFn> {
        let Some(arr) = val.as_array() else {
            self.structural_error(FN_FIND_IN_MAP, "Fn::FindInMap value must be an array", path);
            return None;
        };
        // 3-arg form, or 4-arg with a trailing { DefaultValue: ... }.
        if arr.len() != 3 && arr.len() != 4 {
            self.structural_error(
                FN_FIND_IN_MAP,
                &format!("Fn::FindInMap requires 3 or 4 elements, got {}", arr.len()),
                path,
            );
            return None;
        }
        let map_name = self.build(&arr[0], &format!("{}/{}/0", path, FN_FIND_IN_MAP));
        let k1 = self.build(&arr[1], &format!("{}/{}/1", path, FN_FIND_IN_MAP));
        let k2 = self.build(&arr[2], &format!("{}/{}/2", path, FN_FIND_IN_MAP));
        let default = if arr.len() == 4 {
            arr[3]
                .as_object()
                .and_then(|entries| entries.into_iter().find(|(k, _)| k == KEY_DEFAULT_VALUE))
                .map(|(_, dv)| self.build(&dv, &format!("{}/{}/3/{}", path, FN_FIND_IN_MAP, KEY_DEFAULT_VALUE)))
        } else {
            None
        };
        Some(IntrinsicFn::FindInMap(map_name, k1, k2, default))
    }

    fn build_split<V: ParseValue>(&mut self, val: &V, path: &str) -> Option<IntrinsicFn> {
        let Some(arr) = val.as_array() else {
            self.structural_error(FN_SPLIT, "Fn::Split value must be an array", path);
            return None;
        };
        if arr.len() != 2 {
            self.structural_error(FN_SPLIT, &format!("Fn::Split requires exactly 2 elements, got {}", arr.len()), path);
            return None;
        }
        if !matches!(arr[0].kind(), ValueKind::String | ValueKind::Object) {
            self.type_warning(FN_SPLIT, "delimiter (first argument) must be a string or an intrinsic function", path);
        }
        let delim = self.build(&arr[0], &format!("{}/{}/0", path, FN_SPLIT));
        let source = self.build(&arr[1], &format!("{}/{}/1", path, FN_SPLIT));
        Some(IntrinsicFn::Split(delim, source))
    }

    fn build_cidr<V: ParseValue>(&mut self, val: &V, path: &str) -> Option<IntrinsicFn> {
        let Some(arr) = val.as_array() else {
            self.structural_error(FN_CIDR, "Fn::Cidr value must be an array", path);
            return None;
        };
        if arr.len() != 3 {
            self.structural_error(FN_CIDR, &format!("Fn::Cidr requires exactly 3 elements, got {}", arr.len()), path);
            return None;
        }
        // CloudFormation bounds: count must be 1..=256, cidrBits 1..=128.
        if let Some(n) = arr[1].as_integer()
            && !(1..=256).contains(&n)
        {
            self.type_warning(FN_CIDR, "count (second argument) must be between 1 and 256", path);
        }
        if let Some(n) = arr[2].as_integer()
            && !(1..=128).contains(&n)
        {
            self.type_warning(FN_CIDR, "cidrBits (third argument) must be between 1 and 128", path);
        }
        let ip = self.build(&arr[0], &format!("{}/{}/0", path, FN_CIDR));
        let count = self.build(&arr[1], &format!("{}/{}/1", path, FN_CIDR));
        let bits = self.build(&arr[2], &format!("{}/{}/2", path, FN_CIDR));
        Some(IntrinsicFn::Cidr(ip, count, bits))
    }

    fn build_transform<V: ParseValue>(&mut self, val: &V, path: &str) -> Option<IntrinsicFn> {
        let Some(entries) = val.as_object() else {
            self.structural_error(FN_TRANSFORM, "Fn::Transform value must be an object", path);
            return None;
        };
        let Some((_, name_val)) = entries.iter().find(|(k, _)| k == KEY_NAME) else {
            self.structural_error(FN_TRANSFORM, "Fn::Transform requires a 'Name' property", path);
            return None;
        };
        // Name is strict: a macro name is genuinely a string, never coerced.
        let Some(name) = name_val.as_coerced_str().filter(|_| name_val.kind() == ValueKind::String) else {
            self.structural_error(FN_TRANSFORM, "Fn::Transform 'Name' must be a string", path);
            return None;
        };
        let params = entries
            .iter()
            .find(|(k, _)| k == SECTION_PARAMETERS)
            .and_then(|(_, v)| v.as_object())
            .map(|param_entries| {
                param_entries
                    .iter()
                    .map(|(k, v)| {
                        let r = self.build(v, &format!("{}/{}/{}/{}", path, FN_TRANSFORM, SECTION_PARAMETERS, k));
                        (k.clone(), r)
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(IntrinsicFn::Transform(name, params))
    }

    /// `Fn::GetStackOutput`: an object argument `{ StackName*, OutputName*,
    /// Region?, RoleArn? }`. The intrinsic node is built regardless so nested
    /// references still resolve; argument-shape violations (E1033) are reported
    /// only where the call is itself evaluated (see
    /// [`Self::is_get_stack_output_validation_position`]) — reporting elsewhere
    /// (e.g. inside another function, or in a parameter `Default`) would be a
    /// false positive.
    fn build_get_stack_output<V: ParseValue>(&mut self, val: &V, path: &str) -> Option<IntrinsicFn> {
        let fn_path = format!("{}/{}", path, FN_GET_STACK_OUTPUT);
        let report = self.is_get_stack_output_validation_position(path);

        let Some(entries) = val.as_object() else {
            // A non-object argument (string/number/…) cannot form the function; fall
            // through to a plain map, reporting the type mismatch where evaluated.
            if report {
                self.get_stack_output_error(format!("{} is not of type 'object'", val.describe()), &fn_path);
            }
            return None;
        };

        if report {
            for required in [KEY_STACK_NAME, KEY_OUTPUT_NAME] {
                if !entries.iter().any(|(k, _)| k == required) {
                    self.get_stack_output_error(format!("'{}' is a required property", required), &fn_path);
                }
            }
            for (key, _) in &entries {
                if ![KEY_STACK_NAME, KEY_OUTPUT_NAME, KEY_REGION, KEY_ROLE_ARN].contains(&key.as_str()) {
                    self.get_stack_output_error(
                        format!("Additional properties are not allowed ('{}' was unexpected)", key),
                        &format!("{}/{}", fn_path, key),
                    );
                }
            }
        }

        let args = entries.iter().map(|(k, v)| (k.clone(), self.build(v, &format!("{}/{}", fn_path, k)))).collect();
        Some(IntrinsicFn::GetStackOutput(args))
    }

    /// Whether `path` addresses a value written directly under a resource's
    /// `Properties` or `Metadata` (e.g. `Resources/R/Properties/Foo`, or a deeper
    /// property such as `Resources/R/Properties/Foo/0/Bar`), and is not nested
    /// inside another intrinsic. These are the positions where `Fn::GetStackOutput`
    /// has its argument shape validated; a use in a parameter `Default`, a
    /// condition, or as an argument to another function is validated (or coerced)
    /// by the surrounding construct instead, so E1033 must not fire there.
    fn is_get_stack_output_validation_position(&self, path: &str) -> bool {
        let mut segments = path.split('/');
        if segments.next() != Some(SECTION_RESOURCES) {
            return false;
        }
        // Skip the logical id.
        if segments.next().is_none() {
            return false;
        }
        if !matches!(segments.next(), Some(KEY_PROPERTIES | SECTION_METADATA)) {
            return false;
        }
        // No remaining segment may itself be an intrinsic key — that would mean the
        // call is an argument to another function, which owns the validation.
        !segments.any(|seg| seg.starts_with(FN_PREFIX) || seg == FN_REF || seg == FN_CONDITION)
    }

    /// `Fn::And` / `Fn::Or`: a bounded list of boolean condition expressions.
    fn build_bool_list<V: ParseValue>(
        &mut self,
        val: &V,
        path: &str,
        fn_name: &str,
        min: usize,
        max: usize,
        ctor: fn(Vec<NodeRef>) -> IntrinsicFn,
    ) -> Option<IntrinsicFn> {
        let Some(arr) = val.as_array() else {
            self.condition_fn_error(fn_name, &format!("{} is not of type 'array'", val.describe()), path);
            return None;
        };
        if arr.len() < min {
            self.condition_fn_error(
                fn_name,
                &format!("expected minimum item count: {}, found: {}", min, arr.len()),
                path,
            );
            return None;
        }
        if arr.len() > max {
            self.condition_fn_error(
                fn_name,
                &format!("expected maximum item count: {}, found: {}", max, arr.len()),
                path,
            );
            return None;
        }
        for (idx, elem) in arr.iter().enumerate() {
            if let Some(reason) = condition_element_error(elem) {
                self.condition_fn_error(fn_name, &format!("element {}: {}", idx, reason), path);
            }
        }
        let children: Vec<NodeRef> =
            arr.iter().enumerate().map(|(i, v)| self.build(v, &format!("{}/{}/{}", path, fn_name, i))).collect();
        Some(ctor(children))
    }

    fn build_not<V: ParseValue>(&mut self, val: &V, path: &str) -> Option<IntrinsicFn> {
        let Some(arr) = val.as_array() else {
            self.condition_fn_error(FN_NOT, &format!("{} is not of type 'array'", val.describe()), path);
            return None;
        };
        if arr.len() != 1 {
            self.condition_fn_error(FN_NOT, &format!("must have exactly 1 element, got {}", arr.len()), path);
            return None;
        }
        if let Some(reason) = condition_element_error(&arr[0]) {
            self.condition_fn_error(FN_NOT, &format!("element 0: {}", reason), path);
        }
        let child = self.build(&arr[0], &format!("{}/{}/0", path, FN_NOT));
        Some(IntrinsicFn::Not(child))
    }

    fn build_equals<V: ParseValue>(&mut self, val: &V, path: &str) -> Option<IntrinsicFn> {
        let Some(arr) = val.as_array() else {
            self.condition_fn_error(FN_EQUALS, &format!("{} is not of type 'array'", val.describe()), path);
            return None;
        };
        if arr.len() != 2 {
            let bound = if arr.len() < 2 { "minimum" } else { "maximum" };
            self.condition_fn_error(
                FN_EQUALS,
                &format!("expected {} item count: 2, found: {}", bound, arr.len()),
                path,
            );
            return None;
        }
        for (idx, elem) in arr.iter().enumerate() {
            if let Some(reason) = equals_argument_error(elem) {
                self.condition_fn_error(FN_EQUALS, &format!("argument {}: {}", idx, reason), path);
            }
        }
        let a = self.build(&arr[0], &format!("{}/{}/0", path, FN_EQUALS));
        let b = self.build(&arr[1], &format!("{}/{}/1", path, FN_EQUALS));
        Some(IntrinsicFn::Equals(a, b))
    }

    fn build_for_each<V: ParseValue>(&mut self, val: &V, path: &str) -> Option<IntrinsicFn> {
        let Some(arr) = val.as_array() else {
            self.structural_error(FN_FOR_EACH, "Fn::ForEach value must be an array", path);
            return None;
        };
        if arr.len() != 4 {
            self.structural_error(
                FN_FOR_EACH,
                &format!("Fn::ForEach requires exactly 4 elements, got {}", arr.len()),
                path,
            );
            return None;
        }
        let Some(unique_id) = arr[0].as_coerced_str() else {
            self.structural_error(FN_FOR_EACH, "Fn::ForEach first element must be a string", path);
            return None;
        };
        let Some(identifier) = arr[1].as_coerced_str() else {
            self.structural_error(FN_FOR_EACH, "Fn::ForEach second element must be a string", path);
            return None;
        };
        let collection = self.build(&arr[2], &format!("{}/{}/2", path, FN_FOR_EACH));
        let body = self.build(&arr[3], &format!("{}/{}/3", path, FN_FOR_EACH));
        Some(IntrinsicFn::ForEach(unique_id, identifier, collection, body))
    }

    fn build_value_of<V: ParseValue>(
        &mut self,
        val: &V,
        fn_name: &str,
        ctor: fn(String, String) -> IntrinsicFn,
        path: &str,
    ) -> Option<IntrinsicFn> {
        let Some(arr) = val.as_array() else {
            self.structural_error(fn_name, &format!("{} value must be an array", fn_name), path);
            return None;
        };
        if arr.len() != 2 {
            self.structural_error(
                fn_name,
                &format!("{} requires exactly 2 elements, got {}", fn_name, arr.len()),
                path,
            );
            return None;
        }
        let Some(first) = arr[0].as_coerced_str() else {
            self.structural_error(fn_name, &format!("{} first element must be a string", fn_name), path);
            return None;
        };
        let Some(second) = arr[1].as_coerced_str() else {
            self.structural_error(fn_name, &format!("{} second element must be a string", fn_name), path);
            return None;
        };
        Some(ctor(first, second))
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

/// The top-level section node references and scalar header fields, extracted once
/// from a built root map. Shared by both front-ends so section lookup and
/// `TemplateIR` assembly are not duplicated per format.
pub struct TemplateSections {
    pub parameters: NodeRef,
    pub mappings: NodeRef,
    pub conditions: NodeRef,
    pub resources: NodeRef,
    pub outputs: NodeRef,
    pub rules: NodeRef,
    pub template_metadata: NodeRef,
    pub globals: NodeRef,
    pub format_version: Option<String>,
    pub description: Option<String>,
    pub transforms: Vec<String>,
    pub raw_top_level_keys: Vec<String>,
}

impl TemplateSections {
    pub fn extract(arena: &Arena, root: NodeRef) -> Self {
        let section = |key: &str| arena.map_get(root, key).unwrap_or(NULL_REF);
        let header = |key: &str| arena.map_get(root, key).and_then(|r| arena.as_str(r).map(|s| s.to_string()));
        Self {
            parameters: section(SECTION_PARAMETERS),
            mappings: section(SECTION_MAPPINGS),
            conditions: section(SECTION_CONDITIONS),
            resources: section(SECTION_RESOURCES),
            outputs: section(SECTION_OUTPUTS),
            rules: section(SECTION_RULES),
            template_metadata: section(SECTION_METADATA),
            globals: section(SECTION_GLOBALS),
            format_version: header(SECTION_FORMAT_VERSION),
            description: header(SECTION_DESCRIPTION),
            transforms: extract_transforms(arena, root),
            raw_top_level_keys: arena
                .as_map(root)
                .map(|entries| entries.iter().map(|(k, _)| k.clone()).collect())
                .unwrap_or_default(),
        }
    }

    /// Assembles the final [`TemplateIR`], consuming the builder's accumulated arena,
    /// indexes, and diagnostics.
    pub fn into_ir(self, builder: Builder) -> TemplateIR {
        TemplateIR {
            arena: builder.arena,
            global_index: builder.global_index,
            span_index: builder.span_index,
            parameters: self.parameters,
            mappings: self.mappings,
            conditions: self.conditions,
            resources: self.resources,
            outputs: self.outputs,
            rules: self.rules,
            template_metadata: self.template_metadata,
            format_version: self.format_version,
            description: self.description,
            transforms: self.transforms,
            raw_top_level_keys: self.raw_top_level_keys,
            diagnostics: builder.diagnostics,
            globals: self.globals,
        }
    }
}

/// The `Transform` section is a single transform name or a list of them.
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

/// Returns `Some(reason)` if `val` is NOT a well-formed boolean condition element
/// (input to `Fn::And`/`Fn::Or`/`Fn::Not`): a single-key object keyed by `Condition`
/// or a boolean-producing intrinsic.
fn condition_element_error<V: ParseValue>(val: &V) -> Option<String> {
    if val.is_null() {
        return Some("null is not of type 'boolean'".to_string());
    }
    match val.single_key() {
        Some((key, _)) if BOOLEAN_FN_KEYS.contains(&key.as_str()) => None,
        _ => Some(format!("{} is not of type 'boolean'", val.describe())),
    }
}

/// Returns `Some(reason)` if `val` is NOT valid as an `Fn::Equals` argument: a
/// string/number/bool scalar, or a single-key object keyed by a value-producing
/// intrinsic.
fn equals_argument_error<V: ParseValue>(val: &V) -> Option<String> {
    if val.is_null() {
        return Some("null is not of type 'string'".to_string());
    }
    if matches!(val.kind(), ValueKind::String | ValueKind::Number | ValueKind::Bool) {
        return None;
    }
    match val.single_key() {
        Some((key, _)) if EQUALS_ARG_FN_KEYS.contains(&key.as_str()) => None,
        _ => Some(format!("{} is not of type 'string'", val.describe())),
    }
}
