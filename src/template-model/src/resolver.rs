use crate::coercion::type_compatible;
use crate::consts::*;
use crate::ir::*;
use crate::json_value::JsonValue;
use crate::message::render_str_list;
use crate::pattern::{default_matches_pattern, is_service_valid};
use crate::regions::*;
use base64::Engine as _;
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A property value after CloudFormation intrinsics (Ref, Fn::GetAtt, Fn::Sub, Fn::If, ...)
/// have been resolved as far as possible. Depending on how much can be known before
/// deployment, a value is fully concrete, a reference to another resource, one of several
/// possible values, conditional on a template condition, or opaque until deploy time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
pub enum ResolvedValue {
    /// A fully known literal value (string, number, boolean, list, or object).
    Concrete { value: JsonValue },
    /// A list whose elements are not all concrete; each element is itself a resolved value.
    #[cfg_attr(feature = "uniffi-bindings", uniffi(name = "ListValue"))]
    List { items: Vec<ResolvedValue> },
    /// A map whose entry values are not all concrete; each entry value is itself a resolved value.
    Map { entries: Vec<MapEntry> },
    /// One of several possible values, such as the AllowedValues of a parameter; each candidate is a resolved value.
    #[cfg_attr(feature = "uniffi-bindings", uniffi(name = "EnumValue"))]
    Enum { variants: Vec<ResolvedValue> },
    /// A value that depends on a template condition: `if_true` when the named condition holds, `if_false` otherwise.
    Conditional { condition: String, if_true: Box<ResolvedValue>, if_false: Box<ResolvedValue> },
    /// A reference to another resource (via Ref or Fn::GetAtt) rather than a concrete value.
    Reference { target: String, kind: RefKind },
    /// A value that cannot be known until deployment; `reason` is a human-readable explanation of why it is unresolved.
    Dynamic { reason: String },
    /// A value unknown until deployment but whose CloudFormation type is known; `param_type` is that type and `reason` explains why the value is unresolved.
    TypedDynamic { reason: String, param_type: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct MapEntry {
    pub key: String,
    pub value: ResolvedValue,
}

/// How one template item refers to another: a Ref, an Fn::GetAtt attribute lookup,
/// an Fn::Sub variable, or an explicit DependsOn.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RefKind {
    Ref,
    /// An Fn::GetAtt reference; `attr` is the referenced attribute name.
    GetAtt {
        attr: String,
    },
    /// An Fn::Sub reference; `var` is the substituted variable name.
    Sub {
        var: String,
    },
    DependsOn,
}

#[derive(Debug, Clone)]
pub struct ResolverEdge {
    pub source_resource: String,
    pub source_path: String,
    pub target: String,
    pub kind: RefKind,
    pub span: SourceSpan,
    pub condition_context: Option<String>,
}

/// A template Parameter's declaration: its type, constraints (allowed values/pattern,
/// length and value bounds), default, and description.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct ParameterInfo {
    /// The parameter's declared CloudFormation type (for example String, Number, or an AWS-specific type); defaults to String when the template omits Type.
    pub param_type: String,
    #[cfg_attr(feature = "wasm-bindings", tsify(optional))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub default: Option<String>,
    #[cfg_attr(feature = "wasm-bindings", tsify(optional))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub allowed_values: Option<Vec<String>>,
    #[cfg_attr(feature = "wasm-bindings", tsify(optional))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub allowed_pattern: Option<String>,
    #[cfg_attr(feature = "wasm-bindings", tsify(optional))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub min_length: Option<u64>,
    #[cfg_attr(feature = "wasm-bindings", tsify(optional))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub max_length: Option<u64>,
    #[cfg_attr(feature = "wasm-bindings", tsify(optional))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub min_value: Option<i64>,
    #[cfg_attr(feature = "wasm-bindings", tsify(optional))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub max_value: Option<i64>,
    #[cfg_attr(feature = "wasm-bindings", tsify(optional))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub description: Option<String>,
    /// Whether the parameter is declared with NoEcho, meaning its value is masked in CloudFormation output.
    pub no_echo: bool,
    /// Whether the AllowedPattern is a valid, supported regular expression; absent when no AllowedPattern is declared.
    #[cfg_attr(feature = "wasm-bindings", tsify(optional))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub allowed_pattern_valid: Option<bool>,
    /// Whether the Default value satisfies the AllowedPattern; absent unless both a Default and an AllowedPattern are declared.
    #[cfg_attr(feature = "wasm-bindings", tsify(optional))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub default_matches_allowed_pattern: Option<bool>,
}

pub type MappingData = HashMap<String, HashMap<String, HashMap<String, serde_json::Value>>>;

pub(crate) struct Resolver<'a> {
    arena: &'a Arena,
    parameters: &'a HashMap<String, ParameterInfo>,
    mappings: &'a MappingData,
    resource_ids: HashSet<String>,
    pub(crate) edges: Vec<ResolverEdge>,
    pub(crate) diagnostics: Vec<ParseDefect>,
    pub(crate) find_in_map_refs: HashMap<String, Vec<String>>,
    pub(crate) simple_subs: HashMap<String, Vec<(String, String)>>,
    pub(crate) redundant_subs: HashMap<String, Vec<String>>,
    pub(crate) empty_joins: HashMap<String, Vec<String>>,
    pub(crate) hardcoded_partition_arns: HashMap<String, Vec<String>>,
    pub(crate) foreach_expansions: HashMap<String, Vec<(String, String, String)>>,
    pub(crate) unsubstituted_variables: HashMap<String, Vec<(String, String)>>,
    pub(crate) unused_sub_keys: HashMap<String, Vec<(String, String)>>,
    pub(crate) raw_pseudo_params: HashMap<String, Vec<(String, String)>>,
    pub(crate) secretsmanager_ref_paths: HashMap<String, Vec<String>>,
    pub(crate) invalid_refs: HashMap<String, Vec<(String, String)>>,
    pub(crate) extra_condition_refs: HashMap<String, Vec<String>>,
    pub(crate) inline_conditions: Vec<(String, crate::conditions::ConditionExpr)>,
    resolution_source_map: HashMap<(String, String), String>, // (resource_id, property_path) → source description
    /// (resource_id, property_path) → the authored expression behind a value that
    /// stayed opaque, used to establish whether two such values are one value.
    value_node_map: HashMap<(String, String), NodeRef>,
    parameter_overrides: &'a HashMap<String, String>,
    pseudo_parameter_overrides: &'a crate::model::PseudoParameterOverrides,

    pub(crate) current_resource: Option<String>,
    condition_stack: Vec<(String, bool)>, // (condition_name, is_true_branch)
    current_path: String,
    depth: u32,
    local_bindings: HashMap<String, ResolvedValue>,
    /// Per-resource `DefinitionSubstitutions` keys: a `${var}` placeholder in a
    /// Step Functions definition is legitimate exactly when `var` is one of the
    /// resource's substitution keys.
    pub(crate) def_subs_resources: HashMap<String, HashSet<String>>,
}

impl<'a> Resolver<'a> {
    pub fn new(
        arena: &'a Arena,
        parameters: &'a HashMap<String, ParameterInfo>,
        mappings: &'a MappingData,
        resource_ids: HashSet<String>,
        parameter_overrides: &'a HashMap<String, String>,
        pseudo_parameter_overrides: &'a crate::model::PseudoParameterOverrides,
    ) -> Self {
        Self {
            arena,
            parameters,
            mappings,
            resource_ids,
            edges: Vec::new(),
            diagnostics: Vec::new(),
            find_in_map_refs: HashMap::new(),
            simple_subs: HashMap::new(),
            redundant_subs: HashMap::new(),
            empty_joins: HashMap::new(),
            hardcoded_partition_arns: HashMap::new(),
            foreach_expansions: HashMap::new(),
            unsubstituted_variables: HashMap::new(),
            unused_sub_keys: HashMap::new(),
            raw_pseudo_params: HashMap::new(),
            secretsmanager_ref_paths: HashMap::new(),
            invalid_refs: HashMap::new(),
            extra_condition_refs: HashMap::new(),
            inline_conditions: Vec::new(),
            resolution_source_map: HashMap::new(),
            value_node_map: HashMap::new(),
            parameter_overrides,
            pseudo_parameter_overrides,

            current_resource: None,
            condition_stack: Vec::new(),
            current_path: String::new(),
            depth: 0,
            local_bindings: HashMap::new(),
            def_subs_resources: HashMap::new(),
        }
    }

    pub fn resolution_sources(&self) -> HashMap<(String, String), String> {
        self.resolution_source_map.clone()
    }

    pub fn value_nodes(&self) -> HashMap<(String, String), NodeRef> {
        self.value_node_map.clone()
    }

    pub fn resolve_node(&mut self, node_ref: NodeRef) -> ResolvedValue {
        if node_ref == NULL_REF {
            warn!("Attempted to resolve NULL_REF node at path '{}'", self.current_path);
            return ResolvedValue::Dynamic { reason: "null reference".into() };
        }
        if self.depth >= MAX_RESOLVE_DEPTH {
            warn!("Recursion depth limit ({}) exceeded at path '{}'", MAX_RESOLVE_DEPTH, self.current_path);
            return ResolvedValue::Dynamic { reason: "recursion limit exceeded".into() };
        }
        self.depth += 1;
        let result = self.resolve_node_inner(node_ref);
        self.depth -= 1;
        let result = opaque_if_dynamic_reference(result);
        // A value that stays opaque carries no contents to compare, so the
        // expression that produced it is kept: it is the only thing that can
        // later show whether two such values are the same value. A value that
        // resolved to contents needs no such record.
        if !matches!(result, ResolvedValue::Concrete { value: _ })
            && let Some(ref resource_id) = self.current_resource
        {
            self.value_node_map.insert((resource_id.clone(), self.current_path.clone()), node_ref);
        }
        result
    }

    fn resolve_node_inner(&mut self, node_ref: NodeRef) -> ResolvedValue {
        let spanned = self.arena.get(node_ref);
        let span = spanned.span;
        match &spanned.node {
            Node::Null => ResolvedValue::Concrete { value: serde_json::Value::Null.into() },
            Node::Bool(b) => ResolvedValue::Concrete { value: serde_json::Value::Bool(*b).into() },
            Node::Int(i) => ResolvedValue::Concrete { value: serde_json::json!(*i).into() },
            Node::Float(f) => ResolvedValue::Concrete { value: serde_json::json!(*f).into() },
            Node::String(s) => {
                // Embedded dynamic references (`{{resolve:...}}`, even mid-string or
                // produced by Sub/Join/Select) are collapsed to a deploy-time-opaque
                // value centrally in `resolve_node`, so no per-node guard is needed here.
                self.detect_unsubstituted_variables(s);
                self.detect_raw_pseudo_param(s);
                self.detect_secretsmanager_ref(s);
                ResolvedValue::Concrete { value: serde_json::Value::String(s.clone()).into() }
            }
            Node::List(items) => {
                let items = items.clone(); // clone Vec<NodeRef> (cheap: Vec of u32)
                let saved = self.current_path.clone();
                let resolved: Vec<ResolvedValue> = items
                    .iter()
                    .enumerate()
                    .map(|(i, r)| {
                        self.current_path = format!("{}.{}", saved, i);
                        self.resolve_node(*r)
                    })
                    .collect();
                self.current_path = saved;
                if resolved.iter().all(|v| matches!(v, ResolvedValue::Concrete { value: _ })) {
                    let vals: Vec<serde_json::Value> = resolved
                        .into_iter()
                        .map(|v| match v {
                            ResolvedValue::Concrete { value: c } => c.into_inner(),
                            _ => unreachable!(),
                        })
                        .collect();
                    ResolvedValue::Concrete { value: serde_json::Value::Array(vals).into() }
                } else {
                    ResolvedValue::List { items: resolved }
                }
            }
            Node::Map(entries) => {
                let refs: Vec<(String, NodeRef)> = entries.iter().map(|(k, v)| (k.clone(), *v)).collect();
                let saved = self.current_path.clone();
                let resolved: Vec<MapEntry> = refs
                    .into_iter()
                    .map(|(k, v)| {
                        self.current_path = format!("{}.{}", saved, k);
                        let val = self.resolve_node(v);
                        MapEntry { key: k, value: val }
                    })
                    .collect();
                self.current_path = saved;
                if resolved.iter().all(|entry| matches!(entry.value, ResolvedValue::Concrete { value: _ })) {
                    let mut map = serde_json::Map::new();
                    for entry in resolved {
                        if let ResolvedValue::Concrete { value: c } = entry.value {
                            map.insert(entry.key, c.into_inner());
                        }
                    }
                    ResolvedValue::Concrete { value: serde_json::Value::Object(map).into() }
                } else {
                    ResolvedValue::Map { entries: resolved }
                }
            }
            Node::Intrinsic(intrinsic) => {
                let intrinsic = intrinsic.clone(); // clone only the intrinsic
                self.resolve_intrinsic(&intrinsic, &span)
            }
        }
    }

    fn resolve_intrinsic(&mut self, intrinsic: &IntrinsicFn, span: &SourceSpan) -> ResolvedValue {
        debug!("Resolve intrinsic {} at {}", intrinsic_name(intrinsic), self.current_path);
        // Record that the value at this path is produced by a string-building
        // intrinsic, even when it resolves to a concrete string. Rules that must
        // distinguish an intrinsic-built value from a written literal (e.g. the
        // `package`-command and pattern checks, which only apply to written
        // string literals) rely on `is_from_intrinsic` to see this. Ref/GetAtt
        // already record reference edges, and Fn::If is tracked per branch, so
        // only the value-producing structural intrinsics need an explicit marker.
        if let Some(ref rid) = self.current_resource
            && matches!(
                intrinsic,
                IntrinsicFn::Join(_, _)
                    | IntrinsicFn::Sub(_, _)
                    | IntrinsicFn::Select(_, _)
                    | IntrinsicFn::Split(_, _)
                    | IntrinsicFn::FindInMap(_, _, _, _)
                    | IntrinsicFn::Base64(_)
                    | IntrinsicFn::Cidr(_, _, _)
            )
        {
            self.resolution_source_map
                .entry((rid.clone(), self.current_path.clone()))
                .or_insert_with(|| format!("Intrinsic/{}", intrinsic_name(intrinsic)));
        }
        match intrinsic {
            IntrinsicFn::Ref(target) => self.resolve_ref(target, span),
            IntrinsicFn::GetAtt(resource, attr) => {
                self.record_edge(resource, RefKind::GetAtt { attr: attr.clone() }, span);
                ResolvedValue::Reference { target: resource.clone(), kind: RefKind::GetAtt { attr: attr.clone() } }
            }
            IntrinsicFn::If(cond, t_ref, f_ref) => {
                let saved = self.current_path.clone();
                self.current_path = format!("{}.Fn::If", saved);
                self.condition_stack.push((cond.clone(), true));
                self.current_path = format!("{}.Fn::If.1", saved);
                let true_branch = self.resolve_node(*t_ref);
                self.condition_stack.pop();
                self.condition_stack.push((cond.clone(), false));
                self.current_path = format!("{}.Fn::If.2", saved);
                let false_branch = self.resolve_node(*f_ref);
                self.condition_stack.pop();
                self.current_path = saved;
                ResolvedValue::Conditional {
                    condition: cond.clone(),
                    if_true: Box::new(true_branch),
                    if_false: Box::new(false_branch),
                }
            }
            IntrinsicFn::IfExpr(cond_ref, t_ref, f_ref) => {
                let saved = self.current_path.clone();
                self.current_path = format!("{}.Fn::If.1", saved);
                let true_branch = self.resolve_node(*t_ref);
                self.current_path = format!("{}.Fn::If.2", saved);
                let false_branch = self.resolve_node(*f_ref);
                self.current_path = saved;
                // Resolve the condition expression node to capture edges/side effects
                let _cond_resolved = self.resolve_node(*cond_ref);

                // Try to parse and eagerly evaluate the inline condition
                let parsed_expr = crate::conditions::parse_condition_expr(self.arena, *cond_ref, self.parameters);
                // Literal-only Equals can be evaluated immediately
                if let crate::conditions::ConditionExpr::Equals(
                    crate::conditions::ValueExpr::Literal(a),
                    crate::conditions::ValueExpr::Literal(b),
                ) = &parsed_expr
                {
                    return if a == b { true_branch } else { false_branch };
                }

                let cond_label = format!("__inline_cond_{}", cond_ref);
                self.inline_conditions.push((cond_label.clone(), parsed_expr));
                ResolvedValue::Conditional {
                    condition: cond_label,
                    if_true: Box::new(true_branch),
                    if_false: Box::new(false_branch),
                }
            }
            IntrinsicFn::FindInMap(map_name_ref, k1_ref, k2_ref, default_ref) => {
                self.resolve_findinmap(*map_name_ref, *k1_ref, *k2_ref, *default_ref)
            }
            IntrinsicFn::Sub(template, subs) => self.resolve_sub(template, subs, span),
            IntrinsicFn::Join(delim_ref, values_ref) => {
                let saved = self.current_path.clone();
                let join_path = format!("{}.Fn::Join", saved);
                self.current_path = format!("{}.0", join_path);
                let delim = self.resolve_node(*delim_ref);
                // Track Fn::Join with empty delimiter for join-without-delimiter detection
                if let ResolvedValue::Concrete { value: d } = &delim
                    && d.as_str() == Some("")
                    && self.is_simple_join(*values_ref)
                {
                    let key = self.current_resource.clone().unwrap_or_else(|| OUTPUTS_PSEUDO_RESOURCE.into());
                    self.empty_joins.entry(key).or_default().push(join_path.clone());
                }
                self.current_path = format!("{}.1", join_path);
                let values = self.resolve_node(*values_ref);
                self.current_path = saved;
                match (&delim, &values) {
                    (ResolvedValue::Concrete { value: d }, ResolvedValue::Concrete { value: v }) => {
                        if let (Some(ds), Some(arr)) = (d.as_str(), v.as_array()) {
                            let parts: Vec<String> =
                                arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();
                            if parts.len() == arr.len() {
                                return ResolvedValue::Concrete {
                                    value: serde_json::Value::String(parts.join(ds)).into(),
                                };
                            }
                        }
                        self.collect_extra_condition_refs(&values);
                        ResolvedValue::Dynamic { reason: "Join with non-string elements".into() }
                    }
                    (
                        ResolvedValue::Concrete { value: d },
                        ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f },
                    ) => {
                        if let Some(ds) = d.as_str() {
                            return ResolvedValue::Conditional {
                                condition: cond.clone(),
                                if_true: Box::new(join_resolved(ds, t)),
                                if_false: Box::new(join_resolved(ds, f)),
                            };
                        }
                        self.collect_extra_condition_refs(&values);
                        ResolvedValue::Dynamic { reason: "Join with non-string delimiter".into() }
                    }
                    (ResolvedValue::Concrete { value: d }, ResolvedValue::List { items }) => {
                        if let Some(ds) = d.as_str() {
                            if items.iter().any(|v| {
                                matches!(
                                    v,
                                    ResolvedValue::Enum { variants: _ }
                                        | ResolvedValue::Conditional { condition: _, if_true: _, if_false: _ }
                                )
                            }) {
                                return join_with_enum_list(ds, items);
                            }
                            // Partial join: substitute concrete items, placeholder for others
                            let parts: Vec<String> = items
                                .iter()
                                .map(|v| match v {
                                    ResolvedValue::Concrete { value: cv } => cv.as_str().unwrap_or("").to_string(),
                                    ResolvedValue::Reference { target, .. } => {
                                        format!("{}{}}}", UNRESOLVED_REF_PLACEHOLDER_PREFIX, target)
                                    }
                                    _ => UNRESOLVED_DYNAMIC_PLACEHOLDER.to_string(),
                                })
                                .collect();
                            self.collect_extra_condition_refs(&values);
                            return ResolvedValue::Dynamic {
                                reason: format!("{}{}", JOIN_PARTIAL_PREFIX, parts.join(ds)),
                            };
                        }
                        self.collect_extra_condition_refs(&values);
                        ResolvedValue::Dynamic { reason: "Join with unresolvable arguments".into() }
                    }
                    (ResolvedValue::Concrete { value: d }, ResolvedValue::Enum { variants }) => {
                        if let Some(ds) = d.as_str() {
                            let results: Vec<ResolvedValue> = variants.iter().map(|v| join_resolved(ds, v)).collect();
                            return ResolvedValue::Enum { variants: results };
                        }
                        self.collect_extra_condition_refs(&values);
                        ResolvedValue::Dynamic { reason: "Join with non-string delimiter".into() }
                    }
                    _ => {
                        self.collect_extra_condition_refs(&values);
                        ResolvedValue::Dynamic { reason: "Join with unresolvable arguments".into() }
                    }
                }
            }
            IntrinsicFn::Select(idx_ref, list_ref) => {
                let idx = self.resolve_node(*idx_ref);
                let list = self.resolve_node(*list_ref);
                match (&idx, &list) {
                    (ResolvedValue::Concrete { value: i }, ResolvedValue::Concrete { value: l }) => {
                        if let Some(arr) = l.as_array()
                            && let Some(idx) = i.as_u64()
                        {
                            if (idx as usize) < arr.len() {
                                return ResolvedValue::Concrete { value: arr[idx as usize].clone().into() };
                            }
                            return ResolvedValue::Dynamic { reason: "Select index out of bounds".into() };
                        }
                        ResolvedValue::Dynamic { reason: "Select on non-list value".into() }
                    }
                    (
                        ResolvedValue::Concrete { value: i },
                        ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f },
                    ) => ResolvedValue::Conditional {
                        condition: cond.clone(),
                        if_true: Box::new(select_resolved(i, t)),
                        if_false: Box::new(select_resolved(i, f)),
                    },
                    (ResolvedValue::Concrete { value: i }, ResolvedValue::Enum { variants }) => {
                        let results: Vec<ResolvedValue> = variants.iter().map(|v| select_resolved(i, v)).collect();
                        ResolvedValue::Enum { variants: results }
                    }
                    (ResolvedValue::Concrete { value: i }, ResolvedValue::List { items }) => {
                        if let Some(idx) = i.as_u64() {
                            if (idx as usize) < items.len() {
                                return items[idx as usize].clone();
                            }
                            return ResolvedValue::Dynamic { reason: "Select index out of bounds".into() };
                        }
                        ResolvedValue::Dynamic { reason: "Select with non-integer index".into() }
                    }
                    _ => ResolvedValue::Dynamic { reason: "Select with unresolvable arguments".into() },
                }
            }
            IntrinsicFn::Split(delim_ref, src_ref) => {
                let delim = self.resolve_node(*delim_ref);
                let src = self.resolve_node(*src_ref);
                match (&delim, &src) {
                    (ResolvedValue::Concrete { value: d }, ResolvedValue::Concrete { value: s }) => {
                        if let (Some(ds), Some(ss)) = (d.as_str(), s.as_str()) {
                            let parts: Vec<serde_json::Value> =
                                ss.split(ds).map(|p| serde_json::Value::String(p.to_string())).collect();
                            return ResolvedValue::Concrete { value: serde_json::Value::Array(parts).into() };
                        }
                        ResolvedValue::Dynamic { reason: "Split with non-string arguments".into() }
                    }
                    (ResolvedValue::Concrete { value: d }, ResolvedValue::Enum { variants }) => {
                        if let Some(ds) = d.as_str() {
                            let results: Vec<ResolvedValue> = variants.iter().map(|v| split_resolved(ds, v)).collect();
                            return ResolvedValue::Enum { variants: results };
                        }
                        ResolvedValue::Dynamic { reason: "Split with non-string delimiter".into() }
                    }
                    (
                        ResolvedValue::Concrete { value: d },
                        ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f },
                    ) => {
                        if let Some(ds) = d.as_str() {
                            return ResolvedValue::Conditional {
                                condition: cond.clone(),
                                if_true: Box::new(split_resolved(ds, t)),
                                if_false: Box::new(split_resolved(ds, f)),
                            };
                        }
                        ResolvedValue::Dynamic { reason: "Split with non-string delimiter".into() }
                    }
                    _ => ResolvedValue::Dynamic { reason: "Split with unresolvable arguments".into() },
                }
            }
            IntrinsicFn::Base64(val_ref) => {
                let saved = self.current_path.clone();
                self.current_path = format!("{}.Fn::Base64", saved);
                let val = self.resolve_node(*val_ref);
                self.current_path = saved;
                match &val {
                    ResolvedValue::Concrete { value: v } => {
                        if let Some(s) = v.as_str() {
                            let encoded = base64::engine::general_purpose::STANDARD.encode(s);
                            return ResolvedValue::Concrete { value: serde_json::Value::String(encoded).into() };
                        }
                        ResolvedValue::Dynamic { reason: "Base64 with non-string argument".into() }
                    }
                    ResolvedValue::Enum { variants } => {
                        let results: Vec<ResolvedValue> = variants.iter().map(base64_resolved).collect();
                        ResolvedValue::Enum { variants: results }
                    }
                    ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f } => {
                        ResolvedValue::Conditional {
                            condition: cond.clone(),
                            if_true: Box::new(base64_resolved(t)),
                            if_false: Box::new(base64_resolved(f)),
                        }
                    }
                    _ => ResolvedValue::Dynamic { reason: "Base64 with unresolvable argument".into() },
                }
            }
            IntrinsicFn::ImportValue(arg) => {
                let reason = match self.resolve_node(*arg) {
                    ResolvedValue::Concrete { value } => match value.as_str() {
                        Some(export) => format!("cross-stack import: {export}"),
                        None => "cross-stack import".into(),
                    },
                    _ => "cross-stack import".into(),
                };
                ResolvedValue::TypedDynamic { reason, param_type: PARAM_TYPE_STRING.into() }
            }
            IntrinsicFn::GetStackOutput(args) => {
                let saved = self.current_path.clone();
                let mut concrete_arguments: Vec<(&str, String)> = Vec::with_capacity(args.len());
                for (key, arg) in args {
                    self.current_path = format!("{}.{}", saved, key);
                    if let ResolvedValue::Concrete { value } = self.resolve_node(*arg)
                        && let Some(literal) = value.as_str()
                    {
                        concrete_arguments.push((key.as_str(), literal.to_string()));
                    }
                }
                self.current_path = saved;

                // Fixed key order, not template order, so two calls that list the same
                // arguments in a different order stay equal. RoleArn is left out: it does
                // not change which output is read, so two calls differing only there are
                // still the same value. Quoting keeps a separator inside a value from
                // reading as a field boundary.
                let identity: Vec<String> = [KEY_STACK_NAME, KEY_REGION, KEY_OUTPUT_NAME]
                    .into_iter()
                    .filter_map(|key| {
                        concrete_arguments
                            .iter()
                            .find(|(name, _)| *name == key)
                            .map(|(_, literal)| format!("{key}={literal:?}"))
                    })
                    .collect();
                let reason = if identity.is_empty() {
                    "cross-stack output".to_string()
                } else {
                    format!("cross-stack output: {}", identity.join(", "))
                };
                ResolvedValue::Dynamic { reason }
            }
            IntrinsicFn::Transform(_, _) => ResolvedValue::Dynamic { reason: "macro output".into() },
            IntrinsicFn::GetAZs(region_ref) => {
                if let Some(ref rid) = self.current_resource {
                    self.resolution_source_map
                        .insert((rid.clone(), self.current_path.clone()), "Intrinsic/Fn::GetAZs".to_string());
                }
                let region_val = self.resolve_node(*region_ref);
                resolve_getazs_value(&region_val, self.pseudo_parameter_overrides)
            }
            IntrinsicFn::Cidr(ip_ref, count_ref, bits_ref) => {
                let ip_val = self.resolve_node(*ip_ref);
                let count_val = self.resolve_node(*count_ref);
                let bits_val = self.resolve_node(*bits_ref);
                match (&ip_val, &count_val, &bits_val) {
                    (
                        ResolvedValue::Concrete { value: ip },
                        ResolvedValue::Concrete { value: cnt },
                        ResolvedValue::Concrete { value: bits },
                    ) => {
                        let ip_str = ip.as_str().unwrap_or("");
                        let count = cnt.as_u64().or_else(|| cnt.as_str().and_then(|s| s.parse().ok())).unwrap_or(0);
                        let cidr_bits =
                            bits.as_u64().or_else(|| bits.as_str().and_then(|s| s.parse().ok())).unwrap_or(0);
                        match calculate_cidr_blocks(ip_str, count, cidr_bits) {
                            Some(blocks) => ResolvedValue::Concrete {
                                value: serde_json::Value::Array(
                                    blocks.into_iter().map(serde_json::Value::String).collect(),
                                )
                                .into(),
                            },
                            None => ResolvedValue::Dynamic { reason: "Cidr calculation failed".into() },
                        }
                    }
                    _ => {
                        // Propagate Enum ip_block through Cidr
                        if let ResolvedValue::Enum { variants } = &ip_val {
                            let results: Vec<ResolvedValue> =
                                variants.iter().map(|v| resolve_cidr_value(v, &count_val, &bits_val)).collect();
                            return ResolvedValue::Enum { variants: results };
                        }
                        // Propagate Conditional ip_block through Cidr
                        if let ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f } = &ip_val {
                            return ResolvedValue::Conditional {
                                condition: cond.clone(),
                                if_true: Box::new(resolve_cidr_value(t, &count_val, &bits_val)),
                                if_false: Box::new(resolve_cidr_value(f, &count_val, &bits_val)),
                            };
                        }
                        ResolvedValue::Dynamic { reason: "Cidr runtime value".into() }
                    }
                }
            }
            IntrinsicFn::Equals(a_ref, b_ref) => {
                let left = self.resolve_node(*a_ref);
                let right = self.resolve_node(*b_ref);
                self.collect_extra_condition_refs(&left);
                self.collect_extra_condition_refs(&right);
                match (&left, &right) {
                    (ResolvedValue::Concrete { value: lv }, ResolvedValue::Concrete { value: rv }) => {
                        ResolvedValue::Concrete { value: serde_json::Value::Bool(lv == rv).into() }
                    }
                    (ResolvedValue::Enum { variants }, ResolvedValue::Concrete { value: rv }) => {
                        let results: Vec<ResolvedValue> = variants
                            .iter()
                            .map(|v| match v {
                                ResolvedValue::Concrete { value: lv } => {
                                    ResolvedValue::Concrete { value: serde_json::Value::Bool(lv == rv).into() }
                                }
                                _ => ResolvedValue::Dynamic { reason: "condition expression".into() },
                            })
                            .collect();
                        ResolvedValue::Enum { variants: results }
                    }
                    (ResolvedValue::Concrete { value: lv }, ResolvedValue::Enum { variants }) => {
                        let results: Vec<ResolvedValue> = variants
                            .iter()
                            .map(|v| match v {
                                ResolvedValue::Concrete { value: rv } => {
                                    ResolvedValue::Concrete { value: serde_json::Value::Bool(lv == rv).into() }
                                }
                                _ => ResolvedValue::Dynamic { reason: "condition expression".into() },
                            })
                            .collect();
                        ResolvedValue::Enum { variants: results }
                    }
                    _ => ResolvedValue::Dynamic { reason: "condition expression".into() },
                }
            }
            IntrinsicFn::And(children) => {
                let resolved: Vec<ResolvedValue> = children.iter().map(|c| self.resolve_node(*c)).collect();
                for v in &resolved {
                    self.collect_extra_condition_refs(v);
                }
                let all_concrete_bool = resolved
                    .iter()
                    .all(|v| matches!(v, ResolvedValue::Concrete { value: JsonValue(serde_json::Value::Bool(_)) }));
                if all_concrete_bool {
                    let all_true = resolved.iter().all(|v| match v {
                        ResolvedValue::Concrete { value: bv } => bv.as_bool().unwrap_or(false),
                        _ => false,
                    });
                    ResolvedValue::Concrete { value: serde_json::Value::Bool(all_true).into() }
                } else {
                    ResolvedValue::Dynamic { reason: "condition expression".into() }
                }
            }
            IntrinsicFn::Or(children) => {
                let resolved: Vec<ResolvedValue> = children.iter().map(|c| self.resolve_node(*c)).collect();
                for v in &resolved {
                    self.collect_extra_condition_refs(v);
                }
                let all_concrete_bool = resolved
                    .iter()
                    .all(|v| matches!(v, ResolvedValue::Concrete { value: JsonValue(serde_json::Value::Bool(_)) }));
                if all_concrete_bool {
                    let any_true = resolved.iter().any(|v| match v {
                        ResolvedValue::Concrete { value: bv } => bv.as_bool().unwrap_or(false),
                        _ => false,
                    });
                    ResolvedValue::Concrete { value: serde_json::Value::Bool(any_true).into() }
                } else {
                    ResolvedValue::Dynamic { reason: "condition expression".into() }
                }
            }
            IntrinsicFn::Not(child) => {
                let resolved = self.resolve_node(*child);
                self.collect_extra_condition_refs(&resolved);
                match &resolved {
                    ResolvedValue::Concrete { value: JsonValue(serde_json::Value::Bool(b)) } => {
                        ResolvedValue::Concrete { value: serde_json::Value::Bool(!b).into() }
                    }
                    _ => ResolvedValue::Dynamic { reason: "condition expression".into() },
                }
            }
            IntrinsicFn::RefAll(_) => ResolvedValue::Dynamic { reason: "rules-only function".into() },
            IntrinsicFn::ValueOf(param_name, _attr) | IntrinsicFn::ValueOfAll(param_name, _attr) => {
                // The first argument is a parameter (or parameter group) name -
                // record a Ref edge so the parameter is counted as referenced.
                self.record_edge(param_name, RefKind::Ref, span);
                ResolvedValue::Dynamic { reason: "rules-only function".into() }
            }
            IntrinsicFn::Contains(list_ref, value_ref)
            | IntrinsicFn::EachMemberEquals(list_ref, value_ref)
            | IntrinsicFn::EachMemberIn(list_ref, value_ref) => {
                // Walk children for ref-edge side effects. Each argument may
                // contain `Ref`/`Fn::Sub`/etc. that must register a reference
                // even though the function itself resolves to a dynamic value.
                self.resolve_node(*list_ref);
                self.resolve_node(*value_ref);
                ResolvedValue::Dynamic { reason: "rules-only function".into() }
            }
            IntrinsicFn::ToJsonString(val_ref) => {
                let val = self.resolve_node(*val_ref);
                match &val {
                    ResolvedValue::Concrete { value: v } => {
                        ResolvedValue::Concrete { value: serde_json::Value::String(v.to_string()).into() }
                    }
                    ResolvedValue::Enum { variants } => {
                        let results: Vec<ResolvedValue> = variants.iter().map(to_json_string_resolved).collect();
                        ResolvedValue::Enum { variants: results }
                    }
                    ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f } => {
                        ResolvedValue::Conditional {
                            condition: cond.clone(),
                            if_true: Box::new(to_json_string_resolved(t)),
                            if_false: Box::new(to_json_string_resolved(f)),
                        }
                    }
                    _ => ResolvedValue::Dynamic { reason: "ToJsonString with unresolvable argument".into() },
                }
            }
            IntrinsicFn::Length(val_ref) => {
                let val = self.resolve_node(*val_ref);
                match &val {
                    ResolvedValue::Concrete { value: JsonValue(serde_json::Value::Array(arr)) } => {
                        ResolvedValue::Concrete { value: serde_json::json!(arr.len()).into() }
                    }
                    ResolvedValue::Concrete { value: JsonValue(serde_json::Value::Object(map)) } => {
                        ResolvedValue::Concrete { value: serde_json::json!(map.len()).into() }
                    }
                    ResolvedValue::List { items } => {
                        ResolvedValue::Concrete { value: serde_json::json!(items.len()).into() }
                    }
                    ResolvedValue::Map { entries } => {
                        ResolvedValue::Concrete { value: serde_json::json!(entries.len()).into() }
                    }
                    ResolvedValue::Enum { variants } => {
                        let results: Vec<ResolvedValue> = variants.iter().map(length_resolved).collect();
                        ResolvedValue::Enum { variants: results }
                    }
                    ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f } => {
                        ResolvedValue::Conditional {
                            condition: cond.clone(),
                            if_true: Box::new(length_resolved(t)),
                            if_false: Box::new(length_resolved(f)),
                        }
                    }
                    _ => ResolvedValue::Dynamic { reason: "Length with unresolvable argument".into() },
                }
            }
            IntrinsicFn::ForEach(unique_id, identifier, collection_ref, body_ref) => {
                let unique_id = unique_id.clone();
                let identifier = identifier.clone();
                let collection_ref = *collection_ref;
                let body_ref = *body_ref;
                if let Some(ref rid) = self.current_resource {
                    let collection_desc = match self.arena.node(collection_ref) {
                        Node::Intrinsic(IntrinsicFn::Ref(t)) => format!("Ref({})", t),
                        Node::List(items) => format!("[{} items]", items.len()),
                        _ => "dynamic".to_string(),
                    };
                    self.foreach_expansions.entry(rid.clone()).or_default().push((
                        self.current_path.clone(),
                        identifier.clone(),
                        collection_desc,
                    ));
                }
                let collection = self.resolve_node(collection_ref);
                let elements: Option<Vec<ResolvedValue>> = match &collection {
                    ResolvedValue::Concrete { value: v } => v.as_array().map(|arr| {
                        arr.iter().map(|item| ResolvedValue::Concrete { value: item.clone().into() }).collect()
                    }),
                    ResolvedValue::List { items } => Some(items.clone()),
                    _ => None,
                };
                if let Some(elements) = elements {
                    let mut result_entries = Vec::new();
                    for element in &elements {
                        self.local_bindings.insert(identifier.clone(), element.clone());
                        let resolved_body = self.resolve_node(body_ref);
                        self.local_bindings.remove(&identifier);
                        // ForEach body produces a map entry keyed by unique_id+element
                        let key = match element {
                            ResolvedValue::Concrete { value: v } => {
                                format!("{}{}", unique_id, v.as_str().unwrap_or(&v.to_string()))
                            }
                            _ => format!("{}{}", unique_id, "{dynamic}"),
                        };
                        result_entries.push(MapEntry { key, value: resolved_body });
                    }
                    return ResolvedValue::Map { entries: result_entries };
                }
                ResolvedValue::Dynamic { reason: "ForEach macro output".into() }
            }
        }
    }

    fn resolve_ref(&mut self, target: &str, span: &SourceSpan) -> ResolvedValue {
        if let Some(resolved) = self.lookup_ref(target, span) {
            return resolved;
        }
        // The unresolved target is recorded in `invalid_refs`; the engines
        // surface it as the invalid-reference diagnostic. This is an expected
        // outcome for an invalid template, so log it at debug rather than warn.
        debug!("Ref '{}' does not reference a valid target", target);
        if let Some(ref rid) = self.current_resource {
            self.invalid_refs.entry(rid.clone()).or_default().push((self.current_path.clone(), target.to_string()));
        }
        ResolvedValue::Dynamic { reason: format!("unknown ref target: {}", target) }
    }

    /// Resolves a Ref target to a value, recording edges and resolution sources
    /// for known targets. Returns `None` when the target is not a condition,
    /// ForEach binding, pseudo-parameter, parameter, or resource. Recording an
    /// invalid ref is deliberately left to the caller: Fn::Sub variable
    /// expansion shares this resolution path but an unresolved Sub variable is
    /// not an invalid Ref and must not be registered as one.
    fn lookup_ref(&mut self, target: &str, span: &SourceSpan) -> Option<ResolvedValue> {
        if let Some(cond_name) = target.strip_prefix(CONDITION_REF_PREFIX) {
            return Some(ResolvedValue::Dynamic { reason: format!("condition reference: {}", cond_name) });
        }

        // ForEach loop bindings take precedence
        if let Some(bound) = self.local_bindings.get(target) {
            return Some(bound.clone());
        }

        if PSEUDO_PARAMETERS.contains(&target) {
            if target == PSEUDO_NO_VALUE {
                return Some(ResolvedValue::Concrete { value: serde_json::Value::Null.into() });
            }
            if let Some(ref rid) = self.current_resource {
                self.resolution_source_map
                    .entry((rid.clone(), self.current_path.clone()))
                    .or_insert_with(|| format!("Intrinsic/{}", TAG_REF));
            }
            if let Some(val) = self.pseudo_parameter_overrides.get(target) {
                return Some(ResolvedValue::Concrete { value: serde_json::Value::String(val).into() });
            }
            return Some(ResolvedValue::Dynamic { reason: format!("pseudo-parameter {}", target) });
        }

        // Overrides take precedence over AllowedValues/Default
        if let Some(override_val) = self.parameter_overrides.get(target)
            && let Some(param) = self.parameters.get(target)
        {
            self.record_edge(target, RefKind::Ref, span);
            if let Some(ref rid) = self.current_resource {
                self.resolution_source_map
                    .insert((rid.clone(), self.current_path.clone()), format!("Parameters/{}/Override", target));
            }
            let json_val = param_string_to_json(override_val, &param.param_type);
            return Some(ResolvedValue::Concrete { value: json_val.into() });
        }

        if let Some(param) = self.parameters.get(target) {
            self.record_edge(target, RefKind::Ref, span);
            if let Some(ref rid) = self.current_resource {
                let source = if param.allowed_values.is_some() {
                    format!("Parameters/{}/AllowedValues", target)
                } else if param.default.is_some() {
                    format!("Parameters/{}/Default", target)
                } else {
                    format!("Parameters/{}", target)
                };
                self.resolution_source_map.insert((rid.clone(), self.current_path.clone()), source);
            }
            if let Some(ref allowed) = param.allowed_values {
                return Some(ResolvedValue::Enum {
                    variants: allowed
                        .iter()
                        .map(|v| ResolvedValue::Concrete { value: serde_json::Value::String(v.clone()).into() })
                        .collect(),
                });
            }
            if let Some(ref default) = param.default {
                let json_val = param_string_to_json(default, &param.param_type);
                return Some(ResolvedValue::Concrete { value: json_val.into() });
            }
            return Some(ResolvedValue::TypedDynamic {
                reason: format!("parameter {} value unknown", target),
                param_type: param.param_type.clone(),
            });
        }

        if self.resource_ids.contains(target) {
            self.record_edge(target, RefKind::Ref, span);
            return Some(ResolvedValue::Reference { target: target.to_string(), kind: RefKind::Ref });
        }

        None
    }

    fn resolve_findinmap(
        &mut self,
        map_name_ref: NodeRef,
        first_key_ref: NodeRef,
        second_key_ref: NodeRef,
        default_ref: Option<NodeRef>,
    ) -> ResolvedValue {
        let saved_path = self.current_path.clone();
        let fim_path = format!("{}.Fn::FindInMap", saved_path);

        self.current_path = format!("{}.0", fim_path);
        let map_name_resolved = self.resolve_node(map_name_ref);

        self.current_path = format!("{}.1", fim_path);
        let first_key = self.resolve_node(first_key_ref);

        self.current_path = format!("{}.2", fim_path);
        let second_key = self.resolve_node(second_key_ref);

        self.current_path = saved_path;

        match &map_name_resolved {
            ResolvedValue::Concrete { value: name_val } => {
                let map_name = name_val.as_str().unwrap_or("");
                if let Some(ref rid) = self.current_resource {
                    self.find_in_map_refs.entry(rid.clone()).or_default().push(map_name.to_string());
                }
                self.lookup_mapping(map_name, &first_key, &second_key, default_ref)
            }
            ResolvedValue::Enum { variants: name_variants } => {
                let results: Vec<ResolvedValue> = name_variants
                    .iter()
                    .map(|name_val| {
                        let map_name = match name_val {
                            ResolvedValue::Concrete { value: v } => v.as_str().unwrap_or("").to_string(),
                            _ => {
                                return ResolvedValue::Dynamic { reason: "non-concrete enum map name".into() };
                            }
                        };
                        if let Some(ref rid) = self.current_resource {
                            self.find_in_map_refs.entry(rid.clone()).or_default().push(map_name.clone());
                        }
                        self.lookup_mapping(&map_name, &first_key, &second_key, default_ref)
                    })
                    .collect();
                ResolvedValue::Enum { variants: results }
            }
            _ => {
                if let Some(def) = default_ref {
                    return self.resolve_node(def);
                }
                ResolvedValue::Dynamic { reason: "FindInMap with dynamic map name".into() }
            }
        }
    }

    fn lookup_mapping(
        &mut self,
        map_name: &str,
        first_key: &ResolvedValue,
        second_key: &ResolvedValue,
        default_ref: Option<NodeRef>,
    ) -> ResolvedValue {
        let Some(mapping) = self.mappings.get(map_name) else {
            warn!("FindInMap references non-existent mapping '{}'", map_name);
            if let Some(def) = default_ref {
                return self.resolve_node(def);
            }
            return ResolvedValue::Dynamic { reason: format!("mapping '{}' not found", map_name) };
        };

        match (first_key, second_key) {
            (ResolvedValue::Concrete { value: k1v }, ResolvedValue::Concrete { value: k2v }) => {
                let k1s = k1v.as_str().unwrap_or("");
                let k2s = k2v.as_str().unwrap_or("");
                match mapping.get(k1s).and_then(|m| m.get(k2s)) {
                    Some(v) => ResolvedValue::Concrete { value: v.clone().into() },
                    None => {
                        if let Some(def) = default_ref {
                            return self.resolve_node(def);
                        }
                        ResolvedValue::Dynamic { reason: format!("no mapping entry for {}/{}/{}", map_name, k1s, k2s) }
                    }
                }
            }
            (ResolvedValue::Concrete { value: k1v }, ResolvedValue::Enum { variants: k2_variants }) => {
                let k1s = k1v.as_str().unwrap_or("");
                let results: Vec<ResolvedValue> = k2_variants
                    .iter()
                    .map(|k2v| match k2v {
                        ResolvedValue::Concrete { value: v } => {
                            let k2s = v.as_str().unwrap_or("");
                            match mapping.get(k1s).and_then(|m| m.get(k2s)) {
                                Some(val) => ResolvedValue::Concrete { value: val.clone().into() },
                                None => ResolvedValue::Dynamic {
                                    reason: format!("no mapping entry for {}/{}/{}", map_name, k1s, k2s),
                                },
                            }
                        }
                        _ => ResolvedValue::Dynamic { reason: "non-concrete enum key".into() },
                    })
                    .collect();
                ResolvedValue::Enum { variants: results }
            }
            (
                ResolvedValue::Concrete { value: _ },
                ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f },
            ) => ResolvedValue::Conditional {
                condition: cond.clone(),
                if_true: Box::new(self.lookup_mapping(map_name, first_key, t, default_ref)),
                if_false: Box::new(self.lookup_mapping(map_name, first_key, f, default_ref)),
            },
            (ResolvedValue::Enum { variants: k1_vals }, _) => {
                let results: Vec<ResolvedValue> = k1_vals
                    .iter()
                    .map(|k1v| {
                        let k1s = match k1v {
                            ResolvedValue::Concrete { value: v } => v.as_str().unwrap_or("").to_string(),
                            _ => {
                                return ResolvedValue::Dynamic { reason: "non-concrete enum key".into() };
                            }
                        };
                        match second_key {
                            ResolvedValue::Concrete { value: k2v } => {
                                let k2s = k2v.as_str().unwrap_or("");
                                match mapping.get(&k1s).and_then(|m| m.get(k2s)) {
                                    Some(v) => ResolvedValue::Concrete { value: v.clone().into() },
                                    None => ResolvedValue::Dynamic {
                                        reason: format!("no mapping entry for {}/{}/{}", map_name, k1s, k2s),
                                    },
                                }
                            }
                            ResolvedValue::Enum { variants: k2_variants } => {
                                // Cartesian product: each k1 variant × each k2 variant
                                let inner: Vec<ResolvedValue> = k2_variants
                                    .iter()
                                    .map(|k2v| match k2v {
                                        ResolvedValue::Concrete { value: v } => {
                                            let k2s = v.as_str().unwrap_or("");
                                            match mapping.get(&k1s).and_then(|m| m.get(k2s)) {
                                                Some(val) => ResolvedValue::Concrete { value: val.clone().into() },
                                                None => ResolvedValue::Dynamic {
                                                    reason: format!(
                                                        "no mapping entry for {}/{}/{}",
                                                        map_name, k1s, k2s
                                                    ),
                                                },
                                            }
                                        }
                                        _ => ResolvedValue::Dynamic { reason: "non-concrete enum key".into() },
                                    })
                                    .collect();
                                ResolvedValue::Enum { variants: inner }
                            }
                            ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f } => {
                                let k1_concrete =
                                    ResolvedValue::Concrete { value: serde_json::Value::String(k1s).into() };
                                ResolvedValue::Conditional {
                                    condition: cond.clone(),
                                    if_true: Box::new(self.lookup_mapping(map_name, &k1_concrete, t, default_ref)),
                                    if_false: Box::new(self.lookup_mapping(map_name, &k1_concrete, f, default_ref)),
                                }
                            }
                            _ => ResolvedValue::Dynamic { reason: "FindInMap with dynamic key2".into() },
                        }
                    })
                    .collect();
                // Flatten nested Enums from cartesian product into a single Enum
                let flattened: Vec<ResolvedValue> = results
                    .into_iter()
                    .flat_map(|v| match v {
                        ResolvedValue::Enum { variants } => variants,
                        other => vec![other],
                    })
                    .collect();
                ResolvedValue::Enum { variants: flattened }
            }
            (_, ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f }) => {
                ResolvedValue::Conditional {
                    condition: cond.clone(),
                    if_true: Box::new(self.lookup_mapping(map_name, first_key, t, default_ref)),
                    if_false: Box::new(self.lookup_mapping(map_name, first_key, f, default_ref)),
                }
            }
            _ => {
                if let Some(def) = default_ref {
                    return self.resolve_node(def);
                }
                ResolvedValue::Dynamic { reason: "FindInMap with dynamic keys".into() }
            }
        }
    }

    /// Whether the current resource declares `var` as a
    /// `DefinitionSubstitutions` key.
    fn is_definition_substitution(&self, var: &str) -> bool {
        self.current_resource
            .as_ref()
            .and_then(|rid| self.def_subs_resources.get(rid))
            .is_some_and(|keys| keys.contains(var))
    }

    fn detect_unsubstituted_variables(&mut self, s: &str) {
        if !s.contains("${") {
            return;
        }
        let Some(ref rid) = self.current_resource else {
            return;
        };
        // Skip TemplateBody properties (nested stacks)
        let path = &self.current_path;
        if path.contains("TemplateBody") {
            return;
        }

        let mut i = 0;
        let bytes = s.as_bytes();
        while i < bytes.len() {
            if i + 1 < bytes.len() && bytes[i] == b'$' && bytes[i + 1] == b'{' {
                if i + 2 < bytes.len() && bytes[i + 2] == b'!' {
                    i += 3;
                    continue;
                }
                let start = i + 2;
                if let Some(end) = s[start..].find('}') {
                    let var = s[start..start + end].trim();
                    if var.starts_with("stageVariables.") {
                        i = start + end + 1;
                        continue;
                    }
                    // A variable fires when it names a known ref target
                    // (parameter,
                    // resource, pseudo-parameter, or `Resource.Attr`) - or,
                    // regardless of target validity, inside a Step Functions
                    // `DefinitionString`, where every `${...}` placeholder is
                    // expected to come from `DefinitionSubstitutions` (that
                    // resource-level exemption is applied above).
                    let is_sub_style_variable = !var.is_empty()
                        && var.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | ':' | '.'));
                    let names_known_target = self.resource_ids.contains(var)
                        || self.parameters.contains_key(var)
                        || PSEUDO_PARAMETERS.contains(&var)
                        || (var.contains('.')
                            && var.split('.').next().map(|prefix| self.resource_ids.contains(prefix)).unwrap_or(false));
                    // A Step Functions definition placeholder is exempt when it
                    // names one of the resource's DefinitionSubstitutions keys
                    // - and reportable otherwise, whether or not it names a
                    // known ref target.
                    let in_definition = path.contains("DefinitionString") || path.contains("Definition");
                    if in_definition && self.is_definition_substitution(var) {
                        i = start + end + 1;
                        continue;
                    }
                    if is_sub_style_variable && (names_known_target || in_definition) {
                        self.unsubstituted_variables
                            .entry(rid.clone())
                            .or_default()
                            .push((path.clone(), format!("${{{}}}", var)));
                    }
                    i = start + end + 1;
                } else {
                    break;
                }
            } else {
                i += 1;
            }
        }
    }

    fn detect_raw_pseudo_param(&mut self, s: &str) {
        if !s.starts_with(PSEUDO_PREFIX) {
            return;
        }
        let Some(ref rid) = self.current_resource else {
            return;
        };
        if PSEUDO_PARAMETERS.contains(&s) {
            self.raw_pseudo_params.entry(rid.clone()).or_default().push((self.current_path.clone(), s.to_string()));
        }
    }

    fn detect_secretsmanager_ref(&mut self, s: &str) {
        if !s.contains("{{resolve:secretsmanager:") {
            return;
        }
        let Some(ref rid) = self.current_resource else {
            return;
        };
        // The "secret value where an ARN is expected" warning only applies
        // inside a resource's `Properties`. A secretsmanager dynamic reference
        // elsewhere (Metadata, DependsOn, etc.) is governed by the
        // not-supported-location check, not this one, so restrict collection to
        // property paths.
        if !self.current_path.starts_with("Properties.") && self.current_path != "Properties" {
            return;
        }
        self.secretsmanager_ref_paths.entry(rid.clone()).or_default().push(self.current_path.clone());
    }

    /// Returns true if the Fn::Join values array can be converted to Fn::Sub.
    fn is_simple_join(&self, values_ref: NodeRef) -> bool {
        let items = match self.arena.as_list(values_ref) {
            Some(items) => items,
            None => return false,
        };
        items.iter().all(|item_ref| {
            match &self.arena.node(*item_ref) {
                Node::String(_) | Node::Int(_) | Node::Float(_) | Node::Bool(_) => true,
                Node::Intrinsic(intrinsic) => matches!(
                    intrinsic,
                    IntrinsicFn::Ref(_) | IntrinsicFn::GetAtt(_, _) | IntrinsicFn::Sub(_, None) // Sub with string-only template (no substitution map)
                ),
                _ => false,
            }
        })
    }

    fn resolve_sub(
        &mut self,
        template: &str,
        subs: &Option<Vec<(String, NodeRef)>>,
        span: &SourceSpan,
    ) -> ResolvedValue {
        let mut vars: Vec<String> = Vec::new();
        let mut i = 0;
        let bytes = template.as_bytes();
        while i < bytes.len() {
            if i + 1 < bytes.len() && bytes[i] == b'$' && bytes[i + 1] == b'{' {
                let start = i + 2;
                if let Some(end) = template[start..].find('}') {
                    vars.push(template[start..start + end].trim().to_string());
                    i = start + end + 1;
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }

        let mut sub_map: HashMap<String, ResolvedValue> = HashMap::new();
        if let Some(explicit_subs) = subs {
            for (k, v) in explicit_subs {
                sub_map.insert(k.clone(), self.resolve_node(*v));
            }
            if let Some(ref rid) = self.current_resource {
                for (k, _) in explicit_subs {
                    if !vars.iter().any(|v| v == k) {
                        self.unused_sub_keys
                            .entry(rid.clone())
                            .or_default()
                            .push((self.current_path.clone(), k.clone()));
                    }
                }
            }
        }

        for var in &vars {
            if sub_map.contains_key(var) {
                continue;
            }
            // Check for Resource.Attribute syntax (implicit GetAtt in Sub)
            if let Some(dot_pos) = var.find('.') {
                let resource = &var[..dot_pos];
                let attr = &var[dot_pos + 1..];
                if self.resource_ids.contains(resource) {
                    self.record_edge(resource, RefKind::GetAtt { attr: attr.to_string() }, span);
                    sub_map.insert(
                        var.clone(),
                        ResolvedValue::Reference {
                            target: resource.to_string(),
                            kind: RefKind::GetAtt { attr: attr.to_string() },
                        },
                    );
                    continue;
                }
            }
            // Fn::Sub variables share Ref resolution, but an unresolved Sub
            // variable is not an invalid Ref, so resolve it without recording
            // it as one. When the variable names a resource, `lookup_ref` has
            // already recorded a `Ref` edge - CloudFormation treats a bare
            // `${Resource}` substitution as a `Ref`, so recording an extra `Sub`
            // edge would double-count the dependency (surfacing a spurious second
            // dependency finding under a `Sub` label that misrepresents the edge).
            let resolved = self
                .lookup_ref(var, span)
                .unwrap_or_else(|| ResolvedValue::Dynamic { reason: format!("unknown sub variable: {}", var) });
            sub_map.insert(var.clone(), resolved);
        }

        if vars.len() == 1 && subs.is_none() {
            let var = &vars[0];
            let expected = format!("${{{}}}", var);
            if template == expected
                && let Some(ref rid) = self.current_resource
            {
                self.simple_subs.entry(rid.clone()).or_default().push((self.current_path.clone(), var.clone()));
            }
        }

        if vars.is_empty()
            && subs.is_none()
            && let Some(ref rid) = self.current_resource
        {
            self.redundant_subs.entry(rid.clone()).or_default().push(self.current_path.clone());
        }

        if template.contains("arn:aws:")
            && let Some(ref rid) = self.current_resource
        {
            // This finding is anchored at the Fn::Sub node, so its reported path
            // ends in `.Fn::Sub` (the intrinsic that builds the hardcoded ARN).
            self.hardcoded_partition_arns
                .entry(rid.clone())
                .or_default()
                .push(format!("{}.Fn::Sub", self.current_path));
        }

        let all_concrete = sub_map.values().all(|v| matches!(v, ResolvedValue::Concrete { value: _ }));
        if all_concrete && !sub_map.is_empty() {
            let mut result = template.to_string();
            for (var, val) in &sub_map {
                if let ResolvedValue::Concrete { value: v } = val {
                    let replacement = v.as_str().unwrap_or(&v.to_string()).to_string();
                    result = result.replace(&format!("${{{}}}", var), &replacement);
                }
            }
            return ResolvedValue::Concrete { value: serde_json::Value::String(result).into() };
        }

        let has_enum = sub_map.values().any(|v| matches!(v, ResolvedValue::Enum { variants: _ }));
        if has_enum {
            let mut enum_vars: Vec<(String, Vec<String>)> = Vec::new();
            for (var, val) in &sub_map {
                if let ResolvedValue::Enum { variants } = val {
                    let concrete: Vec<String> = variants
                        .iter()
                        .filter_map(|v| {
                            if let ResolvedValue::Concrete { value: cv } = v {
                                Some(cv.as_str().unwrap_or("").to_string())
                            } else {
                                None
                            }
                        })
                        .collect();
                    if !concrete.is_empty() {
                        enum_vars.push((var.clone(), concrete));
                    }
                }
            }
            if !enum_vars.is_empty() {
                let mut combos: Vec<Vec<(String, String)>> = vec![vec![]];
                for (var, vals) in &enum_vars {
                    let mut new_combos = Vec::new();
                    for combo in &combos {
                        for val in vals {
                            let mut c = combo.clone();
                            c.push((var.clone(), val.clone()));
                            new_combos.push(c);
                        }
                    }
                    combos = new_combos;
                }
                let results: Vec<ResolvedValue> = combos
                    .into_iter()
                    .map(|combo| {
                        let mut result = template.to_string();
                        for (var, val) in &combo {
                            result = result.replace(&format!("${{{}}}", var), val);
                        }
                        for (var, val) in &sub_map {
                            if let ResolvedValue::Concrete { value: cv } = val {
                                let replacement = cv.as_str().unwrap_or(&cv.to_string()).to_string();
                                result = result.replace(&format!("${{{}}}", var), &replacement);
                            }
                        }
                        // If unresolved vars remain, produce Dynamic with partial info
                        if result.contains("${") {
                            ResolvedValue::Dynamic { reason: format!("{}{}", SUB_PARTIAL_PREFIX, result) }
                        } else {
                            ResolvedValue::Concrete { value: serde_json::Value::String(result).into() }
                        }
                    })
                    .collect();
                if !results.is_empty() {
                    return ResolvedValue::Enum { variants: results };
                }
            }
        }

        let mut partial = template.to_string();
        for (var, val) in &sub_map {
            if let ResolvedValue::Concrete { value: v } = val {
                let replacement = v.as_str().unwrap_or(&v.to_string()).to_string();
                partial = partial.replace(&format!("${{{}}}", var), &replacement);
            }
        }
        // Must capture condition refs before collapsing to Dynamic
        for val in sub_map.values() {
            self.collect_extra_condition_refs(val);
        }
        ResolvedValue::Dynamic { reason: format!("{}{}", SUB_PARTIAL_PREFIX, partial) }
    }

    fn collect_extra_condition_refs(&mut self, val: &ResolvedValue) {
        let key = match &self.current_resource {
            Some(r) => r.clone(),
            None => return,
        };
        let mut conds = Vec::new();
        crate::resolved_value::collect_condition_refs_from_resolved(val, &mut conds);
        if !conds.is_empty() {
            self.extra_condition_refs.entry(key).or_default().append(&mut conds);
        }
    }

    fn record_edge(&mut self, target: &str, kind: RefKind, span: &SourceSpan) {
        if let Some(ref resource) = self.current_resource.clone() {
            let condition_context = if self.condition_stack.is_empty() {
                None
            } else {
                let ctx: Vec<String> =
                    self.condition_stack.iter().map(|(c, b)| if *b { c.clone() } else { format!("!{}", c) }).collect();
                Some(ctx.join(","))
            };
            self.edges.push(ResolverEdge {
                source_resource: resource.clone(),
                source_path: self.current_path.clone(),
                target: target.to_string(),
                kind,
                span: *span,
                condition_context,
            });
        }
    }

    pub fn set_current_resource(&mut self, resource_id: &str) {
        self.current_resource = Some(resource_id.to_string());
    }

    pub fn set_current_path(&mut self, path: &str) {
        self.current_path = path.to_string();
    }
}

fn param_string_to_json(value: &str, param_type: &str) -> serde_json::Value {
    if param_type == PARAM_TYPE_COMMA_DELIMITED_LIST || param_type.starts_with("List<") {
        return serde_json::Value::Array(
            value.split(',').map(|v| serde_json::Value::String(v.trim().to_string())).collect(),
        );
    }
    match param_type {
        // Parse whole numbers as integers so a Number parameter value of "30"
        // resolves to 30, not 30.0 - the float form would fail integer enum
        // comparisons and render as '30.0' in diagnostics.
        PARAM_TYPE_NUMBER => value
            .parse::<i64>()
            .map(|i| serde_json::Value::Number(i.into()))
            .or_else(|_| {
                value.parse::<f64>().map(|n| {
                    serde_json::Number::from_f64(n)
                        .map(serde_json::Value::Number)
                        .unwrap_or(serde_json::Value::String(value.to_string()))
                })
            })
            .unwrap_or(serde_json::Value::String(value.to_string())),
        _ => serde_json::Value::String(value.to_string()),
    }
}

fn calculate_cidr_blocks(ip_block: &str, count: u64, cidr_bits: u64) -> Option<Vec<String>> {
    let (ip_str, prefix_str) = ip_block.split_once('/')?;
    let prefix_len: u32 = prefix_str.parse().ok()?;
    let new_prefix = 32 - cidr_bits as u32;
    if new_prefix <= prefix_len {
        return None;
    }
    let ip: u32 = ip_str.split('.').enumerate().try_fold(0u32, |acc, (i, octet)| {
        let o: u32 = octet.parse().ok()?;
        Some(acc | (o << (24 - i * 8)))
    })?;
    let subnet_size = 1u32 << cidr_bits;
    let base = ip & !((1u32 << (32 - prefix_len)) - 1);
    let mut results = Vec::new();
    for i in 0..count.min(256) {
        let subnet_ip = base + (i as u32) * subnet_size;
        let a = (subnet_ip >> 24) & 0xFF;
        let b = (subnet_ip >> 16) & 0xFF;
        let c = (subnet_ip >> 8) & 0xFF;
        let d = subnet_ip & 0xFF;
        results.push(format!("{}.{}.{}.{}/{}", a, b, c, d, new_prefix));
    }
    Some(results)
}

/// Collapses a resolved concrete string that embeds a dynamic reference
/// (`{{resolve:ssm:...}}`, `{{resolve:ssm-secure:...}}`, `{{resolve:secretsmanager:...}}`)
/// into a deploy-time-opaque value, mirroring how `Fn::ImportValue` resolves.
fn opaque_if_dynamic_reference(value: ResolvedValue) -> ResolvedValue {
    if let ResolvedValue::Concrete { value: ref json } = value
        && let Some(s) = json.as_str()
        && s.contains("{{resolve:")
    {
        return ResolvedValue::TypedDynamic {
            reason: format!("dynamic reference: {}", s),
            param_type: PARAM_TYPE_STRING.into(),
        };
    }
    value
}

fn join_resolved(delim: &str, values: &ResolvedValue) -> ResolvedValue {
    match values {
        ResolvedValue::Concrete { value: v } => {
            if let Some(arr) = v.as_array() {
                let parts: Vec<String> = arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();
                if parts.len() == arr.len() {
                    return ResolvedValue::Concrete { value: serde_json::Value::String(parts.join(delim)).into() };
                }
            }
            ResolvedValue::Dynamic { reason: "Join with non-string elements".into() }
        }
        ResolvedValue::Enum { variants } => {
            let results: Vec<ResolvedValue> = variants.iter().map(|v| join_resolved(delim, v)).collect();
            ResolvedValue::Enum { variants: results }
        }
        ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f } => ResolvedValue::Conditional {
            condition: cond.clone(),
            if_true: Box::new(join_resolved(delim, t)),
            if_false: Box::new(join_resolved(delim, f)),
        },
        _ => ResolvedValue::Dynamic { reason: "Join with unresolvable arguments".into() },
    }
}

fn join_with_enum_list(delim: &str, items: &[ResolvedValue]) -> ResolvedValue {
    // Build cartesian product of all items, expanding Enum variants
    let mut combos: Vec<Vec<String>> = vec![vec![]];
    for item in items {
        match item {
            ResolvedValue::Concrete { value: v } => {
                let s = v.as_str().unwrap_or("").to_string();
                for combo in &mut combos {
                    combo.push(s.clone());
                }
            }
            ResolvedValue::Enum { variants } => {
                let strs: Vec<String> = variants
                    .iter()
                    .filter_map(|v| {
                        if let ResolvedValue::Concrete { value: cv } = v {
                            cv.as_str().map(|s| s.to_string())
                        } else {
                            None
                        }
                    })
                    .collect();
                if strs.is_empty() {
                    return ResolvedValue::Dynamic { reason: "Join with non-concrete enum".into() };
                }
                let mut new_combos = Vec::new();
                for combo in &combos {
                    for s in &strs {
                        let mut c = combo.clone();
                        c.push(s.clone());
                        new_combos.push(c);
                        if new_combos.len() > MAX_ENUM_EXPANSION {
                            break;
                        }
                    }
                    if new_combos.len() > MAX_ENUM_EXPANSION {
                        break;
                    }
                }
                combos = new_combos;
            }
            _ => {
                return ResolvedValue::Dynamic { reason: "Join with unresolvable list element".into() };
            }
        }
    }
    let results: Vec<ResolvedValue> = combos
        .into_iter()
        .take(MAX_ENUM_EXPANSION)
        .map(|parts| ResolvedValue::Concrete { value: serde_json::Value::String(parts.join(delim)).into() })
        .collect();
    if results.len() == 1 { results.into_iter().next().unwrap() } else { ResolvedValue::Enum { variants: results } }
}

fn select_resolved(idx: &serde_json::Value, list: &ResolvedValue) -> ResolvedValue {
    match list {
        ResolvedValue::Concrete { value: l } => {
            if let (Some(arr), Some(i)) = (l.as_array(), idx.as_u64())
                && (i as usize) < arr.len()
            {
                return ResolvedValue::Concrete { value: arr[i as usize].clone().into() };
            }
            ResolvedValue::Dynamic { reason: "Select index out of bounds".into() }
        }
        ResolvedValue::List { items } => {
            if let Some(i) = idx.as_u64()
                && (i as usize) < items.len()
            {
                return items[i as usize].clone();
            }
            ResolvedValue::Dynamic { reason: "Select index out of bounds".into() }
        }
        ResolvedValue::Enum { variants } => {
            let results: Vec<ResolvedValue> = variants.iter().map(|v| select_resolved(idx, v)).collect();
            ResolvedValue::Enum { variants: results }
        }
        ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f } => ResolvedValue::Conditional {
            condition: cond.clone(),
            if_true: Box::new(select_resolved(idx, t)),
            if_false: Box::new(select_resolved(idx, f)),
        },
        _ => ResolvedValue::Dynamic { reason: "Select with unresolvable arguments".into() },
    }
}

fn split_resolved(delim: &str, src: &ResolvedValue) -> ResolvedValue {
    match src {
        ResolvedValue::Concrete { value: s } => {
            if let Some(ss) = s.as_str() {
                let parts: Vec<serde_json::Value> =
                    ss.split(delim).map(|p| serde_json::Value::String(p.to_string())).collect();
                return ResolvedValue::Concrete { value: serde_json::Value::Array(parts).into() };
            }
            ResolvedValue::Dynamic { reason: "Split with non-string argument".into() }
        }
        ResolvedValue::Enum { variants } => {
            let results: Vec<ResolvedValue> = variants.iter().map(|v| split_resolved(delim, v)).collect();
            ResolvedValue::Enum { variants: results }
        }
        ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f } => ResolvedValue::Conditional {
            condition: cond.clone(),
            if_true: Box::new(split_resolved(delim, t)),
            if_false: Box::new(split_resolved(delim, f)),
        },
        _ => ResolvedValue::Dynamic { reason: "Split with unresolvable argument".into() },
    }
}

fn base64_resolved(val: &ResolvedValue) -> ResolvedValue {
    match val {
        ResolvedValue::Concrete { value: v } => {
            if let Some(s) = v.as_str() {
                let encoded = base64::engine::general_purpose::STANDARD.encode(s);
                return ResolvedValue::Concrete { value: serde_json::Value::String(encoded).into() };
            }
            ResolvedValue::Dynamic { reason: "Base64 with non-string argument".into() }
        }
        ResolvedValue::Enum { variants } => {
            let results: Vec<ResolvedValue> = variants.iter().map(base64_resolved).collect();
            ResolvedValue::Enum { variants: results }
        }
        ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f } => ResolvedValue::Conditional {
            condition: cond.clone(),
            if_true: Box::new(base64_resolved(t)),
            if_false: Box::new(base64_resolved(f)),
        },
        _ => ResolvedValue::Dynamic { reason: "Base64 with unresolvable argument".into() },
    }
}

fn length_resolved(val: &ResolvedValue) -> ResolvedValue {
    match val {
        ResolvedValue::Concrete { value: JsonValue(serde_json::Value::Array(arr)) } => {
            ResolvedValue::Concrete { value: serde_json::json!(arr.len()).into() }
        }
        ResolvedValue::Concrete { value: JsonValue(serde_json::Value::Object(map)) } => {
            ResolvedValue::Concrete { value: serde_json::json!(map.len()).into() }
        }
        ResolvedValue::Enum { variants } => {
            let results: Vec<ResolvedValue> = variants.iter().map(length_resolved).collect();
            ResolvedValue::Enum { variants: results }
        }
        ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f } => ResolvedValue::Conditional {
            condition: cond.clone(),
            if_true: Box::new(length_resolved(t)),
            if_false: Box::new(length_resolved(f)),
        },
        _ => ResolvedValue::Dynamic { reason: "Length with unresolvable argument".into() },
    }
}

fn resolve_getazs_value(
    region_val: &ResolvedValue,
    pseudo_overrides: &crate::model::PseudoParameterOverrides,
) -> ResolvedValue {
    match region_val {
        ResolvedValue::Concrete { value: v } => {
            let region_str = v.as_str().unwrap_or("");
            let effective_region = if region_str.is_empty() { pseudo_overrides.region() } else { region_str };
            match availability_zones_for_region(effective_region) {
                Some(azs) => ResolvedValue::Concrete {
                    value: serde_json::Value::Array(
                        azs.iter().map(|z| serde_json::Value::String((*z).to_string())).collect(),
                    )
                    .into(),
                },
                None => ResolvedValue::Dynamic { reason: format!("GetAZs unknown region {}", effective_region) },
            }
        }
        ResolvedValue::Enum { variants } => {
            let results: Vec<ResolvedValue> =
                variants.iter().map(|v| resolve_getazs_value(v, pseudo_overrides)).collect();
            ResolvedValue::Enum { variants: results }
        }
        ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f } => ResolvedValue::Conditional {
            condition: cond.clone(),
            if_true: Box::new(resolve_getazs_value(t, pseudo_overrides)),
            if_false: Box::new(resolve_getazs_value(f, pseudo_overrides)),
        },
        _ => ResolvedValue::Dynamic { reason: "GetAZs runtime value".into() },
    }
}

fn resolve_cidr_value(ip_val: &ResolvedValue, count_val: &ResolvedValue, bits_val: &ResolvedValue) -> ResolvedValue {
    match (ip_val, count_val, bits_val) {
        (
            ResolvedValue::Concrete { value: ip },
            ResolvedValue::Concrete { value: cnt },
            ResolvedValue::Concrete { value: bits },
        ) => {
            let ip_str = ip.as_str().unwrap_or("");
            let count = cnt.as_u64().or_else(|| cnt.as_str().and_then(|s| s.parse().ok())).unwrap_or(0);
            let cidr_bits = bits.as_u64().or_else(|| bits.as_str().and_then(|s| s.parse().ok())).unwrap_or(0);
            match calculate_cidr_blocks(ip_str, count, cidr_bits) {
                Some(blocks) => ResolvedValue::Concrete {
                    value: serde_json::Value::Array(blocks.into_iter().map(serde_json::Value::String).collect()).into(),
                },
                None => ResolvedValue::Dynamic { reason: "Cidr calculation failed".into() },
            }
        }
        _ => ResolvedValue::Dynamic { reason: "Cidr runtime value".into() },
    }
}

fn to_json_string_resolved(val: &ResolvedValue) -> ResolvedValue {
    match val {
        ResolvedValue::Concrete { value: v } => {
            ResolvedValue::Concrete { value: serde_json::Value::String(v.to_string()).into() }
        }
        ResolvedValue::Enum { variants } => {
            let results: Vec<ResolvedValue> = variants.iter().map(to_json_string_resolved).collect();
            ResolvedValue::Enum { variants: results }
        }
        ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f } => ResolvedValue::Conditional {
            condition: cond.clone(),
            if_true: Box::new(to_json_string_resolved(t)),
            if_false: Box::new(to_json_string_resolved(f)),
        },
        _ => ResolvedValue::Dynamic { reason: "ToJsonString with unresolvable argument".into() },
    }
}

/// Whether a parameter-constraint node satisfies the expected JSON Schema type
/// under CloudFormation's loose coercion. CloudFormation stringifies scalar
/// values, so a quoted number/bool such as `MaxLength: '12'` and `NoEcho: 'true'`
/// is accepted just like its native form. A native match always passes; a string
/// that coerces to the expected type passes too.
fn node_matches_param_type(node: &Node, expected: &str) -> bool {
    match (expected, node) {
        ("integer", Node::Int(_)) => true,
        ("number", Node::Int(_) | Node::Float(_)) => true,
        ("boolean", Node::Bool(_)) => true,
        (_, Node::String(s)) => type_compatible(&serde_json::Value::String(s.clone()), expected),
        _ => false,
    }
}

pub fn extract_parameters(ir: &TemplateIR) -> (HashMap<String, ParameterInfo>, Vec<ParseDefect>) {
    let mut params = HashMap::new();
    let mut diags = Vec::new();
    if ir.parameters == NULL_REF {
        return (params, diags);
    }
    let Some(entries) = ir.arena.as_map(ir.parameters) else {
        return (params, diags);
    };

    let e2001 = |msg: String, param_name: &str, prop: Option<&str>, span: SourceSpan| -> ParseDefect {
        // Section-absolute slash form, so identity and span derivation can
        // attribute the finding to the parameter.
        let path = match prop {
            Some(p) => format!("Parameters/{}/{}", param_name, p),
            None => format!("Parameters/{}", param_name),
        };
        let mut d = crate::make_parse_defect("E2001", msg, span);
        d.property_path = Some(path);
        d
    };

    const VALID_KEYS: &[&str] = &[
        KEY_ALLOWED_PATTERN,
        KEY_ALLOWED_VALUES,
        KEY_CONSTRAINT_DESCRIPTION,
        KEY_DEFAULT,
        SECTION_DESCRIPTION,
        KEY_MAX_LENGTH,
        KEY_MIN_LENGTH,
        KEY_MAX_VALUE,
        KEY_MIN_VALUE,
        KEY_NO_ECHO,
        KEY_TYPE,
    ];

    for (name, node_ref) in entries {
        let param_span = ir.arena.span(*node_ref);

        // Parameter value must be an object (map)
        let Some(param_map) = ir.arena.as_map(*node_ref) else {
            if matches!(ir.arena.node(*node_ref), Node::Null) {
                diags.push(e2001(
                    format!("Parameter '{}': None is not of type 'object'", name),
                    name,
                    None,
                    param_span,
                ));
            }
            continue;
        };

        let has_type = param_map.iter().any(|(k, _)| k == KEY_TYPE);
        if !has_type {
            diags.push(e2001(format!("Parameter '{}': 'Type' is a required property", name), name, None, param_span));
        }

        for (key, val_ref) in param_map {
            let val_span = ir.arena.span(*val_ref);
            let node = ir.arena.node(*val_ref);

            if !VALID_KEYS.contains(&key.as_str()) {
                diags.push(e2001(
                    format!("Parameter '{}': '{}' is not one of {}", name, key, render_str_list(VALID_KEYS)),
                    name,
                    Some(key),
                    val_span,
                ));
                continue;
            }

            match key.as_str() {
                KEY_TYPE => {
                    if matches!(node, Node::Null) {
                        diags.push(e2001(
                            format!("Parameter '{}': Type must not be null", name),
                            name,
                            Some("Type"),
                            val_span,
                        ));
                    } else if !matches!(node, Node::String(_)) {
                        diags.push(e2001(
                            format!("Parameter '{}': Type must be a string", name),
                            name,
                            Some("Type"),
                            val_span,
                        ));
                    }
                }
                KEY_ALLOWED_VALUES => {
                    if !matches!(node, Node::List(_)) {
                        diags.push(e2001(
                            format!("Parameter '{}': AllowedValues must be an array", name),
                            name,
                            Some("AllowedValues"),
                            val_span,
                        ));
                    }
                }
                KEY_NO_ECHO => {
                    if matches!(node, Node::Null) {
                        diags.push(e2001(
                            format!("Parameter '{}': NoEcho must not be null", name),
                            name,
                            Some("NoEcho"),
                            val_span,
                        ));
                    } else if !node_matches_param_type(node, "boolean") {
                        diags.push(e2001(
                            format!("Parameter '{}': NoEcho must be a boolean", name),
                            name,
                            Some("NoEcho"),
                            val_span,
                        ));
                    }
                }
                KEY_MIN_VALUE | KEY_MAX_VALUE => {
                    if matches!(node, Node::Null) {
                        diags.push(e2001(
                            format!("Parameter '{}': {} must not be null", name, key),
                            name,
                            Some(key),
                            val_span,
                        ));
                    } else if !node_matches_param_type(node, "number") {
                        diags.push(e2001(
                            format!("Parameter '{}': {} must be a number", name, key),
                            name,
                            Some(key),
                            val_span,
                        ));
                    }
                }
                KEY_MIN_LENGTH | KEY_MAX_LENGTH => {
                    if matches!(node, Node::Null) {
                        diags.push(e2001(
                            format!("Parameter '{}': {} must not be null", name, key),
                            name,
                            Some(key),
                            val_span,
                        ));
                    } else if !node_matches_param_type(node, "integer") {
                        diags.push(e2001(
                            format!("Parameter '{}': {} must be an integer", name, key),
                            name,
                            Some(key),
                            val_span,
                        ));
                    }
                }
                KEY_DEFAULT | SECTION_DESCRIPTION | KEY_ALLOWED_PATTERN | KEY_CONSTRAINT_DESCRIPTION => {
                    if matches!(node, Node::Null) {
                        diags.push(e2001(
                            format!("Parameter '{}': {} must not be null", name, key),
                            name,
                            Some(key),
                            val_span,
                        ));
                    } else if matches!(node, Node::Map(_) | Node::Intrinsic(_)) {
                        diags.push(e2001(
                            format!("Parameter '{}': {} must be a string", name, key),
                            name,
                            Some(key),
                            val_span,
                        ));
                    }
                }
                _ => {}
            }
        }

        let param_type = param_map
            .iter()
            .find(|(k, _)| k == KEY_TYPE)
            .and_then(|(_, v)| ir.arena.as_str(*v))
            .unwrap_or(PARAM_TYPE_STRING)
            .to_string();

        let default = param_map.iter().find(|(k, _)| k == KEY_DEFAULT).and_then(|(_, v)| match ir.arena.node(*v) {
            Node::String(s) => Some(s.clone()),
            Node::Int(i) => Some(i.to_string()),
            Node::Float(f) => Some(f.to_string()),
            Node::Bool(b) => Some(b.to_string()),
            _ => None,
        });

        let allowed_values =
            param_map.iter().find(|(k, _)| k == KEY_ALLOWED_VALUES).and_then(|(_, v)| ir.arena.as_list(*v)).map(
                |items| {
                    items
                        .iter()
                        .filter_map(|r| match ir.arena.node(*r) {
                            Node::String(s) => Some(s.clone()),
                            Node::Int(i) => Some(i.to_string()),
                            _ => None,
                        })
                        .collect()
                },
            );

        let description = param_map
            .iter()
            .find(|(k, _)| k == SECTION_DESCRIPTION)
            .and_then(|(_, v)| ir.arena.as_str(*v))
            .map(|s| s.to_string());

        let no_echo = param_map
            .iter()
            .find(|(k, _)| k == KEY_NO_ECHO)
            .and_then(|(_, v)| match ir.arena.node(*v) {
                Node::Bool(b) => Some(*b),
                Node::String(s) => Some(s.eq_ignore_ascii_case("true")),
                _ => None,
            })
            .unwrap_or(false);

        let allowed_pattern = param_map
            .iter()
            .find(|(k, _)| k == KEY_ALLOWED_PATTERN)
            .and_then(|(_, v)| ir.arena.as_str(*v))
            .map(|s| s.to_string());

        let min_length =
            param_map.iter().find(|(k, _)| k == KEY_MIN_LENGTH).and_then(|(_, v)| match ir.arena.node(*v) {
                Node::Int(i) => Some(*i as u64),
                Node::String(s) => s.parse().ok(),
                _ => None,
            });

        let max_length =
            param_map.iter().find(|(k, _)| k == KEY_MAX_LENGTH).and_then(|(_, v)| match ir.arena.node(*v) {
                Node::Int(i) => Some(*i as u64),
                Node::String(s) => s.parse().ok(),
                _ => None,
            });

        let min_value = param_map.iter().find(|(k, _)| k == KEY_MIN_VALUE).and_then(|(_, v)| match ir.arena.node(*v) {
            Node::Int(i) => Some(*i),
            Node::String(s) => s.parse().ok(),
            _ => None,
        });

        let max_value = param_map.iter().find(|(k, _)| k == KEY_MAX_VALUE).and_then(|(_, v)| match ir.arena.node(*v) {
            Node::Int(i) => Some(*i),
            Node::String(s) => s.parse().ok(),
            _ => None,
        });

        let allowed_pattern_valid = allowed_pattern.as_deref().map(is_service_valid);
        let is_comma_delimited = param_type == PARAM_TYPE_COMMA_DELIMITED_LIST || param_type.starts_with("List<");
        let default_matches_allowed_pattern = match (&allowed_pattern, &default) {
            (Some(pattern), Some(value)) => default_matches_pattern(pattern, value, is_comma_delimited),
            _ => None,
        };

        params.insert(
            name.clone(),
            ParameterInfo {
                param_type,
                default,
                allowed_values,
                allowed_pattern,
                min_length,
                max_length,
                min_value,
                max_value,
                description,
                no_echo,
                allowed_pattern_valid,
                default_matches_allowed_pattern,
            },
        );
    }
    let with_allowed = params.values().filter(|p| p.allowed_values.is_some()).count();
    let with_defaults = params.values().filter(|p| p.default.is_some()).count();
    debug!(
        "Extracted {} parameters ({} with AllowedValues, {} with Default)",
        params.len(),
        with_allowed,
        with_defaults
    );
    (params, diags)
}

pub fn extract_mappings(ir: &TemplateIR) -> (MappingData, Vec<ParseDefect>) {
    let mut mappings = MappingData::new();
    let mut diagnostics = Vec::new();
    if ir.mappings == NULL_REF {
        return (mappings, diagnostics);
    }
    let Some(entries) = ir.arena.as_map(ir.mappings) else {
        return (mappings, diagnostics);
    };
    for (map_name, map_ref) in entries {
        let Some(level1) = ir.arena.as_map(*map_ref) else {
            diagnostics.push(crate::make_parse_defect_at(
                "F0017",
                format!("Mapping '{}' must be a map, not a scalar value", map_name),
                ir.arena.span(*map_ref),
                &format!("Mappings/{}", map_name),
            ));
            continue;
        };
        let mut l1_map = HashMap::new();
        for (k1, k1_ref) in level1 {
            let Some(level2) = ir.arena.as_map(*k1_ref) else {
                diagnostics.push(crate::make_parse_defect_at(
                    "F0017",
                    format!("Mapping '{}' second level key '{}' must be a map", map_name, k1),
                    ir.arena.span(*k1_ref),
                    &format!("Mappings/{}/{}", map_name, k1),
                ));
                continue;
            };
            let mut l2_map = HashMap::new();
            for (k2, k2_ref) in level2 {
                let val = node_to_json(&ir.arena, *k2_ref);
                l2_map.insert(k2.clone(), val);
            }
            l1_map.insert(k1.clone(), l2_map);
        }
        mappings.insert(map_name.clone(), l1_map);
    }
    let total_entries: usize = mappings.values().map(|l1| l1.values().map(|l2| l2.len()).sum::<usize>()).sum();
    debug!("Extracted {} mappings with {} total leaf entries", mappings.len(), total_entries);
    (mappings, diagnostics)
}

pub fn node_to_json(arena: &Arena, node_ref: NodeRef) -> serde_json::Value {
    if node_ref == NULL_REF {
        return serde_json::Value::Null;
    }
    match arena.node(node_ref) {
        Node::Null => serde_json::Value::Null,
        Node::Bool(b) => serde_json::Value::Bool(*b),
        Node::Int(i) => serde_json::json!(*i),
        Node::Float(f) => serde_json::json!(*f),
        Node::String(s) => serde_json::Value::String(s.clone()),
        Node::List(items) => serde_json::Value::Array(items.iter().map(|r| node_to_json(arena, *r)).collect()),
        Node::Map(entries) => {
            let mut map = serde_json::Map::new();
            for (k, v) in entries {
                map.insert(k.clone(), node_to_json(arena, *v));
            }
            serde_json::Value::Object(map)
        }
        Node::Intrinsic(intrinsic) => {
            serde_json::json!({MARKER_INTRINSIC: intrinsic_name(intrinsic)})
        }
    }
}

fn intrinsic_name(intrinsic: &IntrinsicFn) -> &'static str {
    match intrinsic {
        IntrinsicFn::Ref(_) => TAG_REF,
        IntrinsicFn::GetAtt(_, _) => TAG_GET_ATT,
        IntrinsicFn::If(_, _, _) => TAG_IF,
        IntrinsicFn::IfExpr(_, _, _) => TAG_IF_EXPR,
        IntrinsicFn::FindInMap(_, _, _, _) => TAG_FIND_IN_MAP,
        IntrinsicFn::Sub(_, _) => TAG_SUB,
        IntrinsicFn::Join(_, _) => TAG_JOIN,
        IntrinsicFn::Select(_, _) => TAG_SELECT,
        IntrinsicFn::Split(_, _) => TAG_SPLIT,
        IntrinsicFn::Base64(_) => TAG_BASE64,
        IntrinsicFn::ImportValue(_) => TAG_IMPORT_VALUE,
        IntrinsicFn::GetStackOutput(_) => TAG_GET_STACK_OUTPUT,
        IntrinsicFn::Transform(_, _) => TAG_TRANSFORM,
        IntrinsicFn::GetAZs(_) => TAG_GET_AZS,
        IntrinsicFn::Cidr(_, _, _) => TAG_CIDR,
        IntrinsicFn::And(_) => TAG_AND,
        IntrinsicFn::Or(_) => TAG_OR,
        IntrinsicFn::Not(_) => TAG_NOT,
        IntrinsicFn::Equals(_, _) => TAG_EQUALS,
        IntrinsicFn::ToJsonString(_) => TAG_TO_JSON_STRING,
        IntrinsicFn::Length(_) => TAG_LENGTH,
        IntrinsicFn::ForEach(_, _, _, _) => TAG_FOR_EACH,
        IntrinsicFn::ValueOf(_, _) => TAG_VALUE_OF,
        IntrinsicFn::ValueOfAll(_, _) => TAG_VALUE_OF_ALL,
        IntrinsicFn::RefAll(_) => TAG_REF_ALL,
        IntrinsicFn::Contains(_, _) => TAG_CONTAINS,
        IntrinsicFn::EachMemberEquals(_, _) => TAG_EACH_MEMBER_EQUALS,
        IntrinsicFn::EachMemberIn(_, _) => TAG_EACH_MEMBER_IN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;

    #[test]
    fn param_number_whole_value_resolves_to_integer() {
        // A whole-number Number parameter must resolve to a JSON integer, not a
        // float - 30.0 fails integer enum comparisons and renders as '30.0'.
        assert_eq!(param_string_to_json("30", "Number"), serde_json::json!(30));
        assert!(param_string_to_json("30", "Number").is_i64(), "whole number must be an integer");
        assert_eq!(param_string_to_json("1.5", "Number"), serde_json::json!(1.5));
        assert_eq!(param_string_to_json("not-a-number", "Number"), serde_json::json!("not-a-number"));
    }

    #[test]
    fn resolve_ref_param_with_allowed_values() {
        let input = r#"{"Parameters":{"Env":{"Type":"String","AllowedValues":["dev","prod"]}},"Resources":{"R":{"Type":"T","Properties":{"V":{"Ref":"Env"}}}}}"#;
        let ir = parser::parse(input.as_bytes()).unwrap();
        let (params, _) = extract_parameters(&ir);
        let resource_ids: HashSet<String> = ["R".to_string()].into_iter().collect();
        let (mappings, _) = extract_mappings(&ir);
        let no_param_overrides = HashMap::new();
        let no_pseudo_overrides = crate::model::PseudoParameterOverrides::default();
        let mut resolver =
            Resolver::new(&ir.arena, &params, &mappings, resource_ids, &no_param_overrides, &no_pseudo_overrides);
        let res_map = ir.arena.as_map(ir.resources).unwrap();
        let props = ir.arena.map_get(res_map[0].1, "Properties").unwrap();
        let v_ref = ir.arena.map_get(props, "V").unwrap();
        let result = resolver.resolve_node(v_ref);
        match result {
            ResolvedValue::Enum { variants: vals } => assert_eq!(vals.len(), 2),
            other => panic!("Expected Enum, got {:?}", other),
        }
    }

    #[test]
    fn resolve_ref_pseudo_params() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Ref":"AWS::Region"}}}}}"#;
        let ir = parser::parse(input.as_bytes()).unwrap();
        let (params, _) = extract_parameters(&ir);
        let (mappings, _) = extract_mappings(&ir);
        let no_param_overrides = HashMap::new();
        let no_pseudo_overrides = crate::model::PseudoParameterOverrides::default();
        let mut resolver = Resolver::new(
            &ir.arena,
            &params,
            &mappings,
            ["R".to_string()].into_iter().collect(),
            &no_param_overrides,
            &no_pseudo_overrides,
        );
        let res_map = ir.arena.as_map(ir.resources).unwrap();
        let props = ir.arena.map_get(res_map[0].1, "Properties").unwrap();
        let v_ref = ir.arena.map_get(props, "V").unwrap();
        let result = resolver.resolve_node(v_ref);
        match result {
            ResolvedValue::Concrete { value: JsonValue(serde_json::Value::String(s)) } => {
                assert_eq!(s, DEFAULT_REGION);
            }
            other => panic!("Expected Concrete(\"us-east-1\"), got {:?}", other),
        }
    }

    #[test]
    fn resolve_if() {
        let input = r#"{"Conditions":{"C":{"Fn::Equals":["a","a"]}},"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::If":["C",100,20]}}}}}"#;
        let ir = parser::parse(input.as_bytes()).unwrap();
        let (params, _) = extract_parameters(&ir);
        let (mappings, _) = extract_mappings(&ir);
        let no_param_overrides = HashMap::new();
        let no_pseudo_overrides = crate::model::PseudoParameterOverrides::default();
        let mut resolver = Resolver::new(
            &ir.arena,
            &params,
            &mappings,
            ["R".to_string()].into_iter().collect(),
            &no_param_overrides,
            &no_pseudo_overrides,
        );
        let res_map = ir.arena.as_map(ir.resources).unwrap();
        let props = ir.arena.map_get(res_map[0].1, "Properties").unwrap();
        let v_ref = ir.arena.map_get(props, "V").unwrap();
        let result = resolver.resolve_node(v_ref);
        assert!(matches!(result, ResolvedValue::Conditional { condition: _, if_true: _, if_false: _ }));
    }

    #[test]
    fn resolve_join_concrete() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Join":["-",["a","b","c"]]}}}}}"#;
        let ir = parser::parse(input.as_bytes()).unwrap();
        let (params, _) = extract_parameters(&ir);
        let (mappings, _) = extract_mappings(&ir);
        let no_param_overrides = HashMap::new();
        let no_pseudo_overrides = crate::model::PseudoParameterOverrides::default();
        let mut resolver = Resolver::new(
            &ir.arena,
            &params,
            &mappings,
            ["R".to_string()].into_iter().collect(),
            &no_param_overrides,
            &no_pseudo_overrides,
        );
        let res_map = ir.arena.as_map(ir.resources).unwrap();
        let props = ir.arena.map_get(res_map[0].1, "Properties").unwrap();
        let v_ref = ir.arena.map_get(props, "V").unwrap();
        let result = resolver.resolve_node(v_ref);
        match result {
            ResolvedValue::Concrete { value: v } => assert_eq!(v.as_str().unwrap(), "a-b-c"),
            other => panic!("Expected Concrete, got {:?}", other),
        }
    }

    #[test]
    fn resolve_ref_param_override_bypasses_allowed_values() {
        let input = r#"{"Parameters":{"Env":{"Type":"String","AllowedValues":["dev","prod"]}},"Resources":{"R":{"Type":"T","Properties":{"V":{"Ref":"Env"}}}}}"#;
        let ir = parser::parse(input.as_bytes()).unwrap();
        let (params, _) = extract_parameters(&ir);
        let (mappings, _) = extract_mappings(&ir);
        let param_overrides = [("Env".to_string(), "staging".to_string())].into_iter().collect();
        let no_pseudo_overrides = crate::model::PseudoParameterOverrides::default();
        let mut resolver = Resolver::new(
            &ir.arena,
            &params,
            &mappings,
            ["R".to_string()].into_iter().collect(),
            &param_overrides,
            &no_pseudo_overrides,
        );
        let res_map = ir.arena.as_map(ir.resources).unwrap();
        let props = ir.arena.map_get(res_map[0].1, "Properties").unwrap();
        let v_ref = ir.arena.map_get(props, "V").unwrap();
        let result = resolver.resolve_node(v_ref);
        match result {
            ResolvedValue::Concrete { value: v } => assert_eq!(v.as_str().unwrap(), "staging"),
            other => panic!("Expected Concrete(\"staging\"), got {:?}", other),
        }
    }

    #[test]
    fn resolve_ref_pseudo_param_override() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Ref":"AWS::Region"}}}}}"#;
        let ir = parser::parse(input.as_bytes()).unwrap();
        let (params, _) = extract_parameters(&ir);
        let (mappings, _) = extract_mappings(&ir);
        let no_param_overrides = HashMap::new();
        let pseudo_overrides =
            crate::model::PseudoParameterOverrides { region: Some("us-west-2".to_string()), ..Default::default() };
        let mut resolver = Resolver::new(
            &ir.arena,
            &params,
            &mappings,
            ["R".to_string()].into_iter().collect(),
            &no_param_overrides,
            &pseudo_overrides,
        );
        let res_map = ir.arena.as_map(ir.resources).unwrap();
        let props = ir.arena.map_get(res_map[0].1, "Properties").unwrap();
        let v_ref = ir.arena.map_get(props, "V").unwrap();
        let result = resolver.resolve_node(v_ref);
        match result {
            ResolvedValue::Concrete { value: v } => assert_eq!(v.as_str().unwrap(), "us-west-2"),
            other => panic!("Expected Concrete(\"us-west-2\"), got {:?}", other),
        }
    }

    #[test]
    fn resolve_sub_concrete_interpolation() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Sub":"prefix-${AWS::Region}-suffix"}}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Concrete { value: v }) => {
                assert_eq!(v.as_str().unwrap(), "prefix-us-east-1-suffix");
            }
            other => panic!("Expected Concrete, got {:?}", other),
        }
    }

    #[test]
    fn resolve_sub_with_enum_produces_enum() {
        let input = r#"{"Parameters":{"Env":{"Type":"String","AllowedValues":["dev","prod"]}},"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Sub":"app-${Env}"}}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Enum { variants: vals }) => {
                assert_eq!(vals.len(), 2);
                let strs: Vec<String> = vals
                    .iter()
                    .filter_map(|v| match v {
                        ResolvedValue::Concrete { value: j } => j.as_str().map(|s| s.to_string()),
                        _ => None,
                    })
                    .collect();
                assert!(strs.contains(&"app-dev".to_string()));
                assert!(strs.contains(&"app-prod".to_string()));
            }
            other => panic!("Expected Enum, got {:?}", other),
        }
    }

    #[test]
    fn resolve_sub_no_variables_is_redundant() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Sub":"no-vars-here"}}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        let r = model.resource("R").unwrap();
        assert!(!r.diagnostics.redundant_subs.is_empty());
    }

    #[test]
    fn resolve_sub_single_variable_is_simple() {
        let input = r#"{"Parameters":{"P":{"Type":"String","Default":"val"}},"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Sub":"${P}"}}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        let r = model.resource("R").unwrap();
        assert!(!r.diagnostics.simple_subs.is_empty());
    }

    #[test]
    fn resolve_split_concrete() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Split":[",","a,b,c"]}}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Concrete { value: v }) => {
                let arr = v.as_array().unwrap();
                assert_eq!(arr.len(), 3);
                assert_eq!(arr[0], "a");
                assert_eq!(arr[1], "b");
                assert_eq!(arr[2], "c");
            }
            other => panic!("Expected Concrete array, got {:?}", other),
        }
    }

    #[test]
    fn resolve_base64_concrete() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Base64":"hello"}}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Concrete { value: v }) => {
                assert_eq!(v.as_str().unwrap(), "aGVsbG8=");
            }
            other => panic!("Expected Concrete base64, got {:?}", other),
        }
    }

    #[test]
    fn resolve_select_concrete() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Select":[1,["a","b","c"]]}}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Concrete { value: v }) => assert_eq!(v.as_str().unwrap(), "b"),
            other => panic!("Expected Concrete(\"b\"), got {:?}", other),
        }
    }

    #[test]
    fn resolve_select_out_of_bounds() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Select":[5,["a","b"]]}}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Dynamic { reason: msg }) => assert!(msg.contains("out of bounds")),
            other => panic!("Expected Dynamic, got {:?}", other),
        }
    }

    #[test]
    fn resolve_getazs_default_region() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::GetAZs":""}}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Concrete { value: v }) => {
                let arr = v.as_array().unwrap();
                assert!(arr.len() >= 3);
                assert!(arr[0].as_str().unwrap().starts_with("us-east-1"));
            }
            other => panic!("Expected Concrete AZ array, got {:?}", other),
        }
    }

    #[test]
    fn resolve_to_json_string() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::ToJsonString":{"key":"value"}}}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Concrete { value: v }) => {
                let s = v.as_str().unwrap();
                assert!(s.contains("key"));
                assert!(s.contains("value"));
            }
            other => panic!("Expected Concrete JSON string, got {:?}", other),
        }
    }

    #[test]
    fn resolve_length_array() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Length":["a","b","c"]}}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Concrete { value: v }) => assert_eq!(v.as_i64().unwrap(), 3),
            other => panic!("Expected Concrete(3), got {:?}", other),
        }
    }

    #[test]
    fn resolve_cidr_concrete() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Cidr":["10.0.0.0/16","2","8"]}}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Concrete { value: v }) => {
                let arr = v.as_array().unwrap();
                assert_eq!(arr.len(), 2);
                assert!(arr[0].as_str().unwrap().contains("/24"));
            }
            other => panic!("Expected Concrete CIDR array, got {:?}", other),
        }
    }

    #[test]
    fn resolve_import_value_is_typed_dynamic() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::ImportValue":"StackExport"}}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::TypedDynamic { reason, param_type: t }) => {
                assert_eq!(t, "String");
                // The export name is carried so distinct imports stay distinct.
                assert!(reason.contains("StackExport"), "reason should carry the export name, got {reason:?}");
            }
            other => panic!("Expected TypedDynamic, got {:?}", other),
        }
    }

    #[test]
    fn resolve_import_value_distinct_exports_differ() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{
            "A":{"Fn::ImportValue":"ExportOne"},
            "B":{"Fn::ImportValue":"ExportTwo"}
        }}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        let a = model.resolve("R", "Properties.A").cloned();
        let b = model.resolve("R", "Properties.B").cloned();
        match (a, b) {
            (
                Some(ResolvedValue::TypedDynamic { reason: ra, .. }),
                Some(ResolvedValue::TypedDynamic { reason: rb, .. }),
            ) => assert_ne!(ra, rb, "distinct exports must produce distinct symbolic values"),
            other => panic!("Expected two TypedDynamic, got {:?}", other),
        }
    }

    #[test]
    fn resolve_get_stack_output_carries_source_identity() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::GetStackOutput":{
            "StackName":"VpcStack","Region":"ap-northeast-1","OutputName":"PublicSubnetOne"
        }}}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Dynamic { reason }) => {
                // The source is carried so distinct outputs stay distinct.
                for field in ["VpcStack", "ap-northeast-1", "PublicSubnetOne"] {
                    assert!(reason.contains(field), "reason should carry {field}, got {reason:?}");
                }
            }
            other => panic!("Expected Dynamic, got {:?}", other),
        }
    }

    #[test]
    fn resolve_get_stack_output_distinct_sources_differ() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{
            "Baseline":{"Fn::GetStackOutput":{
                "StackName":"VpcStack","Region":"ap-northeast-1","OutputName":"PublicSubnetOne"
            }},
            "OtherStack":{"Fn::GetStackOutput":{
                "StackName":"OtherVpcStack","Region":"ap-northeast-1","OutputName":"PublicSubnetOne"
            }},
            "OtherRegion":{"Fn::GetStackOutput":{
                "StackName":"VpcStack","Region":"us-east-1","OutputName":"PublicSubnetOne"
            }},
            "OtherOutput":{"Fn::GetStackOutput":{
                "StackName":"VpcStack","Region":"ap-northeast-1","OutputName":"PublicSubnetTwo"
            }},
            "Reordered":{"Fn::GetStackOutput":{
                "OutputName":"PublicSubnetOne","StackName":"VpcStack","Region":"ap-northeast-1"
            }},
            "OtherRole":{"Fn::GetStackOutput":{
                "StackName":"VpcStack","Region":"ap-northeast-1","OutputName":"PublicSubnetOne",
                "RoleArn":"arn:aws:iam::444455556666:role/Lookup"
            }}
        }}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        let source_of = |property: &str| match model.resolve("R", &format!("Properties.{property}")) {
            Some(ResolvedValue::Dynamic { reason }) => reason.clone(),
            other => panic!("Expected Dynamic for {property}, got {other:?}"),
        };

        let baseline = source_of("Baseline");
        for distinct in ["OtherStack", "OtherRegion", "OtherOutput"] {
            assert_ne!(baseline, source_of(distinct), "{distinct} must not collapse onto the baseline output");
        }
        assert_eq!(baseline, source_of("Reordered"), "argument order must not make the same output distinct");
        // RoleArn selects nothing about which output is read, so a call that differs
        // only there is still the same value and must stay a duplicate.
        assert_eq!(baseline, source_of("OtherRole"), "RoleArn must not make the same output distinct");
    }

    #[test]
    fn embedded_dynamic_reference_is_opaque() {
        // A dynamic reference embedded mid-string resolves at deploy time, so it
        // must become opaque even though it does not start with `{{resolve:`.
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":"prefix-{{resolve:ssm:/my/param}}"}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::TypedDynamic { reason, param_type: t }) => {
                assert_eq!(t, "String");
                assert!(
                    reason.contains("{{resolve:ssm:/my/param}}"),
                    "reason should carry the literal, got {reason:?}"
                );
            }
            other => panic!("Expected TypedDynamic, got {:?}", other),
        }
    }

    #[test]
    fn sub_producing_dynamic_reference_is_opaque() {
        // Fn::Sub passes `{{resolve:...}}` through literally; the concatenated
        // result still embeds a dynamic reference and must be opaque.
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Sub":"${AWS::Region}-{{resolve:ssm:/my/param}}"}}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::TypedDynamic { reason, .. }) => {
                assert!(
                    reason.contains("{{resolve:ssm:/my/param}}"),
                    "reason should carry the literal, got {reason:?}"
                );
            }
            other => panic!("Expected TypedDynamic, got {:?}", other),
        }
    }

    #[test]
    fn join_producing_dynamic_reference_is_opaque() {
        // Fn::Join over a list whose element is a dynamic reference: the element
        // is made opaque before the join runs, so the join sees a non-concrete
        // argument and yields an opaque value the value-format rules skip.
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Join":["-",["prefix","{{resolve:ssm:/my/param}}"]]}}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        let resolved = model.resolve("R", "Properties.V").expect("V should resolve");
        assert!(
            crate::resolved_value::contains_dynamic_resolved(resolved),
            "Fn::Join embedding a dynamic reference must be opaque, got {resolved:?}"
        );
        assert!(
            !matches!(resolved, ResolvedValue::Concrete { .. }),
            "the join result must not be a concrete literal, got {resolved:?}"
        );
    }

    #[test]
    fn select_producing_dynamic_reference_is_opaque() {
        // Fn::Select picking a dynamic-reference element must be opaque.
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Select":[1,["a","{{resolve:ssm:/my/param}}"]]}}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::TypedDynamic { reason, .. }) => {
                assert!(
                    reason.contains("{{resolve:ssm:/my/param}}"),
                    "reason should carry the literal, got {reason:?}"
                );
            }
            other => panic!("Expected TypedDynamic, got {:?}", other),
        }
    }

    #[test]
    fn nested_dynamic_reference_stays_inside_list() {
        // A dynamic reference nested in a list element becomes opaque without
        // collapsing the parent list, so the list is preserved with an opaque entry.
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":["plain","{{resolve:ssm:/my/param}}"]}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::List { items }) => {
                assert_eq!(items.len(), 2);
                assert!(matches!(items[0], ResolvedValue::Concrete { .. }));
                assert!(
                    matches!(items[1], ResolvedValue::TypedDynamic { .. }),
                    "the embedded reference element must be opaque, got {:?}",
                    items[1]
                );
            }
            other => panic!("Expected List with an opaque element, got {:?}", other),
        }
    }

    #[test]
    fn malformed_dynamic_reference_with_space_stays_concrete() {
        // `{{ resolve:...}}` (a space after `{{`) is not a valid dynamic reference
        // and CloudFormation will not resolve it, so it must stay concrete for the
        // spaces-in-dynamic-reference warning to inspect.
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":"{{ resolve:ssm:/my/param}}"}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Concrete { value: v }) => {
                assert_eq!(v.as_str().unwrap(), "{{ resolve:ssm:/my/param}}");
            }
            other => panic!("Expected Concrete, got {:?}", other),
        }
    }

    #[test]
    fn comma_delimited_list_default_resolves_to_array() {
        let input = r#"{"Parameters":{"P":{"Type":"CommaDelimitedList","Default":"GET, PUT ,POST"}},
            "Resources":{"R":{"Type":"T","Properties":{"V":{"Ref":"P"}}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Concrete { value }) => {
                assert_eq!(
                    **value,
                    serde_json::json!(["GET", "PUT", "POST"]),
                    "default must split into a trimmed array"
                );
            }
            other => panic!("Expected Concrete array, got {:?}", other),
        }
    }

    #[test]
    fn resolve_no_value_is_null() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Ref":"AWS::NoValue"}}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Concrete { value: v }) => assert!(v.is_null()),
            other => panic!("Expected Concrete(null), got {:?}", other),
        }
    }

    #[test]
    fn extract_parameters_with_constraints() {
        let input = r#"{"Parameters":{"P":{"Type":"String","MinLength":1,"MaxLength":100,"AllowedPattern":"^[a-z]+$","Default":"abc","NoEcho":true}},"Resources":{"R":{"Type":"T"}}}"#;
        let ir = parser::parse(input.as_bytes()).unwrap();
        let (params, _) = extract_parameters(&ir);
        let p = &params["P"];
        assert_eq!(p.param_type, "String");
        assert_eq!(p.default.as_deref(), Some("abc"));
        assert_eq!(p.min_length, Some(1));
        assert_eq!(p.max_length, Some(100));
        assert_eq!(p.allowed_pattern.as_deref(), Some("^[a-z]+$"));
        assert!(p.no_echo);
    }

    #[test]
    fn extract_parameters_number_type() {
        let input = r#"{"Parameters":{"N":{"Type":"Number","Default":"42","MinValue":0,"MaxValue":100}},"Resources":{"R":{"Type":"T"}}}"#;
        let ir = parser::parse(input.as_bytes()).unwrap();
        let (params, _) = extract_parameters(&ir);
        let n = &params["N"];
        assert_eq!(n.param_type, "Number");
        assert_eq!(n.default.as_deref(), Some("42"));
        assert_eq!(n.min_value, Some(0));
        assert_eq!(n.max_value, Some(100));
    }

    #[test]
    fn extract_mappings_three_level() {
        let input = r#"{"Mappings":{"M":{"k1":{"k2":"val"}}},"Resources":{"R":{"Type":"T"}}}"#;
        let ir = parser::parse(input.as_bytes()).unwrap();
        let (mappings, diags) = extract_mappings(&ir);
        assert!(diags.is_empty());
        assert_eq!(mappings["M"]["k1"]["k2"], serde_json::json!("val"));
    }

    #[test]
    fn extract_mappings_invalid_structure_produces_diagnostic() {
        let input = r#"{"Mappings":{"M":"not-a-map"},"Resources":{"R":{"Type":"T"}}}"#;
        let ir = parser::parse(input.as_bytes()).unwrap();
        let (_, diags) = extract_mappings(&ir);
        assert!(!diags.is_empty());
        assert_eq!(diags[0].rule_id, "F0017");
    }

    #[test]
    fn resolve_findinmap_with_enum_key() {
        let input = r#"{"Parameters":{"Env":{"Type":"String","AllowedValues":["dev","prod"]}},"Mappings":{"M":{"dev":{"v":"d"},"prod":{"v":"p"}}},"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::FindInMap":["M",{"Ref":"Env"},"v"]}}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Enum { variants: vals }) => {
                assert_eq!(vals.len(), 2);
                let strs: Vec<String> = vals
                    .iter()
                    .filter_map(|v| match v {
                        ResolvedValue::Concrete { value: j } => j.as_str().map(|s| s.to_string()),
                        _ => None,
                    })
                    .collect();
                assert!(strs.contains(&"d".to_string()));
                assert!(strs.contains(&"p".to_string()));
            }
            other => panic!("Expected Enum, got {:?}", other),
        }
    }

    #[test]
    fn resolve_hardcoded_partition_arn_tracked() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Sub":"arn:aws:s3:::my-bucket"}}}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        let r = model.resource("R").unwrap();
        assert!(!r.diagnostics.hardcoded_partition_arns.is_empty());
    }

    #[test]
    fn resolve_getatt_produces_reference() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::GetAtt":["Other","Arn"]}}},"Other":{"Type":"T2"}}}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Reference { target: t, kind: RefKind::GetAtt { attr: a } }) => {
                assert_eq!(t, "Other");
                assert_eq!(a, "Arn");
            }
            other => panic!("Expected Reference(GetAtt), got {:?}", other),
        }
    }

    #[test]
    fn findinmap_concrete_first_key_enum_second_key_produces_enum() {
        let input = r#"{
            "Parameters":{"K2":{"Type":"String","AllowedValues":["a","b"]}},
            "Mappings":{"M":{"x":{"a":"va","b":"vb"}}},
            "Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::FindInMap":["M","x",{"Ref":"K2"}]}}}}
        }"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Enum { variants }) => {
                assert_eq!(variants.len(), 2);
                let strs: Vec<String> = variants
                    .iter()
                    .filter_map(|v| match v {
                        ResolvedValue::Concrete { value: j } => j.as_str().map(|s| s.to_string()),
                        _ => None,
                    })
                    .collect();
                assert!(strs.contains(&"va".to_string()));
                assert!(strs.contains(&"vb".to_string()));
            }
            other => panic!("Expected Enum, got {:?}", other),
        }
    }

    #[test]
    fn findinmap_enum_first_key_enum_second_key_produces_flattened_enum() {
        let input = r#"{
            "Parameters":{
                "K1":{"Type":"String","AllowedValues":["r1","r2"]},
                "K2":{"Type":"String","AllowedValues":["a","b"]}
            },
            "Mappings":{"M":{"r1":{"a":"r1a","b":"r1b"},"r2":{"a":"r2a","b":"r2b"}}},
            "Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::FindInMap":["M",{"Ref":"K1"},{"Ref":"K2"}]}}}}
        }"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Enum { variants }) => {
                // 2 k1 variants × 2 k2 variants = 4 total
                assert_eq!(variants.len(), 4);
                let strs: Vec<String> = variants
                    .iter()
                    .filter_map(|v| match v {
                        ResolvedValue::Concrete { value: j } => j.as_str().map(|s| s.to_string()),
                        _ => None,
                    })
                    .collect();
                assert!(strs.contains(&"r1a".to_string()));
                assert!(strs.contains(&"r1b".to_string()));
                assert!(strs.contains(&"r2a".to_string()));
                assert!(strs.contains(&"r2b".to_string()));
            }
            other => panic!("Expected Enum with 4 variants, got {:?}", other),
        }
    }

    #[test]
    fn findinmap_conditional_second_key_produces_conditional() {
        let input = r#"{
            "Conditions":{"C":{"Fn::Equals":["a","a"]}},
            "Mappings":{"M":{"x":{"a":"va","b":"vb"}}},
            "Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::FindInMap":["M","x",{"Fn::If":["C","a","b"]}]}}}}
        }"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Conditional { .. }) => {}
            other => panic!("Expected Conditional, got {:?}", other),
        }
    }

    #[test]
    fn select_from_list_with_mixed_items_returns_element() {
        // When the list contains a Ref (non-concrete), it becomes a List variant.
        // Select index 0 should return the concrete element.
        let input = r#"{
            "Resources":{
                "Other":{"Type":"T2"},
                "R":{"Type":"T","Properties":{"V":{"Fn::Select":[0,[{"Fn::GetAZs":"us-east-1"},{"Ref":"Other"}]]}}}
            }
        }"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Concrete { value: v }) => {
                let arr = v.as_array().unwrap();
                assert!(arr[0].as_str().unwrap().starts_with("us-east-1"));
            }
            other => panic!("Expected Concrete AZ array from Select on List, got {:?}", other),
        }
    }

    #[test]
    fn select_from_list_out_of_bounds_returns_dynamic() {
        let input = r#"{
            "Resources":{
                "Other":{"Type":"T2"},
                "R":{"Type":"T","Properties":{"V":{"Fn::Select":[5,["a",{"Ref":"Other"}]]}}}
            }
        }"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Dynamic { reason }) => {
                assert!(reason.contains("out of bounds"));
            }
            other => panic!("Expected Dynamic out of bounds, got {:?}", other),
        }
    }

    #[test]
    fn equals_two_concrete_strings_returns_true() {
        let input = r#"{
            "Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Equals":["hello","hello"]}}}}
        }"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Concrete { value: v }) => {
                assert_eq!(v.as_bool(), Some(true));
            }
            other => panic!("Expected Concrete(true), got {:?}", other),
        }
    }

    #[test]
    fn equals_two_different_strings_returns_false() {
        let input = r#"{
            "Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Equals":["a","b"]}}}}
        }"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Concrete { value: v }) => {
                assert_eq!(v.as_bool(), Some(false));
            }
            other => panic!("Expected Concrete(false), got {:?}", other),
        }
    }

    #[test]
    fn equals_enum_against_concrete_produces_enum_of_bools() {
        let input = r#"{
            "Parameters":{"Env":{"Type":"String","AllowedValues":["dev","prod"]}},
            "Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Equals":[{"Ref":"Env"},"prod"]}}}}
        }"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Enum { variants }) => {
                assert_eq!(variants.len(), 2);
                let bools: Vec<bool> = variants
                    .iter()
                    .filter_map(|v| match v {
                        ResolvedValue::Concrete { value: j } => j.as_bool(),
                        _ => None,
                    })
                    .collect();
                assert!(bools.contains(&true));
                assert!(bools.contains(&false));
            }
            other => panic!("Expected Enum of bools, got {:?}", other),
        }
    }

    #[test]
    fn and_all_true_returns_true() {
        let input = r#"{
            "Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::And":[{"Fn::Equals":["a","a"]},{"Fn::Equals":["b","b"]}]}}}}
        }"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Concrete { value: v }) => {
                assert_eq!(v.as_bool(), Some(true));
            }
            other => panic!("Expected Concrete(true), got {:?}", other),
        }
    }

    #[test]
    fn and_one_false_returns_false() {
        let input = r#"{
            "Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::And":[{"Fn::Equals":["a","a"]},{"Fn::Equals":["a","b"]}]}}}}
        }"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Concrete { value: v }) => {
                assert_eq!(v.as_bool(), Some(false));
            }
            other => panic!("Expected Concrete(false), got {:?}", other),
        }
    }

    #[test]
    fn or_one_true_returns_true() {
        let input = r#"{
            "Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Or":[{"Fn::Equals":["a","b"]},{"Fn::Equals":["c","c"]}]}}}}
        }"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Concrete { value: v }) => {
                assert_eq!(v.as_bool(), Some(true));
            }
            other => panic!("Expected Concrete(true), got {:?}", other),
        }
    }

    #[test]
    fn or_all_false_returns_false() {
        let input = r#"{
            "Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Or":[{"Fn::Equals":["a","b"]},{"Fn::Equals":["c","d"]}]}}}}
        }"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Concrete { value: v }) => {
                assert_eq!(v.as_bool(), Some(false));
            }
            other => panic!("Expected Concrete(false), got {:?}", other),
        }
    }

    #[test]
    fn not_true_returns_false() {
        let input = r#"{
            "Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Not":[{"Fn::Equals":["a","a"]}]}}}}
        }"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Concrete { value: v }) => {
                assert_eq!(v.as_bool(), Some(false));
            }
            other => panic!("Expected Concrete(false), got {:?}", other),
        }
    }

    #[test]
    fn and_with_dynamic_child_returns_dynamic() {
        let input = r#"{
            "Resources":{
                "Other":{"Type":"T2"},
                "R":{"Type":"T","Properties":{"V":{"Fn::And":[{"Fn::Equals":["a","a"]},{"Fn::Equals":[{"Ref":"Other"},"x"]}]}}}
            }
        }"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Dynamic { .. }) => {}
            other => panic!("Expected Dynamic, got {:?}", other),
        }
    }

    #[test]
    fn sub_enum_plus_reference_produces_enum_with_dynamic_variants() {
        let input = r#"{
            "Parameters":{"Env":{"Type":"String","AllowedValues":["dev","prod"]}},
            "Resources":{
                "Bucket":{"Type":"AWS::S3::Bucket"},
                "R":{"Type":"T","Properties":{"V":{"Fn::Sub":"arn:${Env}:${Bucket}"}}}
            }
        }"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Enum { variants }) => {
                assert_eq!(variants.len(), 2);
                // Both should be Dynamic because ${Bucket} is unresolved
                for v in variants {
                    match v {
                        ResolvedValue::Dynamic { reason } => {
                            assert!(reason.starts_with("Sub:"));
                        }
                        _ => panic!("Expected Dynamic variant, got {:?}", v),
                    }
                }
            }
            other => panic!("Expected Enum with Dynamic variants, got {:?}", other),
        }
    }

    #[test]
    fn join_list_with_mixed_concrete_and_reference_produces_partial_dynamic() {
        let input = r#"{
            "Resources":{
                "Other":{"Type":"T2"},
                "R":{"Type":"T","Properties":{"V":{"Fn::Join":["-",["prefix",{"Ref":"Other"},"suffix"]]}}}
            }
        }"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Dynamic { reason }) => {
                assert!(reason.starts_with("Join:"));
                assert!(reason.contains("prefix"));
                assert!(reason.contains("suffix"));
            }
            other => panic!("Expected Dynamic with Join: prefix, got {:?}", other),
        }
    }

    #[test]
    fn getazs_enum_region_produces_enum_of_az_arrays() {
        let input = r#"{
            "Parameters":{"Region":{"Type":"String","AllowedValues":["us-east-1","us-west-2"]}},
            "Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::GetAZs":{"Ref":"Region"}}}}}
        }"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Enum { variants }) => {
                assert_eq!(variants.len(), 2);
                for v in variants {
                    match v {
                        ResolvedValue::Concrete { value: arr } => {
                            assert!(arr.as_array().unwrap().len() >= 2);
                        }
                        _ => panic!("Expected Concrete AZ arrays, got {:?}", v),
                    }
                }
            }
            other => panic!("Expected Enum of AZ arrays, got {:?}", other),
        }
    }

    #[test]
    fn cidr_enum_ip_block_produces_enum_of_cidr_arrays() {
        let input = r#"{
            "Parameters":{"Cidr":{"Type":"String","AllowedValues":["10.0.0.0/16","172.16.0.0/16"]}},
            "Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Cidr":[{"Ref":"Cidr"},"2","8"]}}}}
        }"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Enum { variants }) => {
                assert_eq!(variants.len(), 2);
                for v in variants {
                    match v {
                        ResolvedValue::Concrete { value: arr } => {
                            assert_eq!(arr.as_array().unwrap().len(), 2);
                        }
                        _ => panic!("Expected Concrete CIDR arrays, got {:?}", v),
                    }
                }
            }
            other => panic!("Expected Enum of CIDR arrays, got {:?}", other),
        }
    }

    #[test]
    fn to_json_string_enum_produces_enum_of_strings() {
        let input = r#"{
            "Parameters":{"Val":{"Type":"String","AllowedValues":["a","b"]}},
            "Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::ToJsonString":{"Ref":"Val"}}}}}
        }"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Enum { variants }) => {
                assert_eq!(variants.len(), 2);
                for v in variants {
                    match v {
                        ResolvedValue::Concrete { value: j } => {
                            assert!(j.is_string());
                        }
                        _ => panic!("Expected Concrete string, got {:?}", v),
                    }
                }
            }
            other => panic!("Expected Enum, got {:?}", other),
        }
    }

    #[test]
    fn to_json_string_conditional_produces_conditional() {
        let input = r#"{
            "Conditions":{"C":{"Fn::Equals":["a","a"]}},
            "Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::ToJsonString":{"Fn::If":["C","yes","no"]}}}}}
        }"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Conditional { .. }) => {}
            other => panic!("Expected Conditional, got {:?}", other),
        }
    }

    #[test]
    fn length_of_resolved_list_returns_count() {
        // A list with mixed items (concrete + reference) becomes ResolvedValue::List
        let input = r#"{
            "Resources":{
                "Other":{"Type":"T2"},
                "R":{"Type":"T","Properties":{"V":{"Fn::Length":[1,{"Ref":"Other"},3]}}}
            }
        }"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Concrete { value: v }) => {
                assert_eq!(v.as_i64(), Some(3));
            }
            other => panic!("Expected Concrete(3), got {:?}", other),
        }
    }

    #[test]
    fn foreach_concrete_collection_evaluates_body() {
        let input = r#"{
            "Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::ForEach":["Id","Item",["a","b"],{"Fn::Sub":"prefix-${Item}"}]}}}}
        }"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Map { entries }) => {
                assert_eq!(entries.len(), 2);
                let values: Vec<String> = entries
                    .iter()
                    .filter_map(|e| match &e.value {
                        ResolvedValue::Concrete { value: v } => v.as_str().map(|s| s.to_string()),
                        _ => None,
                    })
                    .collect();
                assert!(values.contains(&"prefix-a".to_string()));
                assert!(values.contains(&"prefix-b".to_string()));
            }
            other => panic!("Expected Map with evaluated body, got {:?}", other),
        }
    }

    #[test]
    fn foreach_dynamic_collection_returns_dynamic() {
        let input = r#"{
            "Resources":{
                "Other":{"Type":"T2"},
                "R":{"Type":"T","Properties":{"V":{"Fn::ForEach":["Id","Item",{"Ref":"Other"},"body"]}}}
            }
        }"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Dynamic { .. }) => {}
            other => panic!("Expected Dynamic, got {:?}", other),
        }
    }
}
