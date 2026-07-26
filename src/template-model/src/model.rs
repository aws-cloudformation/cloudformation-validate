use crate::conditions::ConditionModel;
use crate::consts::*;
use crate::defect::ParseDefect;
use crate::graph::ReferenceGraph;
use crate::ir::*;
use crate::json_value::JsonValue;
use crate::regions::*;
use crate::resolved_value::*;
use crate::resolver::*;
use crate::sam;
use crate::span::SpanProvider;
use log::{debug, info, warn};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// A resource property path paired with a string value found at it, such as a substitution variable or literal.
#[derive(Debug, Clone, Serialize, Default)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct PathValuePair {
    /// Dot-separated property path within the resource (e.g. 'Properties.BucketName').
    pub path: String,
    pub value: String,
}

/// A property that is dropped (resolves to AWS::NoValue) in one branch of an Fn::If condition.
#[derive(Debug, Clone, Serialize, Default)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct ConditionalNullEntry {
    /// Dot-separated property path that becomes absent in one branch.
    pub path: String,
    /// Name of the condition governing the Fn::If that drops this property.
    pub condition: String,
    /// True when the property is absent in the condition's true branch; false when absent in the false branch.
    pub null_in_true_branch: bool,
}

/// Per-resource observations collected while resolving intrinsics, used to drive lint checks.
#[derive(Debug, Clone, Serialize, Default)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct ResourceDiagnostics {
    /// Mapping names referenced by Fn::FindInMap within this resource.
    pub find_in_map_refs: Vec<String>,
    /// Fn::Sub uses whose template is a single variable that could be a plain Ref; each pairs the property path with the variable name.
    pub simple_subs: Vec<PathValuePair>,
    /// Property paths where Fn::Sub wraps a constant string with no variables to substitute.
    pub redundant_subs: Vec<String>,
    /// Property paths where Fn::Join uses an empty delimiter, concatenating its elements directly.
    pub empty_joins: Vec<String>,
    /// Names of conditions referenced by this resource's property values.
    pub condition_refs: Vec<String>,
    /// Property paths building ARNs with a hardcoded 'aws' partition instead of AWS::Partition.
    pub hardcoded_partition_arns: Vec<String>,
    pub conditionally_null_props: Vec<ConditionalNullEntry>,
    pub foreach_expansions: Vec<ForEachExpansion>,
    /// Occurrences of ${...} placeholders outside an Fn::Sub that will not be substituted; each pairs the property path with the placeholder text.
    pub unsubstituted_variables: Vec<PathValuePair>,
    /// Fn::Sub map keys not referenced in the template string; each pairs the property path with the unused key name.
    pub unused_sub_keys: Vec<PathValuePair>,
    /// Property values that are a raw pseudo-parameter string (e.g. "AWS::Region") instead of using Ref.
    pub raw_pseudo_params: Vec<PathValuePair>,
    /// Property paths containing a {{resolve:secretsmanager:...}} dynamic reference.
    pub secretsmanager_ref_paths: Vec<String>,
    /// References whose target is not a defined resource, parameter, or pseudo parameter; each pairs the property path with the missing target name.
    pub invalid_refs: Vec<PathValuePair>,
}

/// A template resource with its metadata and properties after intrinsic functions have been resolved.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct ResolvedResource {
    pub logical_id: String,
    pub resource_type: String,
    #[cfg_attr(feature = "wasm-bindings", tsify(optional))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub condition: Option<String>,
    pub depends_on: Vec<String>,
    #[cfg_attr(feature = "wasm-bindings", tsify(optional))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub deletion_policy: Option<ResolvedValue>,
    #[cfg_attr(feature = "wasm-bindings", tsify(optional))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub update_replace_policy: Option<ResolvedValue>,
    #[cfg_attr(feature = "wasm-bindings", tsify(optional, type = "JsonValue"))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub update_policy: Option<JsonValue>,
    #[cfg_attr(feature = "wasm-bindings", tsify(optional, type = "JsonValue"))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub creation_policy: Option<JsonValue>,
    #[cfg_attr(feature = "wasm-bindings", tsify(optional, type = "JsonValue"))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub metadata: Option<JsonValue>,
    #[cfg_attr(feature = "wasm-bindings", tsify(type = "Record<string, ResolvedValue>"))]
    pub properties: HashMap<String, ResolvedValue>,
    /// True when the entire `Properties` block is a non-map intrinsic (e.g.
    /// `Properties: !Ref AWS::NoValue`) whose effective property set is only known
    /// at deploy time, as distinct from a resource that simply declares no properties.
    pub properties_dynamic: bool,
    pub diagnostics: ResourceDiagnostics,
}

/// An Fn::ForEach loop within a resource that expands a property over a collection.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct ForEachExpansion {
    /// Property path within the resource where the Fn::ForEach appears.
    pub property_path: String,
    /// Loop variable name bound to each element during expansion.
    pub identifier: String,
    /// Human-readable description of the collection being iterated over.
    pub collection_source: String,
}

/// A template output with its value and metadata after intrinsic functions have been resolved.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct ResolvedOutput {
    pub value: ResolvedValue,
    #[cfg_attr(feature = "wasm-bindings", tsify(optional))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub description: Option<String>,
    #[cfg_attr(feature = "wasm-bindings", tsify(optional))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub condition: Option<String>,
    #[cfg_attr(feature = "wasm-bindings", tsify(optional))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub export_name: Option<ResolvedValue>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateRule {
    pub name: String,
    pub condition: Option<serde_json::Value>,
    #[serde(skip)]
    pub condition_node: crate::ir::NodeRef,
    pub assertions: Vec<RuleAssertion>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleAssertion {
    pub assert: serde_json::Value,
    #[serde(skip)]
    pub assert_node: crate::ir::NodeRef,
    pub description: Option<String>,
}

pub struct SemanticModel {
    pub arena: Arena,
    pub span_index: SourceSpanIndex,
    pub format_version: Option<String>,
    pub description: Option<String>,
    pub transforms: Vec<String>,
    pub raw_top_level_keys: Vec<String>,
    pub template_metadata: Option<serde_json::Value>,
    pub rules: Option<serde_json::Value>,
    pub parsed_rules: Vec<TemplateRule>,
    pub parameters: HashMap<String, ParameterInfo>,
    pub mappings: MappingData,
    pub conditions: ConditionModel,
    pub resources: HashMap<String, ResolvedResource>,
    pub outputs: HashMap<String, ResolvedOutput>,
    pub graph: ReferenceGraph,
    pub resources_by_type: HashMap<String, Vec<String>>,
    pub diagnostics: Vec<ParseDefect>,
    pub output_empty_joins: Vec<String>,
    pub sam_globals: HashMap<String, HashMap<String, serde_json::Value>>,
    pub sam_implicit_resources: HashSet<String>,
    pub globals_param_refs: Vec<String>,
    pub is_cdk: bool,
    pub fn_if_conditions: Vec<String>,
    /// Mapping names referenced by an `Fn::FindInMap` with a literal map name,
    /// collected template-wide (resources, outputs, conditions, ForEach bodies).
    pub find_in_map_names: HashSet<String>,
    /// Parameter names referenced from within another parameter's definition
    /// (e.g. a Default of `!Ref OtherParam`); these still count as usage.
    pub params_referenced_in_definitions: HashSet<String>,
    /// True when any `Fn::FindInMap` uses a non-literal map name, which disables
    /// the unused-mapping check because usage can no longer be attributed to a
    /// specific mapping.
    pub has_dynamic_findinmap_name: bool,
    pub resolution_sources: HashMap<(String, String), String>,
    resolve_memo: Mutex<HashMap<(String, String), Option<ResolvedValue>>>,
    scenario_memo: Mutex<HashMap<(String, String), Vec<(serde_json::Value, HashMap<String, bool>)>>>,
    /// Cumulative count of scenarios materialized by `resolve_scenarios` across
    /// the whole validation, charged against `MAX_TOTAL_SCENARIO_COMBINATIONS`.
    /// Bounds total scenario-expansion work the way `ConditionModel`'s
    /// `sat_iterations_used` bounds total satisfiability work.
    scenario_combinations_used: AtomicU64,
}

/// Values used for AWS pseudo parameters (Ref AWS::Region, AWS::AccountId, ...) when
/// resolving the template; any field left unset falls back to a sensible default.
#[derive(Debug, Clone, Default, Serialize, serde::Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm-bindings", tsify(from_wasm_abi))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct PseudoParameterOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub notification_arns: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub partition: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub stack_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub stack_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub url_suffix: Option<String>,
}

fn is_account_id_shaped(value: &str) -> bool {
    value.len() == 12 && value.bytes().all(|b| b.is_ascii_digit())
}

fn is_partition_shaped(value: &str) -> bool {
    value.starts_with("aws")
}

impl PseudoParameterOverrides {
    pub fn region(&self) -> &str {
        self.region.as_deref().unwrap_or(DEFAULT_REGION)
    }

    pub fn get(&self, name: &str) -> Option<String> {
        match name {
            PSEUDO_ACCOUNT_ID => Some(self.account_id.clone().unwrap_or_else(|| DEFAULT_ACCOUNT_ID.into())),
            PSEUDO_NOTIFICATION_ARNS => Some(self.notification_arns.clone().unwrap_or_else(|| {
                let r = self.region();
                let p = self.partition.as_deref().unwrap_or_else(|| partition_for_region(r));
                format!("arn:{}:sns:{}:{}:notification", p, r, DEFAULT_ACCOUNT_ID)
            })),
            PSEUDO_PARTITION => {
                Some(self.partition.clone().unwrap_or_else(|| partition_for_region(self.region()).into()))
            }
            PSEUDO_REGION => Some(self.region().to_string()),
            PSEUDO_STACK_ID => Some(self.stack_id.clone().unwrap_or_else(|| {
                let r = self.region();
                let p = self.partition.as_deref().unwrap_or_else(|| partition_for_region(r));
                format!(
                    "arn:{}:cloudformation:{}:{}:stack/{}/51af3dc0-da77-11e4-872e-1234567db123",
                    p, r, DEFAULT_ACCOUNT_ID, DEFAULT_STACK_NAME
                )
            })),
            PSEUDO_STACK_NAME => Some(self.stack_name.clone().unwrap_or_else(|| DEFAULT_STACK_NAME.into())),
            PSEUDO_URL_SUFFIX => {
                Some(self.url_suffix.clone().unwrap_or_else(|| url_suffix_for_region(self.region()).into()))
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn invalid_overrides(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if let Some(account_id) = self.account_id.as_deref()
            && !is_account_id_shaped(account_id)
        {
            problems.push(format!("{PSEUDO_ACCOUNT_ID} override '{account_id}' is not a 12-digit AWS account ID"));
        }
        if let Some(partition) = self.partition.as_deref()
            && !is_partition_shaped(partition)
        {
            problems.push(format!(
                "{PSEUDO_PARTITION} override '{partition}' is not a valid partition \
                 (expected an 'aws'-family value such as aws, aws-cn, or aws-us-gov)"
            ));
        }
        problems
    }

    /// Returns the user-supplied override for `name` only when the caller
    /// explicitly set the corresponding field. Auto-derived defaults — e.g. the
    /// commercial-vs-cn-vs-gov partition implied by `region` — are *not*
    /// returned here.
    ///
    /// The satisfiability solver uses this to decide whether a pseudo-parameter
    /// is a constant (user pinned its value) or a free variable ranging over
    /// the literals it is compared against plus a sentinel for "any other
    /// value". `get` always returns a default and would force the solver to
    /// treat every pseudo-parameter as a constant, producing false-positive
    /// "unreachable branch" diagnostics for templates that branch on
    /// `AWS::Partition`, `AWS::Region`, etc. — see `ConditionModel::eval_value_concrete`.
    pub fn fixed_value(&self, name: &str) -> Option<String> {
        match name {
            PSEUDO_ACCOUNT_ID => self.account_id.clone(),
            PSEUDO_NOTIFICATION_ARNS => self.notification_arns.clone(),
            PSEUDO_PARTITION => self.partition.clone(),
            PSEUDO_REGION => self.region.clone(),
            PSEUDO_STACK_ID => self.stack_id.clone(),
            PSEUDO_STACK_NAME => self.stack_name.clone(),
            PSEUDO_URL_SUFFIX => self.url_suffix.clone(),
            _ => None,
        }
    }
}

#[derive(Default)]
pub struct ParseConfig {
    pub parameters: HashMap<String, String>,
    pub pseudo_parameters: PseudoParameterOverrides,
}

#[must_use]
pub struct ParseResult {
    pub model: SemanticModel,
    /// Wall-clock time spent building the model, in milliseconds.
    pub model_build_ms: f64,
}

impl SemanticModel {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        Self::parse(bytes, Default::default()).map(|r| r.model)
    }

    pub fn parse(bytes: &[u8], config: ParseConfig) -> Result<ParseResult, ParseError> {
        if bytes.len() > MAX_TEMPLATE_SIZE_BYTES {
            return Err(ParseError {
                message: format!("Template exceeds maximum size of {}MB", MAX_TEMPLATE_SIZE_BYTES / (1024 * 1024)),
                line: None,
                column: None,
            });
        }

        let total_start = web_time::Instant::now();

        info!("Phase 1: Parsing IR ({} bytes)", bytes.len());
        let mut ir = crate::parser::parse(bytes)?;
        let foreach_diagnostics = crate::transform_expansion::expand_language_extensions(&mut ir);
        let (parameters, parameter_diagnostics) = extract_parameters(&ir);
        // A parameter's definition can reference another parameter (e.g. a
        // Default given as `!Ref OtherParam`). Such a reference still counts as
        // usage, so collect the parameter names referenced from within the
        // Parameters section to feed the unused-parameter check.
        let params_referenced_in_definitions = collect_parameter_definition_refs(&ir, &parameters);
        let (mappings, mapping_diagnostics) = extract_mappings(&ir);
        let mut conditions = ConditionModel::from_ir(&ir, &parameters, &config.pseudo_parameters, &mappings);

        let resource_ids: Vec<String> = if ir.resources != NULL_REF {
            ir.arena
                .as_map(ir.resources)
                .map(|entries| entries.iter().map(|(k, _)| k.clone()).collect())
                .unwrap_or_default()
        } else {
            vec![]
        };
        let output_count =
            if ir.outputs != NULL_REF { ir.arena.as_map(ir.outputs).map(|e| e.len()).unwrap_or(0) } else { 0 };
        info!("Phase 2: Resolving {} resources, {} outputs", resource_ids.len(), output_count);

        let mut resolver = Resolver::new(
            &ir.arena,
            &parameters,
            &mappings,
            resource_ids.iter().cloned().collect(),
            &config.parameters,
            &config.pseudo_parameters,
        );
        let mut resources = HashMap::new();
        if ir.resources != NULL_REF
            && let Some(entries) = ir.arena.as_map(ir.resources)
        {
            // Pre-scan: record each resource's DefinitionSubstitutions keys so
            // definition placeholders can be checked for membership per variable.
            for (rname, rnode) in entries {
                if let Some(props) = ir.arena.as_map(*rnode) {
                    for (key, val) in props {
                        if key == KEY_PROPERTIES
                            && let Some(prop_entries) = ir.arena.as_map(*val)
                            && let Some((_, subs_ref)) =
                                prop_entries.iter().find(|(k, _)| k == "DefinitionSubstitutions")
                            && let Some(subs) = ir.arena.as_map(*subs_ref)
                        {
                            resolver
                                .def_subs_resources
                                .entry(rname.clone())
                                .or_default()
                                .extend(subs.iter().map(|(k, _)| k.clone()));
                        }
                    }
                }
            }
            for (name, node_ref) in entries.iter().cloned() {
                resolver.set_current_resource(&name);
                let resolved = resolve_resource(&ir.arena, &name, node_ref, &mut resolver);
                resources.insert(name.clone(), resolved);
            }
        }
        for (name, res) in &resources {
            debug!(
                "Resolved '{}' ({}): {} properties, {} edges, condition={:?}",
                name,
                res.resource_type,
                res.properties.len(),
                resolver.edges.iter().filter(|e| e.source_resource == *name).count(),
                res.condition
            );
        }

        let mut outputs = HashMap::new();
        if ir.outputs != NULL_REF
            && let Some(entries) = ir.arena.as_map(ir.outputs)
        {
            for (name, node_ref) in entries.iter().cloned() {
                resolver.set_current_resource(&format!("{}{}", OUTPUT_PSEUDO_RESOURCE_PREFIX, name));
                resolver.set_current_path(&format!("Outputs/{}/Value", name));
                let resolved = resolve_output(&ir.arena, node_ref, &mut resolver);
                outputs.insert(name.clone(), resolved);
            }
        }

        // Walk the Rules section so that `Ref`/`Fn::Sub`/`Fn::ValueOf` etc.
        // appearing inside rule conditions and assertions emit reference
        // edges. Without this pass, parameters used only in Rules-section
        // assertions would appear unreferenced to downstream rule checks.
        if ir.rules != NULL_REF
            && let Some(rule_entries) = ir.arena.as_map(ir.rules)
        {
            for (rule_name, rule_node) in rule_entries.iter().cloned() {
                resolver.set_current_resource(&format!("{}{}", RULE_PSEUDO_RESOURCE_PREFIX, rule_name));
                let cond_ref = ir.arena.map_get(rule_node, KEY_RULE_CONDITION);
                if let Some(cond_ref) = cond_ref {
                    resolver.set_current_path(&format!("Rules/{}/{}", rule_name, KEY_RULE_CONDITION));
                    resolver.resolve_node(cond_ref);
                }
                let assertions_ref = ir.arena.map_get(rule_node, KEY_ASSERTIONS);
                if let Some(assertions_ref) = assertions_ref
                    && let Some(assertion_items) = ir.arena.as_list(assertions_ref)
                {
                    for (idx, item_ref) in assertion_items.to_vec().iter().enumerate() {
                        if let Some(assert_ref) = ir.arena.map_get(*item_ref, KEY_ASSERT) {
                            resolver.set_current_path(&format!(
                                "Rules/{}/{}/{}/{}",
                                rule_name, KEY_ASSERTIONS, idx, KEY_ASSERT
                            ));
                            resolver.resolve_node(assert_ref);
                        }
                    }
                }
            }
        }

        info!("Phase 3: Building reference graph from {} resolver edges", resolver.edges.len());

        // Register inline conditions (from IfExpr) into the condition model in
        // one batch, so the derived mutex/implication passes run once.
        conditions.register_inline_batch(resolver.inline_conditions.drain(..));

        // Collect every mapping name referenced by an Fn::FindInMap anywhere in
        // the template (resources, outputs, conditions, ForEach bodies). A literal
        // first argument names a specific mapping; a non-literal one (e.g. a nested
        // Fn::FindInMap or Ref) means the referenced mapping can't be determined
        // statically, which disables the unused-mapping check.
        let mut find_in_map_names: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut has_dynamic_findinmap_name = false;
        for idx in 0..ir.arena.len() {
            if let Node::Intrinsic(IntrinsicFn::FindInMap(map_name_ref, _, _, _)) = ir.arena.node(idx as NodeRef) {
                match ir.arena.as_str(*map_name_ref) {
                    Some(name) => {
                        find_in_map_names.insert(name.to_string());
                    }
                    None => has_dynamic_findinmap_name = true,
                }
            }
        }

        let resolution_sources = resolver.resolution_sources();
        let mut all_edges = resolver.edges;
        for (id, res) in &resources {
            for dep in &res.depends_on {
                all_edges.push(ResolverEdge {
                    source_resource: id.clone(),
                    source_path: KEY_DEPENDS_ON.to_string(),
                    target: dep.clone(),
                    kind: RefKind::DependsOn,
                    span: UNKNOWN_SPAN,
                    condition_context: None,
                });
            }
        }
        let graph = ReferenceGraph::build(all_edges, &resource_ids);

        let mut resources_by_type: HashMap<String, Vec<String>> = HashMap::new();
        for (id, res) in &resources {
            resources_by_type.entry(res.resource_type.clone()).or_default().push(id.clone());
        }
        // Deterministic iteration across engines and runs: resource IDs within each
        // resource type are returned in template-declaration order (ascending by source
        // line/column). HashMap iteration is otherwise non-deterministic and was causing
        // per-pair diagnostic rules (e.g. subnet overlap) to attribute findings to
        // different resources on different runs.
        for ids in resources_by_type.values_mut() {
            ids.sort_by_key(|id| {
                let key = format!("Resources/{}", id);
                ir.span_index.get(key.as_str()).map(|s| (s.start_line, s.start_column)).unwrap_or((u32::MAX, u32::MAX))
            });
        }

        let mut diagnostics = ir.diagnostics;
        diagnostics.extend(foreach_diagnostics);
        diagnostics.extend(mapping_diagnostics);
        diagnostics.extend(parameter_diagnostics);

        diagnostics.extend(crate::nesting::validate_intrinsic_nesting(&ir.arena));
        diagnostics.extend(crate::intrinsic_arg_shapes::validate_intrinsic_arg_shapes(&ir.arena, &ir.transforms));
        diagnostics.extend(crate::lang_ext_shapes::validate_lang_ext_parameter_shapes(&ir.arena, &ir.transforms));
        diagnostics.extend(crate::language_extensions::validate_language_extensions(&ir.arena, &ir.transforms));
        diagnostics.extend(crate::dynamic_ref::validate_dynamic_references(&ir.arena, ir.resources));

        let mut fn_if_conditions: Vec<String> = Vec::new();
        for idx in 0..ir.arena.len() {
            match ir.arena.node(idx as NodeRef) {
                Node::Intrinsic(IntrinsicFn::If(cond_name, _, _)) => {
                    fn_if_conditions.push(cond_name.clone());
                    // Inside a Conditions-section body, Fn::If is not a valid
                    // condition function at all — that is the not-a-boolean
                    // finding's territory, so the name of a function that is
                    // itself rejected there is not checked.
                    let in_conditions_body =
                        ir.arena.get(idx as NodeRef).path.split('/').next() == Some(SECTION_CONDITIONS);
                    if !in_conditions_body && !conditions.conditions.contains_key(cond_name) {
                        // A single owner for the undefined-Fn::If-condition
                        // finding. Emitting it here (during the arena scan, which
                        // sees every Fn::If regardless of nesting) rather than in
                        // each engine keeps the two engines identical and covers
                        // the no-Conditions-section case, where a condition-name
                        // reference is still invalid.
                        diagnostics.push(crate::make_parse_defect_at(
                            "E1028",
                            format!("Fn::If condition '{}' does not exist in Conditions section", cond_name),
                            ir.arena.span(idx as NodeRef),
                            &ir.arena.get(idx as NodeRef).path,
                        ));
                    }
                }
                // A structurally malformed Fn::If (wrong arity, wrong type) is
                // rejected by the parser and left as a plain `Fn::If` map node
                // rather than an `IntrinsicFn::If`. Its condition is still
                // referenced, so collect the name here too — otherwise the
                // unused-condition check would wrongly flag a condition that the
                // template does reference.
                Node::Map(entries) if entries.len() == 1 && entries[0].0 == FN_IF => {
                    if let Some(first) = ir.arena.as_list(entries[0].1).and_then(|items| items.first())
                        && let Some(cond_name) = ir.arena.as_str(*first)
                    {
                        fn_if_conditions.push(cond_name.to_string());
                        // The structure error is reported separately; the
                        // undefined condition name is its own finding — a
                        // malformed Fn::If gets both. Conditions-section
                        // bodies are excluded for the same reason as the
                        // well-formed arm.
                        let in_conditions_body =
                            ir.arena.get(idx as NodeRef).path.split('/').next() == Some(SECTION_CONDITIONS);
                        if !in_conditions_body && !conditions.conditions.contains_key(cond_name) {
                            diagnostics.push(crate::make_parse_defect_at(
                                "E1028",
                                format!("Fn::If condition '{}' does not exist in Conditions section", cond_name),
                                ir.arena.span(idx as NodeRef),
                                &ir.arena.get(idx as NodeRef).path,
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
        fn_if_conditions.sort();
        fn_if_conditions.dedup();
        let mut output_empty_joins: Vec<String> = Vec::new();
        for (key, joins) in &resolver.empty_joins {
            if key.starts_with(OUTPUT_PSEUDO_RESOURCE_PREFIX) || key == OUTPUTS_PSEUDO_RESOURCE {
                output_empty_joins.extend(joins.iter().cloned());
            }
        }

        // Raw pseudo-parameter strings in the Outputs section. Such findings are
        // collected against the `__output__`/`__outputs__` pseudo-resources,
        // which are filtered out of the serialized model the engines scan, so
        // the engine rule never sees them. Emit them here (both engines share
        // this parse-time output) so a pseudo-parameter used as a plain string
        // in an output Value is reported the same as one in a resource.
        {
            let mut output_raw_pseudo: Vec<(String, String)> = Vec::new();
            for (key, entries) in &resolver.raw_pseudo_params {
                if key.starts_with(OUTPUT_PSEUDO_RESOURCE_PREFIX) || key == OUTPUTS_PSEUDO_RESOURCE {
                    for (path, value) in entries {
                        output_raw_pseudo.push((path.clone(), value.clone()));
                    }
                }
            }
            output_raw_pseudo.sort();
            for (path, value) in output_raw_pseudo {
                diagnostics.push(crate::make_parse_defect(
                    "W1054",
                    format!(
                        "Found a string '{}' that appears to be a pseudo parameter reference; use 'Ref: {}' instead",
                        value, value
                    ),
                    ir.span_index.get(&path).copied().unwrap_or(UNKNOWN_SPAN),
                ));
            }
        }

        // Raw pseudo-parameter strings in parameter Default values: a Default
        // that is exactly a pseudo-parameter string (e.g. "AWS::Region") is
        // almost certainly a mistake. Parameters are not walked by the resolver,
        // so check the raw default strings directly.
        {
            let mut param_names: Vec<&String> = parameters.keys().collect();
            param_names.sort();
            for pname in param_names {
                if let Some(default) = &parameters[pname].default
                    && PSEUDO_PARAMETERS.contains(&default.as_str())
                {
                    diagnostics.push(crate::make_parse_defect(
                        "W1054",
                        format!("Found a string '{}' that appears to be a pseudo parameter reference; use 'Ref: {}' instead", default, default),
                        ir.span_index.get(&format!("Parameters/{}/Default", pname)).copied().unwrap_or(UNKNOWN_SPAN),
                    ));
                }
            }
        }

        // Raw pseudo-parameter strings in Mappings values and Conditions.
        // Neither section is walked by the resolver (it only visits resources
        // and outputs), so scan their string nodes directly. `Ref` targets are
        // not string nodes in the arena, so `Ref: AWS::Region` is naturally
        // exempt — only a pseudo-parameter used as plain string data fires.
        for idx in 0..ir.arena.len() {
            let spanned = ir.arena.get(idx as NodeRef);
            let Node::String(s) = &spanned.node else {
                continue;
            };
            let section = spanned.path.split('/').next().unwrap_or("");
            // A string that is a `Ref` target (path ends in the Ref key, e.g. a
            // raw `{"Ref": "AWS::Region"}` map the parser could not
            // canonicalize) is already a reference — only plain string *data*
            // warrants the use-Ref-instead advice.
            let is_ref_target = spanned.path.rsplit('/').next() == Some(FN_REF);
            if (section == SECTION_MAPPINGS || section == SECTION_CONDITIONS)
                && !is_ref_target
                && PSEUDO_PARAMETERS.contains(&s.as_str())
            {
                diagnostics.push(crate::make_parse_defect(
                    "W1054",
                    format!(
                        "Found a string '{}' that appears to be a pseudo parameter reference; use 'Ref: {}' instead",
                        s, s
                    ),
                    spanned.span,
                ));
            }
        }

        // Unsubstituted `${Variable}` strings in the Outputs section. Like the
        // raw-pseudo-parameter case above, these are collected against the
        // `__output__` pseudo-resources that never reach the engines, so the
        // Sub-needed finding must be emitted here.
        {
            let mut output_unsubstituted: Vec<(String, String)> = Vec::new();
            for (key, entries) in &resolver.unsubstituted_variables {
                if key.starts_with(OUTPUT_PSEUDO_RESOURCE_PREFIX) || key == OUTPUTS_PSEUDO_RESOURCE {
                    for (path, variable) in entries {
                        output_unsubstituted.push((path.clone(), variable.clone()));
                    }
                }
            }
            output_unsubstituted.sort();
            for (path, variable) in output_unsubstituted {
                diagnostics.push(crate::make_parse_defect(
                    "E1029",
                    format!("Found an embedded parameter '{}' outside of an 'Fn::Sub' at {}", variable, path),
                    ir.span_index.get(&path).copied().unwrap_or(UNKNOWN_SPAN),
                ));
            }
        }

        diagnostics.extend(resolver.diagnostics);
        // SAM handling keys on the exact transform id, matching how the engines
        // detect the transform. A substring match would misclassify a non-SAM
        // transform whose name merely contains "Serverless" (e.g. a typo'd date
        // or a custom macro) as SAM, running the transform-error validators and
        // suppressing the correct "serverless type without transform" finding.
        let is_sam = ir.transforms.iter().any(|t| t == TRANSFORM_SERVERLESS);
        for d in graph.cycle_diagnostics(&ir.span_index) {
            if is_sam && sam::cycle_involves_sam_diagnostic(&d, &resources) {
                continue;
            }
            diagnostics.push(d);
        }
        for (cond_name, always_val) in conditions.tautological_equals() {
            let result_str = if always_val { "True" } else { "False" };
            diagnostics.push(crate::make_parse_defect_at(
                "W8003",
                format!("Fn::Equals in condition '{}' will always return {}", cond_name, result_str),
                ir.span_index.get(&format!("Conditions/{}", cond_name)).copied().unwrap_or(UNKNOWN_SPAN),
                &format!("Conditions/{}", cond_name),
            ));
        }
        // A `Condition:` key that names a condition absent from the Conditions
        // section is reported here — a distinct rule for the resource case and
        // the output case, since they are separate concerns. Emitting both
        // during model build anchors each at its own source location and keeps
        // the two engines identical. Names are sorted for deterministic
        // ordering.
        {
            let mut resource_ids_sorted: Vec<&String> = resources.keys().collect();
            resource_ids_sorted.sort();
            for rid in resource_ids_sorted {
                if let Some(cond) = &resources[rid].condition
                    && !conditions.conditions.contains_key(cond)
                {
                    diagnostics.push(crate::make_parse_defect_for_resource(
                        "E8002",
                        format!("Condition '{}' referenced by resource '{}' is not defined", cond, rid),
                        ir.span_index.get(&format!("Resources/{}", rid)).copied().unwrap_or(UNKNOWN_SPAN),
                        rid,
                    ));
                }
            }
            let mut output_names_sorted: Vec<&String> = outputs.keys().collect();
            output_names_sorted.sort();
            for oname in output_names_sorted {
                if let Some(cond) = &outputs[oname].condition
                    && !conditions.conditions.contains_key(cond)
                {
                    diagnostics.push(crate::make_parse_defect_for_resource(
                        "E6005",
                        format!("Condition '{}' referenced by output '{}' is not defined", cond, oname),
                        ir.span_index.get(&format!("Outputs/{}", oname)).copied().unwrap_or(UNKNOWN_SPAN),
                        oname,
                    ));
                }
            }
        }
        for invalid in conditions.invalid_condition_bodies() {
            diagnostics.push(crate::make_parse_defect(
                "E8001",
                format!("Condition '{}' must be a boolean expression", invalid),
                ir.span_index.get(&format!("Conditions/{}", invalid)).copied().unwrap_or(UNKNOWN_SPAN),
            ));
        }
        for (owner, undefined_ref) in conditions.undefined_condition_refs() {
            // Synthetic conditions (`__`-prefixed, inserted for inline Fn::If and
            // Rules-section assertions) are internal; never surface their names.
            if owner.starts_with("__") || undefined_ref.starts_with("__") {
                continue;
            }
            diagnostics.push(crate::make_parse_defect(
                "E8007",
                format!("Condition '{}' references undefined condition '{}'", owner, undefined_ref),
                ir.span_index.get(&format!("Conditions/{}", owner)).copied().unwrap_or(UNKNOWN_SPAN),
            ));
        }
        for cycle in conditions.detect_cycles() {
            let cycle_desc = cycle.join(" -> ");
            let first = &cycle[0];
            diagnostics.push(crate::make_parse_defect(
                "E9106",
                format!("Circular dependency in conditions: {}", cycle_desc),
                ir.span_index.get(&format!("Conditions/{}", first)).copied().unwrap_or(UNKNOWN_SPAN),
            ));
        }
        for (first, other) in conditions.detect_equivalent_conditions() {
            diagnostics.push(crate::make_parse_defect(
                "W9053",
                format!("Condition '{}' is equivalent to condition '{}' - consider consolidating", other, first),
                ir.span_index.get(&format!("Conditions/{}", other)).copied().unwrap_or(UNKNOWN_SPAN),
            ));
        }
        // The satisfiability-budget-exhaustion advisory is deliberately NOT
        // emitted here: almost every satisfiability query runs later, during
        // engine rule evaluation, so the budget-exhausted set is still empty at
        // model-build time. The validation engine emits it after rule
        // evaluation, once those queries have run.
        let model_build_ms = total_start.elapsed().as_secs_f64() * 1000.0;

        if !diagnostics.is_empty() {
            warn!("{} parse-time diagnostics", diagnostics.len());
        }
        let total_props: usize = resources.values().map(|r| r.properties.len()).sum();
        info!(
            "Semantic model: {} resources ({} types, {} total properties), {} outputs, {} edges, {} conditions, {} diagnostics",
            resources.len(),
            resources_by_type.len(),
            total_props,
            outputs.len(),
            graph.edges.len(),
            conditions.conditions.len(),
            diagnostics.len()
        );

        let template_metadata =
            if ir.template_metadata != NULL_REF { Some(node_to_json(&ir.arena, ir.template_metadata)) } else { None };
        let rules = if ir.rules != NULL_REF { Some(node_to_json(&ir.arena, ir.rules)) } else { None };
        let parsed_rules = parse_rules(&rules, &ir.arena, ir.rules);
        let rule_implications: Vec<(String, crate::ir::NodeRef, Vec<crate::ir::NodeRef>)> = parsed_rules
            .iter()
            .map(|r| {
                let assertion_nodes: Vec<crate::ir::NodeRef> = r.assertions.iter().map(|a| a.assert_node).collect();
                (r.name.clone(), r.condition_node, assertion_nodes)
            })
            .collect();
        if !rule_implications.is_empty() {
            conditions.register_rule_implications(&ir.arena, &rule_implications);
        }
        let rule_diagnostics = crate::rules::validate_rules(&rules, &ir.arena, ir.rules);
        diagnostics.extend(rule_diagnostics);
        let sam_globals = sam::extract_sam_globals(&ir.arena, ir.globals);
        if !sam_globals.is_empty() {
            sam::apply_sam_globals(&mut resources, &sam_globals);
        }
        let sam_implicit_resources =
            if is_sam { sam::collect_sam_implicit_resources(&resources) } else { HashSet::new() };
        let globals_param_refs =
            if is_sam { sam::collect_globals_param_refs(&ir.arena, ir.globals) } else { Vec::new() };
        if is_sam {
            let parameter_names: HashSet<String> = parameters.keys().cloned().collect();
            diagnostics.extend(sam::collect_transform_errors(
                &ir.arena,
                ir.resources,
                ir.globals,
                &resources,
                &parameter_names,
                &ir.span_index,
            ));
        }
        let is_cdk = resources_by_type.contains_key(CDK_METADATA_TYPE);

        Ok(ParseResult {
            model: SemanticModel {
                arena: ir.arena,
                span_index: ir.span_index,
                format_version: ir.format_version,
                description: ir.description,
                transforms: ir.transforms,
                raw_top_level_keys: ir.raw_top_level_keys,
                template_metadata,
                rules,
                parsed_rules,
                parameters,
                mappings,
                conditions,
                resources,
                outputs,
                graph,
                resources_by_type,
                diagnostics,
                output_empty_joins,
                sam_globals,
                sam_implicit_resources,
                globals_param_refs,
                is_cdk,
                fn_if_conditions,
                find_in_map_names,
                params_referenced_in_definitions,
                has_dynamic_findinmap_name,
                resolution_sources,
                resolve_memo: Mutex::new(HashMap::new()),
                scenario_memo: Mutex::new(HashMap::new()),
                scenario_combinations_used: AtomicU64::new(0),
            },
            model_build_ms,
        })
    }

    pub fn resource(&self, id: &str) -> Option<&ResolvedResource> {
        self.resources.get(id)
    }

    pub fn resources_of_type(&self, type_name: &str) -> &[String] {
        self.resources_by_type.get(type_name).map(|v| v.as_slice()).unwrap_or(&[])
    }

    #[must_use]
    pub fn resolve(&self, resource_id: &str, path: &str) -> Option<&ResolvedValue> {
        let resource = self.resources.get(resource_id)?;
        resource.properties.get(path.strip_prefix("Properties.").unwrap_or(path))
    }

    #[must_use]
    pub fn resolve_deep(&self, resource_id: &str, path: &str) -> Option<ResolvedValue> {
        let memo_key = (resource_id.to_string(), path.to_string());
        if let Some(memoized) = self.resolve_memo.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).get(&memo_key)
        {
            return memoized.clone();
        }
        let resource = self.resources.get(resource_id)?;
        let prop_path = path.strip_prefix("Properties.").unwrap_or(path);
        let mut segments = prop_path.splitn(2, '.');
        let top_key = segments.next()?;
        let resolved = resource.properties.get(top_key)?;
        let result = match segments.next() {
            Some(r) if !r.is_empty() => resolved_value_at_path(resolved, r),
            _ => Some(resolved.clone()),
        };
        self.resolve_memo.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(memo_key, result.clone());
        result
    }

    #[must_use]
    pub fn is_from_parameter(&self, resource_id: &str, path: &str) -> bool {
        self.resolution_sources
            .get(&(resource_id.to_string(), path.to_string()))
            .is_some_and(|s| s.starts_with("Parameters/"))
    }

    /// True when the value at `path` (or any ancestor up to the resource root) was
    /// produced by an intrinsic function. Used by rules that skip hardcoded-literal
    /// checks when the property value comes from `Fn::GetAZs`, `Ref`, etc.
    #[must_use]
    pub fn is_from_intrinsic(&self, resource_id: &str, path: &str) -> bool {
        if self.path_from_intrinsic(resource_id, path) {
            return true;
        }
        // Properties wrapped in Fn::If store per-branch intrinsic sources
        // under branch-qualified paths. When a caller queries the bare
        // `Properties.<prop>` path, also consult the branch-qualified
        // variants so intrinsic-sourced values inside either branch are
        // still recognised.
        let properties_prefix = format!("{}.", KEY_PROPERTIES);
        if let Some(rest) = path.strip_prefix(&properties_prefix) {
            for branch in ["1", "2"] {
                let branch_path = format!("{}.{}.{}.{}", KEY_PROPERTIES, FN_IF, branch, rest);
                if self.path_from_intrinsic(resource_id, &branch_path) {
                    return true;
                }
            }
        }
        false
    }

    fn path_from_intrinsic(&self, resource_id: &str, path: &str) -> bool {
        let edges = self.graph.outgoing(resource_id);
        let mut p = path.to_string();
        loop {
            if let Some(src) = self.resolution_sources.get(&(resource_id.to_string(), p.clone()))
                && src.starts_with("Intrinsic/")
            {
                return true;
            }
            // A reference edge (Ref, GetAtt, Sub) anchored at this path means the
            // value is produced by an intrinsic rather than written as a literal.
            if edges.iter().any(|e| e.source_path == p) {
                return true;
            }
            match p.rfind('.') {
                Some(i) => p.truncate(i),
                None => return false,
            }
        }
    }

    /// Whether this model has spent its cumulative scenario-expansion budget.
    /// Mirrors `ConditionModel::satisfiability_budget_exhausted` for the
    /// scenario path: callers that drive many `resolve_scenarios` queries stop
    /// producing new scenarios once further expansion would only be truncated.
    #[must_use]
    pub fn scenario_budget_exhausted(&self) -> bool {
        self.scenario_combinations_used.load(Ordering::Relaxed) >= MAX_TOTAL_SCENARIO_COMBINATIONS
    }

    /// Cumulative scenarios materialized by this model so far.
    #[must_use]
    pub fn scenario_combinations_used(&self) -> u64 {
        self.scenario_combinations_used.load(Ordering::Relaxed)
    }

    /// Test-only: advance the cumulative scenario counter directly, so the
    /// budget threshold and short-circuit behavior can be exercised without
    /// materializing `MAX_TOTAL_SCENARIO_COMBINATIONS` real scenarios (which
    /// would be pointless time and memory).
    #[cfg(test)]
    fn add_scenario_combinations_for_test(&self, count: u64) {
        self.scenario_combinations_used.fetch_add(count, Ordering::Relaxed);
    }

    pub fn resolve_properties_scenarios(&self, resource_id: &str) -> Vec<(ResolvedValue, HashMap<String, bool>)> {
        if self.scenario_budget_exhausted() {
            return vec![];
        }
        let Some(resource) = self.resources.get(resource_id) else {
            return vec![];
        };
        if resource.properties_dynamic {
            return vec![];
        }

        let properties = if resource.properties.len() == 1 {
            resource.properties.get(FN_IF).cloned().unwrap_or_else(|| ResolvedValue::Map {
                entries: resource
                    .properties
                    .iter()
                    .map(|(key, value)| MapEntry { key: key.clone(), value: value.clone() })
                    .collect(),
            })
        } else {
            let mut entries: Vec<MapEntry> = resource
                .properties
                .iter()
                .map(|(key, value)| MapEntry { key: key.clone(), value: value.clone() })
                .collect();
            entries.sort_by(|left, right| left.key.cmp(&right.key));
            ResolvedValue::Map { entries }
        };

        let mut results = Vec::new();
        collect_scenarios(&properties, &HashMap::new(), &mut results);
        self.scenario_combinations_used.fetch_add(results.len() as u64, Ordering::Relaxed);
        results
    }

    pub fn resolve_scenarios(&self, resource_id: &str, path: &str) -> Vec<(ResolvedValue, HashMap<String, bool>)> {
        // Once the cumulative scenario budget for this model is spent, stop
        // materializing scenarios (the conservative truncation documented on
        // `MAX_TOTAL_SCENARIO_COMBINATIONS`). Checked before any resolution so an
        // exhausted call costs O(1), keeping a template with a flood of
        // heavily-gated values bounded — the per-value `MAX_SCENARIO_COMBINATIONS`
        // cap alone does not bound the number of such values.
        if self.scenario_budget_exhausted() {
            return vec![];
        }
        let val = match self.resolve_deep(resource_id, path) {
            Some(v) => v,
            None => match self.resolve(resource_id, path) {
                Some(v) => v.clone(),
                None => match self.resolve_via_properties_if(resource_id, path) {
                    Some(v) => v,
                    None => return vec![],
                },
            },
        };
        let mut results = Vec::new();
        collect_scenarios(&val, &HashMap::new(), &mut results);
        self.scenario_combinations_used.fetch_add(results.len() as u64, Ordering::Relaxed);
        results
    }

    /// Fallback lookup when `Properties` is wrapped in an `Fn::If`: walks
    /// the caller's path inside the synthetic `Fn::If` branch so scenario
    /// resolution still reaches properties that only exist conditionally.
    fn resolve_via_properties_if(&self, resource_id: &str, path: &str) -> Option<ResolvedValue> {
        let resource = self.resources.get(resource_id)?;
        let conditional = resource.properties.get(FN_IF)?;
        let properties_prefix = format!("{}.", KEY_PROPERTIES);
        let prop_path = path.strip_prefix(&properties_prefix).unwrap_or(path);
        if prop_path.is_empty() {
            return Some(conditional.clone());
        }
        resolved_value_at_path(conditional, prop_path)
    }

    pub fn resolve_scenarios_json(
        &self,
        resource_id: &str,
        path: &str,
    ) -> Vec<(serde_json::Value, HashMap<String, bool>)> {
        let memo_key = (resource_id.to_string(), path.to_string());
        {
            let memo = self.scenario_memo.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(memoized) = memo.get(&memo_key) {
                return memoized.clone();
            }
        }
        let scenarios = self.resolve_scenarios(resource_id, path);
        let json_scenarios: Vec<_> = scenarios
            .into_iter()
            .filter_map(|(val, conds)| {
                if contains_dynamic_resolved(&val) {
                    return None;
                }
                if !conds.is_empty() {
                    let assumptions: Vec<(String, bool)> = conds.iter().map(|(k, v)| (k.clone(), *v)).collect();
                    if !self.conditions.is_satisfiable(&assumptions) {
                        return None;
                    }
                }
                let json = crate::serialization::resolved_value_to_json_clean(&val)?;
                if json_contains_markers(&json) {
                    return None;
                }
                Some((json, conds))
            })
            .collect();
        let mut memo = self.scenario_memo.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        memo.entry(memo_key).or_insert_with(|| json_scenarios).clone()
    }

    pub fn follow_ref(&self, resource_id: &str, path: &str) -> Option<&str> {
        if let Some(ResolvedValue::Reference { target, kind: _ }) = self.resolve(resource_id, path) {
            return Some(target.as_str());
        }
        if let Some(ResolvedValue::Reference { target, kind: _ }) = self.resolve_deep(resource_id, path).as_ref() {
            for edge in self.graph.outgoing(resource_id) {
                if edge.target == *target {
                    return Some(&edge.target);
                }
            }
        }
        None
    }

    pub fn source_location(&self, path: &str) -> Option<&SourceSpan> {
        self.span_index.get(path)
    }

    /// Returns the source span for a resource property path, falling back to
    /// the resource-level span if the specific path is not found.
    ///
    /// The span index is keyed with slash-separated paths, so a dotted,
    /// resource-relative path (`Properties.BucketName`) is normalized to slash
    /// form before lookup — the same normalization [`Self::diagnostic_span`]
    /// applies. Callers pass paths in either form, so accepting only slash form
    /// here would silently mislocate every dotted-path diagnostic onto the
    /// resource declaration line.
    pub fn resource_span(&self, resource_id: &str, prop_path: &str) -> SourceSpan {
        // An empty resource id means the path is already a section-absolute span-index
        // key (e.g. an output's `Outputs/X/Value.Fn::Join`); prefixing it with
        // `Resources/` would mislocate the finding onto the Resources block. Resolve it
        // as-is (no dot-to-slash conversion, since dots in segment names like `Fn::Join`
        // are literal, not path separators). Returns UNKNOWN when nothing resolves so
        // callers fall back to section-level or backfill-based location.
        if resource_id.is_empty() {
            return self.walk_up_span(prop_path).unwrap_or(UNKNOWN_SPAN);
        }
        let specific = if prop_path.is_empty() {
            format!("Resources/{}", resource_id)
        } else {
            format!("Resources/{}/{}", resource_id, prop_path.replace('.', "/"))
        };
        // Walk up from the exact path to the nearest indexed ancestor, so a leaf that
        // carries no span of its own — a synthetic intrinsic key (`…/Topic/Fn::Sub`),
        // an `Fn::If` branch index — anchors at its closest real parent rather than
        // collapsing straight to the resource declaration. The resource path itself is
        // the final ancestor, preserving the previous resource-level fallback.
        self.walk_up_span(&specific).unwrap_or(UNKNOWN_SPAN)
    }

    /// Walks up `key` (a `/`-separated span-index path), trimming one trailing
    /// segment at a time, and returns the first ancestor with a known span. This
    /// anchors a diagnostic as close to the offending node as the index allows —
    /// an unindexed leaf (e.g. an `Fn::If` branch index) falls back to its parent
    /// property, then the resource, then the section.
    fn walk_up_span(&self, key: &str) -> Option<SourceSpan> {
        let mut current = key;
        loop {
            // A key can be present in the index but mapped to UNKNOWN_SPAN (an
            // interior node whose byte span was never assigned). Treat that as
            // "not found" and keep walking up to the nearest ancestor that does
            // have a real span, rather than returning the unusable UNKNOWN.
            match self.span_index.get(current) {
                Some(&span) if span != UNKNOWN_SPAN => return Some(span),
                _ => match current.rfind('/') {
                    Some(cut) => current = &current[..cut],
                    None => return None,
                },
            }
        }
    }

    /// Best-effort span for a diagnostic identified by its optional resource and
    /// property path, walking up to the nearest indexed ancestor.
    ///
    /// The path form disambiguates how to root it, which matters because a segment
    /// like `Metadata` names both a top-level section and a resource property:
    /// * A **slash** form (`Outputs/X/Value`, `Conditions/C/Fn::And`) is already an
    ///   absolute, section-rooted span-index key and is resolved as written.
    /// * A **dotted** or bare form (`Properties.Foo`, `Metadata`) is relative to the
    ///   resource, so it is rooted at `Resources/<rid>` before lookup — never
    ///   matched against a same-named top-level section.
    ///
    /// Returns `None` when nothing along the chosen candidate is indexed, so callers
    /// can fall back to a section span.
    pub fn diagnostic_span(&self, resource_id: Option<&str>, property_path: &str) -> Option<SourceSpan> {
        let rid = resource_id.filter(|r| !r.is_empty());

        if property_path.contains('/') {
            // Absolute, section-rooted path: resolve directly.
            if let Some(span) = self.walk_up_span(property_path) {
                return Some(span);
            }
        } else if let Some(rid) = rid {
            // Resource-relative path (dotted or bare): root at the resource so a
            // property named after a top-level section cannot mislocate onto it.
            let key = if property_path.is_empty() {
                format!("Resources/{}", rid)
            } else {
                format!("Resources/{}/{}", rid, property_path.replace('.', "/"))
            };
            if let Some(span) = self.walk_up_span(&key) {
                return Some(span);
            }
        }

        // Last resort: the bare resource span, when a resource id is known.
        rid.and_then(|rid| self.span_index.get(&format!("Resources/{}", rid)))
            .filter(|span| **span != UNKNOWN_SPAN)
            .copied()
    }

    pub fn estimate_string_length(&self, resource_id: &str, path: &str) -> Option<usize> {
        let val = self.resolve_deep(resource_id, path).or_else(|| self.resolve(resource_id, path).cloned())?;
        estimate_resolved_string_length(&val)
    }
}

impl SpanProvider for SemanticModel {
    fn source_location(&self, path: &str) -> Option<SourceSpan> {
        self.span_index.get(path).copied()
    }
}

fn parse_rules(rules_json: &Option<serde_json::Value>, arena: &Arena, rules_node: NodeRef) -> Vec<TemplateRule> {
    let Some(rules) = rules_json else {
        return Vec::new();
    };
    let Some(obj) = rules.as_object() else {
        return Vec::new();
    };

    // Build a lookup from rule name → NodeRef for the rule's IR subtree
    let rule_nodes: HashMap<&str, NodeRef> =
        arena.as_map(rules_node).unwrap_or(&[]).iter().map(|(k, v)| (k.as_str(), *v)).collect();

    obj.iter()
        .filter_map(|(name, rule)| {
            let rule_obj = rule.as_object()?;
            let condition = rule_obj.get(KEY_RULE_CONDITION).cloned();

            // Look up the IR node for this rule to find condition/assertion NodeRefs
            let rule_ir = rule_nodes.get(name.as_str()).copied().unwrap_or(NULL_REF);
            let condition_node = arena.map_get(rule_ir, KEY_RULE_CONDITION).unwrap_or(NULL_REF);

            let assertions_node = arena.map_get(rule_ir, KEY_ASSERTIONS).unwrap_or(NULL_REF);
            let assertion_items = arena.as_list(assertions_node).unwrap_or(&[]);

            let assertions = rule_obj
                .get(KEY_ASSERTIONS)
                .and_then(|a| a.as_array())
                .map(|arr| {
                    arr.iter()
                        .enumerate()
                        .filter_map(|(idx, a)| {
                            let a_obj = a.as_object()?;
                            let assert_node = assertion_items
                                .get(idx)
                                .and_then(|item_ref| arena.map_get(*item_ref, KEY_ASSERT))
                                .unwrap_or(NULL_REF);
                            Some(RuleAssertion {
                                assert: a_obj.get(KEY_ASSERT).cloned().unwrap_or(serde_json::Value::Null),
                                assert_node,
                                description: a_obj
                                    .get(KEY_ASSERT_DESCRIPTION)
                                    .and_then(|d| d.as_str())
                                    .map(String::from),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            Some(TemplateRule { name: name.clone(), condition, condition_node, assertions })
        })
        .collect()
}

/// Collect parameter names that are referenced (via `Ref`/`Fn::Sub`) from within
/// another parameter's definition. These references still count as usage for the
/// unused-parameter check even though they originate in the Parameters section.
fn collect_parameter_definition_refs(ir: &TemplateIR, parameters: &HashMap<String, ParameterInfo>) -> HashSet<String> {
    let mut referenced = HashSet::new();
    if ir.parameters == NULL_REF {
        return referenced;
    }
    let Some(param_entries) = ir.arena.as_map(ir.parameters) else {
        return referenced;
    };
    for (_, param_ref) in param_entries {
        collect_refs_in_subtree(&ir.arena, *param_ref, parameters, &mut referenced);
    }
    referenced
}

fn collect_refs_in_subtree(
    arena: &Arena,
    node_ref: NodeRef,
    parameters: &HashMap<String, ParameterInfo>,
    referenced: &mut HashSet<String>,
) {
    match arena.node(node_ref) {
        Node::Intrinsic(IntrinsicFn::Ref(target)) => {
            if parameters.contains_key(target) {
                referenced.insert(target.clone());
            }
        }
        Node::Intrinsic(IntrinsicFn::Sub(_, Some(bindings))) => {
            for (_, v) in bindings {
                collect_refs_in_subtree(arena, *v, parameters, referenced);
            }
        }
        Node::List(items) => {
            for item in items {
                collect_refs_in_subtree(arena, *item, parameters, referenced);
            }
        }
        Node::Map(entries) => {
            for (_, v) in entries {
                collect_refs_in_subtree(arena, *v, parameters, referenced);
            }
        }
        _ => {}
    }
}

/// Some intrinsic nodes stand in for a whole object — most notably
/// `Properties: {Fn::If: [...]}` which the parser folds into an
/// `IntrinsicFn::If` node. Return the CloudFormation function-name key
/// (`Fn::If`, `Fn::ForEach::*`, etc.) when the node is one of these
/// object-wrapping intrinsics, so downstream resolution can address the
/// conditional by a synthetic path.
fn intrinsic_synthetic_key(arena: &Arena, node_ref: NodeRef) -> Option<String> {
    let Node::Intrinsic(func) = arena.node(node_ref) else {
        return None;
    };
    match func {
        IntrinsicFn::If(_, _, _) | IntrinsicFn::IfExpr(_, _, _) => Some(FN_IF.to_string()),
        IntrinsicFn::ForEach(uid, _, _, _) => Some(format!("{}::{}", FN_FOR_EACH, uid)),
        _ => None,
    }
}

fn resolve_resource(arena: &Arena, name: &str, node_ref: NodeRef, resolver: &mut Resolver) -> ResolvedResource {
    let entries = arena.as_map(node_ref).unwrap_or(&[]);
    let resource_type =
        entries.iter().find(|(k, _)| k == KEY_TYPE).and_then(|(_, v)| arena.as_str(*v)).unwrap_or("").to_string();
    let condition =
        entries.iter().find(|(k, _)| k == KEY_CONDITION).and_then(|(_, v)| arena.as_str(*v)).map(|s| s.to_string());
    let depends_on = entries
        .iter()
        .find(|(k, _)| k == KEY_DEPENDS_ON)
        .map(|(_, v)| match arena.node(*v) {
            Node::String(s) => vec![s.clone()],
            Node::List(items) => items.iter().filter_map(|r| arena.as_str(*r).map(|s| s.to_string())).collect(),
            _ => vec![],
        })
        .unwrap_or_default();
    let deletion_policy =
        entries.iter().find(|(k, _)| k == KEY_DELETION_POLICY).map(|(_, v)| resolver.resolve_node(*v));
    let update_replace_policy =
        entries.iter().find(|(k, _)| k == KEY_UPDATE_REPLACE_POLICY).map(|(_, v)| resolver.resolve_node(*v));
    let metadata_ref = entries.iter().find(|(k, _)| k == SECTION_METADATA).map(|(_, v)| *v);
    let metadata = metadata_ref.map(|v| node_to_json(arena, v));
    let update_policy = entries.iter().find(|(k, _)| k == KEY_UPDATE_POLICY).map(|(_, v)| node_to_json(arena, *v));
    let creation_policy = entries.iter().find(|(k, _)| k == KEY_CREATION_POLICY).map(|(_, v)| node_to_json(arena, *v));

    let resolved_metadata = if let Some(meta_ref) = metadata_ref {
        resolver.set_current_path(SECTION_METADATA);
        Some(resolver.resolve_node(meta_ref))
    } else {
        None
    };

    let mut properties = HashMap::new();
    let mut properties_dynamic = false;
    if let Some((_, props_ref)) = entries.iter().find(|(k, _)| k == KEY_PROPERTIES) {
        if let Some(prop_entries) = arena.as_map(*props_ref) {
            for (key, val_ref) in prop_entries {
                resolver.set_current_path(&format!("Properties.{}", key));
                properties.insert(key.clone(), resolver.resolve_node(*val_ref));
            }
        } else if let Some(synthetic_key) = intrinsic_synthetic_key(arena, *props_ref) {
            // `Properties: {Fn::If: [...]}` collapses in the IR into an intrinsic
            // node rather than a map. Preserve the intrinsic as a single entry so
            // downstream validators can enumerate each branch via scenario
            // resolution without losing the original conditional structure.
            // Use bare `Properties` as the base path so the Fn::If handler in
            // the resolver records branch sources at the single-prefix path
            // rather than doubling the `Fn::If` segment.
            resolver.set_current_path(KEY_PROPERTIES);
            properties.insert(synthetic_key, resolver.resolve_node(*props_ref));
        } else if matches!(arena.node(*props_ref), Node::Intrinsic(_)) {
            // The whole Properties block is an intrinsic (e.g. `!Ref AWS::NoValue`)
            // that did not collapse into a per-branch synthetic key. Its effective
            // properties are only known at deploy time.
            properties_dynamic = true;
        }
    }

    let mut conditionally_null_props = Vec::new();
    for (key, val) in &properties {
        collect_conditional_nulls(val, key, &mut conditionally_null_props);
    }

    let mut condition_refs = Vec::new();
    for v in properties.values() {
        collect_condition_refs_from_resolved(v, &mut condition_refs);
    }
    if let Some(ref meta_resolved) = resolved_metadata {
        collect_condition_refs_from_resolved(meta_resolved, &mut condition_refs);
    }
    if let Some(ref dp) = deletion_policy {
        collect_condition_refs_from_resolved(dp, &mut condition_refs);
    }
    if let Some(ref urp) = update_replace_policy {
        collect_condition_refs_from_resolved(urp, &mut condition_refs);
    }
    if let Some(mut extra) = resolver.extra_condition_refs.remove(name) {
        condition_refs.append(&mut extra);
    }
    condition_refs.sort();
    condition_refs.dedup();

    ResolvedResource {
        logical_id: name.to_string(),
        resource_type,
        condition,
        depends_on,
        deletion_policy,
        update_replace_policy,
        update_policy: update_policy.map(JsonValue),
        creation_policy: creation_policy.map(JsonValue),
        metadata: metadata.map(JsonValue),
        properties,
        properties_dynamic,
        diagnostics: ResourceDiagnostics {
            find_in_map_refs: resolver.find_in_map_refs.remove(name).unwrap_or_default(),
            simple_subs: resolver
                .simple_subs
                .remove(name)
                .unwrap_or_default()
                .into_iter()
                .map(|(a, b)| PathValuePair { path: a, value: b })
                .collect(),
            redundant_subs: resolver.redundant_subs.remove(name).unwrap_or_default(),
            empty_joins: resolver.empty_joins.remove(name).unwrap_or_default(),
            hardcoded_partition_arns: collapse_list_sibling_arn_paths(
                resolver.hardcoded_partition_arns.remove(name).unwrap_or_default(),
            ),
            foreach_expansions: resolver
                .foreach_expansions
                .remove(name)
                .unwrap_or_default()
                .into_iter()
                .map(|(path, ident, coll)| ForEachExpansion {
                    property_path: path,
                    identifier: ident,
                    collection_source: coll,
                })
                .collect(),
            unsubstituted_variables: resolver
                .unsubstituted_variables
                .remove(name)
                .unwrap_or_default()
                .into_iter()
                .map(|(a, b)| PathValuePair { path: a, value: b })
                .collect(),
            unused_sub_keys: resolver
                .unused_sub_keys
                .remove(name)
                .unwrap_or_default()
                .into_iter()
                .map(|(a, b)| PathValuePair { path: a, value: b })
                .collect(),
            raw_pseudo_params: resolver
                .raw_pseudo_params
                .remove(name)
                .unwrap_or_default()
                .into_iter()
                .map(|(a, b)| PathValuePair { path: a, value: b })
                .collect(),
            secretsmanager_ref_paths: resolver.secretsmanager_ref_paths.remove(name).unwrap_or_default(),
            invalid_refs: resolver
                .invalid_refs
                .remove(name)
                .unwrap_or_default()
                .into_iter()
                .map(|(a, b)| PathValuePair { path: a, value: b })
                .collect(),
            conditionally_null_props: conditionally_null_props
                .into_iter()
                .map(|(a, b, c)| ConditionalNullEntry { path: a, condition: b, null_in_true_branch: c })
                .collect(),
            condition_refs,
        },
    }
}

/// Collapses hardcoded-partition ARN paths that are list siblings sharing one
/// source location into a single path at the lowest index.
///
/// When several `Fn::Sub` ARNs are list elements of the same property (e.g.
/// `Principal.AWS.0.Fn::Sub`, `Principal.AWS.1.Fn::Sub`), they map to the same
/// source span — the list's location — so they are one observable finding, not
/// several. Paths whose only difference is the list index immediately before the
/// trailing `.Fn::Sub` segment are therefore folded to the smallest index.
fn collapse_list_sibling_arn_paths(paths: Vec<String>) -> Vec<String> {
    // Group key: the path with the final list index (the segment just before
    // `.Fn::Sub`) blanked out. Tracks the minimum index seen per group so the
    // surviving path reports the first sibling.
    let mut min_index: HashMap<String, usize> = HashMap::new();
    let mut ungrouped: Vec<String> = Vec::new();
    for path in &paths {
        match split_trailing_list_index(path) {
            Some((prefix, idx, suffix)) => {
                let key = format!("{}\u{0}{}", prefix, suffix);
                min_index.entry(key).and_modify(|m| *m = (*m).min(idx)).or_insert(idx);
            }
            None => ungrouped.push(path.clone()),
        }
    }
    let mut out = ungrouped;
    for (key, idx) in min_index {
        let (prefix, suffix) = key.split_once('\u{0}').unwrap_or((key.as_str(), ""));
        out.push(format!("{}{}.{}", prefix, idx, suffix));
    }
    out.sort();
    out
}

/// Splits a path like `a.b.2.Fn::Sub` into (`"a.b."`, `2`, `"Fn::Sub"`) when a
/// numeric list index directly precedes the trailing `.Fn::Sub` segment.
fn split_trailing_list_index(path: &str) -> Option<(String, usize, String)> {
    let suffix = "Fn::Sub";
    let stem = path.strip_suffix(suffix)?.strip_suffix('.')?;
    let (head, last) = stem.rsplit_once('.')?;
    let idx: usize = last.parse().ok()?;
    Some((format!("{}.", head), idx, suffix.to_string()))
}

/// An output `Value` must resolve to a string. A literal non-empty list or map,
/// or a function whose result is a list (`Fn::GetAZs`, `Fn::Split`, `Fn::Cidr`),
/// can never be a string and is a guaranteed template error. `Fn::If` is
/// transparent: each branch is checked at its own location, so a conditional
/// that picks a string in one branch and a list in the other is flagged only on
/// the offending branch. Empty containers are accepted (they carry no members to
/// stringify) and every other function (`Ref`, `Fn::Sub`, `Fn::Join`,
/// `Fn::Select`, `Fn::FindInMap`, `Fn::ImportValue`, …) is treated as
/// string-producing here — a `Fn::GetAtt` returning a non-string is caught later
/// against the resource schema, which this parse-time shape check cannot see.
fn check_output_value_is_string(arena: &Arena, value_ref: NodeRef, output_name: &str, resolver: &mut Resolver) {
    let build_path = format!("Outputs/{}/Value", output_name);
    check_output_value_node(arena, value_ref, output_name, &build_path, resolver);
}

/// Recursive worker for [`check_output_value_is_string`]. `build_path` is the
/// slash path of the node under inspection; each `Fn::If` branch is visited with
/// its own branch path so that a conditional with a bad value in both branches
/// yields a separate, correctly-located diagnostic per branch rather than
/// collapsing to one.
fn check_output_value_node(
    arena: &Arena,
    value_ref: NodeRef,
    output_name: &str,
    build_path: &str,
    resolver: &mut Resolver,
) {
    let span = arena.span(value_ref);
    match arena.node(value_ref) {
        Node::List(items) if !items.is_empty() => {
            resolver.diagnostics.push(crate::make_parse_defect_at(
                "F6101",
                format!("Output '{}' value must be a string, not a list", output_name),
                span,
                build_path,
            ));
        }
        Node::Map(entries) if !entries.is_empty() => {
            resolver.diagnostics.push(crate::make_parse_defect_at(
                "F6101",
                format!("Output '{}' value must be a string, not an object", output_name),
                span,
                build_path,
            ));
        }
        Node::Intrinsic(IntrinsicFn::If(_, if_true, if_false) | IntrinsicFn::IfExpr(_, if_true, if_false)) => {
            let (if_true, if_false) = (*if_true, *if_false);
            check_output_value_node(arena, if_true, output_name, &format!("{}/{}/1", build_path, FN_IF), resolver);
            check_output_value_node(arena, if_false, output_name, &format!("{}/{}/2", build_path, FN_IF), resolver);
        }
        Node::Intrinsic(intrinsic) if returns_list(intrinsic) => {
            resolver.diagnostics.push(crate::make_parse_defect_at(
                "F6101",
                format!("Output '{}' value must be a string, not a list", output_name),
                span,
                build_path,
            ));
        }
        _ => {}
    }
}

/// Whether an intrinsic's result is a list value (never a string). These are the
/// only list-returning functions that can stand as a whole output `Value`;
/// `Fn::If` is handled separately (its branches are checked), and every other
/// function yields a string or an opaque deploy-time value.
fn returns_list(intrinsic: &IntrinsicFn) -> bool {
    matches!(intrinsic, IntrinsicFn::GetAZs(_) | IntrinsicFn::Split(_, _) | IntrinsicFn::Cidr(_, _, _))
}

fn resolve_output(arena: &Arena, node_ref: NodeRef, resolver: &mut Resolver) -> ResolvedOutput {
    let entries = arena.as_map(node_ref).unwrap_or(&[]);

    // Validate output property keys
    const VALID_OUTPUT_KEYS: &[&str] = &[KEY_VALUE, SECTION_DESCRIPTION, KEY_CONDITION, KEY_EXPORT];
    let output_name = resolver.current_resource.as_deref().unwrap_or("");
    let display_name = output_name.strip_prefix(OUTPUT_PSEUDO_RESOURCE_PREFIX).unwrap_or(output_name);
    for (key, _) in entries {
        if !VALID_OUTPUT_KEYS.contains(&key.as_str()) {
            resolver.diagnostics.push(crate::make_parse_defect(
                "E6001",
                format!(
                    "Output '{}' has invalid property '{}'. Valid properties: Value, Description, Condition, Export",
                    display_name, key
                ),
                crate::ir::UNKNOWN_SPAN,
            ));
        }
    }

    if let Some((_, value_ref)) = entries.iter().find(|(k, _)| k == KEY_VALUE) {
        let value_ref = *value_ref;
        let name = display_name.to_string();
        check_output_value_is_string(arena, value_ref, &name, resolver);
    }

    let value = entries
        .iter()
        .find(|(k, _)| k == KEY_VALUE)
        .map(|(_, v)| resolver.resolve_node(*v))
        .unwrap_or(ResolvedValue::Dynamic { reason: "missing output value".into() });
    let description = entries
        .iter()
        .find(|(k, _)| k == SECTION_DESCRIPTION)
        .and_then(|(_, v)| arena.as_str(*v))
        .map(|s| s.to_string());
    let condition =
        entries.iter().find(|(k, _)| k == KEY_CONDITION).and_then(|(_, v)| arena.as_str(*v)).map(|s| s.to_string());
    let export_name = entries
        .iter()
        .find(|(k, _)| k == KEY_EXPORT)
        .and_then(|(_, v)| arena.as_map(*v))
        .and_then(|m| m.iter().find(|(k, _)| k == KEY_NAME))
        .map(|(_, v)| resolver.resolve_node(*v));
    ResolvedOutput { value, description, condition, export_name }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_overrides_reports_nothing_when_unset_or_valid() {
        assert!(PseudoParameterOverrides::default().invalid_overrides().is_empty(), "unset overrides are valid");
        let valid = PseudoParameterOverrides {
            account_id: Some("123456789012".to_string()),
            partition: Some("aws-cn".to_string()),
            ..Default::default()
        };
        assert!(valid.invalid_overrides().is_empty(), "well-formed overrides produce no warnings");
    }

    #[test]
    fn invalid_overrides_reports_each_malformed_provided_value() {
        let bad = PseudoParameterOverrides {
            account_id: Some("unknown-account".to_string()),
            partition: Some("gcp".to_string()),
            ..Default::default()
        };
        let problems = bad.invalid_overrides();
        assert_eq!(problems.len(), 2, "one entry per invalid provided field");
        assert!(problems.iter().any(|p| p.contains("AccountId") && p.contains("unknown-account")));
        assert!(problems.iter().any(|p| p.contains("Partition") && p.contains("gcp")));
    }

    #[test]
    fn invalid_overrides_only_checks_account_id_and_partition() {
        let only_region = PseudoParameterOverrides { region: Some("not a region".to_string()), ..Default::default() };
        assert!(only_region.invalid_overrides().is_empty());
    }

    #[test]
    fn account_id_shape_requires_exactly_twelve_digits() {
        assert!(is_account_id_shaped("123456789012"));
        assert!(!is_account_id_shaped("12345678901"));
        assert!(!is_account_id_shaped("1234567890123"));
        assert!(!is_account_id_shaped("12345678901a"));
        assert!(!is_account_id_shaped(""));
    }

    #[test]
    fn partition_shape_accepts_aws_family_and_rejects_others() {
        for ok in ["aws", "aws-cn", "aws-us-gov", "aws-iso", "aws-iso-b"] {
            assert!(is_partition_shaped(ok), "{ok} should be accepted");
        }
        for bad in ["gcp", "AWS", "azure", ""] {
            assert!(!is_partition_shaped(bad), "{bad} should be rejected");
        }
    }

    #[test]
    fn model_from_simple_template() {
        let input = r#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket
  MyBucket2:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket-2
"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        assert_eq!(model.resources.len(), 2);
        assert_eq!(model.resources_of_type("AWS::S3::Bucket").len(), 2);
        assert_eq!(model.resources_of_type("AWS::Fake::Thing").len(), 0);
    }

    #[test]
    fn diagnostic_span_resolves_dotted_resource_property_path() {
        let input = r#"
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket
"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        // A dotted, resource-relative path is normalized to the slash-keyed index
        // entry and resolves to the specific property span (the BucketName value).
        let via_diag = model.diagnostic_span(Some("MyBucket"), "Properties.BucketName").expect("should resolve");
        let expected = model.source_location("Resources/MyBucket/Properties/BucketName").copied().expect("indexed");
        assert_eq!(via_diag, expected, "dotted path should resolve to the exact property span");
    }

    #[test]
    fn diagnostic_span_resource_relative_path_never_matches_top_level_section() {
        // A resource property named after a top-level section (Metadata) must anchor
        // at the resource's own Metadata, not the unrelated top-level Metadata block.
        let input = r#"
Metadata:
  AWS::CloudFormation::Interface:
    ParameterGroups: []
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Metadata:
      cfn_nag: skip
"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        let via_diag = model.diagnostic_span(Some("MyBucket"), "Metadata").expect("should resolve");
        let resource_meta = model.source_location("Resources/MyBucket/Metadata").copied().expect("indexed");
        let top_level_meta = model.source_location("Metadata").copied().expect("indexed");
        assert_eq!(via_diag, resource_meta, "resource-relative Metadata must anchor at the resource");
        assert_ne!(via_diag, top_level_meta, "must not mislocate onto the top-level Metadata section");
    }

    #[test]
    fn diagnostic_span_resolves_absolute_section_rooted_path() {
        let input = r#"
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
Outputs:
  BucketRef:
    Value: !Ref MyBucket
"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        // An output-anchored path cannot be reached via resource_span (it only roots
        // at Resources/), but diagnostic_span resolves it directly from the index.
        let span = model.diagnostic_span(Some("BucketRef"), "Outputs/BucketRef/Value");
        assert!(span.is_some() && span != Some(UNKNOWN_SPAN), "output path should resolve to a real span");
    }

    #[test]
    fn diagnostic_span_walks_up_when_leaf_node_is_unindexed() {
        let input = r#"
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket
"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        // A deeper path that was never indexed falls back to the nearest indexed
        // ancestor (the property, then the resource) rather than UNKNOWN.
        let span = model.diagnostic_span(Some("MyBucket"), "Properties.BucketName.DoesNotExist.Deeper");
        assert!(span.is_some() && span != Some(UNKNOWN_SPAN), "unindexed leaf should walk up to a real span");
    }

    #[test]
    fn diagnostic_span_returns_none_when_nothing_resolvable() {
        let input = r#"
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        // No resource and no property path: there is no candidate key to resolve.
        assert_eq!(model.diagnostic_span(None, ""), None, "no resource and no path yields no span");
        // A property path whose every ancestor is unindexed (no matching section)
        // resolves to nothing.
        assert_eq!(
            model.diagnostic_span(None, "NoSuchSection/Deep/Path"),
            None,
            "an unindexed absolute path yields no span"
        );
    }

    #[test]
    fn model_resolve_property() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"Name":"hello"}}}}"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.Name").unwrap() {
            ResolvedValue::Concrete { value: v } => assert_eq!(v.as_str().unwrap(), "hello"),
            other => panic!("Expected Concrete, got {:?}", other),
        }
    }

    #[test]
    fn model_follow_ref() {
        let input = r#"{"Resources":{"Svc":{"Type":"T","Properties":{"TaskDef":{"Ref":"TD"}}},"TD":{"Type":"T2"}}}"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        assert_eq!(model.follow_ref("Svc", "Properties.TaskDef"), Some("TD"));
    }

    #[test]
    fn model_to_diagnostic_json() {
        let input = r#"{"Resources":{"R":{"Type":"AWS::S3::Bucket","Properties":{"Name":"test"}}}}"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        let json = serde_json::to_value(model.to_diagnostic_json()).unwrap();
        assert_ne!(json.get("resources"), None, "expected 'resources' key in diagnostic JSON");
        assert_ne!(json["resources"].get("R"), None, "expected resource 'R' in diagnostic JSON");
    }

    #[test]
    fn model_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SemanticModel>();
    }

    #[test]
    fn model_with_conditions() {
        let input = r#"
Parameters:
  Env:
    Type: String
    AllowedValues: [Prod, Dev]
Conditions:
  IsProd:
    Fn::Equals: [!Ref Env, Prod]
Resources:
  R:
    Type: T
    Condition: IsProd
    Properties:
      Size:
        Fn::If: [IsProd, 100, 20]
"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        assert_eq!(model.conditions.conditions.len(), 1);
        let r = model.resource("R").unwrap();
        assert_eq!(r.condition.as_deref(), Some("IsProd"));
        assert!(matches!(
            r.properties.get("Size"),
            Some(ResolvedValue::Conditional { condition: _, if_true: _, if_false: _ })
        ));
    }

    #[test]
    fn model_with_outputs() {
        let input =
            "Resources:\n  R:\n    Type: T\nOutputs:\n  Out1:\n    Value: !Ref R\n    Description: test output\n";
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        assert_eq!(model.outputs.len(), 1);
        assert!(model.outputs.contains_key("Out1"));
    }

    #[test]
    fn resolve_deep_nested_object() {
        let input =
            r#"{"Resources":{"R":{"Type":"T","Properties":{"Config":{"SubKey":"value","Nested":{"Deep":"found"}}}}}}"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve_deep("R", "Properties.Config.SubKey") {
            Some(ResolvedValue::Concrete { value: v }) => assert_eq!(v.as_str().unwrap(), "value"),
            other => panic!("Expected Concrete, got {:?}", other),
        }
        match model.resolve_deep("R", "Properties.Config.Nested.Deep") {
            Some(ResolvedValue::Concrete { value: v }) => assert_eq!(v.as_str().unwrap(), "found"),
            other => panic!("Expected Concrete, got {:?}", other),
        }
    }

    #[test]
    fn resolve_deep_array_index() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"Tags":[{"Key":"Env","Value":"prod"},{"Key":"App","Value":"web"}]}}}}"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve_deep("R", "Properties.Tags.0.Key") {
            Some(ResolvedValue::Concrete { value: v }) => assert_eq!(v.as_str().unwrap(), "Env"),
            other => panic!("Expected Concrete, got {:?}", other),
        }
    }

    #[test]
    fn resolve_deep_out_of_bounds() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"Tags":[{"Key":"A"}]}}}}"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        assert!(model.resolve_deep("R", "Properties.Tags.5.Key").is_none(), "out-of-bounds index should return None");
    }

    #[test]
    fn resolve_deep_missing_intermediate() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"Name":"hello"}}}}"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        assert!(model.resolve_deep("R", "Properties.NonExistent.Sub").is_none());
    }

    #[test]
    fn resolve_deep_top_level_still_works() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"Name":"hello"}}}}"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve_deep("R", "Properties.Name") {
            Some(ResolvedValue::Concrete { value: v }) => assert_eq!(v.as_str().unwrap(), "hello"),
            other => panic!("Expected Concrete, got {:?}", other),
        }
    }

    #[test]
    fn model_findinmap_refs_tracked() {
        let input = br#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::FindInMap":["MyMap","k1","k2"]}}}}}"#;
        let model = SemanticModel::from_bytes(input).unwrap();
        assert!(model.resource("R").unwrap().diagnostics.find_in_map_refs.contains(&"MyMap".to_string()));
    }

    #[test]
    fn model_findinmap_refs_tracked_yaml() {
        let input = b"Resources:\n  R:\n    Type: T\n    Properties:\n      V: !FindInMap [MyMap, k1, k2]\n";
        let model = SemanticModel::from_bytes(input).unwrap();
        assert!(model.resource("R").unwrap().diagnostics.find_in_map_refs.contains(&"MyMap".to_string()));
    }

    #[test]
    fn model_to_diagnostic_json_has_outputs_and_mappings() {
        let input = b"AWSTemplateFormatVersion: '2010-09-09'\nMappings:\n  M:\n    k1:\n      k2: val\nResources:\n  R:\n    Type: AWS::S3::Bucket\nOutputs:\n  Out:\n    Value: !Ref R\n";
        let model = SemanticModel::from_bytes(input).unwrap();
        let json = serde_json::to_value(model.to_diagnostic_json()).unwrap();
        assert_ne!(json.get("outputs"), None, "expected 'outputs' key in diagnostic JSON");
        assert_ne!(json.get("mappings"), None, "expected 'mappings' key in diagnostic JSON");
        assert_eq!(json["mappings"]["M"]["k1"]["k2"], "val");
    }

    #[test]
    fn resolve_deep_into_reference() {
        let input = r#"{"Resources":{"Svc":{"Type":"T","Properties":{"TaskDef":{"Ref":"TD"}}},"TD":{"Type":"T2"}}}"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        assert!(
            model.resolve_deep("Svc", "Properties.TaskDef.Something").is_none(),
            "path through Reference should return None"
        );
        match model.resolve_deep("Svc", "Properties.TaskDef") {
            Some(ResolvedValue::Reference { target, kind: _ }) => assert_eq!(target, "TD"),
            other => panic!("Expected Reference, got {:?}", other),
        }
    }

    #[test]
    fn resolve_scenarios_json_filters_dynamic() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::ImportValue":"Stack"}}}}}"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        let scenarios = model.resolve_scenarios_json("R", "Properties.V");
        assert!(scenarios.is_empty(), "ImportValue should be filtered as dynamic");
    }

    #[test]
    fn resolve_scenarios_json_returns_concrete() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":"hello"}}}}"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        let scenarios = model.resolve_scenarios_json("R", "Properties.V");
        assert_eq!(scenarios.len(), 1);
        assert_eq!(scenarios[0].0, serde_json::json!("hello"));
    }

    #[test]
    fn resolve_scenarios_json_memoized() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":"hello"}}}}"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        let s1 = model.resolve_scenarios_json("R", "Properties.V");
        let s2 = model.resolve_scenarios_json("R", "Properties.V");
        assert_eq!(s1, s2);
    }

    #[test]
    fn cumulative_scenario_budget_accumulates_across_queries_then_halts_expansion() {
        // A conditional property resolves into more than one scenario, so each
        // resolve_scenarios call charges a non-zero, deterministic amount to the
        // model's shared cumulative scenario counter — enough to prove queries
        // accumulate. resolve_scenarios is not memoized, so repeating the same
        // query re-charges.
        let input = br#"{
            "Parameters": {"Env": {"Type": "String"}},
            "Conditions": {"IsProd": {"Fn::Equals": [{"Ref": "Env"}, "prod"]}},
            "Resources": {"R": {"Type": "T", "Properties": {"V": {"Fn::If": ["IsProd", "a", "b"]}}}}
        }"#;
        let model = SemanticModel::from_bytes(input).unwrap();

        assert_eq!(model.scenario_combinations_used(), 0, "a freshly built model has materialized no scenarios");
        assert!(
            !model.scenario_budget_exhausted(),
            "a freshly built model's cumulative scenario budget is not exhausted"
        );

        // (1) Real queries accumulate across queries — a per-query reset would
        // be a silent denial-of-service regression. The conditional value must
        // expand into more than one scenario, and the counter must reflect
        // exactly what was produced.
        let first = model.resolve_scenarios("R", "Properties.V");
        assert!(first.len() > 1, "an Fn::If value must expand into multiple scenarios; got {}", first.len());
        assert_eq!(
            model.scenario_combinations_used(),
            first.len() as u64,
            "the first query charges exactly the scenarios it produced"
        );

        let mut previous = model.scenario_combinations_used();
        for _ in 0..3 {
            let produced = model.resolve_scenarios("R", "Properties.V");
            assert!(!produced.is_empty(), "while under budget the query must still expand scenarios");
            let used = model.scenario_combinations_used();
            assert!(
                used > previous,
                "each query while under budget must add to the shared cumulative counter; a \
                 per-query reset would be a silent denial-of-service regression. was {previous}, \
                 now {used}"
            );
            previous = used;
        }
        assert!(
            !model.scenario_budget_exhausted(),
            "a handful of queries must not exhaust the (large) cumulative budget"
        );

        // (2) The exhausted flag trips exactly at the cumulative threshold.
        // Fast-forward to one scenario short of the cap rather than
        // materializing ~MAX_TOTAL_SCENARIO_COMBINATIONS real scenarios; the
        // accumulation checked in (1) already proves real queries feed this same
        // counter.
        let to_threshold = MAX_TOTAL_SCENARIO_COMBINATIONS - model.scenario_combinations_used() - 1;
        model.add_scenario_combinations_for_test(to_threshold);
        assert!(
            !model.scenario_budget_exhausted(),
            "one scenario short of the cap must not be exhausted; counter is {}",
            model.scenario_combinations_used()
        );
        model.add_scenario_combinations_for_test(1);
        assert!(
            model.scenario_budget_exhausted(),
            "reaching MAX_TOTAL_SCENARIO_COMBINATIONS must trip the exhausted flag; counter is {}",
            model.scenario_combinations_used()
        );

        // (3) Once exhausted, further queries must short-circuit in O(1): they
        // return no scenarios (the conservative truncation) and charge no
        // further work.
        let before_short_circuit = model.scenario_combinations_used();
        let conservative = model.resolve_scenarios("R", "Properties.V");
        assert!(
            conservative.is_empty(),
            "a query issued after the cumulative budget is exhausted must return no scenarios"
        );
        assert_eq!(
            model.scenario_combinations_used(),
            before_short_circuit,
            "an exhausted-budget query must short-circuit without materializing or charging \
             further scenarios"
        );
    }

    #[test]
    fn estimate_string_length_concrete_property() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":"hello"}}}}"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        assert_eq!(model.estimate_string_length("R", "Properties.V"), Some(5));
    }

    #[test]
    fn estimate_string_length_missing_property() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":"hello"}}}}"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        assert!(model.estimate_string_length("R", "Properties.Missing").is_none());
    }

    #[test]
    fn resource_span_specific_path() {
        let input = "Resources:\n  R:\n    Type: T\n    Properties:\n      Name: hello\n";
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        let span = model.resource_span("R", "Properties/Name");
        // Should find a span (not UNKNOWN_SPAN) for the specific path
        assert!(span.start_line > 0 || span.end_line > 0, "expected non-zero span for Properties/Name");
    }

    #[test]
    fn resource_span_specific_path_dotted_form() {
        let input = "Resources:\n  R:\n    Type: T\n    Properties:\n      Name: hello\n";
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        // A dotted, resource-relative path must resolve to the SAME specific span
        // as its slash-form equivalent — not fall back to the resource span.
        let dotted = model.resource_span("R", "Properties.Name");
        let slashed = model.resource_span("R", "Properties/Name");
        let resource = model.resource_span("R", "");
        assert_eq!(dotted, slashed, "dotted and slash forms must resolve to the same span");
        assert_ne!(dotted, resource, "specific property span must differ from the resource span");
    }

    #[test]
    fn resource_span_falls_back_to_resource() {
        let input = "Resources:\n  R:\n    Type: T\n    Properties:\n      Name: hello\n";
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        let span = model.resource_span("R", "Properties/NonExistent/Deep");
        // Should fall back to the resource-level span
        assert!(span.start_line > 0 || span.end_line > 0, "expected non-zero span, got {:?}", span);
    }

    #[test]
    fn resource_span_nested_array_property_anchors_at_element() {
        // A property inside an array element must anchor at that element, not at the
        // array or the resource. The span index is keyed with the array index.
        let input =
            "Resources:\n  R:\n    Type: T\n    Properties:\n      Ingress:\n      - Port: 80\n      - Port: 443\n";
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        let first = model.resource_span("R", "Properties.Ingress.0.Port");
        let second = model.resource_span("R", "Properties.Ingress.1.Port");
        assert_eq!(first.start_line, 6, "Ingress[0].Port is on line 6, got {:?}", first);
        assert_eq!(second.start_line, 7, "Ingress[1].Port is on line 7, got {:?}", second);
    }

    #[test]
    fn resource_span_empty_id_resolves_section_absolute_path_precisely() {
        // A finding with no resource id (e.g. an Outputs-level diagnostic) carries a
        // section-absolute span-index path. It must resolve against that path directly,
        // NOT be prefixed with `Resources/` (which would mislocate onto the Resources
        // block). A path whose exact node is indexed resolves to that node.
        let input = concat!(
            "Resources:\n  R:\n    Type: T\n",                                  // lines 1-3
            "Outputs:\n  Combined:\n    Value: !Join [\"\", [\"a\", \"b\"]]\n", // lines 4-6
        );
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        // The `Value` node is indexed (line 6) — resolution lands on it exactly.
        let value = model.resource_span("", "Outputs/Combined/Value");
        assert_eq!(value.start_line, 6, "Outputs/Combined/Value is on line 6, got {:?}", value);
        // The output key itself resolves to its own line (line 5).
        let combined = model.resource_span("", "Outputs/Combined");
        assert_eq!(combined.start_line, 5, "Outputs/Combined is on line 5, got {:?}", combined);
    }

    #[test]
    fn resource_span_empty_id_fused_intrinsic_suffix_anchors_at_nearest_slash_ancestor() {
        // A synthetic intrinsic suffix (`.Fn::Join`) is joined to its parent by a DOT,
        // which is deliberately not treated as a path separator here: real span-index
        // keys contain literal dots inside a single segment (e.g. API Gateway's
        // `method.request.path.proxy`), so splitting on dots would shred those paths and
        // mis-anchor. The walk-up therefore trims the whole `Value.Fn::Join` segment on
        // the nearest `/`, landing on the enclosing output — still within Outputs, never
        // on the Resources block. Both engines resolve this identically, which is what
        // keeps them at parity.
        let input = concat!(
            "Resources:\n  R:\n    Type: T\n",                                  // lines 1-3
            "Outputs:\n  Combined:\n    Value: !Join [\"\", [\"a\", \"b\"]]\n", // lines 4-6
        );
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        let span = model.resource_span("", "Outputs/Combined/Value.Fn::Join");
        assert_eq!(
            span.start_line, 5,
            "fused-suffix path must anchor at the enclosing output (line 5), got {:?}",
            span
        );
    }

    #[test]
    fn resource_span_empty_id_does_not_leak_onto_resources_block() {
        // Regression guard: an unresolvable empty-id path must return UNKNOWN rather
        // than walking up a spuriously `Resources/`-prefixed key onto the Resources
        // section. This is the divergence that made the two engines disagree.
        let input = "Resources:\n  R:\n    Type: T\n";
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        let span = model.resource_span("", "Outputs/DoesNotExist/Value");
        assert_eq!(span, UNKNOWN_SPAN, "unresolvable empty-id path must be UNKNOWN, got {:?}", span);
    }

    #[test]
    fn resource_span_empty_path_returns_resource_span() {
        let input = "Resources:\n  R:\n    Type: T\n";
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        let span = model.resource_span("R", "");
        assert!(span.start_line > 0 || span.end_line > 0, "expected non-zero span, got {:?}", span);
    }

    #[test]
    fn resolve_nonexistent_resource_returns_none() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":"x"}}}}"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        assert!(model.resolve("NoSuchResource", "Properties.V").is_none(), "nonexistent resource should return None");
        assert!(model.resolve_deep("NoSuchResource", "Properties.V").is_none());
    }

    #[test]
    fn parse_config_with_parameter_overrides() {
        let input = r#"{"Parameters":{"Env":{"Type":"String","AllowedValues":["dev","prod"]}},"Resources":{"R":{"Type":"T","Properties":{"V":{"Ref":"Env"}}}}}"#;
        let config = ParseConfig {
            parameters: [("Env".to_string(), "staging".to_string())].into_iter().collect(),
            pseudo_parameters: PseudoParameterOverrides::default(),
        };
        let result = SemanticModel::parse(input.as_bytes(), config).unwrap();
        match result.model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Concrete { value: v }) => {
                assert_eq!(v.as_str().unwrap(), "staging")
            }
            other => panic!("Expected Concrete(\"staging\"), got {:?}", other),
        }
    }

    #[test]
    fn parse_config_with_pseudo_parameter_overrides() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Ref":"AWS::Region"}}}}}"#;
        let config = ParseConfig {
            parameters: HashMap::new(),
            pseudo_parameters: PseudoParameterOverrides { region: Some("eu-west-1".to_string()), ..Default::default() },
        };
        let result = SemanticModel::parse(input.as_bytes(), config).unwrap();
        match result.model.resolve("R", "Properties.V") {
            Some(ResolvedValue::Concrete { value: v }) => {
                assert_eq!(v.as_str().unwrap(), "eu-west-1")
            }
            other => panic!("Expected Concrete(\"eu-west-1\"), got {:?}", other),
        }
    }

    #[test]
    fn pseudo_parameter_overrides_defaults() {
        let overrides = PseudoParameterOverrides::default();
        assert_eq!(overrides.region(), DEFAULT_REGION);
        assert_eq!(overrides.get("AWS::AccountId").unwrap(), DEFAULT_ACCOUNT_ID);
        assert_eq!(overrides.get("AWS::Partition").unwrap(), DEFAULT_PARTITION);
        assert_eq!(overrides.get("AWS::StackName").unwrap(), DEFAULT_STACK_NAME);
        assert_eq!(overrides.get("AWS::URLSuffix").unwrap(), DEFAULT_URL_SUFFIX);
        assert!(overrides.get("AWS::StackId").unwrap().contains("arn:"));
        assert!(overrides.get("AWS::NotificationARNs").unwrap().contains("sns"));
        assert_eq!(overrides.get("Unknown"), None, "unknown pseudo-param should return None");
    }

    #[test]
    fn pseudo_parameter_overrides_china_region() {
        let overrides = PseudoParameterOverrides { region: Some("cn-north-1".to_string()), ..Default::default() };
        assert_eq!(overrides.get("AWS::Partition").unwrap(), "aws-cn");
        assert_eq!(overrides.get("AWS::URLSuffix").unwrap(), "amazonaws.com.cn");
    }

    /// `fixed_value` underpins the SAT-solver decision "treat this pseudo-param
    /// as a constant or a free variable". It must return `Some` only when the
    /// caller pinned the corresponding field — never for region-derived
    /// defaults — otherwise `Fn::Equals[Ref AWS::Partition, "aws"]` would be
    /// falsely deterministic and `find_unreachable_branches` would emit
    /// false-positive unreachable-branch diagnostics.
    #[test]
    fn fixed_value_returns_none_for_unset_pseudo_parameters() {
        let overrides = PseudoParameterOverrides::default();

        for name in [
            "AWS::AccountId",
            "AWS::NotificationARNs",
            "AWS::Partition",
            "AWS::Region",
            "AWS::StackId",
            "AWS::StackName",
            "AWS::URLSuffix",
        ] {
            assert_eq!(
                overrides.fixed_value(name),
                None,
                "{name} must be a free variable when the user has not explicitly pinned it"
            );
        }
    }

    #[test]
    fn fixed_value_returns_user_supplied_overrides() {
        let overrides = PseudoParameterOverrides {
            account_id: Some("999999999999".to_string()),
            partition: Some("aws-cn".to_string()),
            region: Some("cn-north-1".to_string()),
            stack_name: Some("MyStack".to_string()),
            ..Default::default()
        };

        assert_eq!(overrides.fixed_value("AWS::AccountId"), Some("999999999999".to_string()));
        assert_eq!(overrides.fixed_value("AWS::Partition"), Some("aws-cn".to_string()));
        assert_eq!(overrides.fixed_value("AWS::Region"), Some("cn-north-1".to_string()));
        assert_eq!(overrides.fixed_value("AWS::StackName"), Some("MyStack".to_string()));
        assert_eq!(overrides.fixed_value("AWS::URLSuffix"), None, "URLSuffix not set; must remain a free variable");
        assert_eq!(overrides.fixed_value("Unknown"), None);
    }

    /// Setting `region` alone must NOT cause `fixed_value("AWS::Partition")`
    /// to return a value. The convenience defaulting that `get` performs (so
    /// resource-property substitution sees a sensible partition string) is
    /// deliberately separate from the SAT-solver pinning, because constraining
    /// the region constrains where the stack deploys, not the partition the
    /// template was written against.
    #[test]
    fn fixed_value_does_not_propagate_region_to_partition() {
        let overrides = PseudoParameterOverrides { region: Some("cn-north-1".to_string()), ..Default::default() };

        assert_eq!(overrides.fixed_value("AWS::Region"), Some("cn-north-1".to_string()));
        assert_eq!(
            overrides.fixed_value("AWS::Partition"),
            None,
            "region override must not propagate to partition — partition stays free unless the caller pins it"
        );
    }

    #[test]
    fn model_rejects_oversized_template() {
        let huge = vec![b' '; 11 * 1024 * 1024];
        let result = SemanticModel::from_bytes(&huge);
        match result {
            Err(e) => assert!(e.message.contains("maximum size")),
            Ok(_) => panic!("Expected error for oversized template"),
        }
    }

    #[test]
    fn follow_ref_returns_none_for_non_reference() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":"hello"}}}}"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        assert_eq!(model.follow_ref("R", "Properties.V"), None, "non-reference value should return None");
    }

    #[test]
    fn resolve_deep_memoization_consistency() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"Config":{"A":"1","B":"2"}}}}}"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        let r1 = model.resolve_deep("R", "Properties.Config.A");
        let r2 = model.resolve_deep("R", "Properties.Config.A");
        match (&r1, &r2) {
            (Some(ResolvedValue::Concrete { value: a }), Some(ResolvedValue::Concrete { value: b })) => {
                assert_eq!(a, b);
            }
            _ => panic!("Expected matching Concrete values"),
        }
    }

    #[test]
    fn model_with_mappings_and_findinmap() {
        let input = r#"
Mappings:
  RegionMap:
    us-east-1:
      AMI: ami-12345
    us-west-2:
      AMI: ami-67890
Resources:
  R:
    Type: T
    Properties:
      ImageId: !FindInMap [RegionMap, us-east-1, AMI]
"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.ImageId") {
            Some(ResolvedValue::Concrete { value: v }) => {
                assert_eq!(v.as_str().unwrap(), "ami-12345")
            }
            other => panic!("Expected Concrete, got {:?}", other),
        }
    }

    #[test]
    fn model_invalid_ref_tracked() {
        let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Ref":"NonExistent"}}}}}"#;
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        let r = model.resource("R").unwrap();
        assert!(!r.diagnostics.invalid_refs.is_empty());
        assert!(r.diagnostics.invalid_refs.iter().any(|s| s.value == "NonExistent"));
    }

    #[test]
    fn collapse_arn_paths_folds_list_siblings_to_lowest_index() {
        let input = vec![
            "Properties.KeyPolicy.Statement.2.Principal.AWS.1.Fn::Sub".to_string(),
            "Properties.KeyPolicy.Statement.2.Principal.AWS.0.Fn::Sub".to_string(),
        ];
        let out = collapse_list_sibling_arn_paths(input);
        assert_eq!(out, vec!["Properties.KeyPolicy.Statement.2.Principal.AWS.0.Fn::Sub".to_string()]);
    }

    #[test]
    fn collapse_arn_paths_keeps_distinct_parent_lists() {
        // Differing index is the Statement index, not the one before Fn::Sub, so
        // these are separate source locations and must both survive.
        let input = vec![
            "Properties.PolicyDocument.Statement.0.Resource.Fn::Sub".to_string(),
            "Properties.PolicyDocument.Statement.1.Resource.Fn::Sub".to_string(),
        ];
        let mut out = collapse_list_sibling_arn_paths(input.clone());
        out.sort();
        assert_eq!(out, input);
    }

    #[test]
    fn collapse_arn_paths_leaves_scalar_paths_untouched() {
        let input = vec![
            "Properties.KeyPolicy.Statement.0.Principal.AWS.Fn::Sub".to_string(),
            "Properties.KeyPolicy.Statement.1.Principal.AWS.Fn::Sub".to_string(),
        ];
        let mut out = collapse_list_sibling_arn_paths(input.clone());
        out.sort();
        assert_eq!(out, input);
    }

    /// Number of output value-type diagnostics (F6101) the parse phase produced.
    fn output_string_type_diagnostics(template: &str) -> usize {
        let model = SemanticModel::from_bytes(template.as_bytes()).unwrap();
        model.diagnostics.iter().filter(|d| d.rule_id == "F6101").count()
    }

    #[test]
    fn output_literal_list_value_flagged() {
        let template = "Resources:\n  R:\n    Type: T\nOutputs:\n  O:\n    Value:\n      - a\n      - b\n";
        assert_eq!(output_string_type_diagnostics(template), 1);
    }

    #[test]
    fn output_literal_object_value_flagged() {
        let template = "Resources:\n  R:\n    Type: T\nOutputs:\n  O:\n    Value:\n      Key: v\n";
        assert_eq!(output_string_type_diagnostics(template), 1);
    }

    #[test]
    fn output_list_returning_functions_flagged() {
        for value in ["!GetAZs \"\"", "!Split [\",\", \"a,b\"]", "!Cidr [\"10.0.0.0/16\", 1, 8]"] {
            let template = format!("Resources:\n  R:\n    Type: T\nOutputs:\n  O:\n    Value: {}\n", value);
            assert_eq!(output_string_type_diagnostics(&template), 1, "expected F6101 for output value {}", value);
        }
    }

    #[test]
    fn output_empty_container_value_not_flagged() {
        // An empty list/object has no members to stringify; CloudFormation does
        // not reject it, so neither does the parse-time check.
        for value in ["[]", "{}"] {
            let template = format!("Resources:\n  R:\n    Type: T\nOutputs:\n  O:\n    Value: {}\n", value);
            assert_eq!(output_string_type_diagnostics(&template), 0, "empty container {} must not be flagged", value);
        }
    }

    #[test]
    fn output_string_producing_values_not_flagged() {
        // Scalars coerce to strings; Ref/Fn::Sub/Fn::Join/Fn::Select/Fn::ImportValue
        // produce (or are treated as) strings. None are string-type violations.
        for value in ["hello", "42", "true", "!Ref R", "!Sub \"${R}\"", "!Join [\",\", [\"a\"]]", "!ImportValue X"] {
            let template = format!("Resources:\n  R:\n    Type: T\nOutputs:\n  O:\n    Value: {}\n", value);
            assert_eq!(output_string_type_diagnostics(&template), 0, "string-valued output {} must not fire", value);
        }
    }

    #[test]
    fn output_find_in_map_list_value_not_flagged() {
        // Fn::FindInMap can resolve to a list, but it is not flagged here (the
        // mapping's shape is validated elsewhere): only literal lists and
        // list-returning functions are string-type violations. This is exactly
        // the case a resolved-value check would get wrong, since the resolved
        // value is indistinguishable from a literal list.
        let template = "Mappings:\n  M:\n    k:\n      l:\n        - a\n        - b\nResources:\n  R:\n    Type: T\nOutputs:\n  O:\n    Value: !FindInMap [M, k, l]\n";
        assert_eq!(output_string_type_diagnostics(template), 0);
    }

    #[test]
    fn output_fn_if_flags_each_list_branch() {
        // Fn::If is transparent: each branch is checked. Both branches are lists,
        // so both are flagged.
        let template = "Conditions:\n  C:\n    Fn::Equals: [\"a\", \"a\"]\nResources:\n  R:\n    Type: T\nOutputs:\n  O:\n    Value:\n      Fn::If: [C, [\"a\"], [\"b\"]]\n";
        assert_eq!(output_string_type_diagnostics(template), 2);
    }

    #[test]
    fn output_fn_if_string_branches_not_flagged() {
        let template = "Conditions:\n  C:\n    Fn::Equals: [\"a\", \"a\"]\nResources:\n  R:\n    Type: T\nOutputs:\n  O:\n    Value:\n      Fn::If: [C, \"yes\", \"no\"]\n";
        assert_eq!(output_string_type_diagnostics(template), 0);
    }
}
