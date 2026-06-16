use diagnostics::JsonValue;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticModel {
    pub template: DiagnosticTemplate,
    #[cfg_attr(feature = "wasm-bindings", tsify(type = "Record<string, JsonValue>"))]
    pub parameters: HashMap<String, JsonValue>,
    #[cfg_attr(feature = "wasm-bindings", tsify(type = "Record<string, DiagnosticCondition>"))]
    pub conditions: HashMap<String, DiagnosticCondition>,
    pub condition_param_refs: Vec<String>,
    pub condition_implications: Vec<DiagnosticImplication>,
    pub condition_mutex_groups: Vec<DiagnosticMutexGroup>,
    pub condition_exclusions: Vec<Vec<String>>,
    #[cfg_attr(feature = "wasm-bindings", tsify(type = "Record<string, string>"))]
    pub resource_condition_map: HashMap<String, String>,
    pub mappings: JsonValue,
    #[cfg_attr(feature = "wasm-bindings", tsify(type = "Record<string, DiagnosticResource>"))]
    pub resources: HashMap<String, DiagnosticResource>,
    #[cfg_attr(feature = "wasm-bindings", tsify(type = "Record<string, DiagnosticOutput>"))]
    pub outputs: HashMap<String, DiagnosticOutput>,
    pub edges: Vec<ReferenceEdge>,
    pub cycles: Vec<Vec<String>>,
    pub output_empty_joins: Vec<String>,
    pub sam_implicit_resources: Vec<String>,
    pub globals_param_refs: Vec<String>,
    pub is_cdk: bool,
    pub has_parse_errors: bool,
    pub parsed_rules: Vec<DiagnosticRule>,
    pub resolution_sources: Vec<ResolutionSource>,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticTemplate {
    pub format_version: Option<String>,
    pub description: Option<String>,
    pub transforms: Vec<String>,
    pub raw_top_level_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticCondition {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deps: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mutex_with: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticImplication {
    pub antecedent: String,
    pub consequent: String,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticMutexGroup {
    pub conditions: Vec<String>,
    pub parameter: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct ReferenceEdge {
    pub source: String,
    pub source_path: String,
    pub target: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition_context: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct OutgoingRef {
    pub source_path: String,
    pub target: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition_context: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct IncomingRef {
    pub source: String,
    pub source_path: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attr: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticResource {
    pub resource_type: String,
    pub condition: Option<String>,
    pub depends_on: Vec<String>,
    pub deletion_policy: Option<JsonValue>,
    pub update_replace_policy: Option<JsonValue>,
    pub creation_policy: Option<JsonValue>,
    pub update_policy: Option<JsonValue>,
    #[cfg_attr(feature = "wasm-bindings", tsify(type = "Record<string, JsonValue>"))]
    pub properties: HashMap<String, JsonValue>,
    pub outgoing_refs: Vec<OutgoingRef>,
    pub incoming_refs: Vec<IncomingRef>,
    pub find_in_map_refs: Vec<String>,
    pub simple_subs: Vec<PathVariable>,
    pub redundant_subs: Vec<String>,
    pub empty_joins: Vec<String>,
    pub hardcoded_partition_arns: Vec<String>,
    pub conditionally_null_props: Vec<ConditionalNull>,
    pub condition_refs: Vec<String>,
    pub for_each_expansions: Vec<DiagnosticForEachExpansion>,
    pub unsubstituted_variables: Vec<PathVariable>,
    pub invalid_refs: Vec<PathTarget>,
    pub split_dynamic_ref_delimiters: Vec<String>,
    pub unused_sub_keys: Vec<PathVariable>,
    pub base64_disallowed_functions: Vec<PathVariable>,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct PathVariable {
    pub path: String,
    pub variable: String,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct ConditionalNull {
    pub path: String,
    pub condition: String,
    pub null_in_true: bool,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct DiagnosticForEachExpansion {
    pub path: String,
    pub identifier: String,
    pub collection: String,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct PathTarget {
    pub path: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct GetAttRef {
    pub resource: String,
    pub attribute: String,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticOutput {
    pub value: JsonValue,
    pub description: Option<String>,
    pub condition: Option<String>,
    pub export_name: Option<JsonValue>,
    pub getatt_refs: Vec<GetAttRef>,
    pub condition_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticRule {
    pub name: String,
    pub condition: Option<JsonValue>,
    pub assertions: Vec<DiagnosticRuleAssertion>,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticRuleAssertion {
    pub assert_expr: JsonValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assert_description: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct ResolutionSource {
    pub resource_id: String,
    pub property_path: String,
    pub source: String,
}
