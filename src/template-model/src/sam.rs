use crate::consts::*;
use crate::ir::*;
use crate::model::ResolvedResource;
use crate::resolver::ResolvedValue;
use diagnostics::{Diagnostic, RegisteredDiagnostic, SAM_TRANSFORM_ERROR_PREFIX, SAM_TRANSFORM_ERROR_RULE_ID};
use std::collections::{HashMap, HashSet};

pub fn extract_sam_globals(arena: &Arena, globals_ref: NodeRef) -> HashMap<String, HashMap<String, serde_json::Value>> {
    let mut result = HashMap::new();
    if globals_ref == NULL_REF {
        return result;
    }
    let Some(entries) = arena.as_map(globals_ref) else {
        return result;
    };
    for (type_name, node_ref) in entries {
        let Some(props) = arena.as_map(*node_ref) else {
            continue;
        };
        let mut prop_map = HashMap::new();
        for (k, v) in props {
            prop_map.insert(k.clone(), crate::resolver::node_to_json(arena, *v));
        }
        if !prop_map.is_empty() {
            result.insert(type_name.clone(), prop_map);
        }
    }
    result
}

pub fn apply_sam_globals(
    resources: &mut HashMap<String, ResolvedResource>,
    globals: &HashMap<String, HashMap<String, serde_json::Value>>,
) {
    for (short_name, defaults) in globals {
        let full_type = SAM_GLOBALS_TYPE_MAP.iter().find(|(s, _)| *s == short_name).map(|(_, t)| *t);
        let Some(full_type) = full_type else { continue };
        for res in resources.values_mut() {
            if res.resource_type != full_type {
                continue;
            }
            for (prop, val) in defaults {
                if !res.properties.contains_key(prop) {
                    res.properties.insert(prop.clone(), ResolvedValue::Concrete { value: val.clone().into() });
                }
            }
        }
    }
}

/// Collects the logical ids of resources the SAM transform generates but that
/// are absent from the authored template, so references to them are not flagged
/// as pointing at non-existent resources.
///
/// Only ids that are *deterministic* from the authored template are modeled.
/// SAM also generates content-hash-suffixed resources (a REST API deployment,
/// a Lambda version), whose ids cannot be reconstructed without running the
/// transform; those are intentionally not modeled here.
pub fn collect_sam_implicit_resources(resources: &HashMap<String, ResolvedResource>) -> HashSet<String> {
    let mut implicit = HashSet::new();
    let mut has_api_event = false;
    let mut has_http_api_event = false;
    for (name, res) in resources {
        if res.resource_type == SAM_FUNCTION_TYPE {
            // SAM generates an execution role named `{name}Role` unless the
            // function supplies a concrete Role ARN. A missing Role, or a Role
            // whose value is an intrinsic, still yields the generated role, so a
            // reference to `{name}Role` stays valid in those cases.
            if !has_concrete_role(res.properties.get(SAM_FUNCTION_ROLE)) {
                implicit.insert(format!("{}Role", name));
            }
            if let Some(events) = res.properties.get(SAM_FUNCTION_EVENTS) {
                has_api_event = has_api_event || events_contain_type(events, SAM_EVENT_TYPE_API);
                has_http_api_event = has_http_api_event || events_contain_type(events, SAM_EVENT_TYPE_HTTP_API);
            }
            // A resource-level AutoPublishAlias makes SAM create a Lambda Alias
            // whose logical id is derived from the function id and alias name.
            if let Some(alias_id) = alias_logical_id(name, res.properties.get(SAM_AUTO_PUBLISH_ALIAS)) {
                implicit.insert(alias_id);
            }
        }
    }
    if has_api_event {
        implicit.insert(SAM_IMPLICIT_REST_API.to_string());
        implicit.insert(SAM_IMPLICIT_REST_API_STAGE.to_string());
    }
    if has_http_api_event {
        implicit.insert(SAM_IMPLICIT_HTTP_API.to_string());
    }
    implicit
}

/// Whether the function supplies a concrete Role ARN, in which case SAM does
/// not generate an execution role. An absent Role or an intrinsic-valued Role
/// still results in a generated role.
fn has_concrete_role(role: Option<&ResolvedValue>) -> bool {
    matches!(role, Some(ResolvedValue::Concrete { value }) if value.0.is_string())
}

/// The logical id of the Lambda Alias SAM generates for a function with a
/// literal `AutoPublishAlias`, or `None` when the alias is absent or not a
/// literal string (an intrinsic-valued alias yields a non-deterministic id).
/// Mirrors samtranslator: `{FunctionId}Alias{name}` with hyphens and
/// underscores replaced by `D` and `U` so the id stays alphanumeric.
fn alias_logical_id(function_name: &str, alias: Option<&ResolvedValue>) -> Option<String> {
    let ResolvedValue::Concrete { value } = alias? else {
        return None;
    };
    let name = value.0.as_str()?;
    if name.is_empty() {
        return None;
    }
    let alphanumeric_name = name.replace('-', "D").replace('_', "U");
    Some(format!("{}Alias{}", function_name, alphanumeric_name))
}

fn events_contain_type(events: &ResolvedValue, event_type: &str) -> bool {
    match events {
        ResolvedValue::Map { entries } => entries.iter().any(|e| is_event_of_type(&e.value, event_type)),
        ResolvedValue::Concrete { value: v } => v
            .as_object()
            .map(|obj| {
                obj.values()
                    .any(|ev| ev.as_object().and_then(|o| o.get(KEY_TYPE)).and_then(|t| t.as_str()) == Some(event_type))
            })
            .unwrap_or(false),
        _ => false,
    }
}

fn is_event_of_type(ev: &ResolvedValue, event_type: &str) -> bool {
    match ev {
        ResolvedValue::Map { entries } => entries.iter().any(|e| {
            e.key == KEY_TYPE
                && matches!(&e.value, ResolvedValue::Concrete { value: v } if v.as_str() == Some(event_type))
        }),
        ResolvedValue::Concrete { value: v } => {
            v.as_object().and_then(|obj| obj.get(KEY_TYPE)).and_then(|t| t.as_str()) == Some(event_type)
        }
        _ => false,
    }
}

pub fn collect_globals_param_refs(arena: &Arena, globals_ref: NodeRef) -> Vec<String> {
    let mut refs = Vec::new();
    if globals_ref == NULL_REF {
        return refs;
    }
    collect_arena_param_refs(arena, globals_ref, &mut refs);
    refs.sort();
    refs.dedup();
    refs
}

pub fn cycle_involves_sam_diagnostic(diagnostic: &Diagnostic, resources: &HashMap<String, ResolvedResource>) -> bool {
    resources.iter().any(|(name, res)| {
        res.resource_type.starts_with(SAM_SERVERLESS_TYPE_PREFIX) && diagnostic.message.contains(name.as_str())
    })
}

fn collect_arena_param_refs(arena: &Arena, node_ref: NodeRef, out: &mut Vec<String>) {
    if node_ref == NULL_REF {
        return;
    }
    match arena.node(node_ref) {
        Node::Intrinsic(intrinsic) => match intrinsic {
            IntrinsicFn::Ref(target) => {
                if !target.starts_with(PSEUDO_PREFIX) {
                    out.push(target.clone());
                }
            }
            IntrinsicFn::Sub(template, subs) => {
                for cap in template.split("${").skip(1) {
                    if let Some(end) = cap.find('}') {
                        let var = &cap[..end];
                        if !var.starts_with(PSEUDO_PREFIX) && !var.contains('.') {
                            out.push(var.to_string());
                        }
                    }
                }
                if let Some(sub_list) = subs {
                    for (_, v) in sub_list {
                        collect_arena_param_refs(arena, *v, out);
                    }
                }
            }
            IntrinsicFn::If(_, t, f) => {
                collect_arena_param_refs(arena, *t, out);
                collect_arena_param_refs(arena, *f, out);
            }
            IntrinsicFn::Join(_, v) => {
                collect_arena_param_refs(arena, *v, out);
            }
            IntrinsicFn::ImportValue(v) | IntrinsicFn::Base64(v) => {
                collect_arena_param_refs(arena, *v, out);
            }
            IntrinsicFn::GetStackOutput(args) => {
                for (_, v) in args {
                    collect_arena_param_refs(arena, *v, out);
                }
            }
            _ => {}
        },
        Node::List(items) => {
            for r in items {
                collect_arena_param_refs(arena, *r, out);
            }
        }
        Node::Map(entries) => {
            for (_, r) in entries {
                collect_arena_param_refs(arena, *r, out);
            }
        }
        _ => {}
    }
}

/// Collects SAM transform errors that require the raw template structure.
/// A transform error means CloudFormation rejects the template before resource
/// validation, so downstream diagnostics are gated on these.
///
/// All SAM transform-error checks are emitted from this single location, so the
/// diagnostics are produced once as part of the shared model rather than during
/// rule evaluation.
pub fn collect_transform_errors(
    arena: &Arena,
    resources_node: NodeRef,
    globals_node: NodeRef,
    resources: &HashMap<String, ResolvedResource>,
    parameter_names: &HashSet<String>,
    span_index: &SourceSpanIndex,
) -> Vec<Diagnostic> {
    let context = TransformErrorContext { arena, resources_node, globals_node, resources, parameter_names, span_index };

    let mut errors = Vec::new();
    // The Globals section is validated before resources, so its error preempts
    // the per-resource checks below when present.
    if let Some(globals_error) = globals_section_violation(&context) {
        errors.push(globals_error);
        return errors;
    }
    auto_publish_alias_must_be_string_or_parameter_ref(&context, &mut errors);
    layer_version_must_have_content_uri(&context, &mut errors);
    layer_version_property_transform_errors(&context, &mut errors);
    application_must_have_location(&context, &mut errors);
    schedule_event_must_have_schedule(&context, &mut errors);
    function_property_transform_errors(&context, &mut errors);
    api_must_have_stage_name(&context, &mut errors);
    state_machine_definition_exactly_one(&context, &mut errors);
    connector_must_have_required_properties(&context, &mut errors);
    graphql_api_must_have_auth(&context, &mut errors);
    simple_table_primary_key_type(&context, &mut errors);
    errors
}

/// Inputs that every transform-error validator needs. Bundled into one type so
/// each validator has a stable signature even as new fields are added.
struct TransformErrorContext<'a> {
    arena: &'a Arena,
    resources_node: NodeRef,
    globals_node: NodeRef,
    resources: &'a HashMap<String, ResolvedResource>,
    parameter_names: &'a HashSet<String>,
    span_index: &'a SourceSpanIndex,
}

impl<'a> TransformErrorContext<'a> {
    fn resources_of_type(&self, full_type: &str) -> Vec<&'a str> {
        let mut names: Vec<&str> = self
            .resources
            .iter()
            .filter(|(_, res)| res.resource_type == full_type)
            .map(|(name, _)| name.as_str())
            .collect();
        names.sort_by_key(|name| sort_key(self.span_index, name));
        names
    }

    fn span_for(&self, resource_id: &str, prop_path: &str) -> SourceSpan {
        let resource_path = format!("Resources/{}", resource_id);
        let specific_path =
            if prop_path.is_empty() { resource_path.clone() } else { format!("{}/{}", resource_path, prop_path) };
        self.span_index
            .get(&specific_path)
            .or_else(|| self.span_index.get(&resource_path))
            .copied()
            .unwrap_or(UNKNOWN_SPAN)
    }
}

fn auto_publish_alias_must_be_string_or_parameter_ref(ctx: &TransformErrorContext, out: &mut Vec<Diagnostic>) {
    for name in ctx.resources_of_type(SAM_FUNCTION_TYPE) {
        let Some(located) = located_auto_publish_alias(ctx.arena, ctx.resources_node, ctx.globals_node, name) else {
            continue;
        };
        let Some(message_suffix) = auto_publish_alias_violation(ctx.arena, located.node, ctx.parameter_names) else {
            continue;
        };
        out.push(make_transform_error(
            name,
            sam_property_path(KEY_PROPERTIES, SAM_AUTO_PUBLISH_ALIAS),
            format!("{} Resource with id [{}] is invalid. {}", SAM_TRANSFORM_ERROR_PREFIX, name, message_suffix),
            located.diagnostic_span(name, ctx.span_index),
        ));
    }
}

/// Returns the equivalent message suffix when `AutoPublishAlias` is
/// invalid, or `None` when the value would resolve cleanly. The branching
/// mirrors samtranslator: a multi-key dict fails resource property typing
/// before resolution and surfaces as `"Type of property '…' is invalid."`,
/// while every other unresolvable case (single-key non-Ref intrinsic, Ref to
/// a non-parameter resource, Sub/GetAtt/etc.) surfaces as the alias-type
/// message.
fn auto_publish_alias_violation(arena: &Arena, node: NodeRef, parameter_names: &HashSet<String>) -> Option<String> {
    match arena.node(node) {
        Node::String(_) => None,
        Node::Intrinsic(IntrinsicFn::Ref(target)) if parameter_names.contains(target) => None,
        Node::Map(entries) if entries.len() != 1 => {
            Some(format!("Type of property '{}' is invalid.", SAM_AUTO_PUBLISH_ALIAS))
        }
        _ => Some(format!("'{}' must be a string or a Ref to a template parameter", SAM_AUTO_PUBLISH_ALIAS)),
    }
}

fn layer_version_must_have_content_uri(ctx: &TransformErrorContext, out: &mut Vec<Diagnostic>) {
    for name in ctx.resources_of_type(SAM_LAYER_VERSION_TYPE) {
        if resource_has_property(ctx.resources, name, SAM_LAYER_CONTENT_URI) {
            continue;
        }
        let prop_path = sam_property_path(KEY_PROPERTIES, SAM_LAYER_CONTENT_URI);
        out.push(make_transform_error(
            name,
            prop_path.clone(),
            format!(
                "{} Resource with id [{}] is invalid. Missing required property '{}'.",
                SAM_TRANSFORM_ERROR_PREFIX, name, SAM_LAYER_CONTENT_URI
            ),
            ctx.span_for(name, &prop_path),
        ));
    }
}

/// A `LayerVersion` `RetentionPolicy`, when a literal, must be `Retain` or
/// `Delete`; `CompatibleArchitectures`, when a literal list, must contain only
/// valid Lambda architectures.
fn layer_version_property_transform_errors(ctx: &TransformErrorContext, out: &mut Vec<Diagnostic>) {
    for name in ctx.resources_of_type(SAM_LAYER_VERSION_TYPE) {
        let Some(props) = ctx.resources.get(name).map(|res| &res.properties) else {
            continue;
        };
        if let Some(retention) = props.get(SAM_LAYER_RETENTION_POLICY).and_then(concrete_str)
            && !SAM_LAYER_RETENTION_POLICIES.iter().any(|p| p.eq_ignore_ascii_case(retention))
        {
            out.push(make_transform_error(
                name,
                KEY_PROPERTIES.to_string(),
                format!(
                    "{} Resource with id [{}] is invalid. 'RetentionPolicy' must be one of the following options: {}.",
                    SAM_TRANSFORM_ERROR_PREFIX,
                    name,
                    quoted_list(SAM_LAYER_RETENTION_POLICIES)
                ),
                ctx.span_for(name, KEY_PROPERTIES),
            ));
            continue;
        }
        if has_invalid_architecture(props.get(SAM_LAYER_COMPATIBLE_ARCHITECTURES)) {
            out.push(make_transform_error(
                name,
                KEY_PROPERTIES.to_string(),
                format!(
                    "{} Resource with id [{}] is invalid. CompatibleArchitectures needs to be a list of 'x86_64' or 'arm64'",
                    SAM_TRANSFORM_ERROR_PREFIX, name
                ),
                ctx.span_for(name, KEY_PROPERTIES),
            ));
        }
    }
}

/// Whether a `CompatibleArchitectures` value is a literal list containing an
/// entry outside the valid architecture set. A non-literal value (intrinsic) is
/// not checked.
fn has_invalid_architecture(value: Option<&ResolvedValue>) -> bool {
    let literals: Vec<&str> = match value {
        Some(ResolvedValue::List { items }) => items.iter().filter_map(concrete_str).collect(),
        Some(ResolvedValue::Concrete { value }) => match value.0.as_array() {
            Some(arr) => arr.iter().filter_map(|v| v.as_str()).collect(),
            None => return false,
        },
        _ => return false,
    };
    literals.iter().any(|arch| !SAM_ARCHITECTURES.contains(arch))
}

fn application_must_have_location(ctx: &TransformErrorContext, out: &mut Vec<Diagnostic>) {
    for name in ctx.resources_of_type(SAM_APPLICATION_TYPE) {
        if resource_has_property(ctx.resources, name, SAM_APPLICATION_LOCATION) {
            continue;
        }
        let prop_path = sam_property_path(KEY_PROPERTIES, SAM_APPLICATION_LOCATION);
        out.push(make_transform_error(
            name,
            prop_path.clone(),
            format!(
                "{} Resource with id [{}] is invalid. Resource is missing the required [{}] property.",
                SAM_TRANSFORM_ERROR_PREFIX, name, SAM_APPLICATION_LOCATION
            ),
            ctx.span_for(name, &prop_path),
        ));
    }
}

fn api_must_have_stage_name(ctx: &TransformErrorContext, out: &mut Vec<Diagnostic>) {
    for name in ctx.resources_of_type(SAM_API_TYPE) {
        if resource_has_property(ctx.resources, name, SAM_API_STAGE_NAME) {
            continue;
        }
        out.push(missing_required_property_error(ctx, name, SAM_API_STAGE_NAME));
    }
}

fn graphql_api_must_have_auth(ctx: &TransformErrorContext, out: &mut Vec<Diagnostic>) {
    for name in ctx.resources_of_type(SAM_GRAPHQL_API_TYPE) {
        if resource_has_property(ctx.resources, name, SAM_GRAPHQL_AUTH) {
            continue;
        }
        out.push(missing_required_property_error(ctx, name, SAM_GRAPHQL_AUTH));
    }
}

/// A connector requires `Source`, `Destination`, and `Permissions`. SAM reports
/// the first one missing in that order, so only the first absent property is
/// surfaced to match its single-message behavior.
fn connector_must_have_required_properties(ctx: &TransformErrorContext, out: &mut Vec<Diagnostic>) {
    for name in ctx.resources_of_type(SAM_CONNECTOR_TYPE) {
        let missing = [SAM_CONNECTOR_SOURCE, SAM_CONNECTOR_DESTINATION, SAM_CONNECTOR_PERMISSIONS]
            .into_iter()
            .find(|prop| !resource_has_property(ctx.resources, name, prop));
        if let Some(prop) = missing {
            out.push(missing_required_property_error(ctx, name, prop));
        }
    }
}

/// A state machine must define its workflow through exactly one of `Definition`
/// or `DefinitionUri`; neither and both are transform errors with distinct
/// messages.
fn state_machine_definition_exactly_one(ctx: &TransformErrorContext, out: &mut Vec<Diagnostic>) {
    for name in ctx.resources_of_type(SAM_STATE_MACHINE_TYPE) {
        let has_definition = resource_has_property(ctx.resources, name, SAM_DEFINITION);
        let has_definition_uri = resource_has_property(ctx.resources, name, SAM_DEFINITION_URI);
        let message_suffix = match (has_definition, has_definition_uri) {
            (false, false) => "Either 'Definition' or 'DefinitionUri' property must be specified.",
            (true, true) => "Specify either 'Definition' or 'DefinitionUri' property and not both.",
            _ => continue,
        };
        out.push(make_transform_error(
            name,
            KEY_PROPERTIES.to_string(),
            format!("{} Resource with id [{}] is invalid. {}", SAM_TRANSFORM_ERROR_PREFIX, name, message_suffix),
            ctx.span_for(name, KEY_PROPERTIES),
        ));
    }
}

/// A `SimpleTable` PrimaryKey, when present, must declare a `Type`, and that
/// type must be a valid DynamoDB attribute type. Only literal types are checked
/// — an intrinsic-valued type cannot be validated pre-deployment.
fn simple_table_primary_key_type(ctx: &TransformErrorContext, out: &mut Vec<Diagnostic>) {
    for name in ctx.resources_of_type(SAM_SIMPLE_TABLE_TYPE) {
        let Some(primary_key) =
            ctx.resources.get(name).and_then(|res| res.properties.get(SAM_SIMPLE_TABLE_PRIMARY_KEY))
        else {
            continue;
        };
        let prop_path = sam_property_path(KEY_PROPERTIES, SAM_SIMPLE_TABLE_PRIMARY_KEY);
        match primary_key_type(primary_key) {
            PrimaryKeyType::Missing => out.push(make_transform_error(
                name,
                prop_path.clone(),
                format!(
                    "{} Resource with id [{}] is invalid. Property 'PrimaryKey.Type' is required.",
                    SAM_TRANSFORM_ERROR_PREFIX, name
                ),
                ctx.span_for(name, &prop_path),
            )),
            PrimaryKeyType::Invalid(value) => out.push(make_transform_error(
                name,
                prop_path.clone(),
                format!(
                    "{} Resource with id [{}] is invalid. Invalid 'Type' \"{}\".",
                    SAM_TRANSFORM_ERROR_PREFIX, name, value
                ),
                ctx.span_for(name, &prop_path),
            )),
            PrimaryKeyType::Valid | PrimaryKeyType::NotAnObject => {}
        }
    }
}

enum PrimaryKeyType {
    /// PrimaryKey is an object but has no `Type` key.
    Missing,
    /// `Type` is a literal string that is not a valid attribute type.
    Invalid(String),
    /// `Type` is a valid literal, or an intrinsic that cannot be checked.
    Valid,
    /// PrimaryKey is not an object (e.g. an intrinsic), so no check applies.
    NotAnObject,
}

fn primary_key_type(primary_key: &ResolvedValue) -> PrimaryKeyType {
    let type_value = match primary_key {
        ResolvedValue::Map { entries } => entries.iter().find(|e| e.key == SAM_PRIMARY_KEY_TYPE).map(|e| &e.value),
        ResolvedValue::Concrete { value } => {
            let Some(obj) = value.0.as_object() else {
                return PrimaryKeyType::NotAnObject;
            };
            return match obj.get(SAM_PRIMARY_KEY_TYPE) {
                None => PrimaryKeyType::Missing,
                Some(t) => classify_primary_key_type(t.as_str()),
            };
        }
        _ => return PrimaryKeyType::NotAnObject,
    };
    match type_value {
        None => PrimaryKeyType::Missing,
        Some(ResolvedValue::Concrete { value }) => classify_primary_key_type(value.0.as_str()),
        // A non-concrete Type is an intrinsic; its value is unknown here.
        Some(_) => PrimaryKeyType::Valid,
    }
}

fn classify_primary_key_type(type_str: Option<&str>) -> PrimaryKeyType {
    match type_str {
        // A non-string literal Type cannot be validated against the enum here.
        None => PrimaryKeyType::Valid,
        Some(value) if SAM_PRIMARY_KEY_TYPES.contains(&value) => PrimaryKeyType::Valid,
        Some(value) => PrimaryKeyType::Invalid(value.to_string()),
    }
}

/// Emits at most one transform error per function, mirroring the order in which
/// samtranslator raises them: property validation rules first (combined into a
/// single message), then the dead-letter-queue check, then package-type checks,
/// then the provisioned-concurrency requirement. A function is rejected on the
/// first failure, so only that error is surfaced.
fn function_property_transform_errors(ctx: &TransformErrorContext, out: &mut Vec<Diagnostic>) {
    for name in ctx.resources_of_type(SAM_FUNCTION_TYPE) {
        let Some(props) = ctx.resources.get(name).map(|res| &res.properties) else {
            continue;
        };
        if let Some(message_suffix) = first_function_violation(props) {
            out.push(make_transform_error(
                name,
                KEY_PROPERTIES.to_string(),
                format!("{} Resource with id [{}] is invalid. {}", SAM_TRANSFORM_ERROR_PREFIX, name, message_suffix),
                ctx.span_for(name, KEY_PROPERTIES),
            ));
        }
    }
}

/// The message suffix of the first transform error a function's properties would
/// trigger, or `None` when none apply. Ordered to match the sequence in which
/// samtranslator raises them so that, when several rules are violated, the tool
/// reports the same one CloudFormation would.
fn first_function_violation(props: &HashMap<String, ResolvedValue>) -> Option<String> {
    validation_rule_violations(props)
        .or_else(|| dead_letter_queue_violation(props))
        .or_else(|| package_type_violation(props))
        .or_else(|| function_url_auth_type_violation(props))
        .or_else(|| deployment_preference_violation(props))
        .or_else(|| auto_publish_alias_name_violation(props))
        .or_else(|| provisioned_concurrency_violation(props))
}

/// The mutually-exclusive and conditional-requirement property rules, joined
/// with newlines into a single message as samtranslator does. Only literal
/// property presence is considered; a property whose value is an explicit null
/// is treated as absent.
fn validation_rule_violations(props: &HashMap<String, ResolvedValue>) -> Option<String> {
    let present = |prop: &str| property_present(props, prop);
    let mut messages = Vec::new();
    let mutually_exclusive = [
        (SAM_FUNCTION_CAPACITY_PROVIDER, SAM_FUNCTION_PROVISIONED_CONCURRENCY),
        (SAM_FUNCTION_CAPACITY_PROVIDER, SAM_FUNCTION_VPC_CONFIG),
    ];
    for (a, b) in mutually_exclusive {
        if present(a) && present(b) {
            messages.push(format!("Cannot specify '{}' and '{}' together.", a, b));
        }
    }
    let conditional_requirement = [
        (SAM_FUNCTION_SCALING_CONFIG, SAM_FUNCTION_CAPACITY_PROVIDER),
        (SAM_FUNCTION_VERSION_DELETION_POLICY, SAM_AUTO_PUBLISH_ALIAS),
    ];
    for (dependent, required) in conditional_requirement {
        if present(dependent) && !present(required) {
            messages.push(format!("'{}' requires '{}'.", dependent, required));
        }
    }
    if messages.is_empty() { None } else { Some(messages.join("\n")) }
}

/// A dead-letter queue must specify both `Type` and `TargetArn`, and the type
/// must be one of the supported queue services. Only checked when the queue is
/// an object with literal values.
fn dead_letter_queue_violation(props: &HashMap<String, ResolvedValue>) -> Option<String> {
    let dlq = props.get(SAM_FUNCTION_DEAD_LETTER_QUEUE)?;
    let fields = object_fields(dlq)?;
    let dlq_type = fields.get(KEY_TYPE).and_then(concrete_str);
    let has_target = fields.contains_key(SAM_FUNCTION_TARGET_ARN);
    if dlq_type.is_none() || !has_target {
        return Some("'DeadLetterQueue' requires Type and TargetArn properties to be specified.".to_string());
    }
    let dlq_type = dlq_type?;
    if !SAM_DLQ_TYPES.contains(&dlq_type) {
        return Some(format!("'DeadLetterQueue' requires Type of {}", quoted_list(SAM_DLQ_TYPES)));
    }
    None
}

/// Renders a list of string values the way samtranslator's Python messages do:
/// single-quoted items in square brackets, e.g. `['SQS', 'SNS']`.
fn quoted_list(values: &[&str]) -> String {
    let items: Vec<String> = values.iter().map(|v| format!("'{}'", v)).collect();
    format!("[{}]", items.join(", "))
}

/// Package-type consistency: the type must be Zip or Image, a Zip function must
/// declare Runtime and Handler, and an Image function must not declare Runtime,
/// Handler, or Layers. The package type defaults to Zip when unset.
fn package_type_violation(props: &HashMap<String, ResolvedValue>) -> Option<String> {
    let package_type = match props.get(SAM_FUNCTION_PACKAGE_TYPE) {
        None => SAM_PACKAGE_TYPE_ZIP,
        Some(value) => {
            let literal = concrete_str(value)?;
            if literal != SAM_PACKAGE_TYPE_ZIP && literal != SAM_PACKAGE_TYPE_IMAGE {
                return Some(format!("invalid 'PackageType' : {}", literal));
            }
            literal
        }
    };
    if package_type == SAM_PACKAGE_TYPE_ZIP {
        if !property_present(props, SAM_FUNCTION_RUNTIME) || !property_present(props, SAM_FUNCTION_HANDLER) {
            return Some("Runtime and Handler needs to be present when PackageType is of type `Zip`".to_string());
        }
        if property_present(props, SAM_FUNCTION_IMAGE_URI) || property_present(props, SAM_FUNCTION_IMAGE_CONFIG) {
            return Some("ImageUri or ImageConfig cannot be present when PackageType is of type `Zip`".to_string());
        }
    } else if property_present(props, SAM_FUNCTION_HANDLER)
        || property_present(props, SAM_FUNCTION_RUNTIME)
        || property_present(props, SAM_FUNCTION_LAYERS)
    {
        return Some("Runtime, Handler, Layers cannot be present when PackageType is of type `Image`".to_string());
    }
    None
}

/// `FunctionUrlConfig`, when present, must declare an `AuthType` of `AWS_IAM` or
/// `NONE`. A missing or invalid literal value is rejected with the same message.
fn function_url_auth_type_violation(props: &HashMap<String, ResolvedValue>) -> Option<String> {
    let url_config = props.get(SAM_FUNCTION_URL_CONFIG)?;
    let fields = object_fields(url_config)?;
    let auth_type = fields.get(SAM_FUNCTION_URL_AUTH_TYPE);
    // An intrinsic-valued AuthType cannot be checked; only literals are.
    let invalid = match auth_type {
        None => true,
        Some(value) => match concrete_str(value) {
            Some(literal) => !SAM_FUNCTION_URL_AUTH_TYPES.contains(&literal),
            None => false,
        },
    };
    if invalid {
        return Some(
            "AuthType is required to configure function property `FunctionUrlConfig`. \
             Please provide either AWS_IAM or NONE."
                .to_string(),
        );
    }
    None
}

/// A deployment preference can only be configured on a function that also
/// publishes an alias.
fn deployment_preference_violation(props: &HashMap<String, ResolvedValue>) -> Option<String> {
    if property_present(props, SAM_FUNCTION_DEPLOYMENT_PREFERENCE) && !property_present(props, SAM_AUTO_PUBLISH_ALIAS) {
        return Some("'DeploymentPreference' requires AutoPublishAlias property to be specified.".to_string());
    }
    None
}

/// A literal `AutoPublishAlias` must match the Lambda alias name pattern: only
/// alphanumerics, hyphens, and underscores, and not purely numeric. Non-literal
/// aliases (Refs to parameters) are validated elsewhere.
fn auto_publish_alias_name_violation(props: &HashMap<String, ResolvedValue>) -> Option<String> {
    let alias = concrete_str(props.get(SAM_AUTO_PUBLISH_ALIAS)?)?;
    if is_valid_alias_name(alias) {
        return None;
    }
    Some(format!(
        "AutoPublishAlias name ('{}') must contain only alphanumeric characters, hyphens, or underscores \
         matching (?!^[0-9]+$)([a-zA-Z0-9-_]+) pattern.",
        alias
    ))
}

/// Whether an alias name matches SAM's required pattern `(?!^[0-9]+$)([a-zA-Z0-9-_]+)`:
/// non-empty, only alphanumerics/hyphen/underscore, and not entirely digits.
fn is_valid_alias_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return false;
    }
    !name.chars().all(|c| c.is_ascii_digit())
}

/// Provisioned concurrency can only be configured on a function that also
/// publishes an alias.
fn provisioned_concurrency_violation(props: &HashMap<String, ResolvedValue>) -> Option<String> {
    if property_present(props, SAM_FUNCTION_PROVISIONED_CONCURRENCY) && !property_present(props, SAM_AUTO_PUBLISH_ALIAS)
    {
        return Some(
            "To set ProvisionedConcurrencyConfig AutoPublishALias must be defined on the function".to_string(),
        );
    }
    None
}

/// Whether a property is present with a non-null value. An explicit null is
/// treated as absent, matching how the transform reads missing properties.
fn property_present(props: &HashMap<String, ResolvedValue>, property: &str) -> bool {
    match props.get(property) {
        None => false,
        Some(ResolvedValue::Concrete { value }) => !value.0.is_null(),
        Some(_) => true,
    }
}

/// The field map of an object-valued property, whether it resolved to a concrete
/// JSON object or a partially-resolved map. Returns `None` for non-object values.
fn object_fields(value: &ResolvedValue) -> Option<HashMap<String, ResolvedValue>> {
    match value {
        ResolvedValue::Map { entries } => Some(entries.iter().map(|e| (e.key.clone(), e.value.clone())).collect()),
        ResolvedValue::Concrete { value } => value.0.as_object().map(|obj| {
            obj.iter().map(|(k, v)| (k.clone(), ResolvedValue::Concrete { value: v.clone().into() })).collect()
        }),
        _ => None,
    }
}

/// The string value of a concrete resolved value, or `None` when it is not a
/// literal string.
fn concrete_str(value: &ResolvedValue) -> Option<&str> {
    match value {
        ResolvedValue::Concrete { value } => value.0.as_str(),
        _ => None,
    }
}

fn schedule_event_must_have_schedule(ctx: &TransformErrorContext, out: &mut Vec<Diagnostic>) {
    for name in ctx.resources_of_type(SAM_FUNCTION_TYPE) {
        let Some(events_value) = ctx.resources.get(name).and_then(|res| res.properties.get(SAM_FUNCTION_EVENTS)) else {
            continue;
        };
        for (event_name, event_object) in event_object_entries(events_value) {
            if !is_schedule_event_missing_schedule(&event_object) {
                continue;
            }
            let prop_path = format!("{}/{}/{}", KEY_PROPERTIES, SAM_FUNCTION_EVENTS, event_name);
            out.push(make_transform_error(
                name,
                prop_path.clone(),
                format!(
                    "{} Resource with id [{}{}] is invalid. Missing required property '{}'.",
                    SAM_TRANSFORM_ERROR_PREFIX, name, event_name, SAM_SCHEDULE_PROPERTY
                ),
                ctx.span_for(name, &prop_path),
            ));
        }
    }
}

/// The sorted list of section names the `Globals` section accepts, shown in the
/// unsupported-section error. Mirrors samtranslator's supported resource types.
const SAM_GLOBALS_SECTION_NAMES: &[&str] = &[
    "Api",
    "CapacityProvider",
    "Function",
    "HttpApi",
    "LayerVersion",
    "MicrovmImage",
    "NetworkConnector",
    "SimpleTable",
    "StateMachine",
    "WebSocketApi",
];

/// Each `Globals` section and the properties it permits, mirroring
/// samtranslator's `supported_properties`. A property outside its section's
/// list is a transform error.
fn globals_supported_properties(section: &str) -> Option<&'static [&'static str]> {
    match section {
        "Function" => Some(&[
            "Handler",
            "Runtime",
            "CodeUri",
            "DeadLetterQueue",
            "Description",
            "MemorySize",
            "Timeout",
            "VpcConfig",
            "Environment",
            "Tags",
            "PropagateTags",
            "Tracing",
            "KmsKeyArn",
            "AutoPublishAlias",
            "AutoPublishAliasAllProperties",
            "Layers",
            "DeploymentPreference",
            "RolePath",
            "PermissionsBoundary",
            "ReservedConcurrentExecutions",
            "ProvisionedConcurrencyConfig",
            "AssumeRolePolicyDocument",
            "EventInvokeConfig",
            "FileSystemConfigs",
            "CodeSigningConfigArn",
            "Architectures",
            "SnapStart",
            "EphemeralStorage",
            "FunctionUrlConfig",
            "RuntimeManagementConfig",
            "LoggingConfig",
            "RecursiveLoop",
            "SourceKMSKeyArn",
            "TenancyConfig",
            "DurableConfig",
            "CapacityProviderConfig",
            "FunctionScalingConfig",
            "PublishToLatestPublished",
            "VersionDeletionPolicy",
        ]),
        "Api" => Some(&[
            "Auth",
            "Name",
            "DefinitionUri",
            "CacheClusterEnabled",
            "CacheClusterSize",
            "MergeDefinitions",
            "Variables",
            "EndpointConfiguration",
            "MethodSettings",
            "BinaryMediaTypes",
            "MinimumCompressionSize",
            "Cors",
            "GatewayResponses",
            "AccessLogSetting",
            "CanarySetting",
            "TracingEnabled",
            "OpenApiVersion",
            "Domain",
            "AlwaysDeploy",
            "PropagateTags",
            "SecurityPolicy",
            "EndpointAccessMode",
        ]),
        "HttpApi" => Some(&[
            "Auth",
            "AccessLogSettings",
            "StageVariables",
            "Tags",
            "CorsConfiguration",
            "DefaultRouteSettings",
            "Domain",
            "RouteSettings",
            "FailOnWarnings",
            "PropagateTags",
        ]),
        "SimpleTable" => Some(&["SSESpecification"]),
        "StateMachine" => Some(&["PropagateTags"]),
        "LayerVersion" => Some(&["PublishLambdaVersion"]),
        "CapacityProvider" => Some(&[
            "VpcConfig",
            "OperatorRole",
            "Tags",
            "InstanceRequirements",
            "ScalingConfig",
            "KmsKeyArn",
            "PropagateTags",
        ]),
        "NetworkConnector" => Some(&["OperatorRole", "Tags", "PropagateTags"]),
        "MicrovmImage" => Some(&[
            "BuildRoleArn",
            "BaseImageArn",
            "BaseImageVersion",
            "Logging",
            "EgressNetworkConnectors",
            "CpuConfigurations",
            "Resources",
            "AdditionalOsCapabilities",
            "Hooks",
            "EnvironmentVariables",
            "Tags",
            "PropagateTags",
        ]),
        "WebSocketApi" => Some(&[
            "AccessLogSettings",
            "ApiKeySelectionExpression",
            "DefaultRouteSettings",
            "DisableExecuteApiEndpoint",
            "DisableSchemaValidation",
            "Domain",
            "FailOnWarnings",
            "IpAddressType",
            "PropagateTags",
            "RouteSelectionExpression",
            "RouteSettings",
            "StageVariables",
            "Tags",
        ]),
        _ => None,
    }
}

/// Validates the raw `Globals` section the way samtranslator does before any
/// resource expansion: the section must be a map of known section names, each
/// mapping to a map whose keys are all supported for that section. The first
/// violation aborts the transform, so at most one error is returned.
fn globals_section_violation(ctx: &TransformErrorContext) -> Option<Diagnostic> {
    if ctx.globals_node == NULL_REF {
        return None;
    }
    let globals_span = ctx.span_index.get(SECTION_GLOBALS).copied().unwrap_or(UNKNOWN_SPAN);
    let Some(sections) = ctx.arena.as_map(ctx.globals_node) else {
        // A Globals value that is not a map is rejected outright. An empty map
        // is accepted (the transform treats it as no globals), matching SAM's
        // own dict-type check which passes for an empty dictionary.
        return Some(make_globals_error("It must be a non-empty dictionary".to_string(), globals_span));
    };
    for (section_name, section_ref) in sections {
        let Some(supported) = globals_supported_properties(section_name) else {
            return Some(make_globals_error(
                format!(
                    "'{}' is not supported. Must be one of the following values - {}",
                    section_name,
                    quoted_list(SAM_GLOBALS_SECTION_NAMES)
                ),
                globals_span,
            ));
        };
        let Some(properties) = ctx.arena.as_map(*section_ref) else {
            return Some(make_globals_error("Value of ${section} must be a dictionary".to_string(), globals_span));
        };
        for (property_name, _) in properties {
            if !supported.contains(&property_name.as_str()) {
                return Some(make_globals_error(
                    format!(
                        "'{}' is not a supported property of '{}'. Must be one of the following values - {}",
                        property_name,
                        section_name,
                        quoted_list(supported)
                    ),
                    globals_span,
                ));
            }
        }
    }
    None
}

/// Builds a `Globals`-section transform error. These are not tied to a specific
/// resource, so the diagnostic anchors at the `Globals` section rather than a
/// resource id.
fn make_globals_error(detail: String, span: SourceSpan) -> Diagnostic {
    RegisteredDiagnostic::new(
        SAM_TRANSFORM_ERROR_RULE_ID,
        format!("{} 'Globals' section is invalid. {}", SAM_TRANSFORM_ERROR_PREFIX, detail),
    )
    .property_path(SECTION_GLOBALS)
    .location(span)
    .build()
}

fn sam_property_path(prefix: &str, property: &str) -> String {
    format!("{}/{}", prefix, property)
}

/// Builds the transform error for a required property missing from a resource,
/// anchored at that property's path. Shared by the required-property validators
/// that all surface SAM's `Missing required property '<name>'.` message.
fn missing_required_property_error(ctx: &TransformErrorContext, resource_id: &str, property: &str) -> Diagnostic {
    let prop_path = sam_property_path(KEY_PROPERTIES, property);
    let span = ctx.span_for(resource_id, &prop_path);
    make_transform_error(
        resource_id,
        prop_path,
        format!(
            "{} Resource with id [{}] is invalid. Missing required property '{}'.",
            SAM_TRANSFORM_ERROR_PREFIX, resource_id, property
        ),
        span,
    )
}

fn resource_has_property(resources: &HashMap<String, ResolvedResource>, resource_id: &str, property: &str) -> bool {
    resources.get(resource_id).map(|r| r.properties.contains_key(property)).unwrap_or(false)
}

/// Flattens a SAM `Events` map into `(event_name, event_json)` pairs, skipping
/// internal keys (`__*`) the resolver may have inserted and any non-object
/// entries that cannot be a SAM event definition.
fn event_object_entries(events: &ResolvedValue) -> Vec<(String, serde_json::Value)> {
    let entries = match events {
        ResolvedValue::Map { entries } => entries.clone(),
        ResolvedValue::Concrete { value } => {
            let Some(obj) = value.as_object() else {
                return Vec::new();
            };
            return obj
                .iter()
                .filter(|(k, _)| !k.starts_with("__"))
                .filter_map(|(k, v)| v.as_object().map(|_| (k.clone(), v.clone())))
                .collect();
        }
        _ => return Vec::new(),
    };
    entries
        .into_iter()
        .filter(|e| !e.key.starts_with("__"))
        .filter_map(|e| match e.value {
            ResolvedValue::Concrete { value } => Some((e.key, value.0.clone())),
            ResolvedValue::Map { entries: inner } => {
                let obj: serde_json::Map<String, serde_json::Value> = inner
                    .into_iter()
                    .filter_map(|me| match me.value {
                        ResolvedValue::Concrete { value } => Some((me.key, value.0.clone())),
                        _ => None,
                    })
                    .collect();
                Some((e.key, serde_json::Value::Object(obj)))
            }
            _ => None,
        })
        .collect()
}

fn is_schedule_event_missing_schedule(event_json: &serde_json::Value) -> bool {
    let Some(obj) = event_json.as_object() else {
        return false;
    };
    if obj.get(KEY_TYPE).and_then(|v| v.as_str()) != Some(SAM_EVENT_TYPE_SCHEDULE) {
        return false;
    }
    let has_schedule = obj
        .get(KEY_PROPERTIES)
        .and_then(|p| p.as_object())
        .map(|p| p.contains_key(SAM_SCHEDULE_PROPERTY))
        .unwrap_or(false);
    !has_schedule
}

struct LocatedAlias {
    node: NodeRef,
    source: AliasSource,
}

#[derive(Copy, Clone)]
enum AliasSource {
    Resource,
    GlobalsFunction,
}

impl LocatedAlias {
    /// Falls back to the resource span when the property is present but the
    /// parser did not index a span for it (e.g. JSON parser emits fewer paths
    /// than the YAML parser).
    fn diagnostic_span(&self, function_name: &str, span_index: &SourceSpanIndex) -> SourceSpan {
        let resource_path = format!("Resources/{}", function_name);
        let property_path = match self.source {
            AliasSource::Resource => {
                format!("Resources/{}/{}/{}", function_name, KEY_PROPERTIES, SAM_AUTO_PUBLISH_ALIAS)
            }
            AliasSource::GlobalsFunction => format!("Globals/{}/{}", SAM_FUNCTION_GLOBALS_KEY, SAM_AUTO_PUBLISH_ALIAS),
        };
        span_index.get(&property_path).or_else(|| span_index.get(&resource_path)).copied().unwrap_or(UNKNOWN_SPAN)
    }
}

/// Prefers the resource-level property and falls back to `Globals.Function`,
/// matching SAM's own override precedence. An explicit null is treated as
/// absent.
fn located_auto_publish_alias(
    arena: &Arena,
    resources_node: NodeRef,
    globals_node: NodeRef,
    function_name: &str,
) -> Option<LocatedAlias> {
    let resource = arena.map_get(resources_node, function_name)?;
    if let Some(props) = arena.map_get(resource, KEY_PROPERTIES)
        && let Some(node) = present_alias(arena, props)
    {
        return Some(LocatedAlias { node, source: AliasSource::Resource });
    }
    let function_globals = arena.map_get(globals_node, SAM_FUNCTION_GLOBALS_KEY)?;
    let node = present_alias(arena, function_globals)?;
    Some(LocatedAlias { node, source: AliasSource::GlobalsFunction })
}

fn present_alias(arena: &Arena, container: NodeRef) -> Option<NodeRef> {
    let alias = arena.map_get(container, SAM_AUTO_PUBLISH_ALIAS)?;
    match arena.node(alias) {
        Node::Null => None,
        _ => Some(alias),
    }
}

fn sort_key(span_index: &SourceSpanIndex, name: &str) -> (u32, u32) {
    span_index
        .get(&format!("Resources/{}", name))
        .map(|span| (span.start_line, span.start_column))
        .unwrap_or((u32::MAX, u32::MAX))
}

fn make_transform_error(resource_id: &str, property_path: String, message: String, span: SourceSpan) -> Diagnostic {
    RegisteredDiagnostic::new(SAM_TRANSFORM_ERROR_RULE_ID, message)
        .resource(resource_id, None)
        .property_path(property_path)
        .location(span)
        .build()
}

#[cfg(test)]
mod tests {
    use crate::model::SemanticModel;
    use diagnostics::{Diagnostic, is_sam_transform_error_message};

    fn transform_errors(template: &str) -> Vec<String> {
        sam_transform_diagnostics(template).into_iter().map(|d| d.message).collect()
    }

    fn sam_transform_diagnostics(template: &str) -> Vec<Diagnostic> {
        let model = SemanticModel::from_bytes(template.as_bytes()).expect("template should parse");
        model.diagnostics.iter().filter(|d| is_sam_transform_error_message(&d.message)).cloned().collect()
    }

    #[test]
    fn literal_string_alias_is_accepted() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      AutoPublishAlias: live
"#;
        assert!(transform_errors(template).is_empty());
    }

    #[test]
    fn ref_to_parameter_alias_is_accepted() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Parameters:
  AliasName:
    Type: String
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      AutoPublishAlias: !Ref AliasName
"#;
        assert!(transform_errors(template).is_empty());
    }

    #[test]
    fn absent_alias_is_accepted() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
"#;
        assert!(transform_errors(template).is_empty());
    }

    #[test]
    fn sub_alias_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      AutoPublishAlias: !Sub '${AWS::StackName}-live'
"#;
        let errors = transform_errors(template);
        assert_eq!(errors.len(), 1);
        assert_eq!(
            errors[0],
            "Error transforming template: Resource with id [Fn] is invalid. \
             'AutoPublishAlias' must be a string or a Ref to a template parameter"
        );
    }

    #[test]
    fn ref_to_resource_alias_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Bucket:
    Type: AWS::S3::Bucket
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      AutoPublishAlias: !Ref Bucket
"#;
        assert_eq!(transform_errors(template).len(), 1);
    }

    #[test]
    fn multi_key_map_alias_emits_type_invalid_message() {
        // A multi-key map fails resource-property typing in samtranslator
        // before resolution, surfacing as the type-invalid message — distinct
        // from the unresolvable-intrinsic message.
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Parameters:
  Stage:
    Type: String
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      AutoPublishAlias:
        Ref: Stage
        Extra: Bad
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0],
            "Error transforming template: Resource with id [Fn] is invalid. \
             Type of property 'AutoPublishAlias' is invalid."
        );
    }

    #[test]
    fn globals_alias_applies_to_each_function() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Globals:
  Function:
    AutoPublishAlias: !Sub '${AWS::StackName}-live'
Resources:
  First:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
  Second:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
"#;
        assert_eq!(transform_errors(template).len(), 2);
    }

    #[test]
    fn resource_alias_overrides_invalid_global() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Globals:
  Function:
    AutoPublishAlias: !Sub '${AWS::StackName}-live'
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      AutoPublishAlias: live
"#;
        assert!(transform_errors(template).is_empty());
    }

    #[test]
    fn layer_version_with_content_uri_is_accepted() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Layer:
    Type: AWS::Serverless::LayerVersion
    Properties:
      ContentUri: s3://bucket/layer.zip
"#;
        assert!(transform_errors(template).is_empty());
    }

    #[test]
    fn layer_version_without_content_uri_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Layer:
    Type: AWS::Serverless::LayerVersion
    Properties:
      LayerName: my-layer
"#;
        let diagnostics = sam_transform_diagnostics(template);
        assert_eq!(diagnostics.len(), 1, "expected exactly one diagnostic");
        let diag = &diagnostics[0];
        assert_eq!(
            diag.message,
            "Error transforming template: Resource with id [Layer] is invalid. \
             Missing required property 'ContentUri'."
        );
        assert_eq!(diag.rule_id, "E0001");
        assert_eq!(diag.resource_logical_id(), Some("Layer"), "diagnostic must carry the offending resource id");
        assert_eq!(
            diag.property_path.as_deref(),
            Some("Properties/ContentUri"),
            "diagnostic must point at the missing property path"
        );
    }

    #[test]
    fn application_with_location_is_accepted() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  App:
    Type: AWS::Serverless::Application
    Properties:
      Location: https://serverlessrepo.example/template.yaml
"#;
        assert!(transform_errors(template).is_empty());
    }

    #[test]
    fn application_without_location_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  App:
    Type: AWS::Serverless::Application
    Properties:
      Parameters: {}
"#;
        let diagnostics = sam_transform_diagnostics(template);
        assert_eq!(diagnostics.len(), 1, "expected exactly one diagnostic");
        let diag = &diagnostics[0];
        assert_eq!(
            diag.message,
            "Error transforming template: Resource with id [App] is invalid. \
             Resource is missing the required [Location] property."
        );
        assert_eq!(diag.resource_logical_id(), Some("App"));
        assert_eq!(diag.property_path.as_deref(), Some("Properties/Location"));
    }

    #[test]
    fn schedule_event_with_schedule_property_is_accepted() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      Events:
        Hourly:
          Type: Schedule
          Properties:
            Schedule: rate(1 hour)
"#;
        assert!(transform_errors(template).is_empty());
    }

    #[test]
    fn schedule_event_without_schedule_property_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      Events:
        Hourly:
          Type: Schedule
          Properties:
            Description: missing schedule expression
"#;
        let diagnostics = sam_transform_diagnostics(template);
        assert_eq!(diagnostics.len(), 1, "expected exactly one diagnostic");
        let diag = &diagnostics[0];
        assert_eq!(
            diag.message,
            "Error transforming template: Resource with id [FnHourly] is invalid. \
             Missing required property 'Schedule'."
        );
        assert_eq!(
            diag.resource_logical_id(),
            Some("Fn"),
            "diagnostic must point at the parent function, not the synthetic event id"
        );
        assert_eq!(
            diag.property_path.as_deref(),
            Some("Properties/Events/Hourly"),
            "diagnostic must anchor at the offending event so users navigate \
             directly to it"
        );
    }

    #[test]
    fn schedule_event_with_no_properties_block_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      Events:
        Daily:
          Type: Schedule
"#;
        let diagnostics = sam_transform_diagnostics(template);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].message,
            "Error transforming template: Resource with id [FnDaily] is invalid. \
             Missing required property 'Schedule'."
        );
    }

    #[test]
    fn non_schedule_events_are_ignored_by_schedule_check() {
        // S3 and Api events do not require a 'Schedule' property — only the
        // schedule event check should fire when present, and it must not
        // false-positive on other event types.
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      Events:
        ApiCall:
          Type: Api
          Properties:
            Path: /
            Method: get
"#;
        assert!(transform_errors(template).is_empty());
    }

    #[test]
    fn multiple_distinct_transform_errors_all_reported() {
        // Verifies the coordinator runs every validator and reports all
        // findings independently (no early exit).
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Layer:
    Type: AWS::Serverless::LayerVersion
    Properties:
      LayerName: noop
  App:
    Type: AWS::Serverless::Application
    Properties: {}
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      AutoPublishAlias: !Sub '${AWS::StackName}-live'
      Events:
        Hourly:
          Type: Schedule
          Properties:
            Description: missing schedule
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 4, "got: {:#?}", messages);
        assert!(messages.iter().any(|m| m.contains("Missing required property 'ContentUri'")));
        assert!(messages.iter().any(|m| m.contains("Resource is missing the required [Location] property")));
        assert!(
            messages
                .iter()
                .any(|m| { m.contains("'AutoPublishAlias' must be a string or a Ref to a template parameter") })
        );
        assert!(messages.iter().any(|m| m.contains("[FnHourly] is invalid. Missing required property 'Schedule'")));
    }

    #[test]
    fn api_without_stage_name_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  MyApi:
    Type: AWS::Serverless::Api
    Properties:
      DefinitionUri: s3://b/swagger.yaml
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0],
            "Error transforming template: Resource with id [MyApi] is invalid. Missing required property 'StageName'."
        );
    }

    #[test]
    fn api_with_stage_name_is_accepted() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  MyApi:
    Type: AWS::Serverless::Api
    Properties:
      StageName: Prod
      DefinitionUri: s3://b/swagger.yaml
"#;
        assert!(transform_errors(template).is_empty());
    }

    #[test]
    fn state_machine_without_any_definition_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  SM:
    Type: AWS::Serverless::StateMachine
    Properties:
      Role: arn:aws:iam::123456789012:role/r
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("Either 'Definition' or 'DefinitionUri' property must be specified."));
    }

    #[test]
    fn state_machine_with_both_definitions_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  SM:
    Type: AWS::Serverless::StateMachine
    Properties:
      Definition:
        StartAt: Done
        States:
          Done:
            Type: Succeed
      DefinitionUri: s3://b/def.asl.json
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("Specify either 'Definition' or 'DefinitionUri' property and not both."));
    }

    #[test]
    fn state_machine_with_one_definition_is_accepted() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  SM:
    Type: AWS::Serverless::StateMachine
    Properties:
      DefinitionUri: s3://b/def.asl.json
"#;
        assert!(transform_errors(template).is_empty());
    }

    #[test]
    fn connector_reports_first_missing_required_property() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Conn:
    Type: AWS::Serverless::Connector
    Properties:
      Source:
        Id: Fn
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0],
            "Error transforming template: Resource with id [Conn] is invalid. Missing required property 'Destination'."
        );
    }

    #[test]
    fn graphql_api_without_auth_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Api:
    Type: AWS::Serverless::GraphQLApi
    Properties:
      SchemaUri: ./schema.graphql
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0],
            "Error transforming template: Resource with id [Api] is invalid. Missing required property 'Auth'."
        );
    }

    #[test]
    fn simple_table_primary_key_without_type_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  T:
    Type: AWS::Serverless::SimpleTable
    Properties:
      PrimaryKey:
        Name: id
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("Property 'PrimaryKey.Type' is required."));
    }

    #[test]
    fn simple_table_primary_key_with_invalid_type_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  T:
    Type: AWS::Serverless::SimpleTable
    Properties:
      PrimaryKey:
        Name: id
        Type: Banana
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains(r#"Invalid 'Type' "Banana"."#));
    }

    #[test]
    fn simple_table_valid_primary_key_is_accepted() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  T:
    Type: AWS::Serverless::SimpleTable
    Properties:
      PrimaryKey:
        Name: id
        Type: String
"#;
        assert!(transform_errors(template).is_empty());
    }

    #[test]
    fn simple_table_without_primary_key_is_accepted() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  T:
    Type: AWS::Serverless::SimpleTable
    Properties:
      TableName: t
"#;
        assert!(transform_errors(template).is_empty());
    }

    #[test]
    fn function_invalid_package_type_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      PackageType: Banana
      CodeUri: s3://b/k.zip
      Handler: index.handler
      Runtime: python3.12
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("invalid 'PackageType' : Banana"));
    }

    #[test]
    fn function_zip_missing_runtime_handler_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: s3://b/k.zip
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("Runtime and Handler needs to be present when PackageType is of type `Zip`"));
    }

    #[test]
    fn function_zip_runtime_handler_from_globals_is_accepted() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Globals:
  Function:
    Runtime: python3.12
    Handler: index.handler
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: s3://b/k.zip
"#;
        assert!(transform_errors(template).is_empty());
    }

    #[test]
    fn function_image_with_handler_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      PackageType: Image
      ImageUri: 123456789012.dkr.ecr.us-east-1.amazonaws.com/r:l
      Handler: index.handler
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("Runtime, Handler, Layers cannot be present when PackageType is of type `Image`"));
    }

    #[test]
    fn function_dlq_missing_target_arn_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      DeadLetterQueue:
        Type: SQS
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("'DeadLetterQueue' requires Type and TargetArn properties to be specified."));
    }

    #[test]
    fn function_dlq_invalid_type_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      DeadLetterQueue:
        Type: Kinesis
        TargetArn: arn:aws:kinesis:us-east-1:123456789012:stream/s
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("'DeadLetterQueue' requires Type of ['SQS', 'SNS']"));
    }

    #[test]
    fn function_provisioned_concurrency_without_alias_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      ProvisionedConcurrencyConfig:
        ProvisionedConcurrentExecutions: 5
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert!(
            messages[0]
                .contains("To set ProvisionedConcurrencyConfig AutoPublishALias must be defined on the function")
        );
    }

    #[test]
    fn function_version_deletion_policy_without_alias_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      VersionDeletionPolicy: Retain
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("'VersionDeletionPolicy' requires 'AutoPublishAlias'."));
    }

    #[test]
    fn function_capacity_provider_with_vpc_config_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      CapacityProviderConfig: {}
      VpcConfig:
        SubnetIds:
          - subnet-1
        SecurityGroupIds:
          - sg-1
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("Cannot specify 'CapacityProviderConfig' and 'VpcConfig' together."));
    }

    #[test]
    fn valid_function_has_no_transform_error() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
"#;
        assert!(transform_errors(template).is_empty());
    }

    #[test]
    fn globals_unknown_property_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Globals:
  Function:
    NotARealProperty: foo
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("'Globals' section is invalid."));
        assert!(messages[0].contains("'NotARealProperty' is not a supported property of 'Function'."));
    }

    #[test]
    fn globals_unknown_section_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Globals:
  Foo:
    Bar: baz
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("'Foo' is not supported. Must be one of the following values -"));
    }

    #[test]
    fn globals_section_not_dict_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Globals:
  Function: notadict
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("Value of ${section} must be a dictionary"));
    }

    #[test]
    fn globals_not_dict_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Globals: notadict
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("It must be a non-empty dictionary"));
    }

    #[test]
    fn globals_empty_is_accepted() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Globals: {}
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
"#;
        assert!(transform_errors(template).is_empty());
    }

    #[test]
    fn globals_valid_sections_are_accepted() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Globals:
  Function:
    Timeout: 30
  Api:
    Cors: "'*'"
  HttpApi:
    FailOnWarnings: true
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
"#;
        assert!(transform_errors(template).is_empty());
    }

    #[test]
    fn globals_error_preempts_resource_errors() {
        // A Globals violation aborts the transform before resources are
        // validated, so only the single Globals error is reported.
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Globals:
  Function:
    NotARealProperty: foo
Resources:
  MyApi:
    Type: AWS::Serverless::Api
    Properties:
      DefinitionUri: s3://b/x.yaml
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("'Globals' section is invalid."));
    }

    #[test]
    fn wrong_transform_date_does_not_emit_transform_error() {
        // A non-SAM transform id must not trigger the transform-error
        // validators — those only apply under the exact SAM transform.
        let template = r#"
Transform: AWS::Serverless-2016-10-30
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      AutoPublishAlias: !Sub '${AWS::StackName}-live'
"#;
        assert!(transform_errors(template).is_empty());
    }

    #[test]
    fn function_url_config_without_auth_type_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      FunctionUrlConfig:
        Cors: {}
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("AuthType is required to configure function property `FunctionUrlConfig`"));
    }

    #[test]
    fn function_url_config_invalid_auth_type_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      FunctionUrlConfig:
        AuthType: BANANA
"#;
        assert_eq!(transform_errors(template).len(), 1);
    }

    #[test]
    fn function_url_config_valid_auth_type_is_accepted() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      FunctionUrlConfig:
        AuthType: NONE
"#;
        assert!(transform_errors(template).is_empty());
    }

    #[test]
    fn function_deployment_preference_without_alias_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      DeploymentPreference:
        Type: AllAtOnce
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("'DeploymentPreference' requires AutoPublishAlias property to be specified."));
    }

    #[test]
    fn function_zip_with_image_config_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      ImageConfig:
        Command:
          - app.handler
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("ImageUri or ImageConfig cannot be present when PackageType is of type `Zip`"));
    }

    #[test]
    fn function_purely_numeric_alias_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      AutoPublishAlias: "123"
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("AutoPublishAlias name ('123') must contain only alphanumeric characters"));
    }

    #[test]
    fn function_alias_with_hyphen_is_accepted() {
        // Hyphens and underscores are valid alias characters.
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      CodeUri: s3://b/k.zip
      AutoPublishAlias: my-alias_1
"#;
        assert!(transform_errors(template).is_empty());
    }

    #[test]
    fn layer_version_invalid_retention_policy_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Layer:
    Type: AWS::Serverless::LayerVersion
    Properties:
      ContentUri: s3://b/layer.zip
      RetentionPolicy: Banana
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("'RetentionPolicy' must be one of the following options: ['Retain', 'Delete']."));
    }

    #[test]
    fn layer_version_invalid_architecture_is_rejected() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Layer:
    Type: AWS::Serverless::LayerVersion
    Properties:
      ContentUri: s3://b/layer.zip
      CompatibleArchitectures:
        - sparc
"#;
        let messages = transform_errors(template);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("CompatibleArchitectures needs to be a list of 'x86_64' or 'arm64'"));
    }

    #[test]
    fn layer_version_valid_retention_and_architecture_is_accepted() {
        let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Layer:
    Type: AWS::Serverless::LayerVersion
    Properties:
      ContentUri: s3://b/layer.zip
      RetentionPolicy: Delete
      CompatibleArchitectures:
        - arm64
"#;
        assert!(transform_errors(template).is_empty());
    }
}
