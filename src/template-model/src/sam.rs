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

pub fn collect_sam_implicit_resources(resources: &HashMap<String, ResolvedResource>) -> HashSet<String> {
    let mut implicit = HashSet::new();
    let mut has_api_event = false;
    for (name, res) in resources {
        if res.resource_type == SAM_FUNCTION_TYPE {
            implicit.insert(format!("{}Role", name));
            if let Some(events) = res.properties.get("Events") {
                has_api_event = has_api_event || events_contain_api(events);
            }
        }
    }
    if has_api_event {
        implicit.insert(SAM_IMPLICIT_REST_API.to_string());
    }
    implicit
}

fn events_contain_api(events: &ResolvedValue) -> bool {
    match events {
        ResolvedValue::Map { entries } => entries.iter().any(|e| is_api_event(&e.value)),
        ResolvedValue::Concrete { value: v } => {
            if let Some(obj) = v.as_object() {
                obj.values().any(|ev| {
                    ev.as_object().and_then(|o| o.get(KEY_TYPE)).and_then(|t| t.as_str()) == Some(SAM_EVENT_TYPE_API)
                })
            } else {
                false
            }
        }
        _ => false,
    }
}

fn is_api_event(ev: &ResolvedValue) -> bool {
    match ev {
        ResolvedValue::Map { entries } => entries.iter().any(|e| {
            e.key == KEY_TYPE
                && matches!(&e.value, ResolvedValue::Concrete { value: v } if v.as_str() == Some(SAM_EVENT_TYPE_API))
        }),
        ResolvedValue::Concrete { value: v } => {
            if let Some(obj) = v.as_object() {
                obj.get(KEY_TYPE).and_then(|t| t.as_str()) == Some(SAM_EVENT_TYPE_API)
            } else {
                false
            }
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
    auto_publish_alias_must_be_string_or_parameter_ref(&context, &mut errors);
    layer_version_must_have_content_uri(&context, &mut errors);
    application_must_have_location(&context, &mut errors);
    schedule_event_must_have_schedule(&context, &mut errors);
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

fn sam_property_path(prefix: &str, property: &str) -> String {
    format!("{}/{}", prefix, property)
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
        assert_eq!(
            diag.resource.as_ref().and_then(|r| r.id.as_deref()),
            Some("Layer"),
            "diagnostic must carry the offending resource id"
        );
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
        assert_eq!(diag.resource.as_ref().and_then(|r| r.id.as_deref()), Some("App"));
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
            diag.resource.as_ref().and_then(|r| r.id.as_deref()),
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
}
