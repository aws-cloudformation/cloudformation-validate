use crate::consts::*;
use crate::ir::*;
use crate::model::ResolvedResource;
use crate::resolver::ResolvedValue;
use std::collections::{HashMap, HashSet};

const TRANSFORM_ERROR_RULE_ID: &str = "F0001";

pub fn extract_sam_globals(
    arena: &Arena,
    globals_ref: NodeRef,
) -> HashMap<String, HashMap<String, serde_json::Value>> {
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
        let full_type = SAM_GLOBALS_TYPE_MAP
            .iter()
            .find(|(s, _)| *s == short_name)
            .map(|(_, t)| *t);
        let Some(full_type) = full_type else { continue };
        for res in resources.values_mut() {
            if res.resource_type != full_type {
                continue;
            }
            for (prop, val) in defaults {
                if !res.properties.contains_key(prop) {
                    res.properties.insert(
                        prop.clone(),
                        ResolvedValue::Concrete {
                            value: val.clone().into(),
                        },
                    );
                }
            }
        }
    }
}

pub fn collect_sam_implicit_resources(
    resources: &HashMap<String, ResolvedResource>,
) -> HashSet<String> {
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
                    ev.as_object()
                        .and_then(|o| o.get(KEY_TYPE))
                        .and_then(|t| t.as_str())
                        == Some(SAM_EVENT_TYPE_API)
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

pub fn cycle_involves_sam_diagnostic(
    diagnostic: &diagnostics::Diagnostic,
    resources: &HashMap<String, ResolvedResource>,
) -> bool {
    resources.iter().any(|(name, res)| {
        res.resource_type.starts_with(SAM_SERVERLESS_TYPE_PREFIX)
            && diagnostic.message.contains(name.as_str())
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


/// Collects SAM transform errors that require the raw template structure and
/// parameter set to evaluate. A transform error means CloudFormation rejects the
/// template before resource validation, so the engine gates downstream
/// diagnostics on these.
///
/// `AutoPublishAlias` must resolve to a string: either a literal or a `Ref` to a
/// template parameter. Any other intrinsic stays an unresolved object and is
/// rejected by the transform.
pub fn collect_transform_errors(
    arena: &Arena,
    resources_node: NodeRef,
    globals_node: NodeRef,
    resources: &HashMap<String, ResolvedResource>,
    parameter_names: &HashSet<String>,
    span_index: &SourceSpanIndex,
) -> Vec<diagnostics::Diagnostic> {
    let mut function_names: Vec<&str> = resources
        .iter()
        .filter(|(_, res)| res.resource_type == SAM_FUNCTION_TYPE)
        .map(|(name, _)| name.as_str())
        .collect();
    function_names.sort_by_key(|name| resource_span(span_index, name));

    let mut errors = Vec::new();
    for name in function_names {
        let Some(alias_node) = auto_publish_alias_node(arena, resources_node, globals_node, name)
        else {
            continue;
        };
        if is_string_or_parameter_ref(arena, alias_node, parameter_names) {
            continue;
        }
        let span = span_index
            .get(&format!("Resources/{}", name))
            .copied()
            .unwrap_or(UNKNOWN_SPAN);
        errors.push(transform_error(
            format!(
                "{} Resource with id [{}] is invalid. '{}' must be a string or a Ref to a template parameter",
                diagnostics::SAM_TRANSFORM_ERROR_PREFIX, name, SAM_AUTO_PUBLISH_ALIAS
            ),
            span,
        ));
    }
    errors
}

/// Resolves the `AutoPublishAlias` value node for a function, preferring the
/// resource-level property and falling back to the SAM `Globals` default. An
/// explicit null is treated as absent.
fn auto_publish_alias_node(
    arena: &Arena,
    resources_node: NodeRef,
    globals_node: NodeRef,
    function_name: &str,
) -> Option<NodeRef> {
    let resource = arena.map_get(resources_node, function_name)?;
    if let Some(props) = arena.map_get(resource, KEY_PROPERTIES)
        && let Some(alias) = present_alias(arena, props)
    {
        return Some(alias);
    }
    let function_globals = arena.map_get(globals_node, sam_function_globals_key()?)?;
    present_alias(arena, function_globals)
}

fn present_alias(arena: &Arena, container: NodeRef) -> Option<NodeRef> {
    let alias = arena.map_get(container, SAM_AUTO_PUBLISH_ALIAS)?;
    match arena.node(alias) {
        Node::Null => None,
        _ => Some(alias),
    }
}

fn is_string_or_parameter_ref(
    arena: &Arena,
    node: NodeRef,
    parameter_names: &HashSet<String>,
) -> bool {
    match arena.node(node) {
        Node::String(_) => true,
        Node::Intrinsic(IntrinsicFn::Ref(target)) => parameter_names.contains(target),
        _ => false,
    }
}

fn sam_function_globals_key() -> Option<&'static str> {
    SAM_GLOBALS_TYPE_MAP
        .iter()
        .find(|(_, full_type)| *full_type == SAM_FUNCTION_TYPE)
        .map(|(short_name, _)| *short_name)
}

fn resource_span(span_index: &SourceSpanIndex, name: &str) -> (u32, u32) {
    span_index
        .get(&format!("Resources/{}", name))
        .map(|span| (span.start_line, span.start_column))
        .unwrap_or((u32::MAX, u32::MAX))
}

fn transform_error(message: String, span: SourceSpan) -> diagnostics::Diagnostic {
    let definition = rules_crate::lookup_rule(TRANSFORM_ERROR_RULE_ID)
        .unwrap_or_else(|| panic!("rule '{}' is not registered", TRANSFORM_ERROR_RULE_ID));
    diagnostics::Diagnostic {
        rule_id: TRANSFORM_ERROR_RULE_ID.into(),
        severity: definition.severity(),
        message,
        resource: None,
        property_path: None,
        suggested_fix: None,
        documentation_url: None,
        category: Some(definition.category.as_str().into()),
        location: if span == UNKNOWN_SPAN {
            None
        } else {
            Some(span)
        },
        related_resources: None,
        condition_scenario: None,
        rule_description: None,
        phase: None,
        section: None,
        source: definition.origin,
        context: None,
    }
}


#[cfg(test)]
mod tests {
    use crate::model::SemanticModel;

    fn transform_errors(template: &str) -> Vec<String> {
        let model = SemanticModel::from_bytes(template.as_bytes()).expect("template should parse");
        model
            .diagnostics
            .iter()
            .filter(|d| diagnostics::is_sam_transform_error_message(&d.message))
            .map(|d| d.message.clone())
            .collect()
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
}
