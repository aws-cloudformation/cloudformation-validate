//! Validation of a resource's declared attributes — the keys CloudFormation
//! accepts alongside `Type`, and the shape each one's value must take.
//!
//! These are contract violations CloudFormation itself rejects, so they are
//! reported at parse time rather than by the rule engines: the malformed
//! attribute is visible in the raw template and never survives into the
//! resolved model (an unknown attribute is dropped, a non-string `Type`
//! collapses to an empty type), which would otherwise hide the defect.

use crate::consts::*;
use crate::ir::*;
use crate::message::quote;
use crate::parser::builder::node_shape_name;

/// Rule reporting a resource whose declared attributes violate the shape
/// CloudFormation requires.
const RESOURCE_CONFIGURATION_RULE: &str = "E3001";

/// Validates every resource in the `Resources` section against the attribute
/// contract: `Type` is required and must be a literal string, only recognized
/// attributes may appear, and each attribute's value must have the shape
/// CloudFormation accepts.
///
/// Only logical IDs CloudFormation accepts (alphanumeric) are validated. A
/// malformed logical ID is reported by its own check, and the `Resources` map
/// also carries `Fn::ForEach::…` loop keys before expansion, which are not
/// resources at all.
pub(crate) fn validate_resource_attributes(
    arena: &Arena,
    resources: NodeRef,
    span_index: &SourceSpanIndex,
) -> Vec<ParseDefect> {
    let mut out = Vec::new();
    let Some(entries) = arena.as_map(resources) else {
        return out;
    };
    for (logical_id, resource_ref) in entries {
        if !logical_id.chars().all(|c| c.is_ascii_alphanumeric()) || logical_id.is_empty() {
            continue;
        }
        validate_resource(arena, logical_id, *resource_ref, span_index, &mut out);
    }
    out
}

fn validate_resource(
    arena: &Arena,
    logical_id: &str,
    resource_ref: NodeRef,
    span_index: &SourceSpanIndex,
    out: &mut Vec<ParseDefect>,
) {
    let Some(attributes) = arena.as_map(resource_ref) else {
        out.push(defect(
            format!("Resource must be an object, got {}", node_shape_name(arena.node(resource_ref))),
            logical_id,
            "",
            arena,
            resource_ref,
            span_index,
        ));
        return;
    };

    for (name, _) in attributes {
        if !RESOURCE_ATTRIBUTES.contains(&name.as_str()) && name != FN_TRANSFORM {
            let value_ref = arena.map_get(resource_ref, name).unwrap_or(resource_ref);
            out.push(defect(
                format!("{} is not a valid resource attribute", quote(name)),
                logical_id,
                name,
                arena,
                value_ref,
                span_index,
            ));
        }
    }

    let attribute = |key: &str| attributes.iter().find(|(k, _)| k == key).map(|(_, v)| *v);

    let declared_type = attribute(KEY_TYPE);
    match declared_type {
        None => out.push(defect(
            format!("Resource is missing the required {} attribute", quote(KEY_TYPE)),
            logical_id,
            "",
            arena,
            resource_ref,
            span_index,
        )),
        Some(type_ref) if !matches!(arena.node(type_ref), Node::String(_)) => out.push(defect(
            format!("{} must be a string, got {}", quote(KEY_TYPE), node_shape_name(arena.node(type_ref))),
            logical_id,
            KEY_TYPE,
            arena,
            type_ref,
            span_index,
        )),
        Some(_) => {}
    }

    if let Some(condition_ref) = attribute(KEY_CONDITION)
        && !matches!(arena.node(condition_ref), Node::String(_))
    {
        out.push(defect(
            format!(
                "{} must be the name of a condition, got {}",
                quote(KEY_CONDITION),
                node_shape_name(arena.node(condition_ref))
            ),
            logical_id,
            KEY_CONDITION,
            arena,
            condition_ref,
            span_index,
        ));
    }

    if let Some(depends_on_ref) = attribute(KEY_DEPENDS_ON) {
        validate_depends_on(arena, logical_id, depends_on_ref, span_index, out);
    }

    let is_custom = declared_type.and_then(|r| arena.as_str(r)).is_some_and(is_custom_resource_type);
    validate_provider_attributes(arena, logical_id, attributes, is_custom, span_index, out);
}

/// `DependsOn` names one resource or a list of resources; each entry must be a
/// literal logical ID, since CloudFormation builds the dependency graph before
/// any intrinsic function is resolved.
fn validate_depends_on(
    arena: &Arena,
    logical_id: &str,
    depends_on_ref: NodeRef,
    span_index: &SourceSpanIndex,
    out: &mut Vec<ParseDefect>,
) {
    match arena.node(depends_on_ref) {
        Node::String(_) => {}
        Node::List(items) => {
            for (index, item_ref) in items.iter().enumerate() {
                if !matches!(arena.node(*item_ref), Node::String(_)) {
                    out.push(defect(
                        format!(
                            "{} entry must be a resource logical ID, got {}",
                            quote(KEY_DEPENDS_ON),
                            node_shape_name(arena.node(*item_ref))
                        ),
                        logical_id,
                        &format!("{}.{}", KEY_DEPENDS_ON, index),
                        arena,
                        *item_ref,
                        span_index,
                    ));
                }
            }
        }
        node => out.push(defect(
            format!(
                "{} must be a resource logical ID or a list of logical IDs, got {}",
                quote(KEY_DEPENDS_ON),
                node_shape_name(node)
            ),
            logical_id,
            KEY_DEPENDS_ON,
            arena,
            depends_on_ref,
            span_index,
        )),
    }
}

/// `Version` identifies a custom resource provider's version and is accepted
/// only there; conversely `CreationPolicy` and `UpdatePolicy` steer lifecycle
/// behavior CloudFormation manages itself, which it cannot do for a resource
/// backed by a provider.
fn validate_provider_attributes(
    arena: &Arena,
    logical_id: &str,
    attributes: &[(String, NodeRef)],
    is_custom: bool,
    span_index: &SourceSpanIndex,
    out: &mut Vec<ParseDefect>,
) {
    let attribute = |key: &str| attributes.iter().find(|(k, _)| k == key).map(|(_, v)| *v);

    if let Some(version_ref) = attribute(KEY_VERSION) {
        if !is_custom {
            out.push(defect(
                format!("{} is only supported on a custom resource", quote(KEY_VERSION)),
                logical_id,
                KEY_VERSION,
                arena,
                version_ref,
                span_index,
            ));
        } else if !matches!(arena.node(version_ref), Node::String(_) | Node::Int(_)) {
            out.push(defect(
                format!(
                    "{} must be a string or an integer, got {}",
                    quote(KEY_VERSION),
                    node_shape_name(arena.node(version_ref))
                ),
                logical_id,
                KEY_VERSION,
                arena,
                version_ref,
                span_index,
            ));
        }
    }

    for policy in [KEY_CREATION_POLICY, KEY_UPDATE_POLICY] {
        let Some(policy_ref) = attribute(policy) else {
            continue;
        };
        if is_custom {
            out.push(defect(
                format!("{} is not supported on a custom resource", quote(policy)),
                logical_id,
                policy,
                arena,
                policy_ref,
                span_index,
            ));
        } else if !matches!(arena.node(policy_ref), Node::Map(_) | Node::Intrinsic(_)) {
            // An intrinsic stands in for an object that is only known at deploy
            // time, so its shape cannot be judged here.
            out.push(defect(
                format!("{} must be an object, got {}", quote(policy), node_shape_name(arena.node(policy_ref))),
                logical_id,
                policy,
                arena,
                policy_ref,
                span_index,
            ));
        }
    }
}

/// Builds a defect anchored at the offending node, falling back to the node's
/// recorded build path in the span index when the node itself carries no span.
fn defect(
    message: String,
    logical_id: &str,
    attribute_path: &str,
    arena: &Arena,
    node_ref: NodeRef,
    span_index: &SourceSpanIndex,
) -> ParseDefect {
    let mut span = arena.span(node_ref);
    if span == UNKNOWN_SPAN {
        span = span_index.get(&arena.get(node_ref).path).copied().unwrap_or(UNKNOWN_SPAN);
    }
    ParseDefect::new(RESOURCE_CONFIGURATION_RULE, message)
        .location(span)
        .resource(logical_id)
        .property_path(attribute_path)
        .phase(crate::DefectPhase::Parse)
}

#[cfg(test)]
mod tests {
    use crate::SemanticModel;

    fn messages(template: &str) -> Vec<String> {
        let model = SemanticModel::from_bytes(template.as_bytes()).expect("template parses");
        model
            .diagnostics
            .iter()
            .filter(|d| d.rule_id == super::RESOURCE_CONFIGURATION_RULE)
            .map(|d| {
                format!(
                    "{}|{}|{}",
                    d.resource_id.clone().unwrap_or_default(),
                    d.property_path.clone().unwrap_or_default(),
                    d.message
                )
            })
            .collect()
    }

    #[test]
    fn unknown_attribute_is_reported() {
        let found = messages("Resources:\n  R:\n    Type: AWS::S3::Bucket\n    BadAttribute: x\n");
        assert_eq!(found, ["R|BadAttribute|'BadAttribute' is not a valid resource attribute"]);
    }

    #[test]
    fn missing_type_is_reported() {
        let found = messages("Resources:\n  R:\n    Properties:\n      BucketName: b\n");
        assert_eq!(found, ["R||Resource is missing the required 'Type' attribute"]);
    }

    #[test]
    fn non_string_type_is_reported() {
        let found = messages("Resources:\n  R:\n    Type: !Ref AWS::Region\n");
        assert_eq!(found, ["R|Type|'Type' must be a string, got an intrinsic function"]);
    }

    #[test]
    fn non_string_condition_is_reported() {
        let found = messages("Resources:\n  R:\n    Type: AWS::S3::Bucket\n    Condition: false\n");
        assert_eq!(found, ["R|Condition|'Condition' must be the name of a condition, got a boolean"]);
    }

    #[test]
    fn non_object_resource_is_reported() {
        let found = messages("Resources:\n  R: hello\n");
        assert_eq!(found, ["R||Resource must be an object, got a string"]);
    }

    #[test]
    fn depends_on_accepts_a_name_or_a_list_of_names() {
        let template = "Resources:\n  A:\n    Type: AWS::S3::Bucket\n  B:\n    Type: AWS::S3::Bucket\n    DependsOn: A\n  C:\n    Type: AWS::S3::Bucket\n    DependsOn:\n    - A\n    - B\n";
        assert!(messages(template).is_empty(), "literal logical IDs must be accepted");
    }

    #[test]
    fn depends_on_rejects_non_literal_entries() {
        let found = messages(
            "Resources:\n  A:\n    Type: AWS::S3::Bucket\n  B:\n    Type: AWS::S3::Bucket\n    DependsOn:\n    - !Ref A\n",
        );
        assert_eq!(found, ["B|DependsOn.0|'DependsOn' entry must be a resource logical ID, got an intrinsic function"]);
    }

    #[test]
    fn version_is_rejected_outside_custom_resources() {
        let found = messages("Resources:\n  R:\n    Type: AWS::S3::Bucket\n    Version: '1.0'\n");
        assert_eq!(found, ["R|Version|'Version' is only supported on a custom resource"]);
    }

    #[test]
    fn version_is_accepted_on_custom_resources() {
        let template = "Resources:\n  R:\n    Type: Custom::Thing\n    Version: '1.0'\n    Properties:\n      ServiceToken: token\n";
        assert!(messages(template).is_empty(), "a custom resource may declare a provider Version");
    }

    #[test]
    fn lifecycle_policies_are_rejected_on_custom_resources() {
        let found = messages(
            "Resources:\n  R:\n    Type: AWS::CloudFormation::CustomResource\n    CreationPolicy:\n      ResourceSignal:\n        Count: 1\n    Properties:\n      ServiceToken: token\n",
        );
        assert_eq!(found, ["R|CreationPolicy|'CreationPolicy' is not supported on a custom resource"]);
    }

    #[test]
    fn lifecycle_policy_must_be_an_object() {
        let found = messages("Resources:\n  R:\n    Type: AWS::S3::Bucket\n    CreationPolicy: nope\n");
        assert_eq!(found, ["R|CreationPolicy|'CreationPolicy' must be an object, got a string"]);
    }

    #[test]
    fn lifecycle_policy_accepts_a_conditional_object() {
        let template = "Conditions:\n  C: !Equals ['a', 'a']\nResources:\n  R:\n    Type: AWS::AutoScaling::AutoScalingGroup\n    UpdatePolicy: !If [C, {AutoScalingScheduledAction: {IgnoreUnmodifiedGroupSizeProperties: true}}, !Ref 'AWS::NoValue']\n";
        assert!(messages(template).is_empty(), "a conditional policy object is resolved at deploy time");
    }

    #[test]
    fn transform_macro_key_is_accepted() {
        let template = "Resources:\n  R:\n    Type: AWS::S3::Bucket\n    Fn::Transform:\n      Name: AWS::Include\n      Parameters:\n        Location: s3://b/k\n";
        assert!(messages(template).is_empty(), "a resource-level macro is not an attribute violation");
    }

    #[test]
    fn malformed_logical_ids_are_left_to_their_own_check() {
        let template = "Resources:\n  My-Bucket:\n    Type: AWS::S3::Bucket\n    BadAttribute: x\n";
        assert!(messages(template).is_empty(), "an unusable logical ID is reported once, by the logical ID check");
    }
}
