//! Validation of each named condition's body.
//!
//! A condition must evaluate to a boolean, which CloudFormation expresses as one
//! of the condition functions (`Fn::And`, `Fn::Equals`, `Fn::Not`, `Fn::Or`) or a
//! reference to another condition. Anything else - a bare string, a map of
//! several functions, an unknown function name - cannot be evaluated, so every
//! resource gated on that condition fails to deploy. The condition model drops
//! such a body, so reporting it here is what keeps the failure visible.

use crate::consts::*;
use crate::ir::*;
use crate::message::quote;
use crate::parser::builder::node_shape_name;

/// Rule reporting a condition whose body is not a boolean-valued condition.
const CONDITION_BODY_RULE: &str = "F0013";

pub(super) fn validate_condition_bodies(
    arena: &Arena,
    conditions: NodeRef,
    span_index: &SourceSpanIndex,
) -> Vec<ParseDefect> {
    let mut out = Vec::new();
    let Some(entries) = arena.as_map(conditions) else {
        return out;
    };
    for (name, body_ref) in entries {
        if !is_condition_name(name) {
            continue;
        }
        if let Some(reason) = body_defect_reason(arena, *body_ref) {
            let path = format!("{}/{}", SECTION_CONDITIONS, name);
            let span = span_index.get(&path).copied().unwrap_or(UNKNOWN_SPAN);
            out.push(
                ParseDefect::new(CONDITION_BODY_RULE, format!("Condition {} {}", quote(name), reason))
                    .location(span)
                    .property_path(path)
                    .phase(crate::DefectPhase::Parse),
            );
        }
    }
    out
}

/// Whether the key names a condition. The `Conditions` section can also carry an
/// `Fn::ForEach::…` loop key, which expands into conditions rather than being
/// one, so only keys shaped like a condition name are checked.
fn is_condition_name(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= MAX_CONDITION_NAME_LENGTH
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '&' || c == '_')
}

/// Whether a body that names this function is already covered by that function's
/// own argument validation.
fn is_separately_validated(function_key: &str) -> bool {
    function_key == FN_IF || CONDITION_FUNCTIONS.contains(&function_key)
}

/// Why the body cannot evaluate to a boolean, or `None` when it can.
fn body_defect_reason(arena: &Arena, body_ref: NodeRef) -> Option<String> {
    match arena.node(body_ref) {
        Node::Intrinsic(IntrinsicFn::And(_))
        | Node::Intrinsic(IntrinsicFn::Or(_))
        | Node::Intrinsic(IntrinsicFn::Not(_))
        | Node::Intrinsic(IntrinsicFn::Equals(_, _))
        | Node::Bool(_) => None,
        // A body that only names another condition parses into a reference
        // carrying the condition-name prefix.
        Node::Intrinsic(IntrinsicFn::Ref(target)) if target.starts_with(CONDITION_REF_PREFIX) => None,
        Node::Map(entries) if entries.len() == 1 && entries[0].0 == FN_CONDITION => None,
        // A function whose arguments are malformed does not parse into an
        // intrinsic and stays a plain map. The body names a function the parser
        // validates in its own right - including `Fn::If`, which is not a
        // condition function but does carry its own structural check - so the
        // argument defect is already reported; saying "not a condition" on top of
        // that would double-report one mistake.
        Node::Map(entries) if entries.len() == 1 && is_separately_validated(&entries[0].0) => None,
        Node::Map(entries) if entries.len() > 1 => Some(format!(
            "must be a single condition function, but declares {}: {}",
            entries.len(),
            crate::message::render_str_list(entries.iter().map(|(key, _)| key))
        )),
        Node::Map(entries) => Some(format!(
            "must be one of {}, got {}",
            crate::message::render_str_list(CONDITION_FUNCTIONS),
            quote(&entries[0].0)
        )),
        node => Some(format!(
            "must be one of {}, got {}",
            crate::message::render_str_list(CONDITION_FUNCTIONS),
            node_shape_name(node)
        )),
    }
}

#[cfg(test)]
mod tests {
    use crate::SemanticModel;

    fn messages(template: &str) -> Vec<String> {
        let model = SemanticModel::from_bytes(template.as_bytes()).expect("template parses");
        model
            .diagnostics
            .iter()
            .filter(|d| d.rule_id == super::CONDITION_BODY_RULE)
            .map(|d| format!("{}|{}", d.property_path.clone().unwrap_or_default(), d.message))
            .collect()
    }

    const RESOURCES: &str = "Resources:\n  R:\n    Type: AWS::SNS::Topic\n";

    #[test]
    fn condition_functions_are_accepted() {
        let template = format!(
            "Parameters:\n  P:\n    Type: String\nConditions:\n  IsProd: !Equals [!Ref P, prod]\n  NotProd: !Not [!Condition IsProd]\n  Either: !Or [!Condition IsProd, !Condition NotProd]\n  Both: !And [!Condition IsProd, !Condition Either]\n  Alias:\n    Condition: IsProd\n{RESOURCES}"
        );
        assert!(messages(&template).is_empty(), "every condition function form must be accepted");
    }

    #[test]
    fn a_scalar_body_is_reported() {
        let template = format!("Conditions:\n  Bad: String\n{RESOURCES}");
        assert_eq!(
            messages(&template),
            [
                "Conditions/Bad|Condition 'Bad' must be one of ['Fn::And', 'Fn::Equals', 'Fn::Not', 'Fn::Or'], got a string"
            ]
        );
    }

    #[test]
    fn a_null_body_is_reported() {
        let template = format!("Conditions:\n  Bad: null\n{RESOURCES}");
        assert_eq!(
            messages(&template),
            ["Conditions/Bad|Condition 'Bad' must be one of ['Fn::And', 'Fn::Equals', 'Fn::Not', 'Fn::Or'], got null"]
        );
    }

    #[test]
    fn several_functions_in_one_body_are_reported() {
        let template = format!(
            "Parameters:\n  P:\n    Type: String\nConditions:\n  Bad:\n    Fn::Equals: [!Ref P, prod]\n    Fn::Not: [!Equals [!Ref P, dev]]\n{RESOURCES}"
        );
        assert_eq!(
            messages(&template),
            [
                "Conditions/Bad|Condition 'Bad' must be a single condition function, but declares 2: ['Fn::Equals', 'Fn::Not']"
            ]
        );
    }

    #[test]
    fn an_unknown_function_body_is_reported() {
        let template = format!("Conditions:\n  Bad:\n    Fn::Of:\n    - true\n{RESOURCES}");
        assert_eq!(
            messages(&template),
            [
                "Conditions/Bad|Condition 'Bad' must be one of ['Fn::And', 'Fn::Equals', 'Fn::Not', 'Fn::Or'], got 'Fn::Of'"
            ]
        );
    }

    #[test]
    fn a_value_function_body_is_reported() {
        let template = format!("Conditions:\n  Bad: !Ref P\n{RESOURCES}");
        let found = messages(&template);
        assert_eq!(found.len(), 1, "a value function cannot evaluate to a boolean, got {found:?}");
        assert!(found[0].contains("got an intrinsic function"), "unexpected message: {found:?}");
    }
}
