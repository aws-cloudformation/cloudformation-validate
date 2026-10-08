//! Presence analysis for the members of a resolved list or map.
//!
//! A member gated by `Fn::If` over `AWS::NoValue` is present in exactly the
//! deployments where its condition literals hold. Knowing each member's
//! presence literals lets a consumer reason about cardinality and co-presence
//! without enumerating the 2^N joint assignments of N independent conditions.

use std::collections::HashMap;

use crate::resolved_value::{contains_dynamic_resolved, is_resolved_null};
use crate::resolver::ResolvedValue;

/// When a container member survives to deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberPresence {
    /// The member is present in every deployment.
    Always,
    /// The member resolves to `AWS::NoValue` in every deployment.
    Never,
    /// The member is present exactly when every listed `(condition, value)`
    /// literal holds.
    When(Vec<(String, bool)>),
    /// Presence depends on conditions in a shape that has no single literal
    /// conjunction (both branches partly present, or a parameter-driven `Enum`
    /// mixing null and non-null variants).
    Complex,
}

/// Classifies one member of a resolved container.
#[must_use]
pub fn member_presence(member: &ResolvedValue) -> MemberPresence {
    match member {
        ResolvedValue::Conditional { condition, if_true, if_false } => {
            conditional_presence(condition, member_presence(if_true), member_presence(if_false))
        }
        ResolvedValue::Enum { variants } => {
            let null_variants = variants.iter().filter(|variant| is_resolved_null(variant)).count();
            if null_variants == 0 {
                MemberPresence::Always
            } else if null_variants == variants.len() {
                MemberPresence::Never
            } else {
                MemberPresence::Complex
            }
        }
        other if is_resolved_null(other) => MemberPresence::Never,
        _ => MemberPresence::Always,
    }
}

fn conditional_presence(condition: &str, if_true: MemberPresence, if_false: MemberPresence) -> MemberPresence {
    let literal = |value: bool| (condition.to_string(), value);
    match (if_true, if_false) {
        (MemberPresence::Always, MemberPresence::Always) => MemberPresence::Always,
        (MemberPresence::Never, MemberPresence::Never) => MemberPresence::Never,
        (MemberPresence::Always, MemberPresence::Never) => MemberPresence::When(vec![literal(true)]),
        (MemberPresence::Never, MemberPresence::Always) => MemberPresence::When(vec![literal(false)]),
        (MemberPresence::When(mut literals), MemberPresence::Never) => {
            literals.insert(0, literal(true));
            MemberPresence::When(literals)
        }
        (MemberPresence::Never, MemberPresence::When(mut literals)) => {
            literals.insert(0, literal(false));
            MemberPresence::When(literals)
        }
        _ => MemberPresence::Complex,
    }
}

/// One container member with its presence and whether a present value would
/// carry an unresolved reference or dynamic placeholder.
#[derive(Debug, Clone)]
pub struct ContainerMember<'a> {
    pub value: &'a ResolvedValue,
    pub presence: MemberPresence,
    pub is_dynamic: bool,
}

/// Classifies every member of a list, or every entry value of a map.
#[must_use]
pub fn classify_members(members: &[ResolvedValue]) -> Vec<ContainerMember<'_>> {
    members
        .iter()
        .map(|value| ContainerMember {
            value,
            presence: member_presence(value),
            is_dynamic: contains_dynamic_resolved(value),
        })
        .collect()
}

/// Every non-null value a member can take, each with the condition literals
/// that select it. A member that is a plain value has one alternative with no
/// literals; an `Fn::If` chain has one per reachable non-null leaf.
#[must_use]
pub fn present_alternatives(member: &ResolvedValue) -> Vec<(Vec<(String, bool)>, &ResolvedValue)> {
    let mut alternatives = Vec::new();
    collect_present_alternatives(member, &mut Vec::new(), &mut alternatives);
    alternatives
}

fn collect_present_alternatives<'a>(
    value: &'a ResolvedValue,
    literals: &mut Vec<(String, bool)>,
    alternatives: &mut Vec<(Vec<(String, bool)>, &'a ResolvedValue)>,
) {
    match value {
        ResolvedValue::Conditional { condition, if_true, if_false } => {
            for (branch, holds) in [(if_true, true), (if_false, false)] {
                match literals.iter().find(|(name, _)| name == condition) {
                    Some((_, decided)) if *decided == holds => {
                        collect_present_alternatives(branch, literals, alternatives);
                    }
                    Some(_) => {}
                    None => {
                        literals.push((condition.clone(), holds));
                        collect_present_alternatives(branch, literals, alternatives);
                        literals.pop();
                    }
                }
            }
        }
        ResolvedValue::Enum { variants } => {
            for variant in variants {
                collect_present_alternatives(variant, literals, alternatives);
            }
        }
        other if is_resolved_null(other) => {}
        other => alternatives.push((literals.clone(), other)),
    }
}

/// Every way a member resolves to `AWS::NoValue`, each as the condition
/// literals that select that null leaf. Empty when the member is always
/// present; one empty literal set when it is unconditionally null.
#[must_use]
pub fn absent_alternatives(member: &ResolvedValue) -> Vec<Vec<(String, bool)>> {
    let mut alternatives = Vec::new();
    collect_absent_alternatives(member, &mut Vec::new(), &mut alternatives);
    alternatives
}

fn collect_absent_alternatives(
    value: &ResolvedValue,
    literals: &mut Vec<(String, bool)>,
    alternatives: &mut Vec<Vec<(String, bool)>>,
) {
    match value {
        ResolvedValue::Conditional { condition, if_true, if_false } => {
            for (branch, holds) in [(if_true, true), (if_false, false)] {
                match literals.iter().find(|(name, _)| name == condition) {
                    Some((_, decided)) if *decided == holds => {
                        collect_absent_alternatives(branch, literals, alternatives);
                    }
                    Some(_) => {}
                    None => {
                        literals.push((condition.clone(), holds));
                        collect_absent_alternatives(branch, literals, alternatives);
                        literals.pop();
                    }
                }
            }
        }
        ResolvedValue::Enum { variants } => {
            for variant in variants {
                collect_absent_alternatives(variant, literals, alternatives);
            }
        }
        other if is_resolved_null(other) => alternatives.push(literals.clone()),
        _ => {}
    }
}

/// Adds `literals` to `assignment` unless one contradicts an existing entry.
/// Returns whether the literals were compatible; on `false` the assignment is
/// left unchanged.
pub fn extend_assignment(assignment: &mut HashMap<String, bool>, literals: &[(String, bool)]) -> bool {
    if literals.iter().any(|(condition, value)| assignment.get(condition).is_some_and(|existing| existing != value)) {
        return false;
    }
    for (condition, value) in literals {
        assignment.insert(condition.clone(), *value);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn concrete(value: serde_json::Value) -> ResolvedValue {
        ResolvedValue::Concrete { value: value.into() }
    }

    fn no_value() -> ResolvedValue {
        concrete(serde_json::Value::Null)
    }

    fn conditional(condition: &str, if_true: ResolvedValue, if_false: ResolvedValue) -> ResolvedValue {
        ResolvedValue::Conditional {
            condition: condition.to_string(),
            if_true: Box::new(if_true),
            if_false: Box::new(if_false),
        }
    }

    #[test]
    fn optional_member_over_no_value_is_present_when_its_condition_holds() {
        let member = conditional("HasTag", concrete(serde_json::json!({"Key": "k"})), no_value());
        assert_eq!(member_presence(&member), MemberPresence::When(vec![("HasTag".to_string(), true)]));
    }

    #[test]
    fn reversed_branches_negate_the_literal() {
        let member = conditional("Skip", no_value(), concrete(serde_json::json!("x")));
        assert_eq!(member_presence(&member), MemberPresence::When(vec![("Skip".to_string(), false)]));
    }

    #[test]
    fn nested_optional_member_conjoins_literals_outermost_first() {
        let inner = conditional("Inner", concrete(serde_json::json!("x")), no_value());
        let member = conditional("Outer", inner, no_value());
        assert_eq!(
            member_presence(&member),
            MemberPresence::When(vec![("Outer".to_string(), true), ("Inner".to_string(), true)])
        );
    }

    #[test]
    fn conditional_choosing_between_two_values_is_always_present() {
        let member = conditional("Pick", concrete(serde_json::json!("a")), concrete(serde_json::json!("b")));
        assert_eq!(member_presence(&member), MemberPresence::Always);
    }

    #[test]
    fn conditional_whose_branches_are_both_partly_present_is_complex() {
        let left = conditional("A", concrete(serde_json::json!("a")), no_value());
        let right = conditional("B", concrete(serde_json::json!("b")), no_value());
        assert_eq!(member_presence(&conditional("Pick", left, right)), MemberPresence::Complex);
    }

    #[test]
    fn enum_mixing_null_and_values_is_complex_and_all_null_is_never() {
        let mixed = ResolvedValue::Enum { variants: vec![no_value(), concrete(serde_json::json!("a"))] };
        assert_eq!(member_presence(&mixed), MemberPresence::Complex);
        let all_null = ResolvedValue::Enum { variants: vec![no_value(), no_value()] };
        assert_eq!(member_presence(&all_null), MemberPresence::Never);
    }

    #[test]
    fn present_alternatives_lists_each_non_null_leaf_with_its_literals() {
        let member = conditional(
            "Pick",
            concrete(serde_json::json!("a")),
            conditional("Other", no_value(), concrete(serde_json::json!("b"))),
        );
        let alternatives = present_alternatives(&member);
        assert_eq!(alternatives.len(), 2);
        assert_eq!(alternatives[0].0, vec![("Pick".to_string(), true)]);
        assert_eq!(alternatives[1].0, vec![("Pick".to_string(), false), ("Other".to_string(), false)]);
    }

    #[test]
    fn present_alternatives_skips_branches_contradicting_an_outer_literal() {
        let member = conditional(
            "Same",
            conditional("Same", concrete(serde_json::json!("a")), concrete(serde_json::json!("dead"))),
            no_value(),
        );
        let alternatives = present_alternatives(&member);
        assert_eq!(alternatives.len(), 1);
        assert!(matches!(alternatives[0].1, ResolvedValue::Concrete { value } if value.as_str() == Some("a")));
    }

    #[test]
    fn absent_alternatives_lists_the_null_leaves() {
        let member = conditional("HasTag", concrete(serde_json::json!({"Key": "k"})), no_value());
        assert_eq!(absent_alternatives(&member), vec![vec![("HasTag".to_string(), false)]]);
        assert!(absent_alternatives(&concrete(serde_json::json!([]))).is_empty());
        assert_eq!(absent_alternatives(&no_value()), vec![Vec::new()]);
    }

    #[test]
    fn classify_members_marks_reference_values_dynamic() {
        let members = vec![
            ResolvedValue::Reference { target: "P".to_string(), kind: crate::resolver::RefKind::Ref },
            concrete(serde_json::json!("a")),
        ];
        let classified = classify_members(&members);
        assert!(classified[0].is_dynamic && classified[0].presence == MemberPresence::Always);
        assert!(!classified[1].is_dynamic);
    }

    #[test]
    fn extend_assignment_rejects_contradicting_literals_without_mutating() {
        let mut assignment = HashMap::from([("A".to_string(), true)]);
        assert!(!extend_assignment(&mut assignment, &[("B".to_string(), true), ("A".to_string(), false)]));
        assert_eq!(assignment.len(), 1);
        assert!(extend_assignment(&mut assignment, &[("B".to_string(), true)]));
        assert_eq!(assignment.get("B"), Some(&true));
    }
}
