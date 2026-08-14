use crate::consts::*;
use crate::defect::ParseDefect;
use crate::ir::cfn_function_name;
use crate::ir::*;

const CONDITION_CHILDREN: &[&str] = &[FN_CONDITION, FN_EQUALS, FN_AND, FN_OR, FN_NOT];

pub fn validate_intrinsic_nesting(arena: &Arena) -> Vec<ParseDefect> {
    let mut out = Vec::new();

    for idx in 0..arena.len() {
        let node_ref = idx as NodeRef;
        let spanned = arena.get(node_ref);
        let Node::Intrinsic(intrinsic) = &spanned.node else {
            continue;
        };
        let in_rules = spanned.path.starts_with("Rules/");

        for (child_ref, allowlist) in restricted_children(intrinsic, in_rules) {
            if let Node::Intrinsic(child_fn) = arena.node(child_ref) {
                let child_name = cfn_function_name(child_fn);
                // A child the parser's boolean-operand check already rejects
                // (anything outside `BOOLEAN_FN_KEYS`) is that check's finding;
                // re-reporting it here would flag the same operand under two
                // rule IDs. The nesting check owns only the context-sensitive
                // remainder: boolean functions that are valid somewhere (e.g.
                // the Rules-section membership functions) but not in this
                // context.
                if !BOOLEAN_FN_KEYS.contains(&child_name) {
                    continue;
                }
                if !allowlist.contains(&child_name) {
                    let parent_name = cfn_function_name(intrinsic);
                    // Anchor at the offending child node's build path so that when its
                    // own byte span is unassigned, span resolution walks up to the
                    // nearest enclosing element rather than leaving it unlocated.
                    out.push(crate::make_parse_defect_at(
                        "E9101",
                        format!("'{}' is not allowed inside '{}'", child_name, parent_name),
                        arena.span(child_ref),
                        &arena.get(child_ref).path,
                    ));
                }
            }
        }
    }
    out
}

fn restricted_children(intrinsic: &IntrinsicFn, in_rules: bool) -> Vec<(NodeRef, &'static [&'static str])> {
    match intrinsic {
        IntrinsicFn::Equals(_, _) => {
            // Fn::Equals operand validation is owned by the condition-function
            // parser check, which rejects any operand whose function does not
            // produce a scalar. Re-validating the operands here would
            // double-report the same disallowed operand under two rule IDs.
            Vec::new()
        }
        IntrinsicFn::And(items) => {
            let allow = condition_allow(in_rules);
            items.iter().map(|r| (*r, allow)).collect()
        }
        IntrinsicFn::Or(items) => {
            let allow = condition_allow(in_rules);
            items.iter().map(|r| (*r, allow)).collect()
        }
        IntrinsicFn::Not(child) => {
            vec![(*child, condition_allow(in_rules))]
        }
        // Fn::FindInMap operand validation is owned by the intrinsic
        // argument-shape check, which applies the per-function operand schema
        // (including the LanguageExtensions expansion) - re-validating the keys
        // here would double-report the same operand under two rule IDs.
        _ => Vec::new(),
    }
}

fn condition_allow(in_rules: bool) -> &'static [&'static str] {
    if in_rules { CONDITION_CHILDREN_WITH_RULES } else { CONDITION_CHILDREN }
}

/// Combined condition + rules-only children (static, computed once via const).
/// We use a single slice for the rules case to keep the check simple.
const CONDITION_CHILDREN_WITH_RULES: &[&str] = &[
    FN_CONDITION,
    FN_EQUALS,
    FN_AND,
    FN_OR,
    FN_NOT,
    FN_CONTAINS,
    FN_EACH_MEMBER_EQUALS,
    FN_EACH_MEMBER_IN,
    FN_REF_ALL,
    FN_VALUE_OF,
    FN_VALUE_OF_ALL,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equals_operands_not_checked_by_nesting() {
        let mut arena = Arena::new();
        let getatt = arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::GetAtt("R".into(), "Arn".into())),
            span: UNKNOWN_SPAN,
            path: "Resources/R/Properties/X".into(),
        });
        let lit = arena.alloc(SpannedNode {
            node: Node::String("val".into()),
            span: UNKNOWN_SPAN,
            path: "Resources/R/Properties/X".into(),
        });
        arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::Equals(getatt, lit)),
            span: UNKNOWN_SPAN,
            path: "Conditions/C".into(),
        });

        let diags = validate_intrinsic_nesting(&arena);
        assert!(diags.is_empty(), "Fn::Equals operand validity is owned by the parser check, not the nesting check");
    }

    #[test]
    fn getatt_inside_and_is_parser_owned_not_nesting() {
        // A GetAtt operand of Fn::And is rejected by the parser's boolean-operand
        // check; the nesting check must stay silent so the operand is reported
        // exactly once.
        let mut arena = Arena::new();
        let getatt = arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::GetAtt("R".into(), "Arn".into())),
            span: UNKNOWN_SPAN,
            path: "Conditions/C/Fn::And/0".into(),
        });
        let other = arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::Equals(getatt, getatt)),
            span: UNKNOWN_SPAN,
            path: "Conditions/C/Fn::And/1".into(),
        });
        arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::And(vec![getatt, other])),
            span: UNKNOWN_SPAN,
            path: "Conditions/C".into(),
        });
        let diags = validate_intrinsic_nesting(&arena);
        assert!(diags.is_empty(), "parser owns non-boolean operands: {:?}", diags);
    }

    #[test]
    fn rules_section_allows_contains_in_and() {
        let mut arena = Arena::new();
        let list = arena.alloc(SpannedNode { node: Node::List(vec![]), span: UNKNOWN_SPAN, path: "Rules/R".into() });
        let contains = arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::Contains(list, list)),
            span: UNKNOWN_SPAN,
            path: "Rules/R".into(),
        });
        arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::And(vec![contains])),
            span: UNKNOWN_SPAN,
            path: "Rules/R".into(),
        });

        let diags = validate_intrinsic_nesting(&arena);
        assert!(diags.is_empty());
    }

    #[test]
    fn findinmap_keys_are_not_checked_by_nesting() {
        let mut arena = Arena::new();
        let sub = arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::Sub("${x}".into(), None)),
            span: UNKNOWN_SPAN,
            path: "Resources/R".into(),
        });
        let map_name =
            arena.alloc(SpannedNode { node: Node::String("M".into()), span: UNKNOWN_SPAN, path: "Resources/R".into() });
        arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::FindInMap(map_name, sub, sub, None)),
            span: UNKNOWN_SPAN,
            path: "Resources/R".into(),
        });

        let diags = validate_intrinsic_nesting(&arena);
        assert!(diags.is_empty(), "Fn::FindInMap operand validity is owned by the argument-shape check");
    }

    #[test]
    fn condition_ref_inside_and_is_allowed() {
        let mut arena = Arena::new();
        let cond_ref = arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::Ref("Condition:IsProd".into())),
            span: UNKNOWN_SPAN,
            path: "Conditions/C".into(),
        });
        arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::And(vec![cond_ref])),
            span: UNKNOWN_SPAN,
            path: "Conditions/C".into(),
        });

        let diags = validate_intrinsic_nesting(&arena);
        assert!(diags.is_empty());
    }

    #[test]
    fn equals_inside_or_is_allowed() {
        let mut arena = Arena::new();
        let a = arena.alloc(SpannedNode {
            node: Node::String("x".into()),
            span: UNKNOWN_SPAN,
            path: "Conditions/C".into(),
        });
        let eq = arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::Equals(a, a)),
            span: UNKNOWN_SPAN,
            path: "Conditions/C".into(),
        });
        arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::Or(vec![eq])),
            span: UNKNOWN_SPAN,
            path: "Conditions/C".into(),
        });

        let diags = validate_intrinsic_nesting(&arena);
        assert!(diags.is_empty());
    }

    #[test]
    fn ref_inside_not_is_parser_owned_not_nesting() {
        let mut arena = Arena::new();
        let r = arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::Ref("Param".into())),
            span: UNKNOWN_SPAN,
            path: "Conditions/C/Fn::Not/0".into(),
        });
        arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::Not(r)),
            span: UNKNOWN_SPAN,
            path: "Conditions/C".into(),
        });
        let diags = validate_intrinsic_nesting(&arena);
        assert!(diags.is_empty(), "parser owns non-boolean operands: {:?}", diags);
    }

    #[test]
    fn rules_only_function_outside_rules_produces_invalid_nesting() {
        // Fn::Contains is a boolean function, but only valid in the Rules
        // section - in a Conditions-section Fn::And it is the nesting check's
        // finding (the parser's boolean-operand check accepts it everywhere).
        let mut arena = Arena::new();
        let a = arena.alloc(SpannedNode {
            node: Node::String("x".into()),
            span: UNKNOWN_SPAN,
            path: "Conditions/C/Fn::Contains/0".into(),
        });
        let contains = arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::Contains(a, a)),
            span: UNKNOWN_SPAN,
            path: "Conditions/C/Fn::And/0".into(),
        });
        arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::And(vec![contains])),
            span: UNKNOWN_SPAN,
            path: "Conditions/C".into(),
        });
        let diags = validate_intrinsic_nesting(&arena);
        assert_eq!(diags.len(), 1, "{:?}", diags);
        assert_eq!(diags[0].rule_id, "E9101");
    }

    #[test]
    fn non_intrinsic_children_are_not_flagged() {
        let mut arena = Arena::new();
        let s = arena.alloc(SpannedNode {
            node: Node::String("literal".into()),
            span: UNKNOWN_SPAN,
            path: "Conditions/C".into(),
        });
        arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::Equals(s, s)),
            span: UNKNOWN_SPAN,
            path: "Conditions/C".into(),
        });

        let diags = validate_intrinsic_nesting(&arena);
        assert!(diags.is_empty());
    }
}
