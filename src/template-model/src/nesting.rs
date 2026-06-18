use crate::consts::*;
use crate::ir::cfn_function_name;
use crate::ir::*;

const RULE_INVALID_INTRINSIC_NESTING: &str = "E1101";

const CONDITION_CHILDREN: &[&str] = &[FN_CONDITION, FN_EQUALS, FN_AND, FN_OR, FN_NOT];

const FINDINMAP_KEY_CHILDREN: &[&str] = &[FN_REF, FN_FIND_IN_MAP];

const FINDINMAP_KEY_CHILDREN_EXT: &[&str] =
    &[FN_REF, FN_FIND_IN_MAP, FN_JOIN, FN_SUB, FN_IF, FN_SELECT, FN_LENGTH, FN_TO_JSON_STRING];

pub fn validate_intrinsic_nesting(arena: &Arena, transforms: &[String]) -> Vec<diagnostics::Diagnostic> {
    let has_lang_ext = transforms.iter().any(|t| t == TRANSFORM_LANGUAGE_EXTENSIONS);
    let mut out = Vec::new();

    for idx in 0..arena.len() {
        let node_ref = idx as NodeRef;
        let spanned = arena.get(node_ref);
        let Node::Intrinsic(intrinsic) = &spanned.node else {
            continue;
        };
        let in_rules = spanned.path.starts_with("Rules/");

        for (child_ref, allowlist) in restricted_children(intrinsic, in_rules, has_lang_ext) {
            if let Node::Intrinsic(child_fn) = arena.node(child_ref) {
                let child_name = cfn_function_name(child_fn);
                if !allowlist.contains(&child_name) {
                    let parent_name = cfn_function_name(intrinsic);
                    out.push(crate::make_parse_diagnostic(
                        RULE_INVALID_INTRINSIC_NESTING,
                        format!("'{}' is not allowed inside '{}'", child_name, parent_name),
                        arena.span(child_ref),
                    ));
                }
            }
        }
    }
    out
}

fn restricted_children(
    intrinsic: &IntrinsicFn,
    in_rules: bool,
    has_lang_ext: bool,
) -> Vec<(NodeRef, &'static [&'static str])> {
    match intrinsic {
        // `Fn::Equals` operand validation is owned by the parser /
        // `condition_shape` E8003 check (which uses the canonical
        // `EQUALS_ARG_FN_KEYS` list), so the nesting check deliberately does
        // not re-validate Equals operands — doing so would double-report the
        // same disallowed operand under two rule IDs.
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
        IntrinsicFn::FindInMap(map_name_ref, k1, k2, _) => {
            let allow = if has_lang_ext { FINDINMAP_KEY_CHILDREN_EXT } else { FINDINMAP_KEY_CHILDREN };
            vec![(*map_name_ref, allow), (*k1, allow), (*k2, allow)]
        }
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
const LANGUAGE_EXTENSIONS: &str = TRANSFORM_LANGUAGE_EXTENSIONS;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equals_operands_are_not_checked_by_nesting() {
        // `Fn::Equals` operand validity is owned by the E8003 check, not the
        // nesting check — a disallowed operand like Fn::GetAtt must not produce
        // an E1101 here, or it would double-report alongside E8003.
        let mut arena = Arena::new();
        let getatt = arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::GetAtt("R".into(), "Arn".into())),
            span: UNKNOWN_SPAN,
            path: "Conditions/C".into(),
        });
        let lit = arena.alloc(SpannedNode {
            node: Node::String("val".into()),
            span: UNKNOWN_SPAN,
            path: "Conditions/C".into(),
        });
        arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::Equals(getatt, lit)),
            span: UNKNOWN_SPAN,
            path: "Conditions/C".into(),
        });

        let diags = validate_intrinsic_nesting(&arena, &[]);
        assert!(diags.is_empty(), "nesting must not flag Fn::Equals operands, got {:?}", diags);
    }

    #[test]
    fn getatt_inside_and_produces_e1101() {
        let mut arena = Arena::new();
        let getatt = arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::GetAtt("R".into(), "Arn".into())),
            span: UNKNOWN_SPAN,
            path: "Conditions/C".into(),
        });
        arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::And(vec![getatt])),
            span: UNKNOWN_SPAN,
            path: "Conditions/C".into(),
        });

        let diags = validate_intrinsic_nesting(&arena, &[]);
        assert!(
            diags
                .iter()
                .any(|d| d.rule_id == "E1101" && d.message.contains("Fn::GetAtt") && d.message.contains("Fn::And"))
        );
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

        let diags = validate_intrinsic_nesting(&arena, &[]);
        assert!(diags.is_empty());
    }

    #[test]
    fn findinmap_key_with_lang_ext_allows_sub() {
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

        let diags = validate_intrinsic_nesting(&arena, &[LANGUAGE_EXTENSIONS.into()]);
        assert!(diags.is_empty());
    }

    #[test]
    fn findinmap_key_without_lang_ext_rejects_sub() {
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

        let diags = validate_intrinsic_nesting(&arena, &[]);
        assert_eq!(diags.len(), 2); // both k1 and k2
        assert!(diags.iter().all(|d| d.rule_id == "E1101"));
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

        let diags = validate_intrinsic_nesting(&arena, &[]);
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

        let diags = validate_intrinsic_nesting(&arena, &[]);
        assert!(diags.is_empty());
    }

    #[test]
    fn ref_inside_not_produces_e1101() {
        let mut arena = Arena::new();
        let r = arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::Ref("Param".into())),
            span: UNKNOWN_SPAN,
            path: "Conditions/C".into(),
        });
        arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::Not(r)),
            span: UNKNOWN_SPAN,
            path: "Conditions/C".into(),
        });

        let diags = validate_intrinsic_nesting(&arena, &[]);
        assert!(
            diags.iter().any(|d| d.rule_id == "E1101" && d.message.contains("Ref") && d.message.contains("Fn::Not"))
        );
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

        let diags = validate_intrinsic_nesting(&arena, &[]);
        assert!(diags.is_empty());
    }
}
