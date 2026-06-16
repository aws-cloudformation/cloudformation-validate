//! Author-time validation of condition expression shapes.
//!
//! The parser accepts well-formed boolean intrinsics into `IntrinsicFn::And`,
//! `IntrinsicFn::Or`, `IntrinsicFn::Not`, and `IntrinsicFn::Equals` — but
//! ill-formed shapes (non-intrinsic top-level condition values, undefined
//! `Condition:` references, `Fn::Equals` operands that aren't strings or
//! string-producing intrinsics) need a separate pass once the IR exists.

use crate::consts::*;
use crate::ir::*;
use std::collections::HashSet;

/// Rule ID for a condition value that is not a single-key boolean-producing
/// intrinsic. Sourced from the schema layer because CloudFormation itself
/// rejects these templates at deploy time.
const RULE_TOP_LEVEL_SHAPE: &str = "E8001";
const RULE_EQUALS_OPERAND: &str = "E8003";
const RULE_AND_ARITY: &str = "E8004";
const RULE_OR_ARITY: &str = "E8006";
const RULE_UNDEFINED_CONDITION_REF: &str = "E8007";

const CONDITIONS_PATH_PREFIX: &str = "Conditions/";
const RULES_PATH_PREFIX: &str = "Rules/";

pub fn validate_condition_shapes(
    arena: &Arena,
    conditions_node: NodeRef,
    defined_conditions: &HashSet<String>,
    transforms: &[String],
) -> Vec<diagnostics::Diagnostic> {
    let mut out = Vec::new();
    let has_lang_ext = transforms.iter().any(|t| t == TRANSFORM_LANGUAGE_EXTENSIONS);

    if conditions_node != NULL_REF {
        if let Some(entries) = arena.as_map(conditions_node) {
            for (name, node_ref) in entries {
                if has_lang_ext && name.starts_with("Fn::ForEach::") {
                    continue;
                }
                validate_top_level_condition(arena, name, *node_ref, &mut out);
            }
        } else {
            // The Conditions section must be a mapping of condition name to a
            // boolean expression. A list or scalar here is a structural error
            // CloudFormation rejects at deploy time.
            out.push(crate::make_parse_diagnostic(
                RULE_TOP_LEVEL_SHAPE,
                "Conditions section must be a mapping of condition names to boolean expressions".to_string(),
                arena.get(conditions_node).span,
            ));
        }
    }

    validate_intrinsic_shapes(arena, defined_conditions, &mut out);

    out
}

/// A top-level condition value must be a single-key map whose key is a
/// boolean-producing intrinsic — the parser folds well-formed cases into
/// `IntrinsicFn`, so anything left as `Node::Map`/`Node::String`/etc. is
/// malformed.
fn validate_top_level_condition(
    arena: &Arena,
    name: &str,
    node_ref: NodeRef,
    out: &mut Vec<diagnostics::Diagnostic>,
) {
    let spanned = arena.get(node_ref);
    if matches!(spanned.node, Node::Intrinsic(_)) {
        return;
    }

    // When a condition value uses a boolean condition function but is
    // malformed (wrong operand type or arity), the parser cannot fold it into
    // an `IntrinsicFn` and leaves it as a plain single-key `Node::Map` — but it
    // has already emitted the specific shape diagnostic (E8003/E8004/E8005/
    // E8006). Emitting E8001 on top would double-report the same error, so skip
    // it here. A condition that is malformed in some other way (a bare list, a
    // scalar, a multi-key map) still gets E8001 because no specific diagnostic
    // was produced for it.
    if let Some(entries) = arena.as_map(node_ref)
        && entries.len() == 1
        && is_condition_function_key(entries[0].0.as_str())
    {
        return;
    }

    out.push(crate::make_parse_diagnostic(
        RULE_TOP_LEVEL_SHAPE,
        format!(
            "Condition '{}' must be a single-key mapping with one of: {}, {}, {}, {}, {}",
            name, FN_EQUALS, FN_AND, FN_OR, FN_NOT, FN_CONDITION
        ),
        spanned.span,
    ));
}

/// A single-key mapping whose key is one of these is a (possibly malformed)
/// boolean condition function. The parser owns the shape diagnostics for these
/// keys, so the top-level shape check defers to it rather than double-report.
fn is_condition_function_key(key: &str) -> bool {
    matches!(key, FN_EQUALS | FN_AND | FN_OR | FN_NOT | FN_CONDITION)
}

fn validate_intrinsic_shapes(
    arena: &Arena,
    defined_conditions: &HashSet<String>,
    out: &mut Vec<diagnostics::Diagnostic>,
) {
    for idx in 0..arena.len() {
        let node_ref = idx as NodeRef;
        let spanned = arena.get(node_ref);

        if !spanned.path.starts_with(CONDITIONS_PATH_PREFIX) && !spanned.path.starts_with(RULES_PATH_PREFIX) {
            continue;
        }

        // Skip pre-expansion artifacts left over from `Fn::ForEach::*` macros
        // — the LanguageExtensions transform pass has already cloned this
        // subtree into expanded sibling entries with fresh paths, and the
        // original nodes are no longer reachable from the parent map.
        if spanned.path.contains("Fn::ForEach::") {
            continue;
        }

        let Node::Intrinsic(intrinsic) = &spanned.node else {
            continue;
        };

        match intrinsic {
            IntrinsicFn::And(items) => {
                emit_arity_violation(items.len(), FN_AND, RULE_AND_ARITY, spanned.span, out);
            }
            IntrinsicFn::Or(items) => {
                emit_arity_violation(items.len(), FN_OR, RULE_OR_ARITY, spanned.span, out);
            }
            IntrinsicFn::Equals(left, right) => {
                check_equals_operand(arena, *left, 1, spanned.span, out);
                check_equals_operand(arena, *right, 2, spanned.span, out);
            }
            IntrinsicFn::Ref(target) if target.starts_with(CONDITION_REF_PREFIX) => {
                let cond_name = &target[CONDITION_REF_PREFIX.len()..];
                if !defined_conditions.contains(cond_name) {
                    out.push(crate::make_parse_diagnostic(
                        RULE_UNDEFINED_CONDITION_REF,
                        format!("Condition '{}' is not defined", cond_name),
                        spanned.span,
                    ));
                }
            }
            _ => {}
        }
    }
}

fn emit_arity_violation(
    count: usize,
    fn_name: &str,
    rule_id: &str,
    span: diagnostics::SourceSpan,
    out: &mut Vec<diagnostics::Diagnostic>,
) {
    if count < BOOLEAN_FN_MIN_ARITY || count > BOOLEAN_FN_MAX_ARITY {
        out.push(crate::make_parse_diagnostic(
            rule_id,
            format!(
                "{} must have between {} and {} elements, found {}",
                fn_name, BOOLEAN_FN_MIN_ARITY, BOOLEAN_FN_MAX_ARITY, count
            ),
            span,
        ));
    }
}

/// An `Fn::Equals` operand must be a literal scalar or a string-producing
/// intrinsic (`Ref`, `Fn::FindInMap`, `Fn::Sub`, ...). Other intrinsics
/// (`Fn::And`, `Fn::Equals`, ...) return booleans, lists, or unsupported types.
fn check_equals_operand(
    arena: &Arena,
    operand_ref: NodeRef,
    position: u8,
    parent_span: diagnostics::SourceSpan,
    out: &mut Vec<diagnostics::Diagnostic>,
) {
    let operand = arena.get(operand_ref);
    let invalid = match &operand.node {
        Node::String(_) | Node::Int(_) | Node::Float(_) | Node::Bool(_) => false,
        Node::Intrinsic(intrinsic) => !EQUALS_ARG_FN_KEYS.contains(&cfn_function_name(intrinsic)),
        _ => true,
    };
    if invalid {
        out.push(crate::make_parse_diagnostic(
            RULE_EQUALS_OPERAND,
            format!(
                "Fn::Equals operand {} is not a valid type — must be a string literal or one of: {}",
                position,
                EQUALS_ARG_FN_KEYS.join(", ")
            ),
            parent_span,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn condition_names(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn alloc_str(arena: &mut Arena, value: &str, path: &str) -> NodeRef {
        arena.alloc(SpannedNode { node: Node::String(value.into()), span: UNKNOWN_SPAN, path: path.into() })
    }

    fn alloc_intrinsic(arena: &mut Arena, intrinsic: IntrinsicFn, path: &str) -> NodeRef {
        arena.alloc(SpannedNode { node: Node::Intrinsic(intrinsic), span: UNKNOWN_SPAN, path: path.into() })
    }

    #[test]
    fn malformed_condition_function_map_does_not_cascade_e8001() {
        // The parser leaves a malformed condition function (e.g. `Fn::Equals`
        // with a non-array value) as a plain single-key Map after emitting the
        // specific E8003/E8004/... shape diagnostic. The top-level shape check
        // must NOT add a cascading E8001 on top.
        let mut arena = Arena::new();
        let bad_val = alloc_str(&mut arena, "not-an-array", "Conditions/Bad/Fn::Equals");
        let equals_map = arena.alloc(SpannedNode {
            node: Node::Map(vec![("Fn::Equals".into(), bad_val)]),
            span: UNKNOWN_SPAN,
            path: "Conditions/Bad".into(),
        });
        let conditions_map = arena.alloc(SpannedNode {
            node: Node::Map(vec![("Bad".into(), equals_map)]),
            span: UNKNOWN_SPAN,
            path: "Conditions".into(),
        });

        let diags = validate_condition_shapes(&arena, conditions_map, &condition_names(&[]), &[]);
        assert!(
            !diags.iter().any(|d| d.rule_id == RULE_TOP_LEVEL_SHAPE),
            "single-key condition-function map must not produce a cascading E8001, got {:?}",
            diags
        );
    }

    #[test]
    fn non_map_malformed_condition_still_fails_shape_check() {
        // A condition value that is a bare list (not a condition-function map)
        // has no specific parser diagnostic, so E8001 must still fire.
        let mut arena = Arena::new();
        let list_node =
            arena.alloc(SpannedNode { node: Node::List(vec![]), span: UNKNOWN_SPAN, path: "Conditions/Bad".into() });
        let conditions_map = arena.alloc(SpannedNode {
            node: Node::Map(vec![("Bad".into(), list_node)]),
            span: UNKNOWN_SPAN,
            path: "Conditions".into(),
        });

        let diags = validate_condition_shapes(&arena, conditions_map, &condition_names(&[]), &[]);
        assert_eq!(diags.len(), 1, "bare-list condition must still get E8001, got {:?}", diags);
        assert_eq!(diags[0].rule_id, RULE_TOP_LEVEL_SHAPE);
    }

    #[test]
    fn non_intrinsic_top_level_condition_fails_shape_check() {
        let mut arena = Arena::new();
        let str_node = alloc_str(&mut arena, "not-a-function", "Conditions/Bad");
        let conditions_map = arena.alloc(SpannedNode {
            node: Node::Map(vec![("Bad".into(), str_node)]),
            span: UNKNOWN_SPAN,
            path: "Conditions".into(),
        });

        let diags = validate_condition_shapes(&arena, conditions_map, &condition_names(&[]), &[]);
        assert_eq!(diags.len(), 1, "expected 1 diagnostic, got {:?}", diags);
        assert_eq!(diags[0].rule_id, RULE_TOP_LEVEL_SHAPE);
        assert!(diags[0].message.contains("Bad"));
    }

    #[test]
    fn equals_with_string_operands_passes() {
        let mut arena = Arena::new();
        let lit_a = alloc_str(&mut arena, "a", "Conditions/Good");
        let lit_b = alloc_str(&mut arena, "b", "Conditions/Good");
        let equals = alloc_intrinsic(&mut arena, IntrinsicFn::Equals(lit_a, lit_b), "Conditions/Good");
        let conditions_map = arena.alloc(SpannedNode {
            node: Node::Map(vec![("Good".into(), equals)]),
            span: UNKNOWN_SPAN,
            path: "Conditions".into(),
        });

        let diags = validate_condition_shapes(&arena, conditions_map, &condition_names(&[]), &[]);
        assert!(diags.is_empty(), "valid condition should produce no diagnostics, got {:?}", diags);
    }

    #[test]
    fn and_with_one_child_fails_arity() {
        let mut arena = Arena::new();
        let lit_a = alloc_str(&mut arena, "a", "Conditions/C");
        let lit_b = alloc_str(&mut arena, "b", "Conditions/C");
        let eq = alloc_intrinsic(&mut arena, IntrinsicFn::Equals(lit_a, lit_b), "Conditions/C");
        alloc_intrinsic(&mut arena, IntrinsicFn::And(vec![eq]), "Conditions/C");

        let mut diags = Vec::new();
        validate_intrinsic_shapes(&arena, &condition_names(&[]), &mut diags);
        let arity_diags: Vec<_> = diags.iter().filter(|d| d.rule_id == RULE_AND_ARITY).collect();
        assert_eq!(arity_diags.len(), 1, "expected 1 arity diagnostic, got {:?}", arity_diags);
        assert!(arity_diags[0].message.contains("found 1"));
    }

    #[test]
    fn and_with_eleven_children_fails_arity() {
        let mut arena = Arena::new();
        let items: Vec<NodeRef> = (0..11)
            .map(|_| {
                let a = alloc_str(&mut arena, "x", "Conditions/C");
                let b = alloc_str(&mut arena, "y", "Conditions/C");
                alloc_intrinsic(&mut arena, IntrinsicFn::Equals(a, b), "Conditions/C")
            })
            .collect();
        alloc_intrinsic(&mut arena, IntrinsicFn::And(items), "Conditions/C");

        let mut diags = Vec::new();
        validate_intrinsic_shapes(&arena, &condition_names(&[]), &mut diags);
        let arity_diags: Vec<_> = diags.iter().filter(|d| d.rule_id == RULE_AND_ARITY).collect();
        assert_eq!(arity_diags.len(), 1, "expected 1 arity diagnostic, got {:?}", arity_diags);
        assert!(arity_diags[0].message.contains("found 11"));
    }

    #[test]
    fn or_with_one_child_fails_arity() {
        let mut arena = Arena::new();
        let lit_a = alloc_str(&mut arena, "a", "Conditions/C");
        let lit_b = alloc_str(&mut arena, "b", "Conditions/C");
        let eq = alloc_intrinsic(&mut arena, IntrinsicFn::Equals(lit_a, lit_b), "Conditions/C");
        alloc_intrinsic(&mut arena, IntrinsicFn::Or(vec![eq]), "Conditions/C");

        let mut diags = Vec::new();
        validate_intrinsic_shapes(&arena, &condition_names(&[]), &mut diags);
        let arity_diags: Vec<_> = diags.iter().filter(|d| d.rule_id == RULE_OR_ARITY).collect();
        assert_eq!(arity_diags.len(), 1, "expected 1 arity diagnostic, got {:?}", arity_diags);
        assert!(arity_diags[0].message.contains("found 1"));
    }

    #[test]
    fn condition_ref_to_undefined_name_fails() {
        let mut arena = Arena::new();
        let cond_ref = alloc_intrinsic(&mut arena, IntrinsicFn::Ref("Condition:Nope".into()), "Conditions/C");
        alloc_intrinsic(&mut arena, IntrinsicFn::And(vec![cond_ref, cond_ref]), "Conditions/C");

        let mut diags = Vec::new();
        validate_intrinsic_shapes(&arena, &condition_names(&["IsProd"]), &mut diags);
        assert!(
            diags.iter().any(|d| d.rule_id == RULE_UNDEFINED_CONDITION_REF && d.message.contains("Nope")),
            "expected undefined-condition diagnostic, got {:?}",
            diags
        );
    }

    #[test]
    fn condition_ref_to_defined_name_passes() {
        let mut arena = Arena::new();
        let cond_ref = alloc_intrinsic(&mut arena, IntrinsicFn::Ref("Condition:IsProd".into()), "Conditions/C");
        alloc_intrinsic(&mut arena, IntrinsicFn::And(vec![cond_ref, cond_ref]), "Conditions/C");

        let mut diags = Vec::new();
        validate_intrinsic_shapes(&arena, &condition_names(&["IsProd"]), &mut diags);
        assert!(
            !diags.iter().any(|d| d.rule_id == RULE_UNDEFINED_CONDITION_REF),
            "defined condition should not trigger undefined diagnostic, got {:?}",
            diags
        );
    }

    #[test]
    fn equals_with_list_operand_fails() {
        let mut arena = Arena::new();
        let list_node =
            arena.alloc(SpannedNode { node: Node::List(vec![]), span: UNKNOWN_SPAN, path: "Conditions/C".into() });
        let str_node = alloc_str(&mut arena, "val", "Conditions/C");
        alloc_intrinsic(&mut arena, IntrinsicFn::Equals(list_node, str_node), "Conditions/C");

        let mut diags = Vec::new();
        validate_intrinsic_shapes(&arena, &condition_names(&[]), &mut diags);
        let operand_diags: Vec<_> = diags.iter().filter(|d| d.rule_id == RULE_EQUALS_OPERAND).collect();
        assert_eq!(operand_diags.len(), 1, "expected 1 operand diagnostic, got {:?}", operand_diags);
        assert!(operand_diags[0].message.contains("operand 1"));
    }

    #[test]
    fn equals_with_boolean_intrinsic_operand_fails() {
        let mut arena = Arena::new();
        let and_node = alloc_intrinsic(&mut arena, IntrinsicFn::And(vec![]), "Conditions/C");
        let str_node = alloc_str(&mut arena, "val", "Conditions/C");
        alloc_intrinsic(&mut arena, IntrinsicFn::Equals(and_node, str_node), "Conditions/C");

        let mut diags = Vec::new();
        validate_intrinsic_shapes(&arena, &condition_names(&[]), &mut diags);
        assert!(
            diags.iter().any(|d| d.rule_id == RULE_EQUALS_OPERAND),
            "expected operand diagnostic, got {:?}",
            diags
        );
    }

    #[test]
    fn three_child_and_or_passes_arity() {
        let mut arena = Arena::new();
        let items: Vec<NodeRef> = (0..3)
            .map(|_| alloc_intrinsic(&mut arena, IntrinsicFn::Equals(0, 0), "Conditions/C"))
            .collect();
        alloc_intrinsic(&mut arena, IntrinsicFn::And(items.clone()), "Conditions/C");
        alloc_intrinsic(&mut arena, IntrinsicFn::Or(items), "Conditions/C");

        let mut diags = Vec::new();
        validate_intrinsic_shapes(&arena, &condition_names(&[]), &mut diags);
        let arity_diags: Vec<_> =
            diags.iter().filter(|d| d.rule_id == RULE_AND_ARITY || d.rule_id == RULE_OR_ARITY).collect();
        assert!(arity_diags.is_empty(), "valid arity should produce no diagnostics, got {:?}", arity_diags);
    }
}
