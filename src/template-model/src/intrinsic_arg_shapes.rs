//! Structural argument-shape validation for non-condition intrinsics whose
//! operands have a fixed, schema-defined type.
//!
//! cfn-lint validates these through JSON-schema `BaseFn` rules. We mirror the
//! relevant per-function operand schemas so a guaranteed deploy failure (an
//! `Fn::Select` over a non-list, an `Fn::ImportValue` of another
//! `Fn::ImportValue`, …) surfaces with the same rule ID cfn-lint uses:
//!
//! * `Fn::Select` (E1017): the source (second) operand must be a list or a
//!   list-producing intrinsic. The index operand's type is already covered by
//!   the parser's W1102 check, so it is not re-validated here.
//! * `Fn::ImportValue` (E1016): the argument must be a string or a
//!   string-producing intrinsic — notably never another `Fn::ImportValue`,
//!   and never a list.
//!
//! `Fn::Select` arity (exactly two operands) is enforced in the parser, where
//! the raw array is available before it is folded into `IntrinsicFn::Select`.
//! `Fn::FindInMap` operand intrinsics are validated by the intrinsic-nesting
//! check (E1101), so they are intentionally not duplicated here.

use crate::consts::*;
use crate::ir::*;
use diagnostics::{Diagnostic, SourceSpan};

const RULE_SELECT_SHAPE: &str = "E1017";
const RULE_IMPORT_VALUE_SHAPE: &str = "E1016";

/// Intrinsics whose return value is a list and may therefore be the source
/// (second) operand of `Fn::Select`. Mirrors cfn-lint's `select.json`
/// `definitions/array` function list.
const SELECT_SOURCE_FNS: &[&str] =
    &[FN_FIND_IN_MAP, FN_GET_ATT, FN_GET_AZS, FN_IF, FN_SPLIT, FN_CIDR, FN_REF];

/// Intrinsics whose return value is a string and may therefore be the argument
/// of `Fn::ImportValue`. Mirrors cfn-lint's `importvalue.json` function list —
/// notably excludes `Fn::ImportValue` itself (no nesting) and `Fn::GetAtt`.
const IMPORT_VALUE_ARG_FNS: &[&str] = &[FN_BASE64, FN_FIND_IN_MAP, FN_IF, FN_JOIN, FN_SELECT, FN_SUB, FN_REF];

pub fn validate_intrinsic_arg_shapes(arena: &Arena) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for idx in 0..arena.len() {
        let node_ref = idx as NodeRef;
        let spanned = arena.get(node_ref);
        let Node::Intrinsic(intrinsic) = &spanned.node else {
            continue;
        };
        match intrinsic {
            IntrinsicFn::Select(_, source) => check_select_source(arena, *source, spanned.span, &mut out),
            IntrinsicFn::ImportValue(arg) => check_import_value_arg(arena, *arg, spanned.span, &mut out),
            _ => {}
        }
    }
    out
}

fn check_select_source(arena: &Arena, source_ref: NodeRef, span: SourceSpan, out: &mut Vec<Diagnostic>) {
    if !arena.is_valid(source_ref) {
        return;
    }
    let valid = match arena.node(source_ref) {
        Node::List(_) => true,
        Node::Intrinsic(intrinsic) => SELECT_SOURCE_FNS.contains(&cfn_function_name(intrinsic)),
        _ => false,
    };
    if !valid {
        out.push(crate::make_parse_diagnostic(
            RULE_SELECT_SHAPE,
            format!(
                "Fn::Select source (second element) must be a list or a list-producing intrinsic ({})",
                SELECT_SOURCE_FNS.join(", ")
            ),
            span,
        ));
    }
}

fn check_import_value_arg(arena: &Arena, arg_ref: NodeRef, span: SourceSpan, out: &mut Vec<Diagnostic>) {
    if !arena.is_valid(arg_ref) {
        return;
    }
    let valid = match arena.node(arg_ref) {
        Node::String(_) | Node::Int(_) | Node::Float(_) | Node::Bool(_) => true,
        Node::Intrinsic(intrinsic) => IMPORT_VALUE_ARG_FNS.contains(&cfn_function_name(intrinsic)),
        _ => false,
    };
    if !valid {
        out.push(crate::make_parse_diagnostic(
            RULE_IMPORT_VALUE_SHAPE,
            format!(
                "Fn::ImportValue argument must be a string or a string-producing intrinsic ({}) — it must not be a list or another Fn::ImportValue",
                IMPORT_VALUE_ARG_FNS.join(", ")
            ),
            span,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;

    fn parse_and_validate(src: &str) -> Vec<Diagnostic> {
        let ir = parser::parse(src.as_bytes()).expect("parse");
        validate_intrinsic_arg_shapes(&ir.arena)
    }

    #[test]
    fn select_over_literal_list_passes() {
        let diags = parse_and_validate(
            r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Select":[0,["a","b"]]}}}}}"#,
        );
        assert!(diags.iter().all(|d| d.rule_id != RULE_SELECT_SHAPE), "unexpected: {:?}", diags);
    }

    #[test]
    fn select_over_split_passes() {
        let diags = parse_and_validate(
            r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Select":[0,{"Fn::Split":["-","a-b"]}]}}}}}"#,
        );
        assert!(diags.iter().all(|d| d.rule_id != RULE_SELECT_SHAPE), "unexpected: {:?}", diags);
    }

    #[test]
    fn select_over_scalar_emits_e1017() {
        let diags = parse_and_validate(
            r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Select":[0,"not-a-list"]}}}}}"#,
        );
        assert_eq!(diags.iter().filter(|d| d.rule_id == RULE_SELECT_SHAPE).count(), 1, "{:?}", diags);
    }

    #[test]
    fn select_over_disallowed_intrinsic_emits_e1017() {
        let diags = parse_and_validate(
            r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Select":[0,{"Fn::Join":["-",["a","b"]]}]}}}}}"#,
        );
        assert_eq!(diags.iter().filter(|d| d.rule_id == RULE_SELECT_SHAPE).count(), 1, "{:?}", diags);
    }

    #[test]
    fn import_value_of_string_passes() {
        let diags =
            parse_and_validate(r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::ImportValue":"Export"}}}}}"#);
        assert!(diags.iter().all(|d| d.rule_id != RULE_IMPORT_VALUE_SHAPE), "unexpected: {:?}", diags);
    }

    #[test]
    fn import_value_of_sub_passes() {
        let diags = parse_and_validate(
            r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::ImportValue":{"Fn::Sub":"${X}-export"}}}}}}"#,
        );
        assert!(diags.iter().all(|d| d.rule_id != RULE_IMPORT_VALUE_SHAPE), "unexpected: {:?}", diags);
    }

    #[test]
    fn nested_import_value_emits_e1016() {
        let diags = parse_and_validate(
            r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::ImportValue":{"Fn::ImportValue":"Inner"}}}}}}"#,
        );
        assert_eq!(diags.iter().filter(|d| d.rule_id == RULE_IMPORT_VALUE_SHAPE).count(), 1, "{:?}", diags);
    }

    #[test]
    fn import_value_of_list_emits_e1016() {
        let diags = parse_and_validate(
            r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::ImportValue":["Export"]}}}}}"#,
        );
        assert_eq!(diags.iter().filter(|d| d.rule_id == RULE_IMPORT_VALUE_SHAPE).count(), 1, "{:?}", diags);
    }
}
