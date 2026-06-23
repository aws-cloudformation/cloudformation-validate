//! Structural argument-shape validation for non-condition intrinsics whose
//! operands have a fixed, schema-defined type.
//!
//! Each intrinsic has a published per-function operand schema. When an
//! operand violates that schema — `Fn::Select` over a non-list, an
//! `Fn::ImportValue` of another `Fn::ImportValue`, etc. — CloudFormation
//! rejects the template at deploy time. This pass surfaces those failures
//! during validation:
//!
//! * `Fn::Select` (E1017): the source (second) operand must be a list or a
//!   list-producing intrinsic. The index operand's type is already covered by
//!   the parser's W1102 check, so it is not re-validated here.
//! * `Fn::ImportValue` (E1016): the argument must be a string or a
//!   string-producing intrinsic — notably never another `Fn::ImportValue`,
//!   and never a list.
//! * `Fn::Split` (E1018): the source (second) operand must be a string or a
//!   string-producing intrinsic.
//! * `Fn::Sub` (E1019): the variable map values must be strings or
//!   string-producing intrinsics.
//! * `Fn::Base64` (E1021): the argument must be a string or one of the
//!   string-producing intrinsics CloudFormation accepts in this position.
//! * `Fn::Join` (E1022): the delimiter must be a string; the list operand
//!   must be an array or a list-producing intrinsic; list items must be
//!   strings or string-producing intrinsics.
//! * `Fn::Cidr` (E1024): each of the three operands must be a scalar of the
//!   correct type or an allowed string-producing intrinsic.
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
const RULE_SPLIT_SHAPE: &str = "E1018";
const RULE_SUB_SHAPE: &str = "E1019";
const RULE_BASE64_SHAPE: &str = "E1021";
const RULE_JOIN_SHAPE: &str = "E1022";
const RULE_CIDR_SHAPE: &str = "E1024";
const RULE_FIND_IN_MAP_SHAPE: &str = "E1011";

/// Intrinsics whose return value is a list and may therefore be the source
/// (second) operand of `Fn::Select`. CloudFormation rejects any other
/// intrinsic in this position.
const SELECT_SOURCE_FNS: &[&str] =
    &[FN_FIND_IN_MAP, FN_GET_ATT, FN_GET_AZS, FN_IF, FN_SPLIT, FN_CIDR, FN_REF];

/// Intrinsics whose return value is a string and may therefore be the argument
/// of `Fn::ImportValue`. Notably excludes `Fn::ImportValue` itself (no
/// nesting) and `Fn::GetAtt` (return type is not guaranteed string).
const IMPORT_VALUE_ARG_FNS: &[&str] = &[FN_BASE64, FN_FIND_IN_MAP, FN_IF, FN_JOIN, FN_SELECT, FN_SUB, FN_REF];

/// Intrinsics whose return value is a string and may therefore be the source
/// (second) operand of `Fn::Split`. Anything else cannot produce the string
/// CloudFormation needs to split.
const SPLIT_SOURCE_FNS: &[&str] = &[
    FN_BASE64,
    FN_FIND_IN_MAP,
    FN_GET_ATT,
    FN_GET_AZS,
    FN_IF,
    FN_IMPORT_VALUE,
    FN_JOIN,
    FN_SELECT,
    FN_SUB,
    FN_REF,
];

/// Intrinsics whose return value is a string and may therefore appear as the
/// value of an entry in `Fn::Sub`'s variable map.
const SUB_VAR_VALUE_FNS: &[&str] = &[
    FN_BASE64,
    FN_FIND_IN_MAP,
    FN_GET_ATT,
    FN_GET_AZS,
    FN_IF,
    FN_IMPORT_VALUE,
    FN_JOIN,
    FN_SELECT,
    FN_SPLIT,
    FN_SUB,
    FN_REF,
    FN_TRANSFORM,
];

/// Intrinsics whose return value is a string and may therefore be the argument
/// of `Fn::Base64`.
const BASE64_ARG_FNS: &[&str] = &[
    FN_BASE64,
    FN_CIDR,
    FN_FIND_IN_MAP,
    FN_GET_ATT,
    FN_GET_STACK_OUTPUT,
    FN_IF,
    FN_IMPORT_VALUE,
    FN_JOIN,
    FN_LENGTH,
    FN_SELECT,
    FN_SUB,
    FN_TO_JSON_STRING,
    FN_TRANSFORM,
    FN_REF,
];

/// Intrinsics whose return value is a list and may therefore be the second
/// operand of `Fn::Join`. Note: `Fn::GetAZs` is intentionally excluded here
/// (CloudFormation accepts it via `Fn::Split`/`Fn::Select` but not directly).
const JOIN_LIST_FNS: &[&str] =
    &[FN_CIDR, FN_FIND_IN_MAP, FN_GET_ATT, FN_IF, FN_SPLIT, FN_REF];

/// Intrinsics whose return value is a string and may therefore appear as a
/// list element inside `Fn::Join`.
const JOIN_ITEM_FNS: &[&str] = &[
    FN_BASE64,
    FN_FIND_IN_MAP,
    FN_GET_ATT,
    FN_GET_STACK_OUTPUT,
    FN_IF,
    FN_IMPORT_VALUE,
    FN_JOIN,
    FN_SELECT,
    FN_SUB,
    FN_TRANSFORM,
    FN_REF,
];

/// Intrinsics whose return value is a string and may therefore appear as any
/// of the three `Fn::Cidr` operands.
const CIDR_OP_FNS: &[&str] =
    &[FN_FIND_IN_MAP, FN_GET_ATT, FN_IF, FN_IMPORT_VALUE, FN_SELECT, FN_SUB, FN_REF];

/// Intrinsics whose return value is a string and may therefore appear as the
/// map name or as a top-level / second-level key in `Fn::FindInMap`.
/// CloudFormation accepts `Ref` and `Fn::FindInMap` by default; the
/// `AWS::LanguageExtensions` transform broadens the set to include several
/// other string-producing intrinsics. The intrinsic-nesting check (`E1101`)
/// uses the same allow-sets so the two checks stay consistent.
const FIND_IN_MAP_OP_FNS: &[&str] = &[FN_REF, FN_FIND_IN_MAP];
const FIND_IN_MAP_OP_FNS_EXT: &[&str] =
    &[FN_REF, FN_FIND_IN_MAP, FN_JOIN, FN_SUB, FN_IF, FN_SELECT, FN_LENGTH, FN_TO_JSON_STRING];

pub fn validate_intrinsic_arg_shapes(arena: &Arena, transforms: &[String]) -> Vec<Diagnostic> {
    let has_lang_ext = transforms.iter().any(|t| t == TRANSFORM_LANGUAGE_EXTENSIONS);
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
            IntrinsicFn::Split(_, source) => check_split_source(arena, *source, spanned.span, &mut out),
            IntrinsicFn::Sub(_, vars) => check_sub_vars(arena, vars.as_deref(), spanned.span, &mut out),
            IntrinsicFn::Base64(arg) => check_base64_arg(arena, *arg, spanned.span, &mut out),
            IntrinsicFn::Join(delim, list) => check_join_args(arena, *delim, *list, spanned.span, &mut out),
            IntrinsicFn::Cidr(ip, count, bits) => {
                check_cidr_args(arena, *ip, *count, *bits, spanned.span, &mut out)
            }
            IntrinsicFn::FindInMap(map_name, k1, k2, _) => {
                check_find_in_map_args(arena, *map_name, *k1, *k2, has_lang_ext, spanned.span, &mut out)
            }
            _ => {}
        }
    }
    out
}

fn is_string_or_string_intrinsic(arena: &Arena, node_ref: NodeRef, allowed: &[&str]) -> bool {
    if !arena.is_valid(node_ref) {
        return true;
    }
    match arena.node(node_ref) {
        Node::String(_) => true,
        Node::Intrinsic(intrinsic) => allowed.contains(&cfn_function_name(intrinsic)),
        // A single-key map whose key is one of the allowed `Fn::*` names is
        // an intrinsic that the parser was unable to fold (typical when the
        // intrinsic's payload is itself an intrinsic — e.g.
        // `Fn::Sub: {Fn::Transform: ...}` or a syntactically unusual form
        // that the IR-level fold rejects). Conservatively trust the key name
        // rather than emit a shape false positive on the parent intrinsic.
        Node::Map(entries) if entries.len() == 1 => {
            let (key, _) = &entries[0];
            (key == "Ref" || key.starts_with("Fn::")) && allowed.contains(&key.as_str())
        }
        _ => false,
    }
}

fn check_select_source(arena: &Arena, source_ref: NodeRef, span: SourceSpan, out: &mut Vec<Diagnostic>) {
    if !arena.is_valid(source_ref) {
        return;
    }
    let valid = match arena.node(source_ref) {
        Node::List(_) => true,
        Node::Intrinsic(intrinsic) => SELECT_SOURCE_FNS.contains(&cfn_function_name(intrinsic)),
        Node::Map(entries) if entries.len() == 1 => {
            let (key, _) = &entries[0];
            (key == "Ref" || key.starts_with("Fn::")) && SELECT_SOURCE_FNS.contains(&key.as_str())
        }
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
        Node::Map(entries) if entries.len() == 1 => {
            let (key, _) = &entries[0];
            (key == "Ref" || key.starts_with("Fn::")) && IMPORT_VALUE_ARG_FNS.contains(&key.as_str())
        }
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

fn check_split_source(arena: &Arena, source_ref: NodeRef, span: SourceSpan, out: &mut Vec<Diagnostic>) {
    if !arena.is_valid(source_ref) {
        return;
    }
    if !is_string_or_string_intrinsic(arena, source_ref, SPLIT_SOURCE_FNS) {
        out.push(crate::make_parse_diagnostic(
            RULE_SPLIT_SHAPE,
            format!(
                "Fn::Split source (second element) must be a string or a string-producing intrinsic ({})",
                SPLIT_SOURCE_FNS.join(", ")
            ),
            span,
        ));
    }
}

fn check_sub_vars(
    arena: &Arena,
    vars: Option<&[(String, NodeRef)]>,
    span: SourceSpan,
    out: &mut Vec<Diagnostic>,
) {
    let Some(entries) = vars else {
        return;
    };
    for (name, value_ref) in entries {
        if !arena.is_valid(*value_ref) {
            continue;
        }
        // CloudFormation coerces scalar literals (numbers, booleans) to
        // strings when substituting them into a Sub template, so a
        // `number: 1` or `flag: true` pair is valid even though the
        // value is not literally a string.
        let valid = match arena.node(*value_ref) {
            Node::String(_) | Node::Int(_) | Node::Float(_) | Node::Bool(_) => true,
            Node::Intrinsic(intrinsic) => SUB_VAR_VALUE_FNS.contains(&cfn_function_name(intrinsic)),
            Node::Map(map_entries) if map_entries.len() == 1 => {
                let (key, _) = &map_entries[0];
                (key == "Ref" || key.starts_with("Fn::")) && SUB_VAR_VALUE_FNS.contains(&key.as_str())
            }
            _ => false,
        };
        if !valid {
            out.push(crate::make_parse_diagnostic(
                RULE_SUB_SHAPE,
                format!(
                    "Fn::Sub variable '{}' must resolve to a string — provide a string literal, scalar (number/boolean), or a string-producing intrinsic ({})",
                    name,
                    SUB_VAR_VALUE_FNS.join(", ")
                ),
                span,
            ));
        }
    }
}

fn check_base64_arg(arena: &Arena, arg_ref: NodeRef, span: SourceSpan, out: &mut Vec<Diagnostic>) {
    if !arena.is_valid(arg_ref) {
        return;
    }
    if !is_string_or_string_intrinsic(arena, arg_ref, BASE64_ARG_FNS) {
        out.push(crate::make_parse_diagnostic(
            RULE_BASE64_SHAPE,
            format!(
                "Fn::Base64 argument must be a string or a string-producing intrinsic ({})",
                BASE64_ARG_FNS.join(", ")
            ),
            span,
        ));
    }
}

fn check_join_args(
    arena: &Arena,
    delim_ref: NodeRef,
    list_ref: NodeRef,
    span: SourceSpan,
    out: &mut Vec<Diagnostic>,
) {
    if arena.is_valid(delim_ref) && !matches!(arena.node(delim_ref), Node::String(_)) {
        out.push(crate::make_parse_diagnostic(
            RULE_JOIN_SHAPE,
            "Fn::Join delimiter (first element) must be a string literal".into(),
            span,
        ));
    }
    if !arena.is_valid(list_ref) {
        return;
    }
    match arena.node(list_ref) {
        Node::List(items) => {
            for item in items.clone() {
                if !is_string_or_string_intrinsic(arena, item, JOIN_ITEM_FNS) {
                    out.push(crate::make_parse_diagnostic(
                        RULE_JOIN_SHAPE,
                        format!(
                            "Fn::Join list element must be a string or a string-producing intrinsic ({})",
                            JOIN_ITEM_FNS.join(", ")
                        ),
                        span,
                    ));
                    break;
                }
            }
        }
        Node::Intrinsic(intrinsic) => {
            if !JOIN_LIST_FNS.contains(&cfn_function_name(intrinsic)) {
                out.push(crate::make_parse_diagnostic(
                    RULE_JOIN_SHAPE,
                    format!(
                        "Fn::Join list (second element) must be an array or a list-producing intrinsic ({})",
                        JOIN_LIST_FNS.join(", ")
                    ),
                    span,
                ));
            }
        }
        Node::Map(entries) if entries.len() == 1 => {
            let (key, _) = &entries[0];
            let recognised = (key == "Ref" || key.starts_with("Fn::"))
                && JOIN_LIST_FNS.contains(&key.as_str());
            if !recognised {
                out.push(crate::make_parse_diagnostic(
                    RULE_JOIN_SHAPE,
                    format!(
                        "Fn::Join list (second element) must be an array or a list-producing intrinsic ({})",
                        JOIN_LIST_FNS.join(", ")
                    ),
                    span,
                ));
            }
        }
        _ => {
            out.push(crate::make_parse_diagnostic(
                RULE_JOIN_SHAPE,
                format!(
                    "Fn::Join list (second element) must be an array or a list-producing intrinsic ({})",
                    JOIN_LIST_FNS.join(", ")
                ),
                span,
            ));
        }
    }
}

fn check_cidr_args(
    arena: &Arena,
    ip_ref: NodeRef,
    count_ref: NodeRef,
    bits_ref: NodeRef,
    span: SourceSpan,
    out: &mut Vec<Diagnostic>,
) {
    if arena.is_valid(ip_ref)
        && !is_string_or_string_intrinsic(arena, ip_ref, CIDR_OP_FNS)
    {
        out.push(crate::make_parse_diagnostic(
            RULE_CIDR_SHAPE,
            format!(
                "Fn::Cidr ipBlock (first element) must be a string or a string-producing intrinsic ({})",
                CIDR_OP_FNS.join(", ")
            ),
            span,
        ));
    }
    for (label, node_ref) in [("count (second element)", count_ref), ("cidrBits (third element)", bits_ref)] {
        if !arena.is_valid(node_ref) {
            continue;
        }
        let valid = match arena.node(node_ref) {
            Node::Int(_) | Node::String(_) => true,
            Node::Intrinsic(intrinsic) => CIDR_OP_FNS.contains(&cfn_function_name(intrinsic)),
            Node::Map(entries) if entries.len() == 1 => {
                let (key, _) = &entries[0];
                (key == "Ref" || key.starts_with("Fn::")) && CIDR_OP_FNS.contains(&key.as_str())
            }
            _ => false,
        };
        if !valid {
            out.push(crate::make_parse_diagnostic(
                RULE_CIDR_SHAPE,
                format!(
                    "Fn::Cidr {} must be an integer or a string-producing intrinsic ({})",
                    label,
                    CIDR_OP_FNS.join(", ")
                ),
                span,
            ));
        }
    }
}

fn check_find_in_map_args(
    arena: &Arena,
    map_name_ref: NodeRef,
    k1_ref: NodeRef,
    k2_ref: NodeRef,
    has_lang_ext: bool,
    span: SourceSpan,
    out: &mut Vec<Diagnostic>,
) {
    let allowed: &[&str] = if has_lang_ext { FIND_IN_MAP_OP_FNS_EXT } else { FIND_IN_MAP_OP_FNS };
    for (label, node_ref) in [
        ("MapName (first element)", map_name_ref),
        ("TopLevelKey (second element)", k1_ref),
        ("SecondLevelKey (third element)", k2_ref),
    ] {
        if !arena.is_valid(node_ref) {
            continue;
        }
        // Map keys are stringified by CloudFormation, so integer and float
        // literals are accepted in addition to string and the allowed
        // string-producing intrinsics. Lists, maps, booleans, and disallowed
        // intrinsics are rejected. Single-key maps whose key is an allowed
        // intrinsic name are accepted as unfolded intrinsics — the parser
        // can leave intrinsics in raw map form when their payload is itself
        // an unusual intrinsic shape.
        let valid = match arena.node(node_ref) {
            Node::String(_) | Node::Int(_) | Node::Float(_) => true,
            Node::Intrinsic(intrinsic) => allowed.contains(&cfn_function_name(intrinsic)),
            Node::Map(entries) if entries.len() == 1 => {
                let (key, _) = &entries[0];
                (key == "Ref" || key.starts_with("Fn::")) && allowed.contains(&key.as_str())
            }
            _ => false,
        };
        if !valid {
            out.push(crate::make_parse_diagnostic(
                RULE_FIND_IN_MAP_SHAPE,
                format!(
                    "Fn::FindInMap {} must be a string, integer, or one of {}",
                    label,
                    allowed.join(", ")
                ),
                span,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;

    fn parse_and_validate(src: &str) -> Vec<Diagnostic> {
        let ir = parser::parse(src.as_bytes()).expect("parse");
        validate_intrinsic_arg_shapes(&ir.arena, &ir.transforms)
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
