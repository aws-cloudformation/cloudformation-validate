//! Parameter-shape validation for `AWS::LanguageExtensions` intrinsics.
//!
//! `Fn::Length` (E1030), `Fn::ToJsonString` (E1031), and
//! `Fn::GetStackOutput` (E1033) each have a published per-function shape
//! that CloudFormation enforces at deploy time:
//!
//! * `Fn::Length` argument must be an array, or a `Ref`/`Fn::FindInMap`/
//!   `Fn::Split`/`Fn::If`/`Fn::GetAZs` that resolves to one.
//! * `Fn::ToJsonString` argument must be a non-empty array or object, or
//!   one of `Fn::FindInMap`/`Fn::GetAtt`/`Fn::GetAZs`/`Fn::If`/`Fn::Select`/
//!   `Fn::Split`/`Ref`.
//! * `Fn::GetStackOutput` argument must be an object with required
//!   `StackName` and `OutputName` keys, optional `Region` and `RoleArn`,
//!   each a string-producing scalar or an allowed string-returning
//!   intrinsic.
//!
//! This module emits diagnostics under the canonical rule IDs for those
//! shape failures. The transform-missing case is handled separately by
//! the resolver and emits the same `E1033` ID — this pass only runs against
//! post-transform templates, so the two never double-report.

use crate::consts::*;
use crate::ir::*;
use diagnostics::{Diagnostic, SourceSpan};

const RULE_LENGTH_SHAPE: &str = "E1030";
const RULE_TO_JSON_STRING_SHAPE: &str = "E1031";
const RULE_GET_STACK_OUTPUT_SHAPE: &str = "E1033";

const REQUIRED_GET_STACK_OUTPUT_KEYS: &[&str] = &["StackName", "OutputName"];
const ALLOWED_GET_STACK_OUTPUT_KEYS: &[&str] = &["StackName", "OutputName", "Region", "RoleArn"];

/// Intrinsics that resolve to an array — accepted as `Fn::Length` argument
/// even when the literal node is not a `Node::List`.
const LENGTH_ARRAY_RETURNING_FNS: &[&str] = &[FN_REF, FN_FIND_IN_MAP, FN_SPLIT, FN_IF, FN_GET_AZS];

/// Intrinsics whose return value can be passed to `Fn::ToJsonString`.
const TO_JSON_STRING_ARG_FNS: &[&str] =
    &[FN_FIND_IN_MAP, FN_GET_ATT, FN_GET_AZS, FN_IF, FN_SELECT, FN_SPLIT, FN_REF];

/// Intrinsics whose return value is a string and may appear inside
/// `Fn::GetStackOutput`'s `StackName`/`OutputName`/`Region`/`RoleArn` slots.
const GET_STACK_OUTPUT_VALUE_FNS: &[&str] = &[
    FN_BASE64,
    FN_FIND_IN_MAP,
    FN_GET_ATT,
    FN_IF,
    FN_IMPORT_VALUE,
    FN_JOIN,
    FN_SELECT,
    FN_SUB,
    FN_REF,
];

pub fn validate_lang_ext_parameter_shapes(arena: &Arena, transforms: &[String]) -> Vec<Diagnostic> {
    let has_lang_ext = transforms.iter().any(|t| t == TRANSFORM_LANGUAGE_EXTENSIONS);
    if !has_lang_ext {
        // Without the transform, the resolver already emits the
        // `E1033` transform-missing diagnostic for `Fn::GetStackOutput`;
        // running the parameter-shape rules in addition would double-report
        // the failure under the same ID.
        return Vec::new();
    }

    let mut out = Vec::new();
    for idx in 0..arena.len() {
        let node_ref = idx as NodeRef;
        let spanned = arena.get(node_ref);
        let Node::Intrinsic(intrinsic) = &spanned.node else {
            continue;
        };
        match intrinsic {
            IntrinsicFn::Length(arg) => check_length_argument(arena, *arg, spanned.span, &mut out),
            IntrinsicFn::ToJsonString(arg) => check_to_json_string_argument(arena, *arg, spanned.span, &mut out),
            IntrinsicFn::GetStackOutput(arg) => check_get_stack_output_argument(arena, *arg, spanned.span, &mut out),
            _ => {}
        }
    }
    out
}

fn check_length_argument(arena: &Arena, arg_ref: NodeRef, span: SourceSpan, out: &mut Vec<Diagnostic>) {
    if !arena.is_valid(arg_ref) {
        return;
    }
    let valid = match arena.node(arg_ref) {
        Node::List(_) => true,
        Node::Intrinsic(intrinsic) => LENGTH_ARRAY_RETURNING_FNS.contains(&cfn_function_name(intrinsic)),
        _ => false,
    };
    if !valid {
        out.push(crate::make_parse_diagnostic(
            RULE_LENGTH_SHAPE,
            format!(
                "Fn::Length argument must be an array or one of: {}",
                LENGTH_ARRAY_RETURNING_FNS.join(", ")
            ),
            span,
        ));
    }
}

fn check_to_json_string_argument(arena: &Arena, arg_ref: NodeRef, span: SourceSpan, out: &mut Vec<Diagnostic>) {
    if !arena.is_valid(arg_ref) {
        return;
    }
    match arena.node(arg_ref) {
        Node::List(items) if items.is_empty() => {
            out.push(crate::make_parse_diagnostic(
                RULE_TO_JSON_STRING_SHAPE,
                "Fn::ToJsonString argument must be a non-empty array or object".to_string(),
                span,
            ));
        }
        Node::Map(entries) if entries.is_empty() => {
            out.push(crate::make_parse_diagnostic(
                RULE_TO_JSON_STRING_SHAPE,
                "Fn::ToJsonString argument must be a non-empty array or object".to_string(),
                span,
            ));
        }
        Node::List(_) | Node::Map(_) => {}
        Node::Intrinsic(intrinsic) => {
            if !TO_JSON_STRING_ARG_FNS.contains(&cfn_function_name(intrinsic)) {
                out.push(crate::make_parse_diagnostic(
                    RULE_TO_JSON_STRING_SHAPE,
                    format!(
                        "Fn::ToJsonString argument must be an array, object, or one of: {}",
                        TO_JSON_STRING_ARG_FNS.join(", ")
                    ),
                    span,
                ));
            }
        }
        _ => {
            out.push(crate::make_parse_diagnostic(
                RULE_TO_JSON_STRING_SHAPE,
                "Fn::ToJsonString argument must be a non-empty array or object".to_string(),
                span,
            ));
        }
    }
}

fn check_get_stack_output_argument(arena: &Arena, arg_ref: NodeRef, span: SourceSpan, out: &mut Vec<Diagnostic>) {
    if !arena.is_valid(arg_ref) {
        return;
    }
    match arena.node(arg_ref) {
        Node::Map(entries) => {
            check_get_stack_output_object(arena, entries, span, out);
        }
        // The legacy `[StackName, OutputName]` array form is still accepted
        // for backwards compatibility — only validate that both entries are
        // string-typed values.
        Node::List(items) if items.len() == 2 => {
            for (idx, item_ref) in items.iter().enumerate() {
                if !is_string_or_string_intrinsic(arena, *item_ref) {
                    out.push(crate::make_parse_diagnostic(
                        RULE_GET_STACK_OUTPUT_SHAPE,
                        format!("Fn::GetStackOutput element {} must be a string or string-producing intrinsic", idx),
                        span,
                    ));
                }
            }
        }
        _ => {
            out.push(crate::make_parse_diagnostic(
                RULE_GET_STACK_OUTPUT_SHAPE,
                "Fn::GetStackOutput value must be an object with StackName and OutputName".to_string(),
                span,
            ));
        }
    }
}

fn check_get_stack_output_object(
    arena: &Arena,
    entries: &[(String, NodeRef)],
    span: SourceSpan,
    out: &mut Vec<Diagnostic>,
) {
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for (key, value) in entries {
        if !ALLOWED_GET_STACK_OUTPUT_KEYS.contains(&key.as_str()) {
            out.push(crate::make_parse_diagnostic(
                RULE_GET_STACK_OUTPUT_SHAPE,
                format!(
                    "Fn::GetStackOutput contains unsupported key '{}'; allowed keys: {}",
                    key,
                    ALLOWED_GET_STACK_OUTPUT_KEYS.join(", ")
                ),
                span,
            ));
            continue;
        }
        seen.insert(key.as_str());
        if !is_string_or_string_intrinsic(arena, *value) {
            out.push(crate::make_parse_diagnostic(
                RULE_GET_STACK_OUTPUT_SHAPE,
                format!("Fn::GetStackOutput.{} must be a string or string-producing intrinsic", key),
                span,
            ));
        }
    }
    for required in REQUIRED_GET_STACK_OUTPUT_KEYS {
        if !seen.contains(required) {
            out.push(crate::make_parse_diagnostic(
                RULE_GET_STACK_OUTPUT_SHAPE,
                format!("Fn::GetStackOutput is missing required key '{}'", required),
                span,
            ));
        }
    }
}

fn is_string_or_string_intrinsic(arena: &Arena, node_ref: NodeRef) -> bool {
    if !arena.is_valid(node_ref) {
        return false;
    }
    match arena.node(node_ref) {
        Node::String(_) | Node::Int(_) | Node::Float(_) | Node::Bool(_) => true,
        Node::Intrinsic(intrinsic) => GET_STACK_OUTPUT_VALUE_FNS.contains(&cfn_function_name(intrinsic)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;

    fn parse_and_validate(src: &str) -> Vec<Diagnostic> {
        let ir = parser::parse(src.as_bytes()).expect("parse");
        validate_lang_ext_parameter_shapes(&ir.arena, &ir.transforms)
    }

    #[test]
    fn length_with_array_argument_passes() {
        let diags = parse_and_validate(
            r#"{
                "Transform": "AWS::LanguageExtensions",
                "Resources": {"R": {"Type": "T", "Properties": {"V": {"Fn::Length": ["a", "b"]}}}}
            }"#,
        );
        assert!(diags.is_empty(), "unexpected: {:?}", diags);
    }

    #[test]
    fn length_with_string_argument_emits_e1030() {
        let diags = parse_and_validate(
            r#"{
                "Transform": "AWS::LanguageExtensions",
                "Resources": {"R": {"Type": "T", "Properties": {"V": {"Fn::Length": "not-a-list"}}}}
            }"#,
        );
        assert_eq!(diags.iter().filter(|d| d.rule_id == RULE_LENGTH_SHAPE).count(), 1, "{:?}", diags);
    }

    #[test]
    fn length_with_ref_argument_passes() {
        let diags = parse_and_validate(
            r#"{
                "Transform": "AWS::LanguageExtensions",
                "Parameters": {"P": {"Type": "CommaDelimitedList"}},
                "Resources": {"R": {"Type": "T", "Properties": {"V": {"Fn::Length": {"Ref": "P"}}}}}
            }"#,
        );
        assert!(diags.iter().all(|d| d.rule_id != RULE_LENGTH_SHAPE), "{:?}", diags);
    }

    #[test]
    fn to_json_string_with_object_passes() {
        let diags = parse_and_validate(
            r#"{
                "Transform": "AWS::LanguageExtensions",
                "Resources": {"R": {"Type": "T", "Properties": {"V": {"Fn::ToJsonString": {"a": 1}}}}}
            }"#,
        );
        assert!(diags.is_empty(), "unexpected: {:?}", diags);
    }

    #[test]
    fn to_json_string_with_string_emits_e1031() {
        let diags = parse_and_validate(
            r#"{
                "Transform": "AWS::LanguageExtensions",
                "Resources": {"R": {"Type": "T", "Properties": {"V": {"Fn::ToJsonString": "literal"}}}}
            }"#,
        );
        assert_eq!(diags.iter().filter(|d| d.rule_id == RULE_TO_JSON_STRING_SHAPE).count(), 1, "{:?}", diags);
    }

    #[test]
    fn to_json_string_with_empty_array_emits_e1031() {
        let diags = parse_and_validate(
            r#"{
                "Transform": "AWS::LanguageExtensions",
                "Resources": {"R": {"Type": "T", "Properties": {"V": {"Fn::ToJsonString": []}}}}
            }"#,
        );
        assert_eq!(diags.iter().filter(|d| d.rule_id == RULE_TO_JSON_STRING_SHAPE).count(), 1, "{:?}", diags);
    }

    #[test]
    fn get_stack_output_object_with_required_keys_passes() {
        let diags = parse_and_validate(
            r#"{
                "Transform": "AWS::LanguageExtensions",
                "Resources": {"R": {"Type": "T", "Properties": {"V": {
                    "Fn::GetStackOutput": {
                        "StackName": "producer-stack",
                        "OutputName": "MyOutput"
                    }
                }}}}
            }"#,
        );
        assert!(diags.is_empty(), "unexpected: {:?}", diags);
    }

    #[test]
    fn get_stack_output_missing_output_name_emits_e1033() {
        let diags = parse_and_validate(
            r#"{
                "Transform": "AWS::LanguageExtensions",
                "Resources": {"R": {"Type": "T", "Properties": {"V": {
                    "Fn::GetStackOutput": {"StackName": "producer-stack"}
                }}}}
            }"#,
        );
        assert!(
            diags
                .iter()
                .any(|d| d.rule_id == RULE_GET_STACK_OUTPUT_SHAPE && d.message.contains("OutputName")),
            "{:?}",
            diags
        );
    }

    #[test]
    fn get_stack_output_unknown_key_emits_e1033() {
        let diags = parse_and_validate(
            r#"{
                "Transform": "AWS::LanguageExtensions",
                "Resources": {"R": {"Type": "T", "Properties": {"V": {
                    "Fn::GetStackOutput": {
                        "StackName": "producer-stack",
                        "OutputName": "MyOutput",
                        "Bogus": "x"
                    }
                }}}}
            }"#,
        );
        assert!(
            diags
                .iter()
                .any(|d| d.rule_id == RULE_GET_STACK_OUTPUT_SHAPE && d.message.contains("Bogus")),
            "{:?}",
            diags
        );
    }

    #[test]
    fn no_diagnostics_without_lang_ext_transform() {
        // Without the LanguageExtensions transform the resolver emits the
        // `E1033` transform-missing diagnostic; this pass should not duplicate it.
        let diags = parse_and_validate(
            r#"{
                "Resources": {"R": {"Type": "T", "Properties": {"V": {
                    "Fn::GetStackOutput": {"StackName": "x"}
                }}}}
            }"#,
        );
        assert!(diags.is_empty(), "{:?}", diags);
    }
}
