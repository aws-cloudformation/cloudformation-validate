use crate::consts::*;
use crate::defect::ParseDefect;
use crate::ir::*;

const RULE_LENGTH_SHAPE: &str = "E1030";
const RULE_TO_JSON_STRING_SHAPE: &str = "E1031";

const LENGTH_ALLOWED_FNS: &[&str] = &[FN_REF, FN_FIND_IN_MAP, FN_SPLIT, FN_IF, FN_GET_AZS];

const TO_JSON_STRING_ALLOWED_FNS: &[&str] =
    &[FN_FIND_IN_MAP, FN_GET_ATT, FN_GET_AZS, FN_IF, FN_SELECT, FN_SPLIT, FN_REF];

pub fn validate_lang_ext_parameter_shapes(arena: &Arena, transforms: &[String]) -> Vec<ParseDefect> {
    if !transforms.iter().any(|t| t == TRANSFORM_LANGUAGE_EXTENSIONS) {
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
            IntrinsicFn::Length(arg_ref) => check_length_arg(arena, *arg_ref, spanned, &mut out),
            IntrinsicFn::ToJsonString(arg_ref) => check_to_json_string_arg(arena, *arg_ref, spanned, &mut out),
            _ => {}
        }
    }
    out
}

fn check_length_arg(arena: &Arena, arg_ref: NodeRef, parent: &SpannedNode, out: &mut Vec<ParseDefect>) {
    let arg_node = arena.node(arg_ref);
    match arg_node {
        Node::List(_) => {}
        Node::Intrinsic(inner) => {
            let fn_name = cfn_function_name(inner);
            if !LENGTH_ALLOWED_FNS.contains(&fn_name) {
                out.push(crate::make_parse_defect_at(
                    RULE_LENGTH_SHAPE,
                    format!(
                        "'{}' is not supported as an argument to 'Fn::Length' - must be an array or one of {}",
                        fn_name,
                        LENGTH_ALLOWED_FNS.join(", ")
                    ),
                    parent.span,
                    &arena.get(arg_ref).path,
                ));
            }
        }
        _ => {
            out.push(crate::make_parse_defect_at(
                RULE_LENGTH_SHAPE,
                "Fn::Length argument must be an array or a list-producing intrinsic".to_string(),
                parent.span,
                &arena.get(arg_ref).path,
            ));
        }
    }
}

fn check_to_json_string_arg(arena: &Arena, arg_ref: NodeRef, parent: &SpannedNode, out: &mut Vec<ParseDefect>) {
    let arg_node = arena.node(arg_ref);
    match arg_node {
        Node::List(items) if !items.is_empty() => {}
        Node::Map(entries) if !entries.is_empty() => {}
        Node::Intrinsic(inner) => {
            let fn_name = cfn_function_name(inner);
            if !TO_JSON_STRING_ALLOWED_FNS.contains(&fn_name) {
                out.push(crate::make_parse_defect_at(
                    RULE_TO_JSON_STRING_SHAPE,
                    format!(
                        "'{}' is not supported as an argument to 'Fn::ToJsonString' - must be a non-empty array/object or one of {}",
                        fn_name,
                        TO_JSON_STRING_ALLOWED_FNS.join(", ")
                    ),
                    parent.span,
                    &arena.get(arg_ref).path,
                ));
            }
        }
        _ => {
            out.push(crate::make_parse_defect_at(
                RULE_TO_JSON_STRING_SHAPE,
                "Fn::ToJsonString argument must be a non-empty array or object, or a supported intrinsic".to_string(),
                parent.span,
                &arena.get(arg_ref).path,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::SemanticModel;

    /// The shape-check rule IDs must be present in the rule registry; a
    /// diagnostic carrying an unregistered ID panics while the report is built.
    /// Exercise the full public path (parse → build → serialize) so the emit
    /// path is covered, not just the arena-level helper.
    fn rule_ids(template: &str) -> Vec<String> {
        let model = SemanticModel::from_bytes(template.as_bytes()).expect("model builds without panicking");
        model.diagnostics.iter().map(|d| d.rule_id.clone()).collect()
    }

    #[test]
    fn length_shape_error_does_not_panic_and_reports_e1030() {
        let template = "\
Transform: AWS::LanguageExtensions
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Length \"not-a-list\"
";
        assert!(rule_ids(template).iter().any(|id| id == "E1030"), "expected E1030 for a scalar Fn::Length argument");
    }

    #[test]
    fn to_json_string_shape_error_does_not_panic_and_reports_e1031() {
        // Fn::ToJsonString over a disallowed function (Fn::Base64 is not in the
        // allowed set) must produce a shape error, not a panic.
        let template = "\
Transform: AWS::LanguageExtensions
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName:
        Fn::ToJsonString:
          Fn::Base64: \"abc\"
";
        assert!(
            rule_ids(template).iter().any(|id| id == "E1031"),
            "expected E1031 for an unsupported Fn::ToJsonString argument"
        );
    }

    #[test]
    fn shape_checks_are_gated_on_language_extensions_transform() {
        // Without the transform, Fn::Length/Fn::ToJsonString are rejected by the
        // transform-required check, not the argument-shape check.
        let template = "\
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Length \"not-a-list\"
";
        let ids = rule_ids(template);
        assert!(!ids.iter().any(|id| id == "E1030"), "E1030 must not fire without the LanguageExtensions transform");
    }
}
