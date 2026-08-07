//! Parse-time validation that each intrinsic's operands match CloudFormation's
//! published per-function operand schema. Only operands that are themselves
//! intrinsics are checked here - plain scalars and collections of the wrong
//! type are the schema validator's responsibility.

use crate::consts::*;
use crate::defect::ParseDefect;
use crate::ir::cfn_function_name;
use crate::ir::*;

const SELECT_SOURCE_FUNCTIONS: &[&str] = &[FN_FIND_IN_MAP, FN_GET_ATT, FN_GET_AZS, FN_IF, FN_SPLIT, FN_CIDR, FN_REF];

// The Fn::Select *index* accepts a narrower set than the source: only
// reference/lookup functions that can produce an integer, plus Fn::Length under
// the LanguageExtensions transform (from the published select schema's
// if/then/else on the transform).
const SELECT_INDEX_FUNCTIONS: &[&str] = &[FN_REF, FN_FIND_IN_MAP];
const SELECT_INDEX_FUNCTIONS_EXT: &[&str] = &[FN_REF, FN_FIND_IN_MAP, FN_LENGTH];

const SPLIT_SOURCE_FUNCTIONS: &[&str] =
    &[FN_BASE64, FN_FIND_IN_MAP, FN_GET_ATT, FN_GET_AZS, FN_IF, FN_IMPORT_VALUE, FN_JOIN, FN_SELECT, FN_SUB, FN_REF];

const SUB_VARIABLE_FUNCTIONS: &[&str] = &[
    FN_BASE64,
    FN_FIND_IN_MAP,
    FN_GET_ATT,
    FN_GET_AZS,
    FN_GET_STACK_OUTPUT,
    FN_IF,
    FN_IMPORT_VALUE,
    FN_JOIN,
    FN_SELECT,
    FN_SUB,
    FN_TO_JSON_STRING,
    FN_REF,
    FN_TRANSFORM,
];

const BASE64_ARGUMENT_FUNCTIONS: &[&str] = &[
    FN_REF,
    FN_BASE64,
    FN_CIDR,
    FN_CONTAINS,
    FN_FIND_IN_MAP,
    FN_FOR_EACH,
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
];

const JOIN_DELIMITER_FUNCTIONS: &[&str] = &[];

const JOIN_LIST_FUNCTIONS: &[&str] = &[FN_CIDR, FN_FIND_IN_MAP, FN_GET_ATT, FN_IF, FN_SPLIT, FN_REF];

const JOIN_ITEM_FUNCTIONS: &[&str] = &[
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

const CIDR_OPERAND_FUNCTIONS: &[&str] =
    &[FN_FIND_IN_MAP, FN_GET_ATT, FN_IF, FN_IMPORT_VALUE, FN_SELECT, FN_SUB, FN_REF];

const FINDINMAP_KEY_FUNCTIONS: &[&str] = &[FN_REF, FN_FIND_IN_MAP];

const FINDINMAP_KEY_FUNCTIONS_EXT: &[&str] =
    &[FN_REF, FN_FIND_IN_MAP, FN_JOIN, FN_SUB, FN_IF, FN_SELECT, FN_LENGTH, FN_TO_JSON_STRING];

pub fn validate_intrinsic_arg_shapes(arena: &Arena, transforms: &[String]) -> Vec<ParseDefect> {
    let has_lang_ext = transforms.iter().any(|t| t == TRANSFORM_LANGUAGE_EXTENSIONS);
    let mut out = Vec::new();

    for idx in 0..arena.len() {
        let node_ref = idx as NodeRef;
        let Node::Intrinsic(intrinsic) = arena.node(node_ref) else {
            continue;
        };

        // Fn::GetAZs with a literal argument: it must be the empty string
        // (current region) or a known region name. The finding is attributed
        // to the enclosing Fn::Select's rule when nested (its usual usage)
        // and to the GetAZs rule when standalone.
        if let IntrinsicFn::GetAZs(arg_ref) = intrinsic
            && let Node::String(region) = arena.node(*arg_ref)
            && !region.is_empty()
            && !crate::regions::is_known_region(region)
        {
            let spanned = arena.get(*arg_ref);
            let rule_id = if spanned.path.contains(FN_SELECT) { "E1017" } else { "E1015" };
            out.push(crate::make_parse_defect_at(
                rule_id,
                format!("'{}' is not a valid region for Fn::GetAZs (use '' for the current region)", region),
                spanned.span,
                &spanned.path,
            ));
        }

        for (rule_id, operand_ref, allowed_functions) in operand_constraints(intrinsic, arena, has_lang_ext) {
            if let Node::Intrinsic(operand_fn) = arena.node(operand_ref) {
                let operand_name = cfn_function_name(operand_fn);
                if !allowed_functions.contains(&operand_name) {
                    // Anchor at the offending operand's build path so that when its
                    // own byte span is unassigned, span resolution walks up to the
                    // nearest enclosing element rather than leaving it unlocated.
                    out.push(crate::make_parse_defect_at(
                        rule_id,
                        format!(
                            "'{}' is not supported as an argument to '{}'",
                            operand_name,
                            cfn_function_name(intrinsic)
                        ),
                        arena.span(operand_ref),
                        &arena.get(operand_ref).path,
                    ));
                }
            }
        }
    }
    out
}

fn operand_constraints(
    intrinsic: &IntrinsicFn,
    arena: &Arena,
    has_lang_ext: bool,
) -> Vec<(&'static str, NodeRef, &'static [&'static str])> {
    match intrinsic {
        IntrinsicFn::Select(index, source) => {
            let index_allowed = if has_lang_ext { SELECT_INDEX_FUNCTIONS_EXT } else { SELECT_INDEX_FUNCTIONS };
            vec![("E1017", *index, index_allowed), ("E1017", *source, SELECT_SOURCE_FUNCTIONS)]
        }
        IntrinsicFn::Split(_, source) => vec![("E1018", *source, SPLIT_SOURCE_FUNCTIONS)],
        IntrinsicFn::Sub(_, Some(variables)) => {
            variables.iter().map(|(_, value)| ("E1019", *value, SUB_VARIABLE_FUNCTIONS)).collect()
        }
        IntrinsicFn::Base64(argument) => vec![("E1021", *argument, BASE64_ARGUMENT_FUNCTIONS)],
        IntrinsicFn::Join(delimiter, items) => {
            let mut constraints =
                vec![("E1022", *delimiter, JOIN_DELIMITER_FUNCTIONS), ("E1022", *items, JOIN_LIST_FUNCTIONS)];
            if let Some(item_refs) = arena.as_list(*items) {
                constraints.extend(item_refs.iter().map(|item| ("E1022", *item, JOIN_ITEM_FUNCTIONS)));
            }
            constraints
        }
        IntrinsicFn::Cidr(ip_block, count, cidr_bits) => {
            vec![
                ("E1024", *ip_block, CIDR_OPERAND_FUNCTIONS),
                ("E1024", *count, CIDR_OPERAND_FUNCTIONS),
                ("E1024", *cidr_bits, CIDR_OPERAND_FUNCTIONS),
            ]
        }
        IntrinsicFn::FindInMap(map_name, top_level_key, second_level_key, _) => {
            let allowed = if has_lang_ext { FINDINMAP_KEY_FUNCTIONS_EXT } else { FINDINMAP_KEY_FUNCTIONS };
            vec![
                ("E1011", *map_name, allowed),
                ("E1011", *top_level_key, allowed),
                ("E1011", *second_level_key, allowed),
            ]
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROPERTY_PATH: &str = "Resources/R/Properties/X";

    fn alloc_string(arena: &mut Arena, value: &str) -> NodeRef {
        arena.alloc(SpannedNode { node: Node::String(value.into()), span: UNKNOWN_SPAN, path: PROPERTY_PATH.into() })
    }

    fn alloc_intrinsic(arena: &mut Arena, intrinsic: IntrinsicFn) -> NodeRef {
        arena.alloc(SpannedNode { node: Node::Intrinsic(intrinsic), span: UNKNOWN_SPAN, path: PROPERTY_PATH.into() })
    }

    fn alloc_string_list(arena: &mut Arena, values: &[&str]) -> NodeRef {
        let items: Vec<NodeRef> = values.iter().map(|v| alloc_string(arena, v)).collect();
        arena.alloc(SpannedNode { node: Node::List(items), span: UNKNOWN_SPAN, path: PROPERTY_PATH.into() })
    }

    fn alloc_sub(arena: &mut Arena) -> NodeRef {
        alloc_intrinsic(arena, IntrinsicFn::Sub("${x}".into(), None))
    }

    fn alloc_cidr(arena: &mut Arena) -> NodeRef {
        let block = alloc_string(arena, "10.0.0.0/16");
        let count = arena.alloc(SpannedNode { node: Node::Int(6), span: UNKNOWN_SPAN, path: PROPERTY_PATH.into() });
        alloc_intrinsic(arena, IntrinsicFn::Cidr(block, count, count))
    }

    #[test]
    fn select_index_disallowed_function_fires() {
        // Fn::Base64 cannot produce the Select index.
        let mut arena = Arena::new();
        let arg = alloc_string(&mut arena, "0");
        let index = alloc_intrinsic(&mut arena, IntrinsicFn::Base64(arg));
        let source = alloc_string_list(&mut arena, &["a", "b"]);
        alloc_intrinsic(&mut arena, IntrinsicFn::Select(index, source));
        let diags = validate_intrinsic_arg_shapes(&arena, &[]);
        assert_eq!(diags.len(), 1, "{:?}", diags);
        assert_eq!(diags[0].rule_id, "E1017");
        assert_eq!(diags[0].message, "'Fn::Base64' is not supported as an argument to 'Fn::Select'");
    }

    #[test]
    fn select_index_ref_is_accepted() {
        let mut arena = Arena::new();
        let index = alloc_intrinsic(&mut arena, IntrinsicFn::Ref("IndexParam".into()));
        let source = alloc_string_list(&mut arena, &["a", "b"]);
        alloc_intrinsic(&mut arena, IntrinsicFn::Select(index, source));
        assert!(validate_intrinsic_arg_shapes(&arena, &[]).is_empty());
    }

    #[test]
    fn select_index_length_requires_language_extensions() {
        let mut arena = Arena::new();
        let list = alloc_string_list(&mut arena, &["a"]);
        let index = alloc_intrinsic(&mut arena, IntrinsicFn::Length(list));
        let source = alloc_string_list(&mut arena, &["a", "b"]);
        alloc_intrinsic(&mut arena, IntrinsicFn::Select(index, source));
        assert_eq!(validate_intrinsic_arg_shapes(&arena, &[]).len(), 1, "Length index needs the transform");
        assert!(
            validate_intrinsic_arg_shapes(&arena, &[TRANSFORM_LANGUAGE_EXTENSIONS.to_string()]).is_empty(),
            "Length index is allowed with LanguageExtensions"
        );
    }

    #[test]
    fn select_source_sub_fires() {
        let mut arena = Arena::new();
        let index = arena.alloc(SpannedNode { node: Node::Int(0), span: UNKNOWN_SPAN, path: PROPERTY_PATH.into() });
        let source = alloc_sub(&mut arena);
        alloc_intrinsic(&mut arena, IntrinsicFn::Select(index, source));

        let diags = validate_intrinsic_arg_shapes(&arena, &[]);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule_id, "E1017");
        assert_eq!(diags[0].message, "'Fn::Sub' is not supported as an argument to 'Fn::Select'");
    }

    #[test]
    fn select_source_split_is_allowed() {
        let mut arena = Arena::new();
        let index = arena.alloc(SpannedNode { node: Node::Int(0), span: UNKNOWN_SPAN, path: PROPERTY_PATH.into() });
        let delimiter = alloc_string(&mut arena, ",");
        let split_input = alloc_string(&mut arena, "a,b");
        let source = alloc_intrinsic(&mut arena, IntrinsicFn::Split(delimiter, split_input));
        alloc_intrinsic(&mut arena, IntrinsicFn::Select(index, source));

        assert!(validate_intrinsic_arg_shapes(&arena, &[]).is_empty());
    }

    #[test]
    fn select_source_plain_list_is_allowed() {
        let mut arena = Arena::new();
        let index = arena.alloc(SpannedNode { node: Node::Int(0), span: UNKNOWN_SPAN, path: PROPERTY_PATH.into() });
        let item = alloc_string(&mut arena, "a");
        let source =
            arena.alloc(SpannedNode { node: Node::List(vec![item]), span: UNKNOWN_SPAN, path: PROPERTY_PATH.into() });
        alloc_intrinsic(&mut arena, IntrinsicFn::Select(index, source));

        assert!(validate_intrinsic_arg_shapes(&arena, &[]).is_empty());
    }

    #[test]
    fn split_source_cidr_fires() {
        let mut arena = Arena::new();
        let delimiter = alloc_string(&mut arena, ",");
        let source = alloc_cidr(&mut arena);
        alloc_intrinsic(&mut arena, IntrinsicFn::Split(delimiter, source));

        let diags = validate_intrinsic_arg_shapes(&arena, &[]);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule_id, "E1018");
        assert_eq!(diags[0].message, "'Fn::Cidr' is not supported as an argument to 'Fn::Split'");
    }

    #[test]
    fn split_source_ref_is_allowed() {
        let mut arena = Arena::new();
        let delimiter = alloc_string(&mut arena, ",");
        let source = alloc_intrinsic(&mut arena, IntrinsicFn::Ref("Param".into()));
        alloc_intrinsic(&mut arena, IntrinsicFn::Split(delimiter, source));

        assert!(validate_intrinsic_arg_shapes(&arena, &[]).is_empty());
    }

    #[test]
    fn sub_variable_cidr_fires() {
        let mut arena = Arena::new();
        let value = alloc_cidr(&mut arena);
        alloc_intrinsic(&mut arena, IntrinsicFn::Sub("${x}".into(), Some(vec![("x".into(), value)])));

        let diags = validate_intrinsic_arg_shapes(&arena, &[]);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule_id, "E1019");
        assert_eq!(diags[0].message, "'Fn::Cidr' is not supported as an argument to 'Fn::Sub'");
    }

    #[test]
    fn sub_variable_getazs_is_allowed() {
        let mut arena = Arena::new();
        let region = alloc_string(&mut arena, "us-east-1");
        let value = alloc_intrinsic(&mut arena, IntrinsicFn::GetAZs(region));
        alloc_intrinsic(&mut arena, IntrinsicFn::Sub("${x}".into(), Some(vec![("x".into(), value)])));

        assert!(validate_intrinsic_arg_shapes(&arena, &[]).is_empty());
    }

    #[test]
    fn base64_condition_function_fires() {
        let mut arena = Arena::new();
        let operand = alloc_string(&mut arena, "x");
        let argument = alloc_intrinsic(&mut arena, IntrinsicFn::Equals(operand, operand));
        alloc_intrinsic(&mut arena, IntrinsicFn::Base64(argument));

        let diags = validate_intrinsic_arg_shapes(&arena, &[]);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule_id, "E1021");
        assert_eq!(diags[0].message, "'Fn::Equals' is not supported as an argument to 'Fn::Base64'");
    }

    #[test]
    fn base64_cidr_is_allowed() {
        let mut arena = Arena::new();
        let argument = alloc_cidr(&mut arena);
        alloc_intrinsic(&mut arena, IntrinsicFn::Base64(argument));

        assert!(validate_intrinsic_arg_shapes(&arena, &[]).is_empty());
    }

    #[test]
    fn join_delimiter_ref_fires() {
        let mut arena = Arena::new();
        let delimiter = alloc_intrinsic(&mut arena, IntrinsicFn::Ref("Param".into()));
        let item = alloc_string(&mut arena, "a");
        let items =
            arena.alloc(SpannedNode { node: Node::List(vec![item]), span: UNKNOWN_SPAN, path: PROPERTY_PATH.into() });
        alloc_intrinsic(&mut arena, IntrinsicFn::Join(delimiter, items));

        let diags = validate_intrinsic_arg_shapes(&arena, &[]);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule_id, "E1022");
        assert_eq!(diags[0].message, "'Ref' is not supported as an argument to 'Fn::Join'");
    }

    #[test]
    fn join_item_getazs_fires() {
        let mut arena = Arena::new();
        let delimiter = alloc_string(&mut arena, ",");
        let region = alloc_string(&mut arena, "us-east-1");
        let item = alloc_intrinsic(&mut arena, IntrinsicFn::GetAZs(region));
        let items =
            arena.alloc(SpannedNode { node: Node::List(vec![item]), span: UNKNOWN_SPAN, path: PROPERTY_PATH.into() });
        alloc_intrinsic(&mut arena, IntrinsicFn::Join(delimiter, items));

        let diags = validate_intrinsic_arg_shapes(&arena, &[]);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule_id, "E1022");
        assert_eq!(diags[0].message, "'Fn::GetAZs' is not supported as an argument to 'Fn::Join'");
    }

    #[test]
    fn join_item_ref_is_allowed() {
        let mut arena = Arena::new();
        let delimiter = alloc_string(&mut arena, ",");
        let item = alloc_intrinsic(&mut arena, IntrinsicFn::Ref("Param".into()));
        let items =
            arena.alloc(SpannedNode { node: Node::List(vec![item]), span: UNKNOWN_SPAN, path: PROPERTY_PATH.into() });
        alloc_intrinsic(&mut arena, IntrinsicFn::Join(delimiter, items));

        assert!(validate_intrinsic_arg_shapes(&arena, &[]).is_empty());
    }

    #[test]
    fn join_items_from_intrinsic_source_are_not_expanded() {
        let mut arena = Arena::new();
        let delimiter = alloc_string(&mut arena, ",");
        let split_delimiter = alloc_string(&mut arena, "|");
        let split_input = alloc_string(&mut arena, "a|b");
        let items = alloc_intrinsic(&mut arena, IntrinsicFn::Split(split_delimiter, split_input));
        alloc_intrinsic(&mut arena, IntrinsicFn::Join(delimiter, items));

        assert!(validate_intrinsic_arg_shapes(&arena, &[]).is_empty());
    }

    #[test]
    fn findinmap_key_sub_fires_without_language_extensions() {
        let mut arena = Arena::new();
        let map_name = alloc_string(&mut arena, "M");
        let top_key = alloc_sub(&mut arena);
        let second_key = alloc_string(&mut arena, "k2");
        alloc_intrinsic(&mut arena, IntrinsicFn::FindInMap(map_name, top_key, second_key, None));

        let diags = validate_intrinsic_arg_shapes(&arena, &[]);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule_id, "E1011");
        assert_eq!(diags[0].message, "'Fn::Sub' is not supported as an argument to 'Fn::FindInMap'");
    }

    #[test]
    fn findinmap_key_sub_is_allowed_with_language_extensions() {
        let mut arena = Arena::new();
        let map_name = alloc_string(&mut arena, "M");
        let top_key = alloc_sub(&mut arena);
        let second_key = alloc_string(&mut arena, "k2");
        alloc_intrinsic(&mut arena, IntrinsicFn::FindInMap(map_name, top_key, second_key, None));

        let diags = validate_intrinsic_arg_shapes(&arena, &[TRANSFORM_LANGUAGE_EXTENSIONS.into()]);
        assert!(diags.is_empty());
    }

    #[test]
    fn findinmap_key_getatt_fires_even_with_language_extensions() {
        let mut arena = Arena::new();
        let map_name = alloc_string(&mut arena, "M");
        let top_key = alloc_intrinsic(&mut arena, IntrinsicFn::GetAtt("R".into(), "Arn".into()));
        let second_key = alloc_string(&mut arena, "k2");
        alloc_intrinsic(&mut arena, IntrinsicFn::FindInMap(map_name, top_key, second_key, None));

        let diags = validate_intrinsic_arg_shapes(&arena, &[TRANSFORM_LANGUAGE_EXTENSIONS.into()]);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule_id, "E1011");
    }

    #[test]
    fn non_intrinsic_operands_are_not_flagged() {
        let mut arena = Arena::new();
        let delimiter = alloc_string(&mut arena, ",");
        let source = alloc_string(&mut arena, "a,b");
        alloc_intrinsic(&mut arena, IntrinsicFn::Split(delimiter, source));
        alloc_intrinsic(&mut arena, IntrinsicFn::Base64(source));

        assert!(validate_intrinsic_arg_shapes(&arena, &[]).is_empty());
    }
}
