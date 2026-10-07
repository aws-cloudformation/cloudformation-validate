//! Validation of each named condition's body.

use crate::consts::{CONDITION_REF_PREFIX, FN_AND, FN_CONDITION, FN_EQUALS, FN_IF, FN_NOT, FN_OR, SECTION_CONDITIONS};
use crate::ir::{Arena, IntrinsicFn, Node, NodeRef, SourceSpanIndex};
use crate::message::{quote, render_str_list};
use crate::parser::builder::node_shape_name;
use crate::{DefectPhase, ParseDefect, UNKNOWN_SPAN};

const CONDITION_BODY_RULE: &str = "E8001";
const CONDITION_FUNCTIONS: &[&str] = &[FN_AND, FN_EQUALS, FN_NOT, FN_OR];
const MAX_CONDITION_NAME_LENGTH: usize = 255;

pub(crate) fn validate_condition_bodies(
    arena: &Arena,
    conditions: NodeRef,
    span_index: &SourceSpanIndex,
) -> Vec<ParseDefect> {
    let Some(entries) = arena.as_map(conditions) else {
        return Vec::new();
    };

    entries
        .iter()
        .filter(|(name, _)| is_condition_name(name))
        .filter_map(|(name, body_ref)| {
            let reason = body_defect_reason(arena, *body_ref)?;
            let path = format!("{}/{}", SECTION_CONDITIONS, name);
            let span = span_index.get(&path).copied().unwrap_or(UNKNOWN_SPAN);
            Some(
                ParseDefect::new(CONDITION_BODY_RULE, format!("Condition {} {}", quote(name), reason))
                    .location(span)
                    .property_path(path)
                    .phase(DefectPhase::Parse),
            )
        })
        .collect()
}

fn is_condition_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_CONDITION_NAME_LENGTH
        && name.chars().all(|character| character.is_ascii_alphanumeric() || character == '&' || character == '_')
}

fn is_separately_validated(function_name: &str) -> bool {
    function_name == FN_IF || CONDITION_FUNCTIONS.contains(&function_name)
}

fn body_defect_reason(arena: &Arena, body_ref: NodeRef) -> Option<String> {
    match arena.node(body_ref) {
        Node::Intrinsic(IntrinsicFn::And(_))
        | Node::Intrinsic(IntrinsicFn::Or(_))
        | Node::Intrinsic(IntrinsicFn::Not(_))
        | Node::Intrinsic(IntrinsicFn::Equals(_, _))
        | Node::Bool(_) => None,
        Node::Intrinsic(IntrinsicFn::Ref(target)) if target.starts_with(CONDITION_REF_PREFIX) => None,
        Node::Map(entries) if entries.len() == 1 && entries[0].0 == FN_CONDITION => None,
        Node::Map(entries) if entries.len() == 1 && is_separately_validated(&entries[0].0) => None,
        Node::Map(entries) if entries.len() > 1 => Some(format!(
            "must be a single condition function, but declares {}: {}",
            entries.len(),
            render_str_list(entries.iter().map(|(name, _)| name))
        )),
        Node::Map(entries) if entries.len() == 1 => {
            Some(format!("must be one of {}, got {}", render_str_list(CONDITION_FUNCTIONS), quote(&entries[0].0)))
        }
        node => Some(format!("must be one of {}, got {}", render_str_list(CONDITION_FUNCTIONS), node_shape_name(node))),
    }
}
