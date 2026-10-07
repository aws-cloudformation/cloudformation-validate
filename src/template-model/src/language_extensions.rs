//! Detects intrinsic functions that require the `AWS::LanguageExtensions`
//! transform but are used in a template that does not declare it. Runs on the
//! raw arena (before intrinsic resolution) so the offending `Fn::` node is still
//! present with its source span - by the time a value is resolved for the
//! engines, the raw key is gone. Emitting here means both engines report these
//! findings identically from the shared model.
//!
//! Three functions are transform-gated:
//! - `Fn::ForEach::<name>` - a section-level looping construct.
//! - `Fn::Length` - length of a list.
//! - `Fn::ToJsonString` - serialize a value to a JSON string.
//!
//! `Fn::Length`/`Fn::ToJsonString` are *position sensitive*: a value slot only
//! accepts them where its argument schema lists them as permitted. In a slot
//! that forbids them (e.g. an `Fn::Join` delimiter, an `Fn::Select` index, an
//! `Fn::Sub` template) the value is a plain type mismatch, reported by the schema
//! layer - flagging the missing transform there would be a false positive. This
//! module therefore walks the value tree top-down carrying whether the current
//! slot permits each function, mirroring the per-slot argument schemas, and fires
//! only in permitting positions.

use crate::conditions::{ConditionModel, Satisfiability};
use crate::consts::*;
use crate::defect::{DefectPhase, ParseDefect};
use crate::ir::*;
use std::collections::HashMap;

/// A `Fn::ForEach::<name>` looping key: the prefix followed by a non-empty
/// alphanumeric loop name. Matches the section-level key that introduces a loop.
fn is_foreach_key(key: &str) -> bool {
    let Some(name) = key.strip_prefix(FN_FOR_EACH_KEY_PREFIX) else {
        return false;
    };
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Whether a value slot permits `Fn::Length` / `Fn::ToJsonString` as a direct
/// child. Derived from CloudFormation's intrinsic argument schemas: a value
/// position accepts them unless it building a string/list where only
/// string-producing functions are allowed.
#[derive(Clone, Copy)]
struct SlotPermits {
    length: bool,
    to_json_string: bool,
}

impl SlotPermits {
    /// A free value position (resource property, output value, condition/rule
    /// expression) accepts both functions.
    const OPEN: SlotPermits = SlotPermits { length: true, to_json_string: true };
    /// A slot that forbids both (e.g. a string/list-building argument).
    const NONE: SlotPermits = SlotPermits { length: false, to_json_string: false };

    fn permits(&self, name: &str) -> bool {
        match name {
            FN_LENGTH => self.length,
            FN_TO_JSON_STRING => self.to_json_string,
            _ => false,
        }
    }
}

/// Validates transform-gated intrinsics against the declared transforms. When
/// `AWS::LanguageExtensions` is present these functions are legal and nothing is
/// reported.
pub fn validate_language_extensions(arena: &Arena, transforms: &[String]) -> Vec<ParseDefect> {
    if transforms.iter().any(|t| t == TRANSFORM_LANGUAGE_EXTENSIONS) {
        return Vec::new();
    }

    let mut out = Vec::new();
    collect_foreach_keys(arena, &mut out);
    collect_length_and_to_json(arena, &mut out);
    collect_findinmap_default_value(arena, &mut out);
    out
}

/// Validates the shape of intrinsic functions authored as a top-level
/// `CreationPolicy`. CloudFormation accepts `Fn::If` there when every reachable
/// result is an object; other root intrinsic functions are rejected. Functions
/// nested inside an object are ordinary property values and are not restricted
/// here. `DeletionPolicy` and `UpdateReplacePolicy` rely on generic intrinsic
/// validation and resolved-value validation rather than a function allowlist.
pub fn validate_lifecycle_intrinsics(
    arena: &Arena,
    conditions: &ConditionModel,
    lifecycle_attribute_nodes: &HashMap<(String, String), NodeRef>,
    resource_conditions: &HashMap<String, String>,
) -> Vec<ParseDefect> {
    let mut roots: Vec<_> = lifecycle_attribute_nodes.iter().collect();
    roots.sort_unstable_by_key(|(_, node_ref)| **node_ref);

    let mut out = Vec::new();
    for ((resource_id, attribute), node_ref) in roots {
        if attribute != KEY_CREATION_POLICY {
            continue;
        }

        let mut assumptions =
            resource_conditions.get(resource_id).map(|condition| vec![(condition.clone(), true)]).unwrap_or_default();
        if matches!(conditions.satisfiability(&assumptions), Satisfiability::Unsatisfiable) {
            continue;
        }

        let node_ref = *node_ref;
        let Node::Intrinsic(intrinsic) = arena.node(node_ref) else {
            continue;
        };
        match intrinsic {
            IntrinsicFn::If(condition, when_true, when_false) => validate_creation_policy_if(
                arena,
                conditions,
                Some(condition),
                *when_true,
                *when_false,
                &mut assumptions,
                &mut out,
            ),
            IntrinsicFn::IfExpr(_, when_true, when_false) => validate_creation_policy_if(
                arena,
                conditions,
                None,
                *when_true,
                *when_false,
                &mut assumptions,
                &mut out,
            ),
            _ => out.push(crate::make_parse_defect_at(
                "F1101",
                format!(
                    "{} is not supported as a top-level {} value; {} must be an object or {} returning an object",
                    cfn_function_name(intrinsic),
                    KEY_CREATION_POLICY,
                    KEY_CREATION_POLICY,
                    FN_IF
                ),
                arena.span(node_ref),
                &arena.get(node_ref).path,
            )),
        }
    }
    out
}

fn validate_creation_policy_if(
    arena: &Arena,
    conditions: &ConditionModel,
    condition: Option<&str>,
    when_true: NodeRef,
    when_false: NodeRef,
    assumptions: &mut Vec<(String, bool)>,
    out: &mut Vec<ParseDefect>,
) {
    for (branch, expected) in [(when_true, true), (when_false, false)] {
        if let Some(condition) = condition {
            assumptions.push((condition.to_string(), expected));
        }
        validate_creation_policy_branch(arena, conditions, branch, assumptions, out);
        if condition.is_some() {
            assumptions.pop();
        }
    }
}

fn validate_creation_policy_branch(
    arena: &Arena,
    conditions: &ConditionModel,
    node_ref: NodeRef,
    assumptions: &mut Vec<(String, bool)>,
    out: &mut Vec<ParseDefect>,
) {
    if matches!(conditions.satisfiability(assumptions), Satisfiability::Unsatisfiable) {
        return;
    }

    match arena.node(node_ref) {
        Node::Map(_) => {}
        Node::Intrinsic(IntrinsicFn::If(condition, when_true, when_false)) => {
            validate_creation_policy_if(arena, conditions, Some(condition), *when_true, *when_false, assumptions, out)
        }
        Node::Intrinsic(IntrinsicFn::IfExpr(_, when_true, when_false)) => {
            validate_creation_policy_if(arena, conditions, None, *when_true, *when_false, assumptions, out)
        }
        node => out.push(crate::make_parse_defect_at(
            "F1101",
            format!(
                "{} branch in {} must be an object, got {}",
                FN_IF,
                KEY_CREATION_POLICY,
                creation_policy_value_shape(node)
            ),
            arena.span(node_ref),
            &arena.get(node_ref).path,
        )),
    }
}

fn creation_policy_value_shape(node: &Node) -> String {
    match node {
        Node::Null => "null".to_string(),
        Node::Bool(_) => "a boolean".to_string(),
        Node::Int(_) | Node::Float(_) => "a number".to_string(),
        Node::String(_) => "a string".to_string(),
        Node::List(_) => "a list".to_string(),
        Node::Map(_) => "an object".to_string(),
        Node::Intrinsic(intrinsic) => cfn_function_name(intrinsic).to_string(),
    }
}

/// Emits a structural error for every `Fn::FindInMap` written in its four-element
/// form `[map, key1, key2, { DefaultValue: ... }]`. That fourth `DefaultValue`
/// element is only accepted under the `AWS::LanguageExtensions` transform; without
/// it CloudFormation rejects the call as exceeding `Fn::FindInMap`'s three-element
/// maximum, so this is a guaranteed deploy failure. Anchored at the `Fn::FindInMap`
/// node to match where the excess element is written.
fn collect_findinmap_default_value(arena: &Arena, out: &mut Vec<ParseDefect>) {
    for idx in 0..arena.len() {
        let node_ref = idx as NodeRef;
        if let Node::Intrinsic(IntrinsicFn::FindInMap(_, _, _, Some(_))) = arena.node(node_ref) {
            out.push(crate::make_parse_defect_at(
                "F1101",
                format!(
                    "{}: the 'DefaultValue' element requires the AWS::LanguageExtensions transform; without it Fn::FindInMap accepts at most 3 elements",
                    FN_FIND_IN_MAP
                ),
                arena.span(node_ref),
                &arena.get(node_ref).path,
            ));
        }
    }
}

/// Emits the transform-required error for every `Fn::ForEach::<name>` key in the
/// template. The loop key appears as a map key at the section level
/// (Resources/Outputs/Conditions) or nested inside another loop's body; scanning
/// every map node covers all
/// placements the way the source template writes them.
///
/// A loop declared directly under `Resources` occupies a resource logical-id
/// slot, so the finding is attributed to that id (with no property path) to land
/// where a resource-scoped consumer expects. Loops elsewhere carry their build
/// path so span resolution can walk up to the nearest located element.
fn collect_foreach_keys(arena: &Arena, out: &mut Vec<ParseDefect>) {
    for idx in 0..arena.len() {
        let node_ref = idx as NodeRef;
        let Node::Map(entries) = arena.node(node_ref) else {
            continue;
        };
        for (key, value_ref) in entries {
            if !is_foreach_key(key) {
                continue;
            }
            let message = format!(
                "Fn::ForEach requires the AWS::LanguageExtensions transform, but it is not declared. Add 'Transform: AWS::LanguageExtensions' to use '{}'",
                key
            );
            let build_path = &arena.get(*value_ref).path;
            let diag = if build_path == &format!("{}/{}", SECTION_RESOURCES, key) {
                ParseDefect::new("F1032", message)
                    .location(arena.span(*value_ref))
                    .phase(DefectPhase::Parse)
                    .resource(key.clone())
            } else {
                crate::make_parse_defect_at("F1032", message, arena.span(*value_ref), build_path)
            };
            out.push(diag);
        }
    }
}

/// Walks each value tree top-down and emits the transform-required error where
/// `Fn::Length`/`Fn::ToJsonString` sit in a slot that permits them. The traversal starts from
/// the open value roots (resource property/metadata values, output values,
/// condition and rule expressions) and narrows the permitted set as it descends
/// through nested intrinsics per their argument schemas.
fn collect_length_and_to_json(arena: &Arena, out: &mut Vec<ParseDefect>) {
    for idx in 0..arena.len() {
        let node_ref = idx as NodeRef;
        let Node::Intrinsic(intrinsic) = arena.node(node_ref) else {
            continue;
        };
        // Only start a descent at a root value position - a slot whose own parent
        // is not itself an intrinsic argument (those are visited through their
        // parent). Roots are recognised by their build path.
        if !is_open_value_root(&arena.get(node_ref).path) {
            continue;
        }
        visit_value(arena, node_ref, intrinsic, SlotPermits::OPEN, out);
    }
}

/// Whether a build path denotes a free value position where a transform-gated
/// function may legally appear as a direct child. These are the roots the
/// top-down traversal starts from; everything below is reached by descending
/// through the enclosing intrinsic, which sets the permitted set for its slots.
///
/// A path is a root when its nearest enclosing structural segment is a resource
/// `Properties`/`Metadata` value, an output `Value`, or a condition/rule
/// expression - i.e. it is not itself a positional argument (`.../Fn::X/<n>`) of
/// another intrinsic, which is handled by that intrinsic's own descent.
fn is_open_value_root(path: &str) -> bool {
    // A positional argument path ends in `/Fn::Something` or `/Fn::Something/<idx>`
    // and is reached via its parent intrinsic, never as a root.
    let segments: Vec<&str> = path.split('/').collect();
    if segments.iter().any(|s| s.starts_with(FN_PREFIX)) {
        return false;
    }
    match segments.first().copied() {
        Some(SECTION_RESOURCES) => {
            segments.get(2).map(|s| *s == KEY_PROPERTIES || *s == SECTION_METADATA).unwrap_or(false)
        }
        Some(SECTION_OUTPUTS) => segments.get(2).map(|s| *s == KEY_VALUE).unwrap_or(false),
        Some(SECTION_CONDITIONS) | Some(SECTION_RULES) => true,
        _ => false,
    }
}

/// Visits an intrinsic node in a slot whose permitted set is `permits`. Fires the
/// transform-required diagnostic when the node is `Fn::Length`/`Fn::ToJsonString`
/// and the slot permits it, then recurses into the node's own argument slots. A
/// transform-gated function in a forbidding slot is left for the schema layer to
/// report as a type mismatch and its subtree is not searched, matching how the
/// reference validator abandons a type-rejected value.
fn visit_value(
    arena: &Arena,
    node_ref: NodeRef,
    intrinsic: &IntrinsicFn,
    permits: SlotPermits,
    out: &mut Vec<ParseDefect>,
) {
    match intrinsic {
        IntrinsicFn::Length(inner) => {
            if !permits.permits(FN_LENGTH) {
                return;
            }
            out.push(make_transform_required(arena, node_ref, FN_LENGTH, "F1030"));
            // Length's own argument is a list whose items permit ToJsonString.
            visit_child(arena, *inner, SlotPermits { length: false, to_json_string: true }, out);
        }
        IntrinsicFn::ToJsonString(inner) => {
            if !permits.permits(FN_TO_JSON_STRING) {
                return;
            }
            out.push(make_transform_required(arena, node_ref, FN_TO_JSON_STRING, "F1031"));
            // ToJsonString serializes an arbitrary value; its child is a free slot.
            visit_child(arena, *inner, SlotPermits::OPEN, out);
        }
        // Base64 wraps a value it re-exposes as an open slot, so a gated function
        // is permitted directly inside it even when Base64 itself sits in a
        // string-building position.
        IntrinsicFn::Base64(inner) => visit_child(arena, *inner, SlotPermits::OPEN, out),
        // Fn::If is transparent: each branch inherits the enclosing slot's
        // permitted set (the condition is boolean and never a gated value).
        IntrinsicFn::If(_, t, f) => {
            visit_child(arena, *t, permits, out);
            visit_child(arena, *f, permits, out);
        }
        IntrinsicFn::IfExpr(_, t, f) => {
            visit_child(arena, *t, permits, out);
            visit_child(arena, *f, permits, out);
        }
        // Fn::Equals compares two values that both permit the gated functions.
        IntrinsicFn::Equals(a, b) => {
            visit_child(arena, *a, SlotPermits::OPEN, out);
            visit_child(arena, *b, SlotPermits::OPEN, out);
        }
        IntrinsicFn::And(items) | IntrinsicFn::Or(items) => {
            for item in items {
                visit_child(arena, *item, SlotPermits::NONE, out);
            }
        }
        IntrinsicFn::Not(inner) => visit_child(arena, *inner, SlotPermits::NONE, out),
        // Fn::Sub: the template string forbids gated functions, but each
        // substitution-variable value is a free string slot that permits
        // ToJsonString (a string producer) though not Length (an integer).
        IntrinsicFn::Sub(_, subs) => {
            if let Some(subs) = subs {
                for (_, value_ref) in subs {
                    visit_child(arena, *value_ref, SlotPermits { length: false, to_json_string: true }, out);
                }
            }
        }
        // Every remaining intrinsic builds a string, list, or reference; its
        // argument slots forbid the gated functions, so descend with an empty
        // permitted set (still recursing so a gated function nested behind a
        // Base64/Equals inside these args is reached).
        _ => {
            for child in intrinsic_child_refs(intrinsic) {
                visit_child(arena, child, SlotPermits::NONE, out);
            }
        }
    }
}

/// Descends into a child node reference, dispatching intrinsic nodes to
/// [`visit_value`] and walking plain containers so a gated function nested inside
/// a literal array/object is still reached with the slot's permitted set.
fn visit_child(arena: &Arena, node_ref: NodeRef, permits: SlotPermits, out: &mut Vec<ParseDefect>) {
    if !arena.is_valid(node_ref) {
        return;
    }
    match arena.node(node_ref) {
        Node::Intrinsic(intrinsic) => visit_value(arena, node_ref, intrinsic, permits, out),
        Node::List(items) => {
            for item in items {
                visit_child(arena, *item, permits, out);
            }
        }
        Node::Map(entries) => {
            for (_, value_ref) in entries {
                visit_child(arena, *value_ref, permits, out);
            }
        }
        _ => {}
    }
}

/// The child node references an intrinsic holds, for descending into functions
/// whose slots forbid the gated functions but may still contain a Base64/Equals
/// re-opening the permitted set.
fn intrinsic_child_refs(intrinsic: &IntrinsicFn) -> Vec<NodeRef> {
    match intrinsic {
        IntrinsicFn::Join(a, b) | IntrinsicFn::Select(a, b) | IntrinsicFn::Split(a, b) => vec![*a, *b],
        IntrinsicFn::FindInMap(m, k1, k2, default) => {
            let mut refs = vec![*m, *k1, *k2];
            refs.extend(default.iter().copied());
            refs
        }
        IntrinsicFn::Cidr(a, b, c) => vec![*a, *b, *c],
        IntrinsicFn::GetAZs(inner) | IntrinsicFn::ImportValue(inner) => vec![*inner],
        IntrinsicFn::GetStackOutput(args) | IntrinsicFn::Transform(_, args) => args.iter().map(|(_, r)| *r).collect(),
        IntrinsicFn::Contains(a, b) | IntrinsicFn::EachMemberEquals(a, b) | IntrinsicFn::EachMemberIn(a, b) => {
            vec![*a, *b]
        }
        _ => Vec::new(),
    }
}

/// Builds the transform-required diagnostic anchored at the gated function node.
fn make_transform_required(arena: &Arena, node_ref: NodeRef, fn_name: &str, rule_id: &str) -> ParseDefect {
    crate::make_parse_defect_at(
        rule_id,
        format!(
            "{} requires the AWS::LanguageExtensions transform, but it is not declared. Add 'Transform: AWS::LanguageExtensions' to use it",
            fn_name
        ),
        arena.span(node_ref),
        &arena.get(node_ref).path,
    )
}
