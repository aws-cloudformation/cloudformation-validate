//! `AWS::LanguageExtensions` `Fn::ForEach` expansion.
//!
//! Rewrites the IR the way CloudFormation expands `Fn::ForEach::<name>` loops
//! before the rest of the model is built, so downstream rules see the expanded
//! resources rather than the raw macro. The contract:
//!
//! * Only `${Identifier}` and `&{Identifier}` placeholders are substituted (never
//!   the bare identifier). `&{Identifier}` strips every non-alphanumeric
//!   character from the substituted value (used to build valid logical IDs).
//! * A `Ref` to a bound loop variable resolves to that variable's value.
//! * `Fn::Sub` template strings have their placeholders substituted; the rest of
//!   the tree is walked recursively, so nested loops and nested intrinsics are
//!   expanded correctly.
//! * A `Fn::ForEach::<name>` value must be a list of exactly three elements
//!   `[identifier, collection, body]`; anything else is a transform error.
//!   Producing two identical output keys is also a transform error.
//! * Collections may be a literal list, or a `Ref`/`Fn::FindInMap` that resolves
//!   to one; an unresolved collection expands to two opaque placeholder values so
//!   the body is still shape-checked without inventing concrete names.

use crate::consts::{FN_FOR_EACH_KEY_PREFIX, MAX_RESOLVE_DEPTH, TRANSFORM_LANGUAGE_EXTENSIONS};
use crate::defect::ParseDefect;
use crate::ir::{Arena, IntrinsicFn, NULL_REF, Node, NodeRef, SpannedNode, TemplateIR};
use crate::span::{SourceSpan, UNKNOWN_SPAN};
use std::collections::BTreeMap;

/// Recursion ceiling for the expansion tree walk. This walk traverses the same
/// IR the resolver walks immediately afterwards, so it shares the resolver's
/// depth bound: any tree shallow enough to resolve is shallow enough to expand,
/// and a tree deep enough to trip this guard is already rejected downstream.
/// Using the shared constant keeps a single, documented ceiling rather than a
/// second ad-hoc one that could silently truncate a valid deep template.
const MAX_EXPANSION_DEPTH: u32 = MAX_RESOLVE_DEPTH;

/// The loop-variable bindings in scope during expansion. Each `Fn::ForEach`
/// iteration binds its identifier to a single scalar value (the current
/// collection element), so a binding is always a scalar string. A `BTreeMap`
/// keeps substitution order deterministic: when one binding's value textually
/// contains another binding's placeholder, iteration order decides the result,
/// and a hash map would make that vary run to run.
type Bindings = BTreeMap<String, String>;

/// Cumulative deterministic work budget for `Fn::ForEach` expansion across all
/// sections of one template. Ordinary traversal outside a loop is free. A limit
/// may be consumed exactly; expansion fails only when another unit is attempted.
struct ExpansionBudget {
    remaining: u64,
    limit: u64,
    halted: bool,
}

impl ExpansionBudget {
    fn new(limit: u64) -> Self {
        Self { remaining: limit, limit, halted: false }
    }

    fn halted(&self) -> bool {
        self.halted
    }

    fn charge(&mut self, diagnostics: &mut Vec<ParseDefect>, span: SourceSpan, path: &str) -> bool {
        if self.halted {
            return false;
        }
        if self.remaining > 0 {
            self.remaining -= 1;
            return true;
        }

        self.halted = true;
        diagnostics.push(transform_error(
            &format!(
                "Fn::ForEach expansion budget exceeded (deterministic work limit: {}); no partial transformed section was applied",
                self.limit
            ),
            span,
            path,
        ));
        false
    }

    fn halt_for_depth(&mut self, diagnostics: &mut Vec<ParseDefect>, span: SourceSpan, path: &str) {
        if self.halted {
            return;
        }
        self.halted = true;
        diagnostics.push(transform_error(
            &format!(
                "Fn::ForEach expansion depth exceeds the deterministic limit of {MAX_EXPANSION_DEPTH}; no partial transformed section was applied"
            ),
            span,
            path,
        ));
    }
}

pub(crate) fn expand_language_extensions(ir: &mut TemplateIR) -> Vec<ParseDefect> {
    expand_language_extensions_with_budget(ir, crate::consts::MAX_FOREACH_EXPANSION_WORK)
}

fn expand_language_extensions_with_budget(ir: &mut TemplateIR, limit: u64) -> Vec<ParseDefect> {
    if !ir.transforms.iter().any(|t| t == TRANSFORM_LANGUAGE_EXTENSIONS) {
        return Vec::new();
    }

    let mut diagnostics = Vec::new();
    let bindings = Bindings::new();
    let mut budget = ExpansionBudget::new(limit);
    // `Fn::ForEach` is expanded where CloudFormation applies it: the
    // Conditions, Mappings, Resources, and Outputs top-level maps. The walk
    // recurses into nested maps/lists from there, so nested loops are covered.
    for section_ref in [ir.conditions, ir.mappings, ir.resources, ir.outputs] {
        if section_ref != NULL_REF {
            let rewritten = walk(
                &mut ir.arena,
                section_ref,
                &bindings,
                0,
                &mut diagnostics,
                ir.parameters,
                ir.mappings,
                &mut budget,
            );
            if budget.halted() {
                break;
            }
            replace_node_in_place(&mut ir.arena, section_ref, rewritten);
        }
    }

    diagnostics
}

/// Copies the node at `source` over `target` so that references to `target`
/// elsewhere in the IR (the section refs held by `TemplateIR`) observe the
/// rewritten content without having to thread new refs back to the caller.
fn replace_node_in_place(arena: &mut Arena, target: NodeRef, source: NodeRef) {
    if target == source {
        return;
    }
    let replacement = arena.get(source).clone();
    arena.set(target, replacement);
}

/// Recursively rewrites the subtree at `node_ref` with `bindings` applied,
/// returning the ref of the rewritten subtree (which may be `node_ref` unchanged).
fn walk(
    arena: &mut Arena,
    node_ref: NodeRef,
    bindings: &Bindings,
    depth: u32,
    diagnostics: &mut Vec<ParseDefect>,
    parameters: NodeRef,
    mappings: NodeRef,
    budget: &mut ExpansionBudget,
) -> NodeRef {
    if budget.halted() {
        return node_ref;
    }
    if depth > MAX_EXPANSION_DEPTH {
        let span = arena.span(node_ref);
        let path = arena.get(node_ref).path.clone();
        budget.halt_for_depth(diagnostics, span, &path);
        return node_ref;
    }

    let spanned = arena.get(node_ref).clone();
    // Every node copied or substituted under an active loop binding is one unit
    // of generated work. Ordinary traversal outside a loop remains uncharged.
    if !bindings.is_empty() && !budget.charge(diagnostics, spanned.span, &spanned.path) {
        return node_ref;
    }
    match &spanned.node {
        Node::String(s) => {
            let substituted = substitute_string(s, bindings);
            if substituted == *s {
                node_ref
            } else {
                arena.alloc(SpannedNode { node: Node::String(substituted), span: spanned.span, path: spanned.path })
            }
        }
        Node::Intrinsic(intrinsic) => {
            walk_intrinsic(arena, intrinsic, &spanned, bindings, depth, diagnostics, parameters, mappings, budget)
        }
        Node::Map(entries) => {
            walk_map(arena, entries.clone(), &spanned, bindings, depth, diagnostics, parameters, mappings, budget)
        }
        Node::List(items) => {
            let items = items.clone();
            let mut new_items = Vec::with_capacity(items.len());
            let mut changed = false;
            for item in &items {
                let rewritten = walk(arena, *item, bindings, depth + 1, diagnostics, parameters, mappings, budget);
                if budget.halted() {
                    return node_ref;
                }
                changed |= rewritten != *item;
                new_items.push(rewritten);
            }
            if changed {
                arena.alloc(SpannedNode { node: Node::List(new_items), span: spanned.span, path: spanned.path })
            } else {
                node_ref
            }
        }
        _ => node_ref,
    }
}

fn walk_intrinsic(
    arena: &mut Arena,
    intrinsic: &IntrinsicFn,
    spanned: &SpannedNode,
    bindings: &Bindings,
    depth: u32,
    diagnostics: &mut Vec<ParseDefect>,
    parameters: NodeRef,
    mappings: NodeRef,
    budget: &mut ExpansionBudget,
) -> NodeRef {
    match intrinsic {
        // A `Ref` to a bound loop variable resolves to that variable's scalar
        // value; otherwise its target string may still carry a placeholder.
        IntrinsicFn::Ref(target) => match bindings.get(target) {
            Some(value) => arena.alloc(SpannedNode {
                node: Node::String(value.clone()),
                span: spanned.span,
                path: spanned.path.clone(),
            }),
            None => {
                let substituted = substitute_string(target, bindings);
                if substituted == *target {
                    // Fall through via a fresh clone so callers can treat the
                    // return uniformly; the arena never mutates in place.
                    arena.alloc(spanned.clone())
                } else {
                    arena.alloc(SpannedNode {
                        node: Node::Intrinsic(IntrinsicFn::Ref(substituted)),
                        span: spanned.span,
                        path: spanned.path.clone(),
                    })
                }
            }
        },
        // `Fn::Sub` substitutes placeholders in its template string and walks the
        // optional variable map.
        IntrinsicFn::Sub(template, subs) => {
            let new_template = substitute_string(template, bindings);
            let new_subs: Option<Vec<(String, NodeRef)>> = subs.as_ref().map(|pairs| {
                pairs
                    .iter()
                    .map(|(k, v)| {
                        (
                            substitute_string(k, bindings),
                            walk(arena, *v, bindings, depth + 1, diagnostics, parameters, mappings, budget),
                        )
                    })
                    .collect()
            });
            // Collapse to a plain string when nothing remains to substitute: an
            // `Fn::Sub` with no variable map whose template no longer contains a
            // `${...}` placeholder is just a literal string, which is how
            // CloudFormation treats it. Collapsing prevents a resolved-to-literal
            // Sub from being treated as an unresolved object by downstream rules
            // (e.g. a Sub inside an Fn::GetAtt argument).
            let no_map = new_subs.as_ref().map(|s| s.is_empty()).unwrap_or(true);
            if no_map && !contains_sub_variable(&new_template) {
                arena.alloc(SpannedNode {
                    // `Fn::Sub` renders the literal escape `${!Name}` as
                    // `${Name}`; apply that here so the collapsed string equals
                    // what CloudFormation would produce.
                    node: Node::String(unescape_sub_literals(&new_template)),
                    span: spanned.span,
                    path: spanned.path.clone(),
                })
            } else {
                arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::Sub(new_template, new_subs)),
                    span: spanned.span,
                    path: spanned.path.clone(),
                })
            }
        }
        // `Fn::GetAtt` addresses `Resource.Attr`; the resource name may embed a
        // placeholder, so substitute both segments.
        IntrinsicFn::GetAtt(resource, attr) => arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::GetAtt(
                substitute_string(resource, bindings),
                substitute_string(attr, bindings),
            )),
            span: spanned.span,
            path: spanned.path.clone(),
        }),
        // Every other intrinsic is rebuilt from its walked children so a loop
        // variable nested inside it (e.g. inside Fn::Select / Fn::Join) is
        // substituted rather than left literal.
        other => {
            let rebuilt = rebuild_intrinsic(arena, other, bindings, depth, diagnostics, parameters, mappings, budget);
            arena.alloc(SpannedNode { node: Node::Intrinsic(rebuilt), span: spanned.span, path: spanned.path.clone() })
        }
    }
}

fn walk_map(
    arena: &mut Arena,
    entries: Vec<(String, NodeRef)>,
    spanned: &SpannedNode,
    bindings: &Bindings,
    depth: u32,
    diagnostics: &mut Vec<ParseDefect>,
    parameters: NodeRef,
    mappings: NodeRef,
    budget: &mut ExpansionBudget,
) -> NodeRef {
    let mut new_entries: Vec<(String, NodeRef)> = Vec::new();
    for (key, value) in &entries {
        if let Some(loop_name) = key.strip_prefix(FN_FOR_EACH_KEY_PREFIX) {
            expand_foreach(
                arena,
                loop_name,
                *value,
                bindings,
                depth,
                diagnostics,
                parameters,
                mappings,
                spanned,
                &mut new_entries,
                budget,
            );
            if budget.halted() {
                return arena.alloc(spanned.clone());
            }
            continue;
        }
        let new_key = substitute_string(key, bindings);
        let new_value = walk(arena, *value, bindings, depth + 1, diagnostics, parameters, mappings, budget);
        if budget.halted() {
            return arena.alloc(spanned.clone());
        }
        insert_unique(&mut new_entries, new_key, new_value, spanned.span, diagnostics);
    }
    // A `Fn::GetAtt` whose arguments were dynamic before expansion (e.g.
    // `!GetAtt [!Sub "R${Id}", {Ref: Attr}]`) is parsed as a raw single-key map
    // rather than an `IntrinsicFn::GetAtt`. Once expansion resolves both
    // arguments to plain strings, canonicalize it back to a GetAtt so the
    // resolver treats it as a reference instead of an opaque object.
    if let Some(getatt) = canonicalize_getatt_map(arena, &new_entries) {
        return arena.alloc(SpannedNode { node: getatt, span: spanned.span, path: spanned.path.clone() });
    }
    arena.alloc(SpannedNode { node: Node::Map(new_entries), span: spanned.span, path: spanned.path.clone() })
}

/// If `entries` is a single `Fn::GetAtt` key whose value is a two-element list of
/// plain strings (or a dotted string), returns the equivalent
/// `IntrinsicFn::GetAtt`. Returns `None` otherwise.
fn canonicalize_getatt_map(arena: &Arena, entries: &[(String, NodeRef)]) -> Option<Node> {
    if entries.len() != 1 {
        return None;
    }
    let (key, value) = &entries[0];
    if key != crate::consts::FN_GET_ATT {
        return None;
    }
    match arena.node(*value) {
        Node::List(items) if items.len() == 2 => {
            let resource = arena.as_str(items[0])?.to_string();
            let attr = arena.as_str(items[1])?.to_string();
            Some(Node::Intrinsic(IntrinsicFn::GetAtt(resource, attr)))
        }
        Node::String(dotted) => {
            let (resource, attr) = dotted.split_once('.')?;
            Some(Node::Intrinsic(IntrinsicFn::GetAtt(resource.to_string(), attr.to_string())))
        }
        _ => None,
    }
}

/// Expands one `Fn::ForEach::<name>` entry, appending the generated entries to
/// `out`. Reports a transform error for a malformed macro or a duplicate
/// generated key.
#[allow(clippy::too_many_arguments)]
fn expand_foreach(
    arena: &mut Arena,
    // The loop name (the suffix after `Fn::ForEach::`) only names the macro; the
    // iterator variable comes from the value's first element. Kept in the
    // signature to document the call site.
    _loop_name: &str,
    macro_ref: NodeRef,
    bindings: &Bindings,
    depth: u32,
    diagnostics: &mut Vec<ParseDefect>,
    parameters: NodeRef,
    mappings: NodeRef,
    parent: &SpannedNode,
    out: &mut Vec<(String, NodeRef)>,
    budget: &mut ExpansionBudget,
) {
    let span = arena.span(macro_ref);
    let Some(items) = arena.as_list(macro_ref).map(<[NodeRef]>::to_vec) else {
        diagnostics.push(transform_error("Fn::ForEach values must be a list of 3 elements", span, &parent.path));
        return;
    };
    if items.len() != 3 {
        diagnostics.push(transform_error("Fn::ForEach values must be a list of 3 elements", span, &parent.path));
        return;
    }
    let Some(identifier) = arena.as_str(items[0]).map(str::to_string) else {
        diagnostics.push(transform_error("Fn::ForEach identifier must be a string", span, &parent.path));
        return;
    };
    let body_ref = items[2];
    let collection = resolve_collection(arena, items[1], bindings, parameters, mappings);

    for value in collection {
        // Charge one deterministic work unit for selecting this collection item;
        // generated body nodes are charged by `walk` below.
        if !budget.charge(diagnostics, span, &parent.path) {
            return;
        }

        let mut iter_bindings = bindings.clone();
        iter_bindings.insert(identifier.clone(), value);
        // The body must be a map whose keys/values are templated per iteration.
        let Some(body_entries) = arena.as_map(body_ref).map(<[(String, NodeRef)]>::to_vec) else {
            diagnostics.push(transform_error("Fn::ForEach output value must be an object", span, &parent.path));
            return;
        };
        for (body_key, body_value) in &body_entries {
            if let Some(nested_loop) = body_key.strip_prefix(FN_FOR_EACH_KEY_PREFIX) {
                expand_foreach(
                    arena,
                    nested_loop,
                    *body_value,
                    &iter_bindings,
                    depth + 1,
                    diagnostics,
                    parameters,
                    mappings,
                    parent,
                    out,
                    budget,
                );
                if budget.halted() {
                    return;
                }
                continue;
            }
            let new_key = substitute_string(body_key, &iter_bindings);
            let new_value =
                walk(arena, *body_value, &iter_bindings, depth + 1, diagnostics, parameters, mappings, budget);
            if budget.halted() {
                return;
            }
            insert_unique(out, new_key, new_value, span, diagnostics);
        }
    }
}

/// Appends `(key, value)` unless `key` already exists, in which case the
/// duplicate is a transform error (matching CloudFormation, which rejects a
/// `Fn::ForEach` that would define the same logical ID twice).
fn insert_unique(
    entries: &mut Vec<(String, NodeRef)>,
    key: String,
    value: NodeRef,
    span: SourceSpan,
    diagnostics: &mut Vec<ParseDefect>,
) {
    if entries.iter().any(|(k, _)| k == &key) {
        diagnostics.push(transform_error(&format!("Duplicate {} while doing transformation", key), span, ""));
        return;
    }
    entries.push((key, value));
}

/// Resolves a `Fn::ForEach` collection to the list of scalar values to iterate.
/// Literal string lists resolve directly; a `Ref`/`Fn::FindInMap` that resolves
/// to a list is used; anything unresolved yields two opaque placeholders so the
/// body is still shape-checked once without inventing concrete names.
fn resolve_collection(
    arena: &Arena,
    collection_ref: NodeRef,
    bindings: &Bindings,
    parameters: NodeRef,
    mappings: NodeRef,
) -> Vec<String> {
    // A literal list of scalars.
    if let Some(items) = arena.as_list(collection_ref) {
        let mut values = Vec::with_capacity(items.len());
        for item in items {
            match arena.node(*item) {
                Node::String(s) => values.push(substitute_string(s, bindings)),
                Node::Int(i) => values.push(i.to_string()),
                Node::Intrinsic(IntrinsicFn::Ref(target)) if bindings.contains_key(target) => {
                    if let Some(v) = bindings.get(target) {
                        values.push(v.clone());
                    }
                }
                // A non-literal member cannot be resolved offline; fall back to
                // a placeholder. Placeholders are indexed so distinct members
                // stay distinct - a shared placeholder would collapse the
                // generated keys and report a duplicate that does not exist.
                _ => values.push(placeholder(values.len())),
            }
        }
        return values;
    }

    // A `Ref` to a bound loop variable (nested loop) or a parameter whose
    // default/allowed values give a comma-delimited list.
    if let Node::Intrinsic(IntrinsicFn::Ref(target)) = arena.node(collection_ref) {
        match bindings.get(target) {
            Some(value) => return vec![value.clone()],
            None => {
                if let Some(values) = parameter_collection(arena, target, parameters) {
                    return values;
                }
            }
        }
    }

    // A `Fn::FindInMap` that resolves to a literal list in the Mappings.
    if let Node::Intrinsic(IntrinsicFn::FindInMap(map, top, second, _)) = arena.node(collection_ref)
        && let Some(values) = findinmap_list(arena, *map, *top, *second, mappings)
    {
        return values;
    }

    // Unresolvable collection: two opaque placeholders so the body is still
    // shape-checked without materializing concrete iteration values.
    vec![placeholder(0), placeholder(1)]
}

/// A stable synthetic placeholder value for an unresolvable collection element.
/// A deterministic value keeps the offline model reproducible while still
/// producing a valid alphanumeric token usable in a logical ID.
fn placeholder(index: usize) -> String {
    format!("ForEachValue{}", index)
}

/// Returns the comma-delimited list value of a parameter when it is a
/// `CommaDelimitedList` (or `List<...>`): the `Default` when present, else the
/// first `AllowedValues` entry - the same fallback order the transform uses
/// when it expands a loop over a parameter collection.
fn parameter_collection(arena: &Arena, name: &str, parameters: NodeRef) -> Option<Vec<String>> {
    if parameters == NULL_REF {
        return None;
    }
    let param_ref = arena.map_get(parameters, name)?;
    let entries = arena.as_map(param_ref)?;
    let type_ref = entries.iter().find(|(k, _)| k == "Type").map(|(_, v)| *v)?;
    let param_type = arena.as_str(type_ref)?;
    if !(param_type == "CommaDelimitedList" || param_type.starts_with("List<")) {
        return None;
    }
    let scalar = entries.iter().find(|(k, _)| k == "Default").and_then(|(_, v)| arena.as_str(*v)).or_else(|| {
        let allowed_ref = entries.iter().find(|(k, _)| k == "AllowedValues").map(|(_, v)| *v)?;
        let first = arena.as_list(allowed_ref)?.first().copied()?;
        arena.as_str(first)
    })?;
    Some(scalar.split(',').map(|s| s.trim().to_string()).collect())
}

/// Resolves a `Fn::FindInMap[map, top, second]` to a literal list when the
/// mapping value is a list of scalars. The transform's
/// fallbacks: an unresolvable *top* key is satisfied by scanning the mapping's
/// top-level entries for one that contains the (literal) second key, preferring
/// the entry with the longest list - so `!FindInMap [M, !Ref Env, Names]`
/// resolves through whichever environment block defines `Names`.
fn findinmap_list(
    arena: &Arena,
    map: NodeRef,
    top: NodeRef,
    second: NodeRef,
    mappings: NodeRef,
) -> Option<Vec<String>> {
    if mappings == NULL_REF {
        return None;
    }
    let map_name = arena.as_str(map)?;
    let second_key = arena.as_str(second)?;
    let map_node = arena.map_get(mappings, map_name)?;
    let top_node = match arena.as_str(top) {
        Some(top_key) => arena.map_get(map_node, top_key)?,
        // Top key not a literal (e.g. `!Ref Environment`): fall back to the
        // top-level entry containing the second key with the longest list.
        None => {
            let entries = arena.as_map(map_node)?;
            let mut best: Option<(usize, NodeRef)> = None;
            for (_, entry_ref) in entries {
                if let Some(value_ref) = arena.map_get(*entry_ref, second_key)
                    && let Some(items) = arena.as_list(value_ref)
                    && best.map(|(len, _)| items.len() > len).unwrap_or(true)
                {
                    best = Some((items.len(), *entry_ref));
                }
            }
            best.map(|(_, entry)| entry)?
        }
    };
    let value_node = arena.map_get(top_node, second_key)?;
    let items = arena.as_list(value_node)?;
    let mut values = Vec::with_capacity(items.len());
    for item in items {
        values.push(arena.as_str(*item)?.to_string());
    }
    Some(values)
}

fn rebuild_intrinsic(
    arena: &mut Arena,
    intrinsic: &IntrinsicFn,
    bindings: &Bindings,
    depth: u32,
    diagnostics: &mut Vec<ParseDefect>,
    parameters: NodeRef,
    mappings: NodeRef,
    budget: &mut ExpansionBudget,
) -> IntrinsicFn {
    let mut w = |child: NodeRef| walk(arena, child, bindings, depth + 1, diagnostics, parameters, mappings, budget);
    match intrinsic {
        IntrinsicFn::If(cond, t, f) => IntrinsicFn::If(cond.clone(), w(*t), w(*f)),
        IntrinsicFn::IfExpr(c, t, f) => IntrinsicFn::IfExpr(w(*c), w(*t), w(*f)),
        IntrinsicFn::Select(idx, src) => IntrinsicFn::Select(w(*idx), w(*src)),
        IntrinsicFn::Split(d, s) => IntrinsicFn::Split(w(*d), w(*s)),
        IntrinsicFn::Join(d, list) => IntrinsicFn::Join(w(*d), w(*list)),
        IntrinsicFn::Base64(a) => IntrinsicFn::Base64(w(*a)),
        IntrinsicFn::Cidr(a, b, c) => IntrinsicFn::Cidr(w(*a), w(*b), w(*c)),
        IntrinsicFn::GetAZs(a) => IntrinsicFn::GetAZs(w(*a)),
        IntrinsicFn::ImportValue(a) => IntrinsicFn::ImportValue(w(*a)),
        IntrinsicFn::FindInMap(a, b, c, d) => IntrinsicFn::FindInMap(w(*a), w(*b), w(*c), d.map(&mut w)),
        IntrinsicFn::And(items) => IntrinsicFn::And(items.iter().map(|r| w(*r)).collect()),
        IntrinsicFn::Or(items) => IntrinsicFn::Or(items.iter().map(|r| w(*r)).collect()),
        IntrinsicFn::Not(a) => IntrinsicFn::Not(w(*a)),
        IntrinsicFn::Equals(a, b) => IntrinsicFn::Equals(w(*a), w(*b)),
        IntrinsicFn::Length(a) => IntrinsicFn::Length(w(*a)),
        IntrinsicFn::ToJsonString(a) => IntrinsicFn::ToJsonString(w(*a)),
        IntrinsicFn::Contains(a, b) => IntrinsicFn::Contains(w(*a), w(*b)),
        IntrinsicFn::EachMemberEquals(a, b) => IntrinsicFn::EachMemberEquals(w(*a), w(*b)),
        IntrinsicFn::EachMemberIn(a, b) => IntrinsicFn::EachMemberIn(w(*a), w(*b)),
        IntrinsicFn::ForEach(id, ident, coll, body) => {
            IntrinsicFn::ForEach(id.clone(), ident.clone(), w(*coll), w(*body))
        }
        IntrinsicFn::GetStackOutput(pairs) => {
            IntrinsicFn::GetStackOutput(pairs.iter().map(|(k, v)| (k.clone(), w(*v))).collect())
        }
        // Reference/name-only intrinsics carry no child refs to rewrite; a loop
        // variable in their string arguments is handled by substituting those
        // strings directly.
        IntrinsicFn::Ref(t) => IntrinsicFn::Ref(substitute_string(t, bindings)),
        IntrinsicFn::GetAtt(r, a) => {
            IntrinsicFn::GetAtt(substitute_string(r, bindings), substitute_string(a, bindings))
        }
        IntrinsicFn::Sub(t, s) => IntrinsicFn::Sub(t.clone(), s.clone()),
        IntrinsicFn::Transform(name, pairs) => {
            IntrinsicFn::Transform(name.clone(), pairs.iter().map(|(k, v)| (k.clone(), w(*v))).collect())
        }
        IntrinsicFn::ValueOf(a, b) => IntrinsicFn::ValueOf(a.clone(), b.clone()),
        IntrinsicFn::ValueOfAll(a, b) => IntrinsicFn::ValueOfAll(a.clone(), b.clone()),
        IntrinsicFn::RefAll(a) => IntrinsicFn::RefAll(a.clone()),
    }
}

/// Substitutes `${Identifier}` and `&{Identifier}` placeholders in `s`. `${}`
/// inserts the bound value verbatim; `&{}` strips non-alphanumeric characters
/// from it (used where the result must be a valid logical ID). The bare
/// identifier is never substituted.
fn substitute_string(s: &str, bindings: &Bindings) -> String {
    if bindings.is_empty() || !(s.contains("${") || s.contains("&{")) {
        return s.to_string();
    }
    let mut result = s.to_string();
    for (name, value) in bindings {
        result = result.replace(&format!("${{{}}}", name), value);
        let sanitized: String = value.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
        result = result.replace(&format!("&{{{}}}", name), &sanitized);
    }
    result
}

/// True if `s` still contains an `Fn::Sub` variable placeholder `${Name}`. The
/// literal escape `${!Name}` is not a variable, so it does not count.
pub(crate) fn contains_sub_variable(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'$' && bytes[i + 1] == b'{' {
            // `${!` is the literal escape, not a variable reference.
            if bytes.get(i + 2) != Some(&b'!') {
                return true;
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    false
}

/// Renders `Fn::Sub`'s literal escape sequences: every `${!` becomes `${`,
/// which is how CloudFormation produces the final string.
pub(crate) fn unescape_sub_literals(s: &str) -> String {
    s.replace("${!", "${")
}

fn transform_error(message: &str, span: SourceSpan, build_path: &str) -> ParseDefect {
    let located = if span == UNKNOWN_SPAN && build_path.is_empty() { UNKNOWN_SPAN } else { span };
    crate::make_parse_defect_at("E0001", format!("Error transforming template: {}", message), located, build_path)
}

#[cfg(test)]
mod tests {
    use crate::SemanticModel;
    use crate::defect::ParseDefect;

    fn model(yaml: &str) -> SemanticModel {
        SemanticModel::from_bytes(yaml.as_bytes()).expect("model builds")
    }

    fn resource_ids(model: &SemanticModel) -> Vec<String> {
        let mut ids: Vec<String> = model.resources.keys().cloned().collect();
        ids.sort();
        ids
    }

    #[test]
    fn substitutes_only_placeholders_never_bare_identifier() {
        // Loop var 'Name' must not corrupt the property key 'DisplayName'.
        let m = model(
            "\
Transform: AWS::LanguageExtensions
Resources:
  Fn::ForEach::Topics:
    - Name
    - [Alpha, Beta]
    - Topic${Name}:
        Type: AWS::SNS::Topic
        Properties:
          DisplayName: fixed
",
        );
        let ids = resource_ids(&m);
        assert_eq!(ids, vec!["TopicAlpha".to_string(), "TopicBeta".to_string()]);
        // No additional-properties schema error from a corrupted 'DisplayName' key.
        assert!(!m.diagnostics.iter().any(|d| d.rule_id == "F3002"), "expected no schema corruption");
    }

    #[test]
    fn ampersand_form_builds_valid_logical_ids() {
        let m = model(
            "\
Transform: AWS::LanguageExtensions
Resources:
  Fn::ForEach::Buckets:
    - Id
    - [\"a-b\", \"c-d\"]
    - Bucket&{Id}:
        Type: AWS::S3::Bucket
",
        );
        let ids = resource_ids(&m);
        assert_eq!(ids, vec!["Bucketab".to_string(), "Bucketcd".to_string()]);
        assert!(!m.diagnostics.iter().any(|d| d.rule_id == "F0006"), "expected valid logical IDs, no F0006");
    }

    #[test]
    fn nested_intrinsic_substitution_is_applied() {
        // A loop var inside a nested Fn::Select must be substituted, not left as
        // the literal '${Item}'.
        let m = model(
            "\
Transform: AWS::LanguageExtensions
Resources:
  Fn::ForEach::Buckets:
    - Item
    - [aa, bb]
    - Bucket${Item}:
        Type: AWS::S3::Bucket
        Properties:
          BucketName: !Select [1, [fixed, \"${Item}\"]]
",
        );
        let aa = m.resources.get("Bucketaa").expect("Bucketaa expanded");
        // The Select resolved to the second element, which is the substituted
        // loop value 'aa', not the literal '${Item}'.
        let resolved = match aa.properties.get("BucketName") {
            Some(crate::resolver::ResolvedValue::Concrete { value }) => value.0.as_str().map(str::to_string),
            _ => None,
        };
        assert_eq!(resolved.as_deref(), Some("aa"), "loop var must be substituted inside Fn::Select");
    }

    #[test]
    fn wrong_arity_is_a_transform_error() {
        let m = model(
            "\
Transform: AWS::LanguageExtensions
Resources:
  Fn::ForEach::Bad:
    - Id
    - [a, b]
    - ABucket:
        Type: AWS::S3::Bucket
    - extra
",
        );
        assert!(
            m.diagnostics.iter().any(|d| d.rule_id == "E0001" && d.message.contains("list of 3 elements")),
            "4-element Fn::ForEach must be E0001"
        );
    }

    #[test]
    fn duplicate_generated_key_is_a_transform_error() {
        // A body key that does not reference the iterator produces the same
        // logical ID on every iteration.
        let m = model(
            "\
Transform: AWS::LanguageExtensions
Resources:
  Fn::ForEach::Dup:
    - Id
    - [a, b]
    - FixedBucket:
        Type: AWS::S3::Bucket
",
        );
        assert!(
            m.diagnostics.iter().any(|d| d.rule_id == "E0001" && d.message.contains("Duplicate")),
            "duplicate generated logical ID must be E0001"
        );
    }

    #[test]
    fn nested_loops_expand() {
        let m = model(
            "\
Transform: AWS::LanguageExtensions
Resources:
  Fn::ForEach::Outer:
    - X
    - [a, b]
    - Fn::ForEach::Inner:
        - Y
        - [1, 2]
        - Bucket${X}${Y}:
            Type: AWS::S3::Bucket
",
        );
        let ids = resource_ids(&m);
        assert_eq!(ids, vec!["Bucketa1", "Bucketa2", "Bucketb1", "Bucketb2"]);
    }

    #[test]
    fn mappings_section_loops_expand() {
        // The LanguageExtensions transform expands Fn::ForEach in Mappings; the
        // generated maps must exist and the raw macro key must not trip the
        // Mappings shape check.
        let m = model(
            "\
Transform: AWS::LanguageExtensions
Mappings:
  Fn::ForEach::MapLoop:
    - X
    - [a, b]
    - Map${X}:
        k:
          v: value
Resources:
  B:
    Type: AWS::S3::Bucket
",
        );
        assert!(!m.diagnostics.iter().any(|d| d.rule_id == "F0017"), "no Mappings shape error: {:?}", m.diagnostics);
    }

    #[test]
    fn unresolvable_collection_members_stay_distinct() {
        // Two unresolvable members must produce two distinct placeholder values,
        // not a duplicate-key transform error.
        let m = model(
            "\
Transform: AWS::LanguageExtensions
Parameters:
  A:
    Type: String
  B:
    Type: String
Resources:
  Fn::ForEach::Loop:
    - X
    - [!Ref A, !Ref B]
    - Topic${X}:
        Type: AWS::SNS::Topic
",
        );
        assert!(
            !m.diagnostics.iter().any(|d| d.rule_id == "E0001"),
            "distinct placeholders must not collide: {:?}",
            m.diagnostics
        );
        assert_eq!(m.resources.len(), 2, "both iterations materialize");
    }

    #[test]
    fn findinmap_collection_resolves_through_unresolvable_top_key() {
        // `!FindInMap [M, !Ref Env, Names]` with a single environment block:
        // the collection resolves through the block containing `Names`, so the
        // generated logical IDs use the real mapping values.
        let m = model(
            "\
Transform: AWS::LanguageExtensions
Parameters:
  Env:
    Type: String
Mappings:
  M:
    prod:
      Names: [One, Two]
Resources:
  Fn::ForEach::Loop:
    - N
    - !FindInMap [M, !Ref Env, Names]
    - Topic${N}:
        Type: AWS::SNS::Topic
",
        );
        let ids = resource_ids(&m);
        assert_eq!(ids, vec!["TopicOne", "TopicTwo"], "mapping fallback must resolve the collection");
    }

    #[test]
    fn collapsed_sub_unescapes_literal_placeholders() {
        let m = model(
            "\
Transform: AWS::LanguageExtensions
Resources:
  Fn::ForEach::Loop:
    - X
    - [a]
    - Topic${X}:
        Type: AWS::SNS::Topic
        Properties:
          DisplayName: !Sub \"lit-${!NotAVar}-end\"
",
        );
        let topic = m.resources.get("Topica").expect("expanded");
        let resolved = match topic.properties.get("DisplayName") {
            Some(crate::resolver::ResolvedValue::Concrete { value }) => value.0.as_str().map(str::to_string),
            _ => None,
        };
        assert_eq!(resolved.as_deref(), Some("lit-${NotAVar}-end"), "escape must render as CloudFormation does");
    }

    /// A single loop within the budget must expand cleanly without diagnostics.
    #[test]
    fn foreach_within_budget_expands_cleanly() {
        // A loop producing 10 elements is well within the budget.
        let items: Vec<String> = (0..10).map(|i| format!("V{}", i)).collect();
        let collection = items.join(", ");
        let yaml = format!(
            "Transform: AWS::LanguageExtensions\nResources:\n  Fn::ForEach::Loop:\n    - Id\n    - [{}]\n    - R${{Id}}:\n        Type: AWS::SNS::Topic\n",
            collection
        );
        let m = model(&yaml);
        assert_eq!(m.resources.len(), 10);
        assert!(
            !m.diagnostics.iter().any(|d| d.message.contains("expansion budget")),
            "must not emit budget diagnostic within limits"
        );
    }

    /// Nested loops that exceed the budget must emit one transform diagnostic
    /// and stop materialization safely.
    #[test]
    fn foreach_exceeding_budget_emits_diagnostic() {
        // Two nested loops: 5x5=25 iterations. With budget of 20, it must exhaust.
        let yaml = "Transform: AWS::LanguageExtensions\nResources:\n  Fn::ForEach::Outer:\n    - A\n    - [A0, A1, A2, A3, A4]\n    - Fn::ForEach::Inner:\n        - B\n        - [B0, B1, B2, B3, B4]\n        - R&{A}&{B}:\n            Type: AWS::SNS::Topic\n";

        let mut ir = crate::parser::parse(yaml.as_bytes()).expect("fixture must parse");
        assert!(
            ir.transforms.iter().any(|t| t == "AWS::LanguageExtensions"),
            "transforms must include LanguageExtensions after parse; got: {:?}",
            ir.transforms
        );
        let diagnostics = super::expand_language_extensions_with_budget(&mut ir, 20);
        let budget_diags: Vec<&ParseDefect> =
            diagnostics.iter().filter(|d| d.message.contains("expansion budget")).collect();
        assert_eq!(budget_diags.len(), 1, "exactly one budget-exhaustion diagnostic expected, got: {:?}", budget_diags);
        assert_eq!(budget_diags[0].rule_id, "E0001");
        // Budget was 20; 25+ iterations attempted; materialization must be truncated.
        let resource_count = ir.arena.as_map(ir.resources).map(|m| m.len()).unwrap_or(0);
        assert!(
            resource_count < 25,
            "materialization must be truncated below the full product, got {} resources",
            resource_count
        );
    }

    /// A budget exactly at the boundary succeeds; one unit over fails.
    #[test]
    fn foreach_budget_exact_boundary() {
        let yaml = "Transform: AWS::LanguageExtensions\nResources:\n  Fn::ForEach::Loop:\n    - X\n    - [A, B, C, D, E]\n    - R${X}:\n        Type: AWS::SNS::Topic\n";

        // Each simple iteration costs exactly three units: one collection item,
        // one generated resource map, and its `Type` scalar. Five iterations
        // therefore consume exactly 15 units and must succeed.
        let mut ir = crate::parser::parse(yaml.as_bytes()).expect("fixture must parse");
        let diagnostics = super::expand_language_extensions_with_budget(&mut ir, 15);
        assert!(
            !diagnostics.iter().any(|d| d.message.contains("expansion budget")),
            "the exact 15-unit budget must succeed; got: {:?}",
            diagnostics
        );
        let resource_count = ir.arena.as_map(ir.resources).map(|m| m.len()).unwrap_or(0);
        assert_eq!(resource_count, 5, "all 5 resources must materialize");

        // One unit below the exact cost must fail visibly and leave the original
        // section in place rather than apply a partial transformed section.
        let mut ir = crate::parser::parse(yaml.as_bytes()).expect("fixture must parse");
        let diagnostics = super::expand_language_extensions_with_budget(&mut ir, 14);
        let budget_diags: Vec<&ParseDefect> =
            diagnostics.iter().filter(|d| d.message.contains("expansion budget")).collect();
        assert_eq!(budget_diags.len(), 1, "a 14-unit budget must trigger exactly one exhaustion diagnostic");
        assert_eq!(budget_diags[0].rule_id, "E0001");
        let keys: Vec<&str> =
            ir.arena.as_map(ir.resources).unwrap_or_default().iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(keys, ["Fn::ForEach::Loop"], "the original untransformed section must remain intact");
    }
}
