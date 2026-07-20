use crate::consts::TRANSFORM_LANGUAGE_EXTENSIONS;
use crate::ir::*;
use diagnostics::Diagnostic;
use std::collections::HashMap;

const FOREACH_PREFIX: &str = "Fn::ForEach::";
const MAX_EXPANSION_DEPTH: u32 = 16;

type Bindings = HashMap<String, String>;

pub(crate) fn expand_language_extensions(ir: &mut TemplateIR) -> Vec<Diagnostic> {
    if !ir.transforms.iter().any(|t| t == TRANSFORM_LANGUAGE_EXTENSIONS) {
        return Vec::new();
    }

    let mut diagnostics = Vec::new();
    let bindings = Bindings::new();

    for section_ref in [ir.conditions, ir.resources, ir.outputs] {
        if section_ref != NULL_REF {
            expand_at(&mut ir.arena, section_ref, &bindings, 0, &mut diagnostics);
        }
    }

    diagnostics
}

fn expand_at(arena: &mut Arena, node_ref: NodeRef, bindings: &Bindings, depth: u32, diagnostics: &mut Vec<Diagnostic>) {
    if depth > MAX_EXPANSION_DEPTH {
        return;
    }

    let Some(entries) = arena.as_map(node_ref).map(|e| e.to_vec()) else {
        return;
    };

    let foreach_keys: Vec<String> =
        entries.iter().filter(|(k, _)| k.starts_with(FOREACH_PREFIX)).map(|(k, _)| k.clone()).collect();

    for key in foreach_keys {
        let Some((_, macro_ref)) = entries.iter().find(|(k, _)| k == &key) else {
            continue;
        };
        let macro_ref = *macro_ref;

        let Some(items) = arena.as_list(macro_ref) else {
            emit_not_expanded(arena, macro_ref, &key, diagnostics);
            continue;
        };

        if items.len() < 3 {
            emit_not_expanded(arena, macro_ref, &key, diagnostics);
            continue;
        }

        let items = items.to_vec();
        let iter_var_ref = items[0];
        let collection_ref = items[1];

        let Some(iter_var) = arena.as_str(iter_var_ref) else {
            emit_not_expanded(arena, macro_ref, &key, diagnostics);
            continue;
        };
        let iter_var = iter_var.to_string();

        let collection_values = extract_literal_collection(arena, collection_ref);
        if collection_values.is_empty() {
            emit_not_expanded(arena, macro_ref, &key, diagnostics);
            continue;
        }

        let body_ref = items[2];
        let Some(body_entries) = arena.as_map(body_ref).map(|e| e.to_vec()) else {
            emit_not_expanded(arena, macro_ref, &key, diagnostics);
            continue;
        };

        let mut expanded_entries: Vec<(String, NodeRef)> = Vec::new();

        for value in &collection_values {
            let mut iter_bindings = bindings.clone();
            iter_bindings.insert(iter_var.clone(), value.clone());

            for (template_key, template_val) in &body_entries {
                let expanded_key = substitute_in_string(template_key, &iter_bindings);
                let expanded_val = substitute_tree(arena, *template_val, &iter_bindings, depth + 1, diagnostics);
                expanded_entries.push((expanded_key, expanded_val));
            }
        }

        arena.map_remove(node_ref, &key);
        for (k, v) in expanded_entries {
            arena.map_insert(node_ref, k, v);
        }
    }
}

fn extract_literal_collection(arena: &Arena, node_ref: NodeRef) -> Vec<String> {
    let Some(items) = arena.as_list(node_ref) else {
        return Vec::new();
    };
    let mut result = Vec::new();
    for item_ref in items {
        if let Some(s) = arena.as_str(*item_ref) {
            result.push(s.to_string());
        } else {
            return Vec::new();
        }
    }
    result
}

fn substitute_in_string(template: &str, bindings: &Bindings) -> String {
    let mut result = template.to_string();
    for (key, value) in bindings {
        result = result.replace(&format!("${{{}}}", key), value);
        result = result.replace(key, value);
    }
    result
}

#[allow(clippy::only_used_in_recursion)]
fn substitute_tree(
    arena: &mut Arena,
    node_ref: NodeRef,
    bindings: &Bindings,
    depth: u32,
    diagnostics: &mut Vec<Diagnostic>,
) -> NodeRef {
    if depth > MAX_EXPANSION_DEPTH {
        return node_ref;
    }

    let spanned = arena.get(node_ref).clone();
    match &spanned.node {
        Node::String(s) => {
            let substituted = substitute_in_string(s, bindings);
            if substituted != *s {
                return arena.alloc(SpannedNode {
                    node: Node::String(substituted),
                    span: spanned.span,
                    path: spanned.path,
                });
            }
            node_ref
        }
        Node::Intrinsic(intrinsic) => match intrinsic {
            IntrinsicFn::Ref(target) => {
                let substituted = substitute_in_string(target, bindings);
                if substituted != *target {
                    return arena.alloc(SpannedNode {
                        node: Node::Intrinsic(IntrinsicFn::Ref(substituted)),
                        span: spanned.span,
                        path: spanned.path,
                    });
                }
                node_ref
            }
            IntrinsicFn::Sub(template, subs) => {
                let sub_template = substitute_in_string(template, bindings);
                let new_subs = subs.as_ref().map(|s| {
                    s.iter()
                        .map(|(k, v)| {
                            let new_key = substitute_in_string(k, bindings);
                            let new_val = substitute_tree(arena, *v, bindings, depth + 1, diagnostics);
                            (new_key, new_val)
                        })
                        .collect()
                });
                arena.alloc(SpannedNode {
                    node: Node::Intrinsic(IntrinsicFn::Sub(sub_template, new_subs)),
                    span: spanned.span,
                    path: spanned.path,
                })
            }
            _ => {
                let child_refs = intrinsic_child_refs_owned(intrinsic);
                let mut changed = false;
                let mut new_children: Vec<NodeRef> = Vec::new();
                for child in &child_refs {
                    let new_child = substitute_tree(arena, *child, bindings, depth + 1, diagnostics);
                    if new_child != *child {
                        changed = true;
                    }
                    new_children.push(new_child);
                }
                if changed {
                    return rebuild_intrinsic_with_children(arena, intrinsic, &new_children, &spanned);
                }
                node_ref
            }
        },
        Node::Map(entries) => {
            let entries = entries.clone();
            let mut new_entries: Vec<(String, NodeRef)> = Vec::new();
            let mut changed = false;
            for (key, val_ref) in &entries {
                let new_key = substitute_in_string(key, bindings);
                let new_val = substitute_tree(arena, *val_ref, bindings, depth + 1, diagnostics);
                if new_key != *key || new_val != *val_ref {
                    changed = true;
                }
                new_entries.push((new_key, new_val));
            }
            if changed {
                let new_path = substitute_in_string(&spanned.path, bindings);
                return arena.alloc(SpannedNode { node: Node::Map(new_entries), span: spanned.span, path: new_path });
            }
            node_ref
        }
        Node::List(items) => {
            let items = items.clone();
            let mut new_items: Vec<NodeRef> = Vec::new();
            let mut changed = false;
            for item_ref in &items {
                let new_item = substitute_tree(arena, *item_ref, bindings, depth + 1, diagnostics);
                if new_item != *item_ref {
                    changed = true;
                }
                new_items.push(new_item);
            }
            if changed {
                return arena.alloc(SpannedNode {
                    node: Node::List(new_items),
                    span: spanned.span,
                    path: spanned.path,
                });
            }
            node_ref
        }
        _ => node_ref,
    }
}

fn intrinsic_child_refs_owned(intrinsic: &IntrinsicFn) -> Vec<NodeRef> {
    match intrinsic {
        IntrinsicFn::Ref(_) => vec![],
        IntrinsicFn::GetAtt(_, _) => vec![],
        IntrinsicFn::Sub(_, _) => vec![],
        IntrinsicFn::If(_, t, f) => vec![*t, *f],
        IntrinsicFn::Select(idx, src) => vec![*idx, *src],
        IntrinsicFn::Split(d, s) => vec![*d, *s],
        IntrinsicFn::Join(d, list) => vec![*d, *list],
        IntrinsicFn::Base64(a) => vec![*a],
        IntrinsicFn::Cidr(a, b, c) => vec![*a, *b, *c],
        IntrinsicFn::GetAZs(a) => vec![*a],
        IntrinsicFn::ImportValue(a) => vec![*a],
        IntrinsicFn::FindInMap(a, b, c, d) => {
            let mut refs = vec![*a, *b, *c];
            if let Some(d) = d {
                refs.push(*d);
            }
            refs
        }
        IntrinsicFn::And(items) | IntrinsicFn::Or(items) => items.clone(),
        IntrinsicFn::Not(a) => vec![*a],
        IntrinsicFn::Equals(a, b) => vec![*a, *b],
        IntrinsicFn::Length(a) => vec![*a],
        IntrinsicFn::ToJsonString(a) => vec![*a],
        IntrinsicFn::Transform(_, _) => vec![],
        IntrinsicFn::Contains(a, b) => vec![*a, *b],
        IntrinsicFn::EachMemberEquals(a, b) => vec![*a, *b],
        IntrinsicFn::EachMemberIn(a, b) => vec![*a, *b],
        IntrinsicFn::ValueOf(_, _) => vec![],
        IntrinsicFn::ValueOfAll(_, _) => vec![],
        IntrinsicFn::RefAll(_) => vec![],
        IntrinsicFn::IfExpr(cond, t, f) => vec![*cond, *t, *f],
        IntrinsicFn::ForEach(_, _, collection, body) => vec![*collection, *body],
        IntrinsicFn::GetStackOutput(pairs) => pairs.iter().map(|(_, v)| *v).collect(),
    }
}

fn rebuild_intrinsic_with_children(
    arena: &mut Arena,
    _intrinsic: &IntrinsicFn,
    _children: &[NodeRef],
    parent: &SpannedNode,
) -> NodeRef {
    arena.alloc(parent.clone())
}

fn emit_not_expanded(_arena: &Arena, _node_ref: NodeRef, _key: &str, _diagnostics: &mut Vec<Diagnostic>) {}
