use crate::consts::*;
use crate::ir::*;
use crate::model::ResolvedResource;
use crate::resolver::ResolvedValue;
use std::collections::{HashMap, HashSet};

pub fn extract_sam_globals(
    arena: &Arena,
    globals_ref: NodeRef,
) -> HashMap<String, HashMap<String, serde_json::Value>> {
    let mut result = HashMap::new();
    if globals_ref == NULL_REF {
        return result;
    }
    let Some(entries) = arena.as_map(globals_ref) else {
        return result;
    };
    for (type_name, node_ref) in entries {
        let Some(props) = arena.as_map(*node_ref) else {
            continue;
        };
        let mut prop_map = HashMap::new();
        for (k, v) in props {
            prop_map.insert(k.clone(), crate::resolver::node_to_json(arena, *v));
        }
        if !prop_map.is_empty() {
            result.insert(type_name.clone(), prop_map);
        }
    }
    result
}

pub fn apply_sam_globals(
    resources: &mut HashMap<String, ResolvedResource>,
    globals: &HashMap<String, HashMap<String, serde_json::Value>>,
) {
    for (short_name, defaults) in globals {
        let full_type = SAM_GLOBALS_TYPE_MAP
            .iter()
            .find(|(s, _)| *s == short_name)
            .map(|(_, t)| *t);
        let Some(full_type) = full_type else { continue };
        for res in resources.values_mut() {
            if res.resource_type != full_type {
                continue;
            }
            for (prop, val) in defaults {
                if !res.properties.contains_key(prop) {
                    res.properties.insert(
                        prop.clone(),
                        ResolvedValue::Concrete {
                            value: val.clone().into(),
                        },
                    );
                }
            }
        }
    }
}

pub fn collect_sam_implicit_resources(
    resources: &HashMap<String, ResolvedResource>,
) -> HashSet<String> {
    let mut implicit = HashSet::new();
    let mut has_api_event = false;
    for (name, res) in resources {
        if res.resource_type == SAM_FUNCTION_TYPE {
            implicit.insert(format!("{}Role", name));
            if let Some(events) = res.properties.get("Events") {
                has_api_event = has_api_event || events_contain_api(events);
            }
        }
    }
    if has_api_event {
        implicit.insert(SAM_IMPLICIT_REST_API.to_string());
    }
    implicit
}

fn events_contain_api(events: &ResolvedValue) -> bool {
    match events {
        ResolvedValue::Map { entries } => entries.iter().any(|e| is_api_event(&e.value)),
        ResolvedValue::Concrete { value: v } => {
            if let Some(obj) = v.as_object() {
                obj.values().any(|ev| {
                    ev.as_object()
                        .and_then(|o| o.get(KEY_TYPE))
                        .and_then(|t| t.as_str())
                        == Some(SAM_EVENT_TYPE_API)
                })
            } else {
                false
            }
        }
        _ => false,
    }
}

fn is_api_event(ev: &ResolvedValue) -> bool {
    match ev {
        ResolvedValue::Map { entries } => entries.iter().any(|e| {
            e.key == KEY_TYPE
                && matches!(&e.value, ResolvedValue::Concrete { value: v } if v.as_str() == Some(SAM_EVENT_TYPE_API))
        }),
        ResolvedValue::Concrete { value: v } => {
            if let Some(obj) = v.as_object() {
                obj.get(KEY_TYPE).and_then(|t| t.as_str()) == Some(SAM_EVENT_TYPE_API)
            } else {
                false
            }
        }
        _ => false,
    }
}

pub fn collect_globals_param_refs(arena: &Arena, globals_ref: NodeRef) -> Vec<String> {
    let mut refs = Vec::new();
    if globals_ref == NULL_REF {
        return refs;
    }
    collect_arena_param_refs(arena, globals_ref, &mut refs);
    refs.sort();
    refs.dedup();
    refs
}

pub fn cycle_involves_sam_diagnostic(
    diagnostic: &diagnostics::Diagnostic,
    resources: &HashMap<String, ResolvedResource>,
) -> bool {
    resources.iter().any(|(name, res)| {
        res.resource_type.starts_with(SAM_SERVERLESS_TYPE_PREFIX)
            && diagnostic.message.contains(name.as_str())
    })
}

fn collect_arena_param_refs(arena: &Arena, node_ref: NodeRef, out: &mut Vec<String>) {
    if node_ref == NULL_REF {
        return;
    }
    match arena.node(node_ref) {
        Node::Intrinsic(intrinsic) => match intrinsic {
            IntrinsicFn::Ref(target) => {
                if !target.starts_with(PSEUDO_PREFIX) {
                    out.push(target.clone());
                }
            }
            IntrinsicFn::Sub(template, subs) => {
                for cap in template.split("${").skip(1) {
                    if let Some(end) = cap.find('}') {
                        let var = &cap[..end];
                        if !var.starts_with(PSEUDO_PREFIX) && !var.contains('.') {
                            out.push(var.to_string());
                        }
                    }
                }
                if let Some(sub_list) = subs {
                    for (_, v) in sub_list {
                        collect_arena_param_refs(arena, *v, out);
                    }
                }
            }
            IntrinsicFn::If(_, t, f) => {
                collect_arena_param_refs(arena, *t, out);
                collect_arena_param_refs(arena, *f, out);
            }
            IntrinsicFn::Join(_, v) => {
                collect_arena_param_refs(arena, *v, out);
            }
            IntrinsicFn::ImportValue(v) | IntrinsicFn::Base64(v) => {
                collect_arena_param_refs(arena, *v, out);
            }
            _ => {}
        },
        Node::List(items) => {
            for r in items {
                collect_arena_param_refs(arena, *r, out);
            }
        }
        Node::Map(entries) => {
            for (_, r) in entries {
                collect_arena_param_refs(arena, *r, out);
            }
        }
        _ => {}
    }
}
