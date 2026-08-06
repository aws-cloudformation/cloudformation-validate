use crate::consts::*;
use crate::resolver::MapEntry;
use crate::resolver::ResolvedValue;
use std::collections::HashMap;

pub fn resolved_value_at_path(val: &ResolvedValue, path: &str) -> Option<ResolvedValue> {
    let mut segments = path.splitn(2, '.');
    let key = segments.next()?;
    let remaining = segments.next();

    let child = match val {
        ResolvedValue::Concrete { value: json_val } => {
            if path.contains("{}") {
                let results = json_values_matching_wildcard_path(json_val, path);
                return if results.is_empty() {
                    None
                } else {
                    Some(ResolvedValue::Enum {
                        variants: results
                            .into_iter()
                            .map(|v| ResolvedValue::Concrete { value: v.clone().into() })
                            .collect(),
                    })
                };
            }
            return json_value_at_path(json_val, path).map(|v| ResolvedValue::Concrete { value: v.clone().into() });
        }
        ResolvedValue::List { items } => {
            if key == "{}" {
                let walked: Vec<ResolvedValue> = items
                    .iter()
                    .filter_map(|item| match remaining {
                        Some(rest) if !rest.is_empty() => resolved_value_at_path(item, rest),
                        _ => Some(item.clone()),
                    })
                    .collect();
                return if walked.is_empty() { None } else { Some(ResolvedValue::Enum { variants: walked }) };
            }
            let idx: usize = key.parse().ok()?;
            items.get(idx)?.clone()
        }
        ResolvedValue::Map { entries } => entries.iter().find(|e| e.key == key).map(|e| e.value.clone())?,
        ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f } => {
            let t_walked = resolved_value_at_path(t, path);
            let f_walked = resolved_value_at_path(f, path);
            return match (t_walked, f_walked) {
                (Some(tw), Some(fw)) => Some(ResolvedValue::Conditional {
                    condition: cond.clone(),
                    if_true: Box::new(tw),
                    if_false: Box::new(fw),
                }),
                (Some(tw), None) => Some(ResolvedValue::Conditional {
                    condition: cond.clone(),
                    if_true: Box::new(tw),
                    if_false: Box::new(ResolvedValue::Dynamic { reason: "path not found in false branch".into() }),
                }),
                (None, Some(fw)) => Some(ResolvedValue::Conditional {
                    condition: cond.clone(),
                    if_true: Box::new(ResolvedValue::Dynamic { reason: "path not found in true branch".into() }),
                    if_false: Box::new(fw),
                }),
                (None, None) => None,
            };
        }
        ResolvedValue::Enum { variants: vals } => {
            let walked: Vec<ResolvedValue> = vals.iter().filter_map(|v| resolved_value_at_path(v, path)).collect();
            return if walked.is_empty() { None } else { Some(ResolvedValue::Enum { variants: walked }) };
        }
        _ => return None,
    };

    match remaining {
        Some(rest) if !rest.is_empty() => resolved_value_at_path(&child, rest),
        _ => Some(child),
    }
}

pub fn collect_condition_refs_from_resolved(val: &ResolvedValue, out: &mut Vec<String>) {
    match val {
        ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f } => {
            out.push(cond.clone());
            collect_condition_refs_from_resolved(t, out);
            collect_condition_refs_from_resolved(f, out);
        }
        ResolvedValue::List { items } => {
            for v in items {
                collect_condition_refs_from_resolved(v, out);
            }
        }
        ResolvedValue::Map { entries } => {
            for e in entries {
                collect_condition_refs_from_resolved(&e.value, out);
            }
        }
        ResolvedValue::Enum { variants: vals } => {
            for v in vals {
                collect_condition_refs_from_resolved(v, out);
            }
        }
        _ => {}
    }
}

pub fn collect_conditional_nulls(val: &ResolvedValue, path: &str, out: &mut Vec<(String, String, bool)>) {
    match val {
        ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f } => {
            let t_null = is_resolved_null(t);
            let f_null = is_resolved_null(f);
            if t_null {
                out.push((path.to_string(), cond.clone(), true));
            }
            if f_null {
                out.push((path.to_string(), cond.clone(), false));
            }
            if !t_null {
                collect_conditional_nulls(t, path, out);
            }
            if !f_null {
                collect_conditional_nulls(f, path, out);
            }
        }
        ResolvedValue::Map { entries } => {
            for e in entries {
                collect_conditional_nulls(&e.value, &format!("{}.{}", path, e.key), out);
            }
        }
        ResolvedValue::List { items } => {
            for (i, v) in items.iter().enumerate() {
                collect_conditional_nulls(v, &format!("{}.{}", path, i), out);
            }
        }
        ResolvedValue::Enum { variants: vals } => {
            for v in vals {
                collect_conditional_nulls(v, path, out);
            }
        }
        _ => {}
    }
}

fn is_resolved_null(val: &ResolvedValue) -> bool {
    match val {
        ResolvedValue::Concrete { value: v } if v.is_null() => true,
        ResolvedValue::Conditional { if_true: t, if_false: f, .. } => is_resolved_null(t) && is_resolved_null(f),
        _ => false,
    }
}

pub fn collect_scenarios(
    val: &ResolvedValue,
    assumptions: &HashMap<String, bool>,
    results: &mut Vec<(ResolvedValue, HashMap<String, bool>)>,
) {
    match val {
        ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f } => {
            if assumptions.contains_key(cond.as_str()) {
                if assumptions[cond.as_str()] {
                    collect_scenarios(t, assumptions, results);
                } else {
                    collect_scenarios(f, assumptions, results);
                }
            } else {
                let mut true_assumptions = assumptions.clone();
                true_assumptions.insert(cond.clone(), true);
                collect_scenarios(t, &true_assumptions, results);
                let mut false_assumptions = assumptions.clone();
                false_assumptions.insert(cond.clone(), false);
                collect_scenarios(f, &false_assumptions, results);
            }
        }
        ResolvedValue::Enum { variants: vals } => {
            for v in vals {
                collect_scenarios(v, assumptions, results);
            }
        }
        ResolvedValue::List { items } => {
            let has_branching = items
                .iter()
                .any(|v| matches!(v, ResolvedValue::Conditional { .. } | ResolvedValue::Enum { variants: _ }));
            if has_branching {
                expand_list_scenarios(items, assumptions, results);
            } else {
                results.push((val.clone(), assumptions.clone()));
            }
        }
        ResolvedValue::Map { entries } => {
            let has_branching = entries
                .iter()
                .any(|e| matches!(e.value, ResolvedValue::Conditional { .. } | ResolvedValue::Enum { variants: _ }));
            if has_branching {
                expand_map_scenarios(entries, assumptions, results);
            } else {
                results.push((val.clone(), assumptions.clone()));
            }
        }
        _ => {
            results.push((val.clone(), assumptions.clone()));
        }
    }
}

pub fn contains_dynamic_resolved(rv: &ResolvedValue) -> bool {
    match rv {
        ResolvedValue::Dynamic { reason: _ } | ResolvedValue::TypedDynamic { .. } | ResolvedValue::Reference { .. } => {
            true
        }
        ResolvedValue::List { items } => items.iter().any(contains_dynamic_resolved),
        ResolvedValue::Map { entries } => entries.iter().any(|e| contains_dynamic_resolved(&e.value)),
        ResolvedValue::Enum { variants: vals } => vals.iter().any(contains_dynamic_resolved),
        ResolvedValue::Conditional { if_true: t, if_false: f, .. } => {
            contains_dynamic_resolved(t) || contains_dynamic_resolved(f)
        }
        ResolvedValue::Concrete { value: v } => json_contains_markers(v),
    }
}

pub fn json_contains_markers(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Object(m) => {
            m.contains_key(MARKER_DYNAMIC)
                || m.contains_key(MARKER_REF)
                || m.contains_key(MARKER_INTRINSIC)
                || m.contains_key(MARKER_CONDITIONAL)
                || m.contains_key(MARKER_ENUM)
                || m.values().any(json_contains_markers)
        }
        serde_json::Value::Array(a) => a.iter().any(json_contains_markers),
        _ => false,
    }
}

/// The shortest and longest a string value can be at deployment, or `None` when
/// any possibility is unknown.
///
/// A length constraint may only be reported broken when it is broken for every
/// possibility, so one unknown possibility withdraws the whole estimate instead
/// of narrowing it. Bounds rather than a single number are what let a caller tell
/// "every possibility is too long" from "every possibility is too short".
pub fn estimate_resolved_string_length_bounds(val: &ResolvedValue) -> Option<(usize, usize)> {
    match val {
        ResolvedValue::Concrete { value: v } if v.is_string() => {
            let length = v.as_str()?.len();
            Some((length, length))
        }
        // A partially resolved Sub or Join is a description of what could be
        // worked out, not the value. Its length is only the value's length when
        // nothing is still standing in for something unknown: a `${...}`
        // interpolation expands to any length at deploy time, and a reference
        // placeholder is internal text whose width says nothing about the value it
        // stands for. Measuring either would report a length the template never
        // produces.
        ResolvedValue::Dynamic { reason: desc } if desc.starts_with(SUB_PARTIAL_PREFIX) => {
            partial_length_bounds(&desc[SUB_PARTIAL_PREFIX.len()..])
        }
        ResolvedValue::Dynamic { reason: desc } if desc.starts_with(JOIN_PARTIAL_PREFIX) => {
            partial_length_bounds(&desc[JOIN_PARTIAL_PREFIX.len()..])
        }
        ResolvedValue::Dynamic { reason: _ } => None,
        ResolvedValue::Conditional { if_true: t, if_false: f, .. } => {
            let (true_shortest, true_longest) = estimate_resolved_string_length_bounds(t)?;
            let (false_shortest, false_longest) = estimate_resolved_string_length_bounds(f)?;
            Some((true_shortest.min(false_shortest), true_longest.max(false_longest)))
        }
        ResolvedValue::Enum { variants } => {
            let mut bounds: Option<(usize, usize)> = None;
            for variant in variants {
                let (shortest, longest) = estimate_resolved_string_length_bounds(variant)?;
                bounds = Some(match bounds {
                    Some((known_shortest, known_longest)) => (known_shortest.min(shortest), known_longest.max(longest)),
                    None => (shortest, longest),
                });
            }
            bounds
        }
        _ => None,
    }
}

fn partial_length_bounds(partial: &str) -> Option<(usize, usize)> {
    if has_interpolation_variable(partial)
        || partial.contains(UNRESOLVED_REF_PLACEHOLDER_PREFIX)
        || partial.contains(UNRESOLVED_DYNAMIC_PLACEHOLDER)
    {
        None
    } else {
        Some((partial.len(), partial.len()))
    }
}

fn has_interpolation_variable(template: &str) -> bool {
    let bytes = template.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'$'
            && bytes[i + 1] == b'{'
            && let Some(_end) = template[i + 2..].find('}')
        {
            return true;
        }
        i += 1;
    }
    false
}

fn json_value_at_path<'a>(val: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = val;
    for segment in path.split('.') {
        match current {
            serde_json::Value::Object(map) => {
                current = map.get(segment)?;
            }
            serde_json::Value::Array(arr) => {
                if segment == "{}" {
                    return None;
                }
                let idx: usize = segment.parse().ok()?;
                current = arr.get(idx)?;
            }
            _ => return None,
        }
    }
    Some(current)
}

fn json_values_matching_wildcard_path(val: &serde_json::Value, path: &str) -> Vec<serde_json::Value> {
    let mut segments: Vec<&str> = path.split('.').collect();
    if segments.is_empty() {
        return vec![val.clone()];
    }
    let key = segments.remove(0);
    let remaining = if segments.is_empty() { String::new() } else { segments.join(".") };
    match val {
        serde_json::Value::Object(map) => {
            if let Some(child) = map.get(key) {
                if remaining.is_empty() {
                    vec![child.clone()]
                } else {
                    json_values_matching_wildcard_path(child, &remaining)
                }
            } else {
                vec![]
            }
        }
        serde_json::Value::Array(arr) => {
            if key == "{}" {
                arr.iter()
                    .flat_map(|item| {
                        if remaining.is_empty() {
                            vec![item.clone()]
                        } else {
                            json_values_matching_wildcard_path(item, &remaining)
                        }
                    })
                    .collect()
            } else if let Ok(idx) = key.parse::<usize>() {
                arr.get(idx)
                    .map(|child| {
                        if remaining.is_empty() {
                            vec![child.clone()]
                        } else {
                            json_values_matching_wildcard_path(child, &remaining)
                        }
                    })
                    .unwrap_or_default()
            } else {
                vec![]
            }
        }
        _ => vec![],
    }
}

/// Generic cartesian product of scenario expansions with conflict detection.
/// Each item provides its own set of scenarios. The `build_result` closure
/// assembles the final `ResolvedValue` from the collected per-item values.
fn expand_cartesian_scenarios<T: Clone>(
    items: &[(T, Vec<(ResolvedValue, HashMap<String, bool>)>)],
    base_assumptions: &HashMap<String, bool>,
    build_result: impl Fn(Vec<(T, ResolvedValue)>) -> ResolvedValue,
    results: &mut Vec<(ResolvedValue, HashMap<String, bool>)>,
) {
    let mut combos: Vec<(Vec<(T, ResolvedValue)>, HashMap<String, bool>)> =
        vec![(Vec::new(), base_assumptions.clone())];
    for (key, item_scenarios) in items {
        let mut new_combos = Vec::new();
        for (partial, partial_conds) in &combos {
            for (val, val_conds) in item_scenarios {
                let mut merged = partial_conds.clone();
                let mut conflict = false;
                for (k, v) in val_conds {
                    if let Some(&existing) = merged.get(k) {
                        if existing != *v {
                            conflict = true;
                            break;
                        }
                    } else {
                        merged.insert(k.clone(), *v);
                    }
                }
                if conflict {
                    continue;
                }
                let mut new_partial = partial.clone();
                new_partial.push((key.clone(), val.clone()));
                new_combos.push((new_partial, merged));
            }
        }
        combos = new_combos;
        if combos.len() > MAX_SCENARIO_COMBINATIONS {
            combos.truncate(MAX_SCENARIO_COMBINATIONS);
            break;
        }
    }
    for (collected, conds) in combos {
        results.push((build_result(collected), conds));
    }
}

fn expand_list_scenarios(
    items: &[ResolvedValue],
    base_assumptions: &HashMap<String, bool>,
    results: &mut Vec<(ResolvedValue, HashMap<String, bool>)>,
) {
    let prepared: Vec<(usize, Vec<(ResolvedValue, HashMap<String, bool>)>)> = items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let mut scenarios = Vec::new();
            collect_scenarios(item, base_assumptions, &mut scenarios);
            if scenarios.is_empty() {
                scenarios.push((item.clone(), base_assumptions.clone()));
            }
            (i, scenarios)
        })
        .collect();
    expand_cartesian_scenarios(
        &prepared,
        base_assumptions,
        |collected| ResolvedValue::List { items: collected.into_iter().map(|(_, v)| v).collect() },
        results,
    );
}

fn expand_map_scenarios(
    entries: &[MapEntry],
    base_assumptions: &HashMap<String, bool>,
    results: &mut Vec<(ResolvedValue, HashMap<String, bool>)>,
) {
    let prepared: Vec<(String, Vec<(ResolvedValue, HashMap<String, bool>)>)> = entries
        .iter()
        .map(|e| {
            let mut scenarios = Vec::new();
            collect_scenarios(&e.value, base_assumptions, &mut scenarios);
            if scenarios.is_empty() {
                scenarios.push((e.value.clone(), base_assumptions.clone()));
            }
            (e.key.clone(), scenarios)
        })
        .collect();
    expand_cartesian_scenarios(
        &prepared,
        base_assumptions,
        |collected| ResolvedValue::Map {
            entries: collected.into_iter().map(|(k, v)| MapEntry { key: k, value: v }).collect(),
        },
        results,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::{MapEntry, RefKind, ResolvedValue};
    use serde_json::json;

    #[test]
    fn path_into_concrete_object() {
        let val = ResolvedValue::Concrete { value: json!({"a": {"b": "found"}}).into() };
        match resolved_value_at_path(&val, "a.b") {
            Some(ResolvedValue::Concrete { value: v }) => assert_eq!(v.0, json!("found")),
            other => panic!("expected Concrete(\"found\"), got {:?}", other),
        }
    }

    #[test]
    fn path_into_concrete_array() {
        let val = ResolvedValue::Concrete { value: json!({"items": ["x", "y", "z"]}).into() };
        match resolved_value_at_path(&val, "items.1") {
            Some(ResolvedValue::Concrete { value: v }) => assert_eq!(v.0, json!("y")),
            other => panic!("expected Concrete(\"y\"), got {:?}", other),
        }
    }

    #[test]
    fn path_missing_key_returns_none() {
        let val = ResolvedValue::Concrete { value: json!({"a": 1}).into() };
        assert!(resolved_value_at_path(&val, "b").is_none(), "missing key should return None");
    }

    #[test]
    fn path_into_resolved_map() {
        let val = ResolvedValue::Map {
            entries: vec![MapEntry {
                key: "key".into(),
                value: ResolvedValue::Concrete { value: json!("val").into() },
            }],
        };
        match resolved_value_at_path(&val, "key") {
            Some(ResolvedValue::Concrete { value: v }) => assert_eq!(v.0, json!("val")),
            other => panic!("expected Concrete, got {:?}", other),
        }
    }

    #[test]
    fn path_into_resolved_list_by_index() {
        let val = ResolvedValue::List {
            items: vec![
                ResolvedValue::Concrete { value: json!("a").into() },
                ResolvedValue::Concrete { value: json!("b").into() },
            ],
        };
        match resolved_value_at_path(&val, "1") {
            Some(ResolvedValue::Concrete { value: v }) => assert_eq!(v.0, json!("b")),
            other => panic!("expected Concrete(\"b\"), got {:?}", other),
        }
    }

    #[test]
    fn path_through_conditional_both_branches() {
        let val = ResolvedValue::Conditional {
            condition: "C".into(),
            if_true: Box::new(ResolvedValue::Concrete { value: json!({"x": "true_val"}).into() }),
            if_false: Box::new(ResolvedValue::Concrete { value: json!({"x": "false_val"}).into() }),
        };
        match resolved_value_at_path(&val, "x") {
            Some(ResolvedValue::Conditional { condition: c, if_true: t, if_false: f }) => {
                assert_eq!(c, "C");
                assert!(matches!(t.as_ref(), ResolvedValue::Concrete { value: v } if v.0 == json!("true_val")));
                assert!(matches!(f.as_ref(), ResolvedValue::Concrete { value: v } if v.0 == json!("false_val")));
            }
            other => panic!("expected Conditional, got {:?}", other),
        }
    }

    #[test]
    fn path_through_conditional_one_branch_missing() {
        let val = ResolvedValue::Conditional {
            condition: "C".into(),
            if_true: Box::new(ResolvedValue::Concrete { value: json!({"x": 1}).into() }),
            if_false: Box::new(ResolvedValue::Concrete { value: json!({"y": 2}).into() }),
        };
        match resolved_value_at_path(&val, "x") {
            Some(ResolvedValue::Conditional { if_true: t, if_false: f, .. }) => {
                assert!(matches!(t.as_ref(), ResolvedValue::Concrete { value: v } if v.0 == json!(1)));
                assert!(matches!(f.as_ref(), ResolvedValue::Dynamic { reason: _ }));
            }
            other => panic!("expected Conditional with Dynamic false branch, got {:?}", other),
        }
    }

    #[test]
    fn path_through_enum_collects_variants() {
        let val = ResolvedValue::Enum {
            variants: vec![
                ResolvedValue::Concrete { value: json!({"k": "v1"}).into() },
                ResolvedValue::Concrete { value: json!({"k": "v2"}).into() },
            ],
        };
        match resolved_value_at_path(&val, "k") {
            Some(ResolvedValue::Enum { variants: vals }) => assert_eq!(vals.len(), 2),
            other => panic!("expected Enum, got {:?}", other),
        }
    }

    #[test]
    fn wildcard_path_on_concrete_array() {
        let val = ResolvedValue::Concrete {
            value: json!({
                "items": [{"name": "a"}, {"name": "b"}]
            })
            .into(),
        };
        match resolved_value_at_path(&val, "items.{}.name") {
            Some(ResolvedValue::Enum { variants: vals }) => {
                assert_eq!(vals.len(), 2);
            }
            other => panic!("expected Enum from wildcard, got {:?}", other),
        }
    }

    #[test]
    fn wildcard_path_on_resolved_list() {
        let val = ResolvedValue::List {
            items: vec![
                ResolvedValue::Map {
                    entries: vec![MapEntry {
                        key: "n".into(),
                        value: ResolvedValue::Concrete { value: json!("x").into() },
                    }],
                },
                ResolvedValue::Map {
                    entries: vec![MapEntry {
                        key: "n".into(),
                        value: ResolvedValue::Concrete { value: json!("y").into() },
                    }],
                },
            ],
        };
        match resolved_value_at_path(&val, "{}.n") {
            Some(ResolvedValue::Enum { variants: vals }) => assert_eq!(vals.len(), 2),
            other => panic!("expected Enum from wildcard on List, got {:?}", other),
        }
    }

    #[test]
    fn path_into_dynamic_returns_none() {
        let val = ResolvedValue::Dynamic { reason: "unknown".into() };
        assert!(resolved_value_at_path(&val, "anything").is_none(), "path into Dynamic should return None");
    }

    #[test]
    fn path_into_reference_returns_none() {
        let val = ResolvedValue::Reference { target: "R".into(), kind: RefKind::Ref };
        assert!(resolved_value_at_path(&val, "sub").is_none(), "path into Reference should return None");
    }

    #[test]
    fn collect_condition_refs_from_nested() {
        let val = ResolvedValue::Conditional {
            condition: "C1".into(),
            if_true: Box::new(ResolvedValue::List {
                items: vec![ResolvedValue::Conditional {
                    condition: "C2".into(),
                    if_true: Box::new(ResolvedValue::Concrete { value: json!(1).into() }),
                    if_false: Box::new(ResolvedValue::Concrete { value: json!(2).into() }),
                }],
            }),
            if_false: Box::new(ResolvedValue::Concrete { value: json!(3).into() }),
        };
        let mut refs = Vec::new();
        collect_condition_refs_from_resolved(&val, &mut refs);
        refs.sort();
        assert_eq!(refs, vec!["C1", "C2"]);
    }

    #[test]
    fn collect_conditional_nulls_detects_null_branch() {
        let val = ResolvedValue::Conditional {
            condition: "C".into(),
            if_true: Box::new(ResolvedValue::Concrete { value: json!(null).into() }),
            if_false: Box::new(ResolvedValue::Concrete { value: json!("ok").into() }),
        };
        let mut nulls = Vec::new();
        collect_conditional_nulls(&val, "prop", &mut nulls);
        assert_eq!(nulls.len(), 1);
        assert_eq!(nulls[0], ("prop".to_string(), "C".to_string(), true));
    }

    #[test]
    fn collect_scenarios_concrete_single() {
        let val = ResolvedValue::Concrete { value: json!("hello").into() };
        let mut results = Vec::new();
        collect_scenarios(&val, &HashMap::new(), &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0].0, ResolvedValue::Concrete { value: v } if v.0 == json!("hello")));
    }

    #[test]
    fn collect_scenarios_conditional_splits() {
        let val = ResolvedValue::Conditional {
            condition: "C".into(),
            if_true: Box::new(ResolvedValue::Concrete { value: json!(1).into() }),
            if_false: Box::new(ResolvedValue::Concrete { value: json!(2).into() }),
        };
        let mut results = Vec::new();
        collect_scenarios(&val, &HashMap::new(), &mut results);
        assert_eq!(results.len(), 2);
        let (_, conds_true) = &results[0];
        assert_eq!(conds_true.get("C"), Some(&true));
        let (_, conds_false) = &results[1];
        assert_eq!(conds_false.get("C"), Some(&false));
    }

    #[test]
    fn collect_scenarios_enum_expands() {
        let val = ResolvedValue::Enum {
            variants: vec![
                ResolvedValue::Concrete { value: json!("a").into() },
                ResolvedValue::Concrete { value: json!("b").into() },
            ],
        };
        let mut results = Vec::new();
        collect_scenarios(&val, &HashMap::new(), &mut results);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn collect_scenarios_respects_existing_assumptions() {
        let val = ResolvedValue::Conditional {
            condition: "C".into(),
            if_true: Box::new(ResolvedValue::Concrete { value: json!(1).into() }),
            if_false: Box::new(ResolvedValue::Concrete { value: json!(2).into() }),
        };
        let mut assumptions = HashMap::new();
        assumptions.insert("C".to_string(), true);
        let mut results = Vec::new();
        collect_scenarios(&val, &assumptions, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0].0, ResolvedValue::Concrete { value: v } if v.0 == json!(1)));
    }

    #[test]
    fn contains_dynamic_detects_nested_dynamic() {
        let val = ResolvedValue::List {
            items: vec![
                ResolvedValue::Concrete { value: json!("ok").into() },
                ResolvedValue::Dynamic { reason: "unknown".into() },
            ],
        };
        assert!(contains_dynamic_resolved(&val));
    }

    #[test]
    fn contains_dynamic_false_for_all_concrete() {
        let val = ResolvedValue::Map {
            entries: vec![MapEntry { key: "a".into(), value: ResolvedValue::Concrete { value: json!(1).into() } }],
        };
        assert!(!contains_dynamic_resolved(&val));
    }

    #[test]
    fn contains_dynamic_detects_typed_dynamic() {
        let val = ResolvedValue::TypedDynamic { reason: "param".into(), param_type: "String".into() };
        assert!(contains_dynamic_resolved(&val));
    }

    #[test]
    fn contains_dynamic_detects_reference() {
        let val = ResolvedValue::Reference { target: "R".into(), kind: RefKind::Ref };
        assert!(contains_dynamic_resolved(&val));
    }

    #[test]
    fn json_contains_markers_detects_dynamic_marker() {
        let val = json!({MARKER_DYNAMIC: "reason"});
        assert!(json_contains_markers(&val));
    }

    #[test]
    fn json_contains_markers_false_for_plain() {
        assert!(!json_contains_markers(&json!({"key": "value"})));
        assert!(!json_contains_markers(&json!("string")));
        assert!(!json_contains_markers(&json!(42)));
    }

    #[test]
    fn bounds_of_a_literal_are_its_own_length() {
        let val = ResolvedValue::Concrete { value: json!("hello").into() };
        assert_eq!(estimate_resolved_string_length_bounds(&val), Some((5, 5)));
    }

    #[test]
    fn bounds_of_a_conditional_span_both_branches() {
        let val = ResolvedValue::Conditional {
            condition: "C".into(),
            if_true: Box::new(ResolvedValue::Concrete { value: json!("short").into() }),
            if_false: Box::new(ResolvedValue::Concrete { value: json!("much longer string").into() }),
        };
        assert_eq!(estimate_resolved_string_length_bounds(&val), Some((5, "much longer string".len())));
    }

    #[test]
    fn bounds_of_a_conditional_are_absent_when_one_branch_is_unknown() {
        // The deployment may take the unknown branch, so no length holds for every
        // possibility.
        let val = ResolvedValue::Conditional {
            condition: "C".into(),
            if_true: Box::new(ResolvedValue::Concrete { value: json!("short").into() }),
            if_false: Box::new(ResolvedValue::Dynamic { reason: "unknown".into() }),
        };
        assert_eq!(estimate_resolved_string_length_bounds(&val), None);
    }

    #[test]
    fn bounds_of_allowed_values_span_every_choice() {
        let val = ResolvedValue::Enum {
            variants: vec![
                ResolvedValue::Concrete { value: json!("ab").into() },
                ResolvedValue::Concrete { value: json!("abcdef").into() },
            ],
        };
        assert_eq!(estimate_resolved_string_length_bounds(&val), Some((2, 6)));
    }

    #[test]
    fn bounds_of_allowed_values_are_absent_when_one_choice_is_unknown() {
        let val = ResolvedValue::Enum {
            variants: vec![
                ResolvedValue::Concrete { value: json!("ab").into() },
                ResolvedValue::Dynamic { reason: "unknown".into() },
            ],
        };
        assert_eq!(estimate_resolved_string_length_bounds(&val), None);
    }

    #[test]
    fn bounds_of_a_sub_with_interpolation_are_absent() {
        // A `${...}` interpolation expands to any length at deploy time, so the
        // literal portion is not a lower bound on the value.
        let val = ResolvedValue::Dynamic { reason: "Sub:arn:aws:s3:::${BucketName}".into() };
        assert_eq!(estimate_resolved_string_length_bounds(&val), None);
    }

    #[test]
    fn bounds_of_a_fully_substituted_sub_are_its_length() {
        let val = ResolvedValue::Dynamic { reason: "Sub:no-variables-here".into() };
        assert_eq!(
            estimate_resolved_string_length_bounds(&val),
            Some(("no-variables-here".len(), "no-variables-here".len()))
        );
    }

    #[test]
    fn bounds_are_absent_for_a_non_string_and_an_opaque_value() {
        assert_eq!(
            estimate_resolved_string_length_bounds(&ResolvedValue::Concrete { value: json!(42).into() }),
            None,
            "a number has no string length"
        );
        assert_eq!(
            estimate_resolved_string_length_bounds(&ResolvedValue::Dynamic { reason: "unknown".into() }),
            None,
            "an opaque value has no known length"
        );
    }

    #[test]
    fn bounds_of_a_join_with_an_unresolved_reference_are_absent() {
        // The placeholder is internal text standing in for a value that is only
        // known at deployment. Measuring it reported the width of the placeholder
        // as the length of the value, which produced length violations citing a
        // number the template never produces.
        let val = ResolvedValue::Dynamic {
            reason: format!("{JOIN_PARTIAL_PREFIX}prefix-{UNRESOLVED_REF_PLACEHOLDER_PREFIX}Other}}-suffix"),
        };
        assert_eq!(estimate_resolved_string_length_bounds(&val), None, "a placeholder has no measurable length");
    }

    #[test]
    fn bounds_of_a_join_with_an_opaque_deploy_time_value_are_absent() {
        let val = ResolvedValue::Dynamic {
            reason: format!("{JOIN_PARTIAL_PREFIX}prefix-{UNRESOLVED_DYNAMIC_PLACEHOLDER}-suffix"),
        };
        assert_eq!(
            estimate_resolved_string_length_bounds(&val),
            None,
            "a deploy-time placeholder has no measurable length"
        );
    }

    #[test]
    fn bounds_of_a_join_of_known_parts_are_its_length() {
        let val = ResolvedValue::Dynamic { reason: "Join:prefix-middle-suffix".into() };
        assert_eq!(
            estimate_resolved_string_length_bounds(&val),
            Some(("prefix-middle-suffix".len(), "prefix-middle-suffix".len()))
        );
    }

    #[test]
    fn bounds_of_a_sub_with_an_unresolved_reference_are_absent() {
        let val = ResolvedValue::Dynamic { reason: "Sub:name-{ref:Other}".into() };
        assert_eq!(estimate_resolved_string_length_bounds(&val), None, "a placeholder has no measurable length");
    }
}
