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

/// Converts an authored scenario source path into its public effective path.
/// Every `Fn::If` branch selector is an implementation detail of the authored
/// syntax and is removed; malformed selectors are rejected rather than treated
/// as ordinary property segments.
pub fn effective_path_from_scenario_source_path(source_path: &str) -> Option<String> {
    if source_path.is_empty() {
        return Some(String::new());
    }
    let segments: Vec<&str> = source_path.split('.').collect();
    if segments.iter().any(|segment| segment.is_empty()) {
        return None;
    }
    let mut effective_segments = Vec::with_capacity(segments.len());
    let mut index = 0;
    while index < segments.len() {
        if segments[index] == FN_IF {
            match segments.get(index + 1).copied() {
                Some("1" | "2") => {
                    index += 2;
                    continue;
                }
                _ => return None,
            }
        }
        effective_segments.push(segments[index]);
        index += 1;
    }
    Some(effective_segments.join("."))
}

pub fn scenario_source_path_at(
    value: &ResolvedValue,
    effective_path: &str,
    conditions: &HashMap<String, bool>,
    source_path: &str,
) -> Option<String> {
    let segments: Vec<&str> = effective_path.split('.').filter(|segment| !segment.is_empty()).collect();
    scenario_source_path_segments(value, &segments, conditions, source_path)
}

fn scenario_source_path_segments(
    value: &ResolvedValue,
    segments: &[&str],
    conditions: &HashMap<String, bool>,
    source_path: &str,
) -> Option<String> {
    match value {
        ResolvedValue::Conditional { condition, if_true, if_false } => {
            let is_true = *conditions.get(condition)?;
            let branch_index = if is_true { 1 } else { 2 };
            let branch = if is_true { if_true } else { if_false };
            scenario_source_path_segments(
                branch,
                segments,
                conditions,
                &append_source_path(source_path, &format!("Fn::If.{branch_index}")),
            )
        }
        ResolvedValue::Map { entries } => {
            let (segment, remaining) = segments.split_first()?;
            let entry = entries.iter().find(|entry| entry.key == *segment)?;
            scenario_source_path_segments(
                &entry.value,
                remaining,
                conditions,
                &append_source_path(source_path, segment),
            )
        }
        ResolvedValue::List { items } => {
            let (segment, remaining) = segments.split_first()?;
            let index: usize = segment.parse().ok()?;
            scenario_source_path_segments(
                items.get(index)?,
                remaining,
                conditions,
                &append_source_path(source_path, segment),
            )
        }
        ResolvedValue::Concrete { value } => json_scenario_source_path(value, segments, source_path),
        ResolvedValue::Enum { variants } => variants
            .iter()
            .find_map(|variant| scenario_source_path_segments(variant, segments, conditions, source_path)),
        ResolvedValue::Reference { .. } | ResolvedValue::Dynamic { .. } | ResolvedValue::TypedDynamic { .. } => {
            segments.is_empty().then(|| source_path.to_string())
        }
    }
}

fn json_scenario_source_path(value: &serde_json::Value, segments: &[&str], source_path: &str) -> Option<String> {
    let Some((segment, remaining)) = segments.split_first() else {
        return Some(source_path.to_string());
    };
    let child = match value {
        serde_json::Value::Object(map) => map.get(*segment)?,
        serde_json::Value::Array(items) => items.get(segment.parse::<usize>().ok()?)?,
        _ => return None,
    };
    json_scenario_source_path(child, remaining, &append_source_path(source_path, segment))
}

fn append_source_path(source_path: &str, segment: &str) -> String {
    if source_path.is_empty() { segment.to_string() } else { format!("{source_path}.{segment}") }
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

fn contains_scenario_branching(value: &ResolvedValue) -> bool {
    match value {
        ResolvedValue::Conditional { .. } | ResolvedValue::Enum { .. } => true,
        ResolvedValue::List { items } => items.iter().any(contains_scenario_branching),
        ResolvedValue::Map { entries } => entries.iter().any(|entry| contains_scenario_branching(&entry.value)),
        ResolvedValue::Concrete { .. }
        | ResolvedValue::Reference { .. }
        | ResolvedValue::Dynamic { .. }
        | ResolvedValue::TypedDynamic { .. } => false,
    }
}

/// Recursively expands scenario branching in a resolved value, collecting all
/// concrete possibilities with their condition assumptions.
///
/// Returns `true` when any expansion within the value tree was curtailed
/// because the intermediate product exceeded `limit`.
pub fn collect_scenarios(
    val: &ResolvedValue,
    assumptions: &HashMap<String, bool>,
    limit: usize,
    results: &mut Vec<(ResolvedValue, HashMap<String, bool>)>,
) -> bool {
    match val {
        ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f } => {
            if assumptions.contains_key(cond.as_str()) {
                if assumptions[cond.as_str()] {
                    collect_scenarios(t, assumptions, limit, results)
                } else {
                    collect_scenarios(f, assumptions, limit, results)
                }
            } else {
                let mut true_assumptions = assumptions.clone();
                true_assumptions.insert(cond.clone(), true);
                let true_curtailed = collect_scenarios(t, &true_assumptions, limit, results);
                if true_curtailed && results.len() >= limit {
                    return true;
                }
                let mut false_assumptions = assumptions.clone();
                false_assumptions.insert(cond.clone(), false);
                let false_curtailed = collect_scenarios(f, &false_assumptions, limit, results);
                true_curtailed || false_curtailed
            }
        }
        ResolvedValue::Enum { variants } => {
            let mut curtailed = false;
            for variant in variants {
                curtailed |= collect_scenarios(variant, assumptions, limit, results);
                if curtailed && results.len() >= limit {
                    break;
                }
            }
            curtailed
        }
        ResolvedValue::List { items } => {
            let has_branching = items.iter().any(contains_scenario_branching);
            if has_branching {
                expand_list_scenarios(items, assumptions, limit, results)
            } else {
                push_scenario(val, assumptions, limit, results)
            }
        }
        ResolvedValue::Map { entries } => {
            let has_branching = entries.iter().any(|entry| contains_scenario_branching(&entry.value));
            if has_branching {
                expand_map_scenarios(entries, assumptions, limit, results)
            } else {
                push_scenario(val, assumptions, limit, results)
            }
        }
        _ => push_scenario(val, assumptions, limit, results),
    }
}

fn push_scenario(
    value: &ResolvedValue,
    assumptions: &HashMap<String, bool>,
    limit: usize,
    results: &mut Vec<(ResolvedValue, HashMap<String, bool>)>,
) -> bool {
    if results.len() >= limit {
        true
    } else {
        results.push((value.clone(), assumptions.clone()));
        false
    }
}

/// Expands deployment scenarios using the standard per-value limit and reports
/// whether at least one possible scenario was omitted.
pub fn collect_scenarios_signaled(
    value: &ResolvedValue,
    assumptions: &HashMap<String, bool>,
    results: &mut Vec<(ResolvedValue, HashMap<String, bool>)>,
    curtailed: &mut bool,
) {
    *curtailed |= collect_scenarios(value, assumptions, MAX_SCENARIO_COMBINATIONS, results);
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
            let length = v.as_str()?.chars().count();
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
        let length = partial.chars().count();
        Some((length, length))
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
///
/// Returns `true` when the product had more than `limit` compatible scenarios.
/// Expansion remains bounded to `limit` partial combinations after every item,
/// but every retained combination continues through every remaining item so no
/// returned list or map is structurally incomplete.
fn expand_cartesian_scenarios<T: Clone>(
    items: &[(T, Vec<(ResolvedValue, HashMap<String, bool>)>)],
    base_assumptions: &HashMap<String, bool>,
    limit: usize,
    build_result: impl Fn(Vec<(T, ResolvedValue)>) -> ResolvedValue,
    results: &mut Vec<(ResolvedValue, HashMap<String, bool>)>,
) -> bool {
    if limit == 0 {
        return !items.is_empty();
    }

    let mut combos: Vec<(Vec<(T, ResolvedValue)>, HashMap<String, bool>)> =
        vec![(Vec::new(), base_assumptions.clone())];
    let mut curtailed = false;
    for (key, item_scenarios) in items {
        let mut new_combos = Vec::new();
        'partials: for (partial, partial_assumptions) in &combos {
            for (value, value_assumptions) in item_scenarios {
                let mut merged = partial_assumptions.clone();
                let mut conflict = false;
                for (condition, expected) in value_assumptions {
                    if let Some(existing) = merged.get(condition) {
                        if existing != expected {
                            conflict = true;
                            break;
                        }
                    } else {
                        merged.insert(condition.clone(), *expected);
                    }
                }
                if conflict {
                    continue;
                }
                if new_combos.len() == limit {
                    curtailed = true;
                    break 'partials;
                }
                let mut collected = partial.clone();
                collected.push((key.clone(), value.clone()));
                new_combos.push((collected, merged));
            }
        }
        combos = new_combos;
    }

    results.extend(combos.into_iter().map(|(collected, assumptions)| (build_result(collected), assumptions)));
    curtailed
}

fn expand_list_scenarios(
    items: &[ResolvedValue],
    base_assumptions: &HashMap<String, bool>,
    limit: usize,
    results: &mut Vec<(ResolvedValue, HashMap<String, bool>)>,
) -> bool {
    let remaining = limit.saturating_sub(results.len());
    if remaining == 0 {
        return true;
    }

    let mut nested_curtailed = false;
    let mut prepared = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let mut scenarios = Vec::new();
        nested_curtailed |= collect_scenarios(item, base_assumptions, remaining, &mut scenarios);
        if scenarios.is_empty() {
            scenarios.push((item.clone(), base_assumptions.clone()));
        }
        prepared.push((index, scenarios));
    }
    let product_curtailed = expand_cartesian_scenarios(
        &prepared,
        base_assumptions,
        remaining,
        |collected| ResolvedValue::List { items: collected.into_iter().map(|(_, value)| value).collect() },
        results,
    );
    nested_curtailed || product_curtailed
}

fn expand_map_scenarios(
    entries: &[MapEntry],
    base_assumptions: &HashMap<String, bool>,
    limit: usize,
    results: &mut Vec<(ResolvedValue, HashMap<String, bool>)>,
) -> bool {
    let remaining = limit.saturating_sub(results.len());
    if remaining == 0 {
        return true;
    }

    let mut nested_curtailed = false;
    let mut prepared = Vec::with_capacity(entries.len());
    for entry in entries {
        let mut scenarios = Vec::new();
        nested_curtailed |= collect_scenarios(&entry.value, base_assumptions, remaining, &mut scenarios);
        if scenarios.is_empty() {
            scenarios.push((entry.value.clone(), base_assumptions.clone()));
        }
        prepared.push((entry.key.clone(), scenarios));
    }
    let product_curtailed = expand_cartesian_scenarios(
        &prepared,
        base_assumptions,
        remaining,
        |collected| ResolvedValue::Map {
            entries: collected.into_iter().map(|(key, value)| MapEntry { key, value }).collect(),
        },
        results,
    );
    nested_curtailed || product_curtailed
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
    fn effective_path_removes_conditional_branch_segments() {
        assert_eq!(
            effective_path_from_scenario_source_path("Properties.ResourceRecords.Fn::If.1.0"),
            Some("Properties.ResourceRecords.0".to_string())
        );
    }

    #[test]
    fn effective_path_removes_nested_conditional_branch_segments() {
        assert_eq!(
            effective_path_from_scenario_source_path("Properties.Fn::If.2.Records.0.Fn::If.1.Value"),
            Some("Properties.Records.0.Value".to_string())
        );
    }

    #[test]
    fn effective_path_preserves_other_intrinsic_segments() {
        assert_eq!(
            effective_path_from_scenario_source_path("Properties.Value.Fn::GetAtt.1"),
            Some("Properties.Value.Fn::GetAtt.1".to_string())
        );
        assert_eq!(effective_path_from_scenario_source_path("Properties.Value.Fn::If.0"), None);
        assert_eq!(effective_path_from_scenario_source_path("Properties..Value"), None);
    }

    #[test]
    fn scenario_source_path_selects_conditional_list_branch() {
        let value = ResolvedValue::Conditional {
            condition: "ChooseFirst".into(),
            if_true: Box::new(ResolvedValue::Concrete { value: json!(["bad"]).into() }),
            if_false: Box::new(ResolvedValue::Concrete { value: json!(["good"]).into() }),
        };
        let mut conditions = HashMap::new();
        conditions.insert("ChooseFirst".to_string(), true);
        assert_eq!(
            scenario_source_path_at(&value, "0", &conditions, "Properties.ResourceRecords"),
            Some("Properties.ResourceRecords.Fn::If.1.0".to_string())
        );
        conditions.insert("ChooseFirst".to_string(), false);
        assert_eq!(
            scenario_source_path_at(&value, "0", &conditions, "Properties.ResourceRecords"),
            Some("Properties.ResourceRecords.Fn::If.2.0".to_string())
        );
    }

    #[test]
    fn scenario_source_path_selects_conditional_list_item_branch() {
        let value = ResolvedValue::List {
            items: vec![ResolvedValue::Conditional {
                condition: "UseValue".into(),
                if_true: Box::new(ResolvedValue::Concrete { value: json!("value").into() }),
                if_false: Box::new(ResolvedValue::Concrete { value: json!(null).into() }),
            }],
        };
        let conditions = HashMap::from([("UseValue".to_string(), true)]);
        assert_eq!(
            scenario_source_path_at(&value, "0", &conditions, "Properties.ResourceRecords"),
            Some("Properties.ResourceRecords.0.Fn::If.1".to_string())
        );
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
        collect_scenarios(&val, &HashMap::new(), MAX_SCENARIO_COMBINATIONS, &mut results);
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
        collect_scenarios(&val, &HashMap::new(), MAX_SCENARIO_COMBINATIONS, &mut results);
        assert_eq!(results.len(), 2);
        let (_, conds_true) = &results[0];
        assert_eq!(conds_true.get("C"), Some(&true));
        let (_, conds_false) = &results[1];
        assert_eq!(conds_false.get("C"), Some(&false));
    }

    #[test]
    fn collect_scenarios_expands_nested_conditional() {
        let val = ResolvedValue::Map {
            entries: vec![MapEntry {
                key: "Statement".into(),
                value: ResolvedValue::List {
                    items: vec![ResolvedValue::Map {
                        entries: vec![MapEntry {
                            key: "Resource".into(),
                            value: ResolvedValue::Conditional {
                                condition: "C".into(),
                                if_true: Box::new(ResolvedValue::Concrete { value: json!("first").into() }),
                                if_false: Box::new(ResolvedValue::Concrete { value: json!("second").into() }),
                            },
                        }],
                    }],
                },
            }],
        };
        let mut results = Vec::new();
        collect_scenarios(&val, &HashMap::new(), MAX_SCENARIO_COMBINATIONS, &mut results);

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].1.get("C"), Some(&true));
        assert_eq!(results[1].1.get("C"), Some(&false));
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
        collect_scenarios(&val, &HashMap::new(), MAX_SCENARIO_COMBINATIONS, &mut results);
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
        collect_scenarios(&val, &assumptions, MAX_SCENARIO_COMBINATIONS, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0].0, ResolvedValue::Concrete { value: v } if v.0 == json!(1)));
    }

    #[test]
    fn direct_enum_at_scenario_limit_is_not_curtailed() {
        let value = ResolvedValue::Enum {
            variants: (0..MAX_SCENARIO_COMBINATIONS)
                .map(|index| ResolvedValue::Concrete { value: json!(index).into() })
                .collect(),
        };
        let mut scenarios = Vec::new();
        let mut curtailed = false;

        collect_scenarios_signaled(&value, &HashMap::new(), &mut scenarios, &mut curtailed);

        assert_eq!(scenarios.len(), MAX_SCENARIO_COMBINATIONS);
        assert!(!curtailed, "an exact-fit direct enum must not report omitted scenarios");
    }

    #[test]
    fn conditional_branch_one_over_scenario_limit_is_curtailed() {
        let value = ResolvedValue::Conditional {
            condition: "UseEnum".into(),
            if_true: Box::new(ResolvedValue::Enum {
                variants: (0..MAX_SCENARIO_COMBINATIONS)
                    .map(|index| ResolvedValue::Concrete { value: json!(index).into() })
                    .collect(),
            }),
            if_false: Box::new(ResolvedValue::Concrete { value: json!("fallback").into() }),
        };
        let mut scenarios = Vec::new();
        let mut curtailed = false;

        collect_scenarios_signaled(&value, &HashMap::new(), &mut scenarios, &mut curtailed);

        assert_eq!(scenarios.len(), MAX_SCENARIO_COMBINATIONS);
        assert!(curtailed, "the first omitted conditional-branch scenario must be reported");
        assert!(scenarios.iter().all(|(_, conditions)| conditions.get("UseEnum") == Some(&true)));
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

    // --- Scenario expansion curtailment tests ---

    /// Helper: builds a map with `n` entries, each containing an independent
    /// conditional so that full expansion produces 2^n scenarios. Uses a small
    /// limit to test curtailment without allocating millions of scenarios.
    fn make_branching_map(n: usize) -> ResolvedValue {
        let entries: Vec<MapEntry> = (0..n)
            .map(|i| MapEntry {
                key: format!("key{i}"),
                value: ResolvedValue::Conditional {
                    condition: format!("C{i}"),
                    if_true: Box::new(ResolvedValue::Concrete { value: json!(format!("true{i}")).into() }),
                    if_false: Box::new(ResolvedValue::Concrete { value: json!(format!("false{i}")).into() }),
                },
            })
            .collect();
        ResolvedValue::Map { entries }
    }

    /// Helper: builds a list with `n` items, each containing an independent
    /// conditional so that full expansion produces 2^n scenarios.
    fn make_branching_list(n: usize) -> ResolvedValue {
        let items: Vec<ResolvedValue> = (0..n)
            .map(|i| ResolvedValue::Conditional {
                condition: format!("C{i}"),
                if_true: Box::new(ResolvedValue::Concrete { value: json!(format!("true{i}")).into() }),
                if_false: Box::new(ResolvedValue::Concrete { value: json!(format!("false{i}")).into() }),
            })
            .collect();
        ResolvedValue::List { items }
    }

    #[test]
    fn exact_limit_expansion_does_not_mark_curtailment() {
        // 4 independent conditions → 2^4 = 16 scenarios. With limit=16 the
        // expansion is exactly at the boundary and must NOT be reported as
        // curtailed.
        let val = make_branching_map(4);
        let mut results = Vec::new();
        let curtailed = collect_scenarios(&val, &HashMap::new(), 16, &mut results);
        assert!(!curtailed, "exact-limit expansion must not be curtailed");
        assert_eq!(results.len(), 16, "all 2^4 scenarios must be produced");
    }

    #[test]
    fn over_limit_expansion_marks_curtailment() {
        // 5 independent conditions → 2^5 = 32 scenarios. With limit=16 the
        // product exceeds the limit and must be reported as curtailed.
        let val = make_branching_map(5);
        let mut results = Vec::new();
        let curtailed = collect_scenarios(&val, &HashMap::new(), 16, &mut results);
        assert!(curtailed, "over-limit expansion must be curtailed");
        assert!(results.len() <= 16, "at most `limit` scenarios may be returned; got {}", results.len());
    }

    #[test]
    fn curtailed_map_scenarios_are_structurally_complete() {
        // With 5 entries and limit=4, expansion is curtailed but every returned
        // scenario must have all 5 map keys present.
        let val = make_branching_map(5);
        let mut results = Vec::new();
        let curtailed = collect_scenarios(&val, &HashMap::new(), 4, &mut results);
        assert!(curtailed, "should be curtailed with limit=4 and 5 conditions");
        for (scenario, _) in &results {
            match scenario {
                ResolvedValue::Map { entries } => {
                    assert_eq!(
                        entries.len(),
                        5,
                        "every returned map scenario must have all 5 entries; got {}: {:?}",
                        entries.len(),
                        entries.iter().map(|e| &e.key).collect::<Vec<_>>()
                    );
                }
                other => panic!("expected Map, got {:?}", other),
            }
        }
    }

    #[test]
    fn curtailed_list_scenarios_are_structurally_complete() {
        // With 5 items and limit=4, expansion is curtailed but every returned
        // scenario must have all 5 list elements present.
        let val = make_branching_list(5);
        let mut results = Vec::new();
        let curtailed = collect_scenarios(&val, &HashMap::new(), 4, &mut results);
        assert!(curtailed, "should be curtailed with limit=4 and 5 conditions");
        for (scenario, _) in &results {
            match scenario {
                ResolvedValue::List { items } => {
                    assert_eq!(
                        items.len(),
                        5,
                        "every returned list scenario must have all 5 items; got {}",
                        items.len()
                    );
                }
                other => panic!("expected List, got {:?}", other),
            }
        }
    }

    #[test]
    fn nested_curtailment_is_propagated_to_the_root() {
        let val = ResolvedValue::List { items: vec![make_branching_map(3)] };
        let mut results = Vec::new();
        let curtailed = collect_scenarios(&val, &HashMap::new(), 4, &mut results);
        assert!(curtailed, "curtailment inside a nested map must be visible to the root collector");
        assert_eq!(results.len(), 4);
        for (scenario, _) in results {
            let ResolvedValue::List { items } = scenario else {
                panic!("expected outer list scenario");
            };
            assert_eq!(items.len(), 1);
            let ResolvedValue::Map { entries } = &items[0] else {
                panic!("expected nested map scenario");
            };
            assert_eq!(entries.len(), 3, "nested scenarios must remain structurally complete");
        }
    }

    #[test]
    fn enum_expansion_obeys_limit_and_exact_boundary() {
        let four = ResolvedValue::Enum {
            variants: (0..4).map(|value| ResolvedValue::Concrete { value: json!(value).into() }).collect(),
        };
        let mut exact_results = Vec::new();
        assert!(!collect_scenarios(&four, &HashMap::new(), 4, &mut exact_results));
        assert_eq!(exact_results.len(), 4);

        let five = ResolvedValue::Enum {
            variants: (0..5).map(|value| ResolvedValue::Concrete { value: json!(value).into() }).collect(),
        };
        let mut limited_results = Vec::new();
        assert!(collect_scenarios(&five, &HashMap::new(), 4, &mut limited_results));
        assert_eq!(limited_results.len(), 4);
    }

    #[test]
    fn expand_cartesian_returns_false_at_exact_limit() {
        // Directly test the inner helper: 2 items × 2 scenarios each → 4 combos.
        // With limit=4 it should NOT be curtailed.
        let a_val = ResolvedValue::Concrete { value: json!("a").into() };
        let b_val = ResolvedValue::Concrete { value: json!("b").into() };
        let items: Vec<(usize, Vec<(ResolvedValue, HashMap<String, bool>)>)> = vec![
            (0, vec![(a_val.clone(), HashMap::new()), (b_val.clone(), HashMap::new())]),
            (1, vec![(a_val.clone(), HashMap::new()), (b_val.clone(), HashMap::new())]),
        ];
        let mut results = Vec::new();
        let curtailed = expand_cartesian_scenarios(
            &items,
            &HashMap::new(),
            4,
            |collected| ResolvedValue::List { items: collected.into_iter().map(|(_, v)| v).collect() },
            &mut results,
        );
        assert!(!curtailed, "4 combos with limit=4 must not be curtailed");
        assert_eq!(results.len(), 4);
    }

    #[test]
    fn expand_cartesian_returns_true_over_limit() {
        // 3 items × 2 scenarios each → 8 combos. With limit=4, curtailed.
        let a_val = ResolvedValue::Concrete { value: json!("a").into() };
        let b_val = ResolvedValue::Concrete { value: json!("b").into() };
        let items: Vec<(usize, Vec<(ResolvedValue, HashMap<String, bool>)>)> = vec![
            (0, vec![(a_val.clone(), HashMap::new()), (b_val.clone(), HashMap::new())]),
            (1, vec![(a_val.clone(), HashMap::new()), (b_val.clone(), HashMap::new())]),
            (2, vec![(a_val.clone(), HashMap::new()), (b_val.clone(), HashMap::new())]),
        ];
        let mut results = Vec::new();
        let curtailed = expand_cartesian_scenarios(
            &items,
            &HashMap::new(),
            4,
            |collected| ResolvedValue::List { items: collected.into_iter().map(|(_, v)| v).collect() },
            &mut results,
        );
        assert!(curtailed, "8 combos with limit=4 must be curtailed");
        assert!(results.len() <= 4, "at most limit results; got {}", results.len());
        // Structural completeness: every result list must have all 3 items
        for (scenario, _) in &results {
            match scenario {
                ResolvedValue::List { items } => {
                    assert_eq!(items.len(), 3, "every scenario must have all 3 items");
                }
                other => panic!("expected List, got {:?}", other),
            }
        }
    }
}
