use crate::engine::{SharedModel, SharedRegion};
use data_source::embedded::{GETATT_ATTRIBUTES_BYTES, SCHEMA_METADATA_BYTES};
use data_source::types::GetattData;
use diagnostics::{SourceSpan, UNKNOWN_SPAN, render_value, render_value_list};
use regorus::Value;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use template_model::SemanticModel;
use template_model::coercion::{
    coerce_port_to_string, coerce_to_bool, coerce_to_integer, coerce_to_number, coerce_to_string, type_compatible,
};
use template_model::consts::{
    DEFAULT_REGION, FIELD_CONDITION, FIELD_DEPENDS_ON, FIELD_KIND, FIELD_PROPERTIES, FIELD_RESOURCE_TYPE, FIELD_SOURCE,
    FIELD_SOURCE_PATH, FIELD_TARGET, FN_IF,
};
use template_model::resolved_value::json_contains_markers;
use template_model::resolver::{MapEntry, RefKind, ResolvedValue};
use template_model::{MARKER_DYNAMIC, MARKER_PARAM_TYPE, MARKER_REF};

pub(crate) fn serde_json_to_rego_value(v: &serde_json::Value) -> Value {
    json_to_value(v)
}

fn get_model(holder: &SharedModel) -> Option<Arc<SemanticModel>> {
    holder.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

pub(crate) fn register_all(rego: &mut regorus::Engine, holder: SharedModel, region_holder: SharedRegion) {
    register_resolve(rego, holder.clone());
    register_resolve_preserving_conditionals(rego, holder.clone());
    register_resolve_all(rego, holder.clone());
    register_is_dynamic(rego, holder.clone());
    register_is_from_parameter(rego, holder.clone());
    register_is_from_intrinsic(rego, holder.clone());
    register_follow_ref(rego, holder.clone());
    register_authored_form(rego, holder.clone());
    register_resources_of_type(rego, holder.clone());
    register_ref_targets(rego, holder.clone());
    register_ref_sources(rego, holder.clone());
    register_depends_on(rego, holder.clone());
    register_conditions_compatible(rego, holder.clone());
    register_condition_implies(rego, holder.clone());
    register_conjunction_implies(rego, holder.clone());
    register_resource_condition(rego, holder.clone());
    register_has_property(rego, holder.clone());
    register_property_can_be_absent(rego, holder.clone());
    register_param_allowed_values(rego, holder.clone());
    register_param_type(rego, holder.clone());
    register_mapping_value(rego, holder.clone());
    register_has_transform(rego, holder.clone());
    register_make_diag(rego, holder.clone());
    register_make_diag_at(rego, holder.clone());
    register_make_diag_full(rego, holder.clone());
    register_make_diag_related(rego, holder.clone());
    register_make_diag_conditional(rego, holder.clone());
    register_resolve_scenarios(rego, holder.clone());
    register_is_satisfiable(rego, holder.clone());
    register_get_resource(rego, holder.clone());
    register_resolve_ref_target(rego, holder.clone());
    register_flatten_list(rego, holder.clone());
    register_pipeline_artifacts(rego, holder.clone());
    register_pipeline_artifact_count_issues(rego, holder.clone());
    register_resolve_type(rego, holder.clone());
    let schema_registry: LazySchemaRegistry = Arc::new(OnceLock::new());
    let getatt_registry: LazyGetattRegistry = Arc::new(OnceLock::new());
    register_schema_properties(rego, schema_registry.clone());
    register_schema_required(rego, schema_registry.clone());
    register_schema_type(rego, schema_registry.clone());
    register_schema_enum(rego, schema_registry.clone());
    register_attribute_type(rego, schema_registry.clone());
    register_getatt_return_type(rego, getatt_registry);
    register_edges_from(rego, holder.clone());
    register_edges_to(rego, holder.clone());
    register_arn_matches(rego);
    register_arn_matches_format(rego);
    register_ip_overlaps(rego);
    register_ip_subnet_of(rego);
    register_is_valid_cidr_strict(rego);
    register_ensure_list(rego);
    register_input_region(rego, region_holder.clone());
    register_effective_region(rego, region_holder);
    register_render_list(rego);
    register_render_value(rego);
    register_conditional_instance_class_enum(rego);
    register_coerce_to_number(rego);
    register_coerce_to_integer(rego);
    register_coerce_to_string(rego);
    register_coerce_port_to_string(rego);
    register_coerce_to_bool(rego);
    register_cfn_type_compatible(rego);
    register_estimate_string_length(rego, holder.clone());
    register_schema_string_length(rego, schema_registry.clone());
    register_schema_requires_unique_items(rego, schema_registry);
    register_unreachable_if_branches(rego, holder);
}

fn resolved_to_rego(rv: &ResolvedValue) -> Value {
    match rv {
        ResolvedValue::Concrete { value: v } => json_to_value(v),
        ResolvedValue::List { items } => {
            let vals: Vec<Value> = items.iter().map(resolved_to_rego).collect();
            Value::from(vals)
        }
        ResolvedValue::Map { entries } => {
            let mut map = serde_json::Map::new();
            for MapEntry { key: k, value: v } in entries {
                map.insert(k.clone(), resolved_value_to_json_static(v));
            }
            json_to_value(&serde_json::Value::Object(map))
        }
        ResolvedValue::Enum { variants: vals } => {
            for v in vals {
                if let ResolvedValue::Concrete { value: c } = v {
                    return json_to_value(c);
                }
            }
            Value::Undefined
        }
        ResolvedValue::Conditional { if_true: t, .. } => resolved_to_rego(t),
        ResolvedValue::Reference { target, .. } => Value::from(target.as_str()),
        ResolvedValue::Dynamic { .. } | ResolvedValue::TypedDynamic { .. } => Value::Undefined,
    }
}

fn resolved_all_to_rego(rv: &ResolvedValue) -> Vec<Value> {
    match rv {
        ResolvedValue::Concrete { value: v } => vec![json_to_value(v)],
        ResolvedValue::List { items } => {
            let vals: Vec<Value> = items.iter().map(resolved_to_rego).collect();
            vec![Value::from(vals)]
        }
        ResolvedValue::Map { entries } => {
            let mut map = serde_json::Map::new();
            for MapEntry { key: k, value: v } in entries {
                map.insert(k.clone(), resolved_value_to_json_static(v));
            }
            vec![json_to_value(&serde_json::Value::Object(map))]
        }
        ResolvedValue::Enum { variants: vals } => vals.iter().flat_map(resolved_all_to_rego).collect(),
        ResolvedValue::Conditional { if_true: t, if_false: f, .. } => {
            let mut r = resolved_all_to_rego(t);
            r.extend(resolved_all_to_rego(f));
            r
        }
        // Unresolved references and dynamic values have no concrete literal to return.
        // Returning the logical ID of a Ref target would cause false positives in rules
        // that validate literal content (e.g. format-validation rules).
        ResolvedValue::Reference { .. } | ResolvedValue::Dynamic { .. } | ResolvedValue::TypedDynamic { .. } => vec![],
    }
}

fn json_to_value(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::from(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::from(i)
            } else if let Some(f) = n.as_f64() {
                Value::from(f)
            } else {
                Value::Undefined
            }
        }
        serde_json::Value::String(s) => Value::from(s.as_str()),
        serde_json::Value::Array(arr) => Value::from(arr.iter().map(json_to_value).collect::<Vec<_>>()),
        serde_json::Value::Object(map) => {
            let mut obj = regorus::Value::new_object();
            for (k, v) in map {
                obj.as_object_mut().unwrap().insert(Value::from(k.as_str()), json_to_value(v));
            }
            obj
        }
    }
}

fn resolved_value_to_json_static(val: &ResolvedValue) -> serde_json::Value {
    match val {
        ResolvedValue::Concrete { value: v } => v.0.clone(),
        ResolvedValue::List { items } => {
            serde_json::Value::Array(items.iter().map(resolved_value_to_json_static).collect())
        }
        ResolvedValue::Map { entries } => {
            let mut map = serde_json::Map::new();
            for MapEntry { key: k, value: v } in entries {
                map.insert(k.clone(), resolved_value_to_json_static(v));
            }
            serde_json::Value::Object(map)
        }
        ResolvedValue::Enum { variants: vals } => {
            for v in vals {
                if let ResolvedValue::Concrete { value: c } = v {
                    return c.0.clone();
                }
            }
            serde_json::Value::Null
        }
        ResolvedValue::Conditional { if_true: t, .. } => resolved_value_to_json_static(t),
        ResolvedValue::Reference { target, .. } => {
            serde_json::json!({MARKER_REF: target})
        }
        ResolvedValue::Dynamic { reason } => {
            serde_json::json!({MARKER_DYNAMIC: reason})
        }
        ResolvedValue::TypedDynamic { reason, param_type } => {
            serde_json::json!({MARKER_DYNAMIC: reason, MARKER_PARAM_TYPE: param_type})
        }
    }
}

/// Like `resolved_value_to_json_static` but preserves `Fn::If` structure as
/// `{"Fn::If": [condition, then, else]}` instead of collapsing to the true
/// branch, so branch-sensitive checks (CodePipeline artifact counts) can inspect
/// every branch.
fn resolved_to_json_preserving_conditionals(val: &ResolvedValue) -> serde_json::Value {
    match val {
        ResolvedValue::List { items } => {
            serde_json::Value::Array(items.iter().map(resolved_to_json_preserving_conditionals).collect())
        }
        ResolvedValue::Map { entries } => {
            let mut map = serde_json::Map::new();
            for MapEntry { key: k, value: v } in entries {
                map.insert(k.clone(), resolved_to_json_preserving_conditionals(v));
            }
            serde_json::Value::Object(map)
        }
        ResolvedValue::Conditional { condition, if_true, if_false } => serde_json::json!({
            FN_IF: [
                condition.clone(),
                resolved_to_json_preserving_conditionals(if_true),
                resolved_to_json_preserving_conditionals(if_false),
            ]
        }),
        other => resolved_value_to_json_static(other),
    }
}

fn contains_dynamic(rv: &ResolvedValue) -> bool {
    match rv {
        ResolvedValue::Dynamic { .. } | ResolvedValue::TypedDynamic { .. } => true,
        ResolvedValue::List { items } => items.iter().any(contains_dynamic),
        ResolvedValue::Map { entries } => entries.iter().any(|e| contains_dynamic(&e.value)),
        ResolvedValue::Enum { variants: vals } => vals.iter().any(contains_dynamic),
        ResolvedValue::Conditional { if_true: t, if_false: f, .. } => contains_dynamic(t) || contains_dynamic(f),
        ResolvedValue::Reference { .. } => true,
        ResolvedValue::Concrete { value: v } => json_contains_markers(v),
    }
}
fn register_resolve(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "resolve".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rid = params[0].as_string()?;
            let path = params[1].as_string()?;
            if let Some(val) = model.resolve_deep(rid, path) {
                return Ok(resolved_to_rego(&val));
            }
            if let Some(val) = model.resolve(rid, path) {
                return Ok(resolved_to_rego(val));
            }
            // `Properties` wrapped in `Fn::If` stores values only under the
            // synthetic branch path — fall back to scenario resolution so the
            // rule still sees a per-branch value.
            let scenarios = model.resolve_scenarios_json(rid, path);
            if let Some((first, _)) = scenarios.into_iter().next() {
                return Ok(serde_json_to_rego_value(&first));
            }
            Ok(Value::Undefined)
        }),
    );
}

/// `resolve_preserving_conditionals(rid, path)`: like `resolve`, but keeps every
/// `Fn::If` as `{"Fn::If": [condition, then, else]}` rather than collapsing to the
/// true branch, so a rule can consider every branch of a conditional value.
fn register_resolve_preserving_conditionals(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "resolve_preserving_conditionals".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rid = params[0].as_string()?;
            let path = params[1].as_string()?;
            let resolved = model.resolve_deep(rid, path).or_else(|| model.resolve(rid, path).cloned());
            if let Some(val) = resolved {
                return Ok(serde_json_to_rego_value(&resolved_to_json_preserving_conditionals(&val)));
            }
            Ok(Value::Undefined)
        }),
    );
}

fn register_resolve_all(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "resolve_all".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rid = params[0].as_string()?;
            let path = params[1].as_string()?;
            if let Some(val) = model.resolve_deep(rid, path) {
                return Ok(Value::from(resolved_all_to_rego(&val)));
            }
            if let Some(val) = model.resolve(rid, path) {
                return Ok(Value::from(resolved_all_to_rego(val)));
            }
            // `Properties` wrapped in `Fn::If` stores values under a synthetic
            // branch path. Fall back to scenario resolution so rules that walk
            // by property name still see per-branch values.
            let scenarios = model.resolve_scenarios_json(rid, path);
            if scenarios.is_empty() {
                return Ok(Value::from(Vec::<Value>::new()));
            }
            let vals: Vec<Value> = scenarios.into_iter().map(|(v, _)| serde_json_to_rego_value(&v)).collect();
            Ok(Value::from(vals))
        }),
    );
}

fn register_is_dynamic(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "is_dynamic".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rid = params[0].as_string()?;
            let path = params[1].as_string()?;
            if let Some(val) = model.resolve_deep(rid, path) {
                return Ok(Value::from(contains_dynamic(&val)));
            }
            if let Some(val) = model.resolve(rid, path) {
                return Ok(Value::from(contains_dynamic(val)));
            }
            Ok(Value::from(false))
        }),
    );
}

fn register_is_from_parameter(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "is_from_parameter".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rid = params[0].as_string()?;
            let path = params[1].as_string()?;
            Ok(Value::from(model.is_from_parameter(rid, path)))
        }),
    );
}

fn register_is_from_intrinsic(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "is_from_intrinsic".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rid = params[0].as_string()?;
            let path = params[1].as_string()?;
            Ok(Value::from(model.is_from_intrinsic(rid, path)))
        }),
    );
}

fn register_resolve_scenarios(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "resolve_scenarios".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rid = params[0].as_string()?;
            let path = params[1].as_string()?;

            if path.contains("{}") {
                let arr_path = path.split(".{}").next().unwrap_or(path);
                let suffix = path.split_once("{}").map(|x| x.1).unwrap_or("");
                let arr_len = match model.resolve_deep(rid, arr_path) {
                    Some(ResolvedValue::List { items }) => items.len(),
                    Some(ResolvedValue::Concrete { value: v }) if v.as_array().is_some() => v.as_array().unwrap().len(),
                    _ => 0,
                };
                if arr_len > 0 {
                    let mut results: Vec<Value> = Vec::new();
                    for i in 0..arr_len {
                        let idx_path = format!("{}.{}{}", arr_path, i, suffix);
                        let scenarios = model.resolve_scenarios_json(rid, &idx_path);
                        for (v_json, conds) in scenarios {
                            let mut conds_map = serde_json::Map::new();
                            for (k, b) in &conds {
                                conds_map.insert(k.clone(), serde_json::Value::Bool(*b));
                            }
                            if let Ok(v) = Value::from_json_str(
                                &serde_json::json!({"value": v_json, "conditions": conds_map, "path": idx_path})
                                    .to_string(),
                            ) {
                                results.push(v);
                            }
                        }
                    }
                    return Ok(Value::from(results));
                }
            }

            let scenarios = model.resolve_scenarios_json(rid, path);
            let results: Vec<Value> = scenarios
                .into_iter()
                .filter_map(|(v_json, conds)| {
                    let mut conds_map = serde_json::Map::new();
                    for (k, b) in &conds {
                        conds_map.insert(k.clone(), serde_json::Value::Bool(*b));
                    }
                    Value::from_json_str(&serde_json::json!({"value": v_json, "conditions": conds_map}).to_string())
                        .ok()
                })
                .collect();
            Ok(Value::from(results))
        }),
    );
}

fn register_is_satisfiable(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "is_satisfiable".into(),
        1,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let conds_str = params[0].to_json_str()?;
            let conds_val: serde_json::Value = serde_json::from_str(&conds_str).unwrap_or_default();
            let assumptions: Vec<(String, bool)> = conds_val
                .as_object()
                .map(|m| m.iter().filter_map(|(k, v)| v.as_bool().map(|b| (k.clone(), b))).collect())
                .unwrap_or_default();
            if assumptions.is_empty() {
                return Ok(Value::from(true));
            }
            Ok(Value::from(model.conditions.is_satisfiable(&assumptions)))
        }),
    );
}
fn register_follow_ref(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "follow_ref".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rid = params[0].as_string()?;
            let path = params[1].as_string()?;
            Ok(model.follow_ref(rid, path).map(Value::from).unwrap_or(Value::Undefined))
        }),
    );
}

/// `authored_form(rid, path)`: the authored JSON form of a resource property,
/// reconstructed from the resolved value — `{"Ref": target}` for a `Ref`,
/// `{"Fn::GetAtt": [target, attr]}` for a `GetAtt`, or the literal for a concrete
/// value. A `Ref`/`GetAtt` to a parameter resolves to a dynamic value rather than
/// a reference, so the reference graph is consulted to recover the authored form.
/// Returns undefined when the property is absent or is an opaque function.
fn register_authored_form(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "authored_form".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rid = params[0].as_string()?;
            let path = params[1].as_string()?;
            let form = match model.resolve(rid.as_ref(), path.as_ref()) {
                Some(ResolvedValue::Reference { target, kind }) => authored_ref_form(target, kind),
                Some(ResolvedValue::Concrete { value: v }) => Some(v.0.clone()),
                _ => {
                    let prop_path = path.strip_prefix("Properties.").unwrap_or(path.as_ref());
                    let qualified = format!("Properties.{}", prop_path);
                    model
                        .graph
                        .outgoing(rid.as_ref())
                        .into_iter()
                        .find(|e| {
                            e.source_path == path.as_ref() || e.source_path == prop_path || e.source_path == qualified
                        })
                        .and_then(|e| authored_ref_form(&e.target, &e.kind))
                }
            };
            match form {
                Some(v) => Ok(serde_json_to_rego_value(&v)),
                None => Ok(Value::Undefined),
            }
        }),
    );
}

fn authored_ref_form(target: &str, kind: &RefKind) -> Option<serde_json::Value> {
    match kind {
        RefKind::Ref => Some(serde_json::json!({ "Ref": target })),
        RefKind::GetAtt { attr } => Some(serde_json::json!({ "Fn::GetAtt": [target, attr] })),
        _ => None,
    }
}

fn register_resources_of_type(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "resources_of_type".into(),
        1,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let type_name = params[0].as_string()?;
            let ids = model.resources_of_type(type_name);
            let set: Vec<Value> = ids.iter().map(|s: &String| Value::from(s.as_str())).collect();
            Ok(Value::from(set))
        }),
    );
}

fn register_ref_targets(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "ref_targets".into(),
        1,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rid = params[0].as_string()?;
            let targets: Vec<Value> = model.graph.ref_targets(rid).into_iter().map(Value::from).collect();
            Ok(Value::from(targets))
        }),
    );
}

fn register_ref_sources(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "ref_sources".into(),
        1,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rid = params[0].as_string()?;
            let sources: Vec<Value> = model.graph.ref_sources(rid).into_iter().map(Value::from).collect();
            Ok(Value::from(sources))
        }),
    );
}

fn register_depends_on(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "depends_on".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let source_id = params[0].as_string()?;
            let target_id = params[1].as_string()?;
            Ok(Value::from(model.graph.depends_on(source_id, target_id)))
        }),
    );
}
fn register_conditions_compatible(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "conditions_compatible".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let resource_a = params[0].as_string()?;
            let resource_b = params[1].as_string()?;
            let cond_a = model.resources.get(resource_a.as_ref()).and_then(|r| r.condition.as_deref());
            let cond_b = model.resources.get(resource_b.as_ref()).and_then(|r| r.condition.as_deref());
            Ok(Value::from(model.conditions.resources_compatible(cond_a, cond_b)))
        }),
    );
}

fn register_condition_implies(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "condition_implies".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            if params[0] == Value::Null {
                return Ok(Value::from(false));
            }
            if params[1] == Value::Null {
                return Ok(Value::from(true));
            }
            let antecedent = params[0].as_string()?;
            let consequent = params[1].as_string()?;
            Ok(Value::from(model.conditions.condition_implies(antecedent, consequent)))
        }),
    );
}

/// Returns true iff `[guard1=T, guard2=T, target=F]` is unsatisfiable.
/// A Null guard is treated as "no constraint" (equivalent to `true`).
fn register_conjunction_implies(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "conjunction_implies".into(),
        3,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            if params[2] == Value::Null {
                return Ok(Value::from(true));
            }
            let target = params[2].as_string()?;
            let mut assumptions: Vec<(String, bool)> = vec![(target.to_string(), false)];
            if params[0] != Value::Null {
                let g1 = params[0].as_string()?;
                assumptions.push((g1.to_string(), true));
            }
            if params[1] != Value::Null {
                let g2 = params[1].as_string()?;
                assumptions.push((g2.to_string(), true));
            }
            Ok(Value::from(!model.conditions.is_satisfiable(&assumptions)))
        }),
    );
}

fn register_resource_condition(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "resource_condition".into(),
        1,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rid = params[0].as_string()?;
            Ok(model
                .resources
                .get(rid.as_ref())
                .and_then(|r| r.condition.as_deref())
                .map(Value::from)
                .unwrap_or(Value::Null))
        }),
    );
}
fn register_has_property(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "has_property".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rid = params[0].as_string()?;
            let prop = params[1].as_string()?;
            let has =
                model.resources.get(rid.as_ref()).map(|r| r.properties.contains_key(prop.as_ref())).unwrap_or(false);
            Ok(Value::from(has))
        }),
    );
}

fn register_param_allowed_values(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "param_allowed_values".into(),
        1,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let name = params[0].as_string()?;
            match model.parameters.get(name.as_ref()).and_then(|p| p.allowed_values.as_ref()) {
                Some(vals) => {
                    let v: Vec<Value> = vals.iter().map(|s: &String| Value::from(s.as_str())).collect();
                    Ok(Value::from(v))
                }
                None => Ok(Value::from(Vec::<Value>::new())),
            }
        }),
    );
}

fn register_param_type(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "param_type".into(),
        1,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let name = params[0].as_string()?;
            Ok(model
                .parameters
                .get(name.as_ref())
                .map(|p| Value::from(p.param_type.as_str()))
                .unwrap_or(Value::Undefined))
        }),
    );
}

fn register_mapping_value(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "mapping_value".into(),
        3,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let map_name = params[0].as_string()?;
            let k1 = params[1].as_string()?;
            let k2 = params[2].as_string()?;
            let result = model
                .mappings
                .get(map_name.as_ref())
                .and_then(|l1| l1.get(k1.as_ref()))
                .and_then(|l2| l2.get(k2.as_ref()));
            Ok(result.map(json_to_value).unwrap_or(Value::Undefined))
        }),
    );
}

fn register_has_transform(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "has_transform".into(),
        1,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let name = params[0].as_string()?;
            Ok(Value::from(model.transforms.iter().any(|t| t.as_str() == name.as_ref())))
        }),
    );
}
fn register_get_resource(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "get_resource".into(),
        1,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rid = params[0].as_string()?;
            let res = match model.resources.get(rid.as_ref()) {
                Some(r) => r,
                None => return Ok(Value::Undefined),
            };
            let mut props = serde_json::Map::new();
            for (k, v) in &res.properties {
                props.insert(k.clone(), resolved_value_to_json_static(v));
            }
            Value::from_json_str(
                &serde_json::json!({
                    (FIELD_RESOURCE_TYPE): res.resource_type, (FIELD_CONDITION): res.condition,
                    (FIELD_DEPENDS_ON): res.depends_on, (FIELD_PROPERTIES): props,
                })
                .to_string(),
            )
        }),
    );
}

fn register_resolve_ref_target(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "resolve_ref_target".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rid = params[0].as_string()?;
            let path = params[1].as_string()?;
            let target_id = match model.follow_ref(rid, path) {
                Some(t) => t.to_string(),
                None => return Ok(Value::Undefined),
            };
            let res = match model.resources.get(&target_id) {
                Some(r) => r,
                None => return Ok(Value::Undefined),
            };
            let mut props = serde_json::Map::new();
            for (k, v) in &res.properties {
                props.insert(k.clone(), resolved_value_to_json_static(v));
            }
            Value::from_json_str(
                &serde_json::json!({
                    (FIELD_RESOURCE_TYPE): res.resource_type, (FIELD_CONDITION): res.condition, (FIELD_PROPERTIES): props,
                })
                .to_string(),
            )
        }),
    );
}

fn register_flatten_list(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "flatten_list".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rid = params[0].as_string()?;
            let path = params[1].as_string()?;
            let val = model.resolve_deep(rid, path).or_else(|| model.resolve(rid, path).cloned());
            let Some(resolved) = val else {
                return Ok(Value::from(Vec::<Value>::new()));
            };
            let items = flatten_resolved_list(&resolved);
            let results: Vec<Value> = items
                .into_iter()
                .enumerate()
                .map(|(i, v)| {
                    let jv = resolved_value_to_json_static(&v);
                    Value::from_json_str(&serde_json::json!({"value": jv, "index": i}).to_string())
                        .unwrap_or(Value::Undefined)
                })
                .collect();
            Ok(Value::from(results))
        }),
    );
}

fn flatten_resolved_list(rv: &ResolvedValue) -> Vec<ResolvedValue> {
    match rv {
        ResolvedValue::Concrete { value: v } if v.is_array() => {
            v.as_array().unwrap().iter().map(|v| ResolvedValue::Concrete { value: v.clone().into() }).collect()
        }
        ResolvedValue::List { items } => items.clone(),
        ResolvedValue::Conditional { if_true: t, if_false: f, .. } => {
            let mut items = flatten_resolved_list(t);
            items.extend(flatten_resolved_list(f));
            items
        }
        ResolvedValue::Enum { variants: vals } => vals.iter().flat_map(flatten_resolved_list).collect(),
        _ => vec![rv.clone()],
    }
}
fn register_arn_matches(rego: &mut regorus::Engine) {
    let _ = rego.add_extension(
        "arn_matches".into(),
        2,
        Box::new(|params: Vec<Value>| {
            let arn = params[0].as_string()?;
            let pattern = params[1].as_string()?;
            let arn_parts: Vec<&str> = arn.split(':').collect();
            let pat_parts: Vec<&str> = pattern.split(':').collect();
            if arn_parts.len() < 6 || pat_parts.len() < 6 {
                return Ok(Value::from(false));
            }
            for (a, p) in arn_parts.iter().zip(pat_parts.iter()) {
                if *p != "*" && *p != *a {
                    return Ok(Value::from(false));
                }
            }
            Ok(Value::from(true))
        }),
    );
}

/// Registers `arn_matches_format(resource_arn, format_arn)`: whether an IAM
/// statement resource ARN matches an action's expected ARN format. Both ARNs are
/// padded to six colon parts with "*" (a shorter ARN, e.g. missing region or
/// account, is not a mismatch), `${Partition}`/`${Region}`/`${Account}`
/// placeholders match anything, and the sixth part is compared per its `:` or
/// `/` delimiter — the shared ARN-matching behavior every engine agrees on.
fn register_arn_matches_format(rego: &mut regorus::Engine) {
    let _ = rego.add_extension(
        "arn_matches_format".into(),
        2,
        Box::new(|params: Vec<Value>| {
            let resource_arn = params[0].as_string()?;
            let format_arn = params[1].as_string()?;
            Ok(Value::from(arn_matches_format(resource_arn.as_ref(), format_arn.as_ref())))
        }),
    );
}

fn arn_matches_format(resource_arn: &str, format_arn: &str) -> bool {
    let pad_to_six = |arn: &str| -> Vec<String> {
        let mut parts: Vec<String> = arn.splitn(6, ':').map(str::to_string).collect();
        while parts.len() < 6 {
            parts.push("*".to_string());
        }
        parts
    };
    let r_parts = pad_to_six(resource_arn);
    let f_parts = pad_to_six(format_arn);
    for i in 0..5 {
        if r_parts[i] == "*" {
            continue;
        }
        if matches!(f_parts[i].as_str(), "${Partition}" | "${Region}" | "${Account}") {
            continue;
        }
        if r_parts[i] != f_parts[i] {
            return false;
        }
    }
    if r_parts[5] == "*" {
        return true;
    }
    let delimiter = if f_parts[5].contains(':') {
        ':'
    } else if f_parts[5].contains('/') {
        '/'
    } else {
        return true;
    };
    for (r_seg, f_seg) in r_parts[5].split(delimiter).zip(f_parts[5].split(delimiter)) {
        if r_seg == f_seg {
            continue;
        }
        if r_seg == "*" || r_seg.starts_with('*') || f_seg.is_empty() || f_seg == ".*" {
            return true;
        }
        if r_seg.starts_with(f_seg) && r_seg.contains('*') {
            return true;
        }
        return false;
    }
    true
}

fn register_ip_overlaps(rego: &mut regorus::Engine) {
    let _ = rego.add_extension(
        "ip_overlaps".into(),
        2,
        Box::new(|params: Vec<Value>| {
            let a_str = params[0].as_string()?;
            let b_str = params[1].as_string()?;
            let net_a: ipnetwork::IpNetwork =
                a_str.parse().map_err(|e| anyhow::anyhow!("Invalid CIDR '{}': {}", a_str, e))?;
            let net_b: ipnetwork::IpNetwork =
                b_str.parse().map_err(|e| anyhow::anyhow!("Invalid CIDR '{}': {}", b_str, e))?;
            let overlaps = net_a.contains(net_b.network()) || net_b.contains(net_a.network());
            Ok(Value::from(overlaps))
        }),
    );
}

fn register_ip_subnet_of(rego: &mut regorus::Engine) {
    let _ = rego.add_extension(
        "ip_subnet_of".into(),
        2,
        Box::new(|params: Vec<Value>| {
            let sub_str = params[0].as_string()?;
            let vpc_str = params[1].as_string()?;
            let sub_net: ipnetwork::IpNetwork =
                sub_str.parse().map_err(|e| anyhow::anyhow!("Invalid CIDR '{}': {}", sub_str, e))?;
            let vpc_net: ipnetwork::IpNetwork =
                vpc_str.parse().map_err(|e| anyhow::anyhow!("Invalid CIDR '{}': {}", vpc_str, e))?;
            let is_sub = match (sub_net, vpc_net) {
                (ipnetwork::IpNetwork::V4(s), ipnetwork::IpNetwork::V4(v)) => s.is_subnet_of(v),
                (ipnetwork::IpNetwork::V6(s), ipnetwork::IpNetwork::V6(v)) => s.is_subnet_of(v),
                _ => false,
            };
            Ok(Value::from(is_sub))
        }),
    );
}

fn register_is_valid_cidr_strict(rego: &mut regorus::Engine) {
    let _ = rego.add_extension(
        "is_valid_cidr_strict".into(),
        1,
        Box::new(|params: Vec<Value>| {
            let cidr_str = params[0].as_string()?;
            let valid = cidr_str
                .parse::<ipnetwork::IpNetwork>()
                .map(|net| match net {
                    ipnetwork::IpNetwork::V4(n) => {
                        let ip: u32 = n.ip().into();
                        let host_bits = 32u32.saturating_sub(n.prefix() as u32);
                        let mask = if host_bits >= 32 { 0u32 } else { !0u32 << host_bits };
                        ip & !mask == 0
                    }
                    ipnetwork::IpNetwork::V6(_) => true,
                })
                .unwrap_or(false);
            Ok(Value::from(valid))
        }),
    );
}

fn register_ensure_list(rego: &mut regorus::Engine) {
    let _ = rego.add_extension(
        "ensure_list".into(),
        1,
        Box::new(|params: Vec<Value>| match &params[0] {
            Value::Array(_) => Ok(params[0].clone()),
            other => Ok(Value::from(vec![other.clone()])),
        }),
    );
}

fn register_render_list(rego: &mut regorus::Engine) {
    let _ = rego.add_extension(
        "render_list".into(),
        1,
        Box::new(|params: Vec<Value>| {
            let items = match rego_to_json(&params[0]) {
                serde_json::Value::Array(items) => items,
                other => vec![other],
            };
            Ok(Value::from(render_value_list(&items)))
        }),
    );
}

fn register_render_value(rego: &mut regorus::Engine) {
    let _ = rego.add_extension(
        "render_value".into(),
        1,
        Box::new(|params: Vec<Value>| Ok(Value::from(render_value(&rego_to_json(&params[0]))))),
    );
}

/// Registers `conditional_instance_class_enum(region_schema, props)`: given a
/// conditional RDS region document and an object of the resource's resolved
/// scalar properties (Engine, LicenseModel, …), returns the sorted enum of the
/// first `allOf` branch whose `if.required` consts all match, or `undefined`
/// when no branch matches.
/// Registers `property_can_be_absent(rid, path)`: true when a property is not
/// set in every satisfiable scenario — either its key is missing, or it resolves
/// to `AWS::NoValue`/null in at least one satisfiable `Fn::If` branch. Rules that
/// require a property to always be present (e.g. retention periods) use this so
/// an `Fn::If [cond, X, AWS::NoValue]` is correctly treated as possibly-absent.
fn register_property_can_be_absent(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "property_can_be_absent".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::from(false));
            };
            let rid = params[0].as_string()?;
            let path = params[1].as_string()?;
            let prop = path.strip_prefix("Properties.").unwrap_or(path.as_ref());
            let key_present =
                model.resources.get(rid.as_ref()).map(|r| r.properties.contains_key(prop)).unwrap_or(false);
            if !key_present {
                return Ok(Value::from(true));
            }
            let scenarios = model.resolve_scenarios_json(rid.as_ref(), path.as_ref());
            let absent = scenarios.is_empty() || scenarios.iter().any(|(v, _)| v.is_null());
            Ok(Value::from(absent))
        }),
    );
}

/// Registers `invalid_instance_class_enum(schema, props, target_prop, normalize_engine_case, value)`:
/// for a conditional RDS region document, returns the sorted enum to render in an
/// E3025/E3694 diagnostic when `value` is invalid, or `undefined` when the value
/// is valid or no branch matches. A value is valid only when it is in EVERY
/// matching branch's enum (the intersection); when invalid, the largest failing
/// branch's enum is returned.
fn register_conditional_instance_class_enum(rego: &mut regorus::Engine) {
    let _ = rego.add_extension(
        "invalid_instance_class_enum".into(),
        5,
        Box::new(|params: Vec<Value>| {
            let schema = rego_to_json(&params[0]);
            let props = rego_to_json(&params[1]);
            let target_prop = params[2].as_string()?;
            let normalize_engine_case = matches!(&params[3], Value::Bool(b) if *b);
            let value = params[4].as_string()?;
            let branch_enums =
                conditional_instance_class_enums(&schema, target_prop.as_ref(), normalize_engine_case, &props);
            match invalid_class_branch_enum(&branch_enums, value.as_ref()) {
                Some(vals) => Ok(Value::from(vals.into_iter().map(Value::from).collect::<Vec<_>>())),
                None => Ok(Value::Undefined),
            }
        }),
    );
}

/// Collects every `then.<target_prop>.enum` from a conditional region document
/// whose `allOf` branch `if.required` consts all match `props`. Returns one enum
/// per matching branch. The `Engine` const is matched case-insensitively when
/// `normalize_engine_case` is set, because RDS DBInstance treats the engine name
/// case-insensitively.
fn conditional_instance_class_enums(
    schema: &serde_json::Value,
    target_prop: &str,
    normalize_engine_case: bool,
    props: &serde_json::Value,
) -> Vec<Vec<String>> {
    let mut enums = Vec::new();
    let Some(branches) = schema.get("allOf").and_then(|v| v.as_array()) else {
        return enums;
    };
    for branch in branches {
        let (Some(required), Some(if_props)) = (
            branch.get("if").and_then(|c| c.get("required")).and_then(|v| v.as_array()),
            branch.get("if").and_then(|c| c.get("properties")).and_then(|v| v.as_object()),
        ) else {
            continue;
        };
        let all_match = required.iter().filter_map(|r| r.as_str()).filter(|p| *p != target_prop).all(|prop| {
            let Some(expected) = if_props.get(prop).and_then(|p| p.get("const")).and_then(|c| c.as_str()) else {
                return false;
            };
            let Some(actual) = props.get(prop).and_then(|v| v.as_str()) else {
                return false;
            };
            if normalize_engine_case && prop == "Engine" {
                actual.eq_ignore_ascii_case(expected)
            } else {
                actual == expected
            }
        });
        if all_match
            && let Some(enum_vals) = branch
                .get("then")
                .and_then(|t| t.get("properties"))
                .and_then(|p| p.get(target_prop))
                .and_then(|d| d.get("enum"))
                .and_then(|e| e.as_array())
        {
            enums.push(enum_vals.iter().filter_map(|v| v.as_str()).map(String::from).collect());
        }
    }
    enums
}

/// The enum to render when `value` is not in the intersection of all matching
/// branch enums: the largest branch enum missing the value. `None` when the value
/// is in every branch (valid) or there are no matching branches.
fn invalid_class_branch_enum(branch_enums: &[Vec<String>], value: &str) -> Option<Vec<String>> {
    let failing_largest = branch_enums
        .iter()
        .filter(|allowed| !allowed.iter().any(|v| v == value))
        .max_by_key(|allowed| allowed.len())?;
    let mut sorted = failing_largest.clone();
    sorted.sort();
    Some(sorted)
}

fn rego_to_json(v: &Value) -> serde_json::Value {
    match v.to_json_str() {
        Ok(s) => serde_json::from_str(&s).unwrap_or(serde_json::Value::Null),
        Err(_) => serde_json::Value::Null,
    }
}

fn register_coerce_to_number(rego: &mut regorus::Engine) {
    let _ = rego.add_extension(
        "coerce_to_number".into(),
        1,
        Box::new(|params: Vec<Value>| {
            let jv = rego_to_json(&params[0]);
            match coerce_to_number(&jv) {
                Some(n) => {
                    if n.fract() == 0.0 && n >= i64::MIN as f64 && n <= i64::MAX as f64 {
                        Ok(Value::from(n as i64))
                    } else {
                        Ok(Value::from(n))
                    }
                }
                None => Ok(Value::Undefined),
            }
        }),
    );
}

fn register_coerce_to_integer(rego: &mut regorus::Engine) {
    let _ = rego.add_extension(
        "coerce_to_integer".into(),
        1,
        Box::new(|params: Vec<Value>| {
            let jv = rego_to_json(&params[0]);
            match coerce_to_integer(&jv) {
                Some(i) => Ok(Value::from(i)),
                None => Ok(Value::Undefined),
            }
        }),
    );
}

fn register_coerce_to_string(rego: &mut regorus::Engine) {
    let _ = rego.add_extension(
        "coerce_to_string".into(),
        1,
        Box::new(|params: Vec<Value>| {
            let jv = rego_to_json(&params[0]);
            match coerce_to_string(&jv) {
                Some(s) => Ok(Value::from(s.as_str())),
                None => Ok(Value::Undefined),
            }
        }),
    );
}

fn register_coerce_port_to_string(rego: &mut regorus::Engine) {
    let _ = rego.add_extension(
        "coerce_port_to_string".into(),
        1,
        Box::new(|params: Vec<Value>| {
            let jv = rego_to_json(&params[0]);
            match coerce_port_to_string(&jv) {
                Some(s) => Ok(Value::from(s.as_str())),
                None => Ok(Value::Undefined),
            }
        }),
    );
}

fn register_coerce_to_bool(rego: &mut regorus::Engine) {
    let _ = rego.add_extension(
        "coerce_to_bool".into(),
        1,
        Box::new(|params: Vec<Value>| {
            let jv = rego_to_json(&params[0]);
            match coerce_to_bool(&jv) {
                Some(b) => Ok(Value::from(b)),
                None => Ok(Value::Undefined),
            }
        }),
    );
}

fn register_cfn_type_compatible(rego: &mut regorus::Engine) {
    let _ = rego.add_extension(
        "cfn_type_compatible".into(),
        2,
        Box::new(|params: Vec<Value>| {
            let jv = rego_to_json(&params[0]);
            let expected = params[1].as_string()?;
            Ok(Value::from(type_compatible(&jv, expected)))
        }),
    );
}

fn register_input_region(rego: &mut regorus::Engine, holder: SharedRegion) {
    let _ = rego.add_extension(
        "input_region".into(),
        0,
        Box::new(move |_: Vec<Value>| match holder.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            Some(r) => Ok(Value::from(r.as_str())),
            None => Ok(Value::Null),
        }),
    );
}

/// Region used for region-scoped enum validation: the configured region, or
/// the platform default ([`template_model::DEFAULT_REGION`]) when unset. This
/// keeps the default in one place and validates against the default region
/// when none is configured.
fn register_effective_region(rego: &mut regorus::Engine, holder: SharedRegion) {
    let _ = rego.add_extension(
        "effective_region".into(),
        0,
        Box::new(move |_: Vec<Value>| match holder.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            Some(r) => Ok(Value::from(r.as_str())),
            None => Ok(Value::from(DEFAULT_REGION)),
        }),
    );
}

fn register_pipeline_artifacts(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension("pipeline_artifacts".into(), 1, Box::new(move |params: Vec<Value>| {
        let Some(model) = get_model(&holder) else { return Ok(Value::Undefined); };
        let rid = params[0].as_string()?;
        let resource = match model.resources.get(rid.as_ref()) {
            Some(r) => r,
            None => return Ok(Value::Undefined),
        };
        let stages_val = match resource.properties.get("Stages") {
            Some(ResolvedValue::Concrete { value: v }) => v.0.clone(),
            _ => return Value::from_json_str(&serde_json::json!({"issues": []}).to_string()),
        };
        let stages = match stages_val.as_array() {
            Some(a) => a,
            None => return Value::from_json_str(&serde_json::json!({"issues": []}).to_string()),
        };
        let mut seen_outputs = HashSet::new();
        let mut issues: Vec<serde_json::Value> = Vec::new();
        for (stage_idx, stage) in stages.iter().enumerate() {
            let stage_name = stage.get("Name").and_then(|v| v.as_str()).unwrap_or("unknown");
            let actions = match stage.get("Actions").and_then(|v| v.as_array()) {
                Some(a) => a,
                None => continue,
            };
            for action in actions {
                let action_name = action.get("Name").and_then(|v| v.as_str()).unwrap_or("unknown");
                if let Some(outputs) = action.get("OutputArtifacts").and_then(|v| v.as_array()) {
                    for out in outputs {
                        if let Some(name) = out.get("Name").and_then(|v| v.as_str())
                            && !seen_outputs.insert(name.to_string()) {
                                issues.push(serde_json::json!({"message": format!("Duplicate OutputArtifact name '{}' in stage '{}' action '{}'", name, stage_name, action_name)}));
                            }
                    }
                }
                if stage_idx > 0
                    && let Some(inputs) = action.get("InputArtifacts").and_then(|v| v.as_array()) {
                        for inp in inputs {
                            if let Some(name) = inp.get("Name").and_then(|v| v.as_str())
                                && !seen_outputs.contains(name) {
                                    issues.push(serde_json::json!({"message": format!("InputArtifact '{}' in stage '{}' action '{}' does not reference a previously defined OutputArtifact", name, stage_name, action_name)}));
                                }
                        }
                    }
            }
        }
        Value::from_json_str(&serde_json::json!({"issues": issues}).to_string())
    }));
}

/// Enumerates the possible element counts of a CodePipeline artifact list.
/// A list may be a plain array (one count) or an `Fn::If` whose branches each
/// contribute a count (nested `Fn::If`s recurse). Absent/other values count 0.
/// The result is sorted and deduped so identical branch counts are checked once.
fn rego_artifact_count_scenarios(value: Option<&serde_json::Value>) -> Vec<usize> {
    fn walk(value: Option<&serde_json::Value>, out: &mut BTreeSet<usize>) {
        match value {
            Some(serde_json::Value::Array(a)) => {
                out.insert(a.len());
            }
            Some(serde_json::Value::Object(o)) if o.len() == 1 && o.contains_key(FN_IF) => {
                if let Some(branches) = o.get(FN_IF).and_then(|v| v.as_array()) {
                    walk(branches.get(1), out);
                    walk(branches.get(2), out);
                }
            }
            _ => {
                out.insert(0);
            }
        }
    }
    let mut counts = BTreeSet::new();
    walk(value, &mut counts);
    counts.into_iter().collect()
}

/// Returns the E3702 artifact-count violation messages for a pipeline, keyed by
/// the Owner/Category/Provider tuple. Resolves Stages preserving `Fn::If` so an
/// artifact list authored behind a condition has EVERY branch's count checked
fn register_pipeline_artifact_count_issues(rego: &mut regorus::Engine, holder: SharedModel) {
    // The embedded document wraps the count table under a single top-level key
    // (`codepipeline_action_artifact_counts`); unwrap it to reach the per-tuple
    // bounds.
    let counts: HashMap<String, serde_json::Value> =
        serde_json::from_slice::<serde_json::Value>(&data_source::embedded::CODEPIPELINE_ACTION_ARTIFACT_COUNTS_BYTES)
            .ok()
            .and_then(|v| v.as_object().and_then(|o| o.values().next()).and_then(|v| v.as_object()).cloned())
            .map(|o| o.into_iter().collect())
            .unwrap_or_default();
    let _ = rego.add_extension(
        "pipeline_artifact_count_issues".into(),
        1,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rid = params[0].as_string()?;
            let stages_json = model
                .resolve_deep(rid.as_ref(), "Properties.Stages")
                .map(|rv| resolved_to_json_preserving_conditionals(&rv));
            let issues = pipeline_artifact_count_issues(stages_json.as_ref(), &counts);
            Value::from_json_str(&serde_json::json!({ "issues": issues }).to_string())
        }),
    );
}

/// Computes the E3702 count-violation messages from a Stages JSON that preserves
/// `Fn::If` structure. Shared helper so the builtin stays readable.
fn pipeline_artifact_count_issues(
    stages_json: Option<&serde_json::Value>,
    counts: &HashMap<String, serde_json::Value>,
) -> Vec<serde_json::Value> {
    let mut issues = Vec::new();
    let Some(stages) = stages_json.and_then(|v| v.as_array()) else {
        return issues;
    };
    for stage in stages {
        let Some(actions) = stage.get("Actions").and_then(|a| a.as_array()) else {
            continue;
        };
        for action in actions {
            let action_type_id = action.get("ActionTypeId");
            let (Some(owner), Some(category), Some(provider)) = (
                action_type_id.and_then(|a| a.get("Owner")).and_then(|c| c.as_str()),
                action_type_id.and_then(|a| a.get("Category")).and_then(|c| c.as_str()),
                action_type_id.and_then(|a| a.get("Provider")).and_then(|c| c.as_str()),
            ) else {
                continue;
            };
            let aname = action.get("Name").and_then(|n| n.as_str()).unwrap_or("unknown");
            let key = format!("{owner}/{category}/{provider}");
            let Some(bounds) = counts.get(&key) else { continue };
            let bound = |field: &str| bounds.get(field).and_then(|v| v.as_u64()).map(|v| v as usize);
            let (min_in, max_in) = (bound("min_input"), bound("max_input"));
            let (min_out, max_out) = (bound("min_output"), bound("max_output"));
            for n in rego_artifact_count_scenarios(action.get("InputArtifacts")) {
                if let Some(lo) = min_in
                    && n < lo
                {
                    issues.push(serde_json::json!({"message":
                        format!("Action '{}' ({}) has {} input artifacts, expected at least {}", aname, key, n, lo)}));
                }
                if let Some(hi) = max_in
                    && n > hi
                {
                    issues.push(serde_json::json!({"message":
                        format!("Action '{}' ({}) has {} input artifacts, expected at most {}", aname, key, n, hi)}));
                }
            }
            for n in rego_artifact_count_scenarios(action.get("OutputArtifacts")) {
                if let Some(lo) = min_out
                    && n < lo
                {
                    issues.push(serde_json::json!({"message":
                        format!("Action '{}' ({}) has {} output artifacts, expected at least {}", aname, key, n, lo)}));
                }
                if let Some(hi) = max_out
                    && n > hi
                {
                    issues.push(serde_json::json!({"message":
                        format!("Action '{}' ({}) has {} output artifacts, expected at most {}", aname, key, n, hi)}));
                }
            }
        }
    }
    issues
}

fn register_resolve_type(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "resolve_type".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rid = params[0].as_string()?;
            let path = params[1].as_string()?;
            let val = model.resolve_deep(rid, path).or_else(|| model.resolve(rid, path).cloned());
            let type_str = match val {
                Some(ResolvedValue::Concrete { value: v }) if v.is_string() => "string",
                Some(ResolvedValue::Concrete { value: v }) if v.is_number() => "number",
                Some(ResolvedValue::Concrete { value: v }) if v.is_boolean() => "boolean",
                Some(ResolvedValue::Concrete { value: v }) if v.is_array() => "array",
                Some(ResolvedValue::List { .. }) => "array",
                Some(ResolvedValue::Concrete { value: v }) if v.is_object() => "object",
                Some(ResolvedValue::Map { .. }) => "object",
                Some(ResolvedValue::Concrete { value: v }) if v.is_null() => "null",
                Some(ResolvedValue::Conditional { .. }) => "conditional",
                Some(ResolvedValue::Dynamic { .. }) => "dynamic",
                Some(ResolvedValue::TypedDynamic { .. }) => "dynamic",
                Some(ResolvedValue::Reference { .. }) => "reference",
                Some(ResolvedValue::Enum { .. }) => "enum",
                Some(ResolvedValue::Concrete { .. }) => "null",
                None => return Ok(Value::Undefined),
            };
            Ok(Value::from(type_str))
        }),
    );
}
#[derive(Debug, Clone, Default, serde::Deserialize)]
struct SchemaInfo {
    #[serde(default)]
    properties: Vec<String>,
    #[serde(default)]
    required: Vec<String>,
    #[serde(default)]
    property_types: HashMap<String, String>,
    #[serde(default)]
    property_enums: HashMap<String, Vec<serde_json::Value>>,
    #[serde(default)]
    property_constraints: HashMap<String, serde_json::Value>,
}

fn load_schema_registry() -> HashMap<String, SchemaInfo> {
    #[derive(serde::Deserialize)]
    struct Wrapper {
        #[serde(default)]
        schema_metadata: HashMap<String, SchemaInfo>,
    }
    let w: Wrapper = serde_json::from_slice(&SCHEMA_METADATA_BYTES).expect("Failed to parse schema_metadata JSON");
    w.schema_metadata
}

type LazySchemaRegistry = Arc<OnceLock<HashMap<String, SchemaInfo>>>;
fn schema_reg(reg: &LazySchemaRegistry) -> &HashMap<String, SchemaInfo> {
    reg.get_or_init(load_schema_registry)
}

type LazyGetattRegistry = Arc<OnceLock<HashMap<String, HashMap<String, String>>>>;
fn getatt_reg(reg: &LazyGetattRegistry) -> &HashMap<String, HashMap<String, String>> {
    reg.get_or_init(load_getatt_type_registry)
}

fn register_schema_properties(rego: &mut regorus::Engine, registry: LazySchemaRegistry) {
    let _ = rego.add_extension(
        "schema_properties".into(),
        1,
        Box::new(move |params: Vec<Value>| {
            let rtype = params[0].as_string()?;
            match schema_reg(&registry).get(rtype.as_ref()) {
                Some(info) => {
                    let vals: Vec<Value> = info.properties.iter().map(|s| Value::from(s.as_str())).collect();
                    Ok(Value::from(vals))
                }
                None => Ok(Value::from(Vec::<Value>::new())),
            }
        }),
    );
}

fn register_schema_required(rego: &mut regorus::Engine, registry: LazySchemaRegistry) {
    let _ = rego.add_extension(
        "schema_required".into(),
        1,
        Box::new(move |params: Vec<Value>| {
            let rtype = params[0].as_string()?;
            match schema_reg(&registry).get(rtype.as_ref()) {
                Some(info) => {
                    let vals: Vec<Value> = info.required.iter().map(|s| Value::from(s.as_str())).collect();
                    Ok(Value::from(vals))
                }
                None => Ok(Value::from(Vec::<Value>::new())),
            }
        }),
    );
}

fn register_schema_type(rego: &mut regorus::Engine, registry: LazySchemaRegistry) {
    let _ = rego.add_extension(
        "schema_type".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let rtype = params[0].as_string()?;
            let prop = params[1].as_string()?;
            match schema_reg(&registry).get(rtype.as_ref()).and_then(|i| i.property_types.get(prop.as_ref())) {
                Some(s) => Ok(Value::from(s.as_str())),
                None => Ok(Value::Undefined),
            }
        }),
    );
}

fn register_schema_enum(rego: &mut regorus::Engine, registry: LazySchemaRegistry) {
    let _ = rego.add_extension(
        "schema_enum".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let rtype = params[0].as_string()?;
            let prop = params[1].as_string()?;
            match schema_reg(&registry).get(rtype.as_ref()).and_then(|i| i.property_enums.get(prop.as_ref())) {
                Some(vals) => {
                    let v: Vec<Value> = vals.iter().map(json_to_value).collect();
                    Ok(Value::from(v))
                }
                None => Ok(Value::from(Vec::<Value>::new())),
            }
        }),
    );
}

fn register_attribute_type(rego: &mut regorus::Engine, registry: LazySchemaRegistry) {
    let _ = rego.add_extension(
        "attribute_type".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let rtype = params[0].as_string()?;
            let attr = params[1].as_string()?;
            match schema_reg(&registry).get(rtype.as_ref()).and_then(|i| i.property_types.get(attr.as_ref())) {
                Some(s) => Ok(Value::from(s.as_str())),
                None => Ok(Value::Undefined),
            }
        }),
    );
}

fn load_getatt_type_registry() -> HashMap<String, HashMap<String, String>> {
    let data: GetattData =
        serde_json::from_slice(&GETATT_ATTRIBUTES_BYTES).expect("Failed to deserialize getatt_attributes JSON data");
    data.getatt_attribute_types
}

fn register_getatt_return_type(rego: &mut regorus::Engine, registry: LazyGetattRegistry) {
    let _ = rego.add_extension(
        "getatt_return_type".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let rtype = params[0].as_string()?;
            let attr = params[1].as_string()?;
            match getatt_reg(&registry).get(rtype.as_ref()).and_then(|m| m.get(attr.as_ref())) {
                Some(s) => Ok(Value::from(s.as_str())),
                None => Ok(Value::from("string")),
            }
        }),
    );
}
fn register_edges_from(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "edges_from".into(),
        1,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rid = params[0].as_string()?;
            let edges: Vec<Value> = model
                .graph
                .outgoing(rid)
                .into_iter()
                .filter_map(|e| {
                    Value::from_json_str(
                        &serde_json::json!({
                            (FIELD_TARGET): e.target, (FIELD_KIND): format!("{:?}", e.kind),
                            (FIELD_SOURCE_PATH): e.source_path,
                        })
                        .to_string(),
                    )
                    .ok()
                })
                .collect();
            Ok(Value::from(edges))
        }),
    );
}

fn register_edges_to(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "edges_to".into(),
        1,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rid = params[0].as_string()?;
            let edges: Vec<Value> = model
                .graph
                .incoming(rid)
                .into_iter()
                .filter_map(|e| {
                    Value::from_json_str(
                        &serde_json::json!({
                            (FIELD_SOURCE): e.source_resource, (FIELD_KIND): format!("{:?}", e.kind),
                            (FIELD_SOURCE_PATH): e.source_path,
                        })
                        .to_string(),
                    )
                    .ok()
                })
                .collect();
            Ok(Value::from(edges))
        }),
    );
}
fn register_make_diag(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "make_diag".into(),
        4,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rule_id = params[0].as_string()?;
            let severity = params[1].as_string()?;
            let resource_id = params[2].as_string()?;
            let message = params[3].as_string()?;
            let span = if resource_id.is_empty() { UNKNOWN_SPAN } else { model.resource_span(resource_id, "") };
            let mut obj = serde_json::json!({
                "rule_id": rule_id.as_ref(), "severity": severity.as_ref(),
                "message": message.as_ref(), "resource_id": resource_id.as_ref(),
                "resource_path": "",
            });
            if span != UNKNOWN_SPAN {
                let m = obj.as_object_mut().unwrap();
                m.insert("start_line".into(), span.start_line.into());
                m.insert("start_column".into(), span.start_column.into());
                m.insert("end_line".into(), span.end_line.into());
                m.insert("end_column".into(), span.end_column.into());
            }
            Value::from_json_str(&obj.to_string())
        }),
    );
}

fn register_make_diag_at(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "make_diag_at".into(),
        5,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rule_id = params[0].as_string()?;
            let severity = params[1].as_string()?;
            let resource_id = params[2].as_string()?;
            let prop_path = params[3].as_string()?;
            let message = params[4].as_string()?;
            let span = if resource_id.is_empty() { UNKNOWN_SPAN } else { model.resource_span(resource_id, prop_path) };
            let mut obj = serde_json::json!({
                "rule_id": rule_id.as_ref(), "severity": severity.as_ref(),
                "message": message.as_ref(), "resource_id": resource_id.as_ref(),
                "resource_path": prop_path.as_ref(),
            });
            if span != UNKNOWN_SPAN {
                let m = obj.as_object_mut().unwrap();
                m.insert("start_line".into(), span.start_line.into());
                m.insert("start_column".into(), span.start_column.into());
                m.insert("end_line".into(), span.end_line.into());
                m.insert("end_column".into(), span.end_column.into());
            }
            Value::from_json_str(&obj.to_string())
        }),
    );
}

fn resolve_span(model: &SemanticModel, resource_id: &str, prop_path: &str) -> SourceSpan {
    model.resource_span(resource_id, prop_path)
}

fn register_make_diag_full(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "make_diag_full".into(),
        7,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rule_id = params[0].as_string()?;
            let severity = params[1].as_string()?;
            let resource_id = params[2].as_string()?;
            let prop_path = params[3].as_string()?;
            let message = params[4].as_string()?;
            let fix = params[5].as_string()?;
            let doc_url = params[6].as_string()?;
            let span = resolve_span(&model, resource_id, prop_path);
            let fix_val =
                if fix.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(fix.to_string()) };
            let doc_val = if doc_url.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(doc_url.to_string())
            };
            let mut obj = serde_json::json!({
                "rule_id": rule_id.as_ref(), "severity": severity.as_ref(),
                "message": message.as_ref(), "resource_id": resource_id.as_ref(),
                "resource_path": prop_path.as_ref(),
                "suggested_fix": fix_val, "documentation_url": doc_val,
            });
            if span != UNKNOWN_SPAN {
                let m = obj.as_object_mut().unwrap();
                m.insert("start_line".into(), span.start_line.into());
                m.insert("start_column".into(), span.start_column.into());
                m.insert("end_line".into(), span.end_line.into());
                m.insert("end_column".into(), span.end_column.into());
            }
            Value::from_json_str(&obj.to_string())
        }),
    );
}

fn register_make_diag_related(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension("make_diag_related".into(), 6, Box::new(move |params: Vec<Value>| {
        let Some(model) = get_model(&holder) else { return Ok(Value::Undefined); };
        let rule_id = params[0].as_string()?;
        let severity = params[1].as_string()?;
        let resource_id = params[2].as_string()?;
        let prop_path = params[3].as_string()?;
        let message = params[4].as_string()?;
        let related_str = params[5].to_json_str()?;
        let span = resolve_span(&model, resource_id, prop_path);

        let related_arr: Vec<serde_json::Value> = serde_json::from_str(&related_str).unwrap_or_default();
        let related: Vec<serde_json::Value> = related_arr.iter().filter_map(|r| {
            let rr = r.get("resource")?.as_str()?;
            let rp = r.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let rm = r.get("message").and_then(|v| v.as_str()).unwrap_or("");
            let rspan = resolve_span(&model, rr, rp);
            let rtype = model.resources.get(rr).map(|res| res.resource_type.as_str()).unwrap_or("");
            Some(serde_json::json!({"start_line": rspan.start_line, "start_column": rspan.start_column, "end_line": rspan.end_line, "end_column": rspan.end_column, "message": rm, "resource_id": rr, "resource_type": rtype}))
        }).collect();

        let mut obj = serde_json::json!({
            "rule_id": rule_id.as_ref(), "severity": severity.as_ref(),
            "message": message.as_ref(), "resource_id": resource_id.as_ref(),
            "resource_path": prop_path.as_ref(),
            "related_locations": related,
        });
        if span != UNKNOWN_SPAN {
            let m = obj.as_object_mut().unwrap();
            m.insert("start_line".into(), span.start_line.into());
            m.insert("start_column".into(), span.start_column.into());
            m.insert("end_line".into(), span.end_line.into());
            m.insert("end_column".into(), span.end_column.into());
        }
        Value::from_json_str(&obj.to_string())
    }));
}

fn register_make_diag_conditional(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "make_diag_conditional".into(),
        6,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rule_id = params[0].as_string()?;
            let severity = params[1].as_string()?;
            let resource_id = params[2].as_string()?;
            let prop_path = params[3].as_string()?;
            let message = params[4].as_string()?;
            let conds_str = params[5].to_json_str()?;
            let span = resolve_span(&model, resource_id, prop_path);
            let conds_val: serde_json::Value = serde_json::from_str(&conds_str).unwrap_or(serde_json::Value::Null);

            let mut obj = serde_json::json!({
                "rule_id": rule_id.as_ref(), "severity": severity.as_ref(),
                "message": message.as_ref(), "resource_id": resource_id.as_ref(),
                "resource_path": prop_path.as_ref(),
                "condition_scenario": conds_val,
            });
            if span != UNKNOWN_SPAN {
                let m = obj.as_object_mut().unwrap();
                m.insert("start_line".into(), span.start_line.into());
                m.insert("start_column".into(), span.start_column.into());
                m.insert("end_line".into(), span.end_line.into());
                m.insert("end_column".into(), span.end_column.into());
            }
            Value::from_json_str(&obj.to_string())
        }),
    );
}

fn register_estimate_string_length(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "estimate_string_length".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::Undefined);
            };
            let rid = params[0].as_string()?;
            let path = params[1].as_string()?;
            match model.estimate_string_length(rid, path) {
                Some(len) => Ok(Value::from(len as i64)),
                None => Ok(Value::Undefined),
            }
        }),
    );
}

fn register_schema_string_length(rego: &mut regorus::Engine, registry: LazySchemaRegistry) {
    let _ = rego.add_extension(
        "schema_string_length".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let rtype = params[0].as_string()?;
            let prop = params[1].as_string()?;
            let info = match schema_reg(&registry).get(rtype.as_ref()) {
                Some(i) => i,
                None => return Ok(Value::Undefined),
            };
            let constraints = match info.property_constraints.get(prop.as_ref()) {
                Some(c) => c,
                None => return Ok(Value::Undefined),
            };
            let is_string = info.property_types.get(prop.as_ref()).map(|t| t == "string").unwrap_or(false);
            let mut map = serde_json::Map::new();
            if let Some(v) = constraints.get("minLength") {
                map.insert("minLength".into(), v.clone());
            } else if is_string && let Some(v) = constraints.get("minimum") {
                map.insert("minLength".into(), v.clone());
            }
            if let Some(v) = constraints.get("maxLength") {
                map.insert("maxLength".into(), v.clone());
            } else if is_string && let Some(v) = constraints.get("maximum") {
                map.insert("maxLength".into(), v.clone());
            }
            if map.is_empty() {
                return Ok(Value::Undefined);
            }
            Ok(json_to_value(&serde_json::Value::Object(map)))
        }),
    );
}

/// `schema_requires_unique_items(resource_type, property) -> bool` — true when
/// the property's schema constraint sets `uniqueItems: true`.
fn register_schema_requires_unique_items(rego: &mut regorus::Engine, registry: LazySchemaRegistry) {
    let _ = rego.add_extension(
        "schema_requires_unique_items".into(),
        2,
        Box::new(move |params: Vec<Value>| {
            let rtype = params[0].as_string()?;
            let prop = params[1].as_string()?;
            let requires_unique = schema_reg(&registry)
                .get(rtype.as_ref())
                .and_then(|info| info.property_constraints.get(prop.as_ref()))
                .and_then(|c| c.get("uniqueItems"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Ok(Value::from(requires_unique))
        }),
    );
}

fn register_unreachable_if_branches(rego: &mut regorus::Engine, holder: SharedModel) {
    let _ = rego.add_extension(
        "unreachable_if_branches".into(),
        1,
        Box::new(move |params: Vec<Value>| {
            let Some(model) = get_model(&holder) else {
                return Ok(Value::from(Vec::<Value>::new()));
            };
            let rid = params[0].as_string()?;
            let rid_str: &str = rid.as_ref();

            // Check if this is an output pseudo-resource
            if let Some(output_name) = rid_str.strip_prefix("__output__") {
                if let Some(output) = model.outputs.get(output_name) {
                    let base_assumptions: Vec<(String, bool)> = match &output.condition {
                        Some(cond) => vec![(cond.clone(), true)],
                        None => vec![],
                    };
                    let mut results = Vec::new();
                    // An output is not a resource; anchor the diagnostic at the
                    // full "Outputs/<name>/Value" path rather than a bare "Value".
                    let path_prefix = format!("Outputs/{}/Value", output_name);
                    collect_unreachable_branches(
                        &model,
                        output_name,
                        &output.value,
                        &path_prefix,
                        &base_assumptions,
                        &mut results,
                    );
                    return Ok(Value::from(results));
                }
                return Ok(Value::from(Vec::<Value>::new()));
            }

            let res = match model.resources.get(rid_str) {
                Some(r) => r,
                None => return Ok(Value::from(Vec::<Value>::new())),
            };
            let base_assumptions: Vec<(String, bool)> = match &res.condition {
                Some(cond) => vec![(cond.clone(), true)],
                None => vec![],
            };
            let mut results = Vec::new();
            for (prop_key, prop_val) in &res.properties {
                let path_prefix = format!("Properties.{}", prop_key);
                collect_unreachable_branches(&model, rid, prop_val, &path_prefix, &base_assumptions, &mut results);
            }
            Ok(Value::from(results))
        }),
    );
}

fn collect_unreachable_branches(
    model: &Arc<SemanticModel>,
    resource_id: &str,
    value: &ResolvedValue,
    path: &str,
    assumptions: &[(String, bool)],
    results: &mut Vec<Value>,
) {
    match value {
        ResolvedValue::Conditional { condition: cond, if_true: _, if_false: _ } => {
            let mut true_assumptions = assumptions.to_vec();
            true_assumptions.push((cond.clone(), true));
            // Flag the branch only when the surrounding assumptions make this
            // condition value unreachable — not when the condition can never take
            // the value on its own. A condition that is constant (a literal
            // tautology, or a parameter pinned to a single value) is the concern
            // of equality rules, not of branch reachability.
            if !model.conditions.is_satisfiable(&true_assumptions)
                && model.conditions.is_satisfiable(&[(cond.clone(), true)])
            {
                let mut map = serde_json::Map::new();
                map.insert("resourceId".into(), serde_json::Value::String(resource_id.to_string()));
                map.insert("path".into(), serde_json::Value::String(format!("{}.{}.1", path, FN_IF)));
                map.insert(
                    "message".into(),
                    serde_json::Value::String(format!(
                        "['Fn::If', 1] is not reachable. When setting condition '{}' to True",
                        cond
                    )),
                );
                results.push(json_to_value(&serde_json::Value::Object(map)));
            }

            let mut false_assumptions = assumptions.to_vec();
            false_assumptions.push((cond.clone(), false));
            if !model.conditions.is_satisfiable(&false_assumptions)
                && model.conditions.is_satisfiable(&[(cond.clone(), false)])
            {
                let existing: Vec<String> = assumptions
                    .iter()
                    .filter(|(name, _)| name != cond)
                    .map(|(name, val)| format!("condition '{}' is {}", name, if *val { "True" } else { "False" }))
                    .collect();
                let explanation = if existing.is_empty() {
                    format!("When setting condition '{}' to False from current status True", cond)
                } else {
                    format!(
                        "When setting condition '{}' to False. Where existing status for {}",
                        cond,
                        existing.join(" and ")
                    )
                };
                let mut map = serde_json::Map::new();
                map.insert("resourceId".into(), serde_json::Value::String(resource_id.to_string()));
                map.insert("path".into(), serde_json::Value::String(format!("{}.{}.2", path, FN_IF)));
                map.insert(
                    "message".into(),
                    serde_json::Value::String(format!("['Fn::If', 2] is not reachable. {}", explanation)),
                );
                results.push(json_to_value(&serde_json::Value::Object(map)));
            }

            // Only the reachability of the immediate Fn::If branches is checked;
            // we do not recurse into an Fn::If nested inside a branch, so we stop
            // here. Recursing would produce spurious findings (e.g.
            // `Fn::If.2.Fn::If.1`) for branches whose reachability depends on the
            // already-evaluated outer condition.
        }
        ResolvedValue::Map { entries } => {
            for MapEntry { key, value: val } in entries {
                collect_unreachable_branches(
                    model,
                    resource_id,
                    val,
                    &format!("{}.{}", path, key),
                    assumptions,
                    results,
                );
            }
        }
        ResolvedValue::List { items } => {
            for (i, val) in items.iter().enumerate() {
                collect_unreachable_branches(model, resource_id, val, &format!("{}.{}", path, i), assumptions, results);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use template_model::resolver::{MapEntry, RefKind, ResolvedValue};
    use template_model::{MARKER_DYNAMIC, MARKER_PARAM_TYPE, MARKER_REF};

    #[test]
    fn json_to_value_preserves_nested_structure() {
        let v = json_to_value(&serde_json::json!({"a": [1, "two", true], "b": {"c": null}}));
        let obj = v.as_object().expect("should be object");
        let a = obj.get(&Value::from("a")).expect("should have key 'a'");
        let arr = a.as_array().expect("'a' should be array");
        assert_eq!(arr.len(), 3);
    }

    #[test]
    fn json_to_value_empty_collections() {
        let arr = json_to_value(&serde_json::json!([]));
        assert!(arr.as_array().expect("should be array").is_empty());
        let obj = json_to_value(&serde_json::json!({}));
        obj.as_object().expect("should be a valid object");
    }

    #[test]
    fn rego_to_json_round_trips_primitives() {
        assert_eq!(rego_to_json(&Value::from("hello")), serde_json::json!("hello"));
        assert_eq!(rego_to_json(&Value::from(42i64)), serde_json::json!(42));
        assert_eq!(rego_to_json(&Value::from(true)), serde_json::json!(true));
        assert_eq!(rego_to_json(&Value::Null), serde_json::Value::Null);
    }

    #[test]
    fn resolved_to_rego_concrete_string() {
        let rv = ResolvedValue::Concrete { value: serde_json::json!("test").into() };
        assert_eq!(resolved_to_rego(&rv), Value::from("test"));
    }

    #[test]
    fn resolved_to_rego_concrete_number() {
        let rv = ResolvedValue::Concrete { value: serde_json::json!(99).into() };
        assert_eq!(resolved_to_rego(&rv), Value::from(99i64));
    }

    #[test]
    fn resolved_to_rego_list() {
        let rv = ResolvedValue::List {
            items: vec![
                ResolvedValue::Concrete { value: serde_json::json!(1).into() },
                ResolvedValue::Concrete { value: serde_json::json!(2).into() },
            ],
        };
        let v = resolved_to_rego(&rv);
        let arr = v.as_array().expect("should be array");
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn resolved_to_rego_map() {
        let rv = ResolvedValue::Map {
            entries: vec![MapEntry {
                key: "key".to_string(),
                value: ResolvedValue::Concrete { value: serde_json::json!("val").into() },
            }],
        };
        let v = resolved_to_rego(&rv);
        v.as_object().expect("resolved_to_rego should produce a valid object");
    }

    #[test]
    fn resolved_to_rego_enum_picks_first_concrete() {
        let rv = ResolvedValue::Enum {
            variants: vec![
                ResolvedValue::Concrete { value: serde_json::json!("first").into() },
                ResolvedValue::Concrete { value: serde_json::json!("second").into() },
            ],
        };
        assert_eq!(resolved_to_rego(&rv), Value::from("first"));
    }

    #[test]
    fn resolved_to_rego_enum_empty_returns_undefined() {
        let rv = ResolvedValue::Enum { variants: vec![] };
        assert_eq!(resolved_to_rego(&rv), Value::Undefined);
    }

    #[test]
    fn resolved_to_rego_conditional_returns_true_branch() {
        let rv = ResolvedValue::Conditional {
            condition: "cond".to_string(),
            if_true: Box::new(ResolvedValue::Concrete { value: serde_json::json!("yes").into() }),
            if_false: Box::new(ResolvedValue::Concrete { value: serde_json::json!("no").into() }),
        };
        assert_eq!(resolved_to_rego(&rv), Value::from("yes"));
    }

    #[test]
    fn resolved_to_rego_reference() {
        let rv = ResolvedValue::Reference { target: "MyBucket".to_string(), kind: RefKind::Ref };
        assert_eq!(resolved_to_rego(&rv), Value::from("MyBucket"));
    }

    #[test]
    fn resolved_to_rego_dynamic_returns_undefined() {
        let rv = ResolvedValue::Dynamic { reason: "param".to_string() };
        assert_eq!(resolved_to_rego(&rv), Value::Undefined);
    }

    #[test]
    fn resolved_to_rego_typed_dynamic_returns_undefined() {
        let rv = ResolvedValue::TypedDynamic { reason: "param".to_string(), param_type: "String".to_string() };
        assert_eq!(resolved_to_rego(&rv), Value::Undefined);
    }

    #[test]
    fn resolved_all_concrete_returns_single() {
        let rv = ResolvedValue::Concrete { value: serde_json::json!("x").into() };
        let vals = resolved_all_to_rego(&rv);
        assert_eq!(vals.len(), 1);
        assert_eq!(vals[0], Value::from("x"));
    }

    #[test]
    fn resolved_all_enum_expands_all() {
        let rv = ResolvedValue::Enum {
            variants: vec![
                ResolvedValue::Concrete { value: serde_json::json!("a").into() },
                ResolvedValue::Concrete { value: serde_json::json!("b").into() },
            ],
        };
        let vals = resolved_all_to_rego(&rv);
        assert_eq!(vals.len(), 2);
    }

    #[test]
    fn resolved_all_conditional_expands_both_branches() {
        let rv = ResolvedValue::Conditional {
            condition: "c".to_string(),
            if_true: Box::new(ResolvedValue::Concrete { value: serde_json::json!("t").into() }),
            if_false: Box::new(ResolvedValue::Concrete { value: serde_json::json!("f").into() }),
        };
        let vals = resolved_all_to_rego(&rv);
        assert_eq!(vals.len(), 2);
    }

    #[test]
    fn resolved_all_dynamic_returns_empty() {
        let rv = ResolvedValue::Dynamic { reason: "x".to_string() };
        assert!(resolved_all_to_rego(&rv).is_empty());
    }

    #[test]
    fn contains_dynamic_concrete_false() {
        let rv = ResolvedValue::Concrete { value: serde_json::json!("static").into() };
        assert!(!contains_dynamic(&rv));
    }

    #[test]
    fn contains_dynamic_dynamic_true() {
        let rv = ResolvedValue::Dynamic { reason: "param".to_string() };
        assert!(contains_dynamic(&rv));
    }

    #[test]
    fn contains_dynamic_typed_dynamic_true() {
        let rv = ResolvedValue::TypedDynamic { reason: "p".to_string(), param_type: "String".to_string() };
        assert!(contains_dynamic(&rv));
    }

    #[test]
    fn contains_dynamic_reference_true() {
        let rv = ResolvedValue::Reference { target: "Ref".to_string(), kind: RefKind::Ref };
        assert!(contains_dynamic(&rv));
    }

    #[test]
    fn contains_dynamic_nested_list() {
        let rv = ResolvedValue::List {
            items: vec![
                ResolvedValue::Concrete { value: serde_json::json!("ok").into() },
                ResolvedValue::Dynamic { reason: "param".to_string() },
            ],
        };
        assert!(contains_dynamic(&rv));
    }

    #[test]
    fn contains_dynamic_nested_map() {
        let rv = ResolvedValue::Map {
            entries: vec![
                MapEntry {
                    key: "a".to_string(),
                    value: ResolvedValue::Concrete { value: serde_json::json!("ok").into() },
                },
                MapEntry { key: "b".to_string(), value: ResolvedValue::Dynamic { reason: "p".to_string() } },
            ],
        };
        assert!(contains_dynamic(&rv));
    }

    #[test]
    fn contains_dynamic_conditional_true_branch() {
        let rv = ResolvedValue::Conditional {
            condition: "c".to_string(),
            if_true: Box::new(ResolvedValue::Dynamic { reason: "p".to_string() }),
            if_false: Box::new(ResolvedValue::Concrete { value: serde_json::json!("ok").into() }),
        };
        assert!(contains_dynamic(&rv));
    }

    #[test]
    fn resolved_value_to_json_static_concrete() {
        let rv = ResolvedValue::Concrete { value: serde_json::json!(42).into() };
        assert_eq!(resolved_value_to_json_static(&rv), serde_json::json!(42));
    }

    #[test]
    fn resolved_value_to_json_static_list() {
        let rv = ResolvedValue::List { items: vec![ResolvedValue::Concrete { value: serde_json::json!(1).into() }] };
        assert_eq!(resolved_value_to_json_static(&rv), serde_json::json!([1]));
    }

    #[test]
    fn resolved_value_to_json_static_map() {
        let rv = ResolvedValue::Map {
            entries: vec![MapEntry {
                key: "k".to_string(),
                value: ResolvedValue::Concrete { value: serde_json::json!("v").into() },
            }],
        };
        let j = resolved_value_to_json_static(&rv);
        assert_eq!(j["k"], serde_json::json!("v"));
    }

    #[test]
    fn resolved_value_to_json_static_enum_picks_first_concrete() {
        let rv = ResolvedValue::Enum {
            variants: vec![
                ResolvedValue::Dynamic { reason: "x".to_string() },
                ResolvedValue::Concrete { value: serde_json::json!("found").into() },
            ],
        };
        assert_eq!(resolved_value_to_json_static(&rv), serde_json::json!("found"));
    }

    #[test]
    fn resolved_value_to_json_static_enum_no_concrete_returns_null() {
        let rv = ResolvedValue::Enum { variants: vec![ResolvedValue::Dynamic { reason: "x".to_string() }] };
        assert_eq!(resolved_value_to_json_static(&rv), serde_json::Value::Null);
    }

    #[test]
    fn resolved_value_to_json_static_conditional_returns_true_branch() {
        let rv = ResolvedValue::Conditional {
            condition: "c".to_string(),
            if_true: Box::new(ResolvedValue::Concrete { value: serde_json::json!("yes").into() }),
            if_false: Box::new(ResolvedValue::Concrete { value: serde_json::json!("no").into() }),
        };
        assert_eq!(resolved_value_to_json_static(&rv), serde_json::json!("yes"));
    }

    #[test]
    fn resolved_value_to_json_static_reference_produces_marker() {
        let rv = ResolvedValue::Reference { target: "MyBucket".to_string(), kind: RefKind::Ref };
        let j = resolved_value_to_json_static(&rv);
        assert_ne!(j.get(MARKER_REF), None, "expected MARKER_REF key");
    }

    #[test]
    fn resolved_value_to_json_static_dynamic_produces_marker() {
        let rv = ResolvedValue::Dynamic { reason: "param".to_string() };
        let j = resolved_value_to_json_static(&rv);
        assert_ne!(j.get(MARKER_DYNAMIC), None, "expected MARKER_DYNAMIC key");
    }

    #[test]
    fn flatten_resolved_list_concrete_array() {
        let rv = ResolvedValue::Concrete { value: serde_json::json!([1, 2, 3]).into() };
        let items = flatten_resolved_list(&rv);
        assert_eq!(items.len(), 3);
    }

    #[test]
    fn flatten_resolved_list_ir_list() {
        let rv = ResolvedValue::List {
            items: vec![
                ResolvedValue::Concrete { value: serde_json::json!("a").into() },
                ResolvedValue::Concrete { value: serde_json::json!("b").into() },
            ],
        };
        let items = flatten_resolved_list(&rv);
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn flatten_resolved_list_conditional_merges_branches() {
        let rv = ResolvedValue::Conditional {
            condition: "c".to_string(),
            if_true: Box::new(ResolvedValue::List {
                items: vec![ResolvedValue::Concrete { value: serde_json::json!("a").into() }],
            }),
            if_false: Box::new(ResolvedValue::List {
                items: vec![ResolvedValue::Concrete { value: serde_json::json!("b").into() }],
            }),
        };
        let items = flatten_resolved_list(&rv);
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn flatten_resolved_list_scalar_wraps() {
        let rv = ResolvedValue::Concrete { value: serde_json::json!("scalar").into() };
        let items = flatten_resolved_list(&rv);
        assert_eq!(items.len(), 1);
    }

    #[test]
    fn flatten_resolved_list_empty_array() {
        let rv = ResolvedValue::Concrete { value: serde_json::json!([]).into() };
        assert!(flatten_resolved_list(&rv).is_empty());
    }

    fn eval_builtin(expr: &str) -> Value {
        let holder: SharedModel = Arc::new(Mutex::new(None));
        let region: SharedRegion = Arc::new(Mutex::new(None));
        let mut rego = regorus::Engine::new();
        rego.set_strict_builtin_errors(false);
        register_all(&mut rego, holder, region);
        let policy = format!("package test\nimport rego.v1\nresult := {}", expr);
        rego.add_policy("test.rego".into(), policy).unwrap();
        rego.set_input(Value::new_object());
        rego.eval_rule("data.test.result".into()).unwrap()
    }

    #[test]
    fn arn_matches_exact() {
        let v = eval_builtin(r#"arn_matches("arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket")"#);
        assert_eq!(v, Value::from(true));
    }

    #[test]
    fn arn_matches_wildcard_region() {
        let v = eval_builtin(r#"arn_matches("arn:aws:s3:us-east-1:123:bucket", "arn:aws:s3:*:123:bucket")"#);
        assert_eq!(v, Value::from(true));
    }

    #[test]
    fn arn_matches_mismatch() {
        let v = eval_builtin(r#"arn_matches("arn:aws:s3:::my-bucket", "arn:aws:ec2:::my-bucket")"#);
        assert_eq!(v, Value::from(false));
    }

    #[test]
    fn arn_matches_too_few_parts() {
        let v = eval_builtin(r#"arn_matches("arn:aws", "arn:aws:s3:::bucket")"#);
        assert_eq!(v, Value::from(false));
    }

    #[test]
    fn arn_matches_all_wildcards() {
        let v = eval_builtin(r#"arn_matches("arn:aws:s3:us-east-1:123:bucket", "arn:*:*:*:*:*")"#);
        assert_eq!(v, Value::from(true));
    }

    #[test]
    fn ip_overlaps_same_cidr() {
        let v = eval_builtin(r#"ip_overlaps("10.0.0.0/24", "10.0.0.0/24")"#);
        assert_eq!(v, Value::from(true));
    }

    #[test]
    fn ip_overlaps_supernet_contains_subnet() {
        let v = eval_builtin(r#"ip_overlaps("10.0.0.0/16", "10.0.1.0/24")"#);
        assert_eq!(v, Value::from(true));
    }

    #[test]
    fn ip_overlaps_disjoint() {
        let v = eval_builtin(r#"ip_overlaps("10.0.0.0/24", "10.0.1.0/24")"#);
        assert_eq!(v, Value::from(false));
    }

    #[test]
    fn ip_subnet_of_true() {
        let v = eval_builtin(r#"ip_subnet_of("10.0.1.0/24", "10.0.0.0/16")"#);
        assert_eq!(v, Value::from(true));
    }

    #[test]
    fn ip_subnet_of_false_disjoint() {
        let v = eval_builtin(r#"ip_subnet_of("192.168.0.0/24", "10.0.0.0/16")"#);
        assert_eq!(v, Value::from(false));
    }

    #[test]
    fn ip_subnet_of_same_network() {
        let v = eval_builtin(r#"ip_subnet_of("10.0.0.0/16", "10.0.0.0/16")"#);
        assert_eq!(v, Value::from(true));
    }

    #[test]
    fn is_valid_cidr_strict_valid_network() {
        let v = eval_builtin(r#"is_valid_cidr_strict("10.0.0.0/24")"#);
        assert_eq!(v, Value::from(true));
    }

    #[test]
    fn is_valid_cidr_strict_host_bits_set() {
        let v = eval_builtin(r#"is_valid_cidr_strict("10.0.0.1/24")"#);
        assert_eq!(v, Value::from(false));
    }

    #[test]
    fn is_valid_cidr_strict_slash_32() {
        let v = eval_builtin(r#"is_valid_cidr_strict("10.0.0.1/32")"#);
        assert_eq!(v, Value::from(true));
    }

    #[test]
    fn is_valid_cidr_strict_slash_0() {
        // Regression: previously caused overflow (shift by 32 on u32)
        let v = eval_builtin(r#"is_valid_cidr_strict("0.0.0.0/0")"#);
        assert_eq!(v, Value::from(true));
    }

    #[test]
    fn is_valid_cidr_strict_slash_0_with_host_bits() {
        // 10.0.0.0/0 has host bits set (10 != 0)
        let v = eval_builtin(r#"is_valid_cidr_strict("10.0.0.0/0")"#);
        assert_eq!(v, Value::from(false));
    }

    #[test]
    fn is_valid_cidr_strict_invalid_string() {
        let v = eval_builtin(r#"is_valid_cidr_strict("not-a-cidr")"#);
        assert_eq!(v, Value::from(false));
    }

    #[test]
    fn ensure_list_scalar_wraps() {
        let v = eval_builtin(r#"ensure_list("hello")"#);
        let arr = v.as_array().expect("should be array");
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn ensure_list_array_passthrough() {
        let v = eval_builtin(r#"ensure_list(["a", "b"])"#);
        let arr = v.as_array().expect("should be array");
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn ensure_list_number_wraps() {
        let v = eval_builtin(r#"ensure_list(42)"#);
        let arr = v.as_array().expect("should be array");
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn coerce_to_number_from_string() {
        let v = eval_builtin(r#"coerce_to_number("42")"#);
        assert_eq!(v, Value::from(42i64));
    }

    #[test]
    fn coerce_to_number_from_int() {
        let v = eval_builtin(r#"coerce_to_number(7)"#);
        assert_eq!(v, Value::from(7i64));
    }

    #[test]
    fn coerce_to_number_from_bool_returns_undefined() {
        let v = eval_builtin(r#"coerce_to_number(true)"#);
        assert_eq!(v, Value::Undefined);
    }

    #[test]
    fn coerce_to_number_from_non_numeric_string() {
        let v = eval_builtin(r#"coerce_to_number("abc")"#);
        assert_eq!(v, Value::Undefined);
    }

    #[test]
    fn coerce_to_string_from_number() {
        let v = eval_builtin(r#"coerce_to_string(42)"#);
        assert_eq!(v, Value::from("42"));
    }

    #[test]
    fn coerce_to_string_from_bool() {
        let v = eval_builtin(r#"coerce_to_string(true)"#);
        assert_eq!(v, Value::from("true"));
    }

    #[test]
    fn coerce_to_string_from_string() {
        let v = eval_builtin(r#"coerce_to_string("hello")"#);
        assert_eq!(v, Value::from("hello"));
    }

    #[test]
    fn cfn_type_compatible_string_to_string() {
        let v = eval_builtin(r#"cfn_type_compatible("hello", "string")"#);
        assert_eq!(v, Value::from(true));
    }

    #[test]
    fn cfn_type_compatible_number_string_to_number() {
        let v = eval_builtin(r#"cfn_type_compatible("42", "number")"#);
        assert_eq!(v, Value::from(true));
    }

    #[test]
    fn cfn_type_compatible_bool_to_string() {
        let v = eval_builtin(r#"cfn_type_compatible(true, "string")"#);
        assert_eq!(v, Value::from(false));
    }

    #[test]
    fn input_region_returns_null_when_unset() {
        let v = eval_builtin(r#"input_region()"#);
        assert_eq!(v, Value::Null);
    }

    #[test]
    fn input_region_returns_value_when_set() {
        let holder: SharedModel = Arc::new(Mutex::new(None));
        let region: SharedRegion = Arc::new(Mutex::new(Some("us-west-2".to_string())));
        let mut rego = regorus::Engine::new();
        rego.set_strict_builtin_errors(false);
        register_all(&mut rego, holder, region);
        rego.add_policy("test.rego".into(), "package test\nimport rego.v1\nresult := input_region()".into()).unwrap();
        rego.set_input(Value::new_object());
        let v = rego.eval_rule("data.test.result".into()).unwrap();
        assert_eq!(v, Value::from("us-west-2"));
    }

    #[test]
    fn resolved_value_to_json_static_typed_dynamic_produces_both_markers() {
        let rv = ResolvedValue::TypedDynamic {
            reason: "param".to_string(),
            param_type: "AWS::SSM::Parameter::Value<String>".to_string(),
        };
        let j = resolved_value_to_json_static(&rv);
        assert_ne!(j.get(MARKER_DYNAMIC), None, "expected MARKER_DYNAMIC key");
        assert_ne!(j.get(MARKER_PARAM_TYPE), None, "expected MARKER_PARAM_TYPE key");
        assert_eq!(j[MARKER_PARAM_TYPE], "AWS::SSM::Parameter::Value<String>");
    }

    #[test]
    fn resolved_all_list_returns_single_array() {
        let rv = ResolvedValue::List {
            items: vec![
                ResolvedValue::Concrete { value: serde_json::json!(1).into() },
                ResolvedValue::Concrete { value: serde_json::json!(2).into() },
            ],
        };
        let vals = resolved_all_to_rego(&rv);
        assert_eq!(vals.len(), 1, "List wraps into a single array value");
        vals[0].as_array().expect("first element should be an array");
    }

    #[test]
    fn resolved_all_map_returns_single_object() {
        let rv = ResolvedValue::Map {
            entries: vec![MapEntry {
                key: "k".to_string(),
                value: ResolvedValue::Concrete { value: serde_json::json!("v").into() },
            }],
        };
        let vals = resolved_all_to_rego(&rv);
        assert_eq!(vals.len(), 1, "Map wraps into a single object value");
    }

    #[test]
    fn resolved_all_reference_returns_empty() {
        // References are omitted so format-validation rules don't mistake a logical ID
        // for a literal value.
        let rv = ResolvedValue::Reference { target: "Target".to_string(), kind: RefKind::Ref };
        assert!(resolved_all_to_rego(&rv).is_empty());
    }

    #[test]
    fn resolved_all_typed_dynamic_returns_empty() {
        let rv = ResolvedValue::TypedDynamic { reason: "p".to_string(), param_type: "String".to_string() };
        assert!(resolved_all_to_rego(&rv).is_empty());
    }

    #[test]
    fn flatten_resolved_list_enum_flattens_all_variants() {
        let rv = ResolvedValue::Enum {
            variants: vec![
                ResolvedValue::Concrete { value: serde_json::json!([1, 2]).into() },
                ResolvedValue::Concrete { value: serde_json::json!([3]).into() },
            ],
        };
        let items = flatten_resolved_list(&rv);
        assert_eq!(items.len(), 3, "Enum should flatten all array variants");
    }

    #[test]
    fn contains_dynamic_enum_all_static_false() {
        let rv = ResolvedValue::Enum {
            variants: vec![
                ResolvedValue::Concrete { value: serde_json::json!("a").into() },
                ResolvedValue::Concrete { value: serde_json::json!("b").into() },
            ],
        };
        assert!(!contains_dynamic(&rv));
    }

    #[test]
    fn contains_dynamic_conditional_false_branch_only() {
        let rv = ResolvedValue::Conditional {
            condition: "c".to_string(),
            if_true: Box::new(ResolvedValue::Concrete { value: serde_json::json!("ok").into() }),
            if_false: Box::new(ResolvedValue::Dynamic { reason: "p".to_string() }),
        };
        assert!(contains_dynamic(&rv));
    }

    #[test]
    fn ip_subnet_of_mixed_v4_v6_returns_false() {
        let v = eval_builtin(r#"ip_subnet_of("10.0.0.0/24", "::1/128")"#);
        assert_eq!(v, Value::from(false));
    }

    #[test]
    fn is_valid_cidr_strict_ipv6_valid() {
        let v = eval_builtin(r#"is_valid_cidr_strict("2001:db8::/32")"#);
        assert_eq!(v, Value::from(true));
    }

    #[test]
    fn coerce_to_number_from_float_string() {
        let v = eval_builtin(r#"coerce_to_number("3.14")"#);
        assert_eq!(v, Value::from(3.14f64));
    }

    #[test]
    fn coerce_to_string_from_null_returns_undefined() {
        let v = eval_builtin(r#"coerce_to_string(null)"#);
        assert_eq!(v, Value::Undefined);
    }

    #[test]
    fn ensure_list_null_wraps() {
        let v = eval_builtin(r#"ensure_list(null)"#);
        let arr = v.as_array().expect("should be array");
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn ensure_list_bool_wraps() {
        let v = eval_builtin(r#"ensure_list(true)"#);
        let arr = v.as_array().expect("should be array");
        assert_eq!(arr.len(), 1);
    }
}
