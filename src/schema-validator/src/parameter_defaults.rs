use crate::compiled::{CompiledSchema, PropSchema};
use crate::store::CompiledSchemaStore;
use crate::validate::find_prop_schema_deep;
use diagnostics::{Diagnostic, RegisteredDiagnostic};
use std::collections::{HashMap, HashSet};
use template_model::coercion::{coerce_to_number, scalar_eq};
use template_model::consts::{PARAM_TYPE_NUMBER, PARAM_TYPE_STRING};
use template_model::resolved_value::effective_path_from_scenario_source_path;
use template_model::resolver::{ParameterInfo, RefKind};
use template_model::{SemanticModel, compile_pattern};

fn directly_referenced_property_path(source_path: &str) -> Option<String> {
    let effective_path = effective_path_from_scenario_source_path(source_path)?;
    let property_path = effective_path.strip_prefix("Properties.")?;
    (!property_path.is_empty()).then(|| property_path.to_string())
}

fn composed_constraint_rule_id(intrinsic_name: &str) -> Option<&'static str> {
    match intrinsic_name.strip_prefix("Intrinsic/").unwrap_or(intrinsic_name) {
        "Sub" | "Fn::Sub" => Some("W1031"),
        "Join" | "Fn::Join" => Some("W1032"),
        "Split" | "Fn::Split" => Some("W1033"),
        "FindInMap" | "Fn::FindInMap" => Some("W1034"),
        "Select" | "Fn::Select" => Some("W1035"),
        "GetAZs" | "Fn::GetAZs" => Some("W1036"),
        _ => None,
    }
}

fn containing_property_path(
    model: &SemanticModel,
    resource_schema: &CompiledSchema,
    resource_id: &str,
    source_path: &str,
) -> Option<(String, String, &'static str)> {
    let mut ancestor = source_path.to_string();
    loop {
        let source = model.resolution_sources.get(&(resource_id.to_string(), ancestor.clone()));
        let rule_id = model
            .authored_intrinsic_name_at(resource_id, &ancestor)
            .and_then(composed_constraint_rule_id)
            .or_else(|| source.and_then(|source| composed_constraint_rule_id(source)));
        if let Some(rule_id) = rule_id
            && let Some(effective_path) = effective_path_from_scenario_source_path(&ancestor)
            && let Some(property_path) = effective_path.strip_prefix("Properties.")
            && find_prop_schema_deep(property_path, resource_schema).is_some()
        {
            return Some((effective_path, ancestor, rule_id));
        }
        let (parent, _) = ancestor.rsplit_once('.')?;
        ancestor = parent.to_string();
    }
}

fn condition_scenario(context: Option<&str>) -> Option<HashMap<String, bool>> {
    let context = context?;
    let mut conditions = HashMap::new();
    for selector in context.split(',') {
        let (condition, selected) = selector.strip_prefix('!').map_or((selector, true), |name| (name, false));
        if !condition.is_empty() {
            conditions.insert(condition.to_string(), selected);
        }
    }
    (!conditions.is_empty()).then_some(conditions)
}

struct ParameterCandidate<'a> {
    value: &'a str,
    anchor: String,
    is_default: bool,
}

fn parameter_candidates<'a>(name: &str, parameter: &'a ParameterInfo) -> Vec<ParameterCandidate<'a>> {
    if let Some(allowed_values) = &parameter.allowed_values {
        return allowed_values
            .iter()
            .enumerate()
            .map(|(index, value)| ParameterCandidate {
                value,
                anchor: format!("Parameters/{name}/AllowedValues/{index}"),
                is_default: false,
            })
            .collect();
    }
    parameter
        .default
        .as_deref()
        .map(|value| vec![ParameterCandidate { value, anchor: format!("Parameters/{name}/Default"), is_default: true }])
        .unwrap_or_default()
}

struct ConstraintViolation {
    message: String,
    anchor_default_at_parameter: bool,
}

fn constraint_violations(
    value: &serde_json::Value,
    reference: &str,
    property_path: &str,
    constraints: &PropSchema,
) -> Vec<ConstraintViolation> {
    let mut violations = Vec::new();
    let exact_enum_mismatch =
        !constraints.enum_values.is_empty() && !constraints.enum_values.iter().any(|allowed| scalar_eq(allowed, value));
    let insensitive_enum_mismatch = !constraints.enum_case_insensitive.is_empty()
        && !constraints.enum_case_insensitive.iter().any(|allowed| match (allowed.as_str(), value.as_str()) {
            (Some(allowed), Some(actual)) => allowed.eq_ignore_ascii_case(actual),
            _ => scalar_eq(allowed, value),
        });
    if exact_enum_mismatch || insensitive_enum_mismatch {
        violations.push(ConstraintViolation {
            message: format!("{} is not one of the allowed values for property '{}'", reference, property_path),
            anchor_default_at_parameter: true,
        });
    }
    if let Some(string) = value.as_str() {
        if let Some(pattern) = constraints.pattern.as_deref()
            && let Some(compiled) = compile_pattern(pattern)
            && !compiled.is_match(string)
        {
            violations.push(ConstraintViolation {
                message: format!("{} does not match pattern '{}' for property '{}'", reference, pattern, property_path),
                anchor_default_at_parameter: true,
            });
        }
        let length = string.chars().count() as u64;
        if let Some(minimum) = constraints.min_length
            && length < minimum
        {
            violations.push(ConstraintViolation {
                message: format!(
                    "{} has length {}, below minimum {} for property '{}'",
                    reference, length, minimum, property_path
                ),
                anchor_default_at_parameter: false,
            });
        }
        if let Some(maximum) = constraints.max_length
            && length > maximum
        {
            violations.push(ConstraintViolation {
                message: format!(
                    "{} has length {}, above maximum {} for property '{}'",
                    reference, length, maximum, property_path
                ),
                anchor_default_at_parameter: false,
            });
        }
    }
    if let Some(number) = coerce_to_number(value) {
        if let Some(minimum) = constraints.minimum
            && number < minimum
        {
            violations.push(ConstraintViolation {
                message: format!("{} is below minimum {} for property '{}'", reference, minimum, property_path),
                anchor_default_at_parameter: true,
            });
        }
        if let Some(maximum) = constraints.maximum
            && number > maximum
        {
            violations.push(ConstraintViolation {
                message: format!("{} is above maximum {} for property '{}'", reference, maximum, property_path),
                anchor_default_at_parameter: true,
            });
        }
    }
    violations
}

fn push_warning(
    diagnostics: &mut Vec<Diagnostic>,
    emitted: &mut HashSet<(String, String, String, String, String)>,
    model: &SemanticModel,
    rule_id: &str,
    resource_id: &str,
    source_path: &str,
    condition_scenario: Option<HashMap<String, bool>>,
    parameter_anchor: Option<&str>,
    message: String,
) {
    let message = if parameter_anchor.is_some() {
        format!("{} when resolved at Resources/{}/{}", message, resource_id, source_path.replace('.', "/"))
    } else {
        message
    };
    let diagnostic_path = parameter_anchor.unwrap_or(source_path).to_string();
    let identity = (
        rule_id.to_string(),
        resource_id.to_string(),
        source_path.to_string(),
        diagnostic_path.clone(),
        message.clone(),
    );
    if !emitted.insert(identity) {
        return;
    }
    let mut diagnostic = RegisteredDiagnostic::new(rule_id, message)
        .property_path(&diagnostic_path)
        .condition_scenario(condition_scenario);
    if parameter_anchor.is_some() {
        if let Some(span) = model.source_location(&diagnostic_path) {
            diagnostic = diagnostic.location(*span);
        }
    } else {
        let effective_path =
            effective_path_from_scenario_source_path(source_path).unwrap_or_else(|| source_path.to_string());
        let value_branch_prefix = format!("{effective_path}.Fn::If.");
        let source_anchor = if source_path.starts_with(&value_branch_prefix) { &effective_path } else { source_path };
        diagnostic = diagnostic
            .property_path(&effective_path)
            .resource(resource_id, model.resources.get(resource_id).map(|resource| resource.resource_type.clone()))
            .location(model.resource_span(resource_id, source_anchor));
    }
    diagnostics.push(diagnostic.build());
}

/// Warns when an overridable parameter candidate violates constraints on the
/// destination property, including nested object and array-item paths. Defaults
/// and AllowedValues remain dynamic for Fatal schema validation because callers
/// may supply a different deployment value.
pub(crate) fn parameter_default_constraint_diagnostics(
    model: &SemanticModel,
    store: &CompiledSchemaStore,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let mut emitted = HashSet::new();

    for edge in &model.graph.edges {
        if !matches!(edge.kind, RefKind::Ref)
            || !model.is_authored_ref_at(&edge.source_resource, &edge.source_path, &edge.target)
            || model.parameter_has_override(&edge.target)
        {
            continue;
        }
        let Some(parameter) = model.parameters.get(&edge.target) else {
            continue;
        };
        if !matches!(parameter.param_type.as_str(), PARAM_TYPE_STRING | PARAM_TYPE_NUMBER) {
            continue;
        }
        let Some(resource) = model.resources.get(&edge.source_resource) else {
            continue;
        };
        let Some(property_path) = directly_referenced_property_path(&edge.source_path) else {
            continue;
        };
        let Some(resource_schema) = store.get(&resource.resource_type) else {
            continue;
        };
        let Some(constraints) = find_prop_schema_deep(&property_path, resource_schema) else {
            continue;
        };
        for candidate in parameter_candidates(&edge.target, parameter) {
            let candidate_value = serde_json::Value::String(candidate.value.to_string());
            let reference = if candidate.is_default {
                format!("{{'Ref': '{}'}} default '{}'", edge.target, candidate.value)
            } else {
                format!("{{'Ref': '{}'}} AllowedValues entry '{}'", edge.target, candidate.value)
            };
            for violation in constraint_violations(&candidate_value, &reference, &property_path, &constraints) {
                let parameter_anchor = (!candidate.is_default || violation.anchor_default_at_parameter)
                    .then_some(candidate.anchor.as_str());
                push_warning(
                    &mut diagnostics,
                    &mut emitted,
                    model,
                    "W1030",
                    &edge.source_resource,
                    &edge.source_path,
                    condition_scenario(edge.condition_context.as_deref()),
                    parameter_anchor,
                    violation.message,
                );
            }
        }
    }

    let mut processed_composed_sources = HashSet::new();
    for edge in &model.graph.edges {
        if !matches!(edge.kind, RefKind::Ref) || model.parameter_has_override(&edge.target) {
            continue;
        }
        let Some(parameter) = model.parameters.get(&edge.target) else {
            continue;
        };
        if !matches!(parameter.param_type.as_str(), PARAM_TYPE_STRING | PARAM_TYPE_NUMBER)
            || (parameter.default.is_none() && parameter.allowed_values.is_none())
        {
            continue;
        }
        let Some(resource) = model.resources.get(&edge.source_resource) else {
            continue;
        };
        let Some(resource_schema) = store.get(&resource.resource_type) else {
            continue;
        };
        let is_direct_destination = model.is_authored_ref_at(&edge.source_resource, &edge.source_path, &edge.target)
            && directly_referenced_property_path(&edge.source_path)
                .is_some_and(|path| find_prop_schema_deep(&path, resource_schema).is_some());
        if is_direct_destination {
            continue;
        }
        let Some((effective_path, intrinsic_source_path, rule_id)) =
            containing_property_path(model, resource_schema, &edge.source_resource, &edge.source_path)
        else {
            continue;
        };
        if !processed_composed_sources.insert((edge.source_resource.clone(), intrinsic_source_path.clone())) {
            continue;
        }
        let Some(property_path) = effective_path.strip_prefix("Properties.") else {
            continue;
        };
        let Some(constraints) = find_prop_schema_deep(property_path, resource_schema) else {
            continue;
        };
        for (value, conditions) in model.resolve_scenarios_json(&edge.source_resource, &effective_path) {
            let assumptions: Vec<_> = conditions.iter().map(|(name, value)| (name.clone(), *value)).collect();
            if !model.conditions.is_satisfiable(&assumptions) || value.is_null() {
                continue;
            }
            let source_path = model
                .scenario_source_path(&edge.source_resource, &effective_path, &conditions)
                .unwrap_or_else(|| effective_path.clone());
            let intrinsic_descendant_prefix = format!("{intrinsic_source_path}.");
            if source_path != intrinsic_source_path && !source_path.starts_with(&intrinsic_descendant_prefix) {
                continue;
            }
            let selected_parameter_candidate = (rule_id == "W1035")
                .then(|| model.authored_select_ref_target_at(&edge.source_resource, &intrinsic_source_path))
                .flatten()
                .and_then(|target| model.parameters.get(target).map(|parameter| (target, parameter)))
                .filter(|(target, parameter)| {
                    !model.parameter_has_override(target)
                        && matches!(parameter.param_type.as_str(), PARAM_TYPE_STRING | PARAM_TYPE_NUMBER)
                })
                .and_then(|(target, parameter)| {
                    parameter_candidates(target, parameter)
                        .into_iter()
                        .find(|candidate| scalar_eq(&serde_json::Value::String(candidate.value.to_string()), &value))
                });
            let reference = format!("Resolved parameter-dependent value {}", value);
            for violation in constraint_violations(&value, &reference, property_path, &constraints) {
                let parameter_anchor = selected_parameter_candidate
                    .as_ref()
                    .filter(|candidate| !candidate.is_default || violation.anchor_default_at_parameter)
                    .map(|candidate| candidate.anchor.as_str());
                push_warning(
                    &mut diagnostics,
                    &mut emitted,
                    model,
                    rule_id,
                    &edge.source_resource,
                    &source_path,
                    (!conditions.is_empty()).then_some(conditions.clone()),
                    parameter_anchor,
                    violation.message,
                );
            }
        }
    }

    diagnostics
}
