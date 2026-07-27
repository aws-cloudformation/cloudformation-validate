use super::{EvalContext, NativeRuleRegistry};
use diagnostics::{Diagnostic, RelatedResource, ResourceRef};
use rules::Category;
use std::collections::HashMap;
use std::sync::Arc;
use template_model::SemanticModel;
use template_model::SourceSpan;
use template_model::consts::{INLINE_CONDITION_PREFIX, KEY_DEPENDS_ON};
use template_model::resolver::ResolvedValue;
use validation_engine::make_resource_diagnostic;

pub fn register(reg: &mut NativeRuleRegistry) {
    reg.add(Category::Resource, eval_condition_dependencies);
    reg.add(Category::Resource, eval_unreachable_if_branches);
}

fn eval_condition_dependencies(ctx: &EvalContext) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let m = ctx.model;

    let mut res_cond: HashMap<&str, &str> = HashMap::new();
    for (id, res) in &m.resources {
        if let Some(ref c) = res.condition {
            res_cond.insert(id.as_str(), c.as_str());
        }
    }

    for edge in &m.graph.edges {
        let source = &edge.source_resource;
        let target = &edge.target;
        if source.starts_with("__output__") {
            continue;
        }
        if !m.resources.contains_key(target.as_str()) {
            continue;
        }
        if !m.resources.contains_key(source.as_str()) {
            continue;
        }

        let target_cond = match res_cond.get(target.as_str()) {
            Some(c) => *c,
            None => continue,
        };
        let source_cond = match res_cond.get(source.as_str()) {
            Some(c) => *c,
            None => continue, // unconditional → already covered by output-reference checks
        };
        if source_cond == target_cond {
            continue;
        }
        if m.conditions.condition_implies(source_cond, target_cond) {
            continue;
        }

        if !m.conditions.conditions_compatible(source_cond, target_cond) {
            let mut d = make_resource_diagnostic(
                "W2503",
                &format!(
                    "Resource '{}' (condition '{}') references '{}' (condition '{}'), but these conditions are mutually exclusive - this reference will always fail",
                    source, source_cond, target, target_cond
                ),
                m,
                source,
                &edge.source_path,
                None,
            );

            let target_path = format!("Resources/{}", target);
            if let Some(span) = m.source_location(&target_path) {
                d.related_resources.get_or_insert_with(Vec::new).push(RelatedResource {
                    resource: Some(ResourceRef {
                        id: Some(target.clone()),
                        resource_type: m.resources.get(target.as_str()).map(|r| r.resource_type.clone()),
                    }),
                    location: Some(SourceSpan {
                        start_line: span.start_line,
                        start_column: span.start_column,
                        end_line: span.end_line,
                        end_column: span.end_column,
                    }),
                    message: format!("Conditional resource '{}' (condition '{}')", target, target_cond),
                });
            }
            out.push(d);
        }
    }

    for (source, res) in &m.resources {
        for dep in &res.depends_on {
            let target_cond = match res_cond.get(dep.as_str()) {
                Some(c) => *c,
                None => continue,
            };
            let source_cond = res_cond.get(source.as_str()).copied();
            if source_cond == Some(target_cond) {
                continue;
            }
            if let Some(sc) = source_cond
                && m.conditions.condition_implies(sc, target_cond)
            {
                continue;
            }

            out.push(make_resource_diagnostic("W2502",
                &format!("Resource '{}' has DependsOn '{}' which is conditional (condition '{}'), but '{}' does not have a matching condition",
                    source, dep, target_cond, source),
                m,
                source,
                KEY_DEPENDS_ON,
                Some(&format!("Add Condition: {} to resource '{}'", target_cond, source)),
            ));
        }
    }

    out
}

fn eval_unreachable_if_branches(ctx: &EvalContext) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let m = ctx.model;

    for (name, res) in &m.resources {
        let base_assumptions: Vec<(String, bool)> = match &res.condition {
            Some(cond) => vec![(cond.clone(), true)],
            None => vec![],
        };
        for (prop_key, prop_val) in &res.properties {
            let path_prefix = format!("Properties.{}", prop_key);
            find_unreachable_branches(&mut out, m, name, prop_val, &path_prefix, &base_assumptions);
        }
    }

    // Also check Output values for unreachable Fn::If branches. An output is not
    // a resource, so leave the resource slot empty and anchor the diagnostic at
    // the full "Outputs/<name>/Value" path (matching how output locations are
    // addressed elsewhere) rather than a bare "Value" under the output's logical
    // name.
    for (name, output) in &m.outputs {
        let base_assumptions: Vec<(String, bool)> = match &output.condition {
            Some(cond) => vec![(cond.clone(), true)],
            None => vec![],
        };
        let path_prefix = format!("Outputs/{}/Value", name);
        find_unreachable_branches(&mut out, m, "", &output.value, &path_prefix, &base_assumptions);
    }
    out
}

fn find_unreachable_branches(
    out: &mut Vec<Diagnostic>,
    model: &Arc<SemanticModel>,
    resource_id: &str,
    value: &ResolvedValue,
    path: &str,
    assumptions: &[(String, bool)],
) {
    match value {
        ResolvedValue::Conditional { condition: cond, if_true, if_false } => {
            // A synthetic name minted for an inline `Fn::If` expression is not a
            // template condition: the expression form is already reported at
            // parse time, and the internal label means nothing to the author.
            let synthetic = cond.starts_with(INLINE_CONDITION_PREFIX);
            let mut true_assumptions = assumptions.to_vec();
            true_assumptions.push((cond.clone(), true));
            // Flag the branch only when the surrounding assumptions make this
            // condition value unreachable — not when the condition can never take
            // the value on its own. A condition that is constant (a literal
            // tautology, or a parameter pinned to a single value) is the concern
            // of equality rules, not of branch reachability.
            let true_reachable = model.conditions.is_satisfiable(&true_assumptions);
            if !true_reachable && !synthetic && model.conditions.is_satisfiable(&[(cond.clone(), true)]) {
                let explanation = build_unreachable_explanation(cond, true, assumptions);
                out.push(make_resource_diagnostic(
                    "W1028",
                    &format!("['Fn::If', 1] is not reachable. {}", explanation),
                    model,
                    resource_id,
                    &format!("{}.Fn::If.1", path),
                    None,
                ));
            }

            let mut false_assumptions = assumptions.to_vec();
            false_assumptions.push((cond.clone(), false));
            let false_reachable = model.conditions.is_satisfiable(&false_assumptions);
            if !false_reachable && !synthetic && model.conditions.is_satisfiable(&[(cond.clone(), false)]) {
                let explanation = build_unreachable_explanation(cond, false, assumptions);
                out.push(make_resource_diagnostic(
                    "W1028",
                    &format!("['Fn::If', 2] is not reachable. {}", explanation),
                    model,
                    resource_id,
                    &format!("{}.Fn::If.2", path),
                    None,
                ));
            }

            // Recurse into each branch that is itself reachable, carrying this
            // condition's value as an assumption — an inner Fn::If whose
            // condition is implied (or contradicted) by the outer one has a
            // branch nothing can select. An unreachable branch is not entered:
            // its contradictory assumption set would mark every nested branch
            // unreachable, burying the one finding that matters.
            if true_reachable {
                find_unreachable_branches(
                    out,
                    model,
                    resource_id,
                    if_true,
                    &format!("{}.Fn::If.1", path),
                    &true_assumptions,
                );
            }
            if false_reachable {
                find_unreachable_branches(
                    out,
                    model,
                    resource_id,
                    if_false,
                    &format!("{}.Fn::If.2", path),
                    &false_assumptions,
                );
            }
        }
        ResolvedValue::Map { entries } => {
            for e in entries {
                find_unreachable_branches(
                    out,
                    model,
                    resource_id,
                    &e.value,
                    &format!("{}.{}", path, e.key),
                    assumptions,
                );
            }
        }
        ResolvedValue::List { items } => {
            for (i, val) in items.iter().enumerate() {
                find_unreachable_branches(out, model, resource_id, val, &format!("{}.{}", path, i), assumptions);
            }
        }
        _ => {}
    }
}

fn build_unreachable_explanation(condition: &str, target_value: bool, assumptions: &[(String, bool)]) -> String {
    let setting = if target_value { "True" } else { "False" };
    let existing: Vec<String> = assumptions
        .iter()
        .filter(|(name, _)| name != condition)
        .map(|(name, val)| format!("condition '{}' is {}", name, if *val { "True" } else { "False" }))
        .collect();
    if existing.is_empty() {
        format!(
            "When setting condition '{}' to {} from current status {}",
            condition,
            setting,
            if target_value { "False" } else { "True" }
        )
    } else {
        format!(
            "When setting condition '{}' to {}. Where existing status for {}",
            condition,
            setting,
            existing.join(" and ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explanation_no_existing_assumptions() {
        let result = build_unreachable_explanation("IsProduction", false, &[]);
        assert!(result.contains("IsProduction"));
        assert!(result.contains("False"));
    }

    #[test]
    fn explanation_with_existing_assumptions() {
        let assumptions = vec![("IsProduction".to_string(), true)];
        let result = build_unreachable_explanation("IsStaging", false, &assumptions);
        assert!(result.contains("IsStaging"));
        assert!(result.contains("False"));
        assert!(result.contains("IsProduction"));
        assert!(result.contains("True"));
    }

    #[test]
    fn explanation_filters_self_from_existing() {
        let assumptions = vec![("SameCond".to_string(), true)];
        let result = build_unreachable_explanation("SameCond", false, &assumptions);
        // Should not mention SameCond in the "existing status" part
        assert!(result.contains("SameCond"));
        assert!(result.contains("False"));
    }
}
