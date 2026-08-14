use super::{EvalContext, NativeRuleRegistry};
use diagnostics::Diagnostic;
use rules::Category;
use template_model::consts::{
    EDGE_KIND_GET_ATT, EDGE_KIND_REF, EDGE_KIND_SUB, FIELD_CONDITION_CONTEXT, FIELD_KIND, FIELD_OUTGOING_REFS,
    FIELD_RESOURCES, FIELD_SOURCE_PATH, FIELD_TARGET, KEY_DEPENDS_ON, OUTPUT_PSEUDO_RESOURCE_PREFIX,
};
use template_model::resolver::RefKind;
use validation_engine::make_resource_diagnostic;

pub fn register(reg: &mut NativeRuleRegistry) {
    reg.add(Category::Reference, eval_references);
}

/// Whether a property path points at a value selected by an `Fn::If` branch
/// (a path segment `Fn::If` followed by branch index `1` or `2`). Such a
/// reference is guarded by the surrounding `Fn::If`, so the conditional-target
/// reference check does not apply.
fn path_inside_fn_if_branch(path: &str) -> bool {
    let segments: Vec<&str> = path.split('.').collect();
    segments.windows(2).any(|w| w[0] == "Fn::If" && (w[1] == "1" || w[1] == "2"))
}

fn eval_references(ctx: &EvalContext) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let m = ctx.model;
    let input = ctx.input;

    for (name, res) in &m.resources {
        for dep in &res.depends_on {
            if !m.resources.contains_key(dep.as_str()) && !m.sam_implicit_resources.contains(dep.as_str()) {
                // A dynamic reference cannot name a resource: DependsOn takes
                // literal logical IDs only, so say that rather than implying a
                // resource of that name could be added.
                let message = if dep.contains("{{resolve:") {
                    format!("DependsOn must be a resource logical ID, not a dynamic reference: '{}'", dep)
                } else {
                    format!("DependsOn target '{}' does not exist as a resource", dep)
                };
                out.push(make_resource_diagnostic("E3005", &message, m, name, "", None));
            }
        }
    }

    for (name, res) in &m.resources {
        for dep in &res.depends_on {
            if let Some(dep_res) = m.resources.get(dep.as_str())
                && let Some(ref dep_cond) = dep_res.condition
            {
                let source_cond = res.condition.as_deref();
                if !m.conditions.condition_implies(source_cond.unwrap_or(""), dep_cond) && source_cond.is_some()
                    || (source_cond.is_none() && dep_res.condition.is_some())
                {
                    let implies = match source_cond {
                        Some(sc) => m.conditions.condition_implies(sc, dep_cond),
                        None => false, // unconditional resource depends on conditional
                    };
                    if !implies {
                        out.push(make_resource_diagnostic(
                            "E3005",
                            &format!("'{}' will not exist when condition '{}' is False", dep, dep_cond),
                            m,
                            name,
                            KEY_DEPENDS_ON,
                            Some(&format!("Add a Condition to '{}' that implies '{}'", name, dep_cond)),
                        ));
                    }
                }
            }
        }
    }

    for (name, res) in &m.resources {
        for dep in &res.depends_on {
            for edge in m.graph.outgoing(name) {
                if edge.target == *dep {
                    let kind_str = match &edge.kind {
                        RefKind::Ref => EDGE_KIND_REF,
                        RefKind::GetAtt { attr: _ } => EDGE_KIND_GET_ATT,
                        RefKind::Sub { var: _ } => EDGE_KIND_SUB,
                        _ => continue,
                    };
                    out.push(make_resource_diagnostic(
                        "W3005",
                        &format!("'{}' dependency already enforced by a '{}' at '{}'", dep, kind_str, edge.source_path),
                        m,
                        name,
                        KEY_DEPENDS_ON,
                        Some("Remove the DependsOn entry"),
                    ));
                }
            }
        }
    }

    if let Some(resources) = input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
        for (source, res_json) in resources {
            if let Some(edges) = res_json.get(FIELD_OUTGOING_REFS).and_then(|r| r.as_array()) {
                for edge in edges {
                    let kind = edge.get(FIELD_KIND).and_then(|k| k.as_str()).unwrap_or("");
                    if kind != EDGE_KIND_REF && kind != EDGE_KIND_GET_ATT {
                        continue;
                    }
                    let target = edge.get(FIELD_TARGET).and_then(|t| t.as_str()).unwrap_or("");
                    let source_path = edge.get(FIELD_SOURCE_PATH).and_then(|p| p.as_str()).unwrap_or("");
                    // A reference that is itself a value inside an Fn::If branch is
                    // already guarded by that Fn::If; the explicit branch choice
                    // makes it safe, so skip these.
                    if path_inside_fn_if_branch(source_path) {
                        continue;
                    }
                    if let Some(target_res) = m.resources.get(target)
                        && let Some(ref target_cond) = target_res.condition
                    {
                        let source_cond = m.resources.get(source.as_str()).and_then(|r| r.condition.as_deref());
                        let implies = match source_cond {
                            Some(sc) => m.conditions.condition_implies(sc, target_cond),
                            None => false,
                        };
                        if !implies {
                            // Check if the reference is inside an Fn::If guarded by a
                            // condition that (in conjunction with source_cond) implies
                            // the target's condition. Uses SAT: if
                            // `source_cond=T, part=T, target_cond=F` is unsatisfiable,
                            // the reference is safe.
                            let guarded = edge
                                .get(FIELD_CONDITION_CONTEXT)
                                .and_then(|c| c.as_str())
                                .map(|cc| {
                                    cc.split(',').filter(|p| !p.is_empty()).any(|part| {
                                        let mut assumptions: Vec<(String, bool)> =
                                            vec![(target_cond.clone(), false), (part.to_string(), true)];
                                        if let Some(sc) = source_cond {
                                            assumptions.push((sc.to_string(), true));
                                        }
                                        !m.conditions.is_satisfiable(&assumptions)
                                    })
                                })
                                .unwrap_or(false);
                            if !guarded {
                                out.push(make_resource_diagnostic("W1001",
                                        &format!("Reference to '{}' which is conditional on '{}' - target may not exist", target, target_cond),
                                        m,
                                        source,
                                        source_path,
                                        Some("Add a Condition to the referencing resource that implies the target's condition"),
                                    ));
                            }
                        }
                    }
                }
            }
        }
    }

    // Check output references to conditional resources
    for (out_name, output) in &m.outputs {
        let output_pseudo_id = format!("{}{}", OUTPUT_PSEUDO_RESOURCE_PREFIX, out_name);
        for edge in m.graph.outgoing(&output_pseudo_id) {
            let kind_str = match &edge.kind {
                RefKind::Ref => EDGE_KIND_REF,
                RefKind::GetAtt { .. } => EDGE_KIND_GET_ATT,
                _ => continue,
            };
            let _ = kind_str;
            if let Some(target_res) = m.resources.get(&edge.target)
                && let Some(ref target_cond) = target_res.condition
            {
                let source_cond = output.condition.as_deref();
                let implies = match source_cond {
                    Some(sc) => m.conditions.condition_implies(sc, target_cond),
                    None => false,
                };
                if !implies {
                    // An output is not a resource - the edge's section-absolute
                    // source path identifies it.
                    out.push(make_resource_diagnostic(
                        "W1001",
                        &format!(
                            "Reference to '{}' which is conditional on '{}' - target may not exist",
                            edge.target, target_cond
                        ),
                        m,
                        "",
                        &edge.source_path,
                        Some("Add a Condition to the output that implies the target's condition"),
                    ));
                }
            }
        }
    }

    out
}
