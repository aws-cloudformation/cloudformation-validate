use crate::consts::*;
use crate::diagnostic::*;
use crate::model::{ResolvedOutput, ResolvedResource, SemanticModel, TemplateRule};
use crate::resolved_value::collect_condition_refs_from_resolved;
use crate::resolver::{MapEntry, RefKind, ResolvedValue};
use diagnostics::{JsonValue, Phase};
use rules::Severity;
use std::collections::HashMap;

impl SemanticModel {
    pub fn to_diagnostic_json(&self) -> DiagnosticModel {
        let resources = build_resources(&self.resources, &self.graph);
        let conditions = build_conditions(&self.conditions);
        let cycles = filter_sam_cycles(self.graph.cycles(), &self.transforms, &self.resources);
        let outputs = build_outputs(&self.outputs, &self.graph);

        DiagnosticModel {
            template: DiagnosticTemplate {
                format_version: self.format_version.clone(),
                description: self.description.clone(),
                transforms: self.transforms.clone(),
                raw_top_level_keys: self.raw_top_level_keys.clone(),
            },
            parameters: self
                .parameters
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        JsonValue(serde_json::json!({
                            "type": v.param_type,
                            "default": v.default,
                            "allowedValues": v.allowed_values,
                            "allowedPattern": v.allowed_pattern,
                            "allowedPatternValid": v.allowed_pattern_valid,
                            "defaultMatchesAllowedPattern": v.default_matches_allowed_pattern,
                            "minLength": v.min_length,
                            "maxLength": v.max_length,
                            "minValue": v.min_value,
                            "maxValue": v.max_value,
                            "noEcho": v.no_echo,
                        })),
                    )
                })
                .collect(),
            conditions,
            condition_param_refs: self.conditions.referenced_params(),
            condition_implications: self
                .conditions
                .implications
                .iter()
                .map(|i| DiagnosticImplication { antecedent: i.antecedent.clone(), consequent: i.consequent.clone() })
                .collect(),
            condition_mutex_groups: self
                .conditions
                .mutex_groups
                .iter()
                .map(|g| DiagnosticMutexGroup {
                    conditions: g.conditions.clone(),
                    parameter: g.parameter.clone(),
                    values: g.values.clone(),
                })
                .collect(),
            condition_exclusions: {
                // Sort the condition names before the pairwise pass. HashMap
                // iteration order is randomized per run, so if the cumulative
                // satisfiability budget is exhausted partway through, an
                // unsorted order would make the set of pairs examined — and thus
                // the exclusions found — differ across runs. A stable order keeps
                // budget-truncated output deterministic and engine-identical,
                // mirroring the deterministic per-type resource ordering in
                // `model`.
                let mut cond_names: Vec<&String> = self.conditions.conditions.keys().collect();
                cond_names.sort();
                let mut exclusions = Vec::new();
                'pairs: for i in 0..cond_names.len() {
                    for j in (i + 1)..cond_names.len() {
                        // Stop once the model's cumulative satisfiability budget
                        // is spent: every remaining pair would only get the
                        // conservative "compatible" answer, so continuing adds
                        // no exclusions and would let an adversarial condition
                        // graph keep the quadratic pass running unbounded.
                        if self.conditions.satisfiability_budget_exhausted() {
                            break 'pairs;
                        }
                        if !self.conditions.conditions_compatible(cond_names[i], cond_names[j]) {
                            exclusions.push(vec![cond_names[i].clone(), cond_names[j].clone()]);
                        }
                    }
                }
                exclusions
            },
            resource_condition_map: self
                .resources
                .iter()
                .filter_map(|(id, r)| r.condition.as_ref().map(|c| (id.clone(), c.clone())))
                .collect(),
            mappings: JsonValue(serde_json::json!(self.mappings)),
            resources,
            outputs,
            edges: build_edges(&self.graph),
            cycles,
            output_empty_joins: self.output_empty_joins.clone(),
            sam_implicit_resources: self.sam_implicit_resources.iter().cloned().collect(),
            globals_param_refs: self.globals_param_refs.clone(),
            is_cdk: self.is_cdk,
            fn_if_conditions: self.fn_if_conditions.clone(),
            find_in_map_names: {
                let mut names: Vec<String> = self.find_in_map_names.iter().cloned().collect();
                names.sort();
                names
            },
            params_referenced_in_definitions: {
                let mut names: Vec<String> = self.params_referenced_in_definitions.iter().cloned().collect();
                names.sort();
                names
            },
            has_dynamic_findinmap_name: self.has_dynamic_findinmap_name,
            has_parse_errors: self
                .diagnostics
                .iter()
                .any(|d| d.severity == Severity::Fatal && d.phase == Some(Phase::Parse)),
            parsed_rules: self.parsed_rules.iter().map(build_rule).collect(),
            resolution_sources: self
                .resolution_sources
                .iter()
                .map(|((rid, path), source)| ResolutionSource {
                    resource_id: rid.clone(),
                    property_path: path.clone(),
                    source: source.clone(),
                })
                .collect(),
        }
    }
}

fn build_resources(
    resources: &HashMap<String, ResolvedResource>,
    graph: &crate::graph::ReferenceGraph,
) -> HashMap<String, DiagnosticResource> {
    resources
        .iter()
        .map(|(id, res)| {
            let props: HashMap<String, JsonValue> =
                res.properties.iter().map(|(k, v)| (k.clone(), JsonValue(resolved_value_to_json(v)))).collect();

            let outgoing = graph
                .outgoing(id)
                .iter()
                .map(|e| {
                    let (kind, attr) = ref_kind_to_str(&e.kind);
                    OutgoingRef {
                        source_path: e.source_path.clone(),
                        target: e.target.clone(),
                        kind: kind.to_string(),
                        attr,
                        condition_context: e.condition_context.clone(),
                    }
                })
                .collect();

            let incoming = graph
                .incoming(id)
                .iter()
                .map(|e| {
                    let (kind, attr) = ref_kind_to_str(&e.kind);
                    IncomingRef {
                        source: e.source_resource.clone(),
                        source_path: e.source_path.clone(),
                        kind: kind.to_string(),
                        attr,
                    }
                })
                .collect();

            (
                id.clone(),
                DiagnosticResource {
                    resource_type: res.resource_type.clone(),
                    condition: res.condition.clone(),
                    depends_on: res.depends_on.clone(),
                    deletion_policy: res.deletion_policy.as_ref().map(|v| JsonValue(resolved_value_to_json(v))),
                    update_replace_policy: res
                        .update_replace_policy
                        .as_ref()
                        .map(|v| JsonValue(resolved_value_to_json(v))),
                    creation_policy: res.creation_policy.as_ref().map(|v| JsonValue(serde_json::json!(v))),
                    update_policy: res.update_policy.as_ref().map(|v| JsonValue(serde_json::json!(v))),
                    properties: props,
                    outgoing_refs: outgoing,
                    incoming_refs: incoming,
                    find_in_map_refs: res.diagnostics.find_in_map_refs.clone(),
                    simple_subs: res
                        .diagnostics
                        .simple_subs
                        .iter()
                        .map(|s| PathVariable { path: s.path.clone(), variable: s.value.clone() })
                        .collect(),
                    redundant_subs: res.diagnostics.redundant_subs.clone(),
                    empty_joins: res.diagnostics.empty_joins.clone(),
                    hardcoded_partition_arns: res.diagnostics.hardcoded_partition_arns.clone(),
                    conditionally_null_props: res
                        .diagnostics
                        .conditionally_null_props
                        .iter()
                        .map(|s| ConditionalNull {
                            path: s.path.clone(),
                            condition: s.condition.clone(),
                            null_in_true: s.null_in_true_branch,
                        })
                        .collect(),
                    condition_refs: res.diagnostics.condition_refs.clone(),
                    for_each_expansions: res
                        .diagnostics
                        .foreach_expansions
                        .iter()
                        .map(|fe| DiagnosticForEachExpansion {
                            path: fe.property_path.clone(),
                            identifier: fe.identifier.clone(),
                            collection: fe.collection_source.clone(),
                        })
                        .collect(),
                    unsubstituted_variables: res
                        .diagnostics
                        .unsubstituted_variables
                        .iter()
                        .map(|s| PathVariable { path: s.path.clone(), variable: s.value.clone() })
                        .collect(),
                    invalid_refs: res
                        .diagnostics
                        .invalid_refs
                        .iter()
                        .map(|s| PathTarget { path: s.path.clone(), target: s.value.clone() })
                        .collect(),
                },
            )
        })
        .collect()
}

fn build_conditions(conditions: &crate::conditions::ConditionModel) -> HashMap<String, DiagnosticCondition> {
    let mut out = HashMap::new();
    for name in conditions.names() {
        let (expression, deps) = if let Some(expr) = conditions.get(name) {
            let mut d = Vec::new();
            crate::conditions::collect_condition_deps(expr, &mut d);
            d.sort();
            d.dedup();
            (Some(crate::conditions::format_condition_expr(expr)), if d.is_empty() { None } else { Some(d) })
        } else {
            (None, None)
        };

        let mut mutex_with: Vec<String> = Vec::new();
        for group in &conditions.mutex_groups {
            if group.conditions.contains(&name.to_string()) {
                for peer in &group.conditions {
                    if peer != name {
                        mutex_with.push(peer.clone());
                    }
                }
            }
        }

        out.insert(
            name.to_string(),
            DiagnosticCondition {
                expression,
                deps,
                mutex_with: if mutex_with.is_empty() { None } else { Some(mutex_with) },
            },
        );
    }
    out
}

fn build_edges(graph: &crate::graph::ReferenceGraph) -> Vec<ReferenceEdge> {
    graph
        .edges
        .iter()
        .map(|e| {
            let (kind, attr) = ref_kind_to_str(&e.kind);
            ReferenceEdge {
                source: e.source_resource.clone(),
                source_path: e.source_path.clone(),
                target: e.target.clone(),
                kind: kind.to_string(),
                attr,
                condition_context: e.condition_context.clone(),
            }
        })
        .collect()
}

fn build_outputs(
    outputs: &HashMap<String, ResolvedOutput>,
    graph: &crate::graph::ReferenceGraph,
) -> HashMap<String, DiagnosticOutput> {
    let mut output_getatt_refs: HashMap<String, Vec<(String, String)>> = HashMap::new();
    for edge in &graph.edges {
        if let Some(output_name) = edge.source_resource.strip_prefix(OUTPUT_PSEUDO_RESOURCE_PREFIX)
            && let RefKind::GetAtt { attr } = &edge.kind
        {
            output_getatt_refs.entry(output_name.to_string()).or_default().push((edge.target.clone(), attr.clone()));
        }
    }

    outputs
        .iter()
        .map(|(name, output)| {
            let mut getatt_refs = Vec::new();
            collect_getatt_refs(&output.value, &mut getatt_refs);
            if let Some(edge_refs) = output_getatt_refs.get(name) {
                for (t, a) in edge_refs {
                    if !getatt_refs.iter().any(|(rt, ra)| rt == t && ra == a) {
                        getatt_refs.push((t.clone(), a.clone()));
                    }
                }
            }
            (
                name.clone(),
                DiagnosticOutput {
                    value: JsonValue(resolved_value_to_json(&output.value)),
                    description: output.description.clone(),
                    condition: output.condition.clone(),
                    export_name: output.export_name.as_ref().map(|v| JsonValue(resolved_value_to_json(v))),
                    getatt_refs: getatt_refs
                        .into_iter()
                        .map(|(r, a)| GetAttRef { resource: r, attribute: a })
                        .collect(),
                    condition_refs: {
                        let mut crefs = Vec::new();
                        collect_condition_refs_from_resolved(&output.value, &mut crefs);
                        crefs.sort();
                        crefs.dedup();
                        crefs
                    },
                },
            )
        })
        .collect()
}

fn build_rule(r: &TemplateRule) -> DiagnosticRule {
    DiagnosticRule {
        name: r.name.clone(),
        condition: r.condition.as_ref().map(|v| JsonValue(v.clone())),
        assertions: r
            .assertions
            .iter()
            .map(|a| DiagnosticRuleAssertion {
                assert_expr: JsonValue(a.assert.clone()),
                assert_description: a.description.clone(),
            })
            .collect(),
    }
}

fn filter_sam_cycles(
    raw_cycles: &[Vec<String>],
    transforms: &[String],
    resources: &HashMap<String, ResolvedResource>,
) -> Vec<Vec<String>> {
    let has_sam = transforms.iter().any(|t| t.contains(SAM_TRANSFORM_MARKER));
    if has_sam {
        raw_cycles
            .iter()
            .filter(|cycle| {
                !cycle.iter().any(|rid| {
                    resources.get(rid).map(|r| r.resource_type.starts_with(SAM_SERVERLESS_TYPE_PREFIX)).unwrap_or(false)
                })
            })
            .cloned()
            .collect()
    } else {
        raw_cycles.to_vec()
    }
}

pub fn resolved_value_to_json(val: &ResolvedValue) -> serde_json::Value {
    match val {
        ResolvedValue::Concrete { value: v } => v.0.clone(),
        ResolvedValue::List { items } => serde_json::Value::Array(items.iter().map(resolved_value_to_json).collect()),
        ResolvedValue::Map { entries } => {
            let mut map = serde_json::Map::new();
            for MapEntry { key: k, value: v } in entries {
                map.insert(k.clone(), resolved_value_to_json(v));
            }
            serde_json::Value::Object(map)
        }
        ResolvedValue::Enum { variants: vals } => {
            serde_json::json!({MARKER_ENUM: vals.iter().map(resolved_value_to_json).collect::<Vec<_>>()})
        }
        ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f } => {
            serde_json::json!({MARKER_CONDITIONAL: cond, MARKER_IF_TRUE: resolved_value_to_json(t), MARKER_IF_FALSE: resolved_value_to_json(f)})
        }
        ResolvedValue::Reference { target, kind } => {
            let kind_str = match kind {
                RefKind::Ref => "resource".to_string(),
                RefKind::GetAtt { attr: a } => format!("getatt:{}", a),
                RefKind::Sub { var: v } => format!("sub:{}", v),
                RefKind::DependsOn => "dependson".to_string(),
            };
            serde_json::json!({MARKER_REF: target, MARKER_KIND: kind_str})
        }
        ResolvedValue::Dynamic { reason } => serde_json::json!({MARKER_DYNAMIC: reason}),
        ResolvedValue::TypedDynamic { reason, param_type } => {
            serde_json::json!({MARKER_DYNAMIC: reason, MARKER_PARAM_TYPE: param_type})
        }
    }
}

pub fn resolved_value_to_json_clean(val: &ResolvedValue) -> Option<serde_json::Value> {
    match val {
        ResolvedValue::Concrete { value: v } => Some(v.0.clone()),
        ResolvedValue::List { items } => {
            Some(serde_json::Value::Array(items.iter().filter_map(resolved_value_to_json_clean).collect()))
        }
        ResolvedValue::Map { entries } => {
            let mut map = serde_json::Map::new();
            for MapEntry { key: k, value: v } in entries {
                if let Some(jv) = resolved_value_to_json_clean(v) {
                    map.insert(k.clone(), jv);
                }
            }
            Some(serde_json::Value::Object(map))
        }
        ResolvedValue::Enum { variants: vals } => {
            let concrete: Vec<serde_json::Value> = vals.iter().filter_map(resolved_value_to_json_clean).collect();
            match concrete.len() {
                0 => None,
                1 => Some(concrete.into_iter().next().unwrap()),
                _ => Some(serde_json::Value::Array(concrete)),
            }
        }
        ResolvedValue::Conditional { condition: _, if_true: t, if_false: _ } => resolved_value_to_json_clean(t),
        ResolvedValue::Dynamic { reason: _ }
        | ResolvedValue::TypedDynamic { reason: _, param_type: _ }
        | ResolvedValue::Reference { target: _, kind: _ } => None,
    }
}

fn ref_kind_to_str(kind: &RefKind) -> (&'static str, Option<String>) {
    match kind {
        RefKind::Ref => (EDGE_KIND_REF, None),
        RefKind::GetAtt { attr } => (EDGE_KIND_GET_ATT, Some(attr.clone())),
        RefKind::Sub { var } => (EDGE_KIND_SUB, Some(var.clone())),
        RefKind::DependsOn => (EDGE_KIND_DEPENDS_ON, None),
    }
}

fn collect_getatt_refs(val: &ResolvedValue, out: &mut Vec<(String, String)>) {
    match val {
        ResolvedValue::Reference { target, kind: RefKind::GetAtt { attr } } => out.push((target.clone(), attr.clone())),
        ResolvedValue::List { items } => {
            for v in items {
                collect_getatt_refs(v, out);
            }
        }
        ResolvedValue::Map { entries } => {
            for MapEntry { key: _, value: v } in entries {
                collect_getatt_refs(v, out);
            }
        }
        ResolvedValue::Enum { variants: vals } => {
            for v in vals {
                collect_getatt_refs(v, out);
            }
        }
        ResolvedValue::Conditional { condition: _, if_true: t, if_false: f } => {
            collect_getatt_refs(t, out);
            collect_getatt_refs(f, out);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn to_json_concrete() {
        assert_eq!(resolved_value_to_json(&ResolvedValue::Concrete { value: json!("hi").into() }), json!("hi"));
        assert_eq!(resolved_value_to_json(&ResolvedValue::Concrete { value: json!(42).into() }), json!(42));
    }

    #[test]
    fn to_json_list() {
        let val = ResolvedValue::List {
            items: vec![
                ResolvedValue::Concrete { value: json!(1).into() },
                ResolvedValue::Concrete { value: json!(2).into() },
            ],
        };
        assert_eq!(resolved_value_to_json(&val), json!([1, 2]));
    }

    #[test]
    fn to_json_map() {
        let val = ResolvedValue::Map {
            entries: vec![MapEntry { key: "k".into(), value: ResolvedValue::Concrete { value: json!("v").into() } }],
        };
        assert_eq!(resolved_value_to_json(&val), json!({"k": "v"}));
    }

    #[test]
    fn to_json_enum_uses_marker() {
        let val = ResolvedValue::Enum { variants: vec![ResolvedValue::Concrete { value: json!("a").into() }] };
        let j = resolved_value_to_json(&val);
        assert_ne!(j.get(MARKER_ENUM), None, "expected MARKER_ENUM key in serialized enum");
    }

    #[test]
    fn to_json_conditional_uses_markers() {
        let val = ResolvedValue::Conditional {
            condition: "C".into(),
            if_true: Box::new(ResolvedValue::Concrete { value: json!(1).into() }),
            if_false: Box::new(ResolvedValue::Concrete { value: json!(2).into() }),
        };
        let j = resolved_value_to_json(&val);
        assert_eq!(j[MARKER_CONDITIONAL], "C");
        assert_eq!(j[MARKER_IF_TRUE], 1);
        assert_eq!(j[MARKER_IF_FALSE], 2);
    }

    #[test]
    fn to_json_reference_uses_markers() {
        let val = ResolvedValue::Reference { target: "R".into(), kind: RefKind::GetAtt { attr: "Arn".into() } };
        let j = resolved_value_to_json(&val);
        assert_eq!(j[MARKER_REF], "R");
        assert_eq!(j[MARKER_KIND], "getatt:Arn");
    }

    #[test]
    fn to_json_dynamic_uses_marker() {
        let val = ResolvedValue::Dynamic { reason: "reason".into() };
        assert_eq!(resolved_value_to_json(&val)[MARKER_DYNAMIC], "reason");
    }

    #[test]
    fn to_json_typed_dynamic_includes_param_type() {
        let val = ResolvedValue::TypedDynamic { reason: "reason".into(), param_type: "Number".into() };
        let j = resolved_value_to_json(&val);
        assert_eq!(j[MARKER_DYNAMIC], "reason");
        assert_eq!(j[MARKER_PARAM_TYPE], "Number");
    }

    #[test]
    fn to_json_clean_concrete() {
        assert_eq!(
            resolved_value_to_json_clean(&ResolvedValue::Concrete { value: json!("x").into() }),
            Some(json!("x"))
        );
    }

    #[test]
    fn to_json_clean_dynamic_returns_none() {
        assert_eq!(
            resolved_value_to_json_clean(&ResolvedValue::Dynamic { reason: "x".into() }),
            None,
            "Dynamic should return None"
        );
    }

    #[test]
    fn to_json_clean_reference_returns_none() {
        assert_eq!(
            resolved_value_to_json_clean(&ResolvedValue::Reference { target: "R".into(), kind: RefKind::Ref }),
            None,
            "Reference should return None"
        );
    }

    #[test]
    fn to_json_clean_conditional_takes_true_branch() {
        let val = ResolvedValue::Conditional {
            condition: "C".into(),
            if_true: Box::new(ResolvedValue::Concrete { value: json!("yes").into() }),
            if_false: Box::new(ResolvedValue::Concrete { value: json!("no").into() }),
        };
        assert_eq!(resolved_value_to_json_clean(&val), Some(json!("yes")));
    }

    #[test]
    fn to_json_clean_enum_single_unwraps() {
        let val = ResolvedValue::Enum { variants: vec![ResolvedValue::Concrete { value: json!("only").into() }] };
        assert_eq!(resolved_value_to_json_clean(&val), Some(json!("only")));
    }

    #[test]
    fn to_json_clean_enum_multiple_returns_array() {
        let val = ResolvedValue::Enum {
            variants: vec![
                ResolvedValue::Concrete { value: json!("a").into() },
                ResolvedValue::Concrete { value: json!("b").into() },
            ],
        };
        assert_eq!(resolved_value_to_json_clean(&val), Some(json!(["a", "b"])));
    }

    #[test]
    fn to_json_clean_enum_all_dynamic_returns_none() {
        let val = ResolvedValue::Enum { variants: vec![ResolvedValue::Dynamic { reason: "x".into() }] };
        assert_eq!(resolved_value_to_json_clean(&val), None, "all-dynamic enum should return None");
    }

    #[test]
    fn to_json_clean_list_filters_dynamic() {
        let val = ResolvedValue::List {
            items: vec![
                ResolvedValue::Concrete { value: json!(1).into() },
                ResolvedValue::Dynamic { reason: "x".into() },
            ],
        };
        assert_eq!(resolved_value_to_json_clean(&val), Some(json!([1])));
    }

    #[test]
    fn to_json_clean_map_filters_dynamic() {
        let val = ResolvedValue::Map {
            entries: vec![
                MapEntry { key: "a".into(), value: ResolvedValue::Concrete { value: json!(1).into() } },
                MapEntry { key: "b".into(), value: ResolvedValue::Dynamic { reason: "x".into() } },
            ],
        };
        assert_eq!(resolved_value_to_json_clean(&val), Some(json!({"a": 1})));
    }

    #[test]
    fn ref_kind_to_str_all_variants() {
        assert_eq!(ref_kind_to_str(&RefKind::Ref), ("Ref", None));
        assert_eq!(ref_kind_to_str(&RefKind::GetAtt { attr: "A".into() }), ("GetAtt", Some("A".into())));
        assert_eq!(ref_kind_to_str(&RefKind::Sub { var: "V".into() }), ("Sub", Some("V".into())));
        assert_eq!(ref_kind_to_str(&RefKind::DependsOn), ("DependsOn", None));
    }

    #[test]
    fn to_json_reference_sub_kind() {
        let val = ResolvedValue::Reference { target: "R".into(), kind: RefKind::Sub { var: "V".into() } };
        let j = resolved_value_to_json(&val);
        assert_eq!(j[MARKER_KIND], "sub:V");
    }

    #[test]
    fn to_json_reference_dependson_kind() {
        let val = ResolvedValue::Reference { target: "R".into(), kind: RefKind::DependsOn };
        let j = resolved_value_to_json(&val);
        assert_eq!(j[MARKER_KIND], "dependson");
    }
}
