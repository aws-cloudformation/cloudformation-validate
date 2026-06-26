use super::{EvalContext, NativeRuleRegistry};
use diagnostics::Diagnostic;
use template_model::SemanticModel;
use template_model::consts::{
    FIELD_CREATION_POLICY, FIELD_RESOURCE_TYPE, FIELD_RESOURCES, FIELD_UPDATE_POLICY, KEY_CREATION_POLICY,
    KEY_UPDATE_POLICY,
};
use template_model::resolver::ResolvedValue;
use validation_engine::make_resource_diagnostic;

pub fn register(reg: &mut NativeRuleRegistry) {
    reg.add(rules::Category::Resource, eval_resources);
    reg.add(rules::Category::Resource, crate::rules::resources_extra::eval_extra_resources);
}

fn resolve_concrete(m: &SemanticModel, rid: &str, path: &str) -> Option<serde_json::Value> {
    match m.resolve_deep(rid, path).or_else(|| m.resolve(rid, path).cloned())? {
        ResolvedValue::Concrete { value: v } => Some(v.into_inner()),
        _ => None,
    }
}

fn is_dynamic(m: &SemanticModel, rid: &str, path: &str) -> bool {
    m.resolve_deep(rid, path)
        .or_else(|| m.resolve(rid, path).cloned())
        .map(|rv| crate::functions::contains_unresolvable_content(&rv))
        .unwrap_or(false)
}

fn eval_resources(ctx: &EvalContext) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let m = ctx.model;

    for name in m.resources_of_type("AWS::ECS::TaskDefinition") {
        if let Some(serde_json::Value::Array(compat)) = resolve_concrete(m, name, "Properties.RequiresCompatibilities")
        {
            if !compat.iter().any(|v| v.as_str() == Some("FARGATE")) {
                continue;
            }
            if is_dynamic(m, name, "Properties.Cpu") || is_dynamic(m, name, "Properties.Memory") {
                continue;
            }
            let cpu = resolve_concrete(m, name, "Properties.Cpu");
            let mem = resolve_concrete(m, name, "Properties.Memory");
            if let (Some(cpu_val), Some(mem_val)) = (cpu, mem) {
                let cpu_n = to_num(&cpu_val);
                let mem_n = to_num(&mem_val);
                if let (Some(c), Some(me)) = (cpu_n, mem_n)
                    && !valid_fargate_combo(c, me)
                {
                    out.push(make_resource_diagnostic(
                            "E3047",
                            &format!("Cpu {} is not compatible with Memory {} for Fargate", c, me),
                            m,
                            name,
                            "Properties.Cpu",
                            Some("Use a valid Fargate CPU/memory combination (e.g., Cpu: 256 with Memory: 512, 1024, or 2048)"),
                        ));
                }
            }
        }
    }

    let subnets = m.resources_of_type("AWS::EC2::Subnet");
    for (i, b_name) in subnets.iter().enumerate() {
        if i == 0 {
            continue;
        }
        if m.is_from_parameter(b_name, "Properties.CidrBlock") {
            continue;
        }
        let Some(serde_json::Value::String(b_cidr)) = resolve_concrete(m, b_name, "Properties.CidrBlock") else {
            continue;
        };
        let Ok(net_b) = b_cidr.parse::<ipnetwork::IpNetwork>() else {
            continue;
        };
        let b_cond = m.resources.get(b_name.as_str()).and_then(|r| r.condition.as_deref());
        let b_vpc = resolve_concrete(m, b_name, "Properties.VpcId");

        for a_name in &subnets[..i] {
            let a_cond = m.resources.get(a_name.as_str()).and_then(|r| r.condition.as_deref());
            if !m.conditions.resources_compatible(a_cond, b_cond) {
                continue;
            }
            if m.is_from_parameter(a_name, "Properties.CidrBlock") {
                continue;
            }
            let a_vpc = resolve_concrete(m, a_name, "Properties.VpcId");
            if a_vpc != b_vpc {
                continue;
            }
            let Some(serde_json::Value::String(a_cidr)) = resolve_concrete(m, a_name, "Properties.CidrBlock") else {
                continue;
            };
            let Ok(net_a) = a_cidr.parse::<ipnetwork::IpNetwork>() else {
                continue;
            };
            if !(net_a.contains(net_b.network()) || net_b.contains(net_a.network())) {
                continue;
            }
            let mut diag = make_resource_diagnostic(
                "E3060",
                &format!("'{}' overlaps with '{}'", b_cidr, a_cidr),
                m,
                b_name,
                "Properties.CidrBlock",
                None,
            );
            let span = m.resource_span(a_name, "");
            diag.related_resources.get_or_insert_with(Vec::new).push(diagnostics::RelatedResource {
                resource: Some(diagnostics::ResourceRef {
                    id: Some(a_name.clone()),
                    resource_type: m.resources.get(a_name.as_str()).map(|r| r.resource_type.clone()),
                }),
                location: Some(diagnostics::SourceSpan {
                    start_line: span.start_line,
                    start_column: span.start_column,
                    end_line: span.end_line,
                    end_column: span.end_column,
                }),
                message: format!("Overlapping subnet CIDR {}", a_cidr),
            });
            out.push(diag);
        }
    }

    for (name, res) in &m.resources {
        if res.resource_type.ends_with("::MODULE") && res.properties.contains_key("Tags") {
            out.push(make_resource_diagnostic(
                "E5001",
                &format!("Tags is not permitted within Module resource '{}'", name),
                m,
                name,
                "Properties.Tags",
                None,
            ));
        }
    }

    if let Some(resources) = ctx.input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
        for (name, res) in resources {
            let rtype = res.get(FIELD_RESOURCE_TYPE).and_then(|t| t.as_str()).unwrap_or("");
            if rtype.ends_with("::MODULE") {
                if res.get(FIELD_CREATION_POLICY).is_some_and(|v| !v.is_null()) {
                    out.push(make_resource_diagnostic(
                        "E5001",
                        &format!("CreationPolicy is not permitted within Module resource '{}'", name),
                        m,
                        name,
                        KEY_CREATION_POLICY,
                        None,
                    ));
                }
                if res.get(FIELD_UPDATE_POLICY).is_some_and(|v| !v.is_null()) {
                    out.push(make_resource_diagnostic(
                        "E5001",
                        &format!("UpdatePolicy is not permitted within Module resource '{}'", name),
                        m,
                        name,
                        KEY_UPDATE_POLICY,
                        None,
                    ));
                }
            }
        }
    }

    for name in m.resources_of_type("AWS::Lambda::Function") {
        if is_zip_deployment(m, name) {
            // Report a single diagnostic listing every missing property, anchored
            // at the Code property (CloudFormation rejects the resource once, not
            // once per property). Collect them and emit one finding rather than
            // one per property.
            let missing: Vec<&str> = ["Handler", "Runtime"]
                .into_iter()
                .filter(|prop| {
                    !m.resources.get(name.as_str()).map(|r| r.properties.contains_key(*prop)).unwrap_or(false)
                })
                .collect();
            if !missing.is_empty() {
                let formatted = missing.iter().map(|p| format!("'{}'", p)).collect::<Vec<_>>().join(", ");
                out.push(make_resource_diagnostic(
                    "W2533",
                    &format!(
                        "Properties [{}] missing for zip file deployment at Resources/{}/Properties",
                        formatted, name
                    ),
                    m,
                    name,
                    "Properties.Code",
                    Some("Add the missing properties for zip file deployment"),
                ));
            }
        }
    }

    for name in m.resources_of_type("AWS::SQS::Queue") {
        if let Some(serde_json::Value::Bool(true)) = resolve_concrete(m, name, "Properties.FifoQueue")
            && let Some(serde_json::Value::String(qname)) = resolve_concrete(m, name, "Properties.QueueName")
            && !qname.ends_with(".fifo")
        {
            out.push(make_resource_diagnostic(
                "E2504",
                &format!("FIFO queue name '{}' must end with '.fifo'", qname),
                m,
                name,
                "Properties.QueueName",
                None,
            ));
        }
    }

    if let Some(region) = ctx.region {
        let region_data = &ctx.cached_data.region_resource_types;
        if let Some(available) = region_data.get(region.as_str()).and_then(|v| v.as_object()) {
            for (name, res) in &m.resources {
                if !available.contains_key(&res.resource_type) {
                    let exists_somewhere = region_data
                        .as_object()
                        .map(|rd| rd.values().any(|rv| rv.get(&res.resource_type).is_some()))
                        .unwrap_or(false);
                    if exists_somewhere {
                        out.push(make_resource_diagnostic(
                            "E3001",
                            &format!("Resource type '{}' is not available in region '{}'", res.resource_type, region),
                            m,
                            name,
                            "",
                            None,
                        ));
                    }
                }
            }
        }
    }

    out
}

fn to_num(v: &serde_json::Value) -> Option<i64> {
    match v {
        serde_json::Value::Number(n) => n.as_i64(),
        serde_json::Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn valid_fargate_combo(cpu: i64, mem: i64) -> bool {
    match cpu {
        256 => [512, 1024, 2048].contains(&mem),
        512 => (1024..=4096).contains(&mem),
        1024 => (2048..=8192).contains(&mem),
        2048 => (4096..=16384).contains(&mem),
        4096 => (8192..=30720).contains(&mem),
        8192 => (16384..=61440).contains(&mem),
        16384 => (32768..=122880).contains(&mem),
        _ => false,
    }
}

fn is_zip_deployment(m: &SemanticModel, name: &str) -> bool {
    if let Some(serde_json::Value::String(pt)) = resolve_concrete(m, name, "Properties.PackageType") {
        return pt == "Zip";
    }
    if !m.resources.get(name).map(|r| r.properties.contains_key("PackageType")).unwrap_or(false)
        && let Some(serde_json::Value::Object(code)) = resolve_concrete(m, name, "Properties.Code")
    {
        return code.contains_key("ZipFile") || code.contains_key("S3Key");
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── valid_fargate_combo ─────────────────────────────────────────────

    #[test]
    fn fargate_cpu_256_valid() {
        assert!(valid_fargate_combo(256, 512));
        assert!(valid_fargate_combo(256, 1024));
        assert!(valid_fargate_combo(256, 2048));
    }

    #[test]
    fn fargate_cpu_256_invalid() {
        assert!(!valid_fargate_combo(256, 256));
        assert!(!valid_fargate_combo(256, 4096));
    }

    #[test]
    fn fargate_cpu_512_boundaries() {
        assert!(valid_fargate_combo(512, 1024));
        assert!(valid_fargate_combo(512, 4096));
        assert!(!valid_fargate_combo(512, 512));
        assert!(!valid_fargate_combo(512, 8192));
    }

    #[test]
    fn fargate_cpu_1024_boundaries() {
        assert!(valid_fargate_combo(1024, 2048));
        assert!(valid_fargate_combo(1024, 8192));
        assert!(!valid_fargate_combo(1024, 1024));
        assert!(!valid_fargate_combo(1024, 16384));
    }

    #[test]
    fn fargate_cpu_4096_boundaries() {
        assert!(valid_fargate_combo(4096, 8192));
        assert!(valid_fargate_combo(4096, 30720));
        assert!(!valid_fargate_combo(4096, 4096));
    }

    #[test]
    fn fargate_cpu_16384_boundaries() {
        assert!(valid_fargate_combo(16384, 32768));
        assert!(valid_fargate_combo(16384, 122880));
        assert!(!valid_fargate_combo(16384, 16384));
    }

    #[test]
    fn fargate_unknown_cpu() {
        assert!(!valid_fargate_combo(128, 512));
        assert!(!valid_fargate_combo(0, 0));
    }

    #[test]
    fn to_num_from_number() {
        assert_eq!(to_num(&serde_json::json!(256)), Some(256));
    }

    #[test]
    fn to_num_from_string() {
        assert_eq!(to_num(&serde_json::json!("1024")), Some(1024));
    }

    #[test]
    fn to_num_from_invalid_string() {
        assert_eq!(to_num(&serde_json::json!("abc")), None);
    }

    #[test]
    fn to_num_from_bool() {
        assert_eq!(to_num(&serde_json::json!(true)), None);
    }
}
