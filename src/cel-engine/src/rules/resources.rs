use super::{EvalContext, NativeRuleRegistry};
use diagnostics::{Diagnostic, RelatedResource, ResourceRef};
use rules::Category;
use template_model::SemanticModel;
use template_model::SourceSpan;
use template_model::consts::{
    FIELD_CREATION_POLICY, FIELD_RESOURCE_TYPE, FIELD_RESOURCES, FIELD_UPDATE_POLICY, KEY_CREATION_POLICY,
    KEY_UPDATE_POLICY,
};
use template_model::resolver::ResolvedValue;
use template_model::{quote, render_str_list, render_value};
use validation_engine::make_resource_diagnostic;

pub fn register(reg: &mut NativeRuleRegistry) {
    reg.add(Category::Resource, eval_resources);
    reg.add(Category::Resource, crate::rules::resources_extra::eval_extra_resources);
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

/// Whether the resource declares `property` at all, independent of the value it
/// resolves to.
fn has_property(m: &SemanticModel, rid: &str, property: &str) -> bool {
    m.resources.get(rid).is_some_and(|r| r.properties.contains_key(property))
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
            if let (Some(cpu_val), Some(mem_val)) = (cpu, mem)
                && !is_valid_fargate_task_size(&cpu_val, &mem_val)
            {
                out.push(make_resource_diagnostic(
                    "E3047",
                    &format!(
                        "Cpu {} is not compatible with Memory {} for Fargate",
                        render_value(&cpu_val),
                        render_value(&mem_val)
                    ),
                    m,
                    name,
                    "Properties.Cpu",
                    Some("Use a task size Fargate offers (e.g. Cpu 256 with Memory 512, 1024, or 2048)"),
                ));
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
            diag.related_resources.get_or_insert_with(Vec::new).push(RelatedResource {
                resource: Some(ResourceRef {
                    id: Some(a_name.clone()),
                    resource_type: m.resources.get(a_name.as_str()).map(|r| r.resource_type.clone()),
                }),
                location: Some(SourceSpan {
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

    out.extend(fargate_task_requirements(m));

    out
}

/// Log drivers a Fargate task can use.
const FARGATE_LOG_DRIVERS: &[&str] = &["awslogs", "splunk", "awsfirelens"];

/// The networking mode Fargate requires.
const FARGATE_NETWORK_MODE: &str = "awsvpc";

/// A Fargate task definition must declare awsvpc networking, a task-level Cpu
/// and Memory size drawn from the sizes Fargate offers, must not pin placement
/// (Fargate selects the infrastructure), and may only use the log drivers
/// Fargate supports.
fn fargate_task_requirements(m: &SemanticModel) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for name in m.resources_of_type("AWS::ECS::TaskDefinition") {
        let Some(serde_json::Value::Array(compatibilities)) =
            resolve_concrete(m, name, "Properties.RequiresCompatibilities")
        else {
            continue;
        };
        if !compatibilities.iter().any(|v| v.as_str() == Some("FARGATE")) {
            continue;
        }

        for property in ["NetworkMode", "Cpu", "Memory"] {
            if !has_property(m, name, property) {
                out.push(make_resource_diagnostic(
                    "E3048",
                    &format!("{} is a required property for a Fargate task", quote(property)),
                    m,
                    name,
                    "Properties",
                    None,
                ));
            }
        }

        if let Some(serde_json::Value::String(mode)) = resolve_concrete(m, name, "Properties.NetworkMode")
            && mode != FARGATE_NETWORK_MODE
        {
            out.push(make_resource_diagnostic(
                "E3048",
                &format!("{} is not one of {}", quote(&mode), render_str_list([FARGATE_NETWORK_MODE])),
                m,
                name,
                "Properties.NetworkMode",
                Some(&format!("Set NetworkMode to {}", quote(FARGATE_NETWORK_MODE))),
            ));
        }

        if let Some(cpu) = fargate_cpu_text(m, name) {
            out.extend(invalid_fargate_cpu(m, name, &cpu));
        }

        if has_property(m, name, "PlacementConstraints") {
            out.push(make_resource_diagnostic(
                "E3048",
                &format!("{} is not supported for a Fargate task", quote("PlacementConstraints")),
                m,
                name,
                "Properties.PlacementConstraints",
                Some("Remove PlacementConstraints; Fargate selects the infrastructure"),
            ));
        }

        out.extend(unsupported_fargate_log_drivers(m, name));
    }
    out
}

/// The declared `Cpu` as text, so the CPU-unit and vCPU forms can be told apart
/// whether the template wrote a number or a string. A value that is only known
/// at deploy time yields `None`.
fn fargate_cpu_text(m: &SemanticModel, name: &str) -> Option<String> {
    if is_dynamic(m, name, "Properties.Cpu") {
        return None;
    }
    match resolve_concrete(m, name, "Properties.Cpu")? {
        serde_json::Value::String(text) => Some(text),
        serde_json::Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn invalid_fargate_cpu(m: &SemanticModel, name: &str, cpu: &str) -> Vec<Diagnostic> {
    if let Some(units) = parse_unsigned_integer(cpu) {
        if FARGATE_TASK_SIZES.iter().any(|(offered, _)| *offered == units) {
            return Vec::new();
        }
        return vec![make_resource_diagnostic(
            "E3048",
            &format!("Cpu {} is not one of {}", quote(cpu), render_str_list(fargate_cpu_unit_sizes())),
            m,
            name,
            "Properties.Cpu",
            Some("Use a task-level Cpu size Fargate offers"),
        )];
    }
    if fargate_cpu_units(&serde_json::Value::String(cpu.to_string())).is_some() {
        return Vec::new();
    }
    vec![make_resource_diagnostic(
        "E3048",
        &format!("Cpu {} is not a vCPU size Fargate offers", quote(cpu)),
        m,
        name,
        "Properties.Cpu",
        Some("Use a vCPU size such as '.25 vCPU', '1 vCPU', or '16 vCPU'"),
    )]
}

/// The CPU-unit spelling of every task size Fargate offers, for listing in a
/// message.
fn fargate_cpu_unit_sizes() -> Vec<String> {
    FARGATE_TASK_SIZES.iter().map(|(units, _)| units.to_string()).collect()
}

fn unsupported_fargate_log_drivers(m: &SemanticModel, name: &str) -> Vec<Diagnostic> {
    let Some(serde_json::Value::Array(containers)) = resolve_concrete(m, name, "Properties.ContainerDefinitions")
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (index, container) in containers.iter().enumerate() {
        let Some(serde_json::Value::String(driver)) =
            container.get("LogConfiguration").and_then(|c| c.get("LogDriver"))
        else {
            continue;
        };
        if FARGATE_LOG_DRIVERS.contains(&driver.as_str()) {
            continue;
        }
        out.push(make_resource_diagnostic(
            "E3048",
            &format!("{} is not one of {}", quote(driver), render_str_list(FARGATE_LOG_DRIVERS)),
            m,
            name,
            &format!("Properties.ContainerDefinitions.{}.LogConfiguration.LogDriver", index),
            Some(&format!("Use a log driver Fargate supports: {}", render_str_list(FARGATE_LOG_DRIVERS))),
        ));
    }
    out
}

/// The task sizes Fargate offers, each pairing the CPU-unit value with the vCPU
/// spelling of the same size. A template may write either spelling.
const FARGATE_TASK_SIZES: &[(i64, &str)] =
    &[(256, ".25"), (512, ".5"), (1024, "1"), (2048, "2"), (4096, "4"), (8192, "8"), (16384, "16")];

/// Whether the declared task size is one Fargate offers. Cpu may be written in
/// CPU units or vCPU, and Memory in MiB or GB; a value in a form Fargate does
/// not accept at all is not a valid size either.
fn is_valid_fargate_task_size(cpu: &serde_json::Value, memory: &serde_json::Value) -> bool {
    match (fargate_cpu_units(cpu), fargate_memory_mib(memory)) {
        (Some(cpu_units), Some(memory_mib)) => valid_fargate_combo(cpu_units, memory_mib),
        _ => false,
    }
}

/// The declared Cpu in CPU units, accepting either the CPU-unit spelling
/// (`1024`, `"1024"`) or the vCPU spelling (`"1 vCPU"`), or `None` when the
/// value is in neither form.
fn fargate_cpu_units(cpu: &serde_json::Value) -> Option<i64> {
    let text = scalar_text(cpu)?;
    if let Some(units) = parse_unsigned_integer(&text) {
        return Some(units);
    }
    let size = text.to_ascii_lowercase().strip_suffix("vcpu")?.trim_end().to_string();
    FARGATE_TASK_SIZES.iter().find(|(_, vcpu)| *vcpu == size).map(|(units, _)| *units)
}

/// The declared Memory in MiB, accepting either the MiB spelling (`2048`,
/// `"2048"`) or the GB spelling (`"2GB"`, `"0.5 GB"`), or `None` when the value
/// is in neither form.
fn fargate_memory_mib(memory: &serde_json::Value) -> Option<i64> {
    const MIB_PER_GB: i64 = 1024;
    let text = scalar_text(memory)?;
    if let Some(mib) = parse_unsigned_integer(&text) {
        return Some(mib);
    }
    let size = text.to_ascii_lowercase().strip_suffix("gb")?.trim_end().to_string();
    if size == "0.5" {
        return Some(MIB_PER_GB / 2);
    }
    parse_unsigned_integer(&size).map(|gigabytes| gigabytes * MIB_PER_GB)
}

/// A scalar property value as the text the template author wrote, so numeric and
/// unit-suffixed spellings can be told apart.
fn scalar_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn parse_unsigned_integer(text: &str) -> Option<i64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// The Memory range each Cpu size supports, in MiB, and the step between the
/// sizes offered within that range.
fn valid_fargate_combo(cpu: i64, mem: i64) -> bool {
    let (range, step) = match cpu {
        256 => return [512, 1024, 2048].contains(&mem),
        512 => (1024..=4096, 1024),
        1024 => (2048..=8192, 1024),
        2048 => (4096..=16384, 1024),
        4096 => (8192..=30720, 1024),
        8192 => (16384..=61440, 4096),
        16384 => (32768..=122880, 8192),
        _ => return false,
    };
    range.contains(&mem) && mem % step == 0
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
    use serde_json::json;

    use super::*;

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
    fn fargate_memory_must_land_on_an_offered_step() {
        assert!(!valid_fargate_combo(512, 1500), "1500 MiB is between the 1 GB and 2 GB sizes offered");
        assert!(!valid_fargate_combo(8192, 20480 + 1024), "the 8 vCPU sizes step by 4 GB");
        assert!(valid_fargate_combo(8192, 20480));
        assert!(!valid_fargate_combo(16384, 32768 + 4096), "the 16 vCPU sizes step by 8 GB");
        assert!(valid_fargate_combo(16384, 40960));
    }

    #[test]
    fn cpu_accepts_both_spellings() {
        assert_eq!(fargate_cpu_units(&json!("1024")), Some(1024));
        assert_eq!(fargate_cpu_units(&json!(1024)), Some(1024));
        assert_eq!(fargate_cpu_units(&json!(".25 vCPU")), Some(256));
        assert_eq!(fargate_cpu_units(&json!("16vcpu")), Some(16384));
        assert_eq!(fargate_cpu_units(&json!("2 VCPU")), Some(2048));
    }

    #[test]
    fn cpu_rejects_sizes_fargate_does_not_offer() {
        assert_eq!(fargate_cpu_units(&json!("3 vCPU")), None);
        assert_eq!(fargate_cpu_units(&json!("abc")), None);
        assert_eq!(fargate_cpu_units(&json!("")), None);
    }

    #[test]
    fn memory_accepts_both_spellings() {
        assert_eq!(fargate_memory_mib(&json!("2048")), Some(2048));
        assert_eq!(fargate_memory_mib(&json!(2048)), Some(2048));
        assert_eq!(fargate_memory_mib(&json!("0.5GB")), Some(512));
        assert_eq!(fargate_memory_mib(&json!("2 GB")), Some(2048));
        assert_eq!(fargate_memory_mib(&json!("30gb")), Some(30720));
    }

    #[test]
    fn memory_rejects_forms_fargate_does_not_accept() {
        assert_eq!(fargate_memory_mib(&json!("2 TB")), None);
        assert_eq!(fargate_memory_mib(&json!("half a gb")), None);
    }

    #[test]
    fn task_size_pairs_the_two_spellings() {
        assert!(is_valid_fargate_task_size(&json!(".25 vCPU"), &json!("0.5GB")));
        assert!(is_valid_fargate_task_size(&json!("256"), &json!("0.5GB")));
        assert!(is_valid_fargate_task_size(&json!(".25 vCPU"), &json!(2048)));
        assert!(!is_valid_fargate_task_size(&json!(".25 vCPU"), &json!("3GB")));
        assert!(!is_valid_fargate_task_size(&json!("abc"), &json!("512")));
    }
}
