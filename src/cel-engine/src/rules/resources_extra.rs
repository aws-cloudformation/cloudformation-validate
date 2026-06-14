use super::EvalContext;
use diagnostics::Diagnostic;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, LazyLock};
use template_model::SemanticModel;
use template_model::consts::{
    DEFAULT_REGION, EDGE_KIND_GET_ATT, EDGE_KIND_REF, EDGE_KIND_SELECT, FIELD_ATTR, FIELD_KIND,
    FIELD_MAPPINGS, FIELD_OUTGOING_REFS, FIELD_PROPERTIES, FIELD_RESOURCE_TYPE, FIELD_RESOURCES,
    FIELD_SOURCE_PATH, FIELD_TARGET, FN_REF, KEY_PROPERTIES, TRANSFORM_SERVERLESS,
};
use template_model::resolver::ResolvedValue;
use validation_engine::make_resource_diagnostic;

static DOMAIN_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r"^(?:[a-z0-9\*](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$",
    )
    .expect("Invalid DOMAIN_RE pattern")
});

static RATE_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^rate\(\s*\d+(\.\d+)?\s+(minutes?|hours?|days?)\s*\)$")
        .expect("Invalid RATE_RE pattern")
});

static ARN_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^arn:(aws|aws-cn|aws-iso|aws-iso-[a-z]|aws-us-gov):iam::[0-9]{12}:role/.*$")
        .expect("Invalid ARN_RE pattern")
});

static SG_NAME_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"^[a-zA-Z0-9 \._\-:/()#,@\[\]+=&;\{\}!\$\*]+$"#)
        .expect("Invalid SG_NAME_RE pattern")
});

static AZ_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^[a-z]{2}-[a-z]+-\d[a-z]$").expect("Invalid AZ_RE pattern")
});

static W1030_AMI_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^ami-[0-9a-f]{8,17}$").expect("Invalid W1030_AMI_RE pattern")
});

static W1030_ARN_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^(arn:(aws[A-Za-z\-]*?|\*):[^:]+:[^:]*(:(\d{12}|\*|aws)?:.+|)|\*)$")
        .expect("Invalid W1030_ARN_RE pattern")
});

static W1030_VPC_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^vpc-(([0-9A-Fa-f]{8})|([0-9A-Fa-f]{17}))$")
        .expect("Invalid W1030_VPC_RE pattern")
});

fn resolve_all_json(m: &SemanticModel, rid: &str, path: &str) -> Vec<serde_json::Value> {
    let rv = m
        .resolve_deep(rid, path)
        .or_else(|| m.resolve(rid, path).cloned());
    let Some(rv) = rv else { return vec![] };
    collect_concrete_values(&rv)
}

fn collect_concrete_values(rv: &ResolvedValue) -> Vec<serde_json::Value> {
    match rv {
        ResolvedValue::Concrete { value: v } => vec![v.0.clone()],
        ResolvedValue::List { items } => {
            vec![serde_json::Value::Array(
                items.iter().map(resolved_to_json_best_effort).collect(),
            )]
        }
        ResolvedValue::Conditional {
            if_true, if_false, ..
        } => {
            let mut vals = collect_concrete_values(if_true);
            vals.extend(collect_concrete_values(if_false));
            vals
        }
        _ => {
            let v = resolved_to_json_best_effort(rv);
            if v.is_null() { vec![] } else { vec![v] }
        }
    }
}

fn resolve_concrete(m: &SemanticModel, rid: &str, path: &str) -> Option<serde_json::Value> {
    if let Some(resolved) = m
        .resolve_deep(rid, path)
        .or_else(|| m.resolve(rid, path).cloned())
    {
        return match resolved {
            ResolvedValue::Concrete { value: v } => Some(v.into_inner()),
            _ => None,
        };
    }
    // `Properties` wrapped in `Fn::If` stores values only under the synthetic
    // branch path — fall back to scenario resolution so rules that look up
    // properties by name still see per-branch values.
    let scenarios = m.resolve_scenarios_json(rid, path);
    scenarios.into_iter().next().map(|(v, _)| v)
}

fn is_valid_cidr_strict(s: &str) -> bool {
    s.parse::<ipnetwork::IpNetwork>()
        .map(|net| match net {
            ipnetwork::IpNetwork::V4(n) => {
                let ip: u32 = n.ip().into();
                let mask = !0u32 << (32 - n.prefix()) as u32;
                ip & !mask == 0
            }
            ipnetwork::IpNetwork::V6(_) => true,
        })
        .unwrap_or(false)
}

pub fn eval_extra_resources(ctx: &EvalContext) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let m = ctx.model;
    let input = ctx.input;

    if !ctx.cached_data.known_types.is_empty() {
        for (name, res) in &m.resources {
            if res.resource_type.is_empty() {
                continue;
            }
            if !ctx.cached_data.known_types.contains(&res.resource_type)
                && !res.resource_type.starts_with("Custom::")
                && !res.resource_type.ends_with("::MODULE")
                && !res.resource_type.starts_with("AWS::CloudFormation::")
            {
                out.push(make_resource_diagnostic(
                    "E9001",
                    &format!("Unknown resource type '{}'", res.resource_type),
                    m,
                    name,
                    "",
                    None,
                ));
            }
        }
    }

    for name in m.resources_of_type("AWS::ECS::TaskDefinition") {
        if let Some(serde_json::Value::Array(cdefs)) =
            resolve_concrete(m, name, "Properties.ContainerDefinitions")
            && cdefs.len() > 1
                && cdefs
                    .iter()
                    .all(|c| c.get("Essential").and_then(|e| e.as_bool()) == Some(false))
            {
                out.push(make_resource_diagnostic(
                    "E3042",
                    "At least one container definition must have Essential set to true",
                    m,
                    name,
                    "",
                    None,
                ));
            }
    }

    for name in m.resources_of_type("AWS::IAM::Policy") {
        if let Some(doc) = resolve_concrete(m, name, "Properties.PolicyDocument") {
            check_iam_statements(&mut out, m, name, &doc, "Properties.PolicyDocument");
        }
    }
    for name in m.resources_of_type("AWS::IAM::Role") {
        if let Some(serde_json::Value::Array(policies)) =
            resolve_concrete(m, name, "Properties.Policies")
        {
            for (idx, pol) in policies.iter().enumerate() {
                if let Some(doc) = pol.get("PolicyDocument") {
                    check_iam_statements(
                        &mut out,
                        m,
                        name,
                        doc,
                        &format!("Properties.Policies[{}].PolicyDocument", idx),
                    );
                }
            }
        }
    }

    for name in m.resources_of_type("AWS::ECS::Service") {
        if resolve_concrete(m, name, "Properties.LaunchType")
            .as_ref()
            .and_then(|v| v.as_str())
            == Some("FARGATE")
            && resolve_concrete(m, name, "Properties.SchedulingStrategy")
                .as_ref()
                .and_then(|v| v.as_str())
                == Some("DAEMON")
            {
                out.push(make_resource_diagnostic(
                    "E3044",
                    "Fargate launch type does not support DAEMON scheduling strategy",
                    m,
                    name,
                    "Properties.SchedulingStrategy",
                    Some("Use REPLICA scheduling strategy with Fargate"),
                ));
            }
    }

    if let Some(resources) = input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
        for (name, res) in resources {
            if let Some(rules) = res
                .get(FIELD_PROPERTIES)
                .and_then(|p| p.get("SecurityGroupIngress"))
                .and_then(|s| s.as_array())
            {
                for rule in rules {
                    let from = rule.get("FromPort").and_then(|p| p.as_i64());
                    let to = rule.get("ToPort").and_then(|p| p.as_i64());
                    if let (Some(f), Some(t)) = (from, to)
                        && f > t {
                            out.push(make_resource_diagnostic(
                                "E9002",
                                &format!("FromPort {} is greater than ToPort {}", f, t),
                                m,
                                name,
                                "Properties.SecurityGroupIngress",
                                Some("Set FromPort to a value less than or equal to ToPort"),
                            ));
                        }
                }
            }
        }
    }

    {
        let port_relevant_protocols: HashSet<&str> =
            ["1", "icmp", "6", "tcp", "17", "udp", "TCP", "UDP", "ICMP"]
                .into_iter()
                .collect();
        let port_relevant_numbers: HashSet<i64> = [1, 6, 17].into_iter().collect();

        let protocol_requires_ports = |proto: Option<&serde_json::Value>| -> bool {
            match proto {
                Some(serde_json::Value::String(s)) => port_relevant_protocols.contains(s.as_str()),
                Some(serde_json::Value::Number(n)) => n
                    .as_i64()
                    .map(|n| port_relevant_numbers.contains(&n))
                    .unwrap_or(false),
                _ => false,
            }
        };
        let protocol_ignores_ports = |proto: Option<&serde_json::Value>| -> bool {
            match proto {
                Some(serde_json::Value::String(s)) => !port_relevant_protocols.contains(s.as_str()),
                Some(serde_json::Value::Number(n)) => n
                    .as_i64()
                    .map(|n| !port_relevant_numbers.contains(&n))
                    .unwrap_or(false),
                _ => false,
            }
        };

        // Inline SecurityGroup ingress/egress rules — access raw properties
        // to handle arrays containing dynamic Refs that resolve_concrete skips
        for name in m.resources_of_type("AWS::EC2::SecurityGroup") {
            let Some(res) = m.resources.get(name.as_str()) else {
                continue;
            };
            for direction in &["SecurityGroupIngress", "SecurityGroupEgress"] {
                let Some(rv) = res.properties.get(*direction) else {
                    continue;
                };
                let items: Vec<serde_json::Value> = match rv {
                    ResolvedValue::Concrete { value: v } => match v.as_array() {
                        Some(a) => a.clone(),
                        None => continue,
                    },
                    ResolvedValue::List { items } => {
                        items.iter().map(resolved_to_json_best_effort).collect()
                    }
                    _ => continue,
                };
                for (idx, rule) in items.iter().enumerate() {
                    let proto = rule.get("IpProtocol");
                    let has_port = rule.get("FromPort").is_some() || rule.get("ToPort").is_some();
                    let val = proto.map(|p| p.to_string()).unwrap_or_default();
                    let val_display = val.trim_matches('"');
                    if protocol_requires_ports(proto) && !has_port {
                        out.push(make_resource_diagnostic(
                            "E3687",
                            &format!("['FromPort', 'ToPort'] are required properties when using 'IpProtocol' value {}", val_display),
                            m, name,
                            &format!("Properties.{}.{}", direction, idx),
                            None,
                        ));
                    }
                    if protocol_ignores_ports(proto) && has_port {
                        out.push(make_resource_diagnostic(
                            "W3687",
                            &format!("['FromPort', 'ToPort'] are ignored when using 'IpProtocol' value '{}'", val_display),
                            m, name,
                            &format!("Properties.{}.{}.FromPort", direction, idx),
                            None,
                        ));
                    }
                }
            }
        }

        // Standalone SecurityGroupIngress/SecurityGroupEgress resources
        for rtype in &[
            "AWS::EC2::SecurityGroupIngress",
            "AWS::EC2::SecurityGroupEgress",
        ] {
            for name in m.resources_of_type(rtype) {
                let proto = resolve_concrete(m, name, "Properties.IpProtocol");
                let has_port = resolve_concrete(m, name, "Properties.FromPort").is_some()
                    || resolve_concrete(m, name, "Properties.ToPort").is_some();
                let val = proto.as_ref().map(|p| p.to_string()).unwrap_or_default();
                let val_display = val.trim_matches('"');
                if protocol_requires_ports(proto.as_ref()) && !has_port {
                    out.push(make_resource_diagnostic(
                        "E3687",
                        &format!("['FromPort', 'ToPort'] are required properties when using 'IpProtocol' value {}", val_display),
                        m, name, KEY_PROPERTIES, None,
                    ));
                }
                if protocol_ignores_ports(proto.as_ref()) && has_port {
                    out.push(make_resource_diagnostic(
                        "W3687",
                        &format!(
                            "['FromPort', 'ToPort'] are ignored when using 'IpProtocol' value '{}'",
                            val_display
                        ),
                        m,
                        name,
                        "Properties.FromPort",
                        None,
                    ));
                }
            }
        }
    }

    for name in m.resources_of_type("AWS::ECS::TaskDefinition") {
        if resolve_concrete(m, name, "Properties.NetworkMode")
            .as_ref()
            .and_then(|v| v.as_str())
            == Some("awsvpc")
            && let Some(serde_json::Value::Array(cdefs)) =
                resolve_concrete(m, name, "Properties.ContainerDefinitions")
            {
                for (ci, cdef) in cdefs.iter().enumerate() {
                    if let Some(pms) = cdef.get("PortMappings").and_then(|p| p.as_array()) {
                        for (pi, pm) in pms.iter().enumerate() {
                            let hp = pm.get("HostPort").and_then(|p| p.as_i64());
                            let cp = pm.get("ContainerPort").and_then(|p| p.as_i64());
                            if let (Some(h), Some(c)) = (hp, cp)
                                && h != c {
                                    out.push(make_resource_diagnostic("E3053", &format!("HostPort {} must equal ContainerPort {} when NetworkMode is awsvpc", h, c), m, name, &format!("Properties.ContainerDefinitions[{}].PortMappings[{}].HostPort", ci, pi), Some("Set HostPort equal to ContainerPort or remove HostPort")));
                                }
                        }
                    }
                }
            }
    }

    for name in m.resources_of_type("AWS::DynamoDB::Table") {
        if let (Some(serde_json::Value::Array(ks)), Some(serde_json::Value::Array(ad))) = (
            resolve_concrete(m, name, "Properties.KeySchema"),
            resolve_concrete(m, name, "Properties.AttributeDefinitions"),
        ) {
            let defined: HashSet<&str> = ad
                .iter()
                .filter_map(|a| a.get("AttributeName").and_then(|n| n.as_str()))
                .collect();
            for k in &ks {
                if let Some(attr) = k.get("AttributeName").and_then(|n| n.as_str())
                    && !defined.contains(attr) {
                        out.push(make_resource_diagnostic(
                            "E3039",
                            &format!(
                                "KeySchema attribute '{}' is not defined in AttributeDefinitions",
                                attr
                            ),
                            m,
                            name,
                            "Properties.KeySchema",
                            Some("Add the attribute to AttributeDefinitions"),
                        ));
                    }
            }
        }
    }

    for name in m.resources_of_type("AWS::CloudFront::Distribution") {
        if let Some(dist) = resolve_concrete(m, name, "Properties.DistributionConfig") {
            let origin_ids: HashSet<&str> = dist
                .get("Origins")
                .and_then(|o| o.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|o| o.get("Id").and_then(|i| i.as_str()))
                        .collect()
                })
                .unwrap_or_default();
            if let Some(target) = dist
                .get("DefaultCacheBehavior")
                .and_then(|d| d.get("TargetOriginId"))
                .and_then(|t| t.as_str())
                && !origin_ids.contains(target) {
                    out.push(make_resource_diagnostic(
                        "E3057",
                        &format!(
                            "TargetOriginId '{}' does not match any Origin Id in the distribution",
                            target
                        ),
                        m,
                        name,
                        "Properties.DistributionConfig.DefaultCacheBehavior.TargetOriginId",
                        Some(
                            "Set TargetOriginId to match one of the Origin Ids defined in Origins",
                        ),
                    ));
                }
        }
    }

    for name in m.resources_of_type("AWS::IAM::Policy") {
        if let Some(doc) = resolve_concrete(m, name, "Properties.PolicyDocument")
            && doc.is_object() && doc.get("Statement").is_none() {
                out.push(make_resource_diagnostic(
                    "E3510",
                    "IAM identity policy must have a Statement property",
                    m,
                    name,
                    "Properties.PolicyDocument",
                    Some("Add a Statement array to the PolicyDocument"),
                ));
            }
    }

    let resource_policy_types = [
        ("AWS::KMS::Key", "Properties.KeyPolicy"),
        ("AWS::S3::BucketPolicy", "Properties.PolicyDocument"),
        ("AWS::SNS::TopicPolicy", "Properties.PolicyDocument"),
        ("AWS::SQS::QueuePolicy", "Properties.PolicyDocument"),
    ];
    for (rtype, path) in &resource_policy_types {
        for name in m.resources_of_type(rtype) {
            if let Some(doc) = resolve_concrete(m, name, path)
                && doc.is_object() && doc.get("Statement").is_none() {
                    out.push(make_resource_diagnostic(
                        "E3512",
                        "Resource-based policy must have a Statement property",
                        m,
                        name,
                        path,
                        Some("Add a Statement array to the policy document"),
                    ));
                }
        }
    }

    for name in m.resources_of_type("AWS::IAM::Role") {
        if let Some(doc) = resolve_concrete(m, name, "Properties.AssumeRolePolicyDocument") {
            if doc.is_object() && doc.get("Statement").is_none() {
                out.push(make_resource_diagnostic(
                    "E3530",
                    "'Statement' is a required property",
                    m,
                    name,
                    "Properties.AssumeRolePolicyDocument",
                    Some("Add a Statement array to the AssumeRolePolicyDocument"),
                ));
            }
            if let Some(stmts) = doc.get("Statement").and_then(|s| s.as_array()) {
                for (idx, stmt) in stmts.iter().enumerate() {
                    if !stmt.is_object() {
                        continue;
                    }
                    let path = format!("Properties.AssumeRolePolicyDocument.Statement.{}", idx);
                    if stmt.get("Effect").is_none() {
                        out.push(make_resource_diagnostic(
                            "E3530",
                            "'Effect' is a required property in trust policy statement",
                            m,
                            name,
                            &path,
                            Some("Add Effect (Allow or Deny) to the statement"),
                        ));
                    }
                    if stmt.get("Principal").is_none() {
                        out.push(make_resource_diagnostic(
                            "E3530",
                            "'Principal' is a required property in trust policy statement",
                            m,
                            name,
                            &path,
                            Some("Add Principal to the statement"),
                        ));
                    }
                    if stmt.get("Action").is_none() && stmt.get("NotAction").is_none() {
                        out.push(make_resource_diagnostic(
                            "E3530",
                            "'Action' or 'NotAction' is a required property in trust policy statement",
                            m,
                            name,
                            &path,
                            Some("Add Action or NotAction to the statement"),
                        ));
                    }
                }
            }
        }
    }

    for name in m.resources_of_type("AWS::ECR::Repository") {
        if let Some(doc) = resolve_concrete(m, name, "Properties.RepositoryPolicyText")
            && doc.is_object() && doc.get("Statement").is_none() {
                out.push(make_resource_diagnostic(
                    "E3513",
                    "ECR repository policy must have a Statement property",
                    m,
                    name,
                    "Properties.RepositoryPolicyText",
                    Some("Add a Statement array to the RepositoryPolicyText"),
                ));
            }
    }

    let policy_doc_types: &[(&str, &str)] = &[
        ("AWS::S3::BucketPolicy", "Properties.PolicyDocument.Version"),
        ("AWS::SNS::TopicPolicy", "Properties.PolicyDocument.Version"),
        ("AWS::SQS::QueuePolicy", "Properties.PolicyDocument.Version"),
        ("AWS::KMS::Key", "Properties.KeyPolicy.Version"),
        (
            "AWS::IAM::Role",
            "Properties.AssumeRolePolicyDocument.Version",
        ),
        ("AWS::IAM::Policy", "Properties.PolicyDocument.Version"),
        (
            "AWS::IAM::ManagedPolicy",
            "Properties.PolicyDocument.Version",
        ),
    ];
    for (rtype, path) in policy_doc_types {
        for name in m.resources_of_type(rtype) {
            let scenarios = m.resolve_scenarios_json(name, path);
            for (val, _conds) in &scenarios {
                if let Some(ver) = val.as_str()
                    && ver != "2012-10-17" {
                        out.push(make_resource_diagnostic(
                            "W2511",
                            &format!(
                                "IAM policy document Version should be '2012-10-17', got '{}'",
                                ver
                            ),
                            m,
                            name,
                            path,
                            Some("Update the policy document Version to '2012-10-17'"),
                        ));
                        break;
                    }
            }
        }
    }

    for name in m.resources_of_type("AWS::CodeBuild::Project") {
        if resolve_concrete(m, name, "Properties.Source.Type")
            .as_ref()
            .and_then(|v| v.as_str())
            == Some("S3")
            && let Some(serde_json::Value::String(loc)) =
                resolve_concrete(m, name, "Properties.Source.Location")
                && !loc.contains('/') {
                    out.push(make_resource_diagnostic(
                        "E3636",
                        &format!(
                            "CodeBuild S3 source location '{}' must be in 'bucket/key' format",
                            loc
                        ),
                        m,
                        name,
                        "Properties.Source.Location",
                        Some("Use format: my-bucket/path/to/source.zip"),
                    ));
                }
    }

    for name in m.resources_of_type("AWS::CodePipeline::Pipeline") {
        if let Some(serde_json::Value::Array(stages)) =
            resolve_concrete(m, name, "Properties.Stages")
            && let Some(first) = stages.first() {
                let has_source = first
                    .get("Actions")
                    .and_then(|a| a.as_array())
                    .map(|actions| {
                        actions.iter().any(|a| {
                            a.get("ActionTypeId")
                                .and_then(|at| at.get("Category"))
                                .and_then(|c| c.as_str())
                                == Some("Source")
                        })
                    })
                    .unwrap_or(false);
                if !has_source {
                    out.push(make_resource_diagnostic(
                        "E3700",
                        "First stage of a pipeline must contain at least one Source action",
                        m,
                        name,
                        "Properties.Stages[0]",
                        Some("Add an action with ActionTypeId.Category=Source to the first stage"),
                    ));
                }
            }
    }

    for name in m.resources_of_type("AWS::Lambda::Function") {
        if let Some(serde_json::Value::Object(code)) = resolve_concrete(m, name, "Properties.Code")
            && code.contains_key("ZipFile")
                && let Some(serde_json::Value::String(rt)) =
                    resolve_concrete(m, name, "Properties.Runtime")
                    && !rt.starts_with("nodejs") && !rt.starts_with("python") {
                        out.push(make_resource_diagnostic(
                            "E3071",
                            &format!(
                                "Runtime '{}' is not supported with Code.ZipFile — use nodejs or python",
                                rt
                            ),
                            m,
                            name,
                            "",
                            None,
                        ));
                    }
    }

    for name in m.resources_of_type("AWS::SQS::Queue") {
        if let Some(serde_json::Value::Bool(true)) =
            resolve_concrete(m, name, "Properties.FifoQueue")
            && let Some(serde_json::Value::String(qname)) =
                resolve_concrete(m, name, "Properties.QueueName")
                && !qname.ends_with(".fifo") {
                    out.push(make_resource_diagnostic(
                        "E3501",
                        &format!("FIFO queue name '{}' must end with '.fifo'", qname),
                        m,
                        name,
                        "Properties.QueueName",
                        Some("Append .fifo to the queue name"),
                    ));
                }
    }

    if let Some(resources) = input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
        for name in m.resources_of_type("AWS::SQS::Queue") {
            let is_fifo = resolve_concrete(m, name, "Properties.FifoQueue")
                .as_ref()
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if let Some(edges) = resources
                .get(name.as_str())
                .and_then(|r| r.get(FIELD_OUTGOING_REFS))
                .and_then(|r| r.as_array())
            {
                for edge in edges {
                    let sp = edge
                        .get(FIELD_SOURCE_PATH)
                        .and_then(|p| p.as_str())
                        .unwrap_or("");
                    if !sp.contains("RedrivePolicy.deadLetterTargetArn") {
                        continue;
                    }
                    let target = match edge.get(FIELD_TARGET).and_then(|t| t.as_str()) {
                        Some(t) => t,
                        None => continue,
                    };
                    let dlq_res = match m.resources.get(target) {
                        Some(r) => r,
                        None => continue,
                    };
                    if dlq_res.resource_type != "AWS::SQS::Queue" {
                        continue;
                    }
                    let dlq_fifo = resolve_concrete(m, target, "Properties.FifoQueue")
                        .as_ref()
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if is_fifo != dlq_fifo {
                        let src_type = if is_fifo { "FIFO" } else { "standard" };
                        let dlq_type = if dlq_fifo { "FIFO" } else { "standard" };
                        out.push(make_resource_diagnostic(
                            "E3502",
                            &format!(
                                "Source queue type '{}' does not match destination queue type '{}'",
                                src_type, dlq_type
                            ),
                            m,
                            name,
                            "Properties.RedrivePolicy",
                            None,
                        ));
                    }
                }
            }
        }
    }

    let srta = m.resources_of_type("AWS::EC2::SubnetRouteTableAssociation");
    for (i, a) in srta.iter().enumerate() {
        for b in srta.iter().skip(i + 1) {
            let a_sub = resolve_concrete(m, a, "Properties.SubnetId");
            let b_sub = resolve_concrete(m, b, "Properties.SubnetId");
            if a_sub.is_some() && a_sub == b_sub
                && !crate::functions::contains_unresolvable_content(
                    &m.resolve_deep(a, "Properties.SubnetId")
                        .or_else(|| m.resolve(a, "Properties.SubnetId").cloned())
                        .unwrap_or(ResolvedValue::Dynamic { reason: "".into() }),
                ) {
                    out.push(make_resource_diagnostic(
                        "E3022",
                        "Subnet has multiple SubnetRouteTableAssociations — only one is allowed",
                        m,
                        a,
                        "Properties.SubnetId",
                        None,
                    ));
                }
        }
    }

    let creation_policy_types = [
        "AWS::AutoScaling::AutoScalingGroup",
        "AWS::EC2::Instance",
        "AWS::CloudFormation::WaitCondition",
        "AWS::AppStream::Fleet",
    ];
    if let Some(resources) = input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
        for (name, res) in resources {
            if res
                .get("creation_policy")
                .map(|v| !v.is_null())
                .unwrap_or(false)
            {
                let rtype = res
                    .get(FIELD_RESOURCE_TYPE)
                    .and_then(|t| t.as_str())
                    .unwrap_or("");
                if !creation_policy_types.contains(&rtype) {
                    out.push(make_resource_diagnostic(
                        "E3055",
                        &format!("CreationPolicy is not valid on resource type '{}'", rtype),
                        m,
                        name,
                        "",
                        None,
                    ));
                }
            }
        }
    }

    for name in m.resources_of_type("AWS::S3::Bucket") {
        if m.resources
            .get(name.as_str())
            .map(|r| r.properties.contains_key("AccessControl"))
            .unwrap_or(false)
        {
            out.push(make_resource_diagnostic(
                "W3045",
                "AccessControl property is deprecated. Use bucket policies instead",
                m,
                name,
                "Properties.AccessControl",
                Some("Remove AccessControl and use an AWS::S3::BucketPolicy resource"),
            ));
        }
    }

    for name in m.resources_of_type("AWS::S3::Bucket") {
        if let Some(res) = m.resources.get(name.as_str())
            && res.properties.contains_key("AccessControl")
                && !res.properties.contains_key("OwnershipControls")
                && let Some(serde_json::Value::String(ac)) =
                    resolve_concrete(m, name, "Properties.AccessControl")
                    && ac != "Private" {
                        out.push(make_resource_diagnostic("E3045",
                            "A bucket with 'AccessControl' set should also have at least one 'OwnershipControl' configured",
                            m, name, KEY_PROPERTIES,
                            Some("Add OwnershipControls to the bucket when using AccessControl")));
                    }
    }

    for name in m.resources_of_type("AWS::Lambda::Permission") {
        if resolve_concrete(m, name, "Properties.Principal")
            .as_ref()
            .and_then(|v| v.as_str())
            == Some("s3.amazonaws.com")
            && !m
                .resources
                .get(name.as_str())
                .map(|r| r.properties.contains_key("SourceAccount"))
                .unwrap_or(false)
            {
                out.push(make_resource_diagnostic("W3663", "Lambda Permission with S3 principal should have SourceAccount to prevent confused deputy", m, name, "Properties.Principal", Some("Add SourceAccount property")));
            }
    }

    let sub_filters = m.resources_of_type("AWS::Logs::SubscriptionFilter");
    let mut lg_counts: HashMap<String, Vec<&str>> = HashMap::new();
    for name in sub_filters {
        if let Some(serde_json::Value::String(lg)) =
            resolve_concrete(m, name, "Properties.LogGroupName")
        {
            lg_counts.entry(lg).or_default().push(name);
        } else if let Some(ref_target) = m.follow_ref(name, "Properties.LogGroupName") {
            let key = format!("__ref:{}", ref_target);
            lg_counts.entry(key).or_default().push(name);
        }
    }
    for (lg, names) in &lg_counts {
        if names.len() > 2 {
            let display = lg.strip_prefix("__ref:").unwrap_or(lg);
            out.push(make_resource_diagnostic(
                "E2529",
                &format!(
                    "Log group '{}' has {} subscription filters, maximum is 2",
                    display,
                    names.len()
                ),
                m,
                names[0],
                "",
                None,
            ));
        }
    }

    let snapstart_runtimes = ["java11", "java17", "java21"];
    for name in m.resources_of_type("AWS::Lambda::Function") {
        if let Some(snap) = resolve_concrete(m, name, "Properties.SnapStart")
            && snap.get("ApplyOn").and_then(|a| a.as_str()) == Some("PublishedVersions")
                && let Some(serde_json::Value::String(rt)) =
                    resolve_concrete(m, name, "Properties.Runtime")
                    && !snapstart_runtimes.contains(&rt.as_str()) {
                        out.push(make_resource_diagnostic(
                            "E2530",
                            &format!("SnapStart is not supported with runtime '{}'", rt),
                            m,
                            name,
                            "Properties.SnapStart",
                            Some("Use a supported Java runtime: java11, java17, java21, or java25"),
                        ));
                    }
    }

    for name in m.resources_of_type("AWS::CloudFront::Distribution") {
        if let Some(serde_json::Value::Array(aliases)) =
            resolve_concrete(m, name, "Properties.DistributionConfig.Aliases")
        {
            for (i, alias) in aliases.iter().enumerate() {
                if let Some(s) = alias.as_str() {
                    let path = format!("Properties.DistributionConfig.Aliases.{}", i);
                    // Wildcard must only appear as the leftmost label (e.g. *.example.com).
                    // `email.*.example.com` or any `.*.` in the middle is invalid.
                    if s.contains(".*.") {
                        out.push(make_resource_diagnostic(
                            "E3013",
                            &format!("CloudFront alias '{}' has wildcard in invalid position", s),
                            m,
                            name,
                            &path,
                            None,
                        ));
                    } else if !DOMAIN_RE.is_match(s) {
                        out.push(make_resource_diagnostic(
                            "E3013",
                            &format!("CloudFront alias '{}' is not a valid domain name", s),
                            m,
                            name,
                            &path,
                            None,
                        ));
                    }
                }
            }
        }
    }

    for name in m.resources_of_type("AWS::CodeBuild::Project") {
        if let Some(target) = m.follow_ref(name, "Properties.ServiceRole")
            && let Some(target_res) = m.resources.get(target)
                && target_res.resource_type == "AWS::IAM::Role"
                    && let Some(serde_json::Value::String(path)) =
                        resolve_concrete(m, target, "Properties.Path")
                        && path != "/" {
                            out.push(make_resource_diagnostic("E3050", &format!("Ref to IAM role '{}' with Path '{}' — use GetAtt {}.Arn instead", target, path, target), m, name, "Properties.ServiceRole", Some("Switch from Ref to !GetAtt <Role>.Arn when Path is not '/'")));
                        }
    }

    for (name, res) in &m.resources {
        if res.properties.len() > 50 {
            out.push(make_resource_diagnostic(
                "E3010",
                &format!(
                    "Resource has {} properties, maximum is 50",
                    res.properties.len()
                ),
                m,
                name,
                "",
                None,
            ));
        }
    }

    for (name, res) in &m.resources {
        for prop in res.properties.keys() {
            let path = format!("Properties.{}", prop);
            let Some(rv) = m
                .resolve_deep(name, &path)
                .or_else(|| m.resolve(name, &path).cloned())
            else {
                continue;
            };
            // Extract array items whether the value came back as fully-Concrete JSON or
            // as a `ResolvedValue::List` tree (which happens when list items contain
            // intrinsics like Ref). Conditional branches in the list are flattened to
            // their concrete representative (first concrete) via best-effort conversion.
            let items: Vec<serde_json::Value> = match &rv {
                ResolvedValue::Concrete { value: v } => match v.as_array() {
                    Some(a) => a.clone(),
                    None => continue,
                },
                ResolvedValue::List { items } => {
                    items.iter().map(resolved_to_json_best_effort).collect()
                }
                _ => match resolved_to_json_best_effort(&rv) {
                    serde_json::Value::Array(a) => a,
                    _ => continue,
                },
            };
            let mut seen = HashSet::new();
            for item in &items {
                if item.is_null() {
                    continue;
                }
                let key = item.to_string();
                if !seen.insert(key) {
                    out.push(make_resource_diagnostic(
                        "I3037",
                        &format!(
                            "Array property '{}' contains duplicate value: {}",
                            prop, item
                        ),
                        m,
                        name,
                        &path,
                        None,
                    ));
                    break;
                }
            }
        }
    }

    static PREV_GEN_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(^|\.)([cmr][1-3]|cc2|cg1|cr1|g2|hi1|hs1|i2|t1)(\.|$)")
            .expect("Invalid PREV_GEN_RE")
    });
    let instance_type_checks: &[(&str, &str)] = &[
        (
            "AWS::AutoScaling::LaunchConfiguration",
            "Properties.InstanceType",
        ),
        ("AWS::EC2::Instance", "Properties.InstanceType"),
        ("AWS::EC2::Host", "Properties.InstanceType"),
        ("AWS::EC2::CapacityReservation", "Properties.InstanceType"),
        ("AWS::RDS::DBInstance", "Properties.DBInstanceClass"),
        ("AWS::ElastiCache::CacheCluster", "Properties.CacheNodeType"),
        (
            "AWS::ElastiCache::ReplicationGroup",
            "Properties.CacheNodeType",
        ),
        (
            "AWS::EC2::LaunchTemplate",
            "Properties.LaunchTemplateData.InstanceType",
        ),
        (
            "AWS::OpenSearchService::Domain",
            "Properties.ClusterConfig.InstanceType",
        ),
        (
            "AWS::Elasticsearch::Domain",
            "Properties.ElasticsearchClusterConfig.InstanceType",
        ),
    ];
    for (rtype, prop_path) in instance_type_checks {
        for name in m.resources_of_type(rtype) {
            if let Some(serde_json::Value::String(val)) = resolve_concrete(m, name, prop_path)
                && PREV_GEN_RE.is_match(&val) {
                    out.push(make_resource_diagnostic(
                        "I3100",
                        &format!(
                            "Previous generation instance type '{}' — consider upgrading",
                            val
                        ),
                        m,
                        name,
                        prop_path,
                        Some("Upgrade to a current generation instance type"),
                    ));
                }
        }
    }

    for name in m.resources_of_type("AWS::ECS::Service") {
        if let Some(target) = m.follow_ref(name, "Properties.TaskDefinition")
            && let Some(_td) = m.resources.get(target)
                && resolve_concrete(m, target, "Properties.NetworkMode")
                    .as_ref()
                    .and_then(|v| v.as_str())
                    == Some("awsvpc")
                    && !m
                        .resources
                        .get(name.as_str())
                        .map(|r| r.properties.contains_key("NetworkConfiguration"))
                        .unwrap_or(false)
                    {
                        out.push(make_resource_diagnostic("E3052", "NetworkConfiguration required when TaskDefinition NetworkMode is 'awsvpc'", m, name, "", None));
                    }
    }

    // Fires both when the TaskDefinition omits RequiresCompatibilities entirely and
    // when it's present but missing the FARGATE value.
    for name in m.resources_of_type("AWS::ECS::Service") {
        if resolve_concrete(m, name, "Properties.LaunchType")
            .as_ref()
            .and_then(|v| v.as_str())
            != Some("FARGATE")
        {
            continue;
        }
        let Some(target) = m.follow_ref(name, "Properties.TaskDefinition") else {
            continue;
        };
        let compat_rv = m
            .resolve_deep(target, "Properties.RequiresCompatibilities")
            .or_else(|| {
                m.resolve(target, "Properties.RequiresCompatibilities")
                    .cloned()
            });
        let compat_strings: Vec<&str> = match compat_rv.as_ref() {
            Some(ResolvedValue::Concrete { value: v }) => v
                .as_array()
                .map(|arr| arr.iter().filter_map(|x| x.as_str()).collect())
                .unwrap_or_default(),
            Some(ResolvedValue::List { items }) => items
                .iter()
                .filter_map(|it| match it {
                    ResolvedValue::Concrete { value: v } => v.as_str(),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        if compat_strings.contains(&"FARGATE") {
            continue;
        }
        let rendered = if compat_strings.is_empty() {
            "[\"\"]".to_string()
        } else {
            format!(
                "[{}]",
                compat_strings
                    .iter()
                    .map(|s| format!("\"{}\"", s))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        out.push(make_resource_diagnostic(
            "E3054",
            &format!("{} does not contain items matching 'FARGATE'", rendered),
            m,
            target,
            "Properties.RequiresCompatibilities",
            Some("Add 'FARGATE' to RequiresCompatibilities"),
        ));
    }

    for name in m.resources_of_type("AWS::CodePipeline::Pipeline") {
        if let Some(serde_json::Value::Array(stages)) =
            resolve_concrete(m, name, "Properties.Stages")
        {
            let mut seen_outputs = HashSet::new();
            for (si, stage) in stages.iter().enumerate() {
                let stage_name = stage
                    .get("Name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown");
                if let Some(actions) = stage.get("Actions").and_then(|a| a.as_array()) {
                    for action in actions {
                        let aname = action
                            .get("Name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("unknown");
                        if let Some(outs) = action.get("OutputArtifacts").and_then(|o| o.as_array())
                        {
                            for o in outs {
                                if let Some(n) = o.get("Name").and_then(|n| n.as_str())
                                    && !seen_outputs.insert(n.to_string()) {
                                        out.push(make_resource_diagnostic(
                                            "E3701",
                                            &format!("Duplicate OutputArtifact name '{}'", n),
                                            m,
                                            name,
                                            "",
                                            None,
                                        ));
                                    }
                            }
                        }
                        if si > 0
                            && let Some(ins) =
                                action.get("InputArtifacts").and_then(|i| i.as_array())
                            {
                                for i in ins {
                                    if let Some(n) = i.get("Name").and_then(|n| n.as_str())
                                        && !seen_outputs.contains(n) {
                                            out.push(make_resource_diagnostic("E3701", &format!("InputArtifact '{}' in stage '{}' action '{}' does not reference a previously defined OutputArtifact", n, stage_name, aname), m, name, "", None));
                                        }
                                }
                            }
                    }
                }
            }
        }
    }

    for name in m.resources_of_type("AWS::CodePipeline::Pipeline") {
        if let Some(serde_json::Value::Array(stages)) =
            resolve_concrete(m, name, "Properties.Stages")
        {
            for stage in &stages {
                if let Some(actions) = stage.get("Actions").and_then(|a| a.as_array()) {
                    for action in actions {
                        let cat = action
                            .get("ActionTypeId")
                            .and_then(|a| a.get("Category"))
                            .and_then(|c| c.as_str())
                            .unwrap_or("");
                        let aname = action
                            .get("Name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("unknown");
                        if let Some(counts) = ctx.cached_data.codepipeline_artifact_counts.get(cat)
                        {
                            let actual_in = action
                                .get("InputArtifacts")
                                .and_then(|i| i.as_array())
                                .map(|a| a.len())
                                .unwrap_or(0);
                            let actual_out = action
                                .get("OutputArtifacts")
                                .and_then(|o| o.as_array())
                                .map(|a| a.len())
                                .unwrap_or(0);
                            if actual_in < counts.min_input {
                                out.push(make_resource_diagnostic(
                                    "E3702",
                                    &format!(
                                        "Action '{}' (category '{}') has {} input artifacts, expected at least {}",
                                        aname, cat, actual_in, counts.min_input
                                    ),
                                    m,
                                    name,
                                    "",
                                    None,
                                ));
                            }
                            if actual_in > counts.max_input {
                                out.push(make_resource_diagnostic(
                                    "E3702",
                                    &format!(
                                        "Action '{}' (category '{}') has {} input artifacts, expected at most {}",
                                        aname, cat, actual_in, counts.max_input
                                    ),
                                    m,
                                    name,
                                    "",
                                    None,
                                ));
                            }
                            if actual_out < counts.min_output {
                                out.push(make_resource_diagnostic(
                                    "E3702",
                                    &format!(
                                        "Action '{}' (category '{}') has {} output artifacts, expected at least {}",
                                        aname, cat, actual_out, counts.min_output
                                    ),
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
        }
    }

    for name in m.resources_of_type("AWS::CodePipeline::Pipeline") {
        if let Some(serde_json::Value::Array(stages)) =
            resolve_concrete(m, name, "Properties.Stages")
        {
            for stage in &stages {
                if let Some(actions) = stage.get("Actions").and_then(|a| a.as_array()) {
                    for action in actions {
                        if let Some(tp) = action
                            .get("Configuration")
                            .and_then(|c| c.get("TemplatePath"))
                            .and_then(|t| t.as_str())
                            && tp.contains("::") {
                                let artifact = tp.split("::").next().unwrap_or("");
                                let input_names: HashSet<&str> = action
                                    .get("InputArtifacts")
                                    .and_then(|i| i.as_array())
                                    .map(|arr| {
                                        arr.iter()
                                            .filter_map(|a| a.get("Name").and_then(|n| n.as_str()))
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                if !input_names.contains(artifact) {
                                    out.push(make_resource_diagnostic("E3703", &format!("TemplatePath artifact '{}' is not one of the InputArtifacts", artifact), m, name, "", None));
                                }
                            }
                    }
                }
            }
        }
    }

    for name in m.resources_of_type("AWS::Lambda::EventSourceMapping") {
        if let Some(target) = m.follow_ref(name, "Properties.EventSourceArn")
            && let Some(sqs) = m.resources.get(target)
                && sqs.resource_type == "AWS::SQS::Queue" {
                    let vis = resolve_concrete(m, target, "Properties.VisibilityTimeout")
                        .and_then(|v| v.as_i64());
                    if let Some(fn_name) = m.follow_ref(name, "Properties.FunctionName") {
                        let timeout = resolve_concrete(m, fn_name, "Properties.Timeout")
                            .and_then(|v| v.as_i64())
                            .unwrap_or(3);
                        if let Some(v) = vis
                            && v < timeout * 6 {
                                out.push(make_resource_diagnostic("E3505", &format!("SQS queue '{}' VisibilityTimeout ({}) is less than Lambda function '{}' Timeout ({})", target, v, fn_name, timeout), m, name, "Properties", Some("Set the SQS VisibilityTimeout to at least the Lambda function Timeout")));
                            }
                    }
                }
    }

    for name in m.resources_of_type("AWS::SSM::Document") {
        if let Some(content) = resolve_concrete(m, name, "Properties.Content")
            && content.is_object() && content.get("schemaVersion").is_none() {
                out.push(make_resource_diagnostic(
                    "E3051",
                    "SSM Document Content must include 'schemaVersion'",
                    m,
                    name,
                    "Properties.Content",
                    None,
                ));
            }
    }

    for name in m.resources_of_type("AWS::S3::Bucket") {
        if let Some(serde_json::Value::Array(configs)) =
            resolve_concrete(m, name, "Properties.IntelligentTieringConfigurations")
        {
            for (config_idx, config) in configs.iter().enumerate() {
                if let Some(tierings) = config.get("Tierings").and_then(|t| t.as_array()) {
                    for (tier_idx, tier) in tierings.iter().enumerate() {
                        if let Some(days) = tier.get("Days").and_then(|d| d.as_i64()) {
                            let access_tier = tier
                                .get("AccessTier")
                                .and_then(|a| a.as_str())
                                .unwrap_or("");
                            let path = format!(
                                "Properties.IntelligentTieringConfigurations[{}].Tierings[{}].Days",
                                config_idx, tier_idx
                            );
                            if access_tier == "ARCHIVE_ACCESS" && days < 90 {
                                out.push(make_resource_diagnostic(
                                    "E3061",
                                    &format!(
                                        "Days {} for ARCHIVE_ACCESS must be between 90 and 730",
                                        days
                                    ),
                                    m,
                                    name,
                                    &path,
                                    Some("Set Days between 90 and 730"),
                                ));
                            }
                            if access_tier == "DEEP_ARCHIVE_ACCESS" && days < 180 {
                                out.push(make_resource_diagnostic(
                                    "E3061",
                                    &format!("Days {} for DEEP_ARCHIVE_ACCESS must be between 180 and 730", days),
                                    m,
                                    name,
                                    &path,
                                    Some("Set Days between 90 and 730"),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    for name in m.resources_of_type("AWS::Lambda::Function") {
        if let Some(snap) = resolve_concrete(m, name, "Properties.SnapStart")
            && snap.get("ApplyOn").and_then(|a| a.as_str()) == Some("PublishedVersions") {
                let version_refs = m.graph.ref_sources(name);
                let has_ver = version_refs.iter().any(|src| {
                    m.resources
                        .get(&**src)
                        .map(|r| r.resource_type == "AWS::Lambda::Version")
                        .unwrap_or(false)
                });
                if !has_ver {
                    out.push(make_resource_diagnostic(
                        "W2530",
                        "SnapStart is enabled but no AWS::Lambda::Version resource is attached",
                        m,
                        name,
                        "Properties.SnapStart",
                        Some("Add an AWS::Lambda::Version resource that references this function"),
                    ));
                }
            }
    }

    let role_arn_props = [
        ("AWS::ECS::TaskDefinition", "Properties.ExecutionRoleArn"),
        (
            "AWS::S3::Bucket",
            "Properties.ReplicationConfiguration.Role",
        ),
    ];
    for (rtype, path) in &role_arn_props {
        for name in m.resources_of_type(rtype) {
            if let Some(serde_json::Value::String(val)) = resolve_concrete(m, name, path)
                && val.starts_with("arn:") && !ARN_RE.is_match(&val) {
                    out.push(make_resource_diagnostic(
                        "E3511",
                        &format!("IAM Role ARN '{}' does not match expected pattern", val),
                        m,
                        name,
                        path,
                        None,
                    ));
                }
        }
    }

    for (name, res) in &m.resources {
        for (prop, val) in &res.properties {
            if let ResolvedValue::Concrete { value: v } = val
                && let Some(s) = v.as_str()
                    && s.starts_with("arn:")
                        && s != "*"
                        && !crate::functions::contains_unresolvable_content(val)
                        && (prop.ends_with("Arn")
                            || prop.ends_with("RoleArn")
                            || prop.ends_with("TopicArn"))
                        {
                            out.push(make_resource_diagnostic(
                                "W9002",
                                &format!(
                                    "Property '{}' has a hardcoded ARN — use Ref, GetAtt, or a parameter instead",
                                    prop
                                ),
                                m,
                                name,
                                &format!("Properties.{}", prop),
                                None,
                            ));
                            break;
                        }
        }
    }

    for (name, res) in &m.resources {
        for p in &res.diagnostics.redundant_subs {
            out.push(make_resource_diagnostic(
                "W1020",
                "Fn::Sub isn't needed because there are no variables",
                m,
                name,
                p,
                None,
            ));
        }
    }

    // Only fires when the variable is a parameter; GetAtt-shaped variables
    // like ${X.Arn} and resource refs to GetAtt attrs are out of scope.
    // Skip NoEcho parameters — simplifying to !Ref would expose the value.
    for (name, res) in &m.resources {
        for pair in &res.diagnostics.simple_subs {
            let path = &pair.path;
            let var = &pair.value;
            let Some(param) = m.parameters.get(var.as_str()) else {
                continue;
            };
            if param.no_echo {
                continue;
            }
            out.push(make_resource_diagnostic(
                "W1020",
                &format!("Fn::Sub '${{{}}}' can be simplified to !Ref {}", var, var),
                m,
                name,
                path,
                None,
            ));
        }
    }

    for (name, res) in &m.resources {
        for (prop, val) in &res.properties {
            check_dynamic_ref_spaces(&mut out, m, name, &format!("Properties.{}", prop), val);
        }
    }

    if let Some(resources) = input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
        for (name, res) in resources {
            if let Some(edges) = res.get(FIELD_OUTGOING_REFS).and_then(|r| r.as_array()) {
                for edge in edges {
                    let target = edge
                        .get(FIELD_TARGET)
                        .and_then(|t| t.as_str())
                        .unwrap_or("");
                    let sp = edge
                        .get(FIELD_SOURCE_PATH)
                        .and_then(|p| p.as_str())
                        .unwrap_or("");
                    if sp.starts_with("Metadata")
                        && let Some(param) = m.parameters.get(target)
                            && param.no_echo {
                                out.push(make_resource_diagnostic(
                                    "W2010",
                                    &format!(
                                        "Don't use 'NoEcho' parameter '{}' in resource metadata",
                                        target
                                    ),
                                    m,
                                    name,
                                    sp,
                                    Some("Move the parameter reference out of Metadata or remove NoEcho"),
                                ));
                            }
                }
            }
        }
    }

    if let Some(resources) = input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
        for (name, res) in resources {
            if let Some(edges) = res.get(FIELD_OUTGOING_REFS).and_then(|r| r.as_array()) {
                for edge in edges {
                    if edge.get(FIELD_KIND).and_then(|k| k.as_str()) == Some(EDGE_KIND_SELECT)
                        && let Some(idx) = edge.get("index").and_then(|i| i.as_i64())
                            && idx < 0 {
                                out.push(make_resource_diagnostic(
                                    "F1050",
                                    "Fn::Select index must be a non-negative integer",
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

    for name in m.resources_of_type("AWS::EC2::SecurityGroup") {
        if let Some(serde_json::Value::String(gn)) =
            resolve_concrete(m, name, "Properties.GroupName")
            && !gn.starts_with("{{") && !SG_NAME_RE.is_match(&gn) {
                out.push(make_resource_diagnostic(
                    "E1153",
                    &format!("Value '{}' does not match Security Group Name format", gn),
                    m,
                    name,
                    "Properties.GroupName",
                    None,
                ));
            }
    }

    const UNIQUE_ARRAY_PROPS: &[&str] = &[
        "AvailabilityZones",
        "SecurityGroupIds",
        "SecurityGroups",
        "SubnetIds",
        "Subnets",
        "RequiresCompatibilities",
        "PlacementConstraints",
    ];
    for (name, res) in &m.resources {
        for prop in res.properties.keys() {
            if !UNIQUE_ARRAY_PROPS.contains(&prop.as_str()) {
                continue;
            }
            let path = format!("Properties.{}", prop);
            let resolved = m
                .resolve_deep(name, &path)
                .or_else(|| m.resolve(name, &path).cloned());
            let Some(rv) = resolved else {
                continue;
            };
            let items: Vec<String> = match &rv {
                ResolvedValue::Concrete { value: v } => {
                    let Some(arr) = v.as_array() else {
                        continue;
                    };
                    arr.iter().map(|x| x.to_string()).collect()
                }
                ResolvedValue::List { items } => items
                    .iter()
                    .map(|it| serde_json::to_string(it).unwrap_or_default())
                    .collect(),
                _ => continue,
            };
            if items.len() < 2 {
                continue;
            }
            let mut seen = HashSet::new();
            let has_dup = items.iter().any(|s| !seen.insert(s.clone()));
            if has_dup {
                out.push(make_resource_diagnostic(
                    "W9007",
                    &format!("Array property '{}' contains duplicate values", prop),
                    m,
                    name,
                    &path,
                    None,
                ));
            }
        }
    }

    if let Some(mappings) = input.get(FIELD_MAPPINGS).and_then(|m| m.as_object()) {
        for (map_name, level1) in mappings {
            if !level1.is_object() {
                out.push(make_resource_diagnostic(
                    "F0050",
                    &format!("Mapping '{}' must be a map", map_name),
                    m,
                    "",
                    "",
                    None,
                ));
            } else if let Some(obj) = level1.as_object() {
                for (k1, level2) in obj {
                    if !level2.is_object() {
                        out.push(make_resource_diagnostic(
                            "F0050",
                            &format!(
                                "Mapping '{}' second level key '{}' must be a map",
                                map_name, k1
                            ),
                            m,
                            "",
                            "",
                            None,
                        ));
                    }
                }
            }
        }
    }

    {
        if let Some(resources) = input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
            for (name, res) in resources {
                if let Some(edges) = res.get(FIELD_OUTGOING_REFS).and_then(|r| r.as_array()) {
                    for edge in edges {
                        if edge.get(FIELD_KIND).and_then(|k| k.as_str()) != Some(EDGE_KIND_REF) {
                            continue;
                        }
                        let target = edge
                            .get(FIELD_TARGET)
                            .and_then(|t| t.as_str())
                            .unwrap_or("");
                        let sp = edge
                            .get(FIELD_SOURCE_PATH)
                            .and_then(|p| p.as_str())
                            .unwrap_or("");
                        if let Some(param) = m.parameters.get(target) {
                            if let Some(ref def) = param.default {
                                // ImageId: only fire if Default fails AMI pattern
                                if sp.ends_with("ImageId") && param.param_type == "String"
                                    && !W1030_AMI_RE.is_match(def) {
                                        out.push(make_resource_diagnostic("W1030", &format!("{{'Ref': '{}'}} is not a 'AWS::EC2::Image.Id' when 'Ref' is resolved", target), m, name, sp, Some("Use parameter type AWS::EC2::Image::Id")));
                                    }
                                // KeyName with empty default
                                if sp.ends_with("KeyName") && def.is_empty() {
                                    out.push(make_resource_diagnostic("W1030", &format!("{{'Ref': '{}'}} is shorter than 1 when 'Ref' is resolved", target), m, name, sp, Some("Set a non-empty default or add AllowedValues")));
                                }
                                // CidrBlock: fire if Default fails strict CIDR validation (host bits set)
                                if (sp.ends_with("CidrBlock")
                                    || sp.ends_with("DestinationCidrBlock"))
                                    && param.param_type == "String"
                                    && !is_valid_cidr_strict(def) {
                                        out.push(make_resource_diagnostic("W1030", &format!("{{'Ref': '{}'}} is not a 'ipv4-network' when 'Ref' is resolved", target), m, name, sp, Some("Validate the parameter value matches CIDR format")));
                                    }
                            }

                            // SecurityGroup.Id: String parameter used where security group ID expected
                            if param.param_type == "String"
                                && (sp.ends_with("GroupSet")
                                    || sp.contains("GroupSet.")
                                    || sp.ends_with("SecurityGroupIds")
                                    || sp.contains("SecurityGroupIds."))
                            {
                                out.push(make_resource_diagnostic("W1030",
                                    &format!("{{'Ref': '{}'}} is not a 'AWS::EC2::SecurityGroup.Id' with pattern '^sg-([a-fA-F0-9]{{8}}|[a-fA-F0-9]{{17}})$' when 'Ref' is resolved", target),
                                    m, name, sp, None));
                            }

                            // Subnet.Id: String parameter used where subnet ID expected
                            if param.param_type == "String" && sp.ends_with("SubnetId") {
                                out.push(make_resource_diagnostic("W1030",
                                    &format!("{{'Ref': '{}'}} is not a 'AWS::EC2::Subnet.Id' with pattern '^subnet-(([0-9A-Fa-f]{{8}})|([0-9A-Fa-f]{{17}}))$' when 'Ref' is resolved", target),
                                    m, name, sp, None));
                                out.push(make_resource_diagnostic("W1030",
                                    &format!("{{'Ref': '{}'}} is not a 'AWS::EC2::Subnet.Id' with pattern '^[\\.\\-_\\/#A-Za-z0-9]{{1,512}}\\Z' when 'Ref' is resolved", target),
                                    m, name, sp, None));
                            }

                            // VPC.Id: String parameter used where VPC ID expected
                            if param.param_type == "String" && sp.ends_with("VpcId") {
                                out.push(make_resource_diagnostic("W1030",
                                    &format!("{{'Ref': '{}'}} is not a 'AWS::EC2::VPC.Id' with pattern '^vpc-([a-fA-F0-9]{{8}}|[a-fA-F0-9]{{17}})$' when 'Ref' is resolved", target),
                                    m, name, sp, None));
                            }

                            // VPC.Id: parameter default fails VPC ID pattern
                            if sp.ends_with("VpcId") && param.param_type == "AWS::EC2::VPC::Id"
                                && let Some(ref def) = param.default
                                    && !W1030_VPC_RE.is_match(def) {
                                        out.push(make_resource_diagnostic("W1030",
                                            &format!("{{'Ref': '{}'}} is not a 'AWS::EC2::VPC.Id' with pattern '^vpc-(([0-9A-Fa-f]{{8}})|([0-9A-Fa-f]{{17}}))$' when 'Ref' is resolved", target),
                                            m, name, sp, None));
                                    }
                        }
                    }
                }
            }
        }
    }

    {
        let mut checked: HashSet<String> = HashSet::new();
        if let Some(resources) = input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
            for (_name, res) in resources {
                if let Some(edges) = res.get(FIELD_OUTGOING_REFS).and_then(|r| r.as_array()) {
                    for edge in edges {
                        if edge.get(FIELD_KIND).and_then(|k| k.as_str()) != Some(EDGE_KIND_REF) {
                            continue;
                        }
                        let target = edge
                            .get(FIELD_TARGET)
                            .and_then(|t| t.as_str())
                            .unwrap_or("");
                        let sp = edge
                            .get(FIELD_SOURCE_PATH)
                            .and_then(|p| p.as_str())
                            .unwrap_or("");
                        if !is_arn_prop(sp) {
                            continue;
                        }
                        if checked.contains(target) {
                            continue;
                        }
                        if let Some(param) = m.parameters.get(target) {
                            if param.param_type != "String" {
                                continue;
                            }
                            if let Some(ref def) = param.default
                                && !W1030_ARN_RE.is_match(def) {
                                    checked.insert(target.to_string());
                                    let param_path = format!("Parameters.{}.Default", target);
                                    out.push(make_resource_diagnostic("W1030",
                                        &format!("{{'Ref': '{}'}} does not match '^(arn:(aws[A-Za-z\\-]*?|\\*):[^:]+:[^:]*(:(?:\\d{{12}}|\\*|aws)?:.+|)|\\*)$' when 'Ref' is resolved", target),
                                        m, "", &param_path, Some("Ensure the parameter default matches the expected ARN pattern")));
                                }
                        }
                    }
                }
            }
        }
    }

    let getatt_format: HashMap<(&str, &str), &str> = [
        (
            ("AWS::EC2::SecurityGroup", "GroupId"),
            "AWS::EC2::SecurityGroup.Id",
        ),
        (
            ("AWS::EC2::SecurityGroup", "GroupName"),
            "AWS::EC2::SecurityGroup.Name",
        ),
        (
            ("AWS::EC2::VPC", "DefaultSecurityGroup"),
            "AWS::EC2::VPC.DefaultSecurityGroup",
        ),
        (("AWS::Logs::LogGroup", "Arn"), "AWS::Logs::LogGroup.Arn"),
    ]
    .into_iter()
    .collect();
    if let Some(resources) = input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
        for (name, res) in resources {
            if let Some(edges) = res.get(FIELD_OUTGOING_REFS).and_then(|r| r.as_array()) {
                for edge in edges {
                    if edge.get(FIELD_KIND).and_then(|k| k.as_str()) != Some(EDGE_KIND_GET_ATT) {
                        continue;
                    }
                    let target = edge
                        .get(FIELD_TARGET)
                        .and_then(|t| t.as_str())
                        .unwrap_or("");
                    let attr = edge.get(FIELD_ATTR).and_then(|a| a.as_str()).unwrap_or("");
                    let sp = edge
                        .get(FIELD_SOURCE_PATH)
                        .and_then(|p| p.as_str())
                        .unwrap_or("");
                    if let Some(target_res) = m.resources.get(target) {
                        let src_fmt = getatt_format
                            .get(&(target_res.resource_type.as_str(), attr))
                            .copied()
                            .unwrap_or("");
                        let dest_fmt = if sp.contains("GroupSet") {
                            "AWS::EC2::SecurityGroup.Id"
                        } else if sp.contains("awslogs-group") {
                            "AWS::Logs::LogGroup.Name"
                        } else {
                            ""
                        };
                        if !src_fmt.is_empty() && !dest_fmt.is_empty() && src_fmt != dest_fmt {
                            out.push(make_resource_diagnostic("E1040", &format!("{{'Fn::GetAtt': ['{}', '{}']}} does not match destination format of '{}'", target, attr, dest_fmt), m, name, sp, Some("Use the correct GetAtt attribute")));
                        }
                    }
                }
            }
        }
    }

    let ref_type_ok: HashMap<(&str, &str), bool> = [
        (("AWS::EC2::VPC", "AWS::EC2::VPC.Id"), true),
        (("AWS::EC2::Subnet", "AWS::EC2::Subnet.Id"), true),
        (
            ("AWS::EC2::SecurityGroup", "AWS::EC2::SecurityGroup.Id"),
            true,
        ),
        (
            (
                "AWS::EC2::NetworkInterface",
                "AWS::EC2::NetworkInterface.Id",
            ),
            true,
        ),
    ]
    .into_iter()
    .collect();
    if let Some(resources) = input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
        for (name, res) in resources {
            if let Some(edges) = res.get(FIELD_OUTGOING_REFS).and_then(|r| r.as_array()) {
                for edge in edges {
                    if edge.get(FIELD_KIND).and_then(|k| k.as_str()) != Some(EDGE_KIND_REF) {
                        continue;
                    }
                    let target = edge
                        .get(FIELD_TARGET)
                        .and_then(|t| t.as_str())
                        .unwrap_or("");
                    let sp = edge
                        .get(FIELD_SOURCE_PATH)
                        .and_then(|p| p.as_str())
                        .unwrap_or("");
                    if let Some(target_res) = m.resources.get(target) {
                        let dest_fmt = if sp.ends_with("VpcId") {
                            "AWS::EC2::VPC.Id"
                        } else if sp.ends_with("SubnetId") {
                            "AWS::EC2::Subnet.Id"
                        } else if sp.ends_with("NetworkInterfaceId") {
                            "AWS::EC2::NetworkInterface.Id"
                        } else if sp.ends_with("SecurityGroupId") {
                            "AWS::EC2::SecurityGroup.Id"
                        } else {
                            ""
                        };
                        if !dest_fmt.is_empty()
                            && !ref_type_ok
                                .contains_key(&(target_res.resource_type.as_str(), dest_fmt))
                        {
                            out.push(make_resource_diagnostic(
                                "E1041",
                                &format!(
                                    "{{'Ref': '{}'}} does not match destination format of '{}'",
                                    target, dest_fmt
                                ),
                                m,
                                name,
                                sp,
                                Some("Use a Ref to a resource whose type matches the expected format"),
                            ));
                        }
                        // Non-VPC SecurityGroup Ref used where SecurityGroup.Id expected
                        if target_res.resource_type == "AWS::EC2::SecurityGroup"
                            && sp.ends_with("SecurityGroupId")
                            && !target_res.properties.contains_key("VpcId")
                        {
                            out.push(make_resource_diagnostic(
                                "E1041",
                                &format!(
                                    "{{'Ref': '{}'}} with formats ['AWS::EC2::SecurityGroup.Name'] does not match destination format of 'AWS::EC2::SecurityGroup.Id'",
                                    target
                                ),
                                m,
                                name,
                                sp,
                                Some("Use a Ref to a resource whose type matches the expected format"),
                            ));
                        }
                    }
                }
            }
        }
    }

    for name in m.resources_of_type("AWS::CloudFront::Distribution") {
        let scenarios =
            m.resolve_scenarios_json(name, "Properties.DistributionConfig.DefaultCacheBehavior");
        for (val, conds) in &scenarios {
            if !conds.is_empty()
                && !m.conditions.is_satisfiable(
                    &conds
                        .iter()
                        .map(|(k, v)| (k.clone(), *v))
                        .collect::<Vec<_>>(),
                )
            {
                continue;
            }
            if val.is_null() {
                out.push(make_resource_diagnostic(
                    "E3003",
                    "'DefaultCacheBehavior' is a required property",
                    m,
                    name,
                    "Properties.DistributionConfig",
                    Some("Add DefaultCacheBehavior to the Fn::If branch"),
                ));
            } else if val.is_object() {
                if val.get("TargetOriginId").is_none() {
                    out.push(make_resource_diagnostic(
                        "E3003",
                        "'TargetOriginId' is a required property",
                        m,
                        name,
                        "Properties.DistributionConfig.DefaultCacheBehavior",
                        None,
                    ));
                }
                if val.get("ViewerProtocolPolicy").is_none() {
                    out.push(make_resource_diagnostic(
                        "E3003",
                        "'ViewerProtocolPolicy' is a required property",
                        m,
                        name,
                        "Properties.DistributionConfig.DefaultCacheBehavior",
                        None,
                    ));
                }
            }
        }
    }

    if let Some(resources) = input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
        for (name, res) in resources {
            if let Some(tags) = res
                .get(FIELD_PROPERTIES)
                .and_then(|p| p.get("Tags"))
                .and_then(|t| t.as_array())
            {
                for tag in tags {
                    if tag.is_object() && tag.get("Value").is_some() {
                        let key = tag.get("Key");
                        if key.is_none() || key == Some(&serde_json::Value::Null) {
                            out.push(make_resource_diagnostic(
                                "E3003",
                                "'Key' is a required property",
                                m,
                                name,
                                "Properties.Tags",
                                Some("Tag Key cannot be null or AWS::NoValue"),
                            ));
                            out.push(make_resource_diagnostic(
                                "E3024",
                                "'Key' is a required property",
                                m,
                                name,
                                "Properties.Tags",
                                Some("Tag Key cannot be null or AWS::NoValue"),
                            ));
                        }
                    }
                }
            }
        }
    }

    // emitted false positives when a conditional was nested inside a specific property
    // (e.g., Stack.Properties.Parameters = Fn::If). Nested-stack parameter validation
    // is covered by the dedicated schema/guard checks for AWS::CloudFormation::Stack.

    for svc_name in m.resources_of_type("AWS::ECS::Service") {
        let td_id = match m.follow_ref(svc_name, "Properties.TaskDefinition") {
            Some(id) => id.to_string(),
            None => continue,
        };
        // Use best-effort JSON conversion so partially-resolved (List, Map) values are
        // still traversable. resolve_concrete would reject anything that isn't a flat
        // Concrete serde value, which is the usual shape for multi-level resource props.
        let lbs = match m
            .resolve_deep(svc_name, "Properties.LoadBalancers")
            .or_else(|| m.resolve(svc_name, "Properties.LoadBalancers").cloned())
        {
            Some(rv) => match resolved_to_json_best_effort(&rv) {
                serde_json::Value::Array(a) => a,
                _ => continue,
            },
            None => continue,
        };
        let cdefs = match m
            .resolve_deep(&td_id, "Properties.ContainerDefinitions")
            .or_else(|| {
                m.resolve(&td_id, "Properties.ContainerDefinitions")
                    .cloned()
            }) {
            Some(rv) => match resolved_to_json_best_effort(&rv) {
                serde_json::Value::Array(a) => a,
                _ => continue,
            },
            None => continue,
        };
        for (i, lb) in lbs.iter().enumerate() {
            let cn = lb
                .get("ContainerName")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let cp = lb.get("ContainerPort").and_then(|v| v.as_i64());
            if cn.is_empty() || cp.is_none() {
                continue;
            }
            let cp = cp.unwrap();
            let has_dynamic = cdefs.iter().any(|c| {
                c.get("Name").and_then(|n| n.as_str()) == Some(cn)
                    && c.get("PortMappings")
                        .and_then(|p| p.as_array())
                        .map(|pms| {
                            pms.iter().any(|pm| {
                                pm.get("ContainerPort").and_then(|p| p.as_i64()) == Some(cp)
                                    && pm.get("HostPort").and_then(|p| p.as_i64()) == Some(0)
                            })
                        })
                        .unwrap_or(false)
            });
            if !has_dynamic {
                continue;
            }
            let tg_path = format!("Properties.LoadBalancers.{}.TargetGroupArn", i);
            if let Some(tg_id) = m.follow_ref(svc_name, &tg_path) {
                let hp_rv = m
                    .resolve_deep(tg_id, "Properties.HealthCheckPort")
                    .or_else(|| m.resolve(tg_id, "Properties.HealthCheckPort").cloned());
                let hp_str = match hp_rv.as_ref() {
                    Some(ResolvedValue::Concrete { value: v }) => {
                        v.as_str().unwrap_or("").to_string()
                    }
                    _ => String::new(),
                };
                if hp_str != "traffic-port" {
                    let mut diag = make_resource_diagnostic(
                        "E3049",
                        &format!(
                            "Container '{}' has HostPort 0 but TargetGroup '{}' HealthCheckPort is '{}', must be 'traffic-port'",
                            cn, tg_id, hp_str
                        ),
                        m,
                        svc_name,
                        "Properties.LoadBalancers",
                        None,
                    );
                    let tg_span = m.resource_span(tg_id, "Properties.HealthCheckPort");
                    diag.related_resources.get_or_insert_with(Vec::new).push(
                        diagnostics::RelatedResource {
                            resource: Some(diagnostics::ResourceRef {
                                id: Some(tg_id.to_string()),
                                resource_type: m
                                    .resources
                                    .get(tg_id)
                                    .map(|r| r.resource_type.clone()),
                            }),
                            location: Some(diagnostics::SourceSpan {
                                start_line: tg_span.start_line,
                                start_column: tg_span.start_column,
                                end_line: tg_span.end_line,
                                end_column: tg_span.end_column,
                            }),
                            message: "HealthCheckPort defined here".into(),
                        },
                    );
                    out.push(diag);
                }
            }
        }
    }

    {
        if let Some(iam_obj) = ctx
            .cached_data
            .iam_action_resource_patterns
            .get("iam_action_resource_patterns")
            .and_then(|v| v.as_object())
            .or_else(|| ctx.cached_data.iam_action_resource_patterns.as_object())
        {
            let mut iam_patterns: HashMap<String, String> = HashMap::new();
            for (k, v) in iam_obj {
                if let Some(s) = v.as_str() {
                    iam_patterns.insert(k.clone(), s.to_string());
                }
            }
            if !iam_patterns.is_empty() {
                let policy_types = [
                    ("AWS::IAM::Policy", "Properties.PolicyDocument"),
                    ("AWS::IAM::ManagedPolicy", "Properties.PolicyDocument"),
                ];
                for (rtype, doc_path) in &policy_types {
                    for name in m.resources_of_type(rtype) {
                        let doc_rv = m
                            .resolve_deep(name, doc_path)
                            .or_else(|| m.resolve(name, doc_path).cloned());
                        let Some(rv) = doc_rv else {
                            continue;
                        };
                        let doc = resolved_to_json_best_effort(&rv);
                        check_iam_action_resources(
                            &mut out,
                            m,
                            name,
                            &doc,
                            doc_path,
                            &iam_patterns,
                        );
                    }
                }
                for name in m.resources_of_type("AWS::IAM::Role") {
                    // Resolve each policy's PolicyDocument independently so that
                    // non-concrete sibling fields (e.g., Sub-templated PolicyName)
                    // don't cause the entire Policies array to fail resolve_concrete.
                    let Some(res) = m.resources.get(name.as_str()) else {
                        continue;
                    };
                    let policies_len = match res.properties.get("Policies") {
                        Some(ResolvedValue::List { items }) => items.len(),
                        Some(ResolvedValue::Concrete { value: v }) => {
                            v.as_array().map(|a| a.len()).unwrap_or(0)
                        }
                        _ => 0,
                    };
                    for idx in 0..policies_len {
                        let doc_path = format!("Properties.Policies.{}.PolicyDocument", idx);
                        if let Some(doc) = resolve_concrete(m, name, &doc_path) {
                            check_iam_action_resources(
                                &mut out,
                                m,
                                name,
                                &doc,
                                &format!("Properties.Policies[{}].PolicyDocument", idx),
                                &iam_patterns,
                            );
                            continue;
                        }
                        // Fallback: the PolicyDocument may be partially unresolved but still
                        // usable as raw JSON — extract via the ResolvedValue tree so we don't
                        // miss statements like those with Sub'd PolicyName sibling fields.
                        if let Some(ResolvedValue::List { items }) = res.properties.get("Policies")
                            && let Some(ResolvedValue::Map { entries }) = items.get(idx) {
                                for entry in entries {
                                    if entry.key == "PolicyDocument" {
                                        let json = resolved_to_json_best_effort(&entry.value);
                                        check_iam_action_resources(
                                            &mut out,
                                            m,
                                            name,
                                            &json,
                                            &format!("Properties.Policies[{}].PolicyDocument", idx),
                                            &iam_patterns,
                                        );
                                    }
                                }
                            }
                    }
                }
            }
        }
    }

    for vpc_name in m.resources_of_type("AWS::EC2::VPC") {
        let vpc_cidr_str =
            match resolve_concrete(m, vpc_name, "Properties.CidrBlock").and_then(|v| {
                if let serde_json::Value::String(s) = v {
                    Some(s)
                } else {
                    None
                }
            }) {
                Some(s) => s,
                None => continue,
            };
        let vpc_net = match parse_ipv4_cidr(&vpc_cidr_str) {
            Some(n) => n,
            None => continue,
        };
        for subnet_name in m.resources_of_type("AWS::EC2::Subnet") {
            let subnet_vpc = resolve_concrete(m, subnet_name, "Properties.VpcId");
            let refs_this_vpc = m
                .follow_ref(subnet_name, "Properties.VpcId")
                .map(|t| t == vpc_name)
                .unwrap_or(false)
                || subnet_vpc.as_ref().and_then(|v| v.as_str()) == Some(vpc_name);
            if !refs_this_vpc {
                continue;
            }
            if let Some(serde_json::Value::String(sub_cidr)) =
                resolve_concrete(m, subnet_name, "Properties.CidrBlock")
                && let Some(sub_net) = parse_ipv4_cidr(&sub_cidr)
                    && !is_subnet_of(sub_net, vpc_net) {
                        out.push(make_resource_diagnostic(
                            "E3059",
                            &format!(
                                "Subnet CIDR '{}' is not within VPC CIDR '{}'",
                                sub_cidr, vpc_cidr_str
                            ),
                            m,
                            subnet_name,
                            "Properties.CidrBlock",
                            None,
                        ));
                    }
        }
    }

    {
        for (rtype, id_props) in &ctx.cached_data.primary_identifiers {
            let resources: Vec<&String> = m.resources_of_type(rtype).iter().collect();
            if resources.len() < 2 {
                continue;
            }
            let mut tuples: BTreeMap<Vec<String>, BTreeSet<String>> = BTreeMap::new();
            for r in &resources {
                let mut tuple: Vec<String> = Vec::with_capacity(id_props.len());
                let mut complete = true;
                for prop in id_props {
                    let path = format!("Properties.{}", prop);
                    let mut vals: Vec<String> = collect_concrete_scenarios(m, r, &path)
                        .into_iter()
                        .filter(|v| !v.is_null())
                        .filter_map(|v| match v {
                            serde_json::Value::String(s) => Some(s),
                            other => Some(other.to_string()),
                        })
                        .collect();
                    vals.sort();
                    match vals.into_iter().next() {
                        Some(v) => tuple.push(v),
                        None => {
                            complete = false;
                            break;
                        }
                    }
                }
                if !complete {
                    continue;
                }
                tuples.entry(tuple).or_default().insert((*r).clone());
            }
            for (tuple, names) in &tuples {
                if names.len() < 2 {
                    continue;
                }
                // Skip if all resources with duplicate identifiers are behind
                // mutually exclusive conditions (they can never coexist at deploy time)
                let all_mutex = names.len() >= 2 && {
                    let conds: Vec<&str> = names
                        .iter()
                        .filter_map(|n| m.resources.get(n.as_str())?.condition.as_deref())
                        .collect();
                    // All resources must have conditions, and no pair can be simultaneously true
                    conds.len() == names.len()
                        && conds
                            .windows(2)
                            .all(|pair| !m.conditions.conditions_compatible(pair[0], pair[1]))
                };
                if all_mutex {
                    continue;
                }
                let instance_repr = render_primary_id_dict(id_props, tuple);
                let resources_repr = render_resource_set(names);
                let path = if id_props.len() == 1 {
                    format!("Properties.{}", id_props[0])
                } else {
                    KEY_PROPERTIES.to_string()
                };
                for rname in names {
                    out.push(make_resource_diagnostic(
                        "E3019",
                        &format!(
                            "Primary identifiers {} should have unique values across the resources {}",
                            instance_repr, resources_repr
                        ),
                        m,
                        rname,
                        &path,
                        None,
                    ));
                }
            }
        }
    }

    for (name, res) in &m.resources {
        for s in &res.diagnostics.unsubstituted_variables {
            out.push(make_resource_diagnostic(
                "F1029",
                &format!(
                    "Found an embedded parameter \"{}\" outside of an \"Fn::Sub\" at {}",
                    s.value, s.path
                ),
                m,
                name,
                &s.path,
                Some("Wrap the string with Fn::Sub"),
            ));
        }
    }

    if let Some(sm) = ctx
        .cached_data
        .schema_metadata()
        .get("schema_metadata")
        .and_then(|s| s.as_object())
    {
        for (name, res) in &m.resources {
            if let Some(type_meta) = sm.get(&res.resource_type).and_then(|t| t.as_object()) {
                let prop_types = type_meta.get("property_types").and_then(|p| p.as_object());
                if let Some(props_meta) = type_meta
                    .get("property_constraints")
                    .and_then(|p| p.as_object())
                {
                    for (prop, meta) in props_meta {
                        let is_string = prop_types
                            .and_then(|pt| pt.get(prop))
                            .and_then(|v| v.as_str())
                            == Some("string");
                        let max_len =
                            meta.get("maxLength").and_then(|v| v.as_u64()).or_else(|| {
                                if is_string {
                                    meta.get("maximum").and_then(|v| v.as_u64())
                                } else {
                                    None
                                }
                            });
                        let min_len =
                            meta.get("minLength").and_then(|v| v.as_u64()).or_else(|| {
                                if is_string {
                                    meta.get("minimum").and_then(|v| v.as_u64())
                                } else {
                                    None
                                }
                            });
                        if max_len.is_none() && min_len.is_none() {
                            continue;
                        }
                        let path = format!("Properties.{}", prop);
                        // Skip concrete strings — already covered by generated schema string-length rules.
                        // Only estimate through intrinsics (Fn::Sub, Fn::Join, etc.).
                        if let Some(ResolvedValue::Concrete { value: v }) = m.resolve(name, &path)
                            && v.is_string() {
                                continue;
                            }
                        if let Some(len) = m.estimate_string_length(name, &path) {
                            if let Some(max) = max_len
                                && len as u64 > max {
                                    out.push(make_resource_diagnostic(
                                        "W9006",
                                        &format!(
                                            "String length {} exceeds maximum {} for property '{}'",
                                            len, max, prop
                                        ),
                                        m,
                                        name,
                                        &path,
                                        None,
                                    ));
                                }
                            if let Some(min) = min_len
                                && (len as u64) < min {
                                    out.push(make_resource_diagnostic("W9006", &format!("String length {} is below minimum {} for property '{}'", len, min, prop), m, name, &path, None));
                                }
                        }
                    }
                }
            }
        }
    }

    for name in m.resources_of_type("AWS::Lambda::EventSourceMapping") {
        if let Some(target) = m.follow_ref(name, "Properties.EventSourceArn")
            && let Some(target_res) = m.resources.get(target as &str)
                && target_res.resource_type == "AWS::SQS::Queue" {
                    let is_fifo = resolve_concrete(m, target, "Properties.FifoQueue")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if is_fifo
                        && let Some(batch) = resolve_concrete(m, name, "Properties.BatchSize")
                            .and_then(|v| v.as_u64())
                            && batch > 10 {
                                out.push(make_resource_diagnostic(
                                    "E3705",
                                    &format!("BatchSize {} exceeds maximum of 10 for SQS FIFO queue event source", batch),
                                    m, name, "Properties.BatchSize", None,
                                ));
                            }
                }
    }

    for name in m.resources_of_type("AWS::RDS::DBInstance") {
        if let Some(cluster_name) = m.follow_ref(name, "Properties.DBClusterIdentifier")
            && let (
                Some(serde_json::Value::String(inst_engine)),
                Some(serde_json::Value::String(cluster_engine)),
            ) = (
                resolve_concrete(m, name, "Properties.Engine"),
                resolve_concrete(m, cluster_name, "Properties.Engine"),
            )
                && inst_engine != cluster_engine {
                    let mut diag = make_resource_diagnostic(
                        "E3707",
                        &format!(
                            "DBInstance Engine '{}' does not match DBCluster Engine '{}'",
                            inst_engine, cluster_engine
                        ),
                        m,
                        name,
                        "Properties.Engine",
                        None,
                    );
                    let cluster_span = m.resource_span(cluster_name, "Properties.Engine");
                    diag.related_resources.get_or_insert_with(Vec::new).push(
                        diagnostics::RelatedResource {
                            resource: Some(diagnostics::ResourceRef {
                                id: Some(cluster_name.to_string()),
                                resource_type: m
                                    .resources
                                    .get(cluster_name)
                                    .map(|r| r.resource_type.clone()),
                            }),
                            location: Some(diagnostics::SourceSpan {
                                start_line: cluster_span.start_line,
                                start_column: cluster_span.start_column,
                                end_line: cluster_span.end_line,
                                end_column: cluster_span.end_column,
                            }),
                            message: "cluster engine".into(),
                        },
                    );
                    out.push(diag);
                }
    }

    for name in m.resources_of_type("AWS::ApiGateway::Method") {
        if let Some(auth_id) = m.follow_ref(name, "Properties.AuthorizerId")
            && let (
                Some(serde_json::Value::String(auth_type)),
                Some(serde_json::Value::String(authorizer_type)),
            ) = (
                resolve_concrete(m, name, "Properties.AuthorizationType"),
                resolve_concrete(m, auth_id, "Properties.Type"),
            ) {
                let expected = match auth_type.as_str() {
                    "CUSTOM" => vec!["TOKEN", "REQUEST"],
                    "COGNITO_USER_POOLS" => vec!["COGNITO_USER_POOLS"],
                    _ => vec![],
                };
                if !expected.is_empty() && !expected.contains(&authorizer_type.as_str()) {
                    out.push(make_resource_diagnostic(
                        "E3708",
                        &format!("'{}' is not one of {:?}", authorizer_type, expected),
                        m,
                        auth_id,
                        "Properties.Type",
                        None,
                    ));
                }
            }
    }

    for name in m.resources_of_type("AWS::ApiGateway::Stage") {
        if let (Some(stage_api), Some(deployment_name)) = (
            m.follow_ref(name, "Properties.RestApiId"),
            m.follow_ref(name, "Properties.DeploymentId"),
        )
            && let Some(deploy_api) = m.follow_ref(deployment_name, "Properties.RestApiId")
                && stage_api != deploy_api {
                    out.push(make_resource_diagnostic(
                        "E3698",
                        &format!(
                            "Stage RestApiId references '{}' but Deployment references '{}'",
                            stage_api, deploy_api
                        ),
                        m,
                        deployment_name,
                        "Properties.RestApiId",
                        None,
                    ));
                }
    }

    for name in m.resources_of_type("AWS::AutoScaling::AutoScalingGroup") {
        if let (Some(min_val), Some(max_val)) = (
            resolve_concrete(m, name, "Properties.MinSize").and_then(|v| v.as_u64()),
            resolve_concrete(m, name, "Properties.MaxSize").and_then(|v| v.as_u64()),
        )
            && min_val > max_val {
                out.push(make_resource_diagnostic(
                    "E3706",
                    &format!(
                        "MinSize ({}) must be less than or equal to MaxSize ({})",
                        min_val, max_val
                    ),
                    m,
                    name,
                    "Properties.MinSize",
                    None,
                ));
            }
    }

    for name in m.resources_of_type("AWS::ElasticLoadBalancingV2::Listener") {
        if let Some(serde_json::Value::String(proto)) =
            resolve_concrete(m, name, "Properties.Protocol")
            && (proto == "HTTPS" || proto == "TLS")
                && resolve_concrete(m, name, "Properties.Certificates").is_none()
            {
                out.push(make_resource_diagnostic(
                    "E3676",
                    &format!("{} listener requires Certificates", proto),
                    m,
                    name,
                    "Properties.Certificates",
                    None,
                ));
            }
    }

    for name in m.resources_of_type("AWS::ElasticLoadBalancing::LoadBalancer") {
        if let Some(serde_json::Value::Array(listeners)) =
            resolve_concrete(m, name, "Properties.Listeners")
        {
            for (i, listener) in listeners.iter().enumerate() {
                let proto = listener
                    .get("Protocol")
                    .and_then(|p| p.as_str())
                    .unwrap_or("");
                if (proto.eq_ignore_ascii_case("HTTPS") || proto.eq_ignore_ascii_case("SSL"))
                    && listener.get("SSLCertificateId").is_none()
                {
                    out.push(make_resource_diagnostic(
                        "E3679",
                        &format!("{} listener requires SSLCertificateId", proto),
                        m,
                        name,
                        &format!("Properties.Listeners.{}", i),
                        None,
                    ));
                }
            }
        }
    }

    for name in m.resources_of_type("AWS::Lambda::Function") {
        if let Some(serde_json::Value::Object(env_vars)) =
            resolve_concrete(m, name, "Properties.Environment.Variables")
        {
            const RESERVED_KEYS: &[&str] = &[
                "_HANDLER",
                "_X_AMZN_TRACE_ID",
                "AWS_DEFAULT_REGION",
                "AWS_REGION",
                "AWS_EXECUTION_ENV",
                "AWS_LAMBDA_FUNCTION_NAME",
                "AWS_LAMBDA_FUNCTION_MEMORY_SIZE",
                "AWS_LAMBDA_FUNCTION_VERSION",
                "AWS_LAMBDA_LOG_GROUP_NAME",
                "AWS_LAMBDA_LOG_STREAM_NAME",
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "AWS_LAMBDA_RUNTIME_API",
                "LAMBDA_TASK_ROOT",
                "LAMBDA_RUNTIME_DIR",
                "TZ",
            ];
            for key in env_vars.keys() {
                if RESERVED_KEYS.contains(&key.as_str()) {
                    out.push(make_resource_diagnostic(
                        "E3663",
                        &format!("Environment variable '{}' is a Lambda reserved key", key),
                        m,
                        name,
                        "Properties.Environment.Variables",
                        None,
                    ));
                }
            }
        }
    }

    for name in m.resources_of_type("AWS::Lambda::Function") {
        if resolve_concrete(m, name, "Properties.PackageType")
            .as_ref()
            .and_then(|v| v.as_str())
            == Some("Image")
        {
            for excluded in &["Handler", "Runtime", "Layers"] {
                if resolve_concrete(m, name, &format!("Properties.{}", excluded)).is_some() {
                    out.push(make_resource_diagnostic(
                        "E3685",
                        &format!("'{}' is not allowed when PackageType is 'Image'", excluded),
                        m,
                        name,
                        &format!("Properties.{}", excluded),
                        None,
                    ));
                }
            }
        }
    }

    for name in m.resources_of_type("AWS::ApiGateway::RestApi") {
        let has_body = resolve_concrete(m, name, "Properties.Body").is_some()
            || resolve_concrete(m, name, "Properties.BodyS3Location").is_some();
        if !has_body && resolve_concrete(m, name, "Properties.Name").is_none() {
            out.push(make_resource_diagnostic(
                "E3660",
                "'Name' is required when 'Body' or 'BodyS3Location' is not provided",
                m,
                name,
                "Properties.Name",
                None,
            ));
        }
    }

    for name in m.resources_of_type("AWS::EC2::Volume") {
        if let Some(serde_json::Value::String(vtype)) =
            resolve_concrete(m, name, "Properties.VolumeType")
        {
            let has_iops = resolve_concrete(m, name, "Properties.Iops").is_some();
            match vtype.as_str() {
                "io1" | "io2" if !has_iops => {
                    out.push(make_resource_diagnostic(
                        "E3671",
                        &format!("Iops is required for VolumeType '{}'", vtype),
                        m,
                        name,
                        "Properties.Iops",
                        None,
                    ));
                }
                "gp2" | "standard" | "st1" | "sc1" if has_iops => {
                    out.push(make_resource_diagnostic(
                        "E3671",
                        &format!("Iops is not supported for VolumeType '{}'", vtype),
                        m,
                        name,
                        "Properties.Iops",
                        None,
                    ));
                }
                _ => {}
            }
        }
    }

    for name in m.resources_of_type("AWS::ElastiCache::ReplicationGroup") {
        if resolve_concrete(m, name, "Properties.Engine")
            .as_ref()
            .and_then(|v| v.as_str())
            == Some("valkey")
            && resolve_concrete(m, name, "Properties.TransitEncryptionEnabled").is_none() {
                out.push(make_resource_diagnostic(
                    "E3704",
                    "TransitEncryptionEnabled must be explicitly set when Engine is 'valkey'",
                    m,
                    name,
                    "Properties.TransitEncryptionEnabled",
                    None,
                ));
            }
    }

    const AZ_PATHS: &[(&str, &str)] = &[
        ("AWS::AutoScaling::AutoScalingGroup", "AvailabilityZones.*"),
        ("AWS::DAX::Cluster", "AvailabilityZones.*"),
        ("AWS::DMS::ReplicationInstance", "AvailabilityZone"),
        ("AWS::EC2::Host", "AvailabilityZone"),
        ("AWS::EC2::Instance", "AvailabilityZone"),
        (
            "AWS::EC2::LaunchTemplate",
            "LaunchTemplateData.Placement.AvailabilityZone",
        ),
        (
            "AWS::EC2::SpotFleet",
            "SpotFleetRequestConfigData.LaunchSpecifications.{}.Placement.AvailabilityZone",
        ),
        (
            "AWS::EC2::SpotFleet",
            "SpotFleetRequestConfigData.LaunchTemplateConfigs.{}.Overrides.{}.AvailabilityZone",
        ),
        ("AWS::EC2::Subnet", "AvailabilityZone"),
        ("AWS::EC2::Volume", "AvailabilityZone"),
        (
            "AWS::ElasticLoadBalancing::LoadBalancer",
            "AvailabilityZones.*",
        ),
        (
            "AWS::ElasticLoadBalancingV2::TargetGroup",
            "Targets.{}.AvailabilityZone",
        ),
        ("AWS::EMR::Cluster", "Instances.Placement.AvailabilityZone"),
        (
            "AWS::Glue::Connection",
            "ConnectionInput.PhysicalConnectionRequirements.AvailabilityZone",
        ),
        ("AWS::OpsWorks::Instance", "AvailabilityZone"),
        ("AWS::RDS::DBCluster", "AvailabilityZones.*"),
        ("AWS::RDS::DBInstance", "AvailabilityZone"),
    ];
    for &(rtype, descriptor) in AZ_PATHS {
        for name in m.resources_of_type(rtype) {
            emit_w3010_for_path(&mut out, m, name, descriptor);
        }
    }

    for name in m.resources_of_type("AWS::ECS::Service") {
        if resolve_concrete(m, name, "Properties.LaunchType")
            .as_ref()
            .and_then(|v| v.as_str())
            == Some("FARGATE")
            && resolve_concrete(m, name, "Properties.PlacementConstraints").is_some() {
                out.push(make_resource_diagnostic(
                    "E3048",
                    "PlacementConstraints is not supported with FARGATE launch type",
                    m,
                    name,
                    "Properties.PlacementConstraints",
                    None,
                ));
            }
    }

    // Instance type enum validation per region
    {
        let region = ctx.region.as_deref().unwrap_or(DEFAULT_REGION);
        let enum_checks: &[(&str, &str, &str, &str)] = &[
            (
                "E3628",
                "AWS::EC2::Instance",
                "Properties.InstanceType",
                "data/aws_ec2_instance_instancetype_enum",
            ),
            (
                "E3641",
                "AWS::GameLift::Fleet",
                "Properties.EC2InstanceType",
                "data/aws_gamelift_fleet_ec2instancetype_enum",
            ),
            (
                "E3675",
                "AWS::EMR::InstanceTypeConfig",
                "Properties.InstanceType",
                "data/aws_emr_cluster_instancetypeconfig_instancetype_enum",
            ),
            (
                "E3617",
                "AWS::ManagedBlockchain::Node",
                "Properties.NodeConfiguration.InstanceType",
                "data/aws_managedblockchain_node_nodeconfiguration_instancetype_enum",
            ),
            (
                "E3620",
                "AWS::DocDB::DBInstance",
                "Properties.DBInstanceClass",
                "data/aws_docdb_dbinstance_dbinstanceclass_enum",
            ),
            (
                "E3621",
                "AWS::AppStream::Fleet",
                "Properties.InstanceType",
                "data/aws_appstream_fleet_instancetype_enum",
            ),
            (
                "E3647",
                "AWS::ElastiCache::CacheCluster",
                "Properties.CacheNodeType",
                "data/aws_elasticache_cachecluster_cachenodetype_enum",
            ),
            (
                "E3672",
                "AWS::DAX::Cluster",
                "Properties.NodeType",
                "data/aws_dax_cluster_nodetype_enum",
            ),
            (
                "E3635",
                "AWS::Neptune::DBInstance",
                "Properties.DBInstanceClass",
                "data/aws_neptune_dbinstance_dbinstanceclass_enum",
            ),
            (
                "E3667",
                "AWS::Redshift::Cluster",
                "Properties.NodeType",
                "data/aws_redshift_cluster_nodetype_enum",
            ),
            (
                "E3694",
                "AWS::RDS::DBCluster",
                "Properties.DBClusterInstanceClass",
                "data/aws_rds_dbcluster_dbclusterinstanceclass_enum",
            ),
            (
                "E3640",
                "AWS::SageMaker::DataQualityJobDefinition",
                "Properties.JobResources.ClusterConfig.InstanceType",
                "data/aws_sagemaker_processing_instancetype_enum",
            ),
            (
                "E3640",
                "AWS::SageMaker::ModelBiasJobDefinition",
                "Properties.JobResources.ClusterConfig.InstanceType",
                "data/aws_sagemaker_processing_instancetype_enum",
            ),
            (
                "E3640",
                "AWS::SageMaker::ModelExplainabilityJobDefinition",
                "Properties.JobResources.ClusterConfig.InstanceType",
                "data/aws_sagemaker_processing_instancetype_enum",
            ),
            (
                "E3640",
                "AWS::SageMaker::ModelQualityJobDefinition",
                "Properties.JobResources.ClusterConfig.InstanceType",
                "data/aws_sagemaker_processing_instancetype_enum",
            ),
            (
                "E3640",
                "AWS::SageMaker::MonitoringSchedule",
                "Properties.MonitoringScheduleConfig.MonitoringJobDefinition.MonitoringResources.ClusterConfig.InstanceType",
                "data/aws_sagemaker_processing_instancetype_enum",
            ),
            (
                "E3652",
                "AWS::Elasticsearch::Domain",
                "Properties.ElasticsearchClusterConfig.InstanceType",
                "data/aws_elasticsearch_domain_elasticsearchclusterconfig_instancetype_enum",
            ),
            (
                "E3653",
                "AWS::OpenSearchService::Domain",
                "Properties.ClusterConfig.InstanceType",
                "data/aws_opensearchservice_domain_clusterconfig_instancetype_enum",
            ),
        ];
        for &(rule_id, rtype, prop_path, enum_key) in enum_checks {
            let Some(allowed) =
                region_instance_type_enum(&ctx.cached_data.enum_data, enum_key, region)
            else {
                continue;
            };
            for name in m.resources_of_type(rtype) {
                if let Some(serde_json::Value::String(val)) = resolve_concrete(m, name, prop_path)
                    && !allowed.contains(val.as_str()) {
                        out.push(make_resource_diagnostic(
                            rule_id,
                            &format!("'{}' is not valid for region '{}'", val, region),
                            m,
                            name,
                            prop_path,
                            None,
                        ));
                    }
            }
        }

        let wildcard_enum_checks: &[(&str, &str, &str, &str, &str)] = &[
            (
                "E3642",
                "AWS::SageMaker::InferenceExperiment",
                "Properties.ModelVariants.{}.InfrastructureConfig.RealTimeInferenceConfig.InstanceType",
                "Properties.ModelVariants.InfrastructureConfig.RealTimeInferenceConfig.InstanceType",
                "data/aws_sagemaker_hosting_instancetype_enum",
            ),
            (
                "E3643",
                "AWS::SageMaker::ModelPackage",
                "Properties.ValidationSpecification.ValidationProfiles.{}.TransformJobDefinition.TransformResources.InstanceType",
                "Properties.ValidationSpecification.ValidationProfiles.TransformJobDefinition.TransformResources.InstanceType",
                "data/aws_sagemaker_transform_instancetype_enum",
            ),
            (
                "E3644",
                "AWS::SageMaker::Cluster",
                "Properties.InstanceGroups.{}.InstanceType",
                "Properties.InstanceGroups.InstanceType",
                "data/aws_sagemaker_cluster_instancetype_enum",
            ),
            (
                "E3644",
                "AWS::SageMaker::Cluster",
                "Properties.RestrictedInstanceGroups.{}.InstanceType",
                "Properties.RestrictedInstanceGroups.InstanceType",
                "data/aws_sagemaker_cluster_instancetype_enum",
            ),
        ];
        for &(rule_id, rtype, wildcard_path, report_path, enum_key) in wildcard_enum_checks {
            let Some(allowed) =
                region_instance_type_enum(&ctx.cached_data.enum_data, enum_key, region)
            else {
                continue;
            };
            for name in m.resources_of_type(rtype) {
                let mut reported = HashSet::new();
                for val in resolve_concrete_strings(m, name, wildcard_path) {
                    if allowed.contains(val.as_str()) || !reported.insert(val.clone()) {
                        continue;
                    }
                    out.push(make_resource_diagnostic(
                        rule_id,
                        &format!("'{}' is not valid for region '{}'", val, region),
                        m,
                        name,
                        report_path,
                        None,
                    ));
                }
            }
        }

        if let Some(region_data) = ctx
            .cached_data
            .enum_data
            .get("data/aws_rds_dbinstance_dbinstanceclass_enum")
            .and_then(|v| v.as_object())
            .and_then(|o| o.values().next())
            .and_then(|v| v.as_object())
            .and_then(|o| o.get(region))
        {
            let allowed = extract_enum_values(region_data);
            if !allowed.is_empty() {
                for name in m.resources_of_type("AWS::RDS::DBInstance") {
                    if let Some(serde_json::Value::String(val)) =
                        resolve_concrete(m, name, "Properties.DBInstanceClass")
                        && !allowed.contains(val.as_str()) {
                            out.push(make_resource_diagnostic(
                                "E3025",
                                &format!("DBInstanceClass '{}' is not valid for AWS::RDS::DBInstance in region '{}'", val, region),
                                m, name, "Properties.DBInstanceClass",
                                Some("Use a valid instance class for the configured region"),
                            ));
                        }
                }
            }
        }

        if let Some(region_data) = ctx
            .cached_data
            .enum_data
            .get("data/aws_rds_dbinstance_dbinstanceclass_enum")
            .and_then(|v| v.as_object())
            .and_then(|o| o.values().next())
            .and_then(|v| v.as_object())
            .and_then(|o| o.get(region))
        {
            let allowed = extract_enum_values(region_data);
            if !allowed.is_empty() {
                for name in m.resources_of_type("AWS::Neptune::DBInstance") {
                    if let Some(serde_json::Value::String(val)) =
                        resolve_concrete(m, name, "Properties.DBInstanceClass")
                        && !allowed.contains(val.as_str()) {
                            out.push(make_resource_diagnostic(
                                "E3635",
                                &format!("'{}' is not valid for region '{}'", val, region),
                                m,
                                name,
                                "Properties.DBInstanceClass",
                                None,
                            ));
                        }
                }
            }
        }

        if let Some(region_data) = ctx
            .cached_data
            .enum_data
            .get("data/aws_rds_dbinstance_dbinstanceclass_enum")
            .and_then(|v| v.as_object())
            .and_then(|o| o.values().next())
            .and_then(|v| v.as_object())
            .and_then(|o| o.get(region))
        {
            let allowed = extract_enum_values(region_data);
            if !allowed.is_empty() {
                for name in m.resources_of_type("AWS::Redshift::Cluster") {
                    if let Some(serde_json::Value::String(val)) =
                        resolve_concrete(m, name, "Properties.NodeType")
                        && !allowed.contains(val.as_str()) {
                            out.push(make_resource_diagnostic(
                                "E3667",
                                &format!("'{}' is not valid for region '{}'", val, region),
                                m,
                                name,
                                "Properties.NodeType",
                                None,
                            ));
                        }
                }
            }
        }

        if let Some(region_data) = ctx
            .cached_data
            .enum_data
            .get("data/aws_amazonmq_broker_instancetype_enum")
            .and_then(|v| v.as_object())
            .and_then(|o| o.values().next())
            .and_then(|v| v.as_object())
            .and_then(|o| o.get(region))
            .and_then(|v| v.get("enum"))
            .and_then(|v| v.as_array())
        {
            let allowed: HashSet<&str> = region_data.iter().filter_map(|v| v.as_str()).collect();
            for name in m.resources_of_type("AWS::AmazonMQ::Broker") {
                if let Some(serde_json::Value::String(val)) =
                    resolve_concrete(m, name, "Properties.HostInstanceType")
                    && !allowed.contains(val.as_str()) {
                        out.push(make_resource_diagnostic(
                            "E3670",
                            &format!("'{}' is not valid for region '{}'", val, region),
                            m,
                            name,
                            "Properties.HostInstanceType",
                            None,
                        ));
                    }
            }
        }

        if let Some(region_data) = ctx
            .cached_data
            .enum_data
            .get("data/aws_emr_cluster_instancetypeconfig_instancetype_enum")
            .and_then(|v| v.as_object())
            .and_then(|o| o.values().next())
            .and_then(|v| v.as_object())
            .and_then(|o| o.get(region))
            .and_then(|v| v.get("enum"))
            .and_then(|v| v.as_array())
        {
            let allowed: HashSet<&str> = region_data.iter().filter_map(|v| v.as_str()).collect();
            for name in m.resources_of_type("AWS::EMR::InstanceFleetConfig") {
                if let Some(serde_json::Value::String(val)) =
                    resolve_concrete(m, name, "Properties.InstanceType")
                    && !allowed.contains(val.as_str()) {
                        out.push(make_resource_diagnostic(
                            "E3675",
                            &format!("'{}' is not valid for region '{}'", val, region),
                            m,
                            name,
                            "Properties.InstanceType",
                            None,
                        ));
                    }
            }
        }
    }

    for name in m.resources_of_type("AWS::ElasticLoadBalancingV2::LoadBalancer") {
        let lb_type = resolve_concrete(m, name, "Properties.Type")
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "application".to_string());
        if lb_type == "application"
            && let Some(serde_json::Value::Array(subnets)) =
                resolve_concrete(m, name, "Properties.Subnets")
                && subnets.len() < 2 {
                    out.push(make_resource_diagnostic(
                        "E3680",
                        "Application load balancer requires at least 2 subnets",
                        m,
                        name,
                        "Properties.Subnets",
                        None,
                    ));
                }
    }

    for name in m.resources_of_type("AWS::Route53::RecordSet") {
        if let (
            Some(serde_json::Value::String(rec_name)),
            Some(serde_json::Value::String(hz_name)),
        ) = (
            resolve_concrete(m, name, "Properties.Name"),
            resolve_concrete(m, name, "Properties.HostedZoneName"),
        ) {
            let trimmed_rec = rec_name.trim_end_matches('.');
            let trimmed_hz = hz_name.trim_end_matches('.');
            if trimmed_rec != trimmed_hz
                && !rec_name.ends_with(&*hz_name)
                && !trimmed_rec.ends_with(trimmed_hz)
            {
                out.push(make_resource_diagnostic(
                    "E3041",
                    &format!(
                        "RecordSet Name '{}' is not a subdomain of HostedZoneName '{}'",
                        rec_name, hz_name
                    ),
                    m,
                    name,
                    "Properties.Name",
                    None,
                ));
            }
        }
    }

    for name in m.resources_of_type("AWS::Backup::BackupPlan") {
        if let Some(serde_json::Value::Array(rules)) =
            resolve_concrete(m, name, "Properties.BackupPlan.BackupPlanRule")
        {
            for rule in &rules {
                if let Some(lifecycle) = rule.get("Lifecycle") {
                    let move_days = lifecycle
                        .get("MoveToColdStorageAfterDays")
                        .and_then(|v| v.as_i64());
                    let delete_days = lifecycle.get("DeleteAfterDays").and_then(|v| v.as_i64());
                    if let (Some(m_d), Some(d_d)) = (move_days, delete_days)
                        && m_d >= d_d {
                            out.push(make_resource_diagnostic(
                                "E3504",
                                &format!(
                                    "MoveToColdStorageAfterDays ({}) must be less than DeleteAfterDays ({})",
                                    m_d, d_d
                                ),
                                m,
                                name,
                                "Properties.BackupPlanRule",
                                None,
                            ));
                        }
                }
            }
        }
    }

    // IAM ManagedPolicy — Statement should have Resource when Action is present
    for name in m.resources_of_type("AWS::IAM::ManagedPolicy") {
        if let Some(doc) = resolve_concrete(m, name, "Properties.PolicyDocument")
            && let Some(stmts) = doc.get("Statement").and_then(|s| s.as_array()) {
                for stmt in stmts {
                    if !stmt.is_object() {
                        continue;
                    }
                    if stmt.get("Action").is_some()
                        && stmt.get("Resource").is_none()
                        && stmt.get("NotResource").is_none()
                    {
                        out.push(make_resource_diagnostic(
                            "W3037",
                            "IAM policy statement has Action but no Resource",
                            m,
                            name,
                            "Properties.PolicyDocument",
                            None,
                        ));
                    }
                }
            }
    }

    // Property names must use correct casing
    if let Some(sm) = ctx
        .cached_data
        .schema_metadata()
        .get("schema_metadata")
        .and_then(|s| s.as_object())
    {
        for (name, res) in &m.resources {
            if let Some(type_meta) = sm.get(&res.resource_type).and_then(|t| t.as_object())
                && let Some(serde_json::Value::Array(expected_props)) = type_meta.get("properties")
                {
                    let expected_map: HashMap<String, &str> = expected_props
                        .iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| (s.to_lowercase(), s))
                        .collect();
                    for prop in res.properties.keys() {
                        if let Some(&correct) = expected_map.get(&prop.to_lowercase())
                            && prop != correct {
                                out.push(make_resource_diagnostic(
                                    "E3011",
                                    &format!("Property '{}' should be '{}'", prop, correct),
                                    m,
                                    name,
                                    &format!("Properties.{}", prop),
                                    None,
                                ));
                            }
                    }
                }
        }
    }

    // Route53 RecordSet validation
    for name in m.resources_of_type("AWS::Route53::RecordSet") {
        if let Some(serde_json::Value::String(rtype)) = resolve_concrete(m, name, "Properties.Type")
        {
            match rtype.as_str() {
                "A" => {
                    if let Some(serde_json::Value::Array(records)) =
                        resolve_concrete(m, name, "Properties.ResourceRecords")
                    {
                        for (i, rec) in records.iter().enumerate() {
                            if let Some(s) = rec.as_str()
                                && s.parse::<Ipv4Addr>().is_err() {
                                    out.push(make_resource_diagnostic(
                                        "E3023",
                                        &format!(
                                            "'{}' is not a valid IPv4 address for record type 'A'",
                                            s
                                        ),
                                        m,
                                        name,
                                        &format!("Properties.ResourceRecords.{}", i),
                                        None,
                                    ));
                                }
                        }
                    }
                }
                "AAAA" => {
                    if let Some(serde_json::Value::Array(records)) =
                        resolve_concrete(m, name, "Properties.ResourceRecords")
                    {
                        for (i, rec) in records.iter().enumerate() {
                            if let Some(s) = rec.as_str()
                                && s.parse::<Ipv6Addr>().is_err() {
                                    out.push(make_resource_diagnostic(
                                        "E3023",
                                        &format!("'{}' is not a valid IPv6 address for record type 'AAAA'", s),
                                        m, name,
                                        &format!("Properties.ResourceRecords.{}", i),
                                        None,
                                    ));
                                }
                        }
                    }
                }
                "CNAME" => {
                    if let (
                        Some(serde_json::Value::String(rec_name)),
                        Some(serde_json::Value::String(hz_name)),
                    ) = (
                        resolve_concrete(m, name, "Properties.Name"),
                        resolve_concrete(m, name, "Properties.HostedZoneName"),
                    ) {
                        let trimmed_rec = rec_name.trim_end_matches('.');
                        let trimmed_hz = hz_name.trim_end_matches('.');
                        if trimmed_rec == trimmed_hz {
                            out.push(make_resource_diagnostic(
                                "E3023",
                                &format!(
                                    "CNAME record Name '{}' must not match HostedZoneName '{}' exactly",
                                    rec_name, hz_name
                                ),
                                m, name, "Properties.Name", None,
                            ));
                        }
                    }
                    if let Some(serde_json::Value::Array(records)) =
                        resolve_concrete(m, name, "Properties.ResourceRecords")
                        && records.len() > 1 {
                            out.push(make_resource_diagnostic(
                                "E3023",
                                "CNAME records must have at most 1 ResourceRecord",
                                m,
                                name,
                                "Properties.ResourceRecords",
                                None,
                            ));
                        }
                }
                "TXT" => {
                    let txt_re = regex::Regex::new(r#"^("[^"]{1,255}" *)*"[^"]{1,255}"$"#).unwrap();
                    if let Some(serde_json::Value::Array(records)) =
                        resolve_concrete(m, name, "Properties.ResourceRecords")
                    {
                        for (i, rec) in records.iter().enumerate() {
                            if let Some(s) = rec.as_str()
                                && !txt_re.is_match(s) {
                                    out.push(make_resource_diagnostic(
                                        "E3023",
                                        &format!("TXT record value '{}' must be enclosed in double quotes", s),
                                        m, name, &format!("Properties.ResourceRecords.{}", i), None,
                                    ));
                                }
                        }
                    }
                }
                "CAA" => {
                    let caa_re = regex::Regex::new(r#"^(0|128)\s+[a-zA-Z0-9]+\s+".+"$"#).unwrap();
                    if let Some(serde_json::Value::Array(records)) =
                        resolve_concrete(m, name, "Properties.ResourceRecords")
                    {
                        for (i, rec) in records.iter().enumerate() {
                            if let Some(s) = rec.as_str()
                                && !caa_re.is_match(s) {
                                    out.push(make_resource_diagnostic(
                                        "E3023",
                                        &format!("CAA record value '{}' must match format: flag tag \"value\"", s),
                                        m, name, &format!("Properties.ResourceRecords.{}", i), None,
                                    ));
                                }
                        }
                    }
                }
                "MX" => {
                    let mx_re = regex::Regex::new(r"^\d+\s+\S+$").unwrap();
                    if let Some(serde_json::Value::Array(records)) =
                        resolve_concrete(m, name, "Properties.ResourceRecords")
                    {
                        for (i, rec) in records.iter().enumerate() {
                            if let Some(s) = rec.as_str()
                                && !mx_re.is_match(s) {
                                    out.push(make_resource_diagnostic(
                                        "E3023",
                                        &format!("MX record value '{}' must match format: priority domain", s),
                                        m, name, &format!("Properties.ResourceRecords.{}", i), None,
                                    ));
                                }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // RecordSetGroup — validate records within RecordSets[]
    for name in m.resources_of_type("AWS::Route53::RecordSetGroup") {
        if let Some(serde_json::Value::Array(rsets)) =
            resolve_concrete(m, name, "Properties.RecordSets")
        {
            let txt_re = regex::Regex::new(r#"^("[^"]{1,255}" *)*"[^"]{1,255}"$"#).unwrap();
            let caa_re = regex::Regex::new(r#"^(0|128)\s+[a-zA-Z0-9]+\s+".+"$"#).unwrap();
            let mx_re = regex::Regex::new(r"^\d+\s+\S+$").unwrap();
            for (si, rset) in rsets.iter().enumerate() {
                let rtype = rset.get("Type").and_then(|t| t.as_str()).unwrap_or("");
                let records = rset.get("ResourceRecords").and_then(|r| r.as_array());
                if let Some(records) = records {
                    for (ri, rec) in records.iter().enumerate() {
                        if let Some(s) = rec.as_str() {
                            let path =
                                format!("Properties.RecordSets.{}.ResourceRecords.{}", si, ri);
                            match rtype {
                                "A" => {
                                    if s.parse::<Ipv4Addr>().is_err() {
                                        out.push(make_resource_diagnostic("E3023",
                                            &format!("'{}' is not a valid IPv4 address for record type 'A'", s),
                                            m, name, &path, None));
                                    }
                                }
                                "AAAA" => {
                                    if s.parse::<Ipv6Addr>().is_err() {
                                        out.push(make_resource_diagnostic("E3023",
                                            &format!("'{}' is not a valid IPv6 address for record type 'AAAA'", s),
                                            m, name, &path, None));
                                    }
                                }
                                "TXT" => {
                                    if !txt_re.is_match(s) {
                                        out.push(make_resource_diagnostic("E3023",
                                            &format!("TXT record value '{}' must be enclosed in double quotes", s),
                                            m, name, &path, None));
                                    }
                                }
                                "CAA" => {
                                    if !caa_re.is_match(s) {
                                        out.push(make_resource_diagnostic("E3023",
                                            &format!("CAA record value '{}' must match format: flag tag \"value\"", s),
                                            m, name, &path, None));
                                    }
                                }
                                "MX" => {
                                    if !mx_re.is_match(s) {
                                        out.push(make_resource_diagnostic("E3023",
                                            &format!("MX record value '{}' must match format: priority domain", s),
                                            m, name, &path, None));
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    if rtype == "CNAME" && records.len() > 1 {
                        out.push(make_resource_diagnostic(
                            "E3023",
                            "CNAME records must have at most 1 ResourceRecord",
                            m,
                            name,
                            &format!("Properties.RecordSets.{}.ResourceRecords", si),
                            None,
                        ));
                    }
                }
            }
        }
    }

    // ElastiCache Redis replication group failover
    for name in m.resources_of_type("AWS::ElastiCache::ReplicationGroup") {
        if resolve_concrete(m, name, "Properties.Engine")
            .as_ref()
            .and_then(|v| v.as_str())
            == Some("redis")
        {
            // NumCacheClusters is ignored when NumNodeGroups is specified
            if resolve_concrete(m, name, "Properties.NumNodeGroups").is_some() {
                continue;
            }
            if let Some(num) =
                resolve_concrete(m, name, "Properties.NumCacheClusters").and_then(|v| v.as_i64())
                && num > 1 {
                    let failover_rv = m
                        .resolve_deep(name, "Properties.AutomaticFailoverEnabled")
                        .or_else(|| {
                            m.resolve(name, "Properties.AutomaticFailoverEnabled")
                                .cloned()
                        });
                    let is_definitely_not_true = match &failover_rv {
                        None => true,
                        Some(ResolvedValue::Concrete { value: v }) => v.as_bool() != Some(true),
                        _ => false,
                    };
                    if is_definitely_not_true {
                        out.push(make_resource_diagnostic(
                            "E3026",
                            "AutomaticFailoverEnabled must be true when NumCacheClusters > 1 and Engine is 'redis'",
                            m, name, "Properties.AutomaticFailoverEnabled", None,
                        ));
                    }
                }
        }
    }

    // Events Rule ScheduleExpression validation
    for name in m.resources_of_type("AWS::Events::Rule") {
        if let Some(serde_json::Value::String(val)) =
            resolve_concrete(m, name, "Properties.ScheduleExpression")
        {
            if !val.starts_with("rate(") && !val.starts_with("cron(") {
                out.push(make_resource_diagnostic(
                    "E3027",
                    &format!(
                        "ScheduleExpression '{}' must be a rate() or cron() expression",
                        val
                    ),
                    m,
                    name,
                    "Properties.ScheduleExpression",
                    None,
                ));
            } else if val.starts_with("rate(") && !RATE_RE.is_match(&val) {
                out.push(make_resource_diagnostic(
                    "E3027",
                    &format!("rate() expression '{}' must have format 'rate(value unit)' where unit is minute(s)|hour(s)|day(s)", val),
                    m, name, "Properties.ScheduleExpression", None,
                ));
            } else if val.starts_with("cron(") && val.ends_with(')') {
                let inner = &val[5..val.len() - 1];
                let fields = inner.split_whitespace().count();
                if fields != 6 {
                    out.push(make_resource_diagnostic(
                        "E3027",
                        &format!("cron() expression '{}' must have exactly 6 fields", val),
                        m,
                        name,
                        "Properties.ScheduleExpression",
                        None,
                    ));
                }
            }
        }
    }

    // Route53 RecordSet Alias validation
    for name in m.resources_of_type("AWS::Route53::RecordSet") {
        let has_alias = resolve_concrete(m, name, "Properties.AliasTarget").is_some();
        if has_alias {
            if resolve_concrete(m, name, "Properties.TTL").is_some() {
                out.push(make_resource_diagnostic(
                    "E3029",
                    "TTL must not be set when AliasTarget is specified",
                    m,
                    name,
                    "Properties.TTL",
                    None,
                ));
            }
            if let Some(serde_json::Value::String(rtype)) =
                resolve_concrete(m, name, "Properties.Type")
                && rtype != "A" && rtype != "AAAA" {
                    out.push(make_resource_diagnostic(
                        "E3029",
                        &format!("AliasTarget cannot be used with record type '{}'", rtype),
                        m,
                        name,
                        "Properties.AliasTarget",
                        None,
                    ));
                }
        }
    }

    // RDS DBInstance class validation by Engine/EngineVersion
    if let Some(rds_data) = ctx
        .cached_data
        .enum_data
        .get("data/aws_rds_dbinstance_db_instance_class")
        .and_then(|v| v.as_object())
        .and_then(|o| o.values().next())
        .and_then(|v| v.get("allOf"))
        .and_then(|v| v.as_array())
    {
        for name in m.resources_of_type("AWS::RDS::DBInstance") {
            let engine = resolve_concrete(m, name, "Properties.Engine").and_then(|v| {
                if let serde_json::Value::String(s) = v {
                    Some(s)
                } else {
                    None
                }
            });
            let engine_ver =
                resolve_concrete(m, name, "Properties.EngineVersion").and_then(|v| match v {
                    serde_json::Value::String(s) => Some(s),
                    serde_json::Value::Number(n) => Some(n.to_string()),
                    _ => None,
                });
            let db_class = resolve_concrete(m, name, "Properties.DBInstanceClass").and_then(|v| {
                if let serde_json::Value::String(s) = v {
                    Some(s)
                } else {
                    None
                }
            });
            if let (Some(eng), Some(ver), Some(cls)) = (engine, engine_ver, db_class) {
                for entry in rds_data {
                    let cond = match entry.get("if").and_then(|v| v.get("properties")) {
                        Some(p) => p,
                        None => continue,
                    };
                    let eng_match = cond
                        .get("Engine")
                        .and_then(|e| e.get("const"))
                        .and_then(|c| c.as_str())
                        .map(|c| c == eng)
                        .unwrap_or(false);
                    if !eng_match {
                        continue;
                    }
                    let ver_match = cond
                        .get("EngineVersion")
                        .and_then(|e| e.get("pattern"))
                        .and_then(|p| p.as_str())
                        .and_then(|p| regex::Regex::new(p).ok())
                        .map(|re| re.is_match(&ver))
                        .unwrap_or(false);
                    if !ver_match {
                        continue;
                    }
                    if let Some(allowed) = entry
                        .get("then")
                        .and_then(|t| t.get("properties"))
                        .and_then(|p| p.get("DBInstanceClass"))
                        .and_then(|d| d.get("enum"))
                        .and_then(|e| e.as_array())
                    {
                        let allowed_set: HashSet<&str> =
                            allowed.iter().filter_map(|v| v.as_str()).collect();
                        if !allowed_set.contains(cls.as_str()) {
                            out.push(make_resource_diagnostic(
                                "E3062",
                                &format!(
                                    "DBInstanceClass '{}' is not valid for Engine '{}' EngineVersion '{}'",
                                    cls, eng, ver
                                ),
                                m, name, "Properties.DBInstanceClass", None,
                            ));
                        }
                    }
                    break;
                }
            }
        }
    }

    // W3002: Properties that only work with `aws cloudformation package`
    // The parent property (e.g. Code, Content, TemplateURL) is checked as a string.
    // If the value is a string not starting with s3:// or https://, it warns.
    // SAM templates are excluded entirely.
    if !m.transforms.iter().any(|t| t == TRANSFORM_SERVERLESS) {
        const PACKAGE_PROPS: &[(&str, &[&str])] = &[
            ("AWS::Lambda::Function", &["Code"]),
            ("AWS::Lambda::LayerVersion", &["Content"]),
            (
                "AWS::ElasticBeanstalk::ApplicationVersion",
                &["SourceBundle"],
            ),
            (
                "AWS::StepFunctions::StateMachine",
                &["DefinitionS3Location"],
            ),
            ("AWS::AppSync::GraphQLSchema", &["DefinitionS3Location"]),
            (
                "AWS::AppSync::Resolver",
                &[
                    "RequestMappingTemplateS3Location",
                    "ResponseMappingTemplateS3Location",
                ],
            ),
            (
                "AWS::AppSync::FunctionConfiguration",
                &[
                    "RequestMappingTemplateS3Location",
                    "ResponseMappingTemplateS3Location",
                ],
            ),
            ("AWS::CloudFormation::Stack", &["TemplateURL"]),
            ("AWS::CodeCommit::Repository", &["Code.S3"]),
            ("AWS::ApiGateway::RestApi", &["BodyS3Location"]),
        ];
        for (rtype, props) in PACKAGE_PROPS {
            for name in m.resources_of_type(rtype) {
                for prop in *props {
                    let path = format!("Properties.{}", prop);
                    if let Some(serde_json::Value::String(val)) = resolve_concrete(m, name, &path) {
                        if val.starts_with("s3://") || val.starts_with("https://") {
                            continue;
                        }
                        out.push(make_resource_diagnostic(
                            "W3002",
                            "This code may only work with 'package' cli command",
                            m,
                            name,
                            &path,
                            None,
                        ));
                    }
                }
            }
        }
    }

    // API Gateway mixing inline definitions with external Body
    {
        let apigw_resource_types = [
            "AWS::ApiGateway::Method",
            "AWS::ApiGateway::Stage",
            "AWS::ApiGateway::Deployment",
        ];
        let mut rest_api_refs: HashMap<String, Vec<String>> = HashMap::new();
        for rtype in &apigw_resource_types {
            for name in m.resources_of_type(rtype) {
                if let Some(api_id) = m.follow_ref(name, "Properties.RestApiId") {
                    rest_api_refs
                        .entry(api_id.to_string())
                        .or_default()
                        .push(name.to_string());
                }
            }
        }
        for (api_id, referrers) in &rest_api_refs {
            if referrers.is_empty() {
                continue;
            }
            let has_body = resolve_concrete(m, api_id, "Properties.Body").is_some()
                || resolve_concrete(m, api_id, "Properties.BodyS3Location").is_some();
            if has_body {
                for referrer in referrers {
                    out.push(make_resource_diagnostic(
                        "W3660",
                        &format!(
                            "Resource references RestApi '{}' which has Body/BodyS3Location — mixing inline definitions with external body",
                            api_id
                        ),
                        m, referrer, "Properties.RestApiId", None,
                    ));
                }
            }
        }
    }

    // Lambda Permission Principal/SourceArn consistency
    for name in m.resources_of_type("AWS::Lambda::Permission") {
        if let Some(serde_json::Value::String(principal)) =
            resolve_concrete(m, name, "Properties.Principal")
            && let Some(target) = m.follow_ref(name, "Properties.SourceArn")
                && let Some(target_res) = m.resources.get(target) {
                    match principal.as_str() {
                        "sns.amazonaws.com" if target_res.resource_type != "AWS::SNS::Topic" => {
                            out.push(make_resource_diagnostic(
                                "W3664",
                                &format!(
                                    "SourceArn references '{}' (type '{}') but Principal 'sns.amazonaws.com' expects an SNS Topic",
                                    target, target_res.resource_type
                                ),
                                m, name, "Properties.SourceArn", None,
                            ));
                        }
                        "s3.amazonaws.com" if target_res.resource_type != "AWS::S3::Bucket" => {
                            out.push(make_resource_diagnostic(
                                "W3664",
                                &format!(
                                    "SourceArn references '{}' (type '{}') but Principal 's3.amazonaws.com' expects an S3 Bucket",
                                    target, target_res.resource_type
                                ),
                                m, name, "Properties.SourceArn", None,
                            ));
                        }
                        _ => {}
                    }
                }
    }

    // EBS Iops silently ignored for certain volume types
    {
        const IOPS_IGNORED_TYPES: &[&str] = &["gp2", "st1", "sc1", "standard"];
        const BDM_RESOURCE_TYPES: &[(&str, &str)] = &[
            ("AWS::EC2::Instance", "Properties.BlockDeviceMappings"),
            (
                "AWS::EC2::LaunchTemplate",
                "Properties.LaunchTemplateData.BlockDeviceMappings",
            ),
            (
                "AWS::EC2::SpotFleet",
                "Properties.SpotFleetRequestConfigData.LaunchSpecifications",
            ),
            (
                "AWS::AutoScaling::LaunchConfiguration",
                "Properties.BlockDeviceMappings",
            ),
            ("AWS::OpsWorks::Instance", "Properties.BlockDeviceMappings"),
        ];
        for (rtype, base_path) in BDM_RESOURCE_TYPES {
            for name in m.resources_of_type(rtype) {
                if *rtype == "AWS::EC2::SpotFleet" {
                    // SpotFleet has nested launch specs
                    if let Some(serde_json::Value::Array(specs)) =
                        resolve_concrete(m, name, base_path)
                    {
                        for (si, spec) in specs.iter().enumerate() {
                            if let Some(bdms) =
                                spec.get("BlockDeviceMappings").and_then(|b| b.as_array())
                            {
                                check_bdm_iops_ignored(
                                    &mut out,
                                    m,
                                    name,
                                    bdms,
                                    &format!("{}.{}.BlockDeviceMappings", base_path, si),
                                    "W3671",
                                    IOPS_IGNORED_TYPES,
                                );
                            }
                        }
                    }
                } else if let Some(serde_json::Value::Array(bdms)) =
                    resolve_concrete(m, name, base_path)
                {
                    check_bdm_iops_ignored(
                        &mut out,
                        m,
                        name,
                        &bdms,
                        base_path,
                        "W3671",
                        IOPS_IGNORED_TYPES,
                    );
                }
            }
        }
    }

    // RDS DBCluster — SnapshotIdentifier makes MasterUsername ignored
    for name in m.resources_of_type("AWS::RDS::DBCluster") {
        if resolve_concrete(m, name, "Properties.SnapshotIdentifier").is_some()
            && resolve_concrete(m, name, "Properties.MasterUsername").is_some() {
                out.push(make_resource_diagnostic(
                    "W3688",
                    "MasterUsername is ignored when SnapshotIdentifier is present",
                    m,
                    name,
                    "Properties.MasterUsername",
                    None,
                ));
            }
    }

    // RDS DBCluster — SourceDBClusterIdentifier makes several properties ignored
    for name in m.resources_of_type("AWS::RDS::DBCluster") {
        if resolve_concrete(m, name, "Properties.SourceDBClusterIdentifier").is_some() {
            for ignored in &["MasterUserPassword", "MasterUsername", "StorageEncrypted"] {
                if resolve_concrete(m, name, &format!("Properties.{}", ignored)).is_some() {
                    out.push(make_resource_diagnostic(
                        "W3689",
                        &format!(
                            "'{}' is ignored when SourceDBClusterIdentifier is present",
                            ignored
                        ),
                        m,
                        name,
                        &format!("Properties.{}", ignored),
                        None,
                    ));
                }
            }
        }
    }

    // RDS DBCluster — Aurora serverless ignores PerformanceInsights properties
    for name in m.resources_of_type("AWS::RDS::DBCluster") {
        let engine = resolve_concrete(m, name, "Properties.Engine").and_then(|v| {
            if let serde_json::Value::String(s) = v {
                Some(s)
            } else {
                None
            }
        });
        let engine_mode = resolve_concrete(m, name, "Properties.EngineMode").and_then(|v| {
            if let serde_json::Value::String(s) = v {
                Some(s)
            } else {
                None
            }
        });
        if let (Some(eng), Some(mode)) = (engine, engine_mode)
            && (eng == "aurora-mysql" || eng == "aurora-postgresql") && mode == "serverless" {
                for ignored in &[
                    "PerformanceInsightsEnabled",
                    "PerformanceInsightsKmsKeyId",
                    "PerformanceInsightsRetentionPeriod",
                ] {
                    if resolve_concrete(m, name, &format!("Properties.{}", ignored)).is_some() {
                        out.push(make_resource_diagnostic(
                            "W3693",
                            &format!("'{}' is ignored when EngineMode is 'serverless'", ignored),
                            m,
                            name,
                            &format!("Properties.{}", ignored),
                            None,
                        ));
                    }
                }
            }
    }

    // SNS Subscription Protocol/Endpoint consistency
    for name in m.resources_of_type("AWS::SNS::Subscription") {
        if let Some(serde_json::Value::String(protocol)) =
            resolve_concrete(m, name, "Properties.Protocol")
            && let Some(target) = m.follow_ref(name, "Properties.Endpoint")
                && let Some(target_res) = m.resources.get(target) {
                    match protocol.as_str() {
                        "sqs" if target_res.resource_type != "AWS::SQS::Queue" => {
                            out.push(make_resource_diagnostic(
                                "W3694",
                                &format!(
                                    "Endpoint references '{}' (type '{}') but Protocol 'sqs' expects an SQS Queue",
                                    target, target_res.resource_type
                                ),
                                m, name, "Properties.Endpoint", None,
                            ));
                        }
                        "lambda" if target_res.resource_type != "AWS::Lambda::Function" => {
                            out.push(make_resource_diagnostic(
                                "W3694",
                                &format!(
                                    "Endpoint references '{}' (type '{}') but Protocol 'lambda' expects a Lambda Function",
                                    target, target_res.resource_type
                                ),
                                m, name, "Properties.Endpoint", None,
                            ));
                        }
                        _ => {}
                    }
                }
    }

    // VirtualName ignored when Ebs is specified in block device mappings
    {
        const BDM_RESOURCE_TYPES_W3698: &[(&str, &str)] = &[
            ("AWS::EC2::Instance", "Properties.BlockDeviceMappings"),
            (
                "AWS::EC2::LaunchTemplate",
                "Properties.LaunchTemplateData.BlockDeviceMappings",
            ),
            (
                "AWS::EC2::SpotFleet",
                "Properties.SpotFleetRequestConfigData.LaunchSpecifications",
            ),
            (
                "AWS::AutoScaling::LaunchConfiguration",
                "Properties.BlockDeviceMappings",
            ),
            ("AWS::OpsWorks::Instance", "Properties.BlockDeviceMappings"),
        ];
        for (rtype, base_path) in BDM_RESOURCE_TYPES_W3698 {
            for name in m.resources_of_type(rtype) {
                if *rtype == "AWS::EC2::SpotFleet" {
                    if let Some(serde_json::Value::Array(specs)) =
                        resolve_concrete(m, name, base_path)
                    {
                        for (si, spec) in specs.iter().enumerate() {
                            if let Some(bdms) =
                                spec.get("BlockDeviceMappings").and_then(|b| b.as_array())
                            {
                                check_bdm_virtualname_ignored(
                                    &mut out,
                                    m,
                                    name,
                                    bdms,
                                    &format!("{}.{}.BlockDeviceMappings", base_path, si),
                                );
                            }
                        }
                    }
                } else {
                    // Concrete resolution handles the common non-conditional case.
                    if let Some(serde_json::Value::Array(bdms)) =
                        resolve_concrete(m, name, base_path)
                    {
                        check_bdm_virtualname_ignored(&mut out, m, name, &bdms, base_path);
                    } else {
                        // Fall back to conditional branch traversal for E3715 only
                        let bdm_arrays = resolve_all_json(m, name, base_path);
                        for bdms_val in &bdm_arrays {
                            if let serde_json::Value::Array(bdms) = bdms_val {
                                for (i, bdm) in bdms.iter().enumerate() {
                                    if let Some(vname) =
                                        bdm.get("VirtualName").and_then(|v| v.as_str())
                                        && bdm.get("Ebs").is_none() && !EPHEMERAL_RE.is_match(vname)
                                        {
                                            out.push(make_resource_diagnostic(
                                                "E3715",
                                                &format!("'{}' is not a valid ephemeral device name. Expected format is 'ephemeralN' where N is 0-23", vname),
                                                m, name,
                                                &format!("{}.{}.VirtualName", base_path, i),
                                                None,
                                            ));
                                        }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    out
}

fn check_bdm_iops_ignored(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    name: &str,
    bdms: &[serde_json::Value],
    base_path: &str,
    rule_id: &str,
    ignored_types: &[&str],
) {
    for (i, bdm) in bdms.iter().enumerate() {
        if let Some(ebs) = bdm.get("Ebs")
            && ebs.get("Iops").is_some()
                && let Some(vtype) = ebs.get("VolumeType").and_then(|v| v.as_str())
                    && ignored_types.contains(&vtype) {
                        out.push(make_resource_diagnostic(
                            rule_id,
                            &format!("Iops is ignored when VolumeType is '{}'", vtype),
                            m,
                            name,
                            &format!("{}.{}.Ebs.Iops", base_path, i),
                            None,
                        ));
                    }
    }
}

static EPHEMERAL_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^ephemeral([0-9]|1[0-9]|2[0-3])$").expect("Invalid EPHEMERAL_RE")
});

fn check_bdm_virtualname_ignored(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    name: &str,
    bdms: &[serde_json::Value],
    base_path: &str,
) {
    for (i, bdm) in bdms.iter().enumerate() {
        let has_vname = bdm.get("VirtualName");
        let has_ebs = bdm.get("Ebs").is_some();
        if let Some(vname_val) = has_vname {
            if has_ebs {
                out.push(make_resource_diagnostic(
                    "W3698",
                    "VirtualName is ignored when Ebs is specified",
                    m,
                    name,
                    &format!("{}.{}.VirtualName", base_path, i),
                    None,
                ));
            } else if let Some(vname) = vname_val.as_str()
                && !EPHEMERAL_RE.is_match(vname) {
                    out.push(make_resource_diagnostic(
                        "E3715",
                        &format!("'{}' is not a valid ephemeral device name. Expected format is 'ephemeralN' where N is 0-23", vname),
                        m, name,
                        &format!("{}.{}.VirtualName", base_path, i),
                        None,
                    ));
                }
        }
    }
}

fn extract_enum_values(region_data: &serde_json::Value) -> HashSet<&str> {
    let mut vals = HashSet::new();
    if let Some(arr) = region_data.get("enum").and_then(|v| v.as_array()) {
        vals.extend(arr.iter().filter_map(|v| v.as_str()));
    }
    if let Some(all_of) = region_data.get("allOf").and_then(|v| v.as_array()) {
        for item in all_of {
            if let Some(arr) = item.get("enum").and_then(|v| v.as_array()) {
                vals.extend(arr.iter().filter_map(|v| v.as_str()));
            }
        }
    }
    vals
}

/// Valid instance-type/class enum values for `region`, or `None` when the
/// document has no entry for that region.
fn region_instance_type_enum<'a>(
    enum_data: &'a HashMap<String, serde_json::Value>,
    enum_key: &str,
    region: &str,
) -> Option<HashSet<&'a str>> {
    let values = enum_data
        .get(enum_key)?
        .as_object()?
        .values()
        .next()? // unwrap the single top-level document key to reach the region map
        .as_object()?
        .get(region)?
        .get("enum")?
        .as_array()?;
    Some(values.iter().filter_map(|v| v.as_str()).collect())
}

fn resolve_concrete_strings(m: &SemanticModel, rid: &str, path: &str) -> Vec<String> {
    let Some(resolved) = m
        .resolve_deep(rid, path)
        .or_else(|| m.resolve(rid, path).cloned())
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_concrete_strings(&resolved, &mut out);
    out
}

fn collect_concrete_strings(value: &ResolvedValue, out: &mut Vec<String>) {
    match value {
        ResolvedValue::Concrete { value: v } => {
            if let Some(s) = v.0.as_str() {
                out.push(s.to_string());
            }
        }
        ResolvedValue::Enum { variants } => {
            for variant in variants {
                collect_concrete_strings(variant, out);
            }
        }
        ResolvedValue::List { items } => {
            for item in items {
                collect_concrete_strings(item, out);
            }
        }
        ResolvedValue::Conditional {
            if_true, if_false, ..
        } => {
            collect_concrete_strings(if_true, out);
            collect_concrete_strings(if_false, out);
        }
        _ => {}
    }
}

fn emit_w3010_for_path(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    name: &str,
    descriptor: &str,
) {
    let segments: Vec<&str> = descriptor.split('.').collect();
    walk_w3010(out, m, name, &segments, 0, KEY_PROPERTIES.to_string());
}

fn walk_w3010(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    name: &str,
    segments: &[&str],
    idx: usize,
    path: String,
) {
    if idx == segments.len() {
        // Scalar leaf: path resolves to a string AZ.
        if m.is_from_intrinsic(name, &path) {
            return;
        }
        if let Some(s) = resolve_concrete_string(m, name, &path)
            && AZ_RE.is_match(&s) {
                out.push(make_resource_diagnostic(
                    "W3010",
                    &format!("Avoid hardcoding availability zones '{}'", s),
                    m,
                    name,
                    &path,
                    None,
                ));
            }
        return;
    }
    let seg = segments[idx];
    if seg == "*" {
        // Leaf list: enumerate items of the current path.
        if m.is_from_intrinsic(name, &path) {
            return;
        }
        let Some(len) = resolve_array_len_any(m, name, &path) else {
            return;
        };
        for i in 0..len {
            let item_path = format!("{}.{}", path, i);
            if m.is_from_intrinsic(name, &item_path) {
                continue;
            }
            if let Some(s) = resolve_concrete_string(m, name, &item_path)
                && AZ_RE.is_match(&s) {
                    out.push(make_resource_diagnostic(
                        "W3010",
                        &format!("Avoid hardcoding availability zones '{}'", s),
                        m,
                        name,
                        &item_path,
                        None,
                    ));
                }
        }
    } else if seg == "{}" {
        // Intermediate list wildcard: recurse into each index.
        let Some(len) = resolve_array_len_any(m, name, &path) else {
            return;
        };
        for i in 0..len {
            walk_w3010(out, m, name, segments, idx + 1, format!("{}.{}", path, i));
        }
    } else {
        walk_w3010(out, m, name, segments, idx + 1, format!("{}.{}", path, seg));
    }
}

fn resolve_concrete_string(m: &Arc<SemanticModel>, name: &str, path: &str) -> Option<String> {
    let rv = m
        .resolve_deep(name, path)
        .or_else(|| m.resolve(name, path).cloned())?;
    match rv {
        ResolvedValue::Concrete { value: v } => v.as_str().map(str::to_string),
        _ => None,
    }
}

fn resolve_array_len_any(m: &Arc<SemanticModel>, name: &str, path: &str) -> Option<usize> {
    let rv = m
        .resolve_deep(name, path)
        .or_else(|| m.resolve(name, path).cloned())?;
    match rv {
        ResolvedValue::Concrete { value: v } => v.as_array().map(|a| a.len()),
        ResolvedValue::List { items } => Some(items.len()),
        _ => None,
    }
}

/// Renders `{'Prop1': 'val1', 'Prop2': 'val2'}` in Python `repr` style for duplicate-identifier messages.
fn render_primary_id_dict(props: &[String], values: &[String]) -> String {
    let pairs: Vec<String> = props
        .iter()
        .zip(values.iter())
        .map(|(p, v)| format!("'{}': '{}'", p, v))
        .collect();
    format!("{{{}}}", pairs.join(", "))
}

/// Renders `{'A', 'B'}` in Python repr style for a Python set of resource names.
/// Python `repr(set)` uses iteration order; we sort for determinism across engines.
fn render_resource_set(names: &BTreeSet<String>) -> String {
    let quoted: Vec<String> = names.iter().map(|n| format!("'{}'", n)).collect();
    format!("{{{}}}", quoted.join(", "))
}

/// needed to detect primary-identifier duplication across templates that
/// switch the identifier on a condition (e.g. `!If [cond, "x", !Ref AWS::NoValue]`).
fn collect_concrete_scenarios(
    m: &Arc<SemanticModel>,
    rid: &str,
    path: &str,
) -> Vec<serde_json::Value> {
    let rv = match m
        .resolve_deep(rid, path)
        .or_else(|| m.resolve(rid, path).cloned())
    {
        Some(v) => v,
        None => {
            // `Properties` wrapped in `Fn::If` stores values only under the
            // synthetic branch path; scenario resolution exposes them for
            // callers that walk by property name.
            let scenarios = m.resolve_scenarios_json(rid, path);
            return scenarios.into_iter().map(|(v, _)| v).collect();
        }
    };
    let mut out = Vec::new();
    push_concrete_leaves(&rv, &mut out);
    out
}

fn push_concrete_leaves(rv: &ResolvedValue, out: &mut Vec<serde_json::Value>) {
    match rv {
        ResolvedValue::Concrete { value: v } => out.push(v.0.clone()),
        ResolvedValue::Enum { variants } => {
            for v in variants {
                push_concrete_leaves(v, out);
            }
        }
        ResolvedValue::Conditional {
            if_true, if_false, ..
        } => {
            push_concrete_leaves(if_true, out);
            push_concrete_leaves(if_false, out);
        }
        // List/Map/Reference/Dynamic: no scalar concrete value to contribute.
        _ => {}
    }
}

fn resolved_to_json_best_effort(rv: &ResolvedValue) -> serde_json::Value {
    match rv {
        ResolvedValue::Concrete { value: v } => v.0.clone(),
        ResolvedValue::List { items } => {
            serde_json::Value::Array(items.iter().map(resolved_to_json_best_effort).collect())
        }
        ResolvedValue::Map { entries } => {
            let mut map = serde_json::Map::new();
            for e in entries {
                map.insert(e.key.clone(), resolved_to_json_best_effort(&e.value));
            }
            serde_json::Value::Object(map)
        }
        ResolvedValue::Enum { variants } => {
            for v in variants {
                if let ResolvedValue::Concrete { value: c } = v {
                    return c.0.clone();
                }
            }
            serde_json::Value::Null
        }
        ResolvedValue::Conditional { if_true, .. } => resolved_to_json_best_effort(if_true),
        ResolvedValue::Reference { target, .. } => serde_json::json!({(FN_REF): target}),
        ResolvedValue::Dynamic { .. } | ResolvedValue::TypedDynamic { .. } => {
            serde_json::Value::Null
        }
    }
}

fn arn_matches_pattern(arn: &str, pattern: &str) -> bool {
    let arn_parts: Vec<&str> = arn.split(':').collect();
    let pat_parts: Vec<&str> = pattern.split(':').collect();
    if arn_parts.len() < 6 || pat_parts.len() < 6 {
        return false;
    }
    arn_parts
        .iter()
        .zip(pat_parts.iter())
        .all(|(a, p)| *p == "*" || *p == *a)
}

fn check_iam_action_resources(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    name: &str,
    doc: &serde_json::Value,
    path: &str,
    patterns: &HashMap<String, String>,
) {
    let stmts = match doc.get("Statement").and_then(|s| s.as_array()) {
        Some(s) => s,
        None => return,
    };
    for stmt in stmts {
        let resources: Vec<&str> = match stmt.get("Resource") {
            Some(serde_json::Value::String(s)) => vec![s.as_str()],
            Some(serde_json::Value::Array(arr)) => {
                if arr.iter().any(|v| !v.is_string()) {
                    continue;
                }
                arr.iter().filter_map(|v| v.as_str()).collect()
            }
            _ => continue,
        };
        if resources.is_empty() {
            continue;
        }
        if resources.contains(&"*") {
            continue;
        }
        if resources
            .iter()
            .any(|r| r.contains("${") || r.contains("{{resolve:"))
        {
            continue;
        }
        let actions: Vec<&str> = match stmt.get("Action") {
            Some(serde_json::Value::String(s)) => vec![s.as_str()],
            Some(serde_json::Value::Array(arr)) => arr.iter().filter_map(|v| v.as_str()).collect(),
            _ => continue,
        };
        for action in &actions {
            if action.contains('*') || action.contains('?') || !action.contains(':') {
                continue;
            }
            let key = action.to_lowercase();
            if let Some(expected) = patterns.get(&key)
                && !resources.iter().any(|r| arn_matches_pattern(r, expected)) {
                    out.push(make_resource_diagnostic("I3510", &format!("Action '{}' requires a resource matching '{}' but none of the resources match", action, expected), m, name, path, None));
                }
        }
    }
}

type Ipv4Cidr = (u32, u8); // (network_addr, prefix_len)

fn parse_ipv4_cidr(s: &str) -> Option<Ipv4Cidr> {
    let (addr_str, prefix_str) = s.split_once('/')?;
    let prefix: u8 = prefix_str.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let parts: Vec<u8> = addr_str.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 4 {
        return None;
    }
    let addr = (parts[0] as u32) << 24
        | (parts[1] as u32) << 16
        | (parts[2] as u32) << 8
        | parts[3] as u32;
    let mask = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    Some((addr & mask, prefix))
}

fn is_subnet_of(sub: Ipv4Cidr, vpc: Ipv4Cidr) -> bool {
    if sub.1 < vpc.1 {
        return false;
    } // subnet prefix must be >= vpc prefix (smaller or equal network)
    let vpc_mask = if vpc.1 == 0 { 0 } else { !0u32 << (32 - vpc.1) };
    (sub.0 & vpc_mask) == vpc.0
}

fn check_iam_statements(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    name: &str,
    doc: &serde_json::Value,
    path: &str,
) {
    if let Some(stmts) = doc.get("Statement").and_then(|s| s.as_array()) {
        for stmt in stmts {
            if !stmt.is_object() {
                continue;
            }

            if stmt.get("Effect").is_none() {
                out.push(make_resource_diagnostic(
                    "W3515",
                    "IAM policy statement is missing required 'Effect' property",
                    m,
                    name,
                    path,
                    Some("Add Effect: Allow or Effect: Deny to the statement"),
                ));
            }

            if let Some(effect) = stmt.get("Effect").and_then(|e| e.as_str())
                && effect != "Allow" && effect != "Deny" {
                    out.push(make_resource_diagnostic(
                        "E3514",
                        &format!(
                            "IAM policy statement Effect must be 'Allow' or 'Deny', got '{}'",
                            effect
                        ),
                        m,
                        name,
                        path,
                        Some("Set Effect to 'Allow' or 'Deny'"),
                    ));
                }

            if stmt.get("Action").is_none() && stmt.get("NotAction").is_none() {
                out.push(make_resource_diagnostic(
                    "E9005",
                    "IAM policy statement must have 'Action' or 'NotAction'",
                    m,
                    name,
                    path,
                    Some("Add an Action or NotAction to the statement"),
                ));
            }
        }
    }
}

fn is_arn_prop(path: &str) -> bool {
    path.ends_with("TopicArn")
        || path.ends_with("Arn")
        || path.contains("Resource.")
        || path.ends_with("Resource")
}

fn check_dynamic_ref_spaces(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    name: &str,
    path: &str,
    val: &ResolvedValue,
) {
    match val {
        ResolvedValue::Concrete { value: v } => {
            if let Some(s) = v.as_str() {
                // Detect strings that look like dynamic reference attempts but have spaces
                // that prevent CloudFormation from resolving them.
                // Valid: {{resolve:ssm:...}}  Invalid: {{ resolve:ssm:...}}
                if s.contains("resolve:") && s.contains("{{") && s.contains("}}") {
                    // Has a valid dynamic ref — no warning needed
                    if s.contains("{{resolve:") {
                        return;
                    }
                    // Looks like a dynamic ref attempt with spaces
                    out.push(make_resource_diagnostic(
                    "W1053",
                    &format!(
                        "'{}' has spaces and will not be resolved as a dynamic reference. Remove spaces from '{{{{resolve:...}}}}'",
                        s
                    ),
                    m,
                    name,
                    path,
                    Some("Remove spaces from the dynamic reference"),
                ));
                }
            }
        }
        ResolvedValue::List { items } => {
            for (i, item) in items.iter().enumerate() {
                check_dynamic_ref_spaces(out, m, name, &format!("{}.{}", path, i), item);
            }
        }
        ResolvedValue::Map { entries } => {
            for e in entries {
                check_dynamic_ref_spaces(out, m, name, &format!("{}.{}", path, e.key), &e.value);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_ipv4_cidr ─────────────────────────────────────────────────

    #[test]
    fn parse_cidr_valid() {
        let (addr, prefix) = parse_ipv4_cidr("10.0.0.0/16").unwrap();
        assert_eq!(prefix, 16);
        assert_eq!(addr, 0x0A000000); // 10.0.0.0
    }

    #[test]
    fn parse_cidr_host_bits_masked() {
        let (addr, _) = parse_ipv4_cidr("10.0.1.5/16").unwrap();
        assert_eq!(addr, 0x0A000000); // masked to 10.0.0.0
    }

    #[test]
    fn parse_cidr_slash_32() {
        let (addr, prefix) = parse_ipv4_cidr("192.168.1.1/32").unwrap();
        assert_eq!(prefix, 32);
        assert_eq!(addr, 0xC0A80101);
    }

    #[test]
    fn parse_cidr_slash_0() {
        let (addr, prefix) = parse_ipv4_cidr("10.0.0.0/0").unwrap();
        assert_eq!(prefix, 0);
        assert_eq!(addr, 0);
    }

    #[test]
    fn parse_cidr_invalid_prefix() {
        assert_eq!(
            parse_ipv4_cidr("10.0.0.0/33"),
            None,
            "prefix > 32 should return None"
        );
    }

    #[test]
    fn parse_cidr_invalid_format() {
        assert_eq!(
            parse_ipv4_cidr("not-a-cidr"),
            None,
            "non-CIDR string should return None"
        );
        assert_eq!(
            parse_ipv4_cidr("10.0.0/16"),
            None,
            "incomplete IP should return None"
        );
        assert_eq!(parse_ipv4_cidr(""), None, "empty string should return None");
    }

    // ── is_subnet_of ────────────────────────────────────────────────────

    #[test]
    fn subnet_of_true() {
        let vpc = parse_ipv4_cidr("10.0.0.0/16").unwrap();
        let sub = parse_ipv4_cidr("10.0.1.0/24").unwrap();
        assert!(is_subnet_of(sub, vpc));
    }

    #[test]
    fn subnet_of_same_network() {
        let vpc = parse_ipv4_cidr("10.0.0.0/16").unwrap();
        assert!(is_subnet_of(vpc, vpc));
    }

    #[test]
    fn subnet_of_false_different_network() {
        let vpc = parse_ipv4_cidr("10.0.0.0/16").unwrap();
        let sub = parse_ipv4_cidr("172.16.0.0/24").unwrap();
        assert!(!is_subnet_of(sub, vpc));
    }

    #[test]
    fn subnet_of_false_larger_subnet() {
        let vpc = parse_ipv4_cidr("10.0.0.0/24").unwrap();
        let sub = parse_ipv4_cidr("10.0.0.0/16").unwrap();
        assert!(!is_subnet_of(sub, vpc));
    }

    #[test]
    fn cidr_strict_valid_network() {
        assert!(is_valid_cidr_strict("10.0.0.0/16"));
    }

    #[test]
    fn cidr_strict_invalid_host_bits() {
        assert!(!is_valid_cidr_strict("10.0.0.1/16"));
    }

    #[test]
    fn cidr_strict_invalid_format() {
        assert!(!is_valid_cidr_strict("not-a-cidr"));
    }

    #[test]
    fn cidr_strict_slash_32_any_host() {
        assert!(is_valid_cidr_strict("192.168.1.1/32"));
    }

    #[test]
    fn arn_matches_exact() {
        assert!(arn_matches_pattern(
            "arn:aws:s3:::my-bucket",
            "arn:aws:s3:::my-bucket"
        ));
    }

    #[test]
    fn arn_matches_wildcard() {
        assert!(arn_matches_pattern(
            "arn:aws:s3:::my-bucket",
            "arn:aws:s3:*:*:*"
        ));
    }

    #[test]
    fn arn_no_match_different_service() {
        assert!(!arn_matches_pattern(
            "arn:aws:ec2:::instance",
            "arn:aws:s3:::*"
        ));
    }

    #[test]
    fn arn_too_few_parts() {
        assert!(!arn_matches_pattern("arn:aws", "arn:aws:s3:::*"));
        assert!(!arn_matches_pattern("arn:aws:s3:::*", "short"));
    }
}
