use super::patterns::AMI_ID_RE;
use super::{EvalContext, NativeRuleRegistry};
use diagnostics::Diagnostic;
use rules::Category;
use std::collections::HashSet;
use std::sync::{Arc, LazyLock};
use template_model::SemanticModel;
use template_model::consts::{
    EDGE_KIND_REF, FIELD_KIND, FIELD_OUTGOING_REFS, FIELD_PROPERTIES, FIELD_RESOURCES, FIELD_SOURCE_PATH, FIELD_TARGET,
    KEY_PROPERTIES, TRANSFORM_SERVERLESS,
};
use template_model::resolver::ResolvedValue;
use validation_engine::make_resource_diagnostic;

static ACCT_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"arn:[^:]*:[^:]*:[^:]*:[0-9]{12}:").expect("Invalid ACCT_RE pattern"));

/// Compile-time fallback when generated stateful_resource_types.json is absent.
static FALLBACK_STATEFUL_TYPES: LazyLock<HashSet<String>> = LazyLock::new(|| {
    [
        "AWS::S3::Bucket",
        "AWS::RDS::DBInstance",
        "AWS::RDS::DBCluster",
        "AWS::DynamoDB::Table",
        "AWS::DynamoDB::GlobalTable",
        "AWS::EFS::FileSystem",
        "AWS::Logs::LogGroup",
        "AWS::Neptune::DBCluster",
        "AWS::Neptune::DBInstance",
        "AWS::DocDB::DBCluster",
        "AWS::DocDB::DBInstance",
        "AWS::OpenSearchService::Domain",
        "AWS::Redshift::Cluster",
        "AWS::CloudFormation::Stack",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
});

pub fn register(reg: &mut NativeRuleRegistry) {
    reg.add(Category::BestPractice, eval_best_practices);
    reg.add(Category::BestPractice, eval_retention_period_rules);
    reg.add(Category::BestPractice, eval_deprecated_resource_types);
    reg.add(Category::Security, eval_sensitive_port_rules);
}

fn resolve_concrete(m: &SemanticModel, rid: &str, path: &str) -> Option<serde_json::Value> {
    let rv = m.resolve_deep(rid, path).or_else(|| m.resolve(rid, path).cloned())?;
    match rv {
        ResolvedValue::Concrete { value: v } => Some(v.into_inner()),
        _ => None,
    }
}

/// Whether a `DeletionPolicy`/`UpdateReplacePolicy` value is the literal
/// `"Delete"`. A lone policy set to `Delete` is the default behavior, so
/// CloudFormation gains nothing from also setting its counterpart, and the
/// configuration is treated as valid (no warning).
fn policy_is_delete(policy: Option<&ResolvedValue>) -> bool {
    matches!(policy, Some(ResolvedValue::Concrete { value: v }) if v.as_str() == Some("Delete"))
}

fn eval_best_practices(ctx: &EvalContext) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let m = ctx.model;
    let stateful_types = if ctx.cached_data.stateful_resource_types.is_empty() {
        &*FALLBACK_STATEFUL_TYPES
    } else {
        &ctx.cached_data.stateful_resource_types
    };

    for (name, res) in &m.resources {
        if stateful_types.contains(&res.resource_type) && res.resource_type != "AWS::S3::Bucket" {
            if res.deletion_policy.is_none() {
                out.push(make_resource_diagnostic("I3011",
                    "'DeletionPolicy' is a required property (The default action when replacing/removing a resource is to delete it. Set explicit values for stateful resource)",
                    m,
                    name,
                    "",
                    None,
                ));
            }
            if res.update_replace_policy.is_none() {
                out.push(make_resource_diagnostic("I3011",
                    "'UpdateReplacePolicy' is a required property (The default action when replacing/removing a resource is to delete it. Set explicit values for stateful resource)",
                    m,
                    name,
                    "",
                    None,
                ));
            }
        }
    }

    for (name, res) in &m.resources {
        // A lone policy whose value is "Delete" is the default behavior, so
        // requiring its counterpart adds no protection and the configuration is
        // valid. Only warn when the single present policy asks for something
        // other than Delete.
        if res.deletion_policy.is_some()
            && res.update_replace_policy.is_none()
            && !policy_is_delete(res.deletion_policy.as_ref())
        {
            out.push(make_resource_diagnostic(
                "W3011",
                "Both 'UpdateReplacePolicy' and 'DeletionPolicy' are needed to protect resource from deletion",
                m,
                name,
                "",
                None,
            ));
        }
        if res.update_replace_policy.is_some()
            && res.deletion_policy.is_none()
            && !policy_is_delete(res.update_replace_policy.as_ref())
        {
            out.push(make_resource_diagnostic(
                "W3011",
                "Both 'UpdateReplacePolicy' and 'DeletionPolicy' are needed to protect resource from deletion",
                m,
                name,
                "",
                None,
            ));
        }
    }

    let policy_doc_types: &[&str] = &[
        "AWS::IAM::Policy",
        "AWS::IAM::ManagedPolicy",
        "AWS::SQS::QueuePolicy",
        "AWS::SNS::TopicPolicy",
        "AWS::S3::BucketPolicy",
    ];
    for rtype in policy_doc_types {
        for name in m.resources_of_type(rtype) {
            if let Some(doc) = resolve_concrete(m, name, "Properties.PolicyDocument") {
                check_notaction_policy(&mut out, m, name, &doc);
            }
        }
    }
    for rtype in &["AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"] {
        for name in m.resources_of_type(rtype) {
            if let Some(serde_json::Value::Array(policies)) = resolve_concrete(m, name, "Properties.Policies") {
                for policy in &policies {
                    if let Some(doc) = policy.get("PolicyDocument") {
                        check_notaction_policy(&mut out, m, name, doc);
                    }
                }
            }
        }
    }
    for name in m.resources_of_type("AWS::SSO::PermissionSet") {
        if let Some(doc) = resolve_concrete(m, name, "Properties.InlinePolicy") {
            check_notaction_policy(&mut out, m, name, &doc);
        }
    }

    for name in m.resources_of_type("AWS::EC2::Instance") {
        let scenarios = m.resolve_scenarios_json(name, "Properties.ImageId");
        let mut seen: HashSet<String> = HashSet::new();
        for (val, _) in scenarios {
            let Some(s) = val.as_str() else {
                continue;
            };
            if !AMI_ID_RE.is_match(s) {
                continue;
            }
            if !seen.insert(s.to_string()) {
                continue;
            }
            out.push(make_resource_diagnostic(
                "W9010",
                "Hardcoded AMI ID — use a parameter or mapping for portability",
                m,
                name,
                "Properties.ImageId",
                None,
            ));
            break;
        }
    }

    for (name, res) in &m.resources {
        for (key, val) in &res.properties {
            // Skip intrinsic-built values (e.g. an ARN assembled with Fn::Join +
            // Ref AWS::AccountId): the account segment is a pseudo-parameter
            // stand-in, not a literal the author typed.
            if let ResolvedValue::Concrete { value: v } = val
                && let Some(s) = v.as_str()
                && ACCT_RE.is_match(s)
                && !m.is_from_intrinsic(name, &format!("Properties.{}", key))
            {
                out.push(make_resource_diagnostic(
                    "W9013",
                    "Hardcoded account ID in ARN — use AWS::AccountId pseudo-parameter",
                    m,
                    name,
                    "",
                    None,
                ));
                break;
            }
        }
    }

    // Only fires for a hardcoded partition inside Fn::Sub, and skips SAM templates.
    let has_serverless = m.transforms.iter().any(|t| t == TRANSFORM_SERVERLESS);
    if !has_serverless {
        for (name, res) in &m.resources {
            for path in &res.diagnostics.hardcoded_partition_arns {
                out.push(make_resource_diagnostic(
                    "I3042",
                    &format!(
                        "ARN in Resource {} contains hardcoded Partition in ARN or incorrectly placed Pseudo Parameters",
                        name
                    ),
                    m,
                    name,
                    path,
                    None,
                ));
            }
        }
    }

    const PASSWORD_PROPS: &[&str] = &[
        "MasterUserPassword",
        "Password",
        "AdminPassword",
        "MasterPassword",
        "LoginPassword",
        "DbPassword",
        "UserPassword",
    ];

    // Build a set of (resource, prop) pairs that are Refs to parameters
    let mut ref_to_param_props: HashSet<(String, String)> = HashSet::new();
    if let Some(resources) = ctx.input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
        for (rname, res) in resources {
            if let Some(edges) = res.get(FIELD_OUTGOING_REFS).and_then(|r| r.as_array()) {
                for edge in edges {
                    if edge.get(FIELD_KIND).and_then(|k| k.as_str()) != Some(EDGE_KIND_REF) {
                        continue;
                    }
                    let sp = edge.get(FIELD_SOURCE_PATH).and_then(|p| p.as_str()).unwrap_or("");
                    let target = edge.get(FIELD_TARGET).and_then(|t| t.as_str()).unwrap_or("");
                    if let Some(prop) = sp.strip_prefix("Properties.")
                        && PASSWORD_PROPS.contains(&prop)
                        && m.parameters.contains_key(target)
                    {
                        ref_to_param_props.insert((rname.clone(), prop.to_string()));
                    }
                }
            }
        }
    }

    if let Some(resources) = ctx.input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
        for (rname, _res) in resources {
            for prop in PASSWORD_PROPS {
                let path = format!("Properties.{}", prop);

                // Check for non-secure dynamic references via raw property
                if let Some(res) = m.resources.get(rname.as_str())
                    && let Some(ResolvedValue::Dynamic { reason }) = res.properties.get(*prop)
                {
                    if reason.contains("{{resolve:")
                        && !reason.contains("{{resolve:ssm-secure:")
                        && !reason.contains("{{resolve:secretsmanager:")
                    {
                        out.push(make_resource_diagnostic(
                            "W2501",
                            &format!(
                                "Password should use a secure dynamic reference for Resources/{}/Properties/{}",
                                rname, prop
                            ),
                            m,
                            rname,
                            &path,
                            None,
                        ));
                    }
                    continue;
                }

                if let Some(scenarios) = m.resolve_scenarios_json(rname, &path).first()
                    && let serde_json::Value::String(s) = &scenarios.0
                {
                    let is_secure = s.contains("{{resolve:ssm-secure:") || s.contains("{{resolve:secretsmanager:");
                    let is_any_dynamic_ref = s.contains("{{resolve:");

                    if is_secure {
                        continue;
                    }

                    // Non-secure dynamic reference in resolved string
                    if is_any_dynamic_ref {
                        out.push(make_resource_diagnostic(
                            "W2501",
                            &format!(
                                "Password should use a secure dynamic reference for Resources/{}/Properties/{}",
                                rname, prop
                            ),
                            m,
                            rname,
                            &path,
                            None,
                        ));
                        continue;
                    }

                    // Skip if this is a Ref to a parameter (handled by parameter-level check)
                    if ref_to_param_props.contains(&(rname.clone(), prop.to_string())) {
                        continue;
                    }

                    // Hardcoded string (not a Ref to parameter, not a dynamic reference)
                    if !crate::functions::contains_unresolvable_content(&ResolvedValue::Concrete {
                        value: scenarios.0.clone().into(),
                    }) {
                        out.push(make_resource_diagnostic("W2501",
                                &format!("Property '{}' should not be a hardcoded string — use a parameter with NoEcho or a dynamic reference", prop),
                                m, rname, &path, None,
                            ));
                    }
                }
            }
        }
    }

    // Parameter used as a password without NoEcho — emit at the parameter location.
    if let Some(resources) = ctx.input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
        for (_rname, res) in resources {
            let Some(edges) = res.get(FIELD_OUTGOING_REFS).and_then(|r| r.as_array()) else {
                continue;
            };
            for edge in edges {
                if edge.get(FIELD_KIND).and_then(|k| k.as_str()) != Some(EDGE_KIND_REF) {
                    continue;
                }
                let sp = edge.get(FIELD_SOURCE_PATH).and_then(|p| p.as_str()).unwrap_or("");
                let prop = sp.strip_prefix("Properties.").unwrap_or("");
                if !PASSWORD_PROPS.contains(&prop) {
                    continue;
                }
                let Some(target) = edge.get(FIELD_TARGET).and_then(|t| t.as_str()) else {
                    continue;
                };
                if let Some(param) = m.parameters.get(target)
                    && !param.no_echo
                {
                    out.push(make_resource_diagnostic(
                        "W2501",
                        &format!("Parameter {} used as {}, therefore NoEcho should be True", target, prop),
                        m,
                        "",
                        &format!("Parameters.{}", target),
                        None,
                    ));
                }
            }
        }
    }

    if let Some(resources) = ctx.input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
        for (rname, res) in resources {
            let Some(edges) = res.get(FIELD_OUTGOING_REFS).and_then(|r| r.as_array()) else {
                continue;
            };
            for edge in edges {
                if edge.get(FIELD_KIND).and_then(|k| k.as_str()) != Some(EDGE_KIND_REF) {
                    continue;
                }
                let sp = edge.get(FIELD_SOURCE_PATH).and_then(|p| p.as_str()).unwrap_or("");
                let prop = sp.strip_prefix("Properties.").unwrap_or("");
                if !PASSWORD_PROPS.contains(&prop) {
                    continue;
                }
                let Some(target) = edge.get(FIELD_TARGET).and_then(|t| t.as_str()) else {
                    continue;
                };
                if !m.parameters.contains_key(target) {
                    continue;
                }
                out.push(make_resource_diagnostic(
                    "W1011",
                    &format!(
                        "Use dynamic references (e.g., SSM SecureString) instead of parameter '{}' for secrets",
                        target
                    ),
                    m,
                    rname,
                    sp,
                    None,
                ));
            }
        }
    }

    if let Some(sm) = ctx.cached_data.schema_metadata().get("schema_metadata") {
        for (name, res) in &m.resources {
            if res.resource_type.ends_with("::MODULE") {
                continue;
            }
            let supports_tags = sm
                .get(&res.resource_type)
                .and_then(|entry| entry.get("properties"))
                .and_then(|p| p.as_array())
                .map(|arr| arr.iter().any(|v| v.as_str() == Some("Tags")))
                .unwrap_or(false);
            if supports_tags && !res.properties.contains_key("Tags") {
                out.push(make_resource_diagnostic(
                    "I9040",
                    &format!(
                        "Resource '{}' of type '{}' supports Tags but none are configured",
                        name, res.resource_type
                    ),
                    m,
                    name,
                    "Properties.Tags",
                    Some("Add Tags to improve resource organization and cost tracking"),
                ));
            }
        }
    }

    let snapstart_runtimes = ["java11", "java17", "java21"];
    for name in m.resources_of_type("AWS::Lambda::Function") {
        if let Some(serde_json::Value::String(rt)) = resolve_concrete(m, name, "Properties.Runtime")
            && snapstart_runtimes.contains(&rt.as_str())
        {
            let has_snap = resolve_concrete(m, name, "Properties.SnapStart")
                .and_then(|v| v.get("ApplyOn").and_then(|a| a.as_str()).map(|s| s.to_string()))
                .unwrap_or_default();
            if has_snap != "PublishedVersions" {
                let mut diag = make_resource_diagnostic(
                    "I2530",
                    &format!("Runtime '{}' should consider using SnapStart for improved performance", rt),
                    m,
                    name,
                    "Properties.Runtime",
                    Some("Add SnapStart with ApplyOn set to 'PublishedVersions'"),
                );
                diag.documentation_url = Some("https://docs.aws.amazon.com/lambda/latest/dg/snapstart.html".into());
                out.push(diag);
            }
        }
    }

    for name in m.resources_of_type("AWS::RDS::DBInstance") {
        if !m.resources.get(name.as_str()).map(|r| r.properties.contains_key("StorageEncrypted")).unwrap_or(false) {
            out.push(make_resource_diagnostic(
                "W9008",
                "RDS instance should have StorageEncrypted set to true",
                m,
                name,
                "",
                Some("Set StorageEncrypted to true"),
            ));
        }
    }

    for name in m.resources_of_type("AWS::RDS::DBInstance") {
        if resolve_concrete(m, name, "Properties.PubliclyAccessible").as_ref().and_then(|v| v.as_bool()) == Some(true) {
            out.push(make_resource_diagnostic(
                "W9011",
                "RDS instance has PubliclyAccessible set to true — consider restricting access",
                m,
                name,
                "Properties.PubliclyAccessible",
                Some("Set PubliclyAccessible to false"),
            ));
        }
    }

    out
}

fn eval_retention_period_rules(ctx: &EvalContext) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let m = ctx.model;
    for (resource_type, required_props) in &ctx.cached_data.retention_period_requirements {
        for resource_name in m.resources_of_type(resource_type) {
            if resource_type == "AWS::RDS::DBInstance" && !rds_dbinstance_needs_retention(ctx, resource_name) {
                continue;
            }
            for prop in required_props {
                let has_prop = m
                    .resources
                    .get(resource_name.as_str())
                    .map(|r| r.properties.contains_key(prop.as_str()))
                    .unwrap_or(false);
                if !has_prop {
                    out.push(make_resource_diagnostic("I3013",
                        &format!("'{}' is a required property (The default retention period will delete the data after a pre-defined time. Set an explicit values to avoid data loss on resource)", prop),
                        m,
                        resource_name,
                        &format!("Properties.{}", prop),
                        None,
                    ));
                }
            }
        }
    }
    out
}

// A standalone, non-Aurora DB instance is the only RDS instance that needs an
// explicit backup retention period: Aurora manages backups at the cluster level
// and a read replica inherits its source's retention.
fn rds_dbinstance_needs_retention(ctx: &EvalContext, name: &str) -> bool {
    let Some(props) =
        ctx.input.get(FIELD_RESOURCES).and_then(|r| r.get(name)).and_then(|res| res.get(FIELD_PROPERTIES))
    else {
        return false;
    };
    let Some(engine) = props.get("Engine").and_then(|e| e.as_str()) else {
        return false;
    };
    !engine.starts_with("aurora") && props.get("SourceDBInstanceIdentifier").is_none()
}

fn check_notaction_policy(out: &mut Vec<Diagnostic>, m: &Arc<SemanticModel>, name: &str, doc: &serde_json::Value) {
    if let Some(stmts) = doc.get("Statement").and_then(|s| s.as_array()) {
        for stmt in stmts {
            let effect = stmt.get("Effect").and_then(|e| e.as_str()).unwrap_or("");
            if effect != "Allow" {
                continue;
            }
            if stmt.get("NotAction").is_some() {
                out.push(make_resource_diagnostic("W2512",
"IAM policy uses NotAction which grants all actions except those listed — consider using Action instead",
m,
name,
"",
None,
));
            }
        }
    }
}

fn eval_deprecated_resource_types(ctx: &EvalContext) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for (name, res) in &ctx.model.resources {
        if ctx.cached_data.deprecated_resource_types.contains(&res.resource_type) {
            out.push(make_resource_diagnostic(
                "W9009",
                &format!("Resource type '{}' is deprecated — consider using a newer alternative", res.resource_type),
                ctx.model,
                name,
                "",
                Some(&format!("Replace {} with a supported alternative", res.resource_type)),
            ));
        }
    }
    out
}

fn eval_sensitive_port_rules(ctx: &EvalContext) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let ports = &ctx.cached_data.sensitive_ports;
    if ports.is_empty() {
        return out;
    }
    let m = ctx.model;

    // Check AWS::EC2::SecurityGroup inline ingress rules
    for name in m.resources_of_type("AWS::EC2::SecurityGroup") {
        let ingress_path = "Properties.SecurityGroupIngress";
        let Some(len) = resolve_array_len(m, name, ingress_path) else {
            continue;
        };
        for idx in 0..len {
            check_sg_rule(&mut out, m, name, &format!("{}.{}", ingress_path, idx), ports);
        }
    }
    // Check standalone AWS::EC2::SecurityGroupIngress resources
    for name in m.resources_of_type("AWS::EC2::SecurityGroupIngress") {
        check_sg_rule(&mut out, m, name, KEY_PROPERTIES, ports);
    }
    out
}

fn resolve_array_len(m: &Arc<SemanticModel>, name: &str, path: &str) -> Option<usize> {
    let rv = m.resolve_deep(name, path).or_else(|| m.resolve(name, path).cloned())?;
    match rv {
        ResolvedValue::Concrete { value: v } => v.as_array().map(|a| a.len()),
        _ => None,
    }
}

fn resolve_str(m: &Arc<SemanticModel>, name: &str, path: &str) -> Option<String> {
    match resolve_concrete(m, name, path)? {
        serde_json::Value::String(s) => Some(s),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn resolve_i64(m: &Arc<SemanticModel>, name: &str, path: &str) -> Option<i64> {
    match resolve_concrete(m, name, path)? {
        serde_json::Value::Number(n) => n.as_i64(),
        serde_json::Value::String(s) => s.parse::<i64>().ok(),
        _ => None,
    }
}

fn check_sg_rule(out: &mut Vec<Diagnostic>, m: &Arc<SemanticModel>, name: &str, rule_path: &str, ports: &[u16]) {
    let cidr4 = resolve_str(m, name, &format!("{}.CidrIp", rule_path)).unwrap_or_default();
    let cidr6 = resolve_str(m, name, &format!("{}.CidrIpv6", rule_path)).unwrap_or_default();
    if cidr4 != "0.0.0.0/0" && cidr6 != "::/0" {
        return;
    }
    let open_cidr = if cidr4 == "0.0.0.0/0" { "0.0.0.0/0" } else { "::/0" };
    let diag_path = if rule_path.starts_with("Properties.SecurityGroupIngress") {
        "Properties.SecurityGroupIngress"
    } else {
        KEY_PROPERTIES
    };
    let proto = resolve_str(m, name, &format!("{}.IpProtocol", rule_path)).unwrap_or_default();
    if proto == "-1" {
        for port in ports {
            out.push(make_resource_diagnostic(
                "W2508",
                &format!("Security group allows all traffic from {} — sensitive port {} is exposed", open_cidr, port),
                m,
                name,
                diag_path,
                Some("Restrict the CIDR range or limit the protocol"),
            ));
        }
        return;
    }
    let Some(from) = resolve_i64(m, name, &format!("{}.FromPort", rule_path)) else {
        return;
    };
    let Some(to) = resolve_i64(m, name, &format!("{}.ToPort", rule_path)) else {
        return;
    };
    for port in ports {
        if (*port as i64) >= from && (*port as i64) <= to {
            out.push(make_resource_diagnostic(
                "W2508",
                &format!(
                    "Security group allows {} access to sensitive port {} (range {}-{})",
                    open_cidr, port, from, to
                ),
                m,
                name,
                diag_path,
                Some("Restrict the CIDR range to specific IP addresses"),
            ));
        }
    }
}
