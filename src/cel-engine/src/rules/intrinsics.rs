use super::{EvalContext, NativeRuleRegistry};
use diagnostics::Diagnostic;
use std::collections::HashSet;
use std::sync::{Arc, LazyLock};
use template_model::consts::{
    EDGE_KIND_GET_ATT, EDGE_KIND_REF, EDGE_KIND_SUB, FIELD_ATTR, FIELD_CONDITIONS,
    FIELD_DEPENDS_ON, FIELD_KIND, FIELD_OUTGOING_REFS, FIELD_OUTPUTS, FIELD_PARAMETERS,
    FIELD_PROPERTIES, FIELD_RESOURCE_TYPE, FIELD_RESOURCES, FIELD_SOURCE_PATH, FIELD_TARGET,
    FN_FOR_EACH, FN_GET_AZS, FN_IMPORT_VALUE, FN_LENGTH, FN_TO_JSON_STRING, KEY_DEFAULT,
    KEY_DEPENDS_ON, KEY_PROPERTIES, OUTPUT_PSEUDO_RESOURCE_PREFIX, PSEUDO_STACK_NAME,
    SECTION_CONDITIONS, SECTION_OUTPUTS, TRANSFORM_LANGUAGE_EXTENSIONS,
};
use template_model::resolver::RefKind;
use template_model::resolver::ResolvedValue;
use template_model::{PSEUDO_PARAMETERS, SemanticModel};
use validation_engine::make_resource_diagnostic;

pub fn register(reg: &mut NativeRuleRegistry) {
    reg.add(rules::Category::Intrinsic, eval_intrinsics);
    reg.add(rules::Category::Intrinsic, eval_format_validation);
    reg.add(rules::Category::Intrinsic, eval_intrinsic_params);
    reg.add(rules::Category::Intrinsic, eval_dynamic_references);
}

fn eval_intrinsics(ctx: &EvalContext) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let m = ctx.model;
    let input = ctx.input;
    let resources = match input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
        Some(r) => r,
        None => return out,
    };
    let resource_keys: HashSet<&str> = resources.keys().map(|k| k.as_str()).collect();
    let param_keys: HashSet<&str> = input
        .get(FIELD_PARAMETERS)
        .and_then(|p| p.as_object())
        .map(|p| p.keys().map(|k| k.as_str()).collect())
        .unwrap_or_default();
    let pseudo: HashSet<&str> = PSEUDO_PARAMETERS.iter().copied().collect();
    let cond_keys: HashSet<&str> = input
        .get(FIELD_CONDITIONS)
        .and_then(|c| c.as_object())
        .map(|c| c.keys().map(|k| k.as_str()).collect())
        .unwrap_or_default();
    let sam_implicit: HashSet<&str> = input
        .get("samImplicitResources")
        .and_then(|s| s.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    // Suppress ref validation when the template has parse errors — the model
    // is incomplete and refs to unparsed sections would be false positives.
    let has_parse_errors = m.diagnostics.iter().any(|d| {
        d.severity == rules::Severity::Fatal && d.phase == Some(diagnostics::Phase::Parse)
    });

    // Load GetAtt attribute data
    let getatt_attrs = &ctx.cached_data.getatt_attrs;
    let getatt_attr_types = &ctx.cached_data.getatt_attr_types;

    for (name, res) in resources {
        let refs = res.get(FIELD_OUTGOING_REFS).and_then(|r| r.as_array());
        if let Some(edges) = refs {
            for edge in edges {
                let kind = edge.get(FIELD_KIND).and_then(|k| k.as_str()).unwrap_or("");
                let target = edge
                    .get(FIELD_TARGET)
                    .and_then(|t| t.as_str())
                    .unwrap_or("");

                match kind {
                    EDGE_KIND_REF => {
                        if !resource_keys.contains(target)
                            && !param_keys.contains(target)
                            && !pseudo.contains(target)
                            && !sam_implicit.contains(target)
                        {
                            out.push(make_resource_diagnostic("F1010",
                                &format!("Ref '{}' does not reference a valid resource, parameter, or pseudo-parameter", target),
                                m,
                                name,
                                "",
                                Some("Check that the Ref target exists as a resource, parameter, or pseudo-parameter"),
        ));
                        }
                    }
                    EDGE_KIND_GET_ATT => {
                        let attr = edge.get(FIELD_ATTR).and_then(|a| a.as_str()).unwrap_or("");
                        let source_path = edge
                            .get(FIELD_SOURCE_PATH)
                            .and_then(|p| p.as_str())
                            .unwrap_or("");

                        if !resource_keys.contains(target) && !has_parse_errors {
                            out.push(make_resource_diagnostic(
                                "F1020",
                                &format!(
                                    "Fn::GetAtt references non-existent resource '{}'",
                                    target
                                ),
                                m,
                                name,
                                "",
                                Some(
                                    "Check that the GetAtt target resource exists in the template",
                                ),
                            ));
                        } else if !attr.is_empty() {
                            if let Some(target_res) = resources.get(target) {
                                if let Some(rtype) =
                                    target_res.get(FIELD_RESOURCE_TYPE).and_then(|t| t.as_str())
                                {
                                    if let Some(valid_list) = getatt_attrs.get(rtype) {
                                        if !valid_list.iter().any(|a| a == attr)
                                            && !rtype.starts_with("Custom::")
                                            && !rtype
                                                .starts_with("AWS::CloudFormation::CustomResource")
                                            && rtype != "AWS::CloudFormation::Stack"
                                            && rtype != "AWS::CloudFormation::Macro"
                                        {
                                            out.push(make_resource_diagnostic(
                                                "E9004",
                                                &format!(
                                                    "'{}' is not one of {:?}",
                                                    attr, valid_list
                                                ),
                                                m,
                                                name,
                                                source_path,
                                                Some("Check the resource type documentation for valid GetAtt attributes"),
                                            ));
                                        }
                                    }

                                    if let Some(ret_type) =
                                        getatt_attr_types.get(rtype).and_then(|m| m.get(attr))
                                    {
                                        if matches!(
                                            ret_type.as_str(),
                                            "integer" | "number" | "boolean"
                                        ) {
                                            let res_type = m
                                                .resources
                                                .get(name)
                                                .map(|r| r.resource_type.as_str())
                                                .unwrap_or("");
                                            if res_type == "AWS::SSM::Parameter"
                                                && source_path.contains("Value")
                                            {
                                                out.push(make_resource_diagnostic("E9003",
                                                    &format!("{{'Fn::GetAtt': ['{}', '{}']}} is not of type 'string'", target, attr),
                                                    m,
                                                    name,
                                                    source_path,
                                                    Some("GetAtt returns a non-string type"),
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    EDGE_KIND_SUB => {
                        if !resource_keys.contains(target)
                            && !param_keys.contains(target)
                            && !pseudo.contains(target)
                        {
                            out.push(make_resource_diagnostic("F1018",
                                &format!("Fn::Sub variable '${{{}}}' does not reference a valid resource, parameter, or pseudo-parameter", target),
                                m,
                                name,
                                "",
                                None,
        ));
                        }
                    }
                    _ => {}
                }
            }
        }

        if !has_parse_errors && !has_language_extensions(m) {
            if let Some(invalid) = res.get("invalidRefs").and_then(|r| r.as_array()) {
                let mut valid_targets: Vec<&str> = resource_keys
                    .iter()
                    .chain(param_keys.iter())
                    .chain(pseudo.iter())
                    .copied()
                    .collect();
                valid_targets.sort();
                for entry in invalid {
                    let target = entry.get("target").and_then(|t| t.as_str()).unwrap_or("");
                    let path = entry.get("path").and_then(|p| p.as_str()).unwrap_or("");
                    if target.is_empty() || sam_implicit.contains(target) {
                        continue;
                    }
                    out.push(make_resource_diagnostic(
                        "F1020",
                        &format!("'{}' is not one of {:?}", target, valid_targets),
                        m,
                        name,
                        path,
                        Some("Check that the Ref target exists as a resource, parameter, or pseudo-parameter"),
                    ));
                }
            }
        }

        if let Some(refs) = res.get("findInMapRefs").and_then(|r| r.as_array()) {
            for map_ref in refs {
                if let Some(map_name) = map_ref.as_str() {
                    if !m.mappings.contains_key(map_name) {
                        out.push(make_resource_diagnostic(
                            "F1012",
                            &format!(
                                "Fn::FindInMap references non-existent mapping '{}'",
                                map_name
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

        if let Some(joins) = res.get("emptyJoins").and_then(|j| j.as_array()) {
            let mut seen_paths = HashSet::new();
            for path in joins {
                if let Some(p) = path.as_str() {
                    if seen_paths.insert(p) {
                        out.push(make_resource_diagnostic(
                            "I1022",
                            "Prefer using Fn::Sub over Fn::Join with an empty delimiter",
                            m,
                            name,
                            p,
                            None,
                        ));
                    }
                }
            }
        }

        if let Some(crefs) = res.get("conditionRefs").and_then(|r| r.as_array()) {
            for cref in crefs {
                if let Some(cname) = cref.as_str() {
                    if !cond_keys.contains(cname) {
                        out.push(make_resource_diagnostic(
                            "F1060",
                            &format!(
                                "Fn::If condition '{}' does not exist in Conditions section",
                                cname
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

    if let Some(joins) = input.get("outputEmptyJoins").and_then(|j| j.as_array()) {
        let mut seen_paths = HashSet::new();
        for path in joins {
            if let Some(p) = path.as_str() {
                if seen_paths.insert(p) {
                    out.push(make_resource_diagnostic(
                        "I1022",
                        "Prefer using Fn::Sub over Fn::Join with an empty delimiter",
                        m,
                        "",
                        p,
                        None,
                    ));
                }
            }
        }
    }

    out
}

static SG_ID_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^sg-[a-f0-9]{8,17}$").expect("Invalid SG_ID_RE"));

// NetworkInterfaces GroupSet accepts mixed-case hex.
static SG_ID_MIXED_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^sg-[a-fA-F0-9]{8,17}$").expect("Invalid SG_ID_MIXED_RE"));

static VPC_ID_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^vpc-[a-f0-9]{8,17}$").expect("Invalid VPC_ID_RE"));

static AMI_ID_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^ami-[a-f0-9]{8,17}$").expect("Invalid AMI_ID_RE"));

static SUBNET_ID_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^subnet-[a-f0-9]{8,17}$").expect("Invalid SUBNET_ID_RE"));

static LOG_GROUP_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^[\.\-_/#A-Za-z0-9]{1,512}$").expect("Invalid LOG_GROUP_RE")
});

static IAM_ROLE_ARN_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r"^arn:(aws|aws-cn|aws-iso|aws-iso-[a-z]{1}|aws-us-gov):iam::[0-9]{12}:role/.*$",
    )
    .expect("Invalid IAM_ROLE_ARN_RE")
});

fn resolve_concrete_fmt(m: &SemanticModel, rid: &str, path: &str) -> Option<serde_json::Value> {
    match m
        .resolve_deep(rid, path)
        .or_else(|| m.resolve(rid, path).cloned())?
    {
        ResolvedValue::Concrete { value: v } => Some(v.into_inner()),
        _ => None,
    }
}

fn check_format(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    name: &str,
    prop: &str,
    rule_id: &str,
    msg_fmt: &str,
    re: &regex::Regex,
) {
    let path = format!("Properties.{}", prop);
    let scenarios = m.resolve_scenarios_json(name, &path);
    let mut seen: HashSet<String> = HashSet::new();
    for (val, _) in scenarios {
        let Some(s) = val.as_str() else {
            continue;
        };
        if s.starts_with("{{") || re.is_match(s) {
            continue;
        }
        if !seen.insert(s.to_string()) {
            continue;
        }
        out.push(make_resource_diagnostic(
            rule_id,
            &format!("Value '{}' does not match {}", s, msg_fmt),
            m,
            name,
            &path,
            None,
        ));
    }
}

fn check_format_arn(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    name: &str,
    prop: &str,
    re: &regex::Regex,
) {
    let path = format!("Properties.{}", prop);
    if let Some(serde_json::Value::String(val)) = resolve_concrete_fmt(m, name, &path) {
        if !val.starts_with("{{") && val.starts_with("arn:") && !re.is_match(&val) {
            out.push(make_resource_diagnostic(
                "E1156",
                &format!("Value '{}' does not match IAM Role ARN format", val),
                m,
                name,
                &path,
                None,
            ));
        }
    }
}

fn eval_format_validation(ctx: &EvalContext) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let m = ctx.model;

    let sg_id_props: &[(&str, &[&str])] = &[("AWS::EC2::Instance", &["SecurityGroupIds"])];
    for &(rtype, props) in sg_id_props {
        for name in m.resources_of_type(rtype) {
            for &prop in props {
                let path = format!("Properties.{}", prop);
                if let Some(serde_json::Value::Array(items)) = resolve_concrete_fmt(m, name, &path)
                {
                    for item in items.iter() {
                        if let Some(val) = item.as_str() {
                            if !val.starts_with("{{") && !SG_ID_RE.is_match(val) {
                                out.push(make_resource_diagnostic(
                                    "E1150",
                                    &format!("Value '{}' does not match Security Group ID format (sg-xxxxxxxxx)", val),
                                    m, name, &path, None,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    for rtype in &["AWS::EC2::Instance", "AWS::EC2::LaunchTemplate"] {
        for name in m.resources_of_type(rtype) {
            let Some(res) = m.resources.get(name.as_str()) else {
                continue;
            };
            let Some(ni) = res.properties.get("NetworkInterfaces") else {
                continue;
            };
            let ni_len = match ni {
                ResolvedValue::Concrete { value: v } => v.as_array().map(|a| a.len()).unwrap_or(0),
                ResolvedValue::List { items } => items.len(),
                _ => 0,
            };
            let mut seen: HashSet<String> = HashSet::new();
            for ni_idx in 0..ni_len {
                let gs_path = format!("Properties.NetworkInterfaces.{}.GroupSet", ni_idx);
                let Some(rv) = m
                    .resolve_deep(&name, &gs_path)
                    .or_else(|| m.resolve(&name, &gs_path).cloned())
                else {
                    continue;
                };
                let items: Vec<serde_json::Value> = match rv {
                    ResolvedValue::Concrete { value: v } => {
                        v.as_array().cloned().unwrap_or_default()
                    }
                    ResolvedValue::List { items } => items
                        .iter()
                        .filter_map(|it| match it {
                            ResolvedValue::Concrete { value: v } => Some(v.0.clone()),
                            _ => None,
                        })
                        .collect(),
                    _ => continue,
                };
                for item in &items {
                    let Some(val) = item.as_str() else { continue };
                    if val.starts_with("sg-")
                        && !SG_ID_MIXED_RE.is_match(val)
                        && seen.insert(val.to_string())
                    {
                        out.push(make_resource_diagnostic(
                            "E1150",
                            &format!("'{}' is not a 'AWS::EC2::SecurityGroup.Id' with pattern '^sg-([a-fA-F0-9]{{8}}|[a-fA-F0-9]{{17}})$'", val),
                            m, &name, "Properties.NetworkInterfaces.GroupSet", None,
                        ));
                    }
                }
            }
        }
    }

    let vpc_id_props: &[(&str, &[&str])] = &[
        ("AWS::EC2::Subnet", &["VpcId"]),
        ("AWS::EC2::SecurityGroup", &["VpcId"]),
        ("AWS::EC2::RouteTable", &["VpcId"]),
        ("AWS::EC2::InternetGatewayAttachment", &["VpcId"]),
        ("AWS::EC2::NetworkAcl", &["VpcId"]),
    ];
    for &(rtype, props) in vpc_id_props {
        for name in m.resources_of_type(rtype) {
            for &prop in props {
                check_format(
                    &mut out,
                    m,
                    name,
                    prop,
                    "E1151",
                    "VPC ID format (vpc-xxxxxxxxx)",
                    &VPC_ID_RE,
                );
            }
        }
    }

    for name in m.resources_of_type("AWS::EC2::Instance") {
        check_format(
            &mut out,
            m,
            name,
            "ImageId",
            "E1152",
            "AMI ID format (ami-xxxxxxxxx)",
            &AMI_ID_RE,
        );
    }

    for name in m.resources_of_type("AWS::AutoScaling::LaunchConfiguration") {
        check_format(
            &mut out,
            m,
            name,
            "ImageId",
            "E1152",
            "AMI ID format (ami-xxxxxxxxx)",
            &AMI_ID_RE,
        );
    }

    for name in m.resources_of_type("AWS::EC2::LaunchTemplate") {
        check_format(
            &mut out,
            m,
            name,
            "LaunchTemplateData.ImageId",
            "E1152",
            "AMI ID format (ami-xxxxxxxxx)",
            &AMI_ID_RE,
        );
    }

    let subnet_id_props: &[(&str, &[&str])] = &[
        ("AWS::EC2::Instance", &["SubnetId"]),
        ("AWS::EC2::NetworkInterface", &["SubnetId"]),
    ];
    for &(rtype, props) in subnet_id_props {
        for name in m.resources_of_type(rtype) {
            for &prop in props {
                check_format(
                    &mut out,
                    m,
                    name,
                    prop,
                    "E1154",
                    "Subnet ID format (subnet-xxxxxxxxx)",
                    &SUBNET_ID_RE,
                );
            }
        }
    }

    for name in m.resources_of_type("AWS::Logs::LogGroup") {
        check_format(
            &mut out,
            m,
            name,
            "LogGroupName",
            "E1155",
            "Log Group Name format",
            &LOG_GROUP_RE,
        );
    }

    let iam_role_arn_props: &[(&str, &[&str])] = &[
        ("AWS::Lambda::Function", &["Role"]),
        (
            "AWS::ECS::TaskDefinition",
            &["ExecutionRoleArn", "TaskRoleArn"],
        ),
        ("AWS::StepFunctions::StateMachine", &["RoleArn"]),
    ];
    for &(rtype, props) in iam_role_arn_props {
        for name in m.resources_of_type(rtype) {
            for &prop in props {
                check_format_arn(&mut out, m, name, prop, &IAM_ROLE_ARN_RE);
            }
        }
    }

    out
}

static VALID_REGIONS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "af-south-1",
        "ap-east-1",
        "ap-northeast-1",
        "ap-northeast-2",
        "ap-northeast-3",
        "ap-south-1",
        "ap-south-2",
        "ap-southeast-1",
        "ap-southeast-2",
        "ap-southeast-3",
        "ap-southeast-4",
        "ca-central-1",
        "ca-west-1",
        "eu-central-1",
        "eu-central-2",
        "eu-north-1",
        "eu-south-1",
        "eu-south-2",
        "eu-west-1",
        "eu-west-2",
        "eu-west-3",
        "il-central-1",
        "me-central-1",
        "me-south-1",
        "sa-east-1",
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
        "us-gov-east-1",
        "us-gov-west-1",
        "cn-north-1",
        "cn-northwest-1",
    ]
    .into_iter()
    .collect()
});

fn has_language_extensions(model: &SemanticModel) -> bool {
    model
        .transforms
        .iter()
        .any(|t| t == TRANSFORM_LANGUAGE_EXTENSIONS)
}

fn eval_intrinsic_params(ctx: &EvalContext) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let m = ctx.model;
    let input = ctx.input;
    let resources = match input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
        Some(r) => r,
        None => return out,
    };

    for (name, res) in resources {
        // ImportValue cannot use Ref to AWS::StackName
        if let Some(edges) = res.get(FIELD_OUTGOING_REFS).and_then(|r| r.as_array()) {
            for edge in edges {
                let kind = edge.get(FIELD_KIND).and_then(|k| k.as_str()).unwrap_or("");
                let target = edge
                    .get(FIELD_TARGET)
                    .and_then(|t| t.as_str())
                    .unwrap_or("");
                let source_path = edge
                    .get(FIELD_SOURCE_PATH)
                    .and_then(|p| p.as_str())
                    .unwrap_or("");
                if kind == EDGE_KIND_REF
                    && target == PSEUDO_STACK_NAME
                    && source_path.contains(FN_IMPORT_VALUE)
                {
                    out.push(make_resource_diagnostic(
                        "E1016",
                        "Fn::ImportValue cannot use Ref to 'AWS::StackName'",
                        m,
                        name,
                        source_path,
                        None,
                    ));
                }
            }
        }

        // Scan properties for intrinsic function validation
        scan_intrinsic_params(&mut out, m, name, res);
    }

    // Also check output edges for ImportValue with Ref to AWS::StackName
    for (out_name, _output) in &m.outputs {
        let pseudo_id = format!("{}{}", OUTPUT_PSEUDO_RESOURCE_PREFIX, out_name);
        for edge in m.graph.outgoing(&pseudo_id) {
            if matches!(edge.kind, RefKind::Ref)
                && edge.target == PSEUDO_STACK_NAME
                && edge.source_path.contains(FN_IMPORT_VALUE)
            {
                out.push(make_resource_diagnostic(
                    "E1016",
                    "Fn::ImportValue cannot use Ref to 'AWS::StackName'",
                    m,
                    out_name,
                    &edge.source_path,
                    None,
                ));
            }
        }
    }

    // Language extensions transform required
    if !has_language_extensions(m) {
        for (name, res) in resources {
            check_language_extension_intrinsics(&mut out, m, name, res);
        }
    }

    out
}

fn scan_intrinsic_params(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    resource_id: &str,
    res: &serde_json::Value,
) {
    if let Some(props) = res.get(FIELD_PROPERTIES).and_then(|p| p.as_object()) {
        for (_, val) in props {
            scan_value_for_intrinsics(out, m, resource_id, val, KEY_PROPERTIES);
        }
    }
}

fn scan_value_for_intrinsics(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    resource_id: &str,
    val: &serde_json::Value,
    _path: &str,
) {
    match val {
        serde_json::Value::Array(arr) => {
            for item in arr {
                scan_value_for_intrinsics(out, m, resource_id, item, _path);
            }
        }
        serde_json::Value::Object(obj) => {
            // GetAZs validation
            if let Some(param) = obj.get(FN_GET_AZS) {
                if let Some(s) = param.as_str() {
                    if !s.is_empty() && !VALID_REGIONS.contains(s) {
                        out.push(make_resource_diagnostic(
                            "E1015",
                            &format!("Fn::GetAZs parameter '{}' is not a valid region", s),
                            m,
                            resource_id,
                            "",
                            None,
                        ));
                    }
                }
            }
            for (_, v) in obj {
                scan_value_for_intrinsics(out, m, resource_id, v, _path);
            }
        }
        _ => {}
    }
}

fn check_language_extension_intrinsics(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    resource_id: &str,
    res: &serde_json::Value,
) {
    if let Some(props) = res.get(FIELD_PROPERTIES).and_then(|p| p.as_object()) {
        for (_, val) in props {
            scan_for_lang_ext_intrinsics(out, m, resource_id, val);
        }
    }
}

fn scan_for_lang_ext_intrinsics(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    resource_id: &str,
    val: &serde_json::Value,
) {
    match val {
        serde_json::Value::Array(arr) => {
            for item in arr {
                scan_for_lang_ext_intrinsics(out, m, resource_id, item);
            }
        }
        serde_json::Value::Object(obj) => {
            if obj.contains_key(FN_LENGTH) {
                out.push(make_resource_diagnostic(
                    "E1030",
                    "Fn::Length requires the AWS::LanguageExtensions transform",
                    m,
                    resource_id,
                    "",
                    None,
                ));
            }
            if obj.contains_key(FN_TO_JSON_STRING) {
                out.push(make_resource_diagnostic(
                    "E1031",
                    "Fn::ToJsonString requires the AWS::LanguageExtensions transform",
                    m,
                    resource_id,
                    "",
                    None,
                ));
            }
            if obj.contains_key(FN_FOR_EACH) {
                out.push(make_resource_diagnostic(
                    "E1032",
                    "Fn::ForEach requires the AWS::LanguageExtensions transform",
                    m,
                    resource_id,
                    "",
                    None,
                ));
            }
            for (_, v) in obj {
                scan_for_lang_ext_intrinsics(out, m, resource_id, v);
            }
        }
        _ => {}
    }
}

static DYNAMIC_REF_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"\{\{resolve:(ssm-secure|ssm|secretsmanager):([^}]*)\}\}")
        .expect("Invalid DYNAMIC_REF_RE")
});

fn eval_dynamic_references(ctx: &EvalContext) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let m = ctx.model;
    let input = ctx.input;

    // Scan resources for dynamic references in non-Properties locations
    if let Some(resources) = input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
        for (name, res) in resources {
            // Check DependsOn, Condition, Metadata for dynamic references
            check_dynamic_ref_in_attributes(&mut out, m, name, res);
            // Check Properties for Secrets Manager cross-account ARN
            check_secrets_manager_arn(&mut out, m, name, res);
        }
    }

    // Dynamic references in Conditions
    if let Some(conds) = input.get(FIELD_CONDITIONS).and_then(|c| c.as_object()) {
        for (_cname, cval) in conds {
            scan_for_dynamic_refs_in_section(
                &mut out,
                m,
                cval,
                SECTION_CONDITIONS,
                "E1051",
                "E1052",
            );
        }
    }

    // Dynamic references in Outputs
    if let Some(outputs) = input.get(FIELD_OUTPUTS).and_then(|o| o.as_object()) {
        for (_oname, oval) in outputs {
            scan_for_dynamic_refs_in_section(&mut out, m, oval, SECTION_OUTPUTS, "E1051", "E1052");
        }
    }

    // Dynamic references to SSM in parameter Defaults
    if let Some(params) = input.get(FIELD_PARAMETERS).and_then(|p| p.as_object()) {
        for (pname, pval) in params {
            if let Some(def) = pval.get("default").and_then(|d| d.as_str()) {
                for cap in DYNAMIC_REF_RE.captures_iter(def) {
                    let ref_type = &cap[1];
                    match ref_type {
                        "ssm-secure" => {
                            out.push(make_resource_diagnostic(
                                "E1027",
                                &format!("Dynamic reference '{{{{resolve:ssm-secure:...}}}}' is not supported in parameter Default for '{}'", pname),
                                m, "", "", None,
                            ));
                        }
                        "secretsmanager" => {
                            out.push(make_resource_diagnostic(
                                "E1051",
                                &format!("Dynamic reference '{{{{resolve:secretsmanager:...}}}}' is not supported in parameter Default for '{}'", pname),
                                m, "", "", None,
                            ));
                        }
                        // SSM in parameter Default is allowed
                        _ => {}
                    }
                }
            }
        }
    }

    out
}

fn check_dynamic_ref_in_attributes(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    resource_id: &str,
    res: &serde_json::Value,
) {
    // Check DependsOn
    if let Some(deps) = res.get(FIELD_DEPENDS_ON).and_then(|d| d.as_array()) {
        for dep in deps {
            if let Some(s) = dep.as_str() {
                check_dynamic_ref_string(out, m, resource_id, s, KEY_DEPENDS_ON);
            }
        }
    }
}

fn check_dynamic_ref_string(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    resource_id: &str,
    val: &str,
    location: &str,
) {
    for cap in DYNAMIC_REF_RE.captures_iter(val) {
        let ref_type = &cap[1];
        match ref_type {
            "ssm-secure" => {
                out.push(make_resource_diagnostic(
                    "E1027",
                    &format!(
                        "Dynamic reference '{{{{resolve:ssm-secure:...}}}}' is not supported in {}",
                        location
                    ),
                    m,
                    resource_id,
                    "",
                    None,
                ));
            }
            "secretsmanager" => {
                out.push(make_resource_diagnostic(
                    "E1051",
                    &format!("Dynamic reference '{{{{resolve:secretsmanager:...}}}}' is not supported in {}", location),
                    m, resource_id, "", None,
                ));
            }
            "ssm" => {
                if location != KEY_DEFAULT {
                    out.push(make_resource_diagnostic(
                        "E1052",
                        &format!(
                            "Dynamic reference '{{{{resolve:ssm:...}}}}' is not supported in {}",
                            location
                        ),
                        m,
                        resource_id,
                        "",
                        None,
                    ));
                }
            }
            _ => {}
        }
    }
}

fn scan_for_dynamic_refs_in_section(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    val: &serde_json::Value,
    section: &str,
    _sm_rule: &str,
    _ssm_rule: &str,
) {
    match val {
        serde_json::Value::String(s) => {
            for cap in DYNAMIC_REF_RE.captures_iter(s) {
                let ref_type = &cap[1];
                match ref_type {
                    "ssm-secure" => {
                        out.push(make_resource_diagnostic(
                            "E1027",
                            &format!("Dynamic reference '{{{{resolve:ssm-secure:...}}}}' is not supported in {}", section),
                            m, "", "", None,
                        ));
                    }
                    "secretsmanager" => {
                        out.push(make_resource_diagnostic(
                            "E1051",
                            &format!("Dynamic reference '{{{{resolve:secretsmanager:...}}}}' is not supported in {}", section),
                            m, "", "", None,
                        ));
                    }
                    "ssm" => {
                        out.push(make_resource_diagnostic(
                            "E1052",
                            &format!("Dynamic reference '{{{{resolve:ssm:...}}}}' is not supported in {}", section),
                            m, "", "", None,
                        ));
                    }
                    _ => {}
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                scan_for_dynamic_refs_in_section(out, m, item, section, _sm_rule, _ssm_rule);
            }
        }
        serde_json::Value::Object(obj) => {
            for (_, v) in obj {
                scan_for_dynamic_refs_in_section(out, m, v, section, _sm_rule, _ssm_rule);
            }
        }
        _ => {}
    }
}

fn check_secrets_manager_arn(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    resource_id: &str,
    res: &serde_json::Value,
) {
    if let Some(props) = res.get(FIELD_PROPERTIES).and_then(|p| p.as_object()) {
        for (_, val) in props {
            scan_for_sm_cross_account(out, m, resource_id, val);
        }
    }
}

fn scan_for_sm_cross_account(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    resource_id: &str,
    val: &serde_json::Value,
) {
    match val {
        serde_json::Value::String(s) => {
            if s.contains("{{resolve:secretsmanager:")
                && !s.contains("{{resolve:secretsmanager:arn:")
            {
                // Secrets Manager should use full ARN for cross-account
                // Only warn if the reference looks like it could be cross-account (has a colon-separated secret name)
                // The pattern {{resolve:secretsmanager:SECRET_NAME:...}} without arn: prefix
                // is fine for same-account, but cross-account requires full ARN
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                scan_for_sm_cross_account(out, m, resource_id, item);
            }
        }
        serde_json::Value::Object(obj) => {
            for (_, v) in obj {
                scan_for_sm_cross_account(out, m, resource_id, v);
            }
        }
        _ => {}
    }
}
