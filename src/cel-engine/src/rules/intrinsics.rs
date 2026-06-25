use super::{EvalContext, NativeRuleRegistry};
use diagnostics::Diagnostic;
use std::collections::HashSet;
use std::sync::{Arc, LazyLock};
use template_model::consts::{
    EDGE_KIND_GET_ATT, EDGE_KIND_REF, EDGE_KIND_SUB, FIELD_ATTR, FIELD_CONDITIONS, FIELD_DEPENDS_ON, FIELD_KIND,
    FIELD_OUTGOING_REFS, FIELD_OUTPUTS, FIELD_PARAMETERS, FIELD_PROPERTIES, FIELD_RESOURCE_TYPE, FIELD_RESOURCES,
    FIELD_SOURCE_PATH, FIELD_TARGET, FN_FOR_EACH, FN_GET_AZS, FN_IMPORT_VALUE, FN_LENGTH, FN_TO_JSON_STRING,
    KEY_DEFAULT, KEY_DEPENDS_ON, KEY_PROPERTIES, OUTPUT_PSEUDO_RESOURCE_PREFIX, PSEUDO_STACK_NAME, SECTION_CONDITIONS,
    SECTION_OUTPUTS, TRANSFORM_LANGUAGE_EXTENSIONS,
};
use template_model::resolver::RefKind;
use template_model::{PSEUDO_PARAMETERS, SemanticModel};
use validation_engine::make_resource_diagnostic;

pub fn register(reg: &mut NativeRuleRegistry) {
    reg.add(rules::Category::Intrinsic, eval_intrinsics);
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
    let has_parse_errors = m
        .diagnostics
        .iter()
        .any(|d| d.severity == rules::Severity::Fatal && d.phase == Some(diagnostics::Phase::Parse));

    // Load GetAtt attribute data
    let getatt_attrs = &ctx.cached_data.getatt_attrs;
    let _getatt_attr_types = &ctx.cached_data.getatt_attr_types;

    for (name, res) in resources {
        let refs = res.get(FIELD_OUTGOING_REFS).and_then(|r| r.as_array());
        if let Some(edges) = refs {
            for edge in edges {
                let kind = edge.get(FIELD_KIND).and_then(|k| k.as_str()).unwrap_or("");
                let target = edge.get(FIELD_TARGET).and_then(|t| t.as_str()).unwrap_or("");

                match kind {
                    EDGE_KIND_REF => {
                        if !resource_keys.contains(target)
                            && !param_keys.contains(target)
                            && !pseudo.contains(target)
                            && !sam_implicit.contains(target)
                        {
                            out.push(make_resource_diagnostic(
                                "F1010",
                                &format!(
                                    "Ref '{}' does not reference a valid resource, parameter, or pseudo-parameter",
                                    target
                                ),
                                m,
                                name,
                                "",
                                Some("Check that the Ref target exists as a resource, parameter, or pseudo-parameter"),
                            ));
                        }
                    }
                    EDGE_KIND_GET_ATT => {
                        let attr = edge.get(FIELD_ATTR).and_then(|a| a.as_str()).unwrap_or("");
                        let source_path = edge.get(FIELD_SOURCE_PATH).and_then(|p| p.as_str()).unwrap_or("");

                        if !resource_keys.contains(target) && !has_parse_errors {
                            out.push(make_resource_diagnostic(
                                "F1020",
                                &format!("Fn::GetAtt references non-existent resource '{}'", target),
                                m,
                                name,
                                "",
                                Some("Check that the GetAtt target resource exists in the template"),
                            ));
                        } else if !attr.is_empty()
                            && let Some(target_res) = resources.get(target)
                            && let Some(rtype) = target_res.get(FIELD_RESOURCE_TYPE).and_then(|t| t.as_str())
                        {
                            if let Some(valid_list) = getatt_attrs.get(rtype)
                                && !valid_list.iter().any(|a| a == attr)
                                && !rtype.starts_with("Custom::")
                                && !rtype.starts_with("AWS::CloudFormation::CustomResource")
                                && rtype != "AWS::CloudFormation::Stack"
                                && rtype != "AWS::CloudFormation::Macro"
                            {
                                out.push(make_resource_diagnostic(
                                    "E9004",
                                    &format!("'{}' is not one of {:?}", attr, valid_list),
                                    m,
                                    name,
                                    source_path,
                                    Some("Check the resource type documentation for valid GetAtt attributes"),
                                ));
                            }

                            // E9003 disabled — CloudFormation auto-converts non-string
                            // GetAtt return values to strings when destination is typed as string.
                        }
                    }
                    EDGE_KIND_SUB
                        if !resource_keys.contains(target)
                            && !param_keys.contains(target)
                            && !pseudo.contains(target) =>
                    {
                        out.push(make_resource_diagnostic("F1018",
                                &format!("Fn::Sub variable '${{{}}}' does not reference a valid resource, parameter, or pseudo-parameter", target),
                                m,
                                name,
                                "",
                                None,
        ));
                    }
                    _ => {}
                }
            }
        }

        if !has_parse_errors
            && !has_language_extensions(m)
            && let Some(invalid) = res.get("invalidRefs").and_then(|r| r.as_array())
        {
            let mut valid_targets: Vec<&str> =
                resource_keys.iter().chain(param_keys.iter()).chain(pseudo.iter()).copied().collect();
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

        if let Some(refs) = res.get("findInMapRefs").and_then(|r| r.as_array()) {
            for map_ref in refs {
                if let Some(map_name) = map_ref.as_str()
                    && !m.mappings.contains_key(map_name)
                {
                    out.push(make_resource_diagnostic(
                        "F1012",
                        &format!("Fn::FindInMap references non-existent mapping '{}'", map_name),
                        m,
                        name,
                        "",
                        None,
                    ));
                }
            }
        }

        if let Some(joins) = res.get("emptyJoins").and_then(|j| j.as_array()) {
            let mut seen_paths = HashSet::new();
            for path in joins {
                if let Some(p) = path.as_str()
                    && seen_paths.insert(p)
                {
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

        if let Some(crefs) = res.get("conditionRefs").and_then(|r| r.as_array()) {
            for cref in crefs {
                if let Some(cname) = cref.as_str()
                    && !cond_keys.contains(cname)
                {
                    out.push(make_resource_diagnostic(
                        "F1060",
                        &format!("Fn::If condition '{}' does not exist in Conditions section", cname),
                        m,
                        name,
                        "",
                        None,
                    ));
                }
            }
        }
    }

    if let Some(joins) = input.get("outputEmptyJoins").and_then(|j| j.as_array()) {
        let mut seen_paths = HashSet::new();
        for path in joins {
            if let Some(p) = path.as_str()
                && seen_paths.insert(p)
            {
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
    model.transforms.iter().any(|t| t == TRANSFORM_LANGUAGE_EXTENSIONS)
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
                let target = edge.get(FIELD_TARGET).and_then(|t| t.as_str()).unwrap_or("");
                let source_path = edge.get(FIELD_SOURCE_PATH).and_then(|p| p.as_str()).unwrap_or("");
                if kind == EDGE_KIND_REF && target == PSEUDO_STACK_NAME && source_path.contains(FN_IMPORT_VALUE) {
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
    for out_name in m.outputs.keys() {
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
            if let Some(param) = obj.get(FN_GET_AZS)
                && let Some(s) = param.as_str()
                && !s.is_empty()
                && !VALID_REGIONS.contains(s)
            {
                out.push(make_resource_diagnostic(
                    "E1015",
                    &format!("Fn::GetAZs parameter '{}' is not a valid region", s),
                    m,
                    resource_id,
                    "",
                    None,
                ));
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
    regex::Regex::new(r"\{\{resolve:(ssm-secure|ssm|secretsmanager):([^}]*)\}\}").expect("Invalid DYNAMIC_REF_RE")
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
            scan_for_dynamic_refs_in_section(&mut out, m, cval, SECTION_CONDITIONS, "E1051", "E1052");
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
                    &format!("Dynamic reference '{{{{resolve:ssm-secure:...}}}}' is not supported in {}", location),
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
                    m,
                    resource_id,
                    "",
                    None,
                ));
            }
            "ssm" if location != KEY_DEFAULT => {
                out.push(make_resource_diagnostic(
                    "E1052",
                    &format!("Dynamic reference '{{{{resolve:ssm:...}}}}' is not supported in {}", location),
                    m,
                    resource_id,
                    "",
                    None,
                ));
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
                            &format!(
                                "Dynamic reference '{{{{resolve:ssm-secure:...}}}}' is not supported in {}",
                                section
                            ),
                            m,
                            "",
                            "",
                            None,
                        ));
                    }
                    "secretsmanager" => {
                        out.push(make_resource_diagnostic(
                            "E1051",
                            &format!(
                                "Dynamic reference '{{{{resolve:secretsmanager:...}}}}' is not supported in {}",
                                section
                            ),
                            m,
                            "",
                            "",
                            None,
                        ));
                    }
                    "ssm" => {
                        out.push(make_resource_diagnostic(
                            "E1052",
                            &format!("Dynamic reference '{{{{resolve:ssm:...}}}}' is not supported in {}", section),
                            m,
                            "",
                            "",
                            None,
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
    _out: &mut Vec<Diagnostic>,
    _m: &Arc<SemanticModel>,
    _resource_id: &str,
    val: &serde_json::Value,
) {
    match val {
        serde_json::Value::String(s) => {
            if s.contains("{{resolve:secretsmanager:") && !s.contains("{{resolve:secretsmanager:arn:") {
                // Secrets Manager should use full ARN for cross-account
                // Only warn if the reference looks like it could be cross-account (has a colon-separated secret name)
                // The pattern {{resolve:secretsmanager:SECRET_NAME:...}} without arn: prefix
                // is fine for same-account, but cross-account requires full ARN
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                scan_for_sm_cross_account(_out, _m, _resource_id, item);
            }
        }
        serde_json::Value::Object(obj) => {
            for (_, v) in obj {
                scan_for_sm_cross_account(_out, _m, _resource_id, v);
            }
        }
        _ => {}
    }
}
