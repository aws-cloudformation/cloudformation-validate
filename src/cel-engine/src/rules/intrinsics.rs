use super::{EvalContext, NativeRuleRegistry};
use diagnostics::Diagnostic;
use diagnostics::Phase;
use diagnostics::message::render_str_list;
use rules::{Category, Severity};
use std::collections::HashSet;
use std::sync::Arc;
use template_model::consts::{
    EDGE_KIND_GET_ATT, EDGE_KIND_REF, EDGE_KIND_SUB, FIELD_ATTR, FIELD_KIND, FIELD_OUTGOING_REFS, FIELD_PARAMETERS,
    FIELD_PROPERTIES, FIELD_RESOURCE_TYPE, FIELD_RESOURCES, FIELD_SOURCE_PATH, FIELD_TARGET, FN_GET_AZS,
    FN_IMPORT_VALUE, KEY_PROPERTIES, OUTPUT_PSEUDO_RESOURCE_PREFIX, PSEUDO_STACK_NAME, TRANSFORM_LANGUAGE_EXTENSIONS,
};
use template_model::resolver::RefKind;
use template_model::{PSEUDO_PARAMETERS, SemanticModel, is_known_region};
use validation_engine::make_resource_diagnostic;

pub fn register(reg: &mut NativeRuleRegistry) {
    reg.add(Category::Intrinsic, eval_intrinsics);
    reg.add(Category::Intrinsic, eval_intrinsic_params);
    reg.add(Category::Intrinsic, eval_unused_sub_keys);
    reg.add(Category::Intrinsic, eval_raw_pseudo_params);
    reg.add(Category::Intrinsic, eval_secretsmanager_arn);
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
    let sam_implicit: HashSet<&str> = input
        .get("samImplicitResources")
        .and_then(|s| s.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    // Suppress ref validation when the template has parse errors — the model
    // is incomplete and refs to unparsed sections would be false positives.
    let has_parse_errors = m.diagnostics.iter().any(|d| d.severity == Severity::Fatal && d.phase == Some(Phase::Parse));

    // Load GetAtt attribute data
    let getatt_attrs = &ctx.cached_data.getatt_attrs;

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

                        if !resource_keys.contains(target) && !sam_implicit.contains(target) && !has_parse_errors {
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
                            && let Some(valid_list) = getatt_attrs.get(rtype)
                            && !valid_list.iter().any(|a| a == attr)
                            && !getatt_attr_is_map_member(attr, rtype)
                            && !rtype.starts_with("Custom::")
                            && !rtype.starts_with("AWS::CloudFormation::CustomResource")
                            && rtype != "AWS::CloudFormation::Stack"
                            && rtype != "AWS::CloudFormation::Macro"
                        {
                            // The return-type-mismatch check is intentionally not emitted here:
                            // CloudFormation auto-converts non-string GetAtt return values to
                            // strings when the destination is typed as string.
                            out.push(make_resource_diagnostic(
                                "E9004",
                                &format!("'{}' is not one of {}", attr, render_str_list(valid_list)),
                                m,
                                name,
                                source_path,
                                Some("Check the resource type documentation for valid GetAtt attributes"),
                            ));
                        }
                    }
                    EDGE_KIND_SUB
                        if !resource_keys.contains(target)
                            && !param_keys.contains(target)
                            && !pseudo.contains(target)
                            && !sam_implicit.contains(target) =>
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
                    &format!("'{}' is not one of {}", target, render_str_list(&valid_targets)),
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

fn has_language_extensions(model: &SemanticModel) -> bool {
    model.transforms.iter().any(|t| t == TRANSFORM_LANGUAGE_EXTENSIONS)
}

/// Whether a dotted GetAtt attribute (e.g. `Outputs.SomeKey`) addresses a member
/// of an open-ended map attribute that CloudFormation exposes as `<Attr>.<key>`
/// for any key. Only two resource types have such an attribute: nested stacks and
/// provisioned products both expose `Outputs.<OutputKey>`. Nested stacks
/// (`AWS::CloudFormation::Stack`) are already skipped entirely before this check,
/// so the only type that reaches here needing the exemption is the provisioned
/// product. Every other dotted attribute (e.g. `Tags.0` on a bucket) is a real
/// attribute-validity error, because CloudFormation does not expose an
/// object/array attribute as itself indexable via GetAtt.
fn getatt_attr_is_map_member(attr: &str, rtype: &str) -> bool {
    rtype == "AWS::ServiceCatalog::CloudFormationProvisionedProduct" && attr.starts_with("Outputs.")
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
                && !is_known_region(s)
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

fn eval_unused_sub_keys(ctx: &EvalContext) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let m = ctx.model;
    let input = ctx.input;

    let resources = match input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
        Some(r) => r,
        None => return out,
    };

    for (name, res) in resources {
        if let Some(entries) = res.get("unusedSubKeys").and_then(|v| v.as_array()) {
            for entry in entries {
                let path = entry.get("path").and_then(|p| p.as_str()).unwrap_or("");
                let variable = entry.get("variable").and_then(|v| v.as_str()).unwrap_or("");
                out.push(make_resource_diagnostic(
                    "W1019",
                    &format!("Parameter '{}' not used in Fn::Sub template string", variable),
                    m,
                    name,
                    path,
                    Some("Remove the unused key from the Fn::Sub variable map or reference it in the template string"),
                ));
            }
        }
    }

    out
}

fn eval_raw_pseudo_params(ctx: &EvalContext) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let m = ctx.model;
    let input = ctx.input;

    let resources = match input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
        Some(r) => r,
        None => return out,
    };

    for (name, res) in resources {
        if let Some(entries) = res.get("rawPseudoParams").and_then(|v| v.as_array()) {
            for entry in entries {
                let path = entry.get("path").and_then(|p| p.as_str()).unwrap_or("");
                let variable = entry.get("variable").and_then(|v| v.as_str()).unwrap_or("");
                out.push(make_resource_diagnostic(
                    "W1054",
                    &format!(
                        "Found a string '{}' that appears to be a pseudo parameter reference; use 'Ref: {}' instead",
                        variable, variable
                    ),
                    m,
                    name,
                    path,
                    Some("Use Ref to reference pseudo parameters instead of embedding them as literal strings"),
                ));
            }
        }
    }

    out
}

fn eval_secretsmanager_arn(ctx: &EvalContext) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let m = ctx.model;
    let input = ctx.input;
    let arn_fields = &ctx.cached_data.secretsmanager_arn_fields;

    if arn_fields.is_empty() {
        return out;
    }

    let resources = match input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
        Some(r) => r,
        None => return out,
    };

    for (name, res) in resources {
        if let Some(paths) = res.get("secretsmanagerRefPaths").and_then(|v| v.as_array()) {
            for path_val in paths {
                let path = path_val.as_str().unwrap_or("");
                if arn_fields.iter().any(|field| path_segment_matches(path, field)) {
                    out.push(make_resource_diagnostic(
                        "W1051",
                        "Dynamic reference resolves the secret value but this property expects the secret ARN",
                        m,
                        name,
                        path,
                        Some("Use the secret ARN directly or retrieve it from Fn::GetAtt instead of using a resolve reference"),
                    ));
                }
            }
        }
    }

    out
}

fn path_segment_matches(path: &str, field: &str) -> bool {
    path.split('.').any(|segment| segment == field)
}
