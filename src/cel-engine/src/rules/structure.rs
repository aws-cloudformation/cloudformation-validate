use super::intrinsics::getatt_attr_is_map_member;
use super::{EvalContext, NativeRuleRegistry};
use diagnostics::Diagnostic;
use rules::Category;
use std::collections::HashSet;
use std::sync::LazyLock;
use template_model::consts::{
    EDGE_KIND_GET_ATT, EDGE_KIND_REF, EDGE_KIND_SUB, FIELD_ATTR, FIELD_CONDITION, FIELD_CONDITIONS, FIELD_EDGES,
    FIELD_KIND, FIELD_MAPPINGS, FIELD_OUTGOING_REFS, FIELD_OUTPUTS, FIELD_PARAMETERS, FIELD_RESOURCE_TYPE,
    FIELD_RESOURCES, FIELD_SOURCE, FIELD_SOURCE_PATH, FIELD_TARGET, FN_FOR_EACH, FN_FOR_EACH_KEY_PREFIX, FN_IF,
    FN_TRANSFORM, KEY_DELETION_POLICY, KEY_UPDATE_REPLACE_POLICY, MARKER_CONDITIONAL, MARKER_DYNAMIC, MARKER_ENUM,
    MARKER_REF, OUTPUT_PSEUDO_RESOURCE_PREFIX, PARAM_TYPE_COMMA_DELIMITED_LIST, PARAM_TYPE_NUMBER, PARAM_TYPE_STRING,
    POLICY_DELETE, POLICY_RETAIN, POLICY_RETAIN_EXCEPT_ON_CREATE, POLICY_SNAPSHOT, SECTION_CONDITIONS,
    SECTION_DESCRIPTION, SECTION_FORMAT_VERSION, SECTION_GLOBALS, SECTION_MAPPINGS, SECTION_METADATA, SECTION_OUTPUTS,
    SECTION_PARAMETERS, SECTION_RESOURCES, SECTION_RULES, SECTION_TRANSFORM, TRANSFORM_LANGUAGE_EXTENSIONS,
    TRANSFORM_SERVERLESS,
};
use template_model::message::render_str_list;
use template_model::{FORMAT_VERSION, PSEUDO_PARAMETERS, is_custom_resource_type, is_service_valid};
use validation_engine::make_resource_diagnostic;

/// Alphanumeric-only string: CloudFormation logical IDs, output names, and
/// second-level mapping keys.
static ALPHANUM_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[a-zA-Z0-9]+$").expect("Invalid ALPHANUM_RE pattern"));

static NUM_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^-?[0-9]+(\.[0-9]+)?$").expect("Invalid NUM_RE pattern"));

/// First-level mapping keys additionally allow `.` and `-`.
static MAPPING_TOP_KEY_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[a-zA-Z0-9.\-]+$").expect("Invalid MAPPING_TOP_KEY_RE pattern"));

pub fn register(reg: &mut NativeRuleRegistry) {
    reg.add(Category::Structure, eval_structure);
    reg.add(Category::Structure, eval_template_size_and_transforms);
}

fn eval_structure(ctx: &EvalContext) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let m = ctx.model;
    let input = ctx.input;

    if m.resources.is_empty() {
        out.push(make_resource_diagnostic("F0001", "Resources section must exist and be non-empty", m, "", "", None));
    }

    if let Some(fv) = input.get("template").and_then(|t| t.get("formatVersion")).and_then(|v| v.as_str())
        && fv != FORMAT_VERSION
    {
        out.push(make_resource_diagnostic(
            "F0002",
            &format!("AWSTemplateFormatVersion must be '{}', got '{}'", FORMAT_VERSION, fv),
            m,
            "",
            SECTION_FORMAT_VERSION,
            None,
        ));
    }

    if m.parameters.len() > 200 {
        out.push(make_resource_diagnostic(
            "F0003",
            &format!("Template has {} parameters, maximum is 200", m.parameters.len()),
            m,
            "",
            "",
            None,
        ));
    }

    let output_count = input.get(FIELD_OUTPUTS).and_then(|o| o.as_object()).map(|o| o.len()).unwrap_or(0);
    if output_count > 200 {
        out.push(make_resource_diagnostic(
            "F0004",
            &format!("Template has {} outputs, maximum is 200", output_count),
            m,
            "",
            "",
            None,
        ));
    }

    if m.resources.len() > 500 {
        out.push(make_resource_diagnostic(
            "F0007",
            &format!("Template has {} resources, maximum is 500", m.resources.len()),
            m,
            "",
            "",
            None,
        ));
    }

    if m.mappings.len() > 200 {
        out.push(make_resource_diagnostic(
            "F0008",
            &format!("Template has {} mappings, maximum is 200", m.mappings.len()),
            m,
            "",
            "",
            None,
        ));
    }

    let cond_count = input.get(FIELD_CONDITIONS).and_then(|c| c.as_object()).map(|c| c.len()).unwrap_or(0);
    if cond_count > 200 {
        out.push(make_resource_diagnostic(
            "F0009",
            &format!("Template has {} conditions, maximum is 200", cond_count),
            m,
            "",
            "",
            None,
        ));
    }

    let valid_sections: HashSet<&str> = [
        SECTION_FORMAT_VERSION,
        SECTION_DESCRIPTION,
        SECTION_METADATA,
        SECTION_PARAMETERS,
        SECTION_RULES,
        SECTION_MAPPINGS,
        SECTION_CONDITIONS,
        SECTION_TRANSFORM,
        SECTION_RESOURCES,
        SECTION_OUTPUTS,
        SECTION_GLOBALS, // SAM
    ]
    .into_iter()
    .collect();
    if let Some(raw_keys) = input.get("template").and_then(|t| t.get("rawTopLevelKeys")).and_then(|v| v.as_array()) {
        for key_val in raw_keys {
            if let Some(key) = key_val.as_str()
                && !valid_sections.contains(key)
            {
                out.push(make_resource_diagnostic(
                    "F0005",
                    &format!("'{}' is not a valid top-level template section", key),
                    m,
                    "",
                    key,
                    None,
                ));
            }
        }
    }

    // Approaching-limit warnings (>90% threshold)
    let param_count = m.parameters.len();
    if param_count > 180 && param_count <= 200 {
        out.push(make_resource_diagnostic(
            "I2010",
            &format!("Template has {} parameters, approaching limit of 200", param_count),
            m,
            "",
            "",
            None,
        ));
    }
    if output_count > 180 && output_count <= 200 {
        out.push(make_resource_diagnostic(
            "I6010",
            &format!("Template has {} outputs, approaching limit of 200", output_count),
            m,
            "",
            "",
            None,
        ));
    }
    if m.mappings.len() > 180 && m.mappings.len() <= 200 {
        out.push(make_resource_diagnostic(
            "I7010",
            &format!("Template has {} mappings, approaching limit of 200", m.mappings.len()),
            m,
            "",
            "",
            None,
        ));
    }

    for (pname, param) in &m.parameters {
        let param_path = format!("{}/{}", SECTION_PARAMETERS, pname);
        if !ALPHANUM_RE.is_match(pname) {
            out.push(make_resource_diagnostic(
                "F2003",
                &format!("Parameter name '{}' must be alphanumeric", pname),
                m,
                "",
                &param_path,
                None,
            ));
        }

        if pname.len() > 255 {
            out.push(make_resource_diagnostic(
                "F2011",
                &format!("Parameter name '{}' exceeds maximum length of 255", pname),
                m,
                "",
                &param_path,
                None,
            ));
        } else if pname.len() > 229 {
            out.push(make_resource_diagnostic(
                "I2011",
                &format!("Parameter name '{}' is approaching maximum length of 255", pname),
                m,
                "",
                &param_path,
                None,
            ));
        }

        if !is_valid_parameter_type(&param.param_type) {
            out.push(make_resource_diagnostic(
                "F2002",
                &format!("Parameter '{}' has invalid Type '{}'", pname, param.param_type),
                m,
                "",
                &format!("{}/Type", param_path),
                None,
            ));
        }
    }

    if let Some(outputs_obj) = input.get(FIELD_OUTPUTS).and_then(|o| o.as_object()) {
        for oname in outputs_obj.keys() {
            let output_path = format!("{}/{}", SECTION_OUTPUTS, oname);
            if !ALPHANUM_RE.is_match(oname) {
                // Fn::ForEach:: prefixed keys are ForEach constructs, not literal output names
                if oname.starts_with(FN_FOR_EACH_KEY_PREFIX) {
                    continue;
                }
                out.push(make_resource_diagnostic(
                    "F6004",
                    &format!("Output name '{}' must be alphanumeric", oname),
                    m,
                    "",
                    &output_path,
                    None,
                ));
            }
            if oname.len() > 255 {
                out.push(make_resource_diagnostic(
                    "F6011",
                    &format!("Output name '{}' exceeds maximum length of 255", oname),
                    m,
                    "",
                    &output_path,
                    None,
                ));
            } else if oname.len() > 229 {
                out.push(make_resource_diagnostic(
                    "I6011",
                    &format!("Output name '{}' is approaching maximum length of 255", oname),
                    m,
                    "",
                    &output_path,
                    None,
                ));
            }
        }
    }

    for mname in m.mappings.keys() {
        let mapping_path = format!("{}/{}", SECTION_MAPPINGS, mname);
        if mname.len() > 255 {
            out.push(make_resource_diagnostic(
                "F7002",
                &format!("Mapping name '{}' exceeds maximum length of 255", mname),
                m,
                "",
                &mapping_path,
                None,
            ));
        } else if mname.len() > 229 {
            out.push(make_resource_diagnostic(
                "I7002",
                &format!("Mapping name '{}' is approaching maximum length of 255", mname),
                m,
                "",
                &mapping_path,
                None,
            ));
        }
    }

    if let Some(desc) = input.get("template").and_then(|t| t.get("description")).and_then(|v| v.as_str())
        && desc.chars().count() > 921
        && desc.chars().count() <= 1024
    {
        out.push(make_resource_diagnostic(
            "I1003",
            &format!("Description length {} is approaching maximum of 1024", desc.chars().count()),
            m,
            "",
            "",
            None,
        ));
    }

    for pname in m.parameters.keys() {
        if m.resources.contains_key(pname) {
            out.push(make_resource_diagnostic(
                "F3007",
                &format!("'{}' is used as both a parameter and resource logical ID", pname),
                m,
                pname,
                "",
                None,
            ));
        }
    }

    if let Some(desc) = input.get("template").and_then(|t| t.get("description")).and_then(|v| v.as_str())
        && desc.chars().count() > 1024
    {
        out.push(make_resource_diagnostic(
            "F0011",
            &format!("Description length {} exceeds maximum 1024", desc.chars().count()),
            m,
            "",
            "",
            None,
        ));
    }

    let has_lang_ext = m.transforms.iter().any(|t| t == TRANSFORM_LANGUAGE_EXTENSIONS);
    for name in m.resources.keys() {
        if name != FN_TRANSFORM
            && !(ALPHANUM_RE.is_match(name) || (has_lang_ext && name.starts_with(FN_FOR_EACH_KEY_PREFIX)))
        {
            out.push(make_resource_diagnostic(
                "F0006",
                &format!("Logical ID '{}' must be alphanumeric (A-Za-z0-9)", name),
                m,
                name,
                "",
                None,
            ));
        }
    }

    if let Some(outputs) = input.get(FIELD_OUTPUTS).and_then(|o| o.as_object()) {
        for (name, out_val) in outputs {
            if out_val.get("value").map(|v| v.is_null()).unwrap_or(true) {
                out.push(make_resource_diagnostic(
                    "F0040",
                    &format!("Output '{}' is missing required 'Value' property", name),
                    m,
                    "",
                    &format!("{}/{}", SECTION_OUTPUTS, name),
                    None,
                ));
            }
        }
    }

    for (map_name, level1) in &m.mappings {
        if level1.len() > 200 {
            out.push(make_resource_diagnostic(
                "F0050",
                &format!("Mapping '{}' has {} top-level keys, maximum is 200", map_name, level1.len()),
                m,
                "",
                &format!("{}/{}", SECTION_MAPPINGS, map_name),
                None,
            ));
        }
        for (key1, level2) in level1 {
            if level2.len() > 200 {
                out.push(make_resource_diagnostic(
                    "F0050",
                    &format!("Mapping '{}'.'{}' has {} attributes, maximum is 200", map_name, key1, level2.len()),
                    m,
                    "",
                    &format!("{}/{}/{}", SECTION_MAPPINGS, map_name, key1),
                    None,
                ));
            }
        }
    }

    for (map_name, level1) in &m.mappings {
        if !ALPHANUM_RE.is_match(map_name) {
            out.push(make_resource_diagnostic(
                "E7001",
                &format!("Mapping name '{}' does not match format '^[a-zA-Z0-9]+$'", map_name),
                m,
                "",
                &format!("{}/{}", SECTION_MAPPINGS, map_name),
                None,
            ));
        }
        for (k1, level2) in level1 {
            if !MAPPING_TOP_KEY_RE.is_match(k1) {
                out.push(make_resource_diagnostic(
                    "E7001",
                    &format!("Mapping '{}' key '{}' does not match format '^[a-zA-Z0-9.-]+$'", map_name, k1),
                    m,
                    "",
                    &format!("{}/{}/{}", SECTION_MAPPINGS, map_name, k1),
                    None,
                ));
            }
            for k2 in level2.keys() {
                if !ALPHANUM_RE.is_match(k2) {
                    out.push(make_resource_diagnostic(
                        "E7001",
                        &format!("Mapping '{}'.'{}' key '{}' does not match format '^[a-zA-Z0-9]+$'", map_name, k1, k2),
                        m,
                        "",
                        &format!("{}/{}/{}/{}", SECTION_MAPPINGS, map_name, k1, k2),
                        None,
                    ));
                }
            }
        }
    }

    const SNAPSHOT_CAPABLE_TYPES: &[&str] = &[
        "AWS::DocDB::DBCluster",
        "AWS::EC2::Volume",
        "AWS::ElastiCache::CacheCluster",
        "AWS::ElastiCache::ReplicationGroup",
        "AWS::Neptune::DBCluster",
        "AWS::RDS::DBCluster",
        "AWS::RDS::DBInstance",
        "AWS::Redshift::Cluster",
    ];
    let base_deletion = [POLICY_DELETE, POLICY_RETAIN, POLICY_RETAIN_EXCEPT_ON_CREATE];
    let base_update = [POLICY_DELETE, POLICY_RETAIN];
    if let Some(resources) = input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
        for (name, _res) in resources {
            let rtype = m.resources.get(name.as_str()).map(|r| r.resource_type.as_str()).unwrap_or("");
            let snapshot_ok = SNAPSHOT_CAPABLE_TYPES.contains(&rtype);

            for scenario_val in m.lifecycle_policy_scenarios(name, KEY_DELETION_POLICY) {
                let allowed = if snapshot_ok {
                    "Delete, Retain, RetainExceptOnCreate, Snapshot"
                } else {
                    "Delete, Retain, RetainExceptOnCreate"
                };
                if let Some(policy) = scenario_val.0.as_str() {
                    let valid = base_deletion.contains(&policy) || (snapshot_ok && policy == POLICY_SNAPSHOT);
                    if !valid {
                        out.push(make_resource_diagnostic(
                            "F3016",
                            &format!("DeletionPolicy must be one of {}, got '{}'", allowed, policy),
                            m,
                            name,
                            KEY_DELETION_POLICY,
                            None,
                        ));
                    }
                } else if let Some(shape) = non_string_policy_shape(&scenario_val.0) {
                    out.push(make_resource_diagnostic(
                        "F3016",
                        &format!("DeletionPolicy must be one of {}, got {}", allowed, shape),
                        m,
                        name,
                        KEY_DELETION_POLICY,
                        None,
                    ));
                }
            }

            for scenario_val in m.lifecycle_policy_scenarios(name, KEY_UPDATE_REPLACE_POLICY) {
                let allowed = if snapshot_ok { "Delete, Retain, Snapshot" } else { "Delete, Retain" };
                if let Some(policy) = scenario_val.0.as_str() {
                    let valid = base_update.contains(&policy) || (snapshot_ok && policy == POLICY_SNAPSHOT);
                    if !valid {
                        out.push(make_resource_diagnostic(
                            "F0018",
                            &format!("UpdateReplacePolicy must be one of {}, got '{}'", allowed, policy),
                            m,
                            name,
                            KEY_UPDATE_REPLACE_POLICY,
                            None,
                        ));
                    }
                } else if let Some(shape) = non_string_policy_shape(&scenario_val.0) {
                    out.push(make_resource_diagnostic(
                        "F0018",
                        &format!("UpdateReplacePolicy must be one of {}, got {}", allowed, shape),
                        m,
                        name,
                        KEY_UPDATE_REPLACE_POLICY,
                        None,
                    ));
                }
            }
        }
    }

    let has_serverless_transform = m.transforms.iter().any(|t| t == TRANSFORM_SERVERLESS);
    if !has_serverless_transform {
        for (name, res) in &m.resources {
            if res.resource_type.starts_with("AWS::Serverless::") {
                out.push(make_resource_diagnostic(
                    "E3038",
                    &format!("Resource type '{}' requires the AWS::Serverless-2016-10-31 transform", res.resource_type),
                    m,
                    name,
                    "",
                    None,
                ));
            }
        }
    }

    for name in m.resources.keys() {
        if name.len() > 200 {
            out.push(make_resource_diagnostic(
                "I3012",
                &format!("Logical ID '{}' is {} characters - approaching the 256 character limit", name, name.len()),
                m,
                name,
                "",
                None,
            ));
        }
    }

    // A transform (SAM, language extensions, or a custom macro) can reference
    // parameters in ways not visible before expansion, so an unreferenced
    // parameter is not a reliable signal once any transform is present.
    //
    // A parameter can be referenced from a section the parser could not read -
    // an unexpanded Fn::ForEach key (the transform that would expand it is
    // missing) or a malformed Conditions section (e.g. authored as a list). In
    // those cases the reference graph is incomplete, so the unused-parameter
    // check is skipped rather than reporting a parameter as unused when the
    // reference simply could not be seen.
    let resources_obj = input.get(FIELD_RESOURCES).and_then(|r| r.as_object());
    let has_unexpanded_foreach = resources_obj.is_some_and(|r| r.keys().any(|k| k.contains(FN_FOR_EACH)));
    let conditions_malformed = input
        .get("template")
        .and_then(|t| t.get("rawTopLevelKeys"))
        .and_then(|v| v.as_array())
        .is_some_and(|keys| keys.iter().any(|k| k.as_str() == Some(SECTION_CONDITIONS)))
        && input.get(FIELD_CONDITIONS).and_then(|c| c.as_object()).map(|c| c.is_empty()).unwrap_or(true);
    if !has_unexpanded_foreach
        && !conditions_malformed
        && m.transforms.is_empty()
        && let Some(params) = input.get(FIELD_PARAMETERS).and_then(|p| p.as_object())
    {
        let resources = resources_obj;
        for pname in params.keys() {
            let mut referenced = false;
            if let Some(res_map) = resources {
                for (_, res) in res_map {
                    if let Some(refs) = res.get(FIELD_OUTGOING_REFS).and_then(|r| r.as_array()) {
                        for edge in refs {
                            if edge.get(FIELD_TARGET).and_then(|t| t.as_str()) == Some(pname.as_str())
                                && let Some(kind) = edge.get(FIELD_KIND).and_then(|k| k.as_str())
                                && (kind == EDGE_KIND_REF || kind == EDGE_KIND_SUB)
                            {
                                referenced = true;
                                break;
                            }
                        }
                    }
                    if !referenced && let Some(subs) = res.get("simpleSubs").and_then(|s| s.as_array()) {
                        for sub in subs {
                            if sub.get("variable").and_then(|v| v.as_str()) == Some(pname.as_str()) {
                                referenced = true;
                                break;
                            }
                        }
                    }
                    if referenced {
                        break;
                    }
                }
            }
            if !referenced && let Some(edges) = input.get(FIELD_EDGES).and_then(|e| e.as_array()) {
                for edge in edges {
                    if edge.get(FIELD_TARGET).and_then(|t| t.as_str()) == Some(pname.as_str()) {
                        referenced = true;
                        break;
                    }
                }
            }
            if !referenced && let Some(refs) = input.get("conditionParamRefs").and_then(|r| r.as_array()) {
                for r in refs {
                    if r.as_str() == Some(pname.as_str()) {
                        referenced = true;
                        break;
                    }
                }
            }
            // Check SAM Globals parameter refs
            if !referenced && let Some(refs) = input.get("globalsParamRefs").and_then(|r| r.as_array()) {
                for r in refs {
                    if r.as_str() == Some(pname.as_str()) {
                        referenced = true;
                        break;
                    }
                }
            }
            // Check references from within other parameter definitions
            if !referenced && let Some(refs) = input.get("paramsReferencedInDefinitions").and_then(|r| r.as_array()) {
                for r in refs {
                    if r.as_str() == Some(pname.as_str()) {
                        referenced = true;
                        break;
                    }
                }
            }
            // Check output edges
            if !referenced && let Some(outputs) = input.get(FIELD_OUTPUTS).and_then(|o| o.as_object()) {
                for (_, out_val) in outputs {
                    if let Some(edges) = out_val.get(FIELD_EDGES).and_then(|e| e.as_array()) {
                        for edge in edges {
                            if edge.get(FIELD_TARGET).and_then(|t| t.as_str()) == Some(pname.as_str()) {
                                referenced = true;
                                break;
                            }
                        }
                    }
                    if referenced {
                        break;
                    }
                }
            }
            if !referenced {
                out.push(make_resource_diagnostic(
                    "W2001",
                    &format!("Parameter '{}' is not referenced anywhere in the template", pname),
                    m,
                    "",
                    &format!("{}/{}", SECTION_PARAMETERS, pname),
                    None,
                ));
            }
        }
    }

    // A FindInMap with a non-literal map name (e.g. a nested FindInMap) makes it
    // impossible to attribute usage to a specific mapping, so the unused-mapping
    // check is disabled entirely. Otherwise a mapping is "used" if its name
    // appears as the literal first argument of any Fn::FindInMap anywhere in the
    // template (resources, outputs, conditions, ForEach bodies), which
    // `findInMapNames` collects template-wide.
    let dynamic_map_name = input.get("hasDynamicFindinmapName").and_then(|v| v.as_bool()).unwrap_or(false);
    if !dynamic_map_name && let Some(mappings) = input.get(FIELD_MAPPINGS).and_then(|m| m.as_object()) {
        let used_names: HashSet<&str> = input
            .get("findInMapNames")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        for mname in mappings.keys() {
            if !used_names.contains(mname.as_str()) {
                out.push(make_resource_diagnostic(
                    "W7001",
                    &format!("Mapping '{}' is not referenced by any Fn::FindInMap", mname),
                    m,
                    "",
                    &format!("{}/{}", SECTION_MAPPINGS, mname),
                    None,
                ));
            }
        }
    }

    if let Some(conds) = input.get(FIELD_CONDITIONS).and_then(|c| c.as_object()) {
        let resources = input.get(FIELD_RESOURCES).and_then(|r| r.as_object());
        let fn_if_conditions: HashSet<&str> = input
            .get("fnIfConditions")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        for cname in conds.keys() {
            if !fn_if_conditions.contains(cname.as_str())
                && !condition_is_referenced(
                    cname,
                    conds,
                    resources,
                    input.get(FIELD_OUTPUTS).and_then(|o| o.as_object()),
                )
            {
                out.push(make_resource_diagnostic(
                    "W8001",
                    &format!("Condition '{}' is not used by any resource or Fn::If", cname),
                    m,
                    "",
                    &format!("{}/{}", SECTION_CONDITIONS, cname),
                    None,
                ));
            }
        }
    }

    for (name, param) in &m.parameters {
        if let (Some(default), Some(allowed)) = (&param.default, &param.allowed_values)
            && !allowed.is_empty()
        {
            let is_cdl = param.param_type == PARAM_TYPE_COMMA_DELIMITED_LIST || param.param_type.starts_with("List<");
            if is_cdl {
                for element in default.split(',').map(|s| s.trim()) {
                    if !allowed.iter().any(|a| a == element) {
                        out.push(make_resource_diagnostic(
                            "F2012",
                            &format!(
                                "Parameter '{}' Default '{}' is not in AllowedValues {}",
                                name,
                                element,
                                render_str_list(allowed)
                            ),
                            m,
                            "",
                            &format!("{}/{}/Default", SECTION_PARAMETERS, name),
                            None,
                        ));
                    }
                }
            } else if !allowed.iter().any(|a| a == default) {
                out.push(make_resource_diagnostic(
                    "F2012",
                    &format!(
                        "Parameter '{}' Default '{}' is not in AllowedValues {}",
                        name,
                        default,
                        render_str_list(allowed)
                    ),
                    m,
                    "",
                    &format!("{}/{}/Default", SECTION_PARAMETERS, name),
                    None,
                ));
            }
        }
    }

    // Output references use top-level edges with a synthetic output source so
    // every diagnostic can retain the precise intrinsic path.
    if let Some(edges) = input.get(FIELD_EDGES).and_then(|value| value.as_array()) {
        let sam_implicit: HashSet<&str> = input
            .get("samImplicitResources")
            .and_then(|value| value.as_array())
            .map(|values| values.iter().filter_map(|value| value.as_str()).collect())
            .unwrap_or_default();
        let has_module_or_foreach = m.resources.values().any(|r| r.resource_type.ends_with("::MODULE"))
            || m.resources.keys().any(|k| k.contains("Fn::ForEach"));
        for edge in edges {
            let source = edge.get(FIELD_SOURCE).and_then(|value| value.as_str()).unwrap_or("");
            let Some(output_name) = source.strip_prefix(OUTPUT_PSEUDO_RESOURCE_PREFIX) else {
                continue;
            };
            let kind = edge.get(FIELD_KIND).and_then(|value| value.as_str()).unwrap_or("");
            let source_path = edge.get(FIELD_SOURCE_PATH).and_then(|value| value.as_str()).unwrap_or("");
            let target = edge.get(FIELD_TARGET).and_then(|value| value.as_str()).unwrap_or("");

            if kind == EDGE_KIND_SUB {
                if !m.resources.contains_key(target)
                    && !m.parameters.contains_key(target)
                    && !PSEUDO_PARAMETERS.contains(&target)
                    && !sam_implicit.contains(target)
                {
                    out.push(make_resource_diagnostic(
                        "F6101",
                        &format!(
                            "Fn::Sub variable '${{{}}}' does not reference a valid resource, parameter, or pseudo-parameter",
                            target
                        ),
                        m,
                        "",
                        source_path,
                        None,
                    ));
                }
                continue;
            }
            if kind != EDGE_KIND_GET_ATT {
                continue;
            }

            let attribute = edge.get(FIELD_ATTR).and_then(|value| value.as_str()).unwrap_or("");
            let Some(resource) = m.resources.get(target) else {
                if !sam_implicit.contains(target) && !has_module_or_foreach {
                    out.push(make_resource_diagnostic(
                        "F6101",
                        &format!("GetAtt '{}.{}' references a resource that does not exist", target, attribute),
                        m,
                        "",
                        &format!("{}.0", source_path),
                        None,
                    ));
                }
                continue;
            };
            if let Some(valid_attributes) = ctx.cached_data.getatt_attrs.get(&resource.resource_type)
                && !valid_attributes.iter().any(|valid| valid == attribute)
                && !getatt_attr_is_map_member(attribute, &resource.resource_type)
                && !is_custom_resource_type(&resource.resource_type)
                && resource.resource_type != "AWS::CloudFormation::Stack"
                && resource.resource_type != "AWS::CloudFormation::Macro"
            {
                out.push(make_resource_diagnostic(
                    "F6101",
                    &format!("'{}' is not one of {}", attribute, render_str_list(valid_attributes)),
                    m,
                    "",
                    &format!("{}.1", source_path),
                    None,
                ));
                continue;
            }

            // A GetAtt inside a literal container is already covered by the
            // output-value shape check. Fn::Select consumes an array attribute.
            if !output_edge_is_in_string_position(source_path) {
                continue;
            }
            if let Some(return_type) =
                ctx.cached_data.getatt_attr_types.get(&resource.resource_type).and_then(|types| types.get(attribute))
                && return_type != "string"
                && return_type != "array"
            {
                out.push(make_resource_diagnostic(
                    "F6101",
                    &format!(
                        "Output '{}': GetAtt '{}.{}' returns type '{}', not 'string'",
                        output_name, target, attribute, return_type
                    ),
                    m,
                    "",
                    source_path,
                    None,
                ));
            }
        }
    }

    for (name, param) in &m.parameters {
        if param.param_type == PARAM_TYPE_NUMBER
            && let Some(ref def) = param.default
            && !NUM_RE.is_match(def)
        {
            out.push(make_resource_diagnostic(
                "F0015",
                &format!("Parameter '{}' Default '{}' is not a valid number", name, def),
                m,
                "",
                &format!("{}/{}/Default", SECTION_PARAMETERS, name),
                None,
            ));
        }
    }

    for (name, param) in &m.parameters {
        if param.param_type == PARAM_TYPE_NUMBER
            && let Some(ref avs) = param.allowed_values
        {
            for val in avs {
                if !NUM_RE.is_match(val) {
                    out.push(make_resource_diagnostic(
                        "F0016",
                        &format!("Parameter '{}' AllowedValues entry '{}' is not a valid number", name, val),
                        m,
                        "",
                        &format!("{}/{}/AllowedValues", SECTION_PARAMETERS, name),
                        None,
                    ));
                }
            }
        }
    }

    if let Some(outputs) = input.get(FIELD_OUTPUTS).and_then(|o| o.as_object()) {
        for (name, ov) in outputs {
            if let Some(export) = ov.get("exportName").and_then(|e| e.as_str())
                && export.is_empty()
            {
                out.push(make_resource_diagnostic(
                    "F6005",
                    &format!("Output '{}' Export Name must not be empty", name),
                    m,
                    "",
                    &format!("{}/{}/Export/Name", SECTION_OUTPUTS, name),
                    None,
                ));
            }
        }
    }

    let mut flagged_image_params = HashSet::new();
    if let Some(resources) = input.get(FIELD_RESOURCES).and_then(|r| r.as_object()) {
        for (_name, res) in resources {
            let rtype = res.get(FIELD_RESOURCE_TYPE).and_then(|t| t.as_str()).unwrap_or("");
            if let Some(edges) = res.get(FIELD_OUTGOING_REFS).and_then(|r| r.as_array()) {
                for edge in edges {
                    let kind = edge.get(FIELD_KIND).and_then(|k| k.as_str()).unwrap_or("");
                    let sp = edge.get(FIELD_SOURCE_PATH).and_then(|p| p.as_str()).unwrap_or("");
                    let target = edge.get(FIELD_TARGET).and_then(|t| t.as_str()).unwrap_or("");
                    if kind == EDGE_KIND_REF
                        && is_image_id_slot(rtype, sp)
                        && let Some(param) = m.parameters.get(target)
                        && !APPROPRIATE_IMAGE_ID_PARAM_TYPES.contains(&param.param_type.as_str())
                        && flagged_image_params.insert(target)
                    {
                        out.push(make_resource_diagnostic("W2506", &format!("Parameter '{}' is used as an ImageId but has Type '{}' - consider using 'AWS::EC2::Image::Id'", target, param.param_type), m, "", &format!("{}/{}", SECTION_PARAMETERS, target),
            None));
                    }
                }
            }
        }
    }

    for (name, param) in &m.parameters {
        let lower = name.to_lowercase();
        if (lower.contains("password") || lower.contains("passphrase") || lower.contains("secret"))
            && param.param_type == PARAM_TYPE_STRING
            && !param.no_echo
        {
            out.push(make_resource_diagnostic(
                "W2509",
                &format!("Parameter '{}' appears to be a password but does not have NoEcho set to true", name),
                m,
                "",
                &format!("{}/{}", SECTION_PARAMETERS, name),
                None,
            ));
        }
    }

    // Tautological Fn::Equals is detected by template-model and emitted as a
    // parser-level diagnostic - no engine rule needed.

    for (pname, info) in &m.parameters {
        let def = match &info.default {
            Some(d) => d,
            None => continue,
        };
        let path_str = format!("Parameters/{}/Default", pname);
        // AllowedPattern: the model precomputes the match verdict with a PCRE-aware compiler. A
        // comma-delimited default reports the element-agnostic message; a scalar default names the
        // value.
        if let Some(ref pat) = info.allowed_pattern
            && info.default_matches_allowed_pattern == Some(false)
        {
            let is_cdl = info.param_type == PARAM_TYPE_COMMA_DELIMITED_LIST || info.param_type.starts_with("List<");
            let message = if is_cdl {
                format!("Parameter '{}' Default does not match AllowedPattern '{}'", pname, pat)
            } else {
                format!("Parameter '{}' Default '{}' does not match AllowedPattern '{}'", pname, def, pat)
            };
            out.push(make_resource_diagnostic("F2015", &message, m, "", &path_str, None));
        }
        // MinLength / MaxLength
        if let Some(min) = info.min_length
            && (def.chars().count() as u64) < min
        {
            out.push(make_resource_diagnostic(
                "F2015",
                &format!("Parameter '{}' Default length {} is less than MinLength {}", pname, def.chars().count(), min),
                m,
                "",
                &path_str,
                None,
            ));
        }
        if let Some(max) = info.max_length
            && (def.chars().count() as u64) > max
        {
            out.push(make_resource_diagnostic(
                "F2015",
                &format!("Parameter '{}' Default length {} exceeds MaxLength {}", pname, def.chars().count(), max),
                m,
                "",
                &path_str,
                None,
            ));
        }
        // MinValue / MaxValue (for Number type)
        if info.param_type == PARAM_TYPE_NUMBER
            && let Ok(num) = def.parse::<i64>()
        {
            if let Some(min) = info.min_value
                && num < min
            {
                out.push(make_resource_diagnostic(
                    "F2015",
                    &format!("Parameter '{}' Default {} is less than MinValue {}", pname, num, min),
                    m,
                    "",
                    &path_str,
                    None,
                ));
            }
            if let Some(max) = info.max_value
                && num > max
            {
                out.push(make_resource_diagnostic(
                    "F2015",
                    &format!("Parameter '{}' Default {} exceeds MaxValue {}", pname, num, max),
                    m,
                    "",
                    &path_str,
                    None,
                ));
            }
        }
    }

    out
}

fn eval_template_size_and_transforms(ctx: &EvalContext) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let m = ctx.model;
    let input = ctx.input;

    if let Some(body_size) = input.get("template").and_then(|t| t.get("bodySize")).and_then(|v| v.as_u64()) {
        if body_size > 460_800 {
            out.push(make_resource_diagnostic(
                "E1002",
                &format!("Template body size {} exceeds maximum of 460,800 bytes", body_size),
                m,
                "",
                "",
                None,
            ));
        } else if body_size > 51_200 {
            out.push(make_resource_diagnostic(
                "E1002",
                &format!(
                    "Template body size {} exceeds 51,200 bytes. Use S3 for templates up to 460,800 bytes",
                    body_size
                ),
                m,
                "",
                "",
                None,
            ));
        }
    }

    for (pname, param) in &m.parameters {
        // CloudFormation validates AllowedPattern with a PCRE-style engine that supports
        // lookaround, backreferences, `\Z`, POSIX classes and large Unicode classes. A pattern
        // that only uses those constructs is still valid service-side, so report I2003 only for a
        // pattern that no compilation strategy can accept - i.e. one that is genuinely malformed.
        if let Some(ref pattern) = param.allowed_pattern
            && !is_service_valid(pattern)
        {
            out.push(make_resource_diagnostic(
                "I2003",
                &format!("Parameter '{}' AllowedPattern '{}' is not a valid regular expression", pname, pattern),
                m,
                "",
                &format!("{}/{}/AllowedPattern", SECTION_PARAMETERS, pname),
                None,
            ));
        }
    }

    out
}

fn condition_is_referenced(
    cname: &str,
    conds: &serde_json::Map<String, serde_json::Value>,
    resources: Option<&serde_json::Map<String, serde_json::Value>>,
    outputs: Option<&serde_json::Map<String, serde_json::Value>>,
) -> bool {
    // Direct usage by resource condition or condition_refs
    if let Some(res_map) = resources {
        for (_, res) in res_map {
            if res.get(FIELD_CONDITION).and_then(|c| c.as_str()) == Some(cname) {
                return true;
            }
            if let Some(refs) = res.get("conditionRefs").and_then(|r| r.as_array())
                && refs.iter().any(|r| r.as_str() == Some(cname))
            {
                return true;
            }
        }
    }
    // Direct usage by output condition or conditionRefs
    if let Some(out_map) = outputs {
        for (_, out_val) in out_map {
            if out_val.get(FIELD_CONDITION).and_then(|c| c.as_str()) == Some(cname) {
                return true;
            }
            if let Some(refs) = out_val.get("conditionRefs").and_then(|r| r.as_array())
                && refs.iter().any(|r| r.as_str() == Some(cname))
            {
                return true;
            }
        }
    }
    // Referenced by another condition via Fn::And/Or/Not Condition entries. The
    // reference alone marks this condition used, independent of whether the
    // referencing condition is itself used.
    for (other, cond_val) in conds {
        if other == cname {
            continue;
        }
        if let Some(deps) = cond_val.get("deps").and_then(|d| d.as_array())
            && deps.iter().any(|d| d.as_str() == Some(cname))
        {
            return true;
        }
    }
    false
}

/// Describes a non-string resource policy value, or returns `None` when the
/// resolved shape may represent an intrinsic CloudFormation accepts here.
fn non_string_policy_shape(value: &serde_json::Value) -> Option<&'static str> {
    match value {
        serde_json::Value::Array(_) => Some("a list"),
        serde_json::Value::Object(map) => {
            let is_intrinsic_marker = map.contains_key(MARKER_DYNAMIC)
                || map.contains_key(MARKER_REF)
                || map.contains_key(MARKER_ENUM)
                || map.contains_key(MARKER_CONDITIONAL);
            if is_intrinsic_marker { None } else { Some("an object") }
        }
        serde_json::Value::Number(_) => Some("a number"),
        serde_json::Value::Bool(_) => Some("a boolean"),
        _ => None,
    }
}

fn is_valid_parameter_type(ptype: &str) -> bool {
    matches!(
        ptype,
        "String"
            | "Number"
            | "CommaDelimitedList"
            | "AWS::SSM::Parameter::Name"
            | "AWS::EC2::AvailabilityZone::Name"
            | "AWS::EC2::Image::Id"
            | "AWS::EC2::Instance::Id"
            | "AWS::EC2::KeyPair::KeyName"
            | "AWS::EC2::SecurityGroup::GroupName"
            | "AWS::EC2::SecurityGroup::Id"
            | "AWS::EC2::Subnet::Id"
            | "AWS::EC2::Volume::Id"
            | "AWS::EC2::VPC::Id"
            | "AWS::Route53::HostedZone::Id"
            | "List<Number>"
            | "List<String>"
            | "List<AWS::EC2::AvailabilityZone::Name>"
            | "List<AWS::EC2::Image::Id>"
            | "List<AWS::EC2::Instance::Id>"
            | "List<AWS::EC2::SecurityGroup::GroupName>"
            | "List<AWS::EC2::SecurityGroup::Id>"
            | "List<AWS::EC2::Subnet::Id>"
            | "List<AWS::EC2::Volume::Id>"
            | "List<AWS::EC2::VPC::Id>"
            | "List<AWS::Route53::HostedZone::Id>"
    ) || ptype.starts_with("AWS::SSM::Parameter::Value<")
}

/// The exact `AWS::EC2::Image::Id`-typed property slots the ImageId-parameter-type
/// check (W2506) applies to: a fixed set of `(resource type, property path)` pairs.
/// The path is relative to the resource (it always starts with `Properties.`); the
/// `*` in the SpotFleet path matches a single array-index segment.
fn is_image_id_slot(resource_type: &str, source_path: &str) -> bool {
    const IMAGE_ID_SLOTS: &[(&str, &str)] = &[
        ("AWS::AutoScaling::LaunchConfiguration", "Properties.ImageId"),
        ("AWS::Batch::ComputeEnvironment", "Properties.ComputeResources.ImageId"),
        ("AWS::Cloud9::EnvironmentEC2", "Properties.ImageId"),
        ("AWS::EC2::Instance", "Properties.ImageId"),
        ("AWS::EC2::LaunchTemplate", "Properties.LaunchTemplateData.ImageId"),
        ("AWS::EC2::SpotFleet", "Properties.SpotFleetRequestConfigData.LaunchSpecifications.*.ImageId"),
        ("AWS::ImageBuilder::Image", "Properties.ImageId"),
    ];
    IMAGE_ID_SLOTS
        .iter()
        .filter(|(rtype, _)| *rtype == resource_type)
        .any(|(_, slot)| path_matches_slot(source_path, slot))
}

/// Match a concrete source path against a slot pattern whose only wildcard is a
/// `*` segment standing for a single array index.
fn path_matches_slot(path: &str, slot: &str) -> bool {
    let (path_segs, slot_segs): (Vec<&str>, Vec<&str>) = (path.split('.').collect(), slot.split('.').collect());
    path_segs.len() == slot_segs.len() && slot_segs.iter().zip(&path_segs).all(|(s, p)| *s == "*" || s == p)
}

/// The two parameter types that are appropriate for an ImageId property; any
/// other type used for an ImageId Ref triggers W2506.
const APPROPRIATE_IMAGE_ID_PARAM_TYPES: &[&str] =
    &["AWS::EC2::Image::Id", "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>"];

/// Determines whether a GetAtt edge from an output is in "string position" -
/// that is, the GetAtt result feeds into a context where a string is expected.
/// A GetAtt inside a literal list/map (bare index or key after the Value node)
/// is NOT in string position because the enclosing container is already a
/// non-string output value caught by the parse-time type check.
fn output_edge_is_in_string_position(source_path: &str) -> bool {
    // Use last-occurrence splitting so an output name containing "Value"
    // (e.g. `ValueFoo`) does not consume the output-name segment as part of
    // the tail.
    let after_value = source_path
        .rsplit_once("/Value")
        .map(|(_, tail)| tail)
        .or_else(|| source_path.strip_prefix("Value"))
        .unwrap_or("");
    let mut segments = after_value.split('.').filter(|s| !s.is_empty());
    while let Some(segment) = segments.next() {
        if segment == FN_IF {
            // Skip the branch selector (1/2) and keep walking transparently.
            segments.next();
            continue;
        }
        // A remaining Fn::* segment is a string-building function consuming the
        // GetAtt (Join/Sub/…): the GetAtt is in string position.
        if segment.starts_with("Fn::") {
            return true;
        }
        // A bare index or key means the GetAtt is inside a literal container.
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_basic_types() {
        assert!(is_valid_parameter_type("String"));
        assert!(is_valid_parameter_type("Number"));
        assert!(is_valid_parameter_type("CommaDelimitedList"));
    }

    #[test]
    fn valid_aws_specific_types() {
        assert!(is_valid_parameter_type("AWS::EC2::VPC::Id"));
        assert!(is_valid_parameter_type("AWS::EC2::Subnet::Id"));
        assert!(is_valid_parameter_type("AWS::EC2::SecurityGroup::Id"));
        assert!(is_valid_parameter_type("AWS::Route53::HostedZone::Id"));
    }

    #[test]
    fn valid_list_types() {
        assert!(is_valid_parameter_type("List<Number>"));
        assert!(is_valid_parameter_type("List<AWS::EC2::Subnet::Id>"));
        assert!(is_valid_parameter_type("List<AWS::EC2::VPC::Id>"));
    }

    #[test]
    fn valid_ssm_parameter_type() {
        assert!(is_valid_parameter_type("AWS::SSM::Parameter::Value<String>"));
        assert!(is_valid_parameter_type("AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>"));
    }

    #[test]
    fn invalid_types() {
        assert!(!is_valid_parameter_type("Integer"));
        assert!(!is_valid_parameter_type("Boolean"));
        assert!(!is_valid_parameter_type(""));
        assert!(!is_valid_parameter_type("NotString"));
    }

    #[test]
    fn list_of_string_is_valid() {
        assert!(is_valid_parameter_type("List<String>"));
    }

    #[test]
    fn string_position_direct_value() {
        assert!(output_edge_is_in_string_position("Outputs/O/Value"));
    }

    #[test]
    fn string_position_fn_if_branch() {
        assert!(output_edge_is_in_string_position("Outputs/O/Value.Fn::If.1"));
        assert!(output_edge_is_in_string_position("Outputs/O/Value.Fn::If.2"));
    }

    #[test]
    fn string_position_fn_join_element() {
        assert!(output_edge_is_in_string_position("Outputs/O/Value.Fn::Join.1.0"));
    }

    #[test]
    fn string_position_fn_sub() {
        assert!(output_edge_is_in_string_position("Outputs/O/Value.Fn::Sub.0"));
    }

    #[test]
    fn string_position_value_prefixed_output_names() {
        // Output names starting with "Value" must not confuse the last-occurrence
        // split. The terminal `/Value` node is always the property key, never
        // part of the output name.
        assert!(output_edge_is_in_string_position("Outputs/ValueFoo/Value"));
        assert!(output_edge_is_in_string_position("Outputs/ValueFoo/Value.Fn::Join.1.0"));
        assert!(output_edge_is_in_string_position("Outputs/ValueFoo/Value.Fn::If.1"));
        assert!(!output_edge_is_in_string_position("Outputs/ValueFoo/Value.0"));
        assert!(!output_edge_is_in_string_position("Outputs/ValueFoo/Value.k"));
        assert!(output_edge_is_in_string_position("Outputs/Value/Value"));
        assert!(output_edge_is_in_string_position("Outputs/Value/Value.Fn::Join.1.0"));
        assert!(!output_edge_is_in_string_position("Outputs/Value/Value.0"));
    }

    #[test]
    fn not_string_position_bare_index() {
        assert!(!output_edge_is_in_string_position("Outputs/O/Value.0"));
    }

    #[test]
    fn not_string_position_bare_key() {
        assert!(!output_edge_is_in_string_position("Outputs/O/Value.someKey"));
    }
}
