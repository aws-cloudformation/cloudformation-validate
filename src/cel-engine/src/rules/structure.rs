use super::{EvalContext, NativeRuleRegistry};
use diagnostics::Diagnostic;
use rules::Category;
use std::collections::HashSet;
use std::sync::LazyLock;
use template_model::FORMAT_VERSION;
use template_model::consts::{
    EDGE_KIND_REF, EDGE_KIND_SUB, FIELD_CONDITION, FIELD_CONDITIONS, FIELD_DELETION_POLICY, FIELD_EDGES, FIELD_KIND,
    FIELD_MAPPINGS, FIELD_OUTGOING_REFS, FIELD_OUTPUTS, FIELD_PARAMETERS, FIELD_RESOURCE_TYPE, FIELD_RESOURCES,
    FIELD_SOURCE_PATH, FIELD_TARGET, FIELD_TRANSFORMS, FIELD_UPDATE_REPLACE_POLICY, POLICY_DELETE, POLICY_RETAIN,
    POLICY_RETAIN_EXCEPT_ON_CREATE, POLICY_SNAPSHOT, SECTION_CONDITIONS, SECTION_DESCRIPTION, SECTION_FORMAT_VERSION,
    SECTION_GLOBALS, SECTION_MAPPINGS, SECTION_METADATA, SECTION_OUTPUTS, SECTION_PARAMETERS, SECTION_RESOURCES,
    SECTION_RULES, SECTION_TRANSFORM, TRANSFORM_LANGUAGE_EXTENSIONS, TRANSFORM_SERVERLESS,
};
use validation_engine::make_resource_diagnostic;

static ALPHANUM_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[a-zA-Z0-9]+$").expect("Invalid ALPHANUM_RE pattern"));

static NUM_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^-?[0-9]+(\.[0-9]+)?$").expect("Invalid NUM_RE pattern"));

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
                    "",
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
        if !ALPHANUM_RE.is_match(pname) {
            out.push(make_resource_diagnostic(
                "F2003",
                &format!("Parameter name '{}' must be alphanumeric", pname),
                m,
                "",
                "",
                None,
            ));
        }

        if pname.len() > 255 {
            out.push(make_resource_diagnostic(
                "F2011",
                &format!("Parameter name '{}' exceeds maximum length of 255", pname),
                m,
                "",
                "",
                None,
            ));
        } else if pname.len() > 229 {
            out.push(make_resource_diagnostic(
                "I2011",
                &format!("Parameter name '{}' is approaching maximum length of 255", pname),
                m,
                "",
                "",
                None,
            ));
        }

        if !is_valid_parameter_type(&param.param_type) {
            out.push(make_resource_diagnostic(
                "F2002",
                &format!("Parameter '{}' has invalid Type '{}'", pname, param.param_type),
                m,
                "",
                "",
                None,
            ));
        }
    }

    if let Some(outputs_obj) = input.get(FIELD_OUTPUTS).and_then(|o| o.as_object()) {
        for oname in outputs_obj.keys() {
            if !ALPHANUM_RE.is_match(oname) {
                // Fn::ForEach:: prefixed keys are ForEach constructs, not literal output names
                if oname.starts_with("Fn::ForEach::") {
                    continue;
                }
                out.push(make_resource_diagnostic(
                    "F6004",
                    &format!("Output name '{}' must be alphanumeric", oname),
                    m,
                    "",
                    "",
                    None,
                ));
            }
            if oname.len() > 255 {
                out.push(make_resource_diagnostic(
                    "F6011",
                    &format!("Output name '{}' exceeds maximum length of 255", oname),
                    m,
                    "",
                    "",
                    None,
                ));
            } else if oname.len() > 229 {
                out.push(make_resource_diagnostic(
                    "I6011",
                    &format!("Output name '{}' is approaching maximum length of 255", oname),
                    m,
                    "",
                    "",
                    None,
                ));
            }
        }
    }

    for mname in m.mappings.keys() {
        if mname.len() > 255 {
            out.push(make_resource_diagnostic(
                "F7002",
                &format!("Mapping name '{}' exceeds maximum length of 255", mname),
                m,
                "",
                "",
                None,
            ));
        } else if mname.len() > 229 {
            out.push(make_resource_diagnostic(
                "I7002",
                &format!("Mapping name '{}' is approaching maximum length of 255", mname),
                m,
                "",
                "",
                None,
            ));
        }
    }

    if let Some(desc_val) = input.get("template").and_then(|t| t.get("description"))
        && !desc_val.is_string()
        && !desc_val.is_null()
    {
        out.push(make_resource_diagnostic("F1004", "Description must be a string", m, "", "", None));
    }

    if let Some(desc) = input.get("template").and_then(|t| t.get("description")).and_then(|v| v.as_str())
        && desc.len() > 921
        && desc.len() <= 1024
    {
        out.push(make_resource_diagnostic(
            "I1003",
            &format!("Description length {} is approaching maximum of 1024", desc.len()),
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

    if let Some(conds_obj) = input.get(FIELD_CONDITIONS).and_then(|c| c.as_object()) {
        let defined_conditions: HashSet<&str> = conds_obj.keys().map(|k| k.as_str()).collect();
        for (rname, res) in &m.resources {
            if let Some(cond) = &res.condition
                && !defined_conditions.contains(cond.as_str())
            {
                out.push(make_resource_diagnostic(
                    "F8002",
                    &format!("Condition '{}' referenced by resource '{}' is not defined", cond, rname),
                    m,
                    rname,
                    "",
                    None,
                ));
            }
        }
    }

    if let Some(desc) = input.get("template").and_then(|t| t.get("description")).and_then(|v| v.as_str())
        && desc.len() > 1024
    {
        out.push(make_resource_diagnostic(
            "F0011",
            &format!("Description length {} exceeds maximum 1024", desc.len()),
            m,
            "",
            "",
            None,
        ));
    }

    let has_lang_ext = m.transforms.iter().any(|t| t == TRANSFORM_LANGUAGE_EXTENSIONS);
    for name in m.resources.keys() {
        if !(ALPHANUM_RE.is_match(name) || (has_lang_ext && name.starts_with("Fn::ForEach::"))) {
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
                    "",
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
                "",
                None,
            ));
        }
        for (key1, level2) in level1 {
            if level2.len() > 200 {
                out.push(make_resource_diagnostic(
                    "F0050",
                    &format!("Mapping '{}'.'{}'  has {} attributes, maximum is 200", map_name, key1, level2.len()),
                    m,
                    "",
                    "",
                    None,
                ));
            }
        }
    }

    {
        let key1_re = regex::Regex::new(r"^[a-zA-Z0-9.\-]+$").unwrap();
        let key2_re = regex::Regex::new(r"^[a-zA-Z0-9]+$").unwrap();
        for (map_name, level1) in &m.mappings {
            for (k1, level2) in level1 {
                if !key1_re.is_match(k1) {
                    out.push(make_resource_diagnostic(
                        "E7001",
                        &format!("Mapping '{}' key '{}' does not match format '^[a-zA-Z0-9.-]+$'", map_name, k1),
                        m,
                        "",
                        "",
                        None,
                    ));
                }
                for k2 in level2.keys() {
                    if !key2_re.is_match(k2) {
                        out.push(make_resource_diagnostic(
                            "E7001",
                            &format!(
                                "Mapping '{}'.'{}' key '{}' does not match format '^[a-zA-Z0-9]+$'",
                                map_name, k1, k2
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
        for (name, res) in resources {
            let rtype = res.get(FIELD_RESOURCE_TYPE).and_then(|t| t.as_str()).unwrap_or("");
            let snapshot_ok = SNAPSHOT_CAPABLE_TYPES.contains(&rtype);
            if let Some(dp) = res.get(FIELD_DELETION_POLICY).and_then(|v| v.as_str()) {
                let valid = base_deletion.contains(&dp) || (snapshot_ok && dp == POLICY_SNAPSHOT);
                if !valid {
                    let allowed = if snapshot_ok {
                        "Delete, Retain, RetainExceptOnCreate, Snapshot"
                    } else {
                        "Delete, Retain, RetainExceptOnCreate"
                    };
                    out.push(make_resource_diagnostic(
                        "F3016",
                        &format!("DeletionPolicy must be one of {}, got '{}'", allowed, dp),
                        m,
                        name,
                        "",
                        None,
                    ));
                }
            }
            if let Some(urp) = res.get(FIELD_UPDATE_REPLACE_POLICY).and_then(|v| v.as_str()) {
                let valid = base_update.contains(&urp) || (snapshot_ok && urp == POLICY_SNAPSHOT);
                if !valid {
                    let allowed = if snapshot_ok { "Delete, Retain, Snapshot" } else { "Delete, Retain" };
                    out.push(make_resource_diagnostic(
                        "F0018",
                        &format!("UpdateReplacePolicy must be one of {}, got '{}'", allowed, urp),
                        m,
                        name,
                        "",
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
                &format!("Logical ID '{}' is {} characters — approaching the 256 character limit", name, name.len()),
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
    // A parameter can be referenced from a section the parser could not read —
    // an unexpanded Fn::ForEach key (the transform that would expand it is
    // missing) or a malformed Conditions section (e.g. authored as a list). In
    // those cases the reference graph is incomplete, so the unused-parameter
    // check is skipped rather than reporting a parameter as unused when the
    // reference simply could not be seen.
    let resources_obj = input.get(FIELD_RESOURCES).and_then(|r| r.as_object());
    let has_unexpanded_foreach = resources_obj.is_some_and(|r| r.keys().any(|k| k.contains("Fn::ForEach")));
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
                    "",
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
                    "",
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
                    "",
                    None,
                ));
            }
        }
    }

    for (name, param) in &m.parameters {
        if let (Some(default), Some(allowed)) = (&param.default, &param.allowed_values)
            && !allowed.is_empty()
            && !allowed.iter().any(|a| a == default)
        {
            out.push(make_resource_diagnostic(
                "F2012",
                &format!("Parameter '{}' Default '{}' is not in AllowedValues {:?}", name, default, allowed),
                m,
                "",
                "",
                None,
            ));
        }
    }

    if let Some(outputs) = input.get(FIELD_OUTPUTS).and_then(|o| o.as_object()) {
        for (name, out_val) in outputs {
            if let Some(refs) = out_val.get("getattRefs").and_then(|r| r.as_array()) {
                for ga_ref in refs {
                    let resource = ga_ref.get("resource").and_then(|r| r.as_str()).unwrap_or("");
                    let attribute = ga_ref.get("attribute").and_then(|a| a.as_str()).unwrap_or("");
                    if let Some(res) = m.resources.get(resource)
                        && let Some(ret_type) =
                            ctx.cached_data.getatt_attr_types.get(&res.resource_type).and_then(|t| t.get(attribute))
                        && ret_type != "string"
                    {
                        // An array-returning GetAtt in an output is consumed by
                        // Fn::Select to extract a string element — the array
                        // itself is never the output value, so it is not a
                        // string-type violation. Only scalar non-string returns
                        // (integer, boolean) are reported.
                        if ret_type == "array" {
                            continue;
                        }
                        out.push(make_resource_diagnostic(
                            "F6101",
                            &format!(
                                "Output '{}': GetAtt '{}.{}' returns type '{}', not 'string'",
                                name, resource, attribute, ret_type
                            ),
                            m,
                            name,
                            &format!("Outputs/{}/Value", name),
                            None,
                        ));
                    }
                }
            }
        }
    }

    for (name, param) in &m.parameters {
        if param.param_type == "Number"
            && let Some(ref def) = param.default
            && !NUM_RE.is_match(def)
        {
            out.push(make_resource_diagnostic(
                "F0015",
                &format!("Parameter '{}' Default '{}' is not a valid number", name, def),
                m,
                "",
                "",
                None,
            ));
        }
    }

    for (name, param) in &m.parameters {
        if param.param_type == "Number"
            && let Some(ref avs) = param.allowed_values
        {
            for val in avs {
                if !NUM_RE.is_match(val) {
                    out.push(make_resource_diagnostic(
                        "F0016",
                        &format!("Parameter '{}' AllowedValues entry '{}' is not a valid number", name, val),
                        m,
                        "",
                        "",
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
                    "",
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
                        out.push(make_resource_diagnostic("W2506", &format!("Parameter '{}' is used as an ImageId but has Type '{}' — consider using 'AWS::EC2::Image::Id'", target, param.param_type), m, "", "",
            None));
                    }
                }
            }
        }
    }

    for (name, param) in &m.parameters {
        let lower = name.to_lowercase();
        if (lower.contains("password") || lower.contains("passphrase") || lower.contains("secret"))
            && param.param_type == "String"
            && !param.no_echo
        {
            out.push(make_resource_diagnostic(
                "W2509",
                &format!("Parameter '{}' appears to be a password but does not have NoEcho set to true", name),
                m,
                "",
                "",
                None,
            ));
        }
    }

    // Tautological Fn::Equals is detected by template-model and emitted as a
    // parser-level diagnostic — no engine rule needed.

    for (pname, info) in &m.parameters {
        let def = match &info.default {
            Some(d) => d,
            None => continue,
        };
        let path_str = format!("Parameters/{}/Default", pname);
        // AllowedPattern (with auto-anchoring)
        if let Some(ref pat) = info.allowed_pattern {
            let anchored = if pat.starts_with('^') && pat.ends_with('$') {
                pat.clone()
            } else if pat.starts_with('^') {
                format!("{}$", pat)
            } else if pat.ends_with('$') {
                format!("^{}", pat)
            } else {
                format!("^{}$", pat)
            };
            if let Ok(re) = regex::Regex::new(&anchored) {
                let is_cdl = info.param_type == "CommaDelimitedList" || info.param_type.starts_with("List<");
                if is_cdl {
                    for elem_raw in def.split(',') {
                        let elem = elem_raw.trim();
                        if !re.is_match(elem) {
                            out.push(make_resource_diagnostic(
                                "F2015",
                                &format!("Parameter '{}' Default does not match AllowedPattern '{}'", pname, pat),
                                m,
                                "",
                                &path_str,
                                None,
                            ));
                            break;
                        }
                    }
                } else if !re.is_match(def) {
                    out.push(make_resource_diagnostic(
                        "F2015",
                        &format!("Parameter '{}' Default '{}' does not match AllowedPattern '{}'", pname, def, pat),
                        m,
                        "",
                        &path_str,
                        None,
                    ));
                }
            }
        }
        // MinLength / MaxLength
        if let Some(min) = info.min_length
            && (def.len() as u64) < min
        {
            out.push(make_resource_diagnostic(
                "F2015",
                &format!("Parameter '{}' Default length {} is less than MinLength {}", pname, def.len(), min),
                m,
                "",
                &path_str,
                None,
            ));
        }
        if let Some(max) = info.max_length
            && (def.len() as u64) > max
        {
            out.push(make_resource_diagnostic(
                "F2015",
                &format!("Parameter '{}' Default length {} exceeds MaxLength {}", pname, def.len(), max),
                m,
                "",
                &path_str,
                None,
            ));
        }
        // MinValue / MaxValue (for Number type)
        if info.param_type == "Number"
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

    if let Some(transforms) = input.get("template").and_then(|t| t.get(FIELD_TRANSFORMS)).and_then(|v| v.as_array()) {
        for t in transforms {
            if !t.is_string() && !t.is_object() {
                out.push(make_resource_diagnostic(
                    "E1005",
                    &format!("Transform entry must be a string or object, got {}", t),
                    m,
                    "",
                    "",
                    None,
                ));
            }
            if t.is_object() && t.get("Name").is_none() {
                out.push(make_resource_diagnostic(
                    "E1005",
                    "Transform object is missing required 'Name' property",
                    m,
                    "",
                    "",
                    None,
                ));
            }
        }
    }

    for (pname, param) in &m.parameters {
        if let Some(ref pattern) = param.allowed_pattern
            && regex::Regex::new(pattern).is_err()
            // CloudFormation validates AllowedPattern with a PCRE-style engine
            // that supports lookaround and backreferences; Rust's `regex` crate
            // does not. A pattern that fails ONLY because of those constructs is
            // still valid service-side, so treat it as valid and only report
            // genuinely-malformed regex.
            && !uses_extended_regex_syntax(pattern)
        {
            out.push(make_resource_diagnostic(
                "I2003",
                &format!("Parameter '{}' AllowedPattern '{}' is not a valid regular expression", pname, pattern),
                m,
                "",
                "",
                None,
            ));
        }
    }

    out
}

/// Whether a regex uses PCRE constructs that CloudFormation's service-side
/// engine accepts but Rust's `regex` / RE2 reject: lookahead `(?=` `(?!`,
/// lookbehind `(?<=` `(?<!`, atomic groups `(?>`, or backreferences `\1`.
fn uses_extended_regex_syntax(pattern: &str) -> bool {
    const EXTENDED_GROUP_PREFIXES: &[&str] = &["(?=", "(?!", "(?<=", "(?<!", "(?>"];
    if EXTENDED_GROUP_PREFIXES.iter().any(|p| pattern.contains(p)) {
        return true;
    }
    // Backreference: a backslash followed by a digit 1-9.
    let bytes = pattern.as_bytes();
    bytes.windows(2).any(|w| w[0] == b'\\' && w[1].is_ascii_digit() && w[1] != b'0')
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
}
