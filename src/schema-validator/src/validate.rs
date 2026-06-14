use crate::compiled::{CompiledSchema, ConditionSchema, PropSchema, PropType, SubSchema};
use crate::store::CompiledSchemaStore;
use diagnostics::Diagnostic;
use rules::Severity;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use template_model::SemanticModel;
use template_model::coercion::{
    CoerceResult, cfn_coerce_to_number, cfn_coerce_to_string, cfn_coerce_value,
};
use template_model::consts::{FN_IF, KEY_PROPERTIES};
use template_model::model::ResolvedResource;
use template_model::resolver::{RefKind, ResolvedValue};

pub fn validate_all_resources(
    store: &CompiledSchemaStore,
    model: &Arc<SemanticModel>,
    region: &str,
) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let relevant: HashSet<&str> = model
        .resources
        .values()
        .map(|r| r.resource_type.as_str())
        .collect();

    validate_lifecycle(&mut out, store, model);

    for rtype in &relevant {
        if rtype.ends_with("::MODULE") {
            continue;
        }

        if store.has_region_data() && !store.is_available_in_region(rtype, region) {
            for rid in model.resources_of_type(rtype) {
                out.push(build_diagnostic(
                    "E9001",
                    Severity::Error,
                    &format!(
                        "Resource type '{}' is not available in region '{}'",
                        rtype, region
                    ),
                    model,
                    rid,
                    "",
                    None,
                ));
            }
            continue;
        }

        let Some(schema) = store.get(rtype) else {
            continue;
        };
        for rid in model.resources_of_type(rtype) {
            let Some(res) = model.resources.get(rid.as_str()) else {
                continue;
            };
            validate_resource(&mut out, store, model, rid, res, schema, region);
            validate_extensions(&mut out, store, model, rid, res);
        }
    }
    out
}

pub fn enrich_schema_context(
    diagnostics: &mut Vec<Diagnostic>,
    store: &CompiledSchemaStore,
    model: &Arc<SemanticModel>,
) {
    for d in diagnostics.iter_mut() {
        if d.phase != Some(diagnostics::Phase::Schema) {
            continue;
        }
        let Some(ref res_ref) = d.resource else {
            continue;
        };
        let rid = match res_ref.id.as_deref() {
            Some(id) => id,
            None => continue,
        };
        let Some(res) = model.resources.get(rid) else {
            continue;
        };
        let Some(schema) = store.get(&res.resource_type) else {
            continue;
        };

        if d.documentation_url.is_none() {
            if let Some(ref url) = schema.documentation_url {
                d.documentation_url = Some(url.clone());
            } else if let Some(ref url) = schema.source_url {
                d.documentation_url = Some(url.clone());
            }
        }

        if let Some(source) =
            describe_resolution(model, rid, d.property_path.as_deref().unwrap_or(""))
        {
            let ctx = d
                .context
                .get_or_insert_with(|| diagnostics::ViolationContext {
                    actual_value: None,
                    expected_constraint: None,
                    property: None,
                    lifecycle: None,
                    resolution_source: None,
                    extra: None,
                });
            if ctx.resolution_source.is_none() {
                ctx.resolution_source = Some(source);
            }
        }

        let pp = d.property_path.as_deref().unwrap_or("");
        let prop_path = pp.strip_prefix("Properties.").unwrap_or(pp);
        let prop_schema = find_prop_schema_deep(prop_path, schema);

        macro_rules! ensure_ctx {
            ($d:expr) => {
                $d.context
                    .get_or_insert_with(|| diagnostics::ViolationContext {
                        actual_value: None,
                        expected_constraint: None,
                        property: None,
                        lifecycle: None,
                        resolution_source: None,
                        extra: None,
                    })
            };
        }

        match d.rule_id.as_str() {
            "F3012" => {
                if let Some(ps) = prop_schema
                    && let Some(ref pt) = ps.prop_type
                {
                    ensure_ctx!(d).expected_constraint =
                        Some(pt.primary().unwrap_or("unknown").to_string());
                }
            }
            "F3030" => {
                if let Some(ps) = prop_schema
                    && !ps.enum_values.is_empty()
                {
                    ensure_ctx!(d)
                        .extra
                        .get_or_insert_with(HashMap::new)
                        .insert(
                            "allowed_values".into(),
                            serde_json::json!(ps.enum_values).into(),
                        );
                }
            }
            "F3031" => {
                if let Some(ps) = prop_schema
                    && let Some(ref pat) = ps.pattern
                {
                    ensure_ctx!(d).expected_constraint = Some(pat.clone());
                }
            }
            "F3034" => {
                if let Some(ps) = prop_schema {
                    let ctx = ensure_ctx!(d);
                    if let Some(v) = ps.minimum {
                        ctx.extra
                            .get_or_insert_with(HashMap::new)
                            .insert("minimum".into(), serde_json::json!(v).into());
                    }
                    if let Some(v) = ps.maximum {
                        ctx.extra
                            .get_or_insert_with(HashMap::new)
                            .insert("maximum".into(), serde_json::json!(v).into());
                    }
                    if let Some(v) = ps.exclusive_minimum {
                        ctx.extra
                            .get_or_insert_with(HashMap::new)
                            .insert("exclusive_minimum".into(), serde_json::json!(v).into());
                    }
                    if let Some(v) = ps.exclusive_maximum {
                        ctx.extra
                            .get_or_insert_with(HashMap::new)
                            .insert("exclusive_maximum".into(), serde_json::json!(v).into());
                    }
                }
            }
            "F3033" => {
                if let Some(ps) = prop_schema {
                    let ctx = ensure_ctx!(d);
                    if let Some(v) = ps.min_length {
                        ctx.extra
                            .get_or_insert_with(HashMap::new)
                            .insert("min_length".into(), serde_json::json!(v).into());
                    }
                    if let Some(v) = ps.max_length {
                        ctx.extra
                            .get_or_insert_with(HashMap::new)
                            .insert("max_length".into(), serde_json::json!(v).into());
                    }
                }
            }
            "F3032" => {
                if let Some(ps) = prop_schema {
                    let ctx = ensure_ctx!(d);
                    if let Some(v) = ps.min_items {
                        ctx.extra
                            .get_or_insert_with(HashMap::new)
                            .insert("min_items".into(), serde_json::json!(v).into());
                    }
                    if let Some(v) = ps.max_items {
                        ctx.extra
                            .get_or_insert_with(HashMap::new)
                            .insert("max_items".into(), serde_json::json!(v).into());
                    }
                }
            }
            "F3002" => {
                let mut allowed: Vec<&str> = schema.properties.keys().map(|s| s.as_str()).collect();
                allowed.sort();
                ensure_ctx!(d)
                    .extra
                    .get_or_insert_with(HashMap::new)
                    .insert(
                        "allowed_properties".into(),
                        serde_json::json!(allowed).into(),
                    );
            }
            "W9009" => {
                ensure_ctx!(d).lifecycle = Some("deprecated".into());
            }
            "I9001" => {
                let ctx = ensure_ctx!(d);
                ctx.lifecycle = Some("create-only".into());
                if let Some(ref rs) = schema.replacement_strategy {
                    ctx.extra
                        .get_or_insert_with(HashMap::new)
                        .insert("replacement_strategy".into(), serde_json::json!(rs).into());
                }
            }
            "W3041" => {
                ensure_ctx!(d).lifecycle = Some("write-only".into());
            }
            _ => {}
        }
    }
}

pub fn enrich_schema_context_standalone(
    diagnostics: &mut Vec<Diagnostic>,
    model: &Arc<SemanticModel>,
) {
    let store = CompiledSchemaStore::new();
    enrich_schema_context(diagnostics, &store, model);
}

fn find_prop_schema<'a>(
    path: &str,
    props: &'a HashMap<String, PropSchema>,
    defs: &'a HashMap<String, PropSchema>,
) -> Option<&'a PropSchema> {
    let mut segments = path.splitn(2, '.');
    let top = segments.next()?;
    let rest = segments.next().filter(|r| !r.is_empty());

    if let Some(ps) = props.get(top) {
        let resolved = ps.resolve(defs);
        return match rest {
            Some(r) => find_prop_schema(r, &resolved.properties, defs),
            None => Some(resolved),
        };
    }
    for (pat, ps) in props.iter() {
        if regex::Regex::new(pat)
            .ok()
            .map(|re| re.is_match(top))
            .unwrap_or(false)
        {
            let resolved = ps.resolve(defs);
            return match rest {
                Some(r) => find_prop_schema(r, &resolved.properties, defs),
                None => Some(resolved),
            };
        }
    }
    None
}

fn find_prop_schema_deep<'a>(path: &str, schema: &'a CompiledSchema) -> Option<&'a PropSchema> {
    if let Some(ps) = find_prop_schema(path, &schema.properties, &schema.definitions) {
        return Some(ps);
    }
    for sub in schema
        .one_of
        .iter()
        .chain(schema.any_of.iter())
        .chain(schema.all_of.iter())
    {
        if let Some(ps) = find_prop_schema(path, &sub.properties, &schema.definitions) {
            return Some(ps);
        }
    }
    for ite in &schema.if_then_else {
        if let Some(ref then_s) = ite.then_schema
            && let Some(ps) = find_prop_schema(path, &then_s.properties, &schema.definitions)
        {
            return Some(ps);
        }
        if let Some(ref else_s) = ite.else_schema
            && let Some(ps) = find_prop_schema(path, &else_s.properties, &schema.definitions)
        {
            return Some(ps);
        }
    }
    None
}

fn validate_resource(
    out: &mut Vec<Diagnostic>,
    store: &CompiledSchemaStore,
    m: &Arc<SemanticModel>,
    rid: &str,
    res: &ResolvedResource,
    schema: &CompiledSchema,
    region: &str,
) {
    let base = "Properties";
    let defs = &schema.definitions;

    for ro in &schema.read_only_properties {
        let top = ro.split('.').next().unwrap_or(ro);
        if res.properties.contains_key(top) {
            out.push(build_diagnostic(
                "E3040",
                Severity::Error,
                &format!("Read only property '{}' should not be specified", top),
                m,
                rid,
                &format!("{}.{}", base, top),
                None,
            ));
        }
    }

    for dp in &schema.deprecated_properties {
        let top = dp.split('.').next().unwrap_or(dp);
        if res.properties.contains_key(top) {
            out.push(build_diagnostic(
                "W9009",
                Severity::Warn,
                &format!("Property '{}' is deprecated", top),
                m,
                rid,
                &format!("{}.{}", base, top),
                None,
            ));
        }
    }

    for cp in &schema.create_only_properties {
        let top = cp.split('.').next().unwrap_or(cp);
        if res.properties.contains_key(top) {
            out.push(build_diagnostic(
                "I9001",
                Severity::Info,
                &format!(
                    "Property '{}' is create-only; updating it will cause resource replacement",
                    top
                ),
                m,
                rid,
                &format!("{}.{}", base, top),
                None,
            ));
        }
    }

    for wo in &schema.write_only_properties {
        let top = wo.split('.').next().unwrap_or(wo);
        for edge in m.graph.incoming(rid) {
            if let RefKind::GetAtt { attr } = &edge.kind
                && attr == top
                && edge.source_resource.starts_with("__output__")
            {
                let output_name = edge
                    .source_resource
                    .strip_prefix("__output__")
                    .unwrap_or(&edge.source_resource);
                out.push(build_diagnostic(
                    "W3041",
                    Severity::Warn,
                    &format!(
                        "Write-only property '{}' of '{}' is referenced in output '{}'",
                        top, rid, output_name
                    ),
                    m,
                    rid,
                    &format!("{}.{}", base, top),
                    None,
                ));
            }
        }
    }

    let key_scenarios = resource_property_key_scenarios(m, rid, res);
    for (actual_keys, conds) in &key_scenarios {
        let scenario = if conds.is_empty() { None } else { Some(conds) };
        validate_object_keys_inner(
            out,
            m,
            rid,
            &res.resource_type,
            &schema.properties,
            defs,
            &schema.required,
            schema.additional_properties,
            &HashMap::new(),
            &schema.dependent_required,
            &schema.dependent_excluded,
            &schema.required_or,
            &schema.required_xor,
            &schema.all_of,
            &schema.any_of,
            &schema.one_of,
            actual_keys,
            base,
            &mut HashSet::new(),
            scenario,
        );
    }

    for (prop_name, prop_schema) in &schema.properties {
        let resolved = prop_schema.resolve(defs);
        let prop_path = format!("{}.{}", base, prop_name);
        validate_prop(
            out,
            store,
            m,
            rid,
            &res.resource_type,
            &prop_path,
            resolved,
            defs,
            &mut HashSet::new(),
            region,
        );
    }

    // Also validate properties that exist only inside conditional branches —
    // when Properties is wrapped in Fn::If, res.properties has only the
    // synthetic "Fn::If" key so the loop above would miss per-branch props.
    let branch_property_names: HashSet<String> = key_scenarios
        .iter()
        .flat_map(|(keys, _)| keys.iter().cloned())
        .collect();
    for prop_name in &branch_property_names {
        if res.properties.contains_key(prop_name) {
            continue;
        }
        let Some(prop_schema) = schema.properties.get(prop_name) else {
            continue;
        };
        let resolved = prop_schema.resolve(defs);
        let prop_path = format!("{}.{}", base, prop_name);
        validate_prop(
            out,
            store,
            m,
            rid,
            &res.resource_type,
            &prop_path,
            resolved,
            defs,
            &mut HashSet::new(),
            region,
        );
    }

    let actual_keys: Vec<String> = res.properties.keys().cloned().collect();
    for ite in &schema.if_then_else {
        let matches = condition_matches(&ite.condition, &actual_keys, m, rid, defs);
        let sub = if matches {
            &ite.then_schema
        } else {
            &ite.else_schema
        };
        if let Some(sub) = sub {
            validate_sub(
                out,
                m,
                rid,
                &res.resource_type,
                &actual_keys,
                sub,
                defs,
                base,
            );
        }
    }
}

fn validate_object_keys(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    rid: &str,
    rtype: &str,
    schema_props: &HashMap<String, PropSchema>,
    defs: &HashMap<String, PropSchema>,
    required: &[String],
    additional_properties: Option<bool>,
    pattern_props: &HashMap<String, PropSchema>,
    dep_req: &HashMap<String, Vec<String>>,
    dep_excl: &HashMap<String, Vec<String>>,
    req_or: &[String],
    req_xor: &[String],
    all_of: &[SubSchema],
    any_of: &[SubSchema],
    one_of: &[SubSchema],
    actual_keys: &[String],
    base_path: &str,
    _visited: &mut HashSet<String>,
) {
    validate_object_keys_inner(
        out,
        m,
        rid,
        rtype,
        schema_props,
        defs,
        required,
        additional_properties,
        pattern_props,
        dep_req,
        dep_excl,
        req_or,
        req_xor,
        all_of,
        any_of,
        one_of,
        actual_keys,
        base_path,
        _visited,
        None,
    )
}

/// Validate object keys, tagging any emitted diagnostics with the given
/// condition scenario. When `scenario` is `None`, diagnostics are unconditioned.
/// When `Some`, each emitted diagnostic records the condition assumptions that
/// make the scenario reachable.
#[allow(clippy::too_many_arguments)]
fn validate_object_keys_inner(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    rid: &str,
    rtype: &str,
    schema_props: &HashMap<String, PropSchema>,
    defs: &HashMap<String, PropSchema>,
    required: &[String],
    additional_properties: Option<bool>,
    pattern_props: &HashMap<String, PropSchema>,
    dep_req: &HashMap<String, Vec<String>>,
    dep_excl: &HashMap<String, Vec<String>>,
    req_or: &[String],
    req_xor: &[String],
    all_of: &[SubSchema],
    any_of: &[SubSchema],
    one_of: &[SubSchema],
    actual_keys: &[String],
    base_path: &str,
    _visited: &mut HashSet<String>,
    scenario: Option<&HashMap<String, bool>>,
) {
    let before_len = out.len();
    for req in required {
        if !actual_keys.contains(req) {
            out.push(build_diagnostic(
                "F3003",
                Severity::Fatal,
                &format!("'{}' is a required property", req),
                m,
                rid,
                base_path,
                Some(&format!("Add the required property '{}'", req)),
            ));
        } else if base_path == "Properties" {
            check_required_not_null(out, m, rid, base_path, req);
        }
    }

    if additional_properties == Some(false)
        && !rtype.starts_with("Custom::")
        && rtype != "AWS::CloudFormation::CustomResource"
    {
        let known: HashSet<&str> = schema_props.keys().map(|s| s.as_str()).collect();
        let pat_regexes: Vec<regex::Regex> = pattern_props
            .keys()
            .filter_map(|p| regex::Regex::new(p).ok())
            .collect();
        for key in actual_keys {
            if known.contains(key.as_str()) {
                continue;
            }
            if pat_regexes.iter().any(|re| re.is_match(key)) {
                continue;
            }
            let suggestion = find_similar(key, &known);
            let msg = match suggestion {
                Some(s) => format!(
                    "Additional properties are not allowed ('{}' was unexpected. Did you mean '{}'?)",
                    key, s
                ),
                None => format!(
                    "Additional properties are not allowed ('{}' was unexpected)",
                    key
                ),
            };
            out.push(build_diagnostic(
                "F3002",
                Severity::Fatal,
                &msg,
                m,
                rid,
                &format!("{}.{}", base_path, key),
                None,
            ));
        }
    }

    for (trigger, excluded) in dep_excl {
        if actual_keys.contains(trigger) {
            for dep in excluded {
                if actual_keys.contains(dep) {
                    out.push(build_diagnostic(
                        "F3020",
                        Severity::Fatal,
                        &format!("'{}' should not be included with '{}'", dep, trigger),
                        m,
                        rid,
                        &format!("{}.{}", base_path, dep),
                        None,
                    ));
                }
            }
        }
    }

    for (trigger, deps) in dep_req {
        if actual_keys.contains(trigger) {
            for dep in deps {
                if !actual_keys.contains(dep) {
                    out.push(build_diagnostic(
                        "F3021",
                        Severity::Fatal,
                        &format!("'{}' is a dependency of '{}'", dep, trigger),
                        m,
                        rid,
                        base_path,
                        Some(&format!("Add '{}' when '{}' is specified", dep, trigger)),
                    ));
                }
            }
        }
    }

    if !req_or.is_empty() && !req_or.iter().any(|p| actual_keys.contains(p)) {
        let names = req_or
            .iter()
            .map(|s| format!("'{}'", s))
            .collect::<Vec<_>>()
            .join(", ");
        out.push(build_diagnostic(
            "F3058",
            Severity::Fatal,
            &format!("One of [{}] is a required property", names),
            m,
            rid,
            base_path,
            None,
        ));
    }

    if !req_xor.is_empty() {
        let count = req_xor.iter().filter(|p| actual_keys.contains(p)).count();
        if count != 1 {
            let names = req_xor
                .iter()
                .map(|s| format!("'{}'", s))
                .collect::<Vec<_>>()
                .join(", ");
            out.push(build_diagnostic(
                "F3014",
                Severity::Fatal,
                &format!("Exactly one of [{}] must be specified", names),
                m,
                rid,
                base_path,
                None,
            ));
        }
    }

    for sub in all_of {
        validate_sub(out, m, rid, rtype, actual_keys, sub, defs, base_path);
    }

    if !any_of.is_empty() {
        let any_valid = any_of.iter().any(|sub| {
            let mut tmp = Vec::new();
            validate_sub(&mut tmp, m, rid, rtype, actual_keys, sub, defs, base_path);
            tmp.is_empty()
        });
        if !any_valid {
            out.push(build_diagnostic(
                "F3017",
                Severity::Fatal,
                &format!(
                    "Value is not valid under any of the given schemas for {}",
                    rtype
                ),
                m,
                rid,
                base_path,
                None,
            ));
        }
    }

    if !one_of.is_empty() {
        let valid_count = one_of
            .iter()
            .filter(|sub| {
                let mut tmp = Vec::new();
                validate_sub(&mut tmp, m, rid, rtype, actual_keys, sub, defs, base_path);
                tmp.is_empty()
            })
            .count();
        if valid_count == 0 {
            out.push(build_diagnostic(
                "F3018",
                Severity::Fatal,
                "Value is not valid under any of the given schemas",
                m,
                rid,
                base_path,
                None,
            ));
        } else if valid_count > 1 {
            out.push(build_diagnostic(
                "F3018",
                Severity::Fatal,
                "Value is valid under more than one of the given schemas",
                m,
                rid,
                base_path,
                None,
            ));
        }
    }

    // Tag every diagnostic this invocation produced with the caller's
    // condition scenario (if any). Callers passing `None` leave diagnostics
    // unconditioned, matching pre-existing behavior.
    if let Some(conds) = scenario {
        for diag in out.iter_mut().skip(before_len) {
            if diag.condition_scenario.is_none() {
                diag.condition_scenario = Some(conds.clone());
            }
        }
    }
}

/// Enumerate object key-sets visible at `prop_path`, one per condition
/// scenario. Returns at least one entry. When the value is not
/// condition-branching, returns a single entry with an empty scenario map.
/// When branches expose different keys, each branch contributes a distinct
/// entry annotated with the condition assumptions that select it.
fn object_key_scenarios(
    m: &Arc<SemanticModel>,
    rid: &str,
    prop_path: &str,
) -> Vec<(Vec<String>, HashMap<String, bool>)> {
    let mut out: Vec<(Vec<String>, HashMap<String, bool>)> = Vec::new();
    for (val, conds) in m.resolve_scenarios_json(rid, prop_path) {
        if !is_satisfiable(m, &conds) {
            continue;
        }
        let Some(obj) = val.as_object() else {
            continue;
        };
        let mut keys: Vec<String> = obj.keys().cloned().collect();
        keys.sort();
        out.push((keys, conds));
    }
    // Deduplicate scenarios that produce the same key set — when both
    // branches of a condition have identical keys, the condition does not
    // affect key validation, so a single unconditioned entry suffices.
    let mut seen_keysets: HashMap<Vec<String>, HashMap<String, bool>> = HashMap::new();
    for (keys, conds) in out.drain(..) {
        seen_keysets
            .entry(keys)
            .and_modify(|existing| {
                // When two scenarios reach the same keys under complementary
                // assumptions, the result is unconditioned — drop shared vars
                // where the two assumption maps disagree.
                existing.retain(|k, v| conds.get(k) == Some(v));
            })
            .or_insert(conds);
    }
    seen_keysets.into_iter().collect()
}

/// Top-level properties of a resource may themselves be wrapped in an
/// `Fn::If` — e.g. `Properties: {Fn::If: [Cond, {a: 1}, {b: 2}]}`. Return one
/// entry per reachable branch: each entry lists the concrete top-level keys
/// a branch exposes plus the condition assumptions that reach it. When
/// properties are not wrapped in `Fn::If`, returns a single unconditioned
/// entry built directly from `res.properties.keys()`.
fn resource_property_key_scenarios(
    m: &Arc<SemanticModel>,
    rid: &str,
    res: &ResolvedResource,
) -> Vec<(Vec<String>, HashMap<String, bool>)> {
    let keys: Vec<&str> = res.properties.keys().map(String::as_str).collect();
    if keys.len() != 1 || keys[0] != FN_IF {
        let mut ks: Vec<String> = res.properties.keys().cloned().collect();
        ks.sort();
        return vec![(ks, HashMap::new())];
    }
    // Walk branches via the scenario resolver using the synthetic path
    // under which the parser stored the conditional.
    let path = format!("{}.{}", KEY_PROPERTIES, FN_IF);
    let scenarios = object_key_scenarios(m, rid, &path);
    if scenarios.is_empty() {
        return vec![(Vec::new(), HashMap::new())];
    }
    scenarios
}

fn validate_sub(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    rid: &str,
    _rtype: &str,
    actual_keys: &[String],
    sub: &SubSchema,
    _defs: &HashMap<String, PropSchema>,
    base_path: &str,
) {
    for req in &sub.required {
        if !actual_keys.contains(req) {
            out.push(build_diagnostic(
                "F3003",
                Severity::Fatal,
                &format!("'{}' is a required property", req),
                m,
                rid,
                base_path,
                Some(&format!("Add '{}'", req)),
            ));
        }
    }
    for (trigger, deps) in &sub.dependent_required {
        if actual_keys.contains(trigger) {
            for dep in deps {
                if !actual_keys.contains(dep) {
                    out.push(build_diagnostic(
                        "F3021",
                        Severity::Fatal,
                        &format!("'{}' is a dependency of '{}'", dep, trigger),
                        m,
                        rid,
                        base_path,
                        None,
                    ));
                }
            }
        }
    }
    for (trigger, excluded) in &sub.dependent_excluded {
        if actual_keys.contains(trigger) {
            for dep in excluded {
                if actual_keys.contains(dep) {
                    out.push(build_diagnostic(
                        "F3020",
                        Severity::Fatal,
                        &format!("'{}' should not be included with '{}'", dep, trigger),
                        m,
                        rid,
                        &format!("{}.{}", base_path, dep),
                        None,
                    ));
                }
            }
        }
    }
}

fn validate_prop(
    out: &mut Vec<Diagnostic>,
    store: &CompiledSchemaStore,
    m: &Arc<SemanticModel>,
    rid: &str,
    rtype: &str,
    prop_path: &str,
    schema: &PropSchema,
    defs: &HashMap<String, PropSchema>,
    visited: &mut HashSet<String>,
    region: &str,
) {
    // Guard against circular $ref chains at validation time
    if let Some(ref rn) = schema.ref_name {
        if !visited.insert(rn.clone()) {
            return;
        }
        if let Some(resolved) = defs.get(rn) {
            validate_prop(
                out, store, m, rid, rtype, prop_path, resolved, defs, visited, region,
            );
        }
        visited.remove(rn);
        return;
    }

    let scenarios = m.resolve_scenarios_json(rid, prop_path);

    if scenarios.is_empty() {
        validate_reference_type(out, store, m, rid, prop_path, schema);
    }

    let res_suffix = describe_resolution(m, rid, prop_path)
        .map(|s| format!(" (from {})", s))
        .unwrap_or_default();

    // Type check — coerce before rejecting since string↔number, string↔boolean,
    // bool→string, number→string are silently coerced at deploy time.
    // Successful coercion → Warn; failed coercion → Fatal.
    if let Some(ref pt) = schema.prop_type {
        for (val, conds) in &scenarios {
            if !is_satisfiable(m, conds) || val.is_null() {
                continue;
            }
            if !type_matches(val, pt) {
                let expected = pt.primary().unwrap_or("unknown");
                match cfn_coerce_value(val, expected) {
                    CoerceResult::Coerced(_, ref description) => {
                        out.push(build_diagnostic_conditional(
                            "W9003",
                            Severity::Warn,
                            &format!(
                                "{}{} is not of type '{}' — automatically coerced ({})",
                                format_value(val),
                                res_suffix,
                                expected,
                                description
                            ),
                            m,
                            rid,
                            prop_path,
                            None,
                            condition_map(conds),
                        ));
                    }
                    _ => {
                        out.push(build_diagnostic_conditional(
                            "F3012",
                            Severity::Fatal,
                            &format!(
                                "{}{} is not of type '{}'",
                                format_value(val),
                                res_suffix,
                                expected
                            ),
                            m,
                            rid,
                            prop_path,
                            None,
                            condition_map(conds),
                        ));
                    }
                }
            }
        }
    }

    if !schema.enum_values.is_empty() {
        let prop_name = prop_path.strip_prefix("Properties.").unwrap_or(prop_path);
        let regional = store.region_enums().get(rtype, prop_name, region);
        for (val, conds) in &scenarios {
            if !is_satisfiable(m, conds) || val.is_null() {
                continue;
            }
            let matches = if let Some(regional_vals) = regional {
                val.as_str()
                    .map(|s| regional_vals.iter().any(|v| v == s))
                    .unwrap_or(false)
                    || enum_matches(val, &schema.enum_values)
            } else {
                enum_matches(val, &schema.enum_values)
            };
            if !matches {
                let enum_desc = if regional.is_some() {
                    format!("allowed values for region '{}'", region)
                } else {
                    format!("{:?}", schema.enum_values)
                };
                out.push(build_diagnostic_conditional(
                    "F3030",
                    Severity::Fatal,
                    &format!(
                        "{}{} is not one of {}",
                        format_value(val),
                        res_suffix,
                        enum_desc
                    ),
                    m,
                    rid,
                    prop_path,
                    None,
                    condition_map(conds),
                ));
            }
        }
    }

    if let Some(ref cv) = schema.const_value {
        for (val, conds) in &scenarios {
            if !is_satisfiable(m, conds) || val.is_null() {
                continue;
            }
            if val != cv {
                out.push(build_diagnostic_conditional(
                    "F3030",
                    Severity::Fatal,
                    &format!("{} was expected", cv),
                    m,
                    rid,
                    prop_path,
                    None,
                    condition_map(conds),
                ));
            }
        }
    }

    if let Some(ref pat) = schema.pattern
        && let Ok(re) = regex::Regex::new(pat)
    {
        let from_param = m.is_from_parameter(rid, prop_path);
        for (val, conds) in &scenarios {
            if !is_satisfiable(m, conds) || val.is_null() {
                continue;
            }
            if let Some(s) = cfn_coerce_to_string(val) {
                if s.contains("{{resolve:") || s.contains("${") {
                    continue;
                }
                // Malformed dynamic reference (e.g. "{{ resolve:ssm:... }}" with
                // spaces) — the pattern-mismatch warning reports this. Skip the Fatal
                // to avoid double-flagging; the downstream API (not CFN itself)
                // is what rejects the unresolved literal.
                if s.contains("{{") && s.contains("resolve") {
                    continue;
                }
                if from_param {
                    continue;
                }
                if !re.is_match(&s) {
                    out.push(build_diagnostic_conditional(
                        "F3031",
                        Severity::Fatal,
                        &format!("{} does not match pattern '{}'", format_value(val), pat),
                        m,
                        rid,
                        prop_path,
                        None,
                        condition_map(conds),
                    ));
                }
            }
        }
    }

    if let Some(ref fmt) = schema.format {
        validate_format(out, m, rid, prop_path, fmt);
    }

    for (val, conds) in &scenarios {
        if !is_satisfiable(m, conds) || val.is_null() {
            continue;
        }
        let Some(n) = cfn_coerce_to_number(val) else {
            continue;
        };
        if let Some(max) = schema.maximum
            && n > max
        {
            out.push(build_diagnostic_conditional(
                "F3034",
                Severity::Fatal,
                &format!("{} is greater than the maximum of {}", n, max),
                m,
                rid,
                prop_path,
                None,
                condition_map(conds),
            ));
        }
        if let Some(min) = schema.minimum
            && n < min
        {
            out.push(build_diagnostic_conditional(
                "F3034",
                Severity::Fatal,
                &format!("{} is less than the minimum of {}", n, min),
                m,
                rid,
                prop_path,
                None,
                condition_map(conds),
            ));
        }
        if let Some(emax) = schema.exclusive_maximum
            && n >= emax
        {
            out.push(build_diagnostic_conditional(
                "F3034",
                Severity::Fatal,
                &format!("{} is >= exclusive maximum {}", n, emax),
                m,
                rid,
                prop_path,
                None,
                condition_map(conds),
            ));
        }
        if let Some(emin) = schema.exclusive_minimum
            && n <= emin
        {
            out.push(build_diagnostic_conditional(
                "F3034",
                Severity::Fatal,
                &format!("{} is <= exclusive minimum {}", n, emin),
                m,
                rid,
                prop_path,
                None,
                condition_map(conds),
            ));
        }
    }

    if schema.min_length.is_some() || schema.max_length.is_some() {
        let from_param = m.is_from_parameter(rid, prop_path);
        for (val, conds) in &scenarios {
            if !is_satisfiable(m, conds) || val.is_null() {
                continue;
            }
            let Some(s) = cfn_coerce_to_string(val) else {
                continue;
            };
            if s.contains("{{resolve:") || s.contains("${") {
                continue;
            }
            if from_param {
                continue;
            }
            let len = s.len() as u64;
            if let Some(max) = schema.max_length
                && len > max
            {
                out.push(build_diagnostic_conditional(
                    "F3033",
                    Severity::Fatal,
                    &format!("length {} exceeds maximum {}", len, max),
                    m,
                    rid,
                    prop_path,
                    None,
                    condition_map(conds),
                ));
            }
            if let Some(min) = schema.min_length
                && len < min
            {
                out.push(build_diagnostic_conditional(
                    "F3033",
                    Severity::Fatal,
                    &format!("length {} is below minimum {}", len, min),
                    m,
                    rid,
                    prop_path,
                    None,
                    condition_map(conds),
                ));
            }
        }
    }

    for (val, conds) in &scenarios {
        if !is_satisfiable(m, conds) || val.is_null() {
            continue;
        }
        if let Some(arr) = val.as_array() {
            let len = arr.len() as u64;
            if let Some(max) = schema.max_items
                && len > max
            {
                out.push(build_diagnostic_conditional(
                    "F3032",
                    Severity::Fatal,
                    &format!("expected maximum item count: {}, found: {}", max, len),
                    m,
                    rid,
                    prop_path,
                    None,
                    condition_map(conds),
                ));
            }
            if let Some(min) = schema.min_items
                && len < min
            {
                out.push(build_diagnostic_conditional(
                    "F3032",
                    Severity::Fatal,
                    &format!("expected minimum item count: {}, found: {}", min, len),
                    m,
                    rid,
                    prop_path,
                    None,
                    condition_map(conds),
                ));
            }
        }
    }

    if schema.unique_items {
        for (val, conds) in &scenarios {
            if !is_satisfiable(m, conds) || val.is_null() {
                continue;
            }
            if let Some(arr) = val.as_array() {
                let mut seen = Vec::new();
                for item in arr {
                    if seen.contains(item) {
                        out.push(build_diagnostic_conditional(
                            "F3037",
                            Severity::Fatal,
                            "Array items are not unique",
                            m,
                            rid,
                            prop_path,
                            None,
                            condition_map(conds),
                        ));
                        break;
                    }
                    seen.push(item.clone());
                }
            }
        }
    }

    let has_nested_constraints = !schema.properties.is_empty()
        || !schema.required.is_empty()
        || !schema.dependent_required.is_empty()
        || !schema.dependent_excluded.is_empty()
        || !schema.all_of.is_empty()
        || !schema.any_of.is_empty()
        || !schema.one_of.is_empty()
        || schema.additional_properties.is_some();
    if has_nested_constraints {
        let nested_keys = collect_keys_deep(m, rid, prop_path);
        if !nested_keys.is_empty() {
            validate_object_keys(
                out,
                m,
                rid,
                rtype,
                &schema.properties,
                defs,
                &schema.required,
                schema.additional_properties,
                &schema.pattern_properties,
                &schema.dependent_required,
                &schema.dependent_excluded,
                &[],
                &[],
                &schema.all_of,
                &schema.any_of,
                &schema.one_of,
                &nested_keys,
                prop_path,
                visited,
            );
        } else if !schema.required.is_empty() {
            // Empty concrete object scenario (e.g. `Fn::If: [C, NoValue, {}]`) —
            // still validate required properties per-scenario. An empty object
            // has no keys but required properties must still be present.
            // Uses `resolve_scenarios` (not _json) to bypass SAT filtering:
            // pseudo-parameter concretization (e.g. AWS::Region default) can
            // mark an Fn::If branch as unreachable, but both branches are
            // evaluated at deploy time with the real parameter values.
            for (val, _conds) in m.resolve_scenarios(rid, prop_path) {
                if let ResolvedValue::Concrete { value } = &val
                    && let Some(obj) = value.as_object()
                {
                    let keys: Vec<String> = obj.keys().cloned().collect();
                    validate_object_keys(
                        out,
                        m,
                        rid,
                        rtype,
                        &schema.properties,
                        defs,
                        &schema.required,
                        schema.additional_properties,
                        &schema.pattern_properties,
                        &schema.dependent_required,
                        &schema.dependent_excluded,
                        &[],
                        &[],
                        &schema.all_of,
                        &schema.any_of,
                        &schema.one_of,
                        &keys,
                        prop_path,
                        visited,
                    );
                }
            }
        }
        for (pn, ps) in &schema.properties {
            let resolved = ps.resolve(defs);
            let sub_path = format!("{}.{}", prop_path, pn);
            let sub_scenarios = m.resolve_scenarios_json(rid, &sub_path);
            if !sub_scenarios.is_empty() || m.resolve_deep(rid, &sub_path).is_some() {
                validate_prop(
                    out, store, m, rid, rtype, &sub_path, resolved, defs, visited, region,
                );
            }
        }
    }

    if let Some(ref item_schema) = schema.items {
        let resolved = item_schema.resolve(defs);
        // Use per-index paths instead of wildcard {} to avoid dedup mismatches
        let mut did_per_index = false;
        {
            let arr_len = match m
                .resolve_deep(rid, prop_path)
                .or_else(|| m.resolve(rid, prop_path).cloned())
            {
                Some(ResolvedValue::List { items }) => Some(items.len()),
                Some(ResolvedValue::Concrete { value: ref v }) if v.is_array() => {
                    Some(v.as_array().unwrap().len())
                }
                _ => None,
            };
            if let Some(len) = arr_len {
                did_per_index = true;
                for idx in 0..len {
                    let idx_path = format!("{}.{}", prop_path, idx);
                    validate_prop(
                        out, store, m, rid, rtype, &idx_path, resolved, defs, visited, region,
                    );
                }
            } else {
                validate_prop(
                    out,
                    store,
                    m,
                    rid,
                    rtype,
                    &format!("{}.{{}}", prop_path),
                    resolved,
                    defs,
                    visited,
                    region,
                );
            }
        }
        if !did_per_index
            && (!resolved.dependent_excluded.is_empty() || !resolved.dependent_required.is_empty())
        {
            validate_array_item_constraints(out, m, rid, prop_path, resolved);
        }
    }
}

fn validate_array_item_constraints(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    rid: &str,
    array_path: &str,
    item_schema: &PropSchema,
) {
    let arr = match m
        .resolve_deep(rid, array_path)
        .or_else(|| m.resolve(rid, array_path).cloned())
    {
        Some(ResolvedValue::List { items }) => items,
        Some(ResolvedValue::Concrete { value: v }) => match v.into_inner() {
            serde_json::Value::Array(items) => items
                .into_iter()
                .map(|i| ResolvedValue::Concrete { value: i.into() })
                .collect(),
            _ => return,
        },
        _ => return,
    };
    for (idx, item) in arr.iter().enumerate() {
        let keys: Vec<String> = match item {
            ResolvedValue::Map { entries } => entries.iter().map(|e| e.key.clone()).collect(),
            ResolvedValue::Concrete { value: v } if v.is_object() => {
                v.as_object().unwrap().keys().cloned().collect()
            }
            _ => continue,
        };
        let item_path = format!("{}.{}", array_path, idx);
        for (trigger, excluded) in &item_schema.dependent_excluded {
            if keys.iter().any(|k| k == trigger) {
                for dep in excluded {
                    if keys.iter().any(|k| k == dep) {
                        out.push(build_diagnostic(
                            "F3020",
                            Severity::Fatal,
                            &format!("'{}' should not be included with '{}'", dep, trigger),
                            m,
                            rid,
                            &format!("{}.{}", item_path, dep),
                            None,
                        ));
                    }
                }
            }
        }
        for (trigger, deps) in &item_schema.dependent_required {
            if keys.iter().any(|k| k == trigger) {
                for dep in deps {
                    if !keys.iter().any(|k| k == dep) {
                        out.push(build_diagnostic(
                            "F3021",
                            Severity::Fatal,
                            &format!("'{}' is a dependency of '{}'", dep, trigger),
                            m,
                            rid,
                            &item_path,
                            Some(&format!("Add '{}' when '{}' is specified", dep, trigger)),
                        ));
                    }
                }
            }
        }
    }
}

fn collect_keys_deep(m: &Arc<SemanticModel>, rid: &str, path: &str) -> Vec<String> {
    let mut keys = HashSet::new();
    match m
        .resolve_deep(rid, path)
        .or_else(|| m.resolve(rid, path).cloned())
    {
        Some(ResolvedValue::Map { entries }) => {
            for e in &entries {
                keys.insert(e.key.clone());
            }
        }
        Some(ResolvedValue::Concrete { value: ref v }) if v.is_object() => {
            for k in v.as_object().unwrap().keys() {
                keys.insert(k.clone());
            }
        }
        _ => {}
    }
    if keys.is_empty() {
        for (val, conds) in &m.resolve_scenarios_json(rid, path) {
            if !is_satisfiable(m, conds) || val.is_null() {
                continue;
            }
            if let Some(obj) = val.as_object() {
                for k in obj.keys() {
                    keys.insert(k.clone());
                }
            }
        }
    }
    keys.into_iter().collect()
}

fn type_matches(val: &serde_json::Value, pt: &PropType) -> bool {
    match pt {
        PropType::Single(s) => single_type(val, s),
        PropType::Multi(types) => types.iter().any(|t| single_type(val, t)),
    }
}

fn single_type(val: &serde_json::Value, expected: &str) -> bool {
    match expected {
        "string" => val.is_string(),
        "integer" => {
            val.is_i64()
                || val.is_u64()
                || (val.is_f64() && val.as_f64().map(|f| f.fract() == 0.0).unwrap_or(false))
        }
        "number" | "double" | "float" => val.is_number(),
        "boolean" => val.is_boolean(),
        "array" => val.is_array(),
        "object" => val.is_object(),
        "null" => val.is_null(),
        _ => true,
    }
}

fn enum_matches(val: &serde_json::Value, allowed: &[serde_json::Value]) -> bool {
    allowed.iter().any(|a| {
        if a == val {
            return true;
        }
        if let (Some(av), Some(vv)) = (cfn_coerce_to_string(a), cfn_coerce_to_string(val)) {
            return av == vv;
        }
        false
    })
}

fn check_required_not_null(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    rid: &str,
    base: &str,
    req: &str,
) {
    for (val, conds) in &m.resolve_scenarios_json(rid, &format!("{}.{}", base, req)) {
        if !is_satisfiable(m, conds) {
            continue;
        }
        if val.is_null() {
            out.push(build_diagnostic_conditional(
                "F3003",
                Severity::Fatal,
                &format!("'{}' is a required property", req),
                m,
                rid,
                base,
                Some(&format!("Add the required property '{}'", req)),
                condition_map(conds),
            ));
        }
    }
}

fn is_satisfiable(m: &Arc<SemanticModel>, conds: &HashMap<String, bool>) -> bool {
    if conds.is_empty() {
        return true;
    }
    m.conditions.is_satisfiable(
        &conds
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect::<Vec<_>>(),
    )
}

fn condition_map(conds: &HashMap<String, bool>) -> Option<HashMap<String, bool>> {
    if conds.is_empty() {
        None
    } else {
        Some(conds.clone())
    }
}

fn find_similar<'a>(key: &str, known: &HashSet<&'a str>) -> Option<&'a str> {
    let kl = key.to_lowercase();
    known
        .iter()
        .find(|k| {
            let l = k.to_lowercase();
            let max = kl.len().max(l.len());
            if max == 0 {
                return true;
            }
            let d = levenshtein_distance(&kl, &l);
            1.0 - (d as f64 / max as f64) > 0.8
        })
        .copied()
}

fn levenshtein_distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut dp = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for i in 0..=a.len() {
        dp[i][0] = i;
    }
    for j in 0..=b.len() {
        dp[0][j] = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let c = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            dp[i][j] = (dp[i - 1][j] + 1)
                .min(dp[i][j - 1] + 1)
                .min(dp[i - 1][j - 1] + c);
        }
    }
    dp[a.len()][b.len()]
}

fn format_value(val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::String(s) => format!("'{}'", s),
        o => o.to_string(),
    }
}

fn condition_matches(
    cond: &ConditionSchema,
    actual_keys: &[String],
    m: &Arc<SemanticModel>,
    rid: &str,
    defs: &HashMap<String, PropSchema>,
) -> bool {
    if !cond.any_of.is_empty() {
        return cond
            .any_of
            .iter()
            .any(|sub| condition_matches(sub, actual_keys, m, rid, defs));
    }
    for req in &cond.required {
        if !actual_keys.iter().any(|k| k == req) {
            return false;
        }
    }
    for (prop_name, prop_schema) in &cond.properties {
        let resolved = prop_schema.resolve(defs);
        let prop_path = format!("Properties.{}", prop_name);
        let scenarios = m.resolve_scenarios_json(rid, &prop_path);
        // When the value is dynamic (unresolvable) and the condition has a concrete
        // constraint (pattern/enum/const), we cannot confirm the match — return false
        // to avoid incorrectly activating the then branch.
        let has_concrete_constraint = resolved.pattern.is_some()
            || !resolved.enum_values.is_empty()
            || !resolved.not_enum.is_empty()
            || resolved.const_value.is_some();
        if scenarios.is_empty() {
            if has_concrete_constraint {
                return false;
            }
            continue;
        }
        let compiled_pattern = resolved
            .pattern
            .as_ref()
            .and_then(|pat| regex::Regex::new(pat).ok());
        // If the schema has a pattern but it failed to compile (e.g. lookahead),
        // we cannot verify the constraint — treat as non-matching.
        let pattern_uncompilable = resolved.pattern.is_some() && compiled_pattern.is_none();
        if pattern_uncompilable {
            return false;
        }
        let any_match = scenarios.iter().any(|(val, conds)| {
            if !is_satisfiable(m, conds) {
                return false;
            }
            if !resolved.enum_values.is_empty() {
                return enum_matches(val, &resolved.enum_values);
            }
            if !resolved.not_enum.is_empty() {
                return !enum_matches(val, &resolved.not_enum);
            }
            if let Some(ref cv) = resolved.const_value {
                return val == cv;
            }
            if let Some(ref re) = compiled_pattern {
                return val.as_str().map(|s| re.is_match(s)).unwrap_or(false);
            }
            if let Some(ref pt) = resolved.prop_type {
                return type_matches(val, pt);
            }
            true
        });
        if !any_match {
            return false;
        }
    }
    true
}

/// Task 2: Validate type compatibility when a property's value is a Ref, GetAtt, or TypedDynamic.
/// Called as fallback when resolve_scenarios_json returns empty (it filters out References).
fn validate_reference_type(
    out: &mut Vec<Diagnostic>,
    store: &CompiledSchemaStore,
    m: &Arc<SemanticModel>,
    rid: &str,
    prop_path: &str,
    schema: &PropSchema,
) {
    let Some(ref expected_type) = schema.prop_type else {
        return;
    };
    let raw = m
        .resolve(rid, prop_path)
        .cloned()
        .or_else(|| m.resolve_deep(rid, prop_path));
    let Some(raw) = raw else { return };

    match &raw {
        ResolvedValue::Reference { target, kind } => {
            let target_type = m
                .resources
                .get(target.as_str())
                .map(|r| r.resource_type.as_str());
            let Some(target_rtype) = target_type else {
                return;
            };

            let source_type = match kind {
                RefKind::Ref => store.ref_types().ref_type_for(target_rtype),
                RefKind::GetAtt { attr } => store.ref_types().getatt_type_for(target_rtype, attr),
                _ => None,
            };
            let Some(source) = source_type else { return };

            if !types_compatible(source, expected_type) {
                let ref_desc = match kind {
                    RefKind::Ref => format!("Ref to '{}'", target),
                    RefKind::GetAtt { attr: a } => {
                        format!("GetAtt {}.{}", target, a)
                    }
                    _ => return,
                };
                out.push(build_diagnostic(
                    "F3012",
                    Severity::Fatal,
                    &format!(
                        "{} ({}) returns '{}', but property expects '{}'",
                        ref_desc,
                        target_rtype,
                        source,
                        expected_type.primary().unwrap_or("unknown")
                    ),
                    m,
                    rid,
                    prop_path,
                    None,
                ));
            }

            if let Some(ref fmt) = schema.format {
                let compatible = store.ref_types().format_compatible_types(fmt);
                if !compatible.is_empty() && !compatible.iter().any(|t| t == target_rtype) {
                    let (rule_id, severity) = match rules::format_rule_for_format(fmt) {
                        Some(id) => (id, Severity::Error),
                        None => ("E1103", Severity::Error),
                    };
                    out.push(build_diagnostic(
                        rule_id,
                        severity,
                        &format!(
                            "Ref to '{}' ({}) may not produce a valid '{}' value",
                            target, target_rtype, fmt
                        ),
                        m,
                        rid,
                        prop_path,
                        None,
                    ));
                }
            }
        }
        ResolvedValue::TypedDynamic {
            reason: _name,
            param_type,
        } => {
            let source = cfn_param_type_to_schema_type(param_type);
            if !types_compatible(source, expected_type) {
                let expected = expected_type.primary().unwrap_or("unknown");
                // Parameters are coerced at deploy time — warn rather than error
                out.push(build_diagnostic(
                    "W9003",
                    Severity::Warn,
                    &format!(
                        "Parameter type '{}' may not be compatible with expected type '{}'",
                        param_type, expected
                    ),
                    m,
                    rid,
                    prop_path,
                    None,
                ));
            }
        }
        _ => {}
    }
}

fn cfn_param_type_to_schema_type(param_type: &str) -> &str {
    match param_type {
        "Number" => "number",
        "String" => "string",
        "CommaDelimitedList" => "array",
        t if t.starts_with("List<") => "array",
        t if t.starts_with("AWS::SSM::Parameter::") => "string",
        _ => "string",
    }
}

fn types_compatible(source: &str, expected: &PropType) -> bool {
    match expected {
        PropType::Single(e) => single_type_compatible(source, e),
        PropType::Multi(types) => types.iter().any(|e| single_type_compatible(source, e)),
    }
}

fn single_type_compatible(source: &str, expected: &str) -> bool {
    match (source, expected) {
        (s, e) if s == e => true,
        ("integer", "number") | ("number", "integer") => true,
        ("string", "number") | ("string", "integer") => true, // CFN coerces string→number
        ("number", "string") | ("integer", "string") | ("boolean", "string") => true, // CFN coerces to string
        (_, "null") => true,
        _ => false,
    }
}

fn validate_format(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    rid: &str,
    prop_path: &str,
    format: &str,
) {
    let re_pattern = match format {
        "AWS::EC2::VPC.Id" => Some(r"^vpc-[a-f0-9]{8,17}$"),
        "AWS::EC2::Subnet.Id" => Some(r"^subnet-[a-f0-9]{8,17}$"),
        "AWS::EC2::SecurityGroup.Id" => Some(r"^sg-[a-f0-9]{8,17}$"),
        "AWS::EC2::Image.Id" => Some(r"^ami-[a-f0-9]{8,17}$"),
        "AWS::IAM::Role.Arn" => Some(r"^arn:(aws|aws-cn|aws-us-gov):iam::\d{12}:role/.+"),
        "AWS::Logs::LogGroup.Name" => Some(r"^[\.\-_/#A-Za-z0-9]{1,512}$"),
        "AWS::EC2::SecurityGroup.Name" => Some(r"^[\s\S]+$"),
        "AWS::EC2::KeyPair.KeyName" => Some(r"^[\x20-\x7E]{1,255}$"),
        "AWS::EC2::AvailabilityZone.Name" => Some(r"^[a-z]{2}(-gov|-iso[a-z]*)?-[a-z]+-\d[a-z]$"),
        "AWS::Route53::HostedZone.Id" => Some(r"^Z[A-Z0-9]{1,32}$"),
        "AWS::EC2::Volume.Id" => Some(r"^vol-[a-f0-9]{8,17}$"),
        "AWS::EC2::NetworkInterface.Id" => Some(r"^eni-[a-f0-9]{8,17}$"),
        "AWS::SSM::Parameter.Name" => Some(r"^[a-zA-Z0-9_./-]{1,2048}$"),
        _ => None,
    };
    let Some(pattern) = re_pattern else { return };
    let Ok(re) = regex::Regex::new(pattern) else {
        return;
    };

    for (val, conds) in &m.resolve_scenarios_json(rid, prop_path) {
        if !is_satisfiable(m, conds) || val.is_null() {
            continue;
        }
        if let Some(s) = cfn_coerce_to_string(val) {
            if s.contains("{{resolve:") || s.contains("${") {
                continue;
            }
            if m.is_from_parameter(rid, prop_path) {
                continue;
            }
            if !re.is_match(&s) {
                let (rule_id, severity) = match rules::format_rule_for_format(format) {
                    Some(id) => (id, Severity::Error),
                    None => ("E1103", Severity::Error),
                };
                out.push(build_diagnostic_conditional(
                    rule_id,
                    severity,
                    &format!("{} does not match format '{}'", format_value(val), format),
                    m,
                    rid,
                    prop_path,
                    None,
                    condition_map(conds),
                ));
            }
        }
    }
}

fn validate_lifecycle(
    out: &mut Vec<Diagnostic>,
    store: &CompiledSchemaStore,
    model: &Arc<SemanticModel>,
) {
    let lifecycle = store.lifecycle();
    for (rid, res) in &model.resources {
        if let Some(entry) = lifecycle.resource_lifecycle(&res.resource_type) {
            let (rule_id, severity, msg) = match (entry.status.as_str(), entry.date.as_deref()) {
                ("shutdown", Some(d)) => (
                    "E3710",
                    Severity::Error,
                    format!(
                        "Resource type '{}' is from a service that was shut down on {}",
                        res.resource_type, d
                    ),
                ),
                ("shutdown", None) => (
                    "E3710",
                    Severity::Error,
                    format!(
                        "Resource type '{}' is from a service that has been shut down",
                        res.resource_type
                    ),
                ),
                ("sunset", Some(d)) => (
                    "W3696",
                    Severity::Warn,
                    format!(
                        "Resource type '{}' is from a service that will be shut down on {}. Plan to migrate to an alternative",
                        res.resource_type, d
                    ),
                ),
                ("sunset", None) => (
                    "W3696",
                    Severity::Warn,
                    format!(
                        "Resource type '{}' is from a service that is sunsetting",
                        res.resource_type
                    ),
                ),
                ("maintenance", Some(d)) => (
                    "W3697",
                    Severity::Warn,
                    format!(
                        "Resource type '{}' is from a service in maintenance mode since {}. Consider migrating to an alternative",
                        res.resource_type, d
                    ),
                ),
                ("maintenance", None) => (
                    "W3697",
                    Severity::Warn,
                    format!(
                        "Resource type '{}' is from a service in maintenance mode",
                        res.resource_type
                    ),
                ),
                _ => continue,
            };
            out.push(build_diagnostic(
                rule_id, severity, &msg, model, rid, "", None,
            ));
        }

        if res.resource_type == "AWS::Lambda::Function"
            || res.resource_type == "AWS::Serverless::Function"
        {
            for (val, _) in &model.resolve_scenarios_json(rid, "Properties.Runtime") {
                let Some(runtime) = val.as_str() else {
                    continue;
                };
                if lifecycle.is_runtime_eol(runtime) {
                    out.push(build_diagnostic(
                        "E2533",
                        Severity::Error,
                        &format!("Runtime '{}' has reached end-of-life", runtime),
                        model,
                        rid,
                        "Properties.Runtime",
                        Some("Update to a supported runtime"),
                    ));
                } else if lifecycle.is_runtime_create_blocked(runtime) {
                    out.push(build_diagnostic(
                        "E2531",
                        Severity::Error,
                        &format!("Runtime '{}' is blocked for new function creation", runtime),
                        model,
                        rid,
                        "Properties.Runtime",
                        Some("Update to a supported runtime"),
                    ));
                } else if lifecycle.is_runtime_deprecated(runtime) {
                    out.push(build_diagnostic(
                        "W2531",
                        Severity::Warn,
                        &format!("Runtime '{}' is deprecated", runtime),
                        model,
                        rid,
                        "Properties.Runtime",
                        Some("Update to a current runtime"),
                    ));
                }
            }
        }
    }
}

fn validate_extensions(
    out: &mut Vec<Diagnostic>,
    store: &CompiledSchemaStore,
    model: &Arc<SemanticModel>,
    rid: &str,
    res: &ResolvedResource,
) {
    let Some(exts) = store.extensions().get(&res.resource_type) else {
        return;
    };
    for ext in exts {
        if ext.get("cfnGather").is_some() {
            validate_cfn_gather(out, model, rid, res, ext);
        } else if ext.get("if").is_some() {
            validate_extension_if_then_else(out, model, rid, res, ext);
        } else if let Some(all_of) = ext.get("allOf").and_then(|v| v.as_array()) {
            for sub_ext in all_of {
                if sub_ext.get("if").is_some() {
                    validate_extension_if_then_else(out, model, rid, res, sub_ext);
                }
            }
        }
    }
}

fn validate_cfn_gather(
    out: &mut Vec<Diagnostic>,
    model: &Arc<SemanticModel>,
    rid: &str,
    res: &ResolvedResource,
    ext: &serde_json::Value,
) {
    let Some(gather_def) = ext.get("cfnGather") else {
        return;
    };
    let Some(gather_slots) = gather_def.get("gather").and_then(|v| v.as_object()) else {
        return;
    };
    let Some(schema) = gather_def.get("schema") else {
        return;
    };

    let mut context = serde_json::Map::new();
    for (slot_name, slot_def) in gather_slots {
        let slot_obj = match slot_def.as_object() {
            Some(o) => o,
            None => continue,
        };
        let properties = slot_obj.get("properties").and_then(|v| v.as_object());
        let reference_path = slot_obj.get("reference").and_then(|v| v.as_str());

        let target_rid = if let Some(ref_path) = reference_path {
            let prop_key = ref_path.trim_start_matches('/');
            model
                .follow_ref(rid, &format!("Properties.{}", prop_key))
                .map(String::from)
        } else {
            Some(rid.to_string())
        };

        let Some(target) = target_rid else { continue };

        if let Some(filter) = slot_obj.get("filter").and_then(|v| v.as_object())
            && let Some(expected_type) = filter.get("type").and_then(|v| v.as_str())
        {
            let actual_type = model
                .resources
                .get(&target)
                .map(|r| r.resource_type.as_str());
            if actual_type != Some(expected_type) {
                continue;
            }
        }

        let mut slot_values = serde_json::Map::new();
        if let Some(props) = properties {
            for (prop_name, prop_def) in props {
                let path = prop_def
                    .get("path")
                    .and_then(|v| v.as_str())
                    .map(|p| format!("Properties.{}", p.trim_start_matches('/')));
                let default_val = prop_def.get("default").cloned();

                let resolved = path.as_ref().and_then(|p| {
                    model
                        .resolve_scenarios_json(&target, p)
                        .into_iter()
                        .next()
                        .map(|(v, _)| v)
                });
                let value = resolved.or(default_val).unwrap_or(serde_json::Value::Null);
                slot_values.insert(prop_name.clone(), value);
            }
        }
        context.insert(slot_name.clone(), serde_json::Value::Object(slot_values));
    }

    let context_val = serde_json::Value::Object(context);

    let resolved_schema = resolve_data_in_schema(schema, &context_val);
    evaluate_gather_schema(out, model, rid, res, &resolved_schema, &context_val);
}

fn validate_extension_if_then_else(
    out: &mut Vec<Diagnostic>,
    model: &Arc<SemanticModel>,
    rid: &str,
    res: &ResolvedResource,
    ext: &serde_json::Value,
) {
    let Some(if_schema) = ext.get("if") else {
        return;
    };
    let if_matches = extension_condition_matches(if_schema, model, rid);
    let branch = if if_matches {
        ext.get("then")
    } else {
        ext.get("else")
    };
    let Some(branch_schema) = branch else { return };

    if let Some(required) = branch_schema.get("required").and_then(|v| v.as_array()) {
        for req in required {
            if let Some(prop_name) = req.as_str()
                && !res.properties.contains_key(prop_name)
            {
                // Dedup: compiled base schema's if_then_else may already have
                // emitted a required-property diagnostic for the same required property (extensions
                // upstream sometimes mirror the base schema's conditional
                // requirements). Skip to avoid double-reporting.
                let already_reported = out.iter().any(|d| {
                    d.rule_id == "F3003"
                        && d.resource.as_ref().and_then(|r| r.id.as_deref()) == Some(rid)
                        && d.message
                            .contains(&format!("'{}' is a required property", prop_name))
                });
                if already_reported {
                    continue;
                }
                out.push(build_diagnostic(
                    "F3003",
                    Severity::Fatal,
                    &format!("'{}' is a required property (from extension)", prop_name),
                    model,
                    rid,
                    "Properties",
                    Some(&format!("Add '{}'", prop_name)),
                ));
            }
        }
    }

    if let Some(props) = branch_schema.get("properties").and_then(|v| v.as_object()) {
        for (prop_name, constraint) in props {
            if constraint == &serde_json::Value::Bool(false)
                && res.properties.contains_key(prop_name)
            {
                // Extension marks the property as non-applicable in this configuration.
                // CloudFormation does not reject such properties — it ignores them.
                // Emit as Info so the finding is surfaced but does not block deployment
                // or cause `good/` fixtures to fail the no-errors contract.
                out.push(build_diagnostic(
                    "I9002",
                    Severity::Info,
                    &format!(
                        "'{}' is ignored in this configuration (from extension)",
                        prop_name
                    ),
                    model,
                    rid,
                    &format!("Properties.{}", prop_name),
                    None,
                ));
            }
        }
    }

    if let Some(props) = branch_schema.get("properties").and_then(|v| v.as_object()) {
        for (prop_name, constraint) in props {
            let constraint_obj = match constraint.as_object() {
                Some(o) => o,
                None => continue,
            };
            let Some(enum_vals) = constraint_obj.get("enum").and_then(|v| v.as_array()) else {
                continue;
            };
            let scenarios = model.resolve_scenarios_json(rid, &format!("Properties.{}", prop_name));
            for (val, conds) in &scenarios {
                if !is_satisfiable(model, conds) {
                    continue;
                }
                let matches_enum = enum_vals.iter().any(|e| {
                    e == val
                        || cfn_coerce_to_string(e) == cfn_coerce_to_string(val)
                        || e.as_str()
                            .zip(val.as_str())
                            .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
                });
                if !matches_enum {
                    let allowed: Vec<String> = enum_vals
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    out.push(build_diagnostic(
                        "E9006",
                        Severity::Error,
                        &format!(
                            "'{}' is not one of {:?}",
                            cfn_coerce_to_string(val).unwrap_or_default(),
                            allowed
                        ),
                        model,
                        rid,
                        &format!("Properties.{}", prop_name),
                        None,
                    ));
                }
            }
        }
    }
}

/// Check whether a resolved JSON value satisfies a single JSON Schema constraint object
/// containing `enum`, `const`, or `pattern`.  Returns `true` when no recognised keyword
/// is present (open constraint).
fn match_constraint_value(
    constraint: &serde_json::Map<String, serde_json::Value>,
    val: &serde_json::Value,
) -> bool {
    if let Some(enum_vals) = constraint.get("enum").and_then(|v| v.as_array()) {
        return enum_vals
            .iter()
            .any(|e| e == val || cfn_coerce_to_string(e) == cfn_coerce_to_string(val));
    }
    if let Some(cv) = constraint.get("const") {
        return val == cv || cfn_coerce_to_string(cv) == cfn_coerce_to_string(val);
    }
    if let Some(pat) = constraint.get("pattern").and_then(|v| v.as_str()) {
        return val
            .as_str()
            .and_then(|s| regex::Regex::new(pat).ok().map(|re| re.is_match(s)))
            .unwrap_or(false);
    }
    true
}

fn extension_condition_matches(
    if_schema: &serde_json::Value,
    model: &Arc<SemanticModel>,
    rid: &str,
) -> bool {
    let Some(obj) = if_schema.as_object() else {
        return false;
    };

    if let Some(required) = obj.get("required").and_then(|v| v.as_array()) {
        for req in required {
            if let Some(name) = req.as_str() {
                let scenarios = model.resolve_scenarios_json(rid, &format!("Properties.{}", name));
                if scenarios.is_empty() {
                    return false;
                }
            }
        }
    }

    if let Some(props) = obj.get("properties").and_then(|v| v.as_object()) {
        for (prop_name, constraint) in props {
            let scenarios = model.resolve_scenarios_json(rid, &format!("Properties.{}", prop_name));
            if scenarios.is_empty() {
                return false;
            }
            let constraint_obj = match constraint.as_object() {
                Some(o) => o,
                None => continue,
            };
            let any_match = scenarios.iter().any(|(val, conds)| {
                if !is_satisfiable(model, conds) {
                    return false;
                }
                if let Some(not_schema) = constraint_obj.get("not").and_then(|v| v.as_object()) {
                    let inner_matches = match_constraint_value(not_schema, val);
                    return !inner_matches;
                }
                match_constraint_value(constraint_obj, val)
            });
            if !any_match {
                return false;
            }
        }
    }
    true
}

fn resolve_data_in_schema(
    schema: &serde_json::Value,
    context: &serde_json::Value,
) -> serde_json::Value {
    match schema {
        serde_json::Value::Object(obj) => {
            if let Some(lookup) = obj.get("$lookup").and_then(|v| v.as_object()) {
                let key = lookup
                    .get("key")
                    .map(|k| resolve_data_in_schema(k, context))
                    .and_then(|v| v.as_str().map(String::from));
                let map = lookup.get("map").and_then(|v| v.as_object());
                if let (Some(k), Some(m)) = (key, map) {
                    return m.get(&k).cloned().unwrap_or(serde_json::Value::Null);
                }
                return serde_json::Value::Null;
            }
            if let Some(pointer) = obj.get("$data").and_then(|v| v.as_str()) {
                return resolve_json_pointer(context, pointer);
            }
            let mut result = serde_json::Map::new();
            for (k, v) in obj {
                result.insert(k.clone(), resolve_data_in_schema(v, context));
            }
            serde_json::Value::Object(result)
        }
        serde_json::Value::Array(arr) => serde_json::Value::Array(
            arr.iter()
                .map(|v| resolve_data_in_schema(v, context))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn resolve_json_pointer(root: &serde_json::Value, pointer: &str) -> serde_json::Value {
    let parts: Vec<&str> = pointer.trim_start_matches('/').split('/').collect();
    let mut current = root;
    for part in &parts {
        if part.is_empty() {
            continue;
        }
        current = match current {
            serde_json::Value::Object(m) => match m.get(*part) {
                Some(v) => v,
                None => return serde_json::Value::Null,
            },
            serde_json::Value::Array(a) => match part.parse::<usize>() {
                Ok(idx) => match a.get(idx) {
                    Some(v) => v,
                    None => return serde_json::Value::Null,
                },
                Err(_) => return serde_json::Value::Null,
            },
            _ => return serde_json::Value::Null,
        };
    }
    current.clone()
}

fn evaluate_gather_schema(
    out: &mut Vec<Diagnostic>,
    model: &Arc<SemanticModel>,
    rid: &str,
    _res: &ResolvedResource,
    schema: &serde_json::Value,
    context: &serde_json::Value,
) {
    let Some(obj) = schema.as_object() else {
        return;
    };
    let if_schema = obj.get("if");
    let then_schema = obj.get("then");
    let else_schema = obj.get("else");

    if let Some(if_val) = if_schema {
        let matches = gather_condition_matches(if_val, context);
        let branch = if matches { then_schema } else { else_schema };
        if let Some(branch_val) = branch {
            evaluate_gather_constraints(out, model, rid, branch_val, context);
        }
    }
}

fn gather_condition_matches(condition: &serde_json::Value, context: &serde_json::Value) -> bool {
    let Some(obj) = condition.as_object() else {
        return false;
    };

    if let Some(required) = obj.get("required").and_then(|v| v.as_array()) {
        for req in required {
            if let Some(name) = req.as_str() {
                let val = resolve_json_pointer(context, &format!("/{}", name));
                if val.is_null() {
                    return false;
                }
            }
        }
    }

    if let Some(props) = obj.get("properties").and_then(|v| v.as_object()) {
        for (prop_name, constraint) in props {
            let actual = resolve_json_pointer(context, &format!("/{}", prop_name));
            if actual.is_null() {
                return false;
            }
            if !gather_prop_matches(&actual, constraint) {
                return false;
            }
        }
    }
    true
}

fn gather_prop_matches(actual: &serde_json::Value, constraint: &serde_json::Value) -> bool {
    let Some(obj) = constraint.as_object() else {
        return true;
    };

    if let Some(props) = obj.get("properties").and_then(|v| v.as_object()) {
        for (k, v) in props {
            let child = match actual.get(k) {
                Some(c) => c,
                None => return false,
            };
            if !gather_prop_matches(child, v) {
                return false;
            }
        }
    }
    if let Some(required) = obj.get("required").and_then(|v| v.as_array()) {
        for req in required {
            if let Some(name) = req.as_str()
                && actual.get(name).is_none()
            {
                return false;
            }
        }
    }
    if let Some(cv) = obj.get("const") {
        return actual == cv || cfn_coerce_to_string(actual) == cfn_coerce_to_string(cv);
    }
    if let Some(enum_vals) = obj.get("enum").and_then(|v| v.as_array()) {
        return enum_vals.iter().any(|e| e == actual);
    }
    true
}

fn evaluate_gather_constraints(
    out: &mut Vec<Diagnostic>,
    model: &Arc<SemanticModel>,
    rid: &str,
    schema: &serde_json::Value,
    context: &serde_json::Value,
) {
    let Some(obj) = schema.as_object() else {
        return;
    };
    if let Some(props) = obj.get("properties").and_then(|v| v.as_object()) {
        for (slot_name, slot_constraints) in props {
            let slot_val = resolve_json_pointer(context, &format!("/{}", slot_name));
            check_gather_property_constraints(
                out,
                model,
                rid,
                slot_name,
                &slot_val,
                slot_constraints,
            );
        }
    }
}

fn check_gather_property_constraints(
    out: &mut Vec<Diagnostic>,
    model: &Arc<SemanticModel>,
    rid: &str,
    slot_name: &str,
    actual: &serde_json::Value,
    constraint: &serde_json::Value,
) {
    let Some(obj) = constraint.as_object() else {
        return;
    };
    if let Some(props) = obj.get("properties").and_then(|v| v.as_object()) {
        for (prop_name, prop_constraint) in props {
            let prop_val = actual.get(prop_name).unwrap_or(&serde_json::Value::Null);
            let pc = match prop_constraint.as_object() {
                Some(o) => o,
                None => continue,
            };
            if let Some(cv) = pc.get("const")
                && !cv.is_null()
                && prop_val != cv
                && cfn_coerce_to_string(prop_val) != cfn_coerce_to_string(cv)
            {
                out.push(build_diagnostic(
                        "E3030",
                        Severity::Fatal,
                        &format!(
                            "Cross-resource constraint: {}.{} is {} but must be {} (from referenced resource)",
                            slot_name, prop_name, format_value(prop_val), format_value(cv)
                        ),
                        model, rid, "Properties", None,
                    ));
            }
            if let Some(min_val) = pc.get("minimum").and_then(cfn_coerce_to_number)
                && let Some(actual_num) = cfn_coerce_to_number(prop_val)
                && actual_num < min_val
            {
                out.push(build_diagnostic(
                            "F3034",
                            Severity::Fatal,
                            &format!(
                                "Cross-resource constraint: {}.{} is {} but must be >= {} (from referenced resource)",
                                slot_name, prop_name, actual_num, min_val
                            ),
                            model, rid, "Properties", None,
                        ));
            }
            if let Some(max_val) = pc.get("maximum").and_then(cfn_coerce_to_number)
                && let Some(actual_num) = cfn_coerce_to_number(prop_val)
                && actual_num > max_val
            {
                out.push(build_diagnostic(
                            "F3034",
                            Severity::Fatal,
                            &format!(
                                "Cross-resource constraint: {}.{} is {} but must be <= {} (from referenced resource)",
                                slot_name, prop_name, actual_num, max_val
                            ),
                            model, rid, "Properties", None,
                        ));
            }
        }
    }
}

fn describe_resolution(m: &Arc<SemanticModel>, rid: &str, prop_path: &str) -> Option<String> {
    let val = m.resolve(rid, prop_path).or_else(|| {
        let stripped = prop_path.strip_prefix("Properties.")?;
        let top = stripped.split('.').next()?;
        m.resources.get(rid)?.properties.get(top)
    })?;
    match val {
        ResolvedValue::Reference { target, kind } => {
            let kind_str = match kind {
                RefKind::Ref => "Ref",
                RefKind::GetAtt { attr: a } => {
                    return Some(format!("GetAtt {}.{}", target, a));
                }
                RefKind::Sub { var: _ } => "Sub",
                RefKind::DependsOn => return None,
            };
            Some(format!("{} to '{}'", kind_str, target))
        }
        ResolvedValue::Enum { variants: _ } => Some("parameter with AllowedValues".into()),
        ResolvedValue::Conditional {
            condition: cond,
            if_true: _,
            if_false: _,
        } => Some(format!("Fn::If on condition '{}'", cond)),
        ResolvedValue::Dynamic { reason: desc } => Some(format!("dynamic ({})", desc)),
        ResolvedValue::TypedDynamic {
            reason: name,
            param_type: typ,
        } => Some(format!("parameter '{}' (type {})", name, typ)),
        _ => None,
    }
}

fn build_diagnostic(
    rule_id: &str,
    severity: Severity,
    msg: &str,
    m: &Arc<SemanticModel>,
    rid: &str,
    prop: &str,
    fix: Option<&str>,
) -> Diagnostic {
    build_diagnostic_conditional(rule_id, severity, msg, m, rid, prop, fix, None)
}

fn build_diagnostic_conditional(
    rule_id: &str,
    severity: Severity,
    msg: &str,
    m: &Arc<SemanticModel>,
    rid: &str,
    prop: &str,
    fix: Option<&str>,
    conds: Option<HashMap<String, bool>>,
) -> Diagnostic {
    let span = if rid.is_empty() {
        diagnostics::resolve_section_span(rule_id, m.as_ref())
    } else {
        m.resource_span(rid, prop)
    };
    let property_path = if prop.is_empty() {
        None
    } else {
        Some(prop.into())
    };
    Diagnostic {
        rule_id: rule_id.into(),
        severity,
        message: msg.into(),
        resource: Some(diagnostics::ResourceRef {
            id: Some(rid.into()),
            resource_type: m.resources.get(rid).map(|r| r.resource_type.clone()),
        }),
        property_path,
        suggested_fix: fix.map(|s| s.into()),
        documentation_url: None,
        category: Some(rules::Category::Schema.as_str().into()),
        location: Some(diagnostics::SourceSpan {
            start_line: span.start_line,
            start_column: span.start_column,
            end_line: span.end_line,
            end_column: span.end_column,
        }),
        related_resources: None,
        condition_scenario: conds,
        rule_description: None,
        phase: Some(diagnostics::Phase::Schema),
        section: None,
        context: None,
        source: diagnostics::source_for_rule(rule_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn levenshtein_distance_identical_strings() {
        assert_eq!(levenshtein_distance("abc", "abc"), 0);
    }

    #[test]
    fn levenshtein_distance_empty_strings() {
        assert_eq!(levenshtein_distance("", ""), 0);
    }

    #[test]
    fn levenshtein_distance_one_empty() {
        assert_eq!(levenshtein_distance("abc", ""), 3);
        assert_eq!(levenshtein_distance("", "xyz"), 3);
    }

    #[test]
    fn levenshtein_distance_single_substitution() {
        assert_eq!(levenshtein_distance("cat", "bat"), 1);
    }

    #[test]
    fn levenshtein_distance_single_insertion() {
        assert_eq!(levenshtein_distance("abc", "abcd"), 1);
    }

    #[test]
    fn levenshtein_distance_single_deletion() {
        assert_eq!(levenshtein_distance("abcd", "abc"), 1);
    }

    #[test]
    fn levenshtein_distance_transposition() {
        assert_eq!(levenshtein_distance("ab", "ba"), 2);
    }

    #[test]
    fn levenshtein_distance_completely_different() {
        assert_eq!(levenshtein_distance("abc", "xyz"), 3);
    }

    #[test]
    fn find_similar_exact_match() {
        let known: HashSet<&str> = ["BucketName", "AccessControl"].into_iter().collect();
        assert_eq!(find_similar("BucketName", &known), Some("BucketName"));
    }

    #[test]
    fn find_similar_close_typo() {
        let known: HashSet<&str> = ["BucketName", "AccessControl"].into_iter().collect();
        let result = find_similar("Bucketame", &known);
        assert_eq!(result, Some("BucketName"));
    }

    #[test]
    fn find_similar_no_match() {
        let known: HashSet<&str> = ["BucketName", "AccessControl"].into_iter().collect();
        assert_eq!(
            find_similar("CompletelyDifferent", &known),
            None,
            "dissimilar name should not match"
        );
    }

    #[test]
    fn find_similar_case_insensitive() {
        let known: HashSet<&str> = ["BucketName"].into_iter().collect();
        assert_eq!(find_similar("bucketname", &known), Some("BucketName"));
    }

    #[test]
    fn type_matches_string() {
        assert!(type_matches(
            &json!("hello"),
            &PropType::Single("string".into())
        ));
        assert!(!type_matches(
            &json!(42),
            &PropType::Single("string".into())
        ));
    }

    #[test]
    fn type_matches_integer() {
        assert!(type_matches(
            &json!(42),
            &PropType::Single("integer".into())
        ));
        assert!(type_matches(
            &json!(42.0),
            &PropType::Single("integer".into())
        ));
        assert!(!type_matches(
            &json!(42.5),
            &PropType::Single("integer".into())
        ));
        assert!(!type_matches(
            &json!("42"),
            &PropType::Single("integer".into())
        ));
    }

    #[test]
    fn type_matches_number() {
        assert!(type_matches(&json!(42), &PropType::Single("number".into())));
        assert!(type_matches(
            &json!(3.14),
            &PropType::Single("number".into())
        ));
        assert!(!type_matches(
            &json!("3.14"),
            &PropType::Single("number".into())
        ));
    }

    #[test]
    fn type_matches_boolean() {
        assert!(type_matches(
            &json!(true),
            &PropType::Single("boolean".into())
        ));
        assert!(!type_matches(
            &json!("true"),
            &PropType::Single("boolean".into())
        ));
    }

    #[test]
    fn type_matches_array() {
        assert!(type_matches(
            &json!([1, 2]),
            &PropType::Single("array".into())
        ));
        assert!(!type_matches(
            &json!("[]"),
            &PropType::Single("array".into())
        ));
    }

    #[test]
    fn type_matches_object() {
        assert!(type_matches(
            &json!({"a": 1}),
            &PropType::Single("object".into())
        ));
        assert!(!type_matches(
            &json!("{}"),
            &PropType::Single("object".into())
        ));
    }

    #[test]
    fn type_matches_null() {
        assert!(type_matches(&json!(null), &PropType::Single("null".into())));
        assert!(!type_matches(
            &json!("null"),
            &PropType::Single("null".into())
        ));
    }

    #[test]
    fn type_matches_multi_with_null() {
        let pt = PropType::Multi(vec!["string".into(), "null".into()]);
        assert!(type_matches(&json!("hello"), &pt));
        assert!(type_matches(&json!(null), &pt));
        assert!(!type_matches(&json!(42), &pt));
    }

    #[test]
    fn type_matches_unknown_type_always_true() {
        assert!(type_matches(
            &json!("anything"),
            &PropType::Single("custom_type".into())
        ));
    }

    #[test]
    fn enum_matches_exact() {
        assert!(enum_matches(&json!("a"), &[json!("a"), json!("b")]));
        assert!(!enum_matches(&json!("c"), &[json!("a"), json!("b")]));
    }

    #[test]
    fn enum_matches_coerced_number_to_string() {
        assert!(enum_matches(&json!("42"), &[json!(42)]));
    }

    #[test]
    fn enum_matches_empty_allowed() {
        assert!(!enum_matches(&json!("a"), &[]));
    }

    #[test]
    fn format_value_wraps_strings_in_quotes() {
        assert_eq!(format_value(&json!("hello")), "'hello'");
    }

    #[test]
    fn format_value_renders_non_strings_directly() {
        assert_eq!(format_value(&json!(42)), "42");
        assert_eq!(format_value(&json!(true)), "true");
        assert_eq!(format_value(&json!(null)), "null");
    }

    #[test]
    fn single_type_compatible_same_type() {
        assert!(single_type_compatible("string", "string"));
        assert!(single_type_compatible("integer", "integer"));
    }

    #[test]
    fn single_type_compatible_integer_number_interchangeable() {
        assert!(single_type_compatible("integer", "number"));
        assert!(single_type_compatible("number", "integer"));
    }

    #[test]
    fn single_type_compatible_string_to_number_coercion() {
        assert!(single_type_compatible("string", "number"));
        assert!(single_type_compatible("string", "integer"));
    }

    #[test]
    fn single_type_compatible_number_to_string_coercion() {
        assert!(single_type_compatible("number", "string"));
        assert!(single_type_compatible("integer", "string"));
        assert!(single_type_compatible("boolean", "string"));
    }

    #[test]
    fn single_type_compatible_null_always_compatible() {
        assert!(single_type_compatible("string", "null"));
        assert!(single_type_compatible("array", "null"));
    }

    #[test]
    fn single_type_compatible_incompatible() {
        assert!(!single_type_compatible("string", "array"));
        assert!(!single_type_compatible("array", "object"));
        assert!(!single_type_compatible("boolean", "integer"));
    }

    #[test]
    fn param_type_number() {
        assert_eq!(cfn_param_type_to_schema_type("Number"), "number");
    }

    #[test]
    fn param_type_string() {
        assert_eq!(cfn_param_type_to_schema_type("String"), "string");
    }

    #[test]
    fn param_type_comma_delimited_list() {
        assert_eq!(cfn_param_type_to_schema_type("CommaDelimitedList"), "array");
    }

    #[test]
    fn param_type_list_prefix() {
        assert_eq!(cfn_param_type_to_schema_type("List<Number>"), "array");
        assert_eq!(
            cfn_param_type_to_schema_type("List<AWS::EC2::Subnet::Id>"),
            "array"
        );
    }

    #[test]
    fn param_type_ssm_parameter() {
        assert_eq!(
            cfn_param_type_to_schema_type("AWS::SSM::Parameter::Value<String>"),
            "string"
        );
    }

    #[test]
    fn param_type_unknown_defaults_to_string() {
        assert_eq!(cfn_param_type_to_schema_type("AWS::EC2::VPC::Id"), "string");
    }

    #[test]
    fn resolve_json_pointer_root() {
        let data = json!({"a": 1});
        let result = resolve_json_pointer(&data, "/");
        assert_eq!(result, json!({"a": 1}));
    }

    #[test]
    fn resolve_json_pointer_nested() {
        let data = json!({"a": {"b": {"c": 42}}});
        assert_eq!(resolve_json_pointer(&data, "/a/b/c"), json!(42));
    }

    #[test]
    fn resolve_json_pointer_missing_key() {
        let data = json!({"a": 1});
        assert_eq!(resolve_json_pointer(&data, "/b"), json!(null));
    }

    #[test]
    fn resolve_json_pointer_array_index() {
        let data = json!({"items": [10, 20, 30]});
        assert_eq!(resolve_json_pointer(&data, "/items/1"), json!(20));
    }

    #[test]
    fn resolve_json_pointer_array_out_of_bounds() {
        let data = json!({"items": [10]});
        assert_eq!(resolve_json_pointer(&data, "/items/5"), json!(null));
    }

    #[test]
    fn resolve_json_pointer_non_numeric_index_on_array() {
        let data = json!([1, 2, 3]);
        assert_eq!(resolve_json_pointer(&data, "/abc"), json!(null));
    }

    #[test]
    fn resolve_json_pointer_scalar_intermediate() {
        let data = json!({"a": "string_value"});
        assert_eq!(resolve_json_pointer(&data, "/a/b"), json!(null));
    }

    #[test]
    fn resolve_data_simple_reference() {
        let schema = json!({"$data": "/source/protocol"});
        let context = json!({"source": {"protocol": "tcp"}});
        assert_eq!(resolve_data_in_schema(&schema, &context), json!("tcp"));
    }

    #[test]
    fn resolve_data_missing_reference() {
        let schema = json!({"$data": "/missing/path"});
        let context = json!({"source": {"protocol": "tcp"}});
        assert_eq!(resolve_data_in_schema(&schema, &context), json!(null));
    }

    #[test]
    fn resolve_data_nested_object() {
        let schema = json!({
            "properties": {
                "port": {"const": {"$data": "/source/port"}}
            }
        });
        let context = json!({"source": {"port": 443}});
        let resolved = resolve_data_in_schema(&schema, &context);
        assert_eq!(resolved["properties"]["port"]["const"], json!(443));
    }

    #[test]
    fn resolve_data_array() {
        let schema = json!([{"$data": "/a"}, {"$data": "/b"}]);
        let context = json!({"a": 1, "b": 2});
        assert_eq!(resolve_data_in_schema(&schema, &context), json!([1, 2]));
    }

    #[test]
    fn resolve_data_non_object_passthrough() {
        assert_eq!(
            resolve_data_in_schema(&json!("plain"), &json!({})),
            json!("plain")
        );
        assert_eq!(resolve_data_in_schema(&json!(42), &json!({})), json!(42));
        assert_eq!(
            resolve_data_in_schema(&json!(null), &json!({})),
            json!(null)
        );
    }

    #[test]
    fn resolve_data_lookup() {
        let schema = json!({
            "$lookup": {
                "key": {"$data": "/source/engine"},
                "map": {
                    "aurora": {"const": 3306},
                    "redis": {"const": 6379}
                }
            }
        });
        let context = json!({"source": {"engine": "aurora"}});
        assert_eq!(
            resolve_data_in_schema(&schema, &context),
            json!({"const": 3306})
        );
    }

    #[test]
    fn resolve_data_lookup_missing_key() {
        let schema = json!({
            "$lookup": {
                "key": {"$data": "/source/engine"},
                "map": {"aurora": 3306}
            }
        });
        let context = json!({"source": {"engine": "postgres"}});
        assert_eq!(resolve_data_in_schema(&schema, &context), json!(null));
    }

    #[test]
    fn types_compatible_single() {
        assert!(types_compatible(
            "string",
            &PropType::Single("string".into())
        ));
        assert!(!types_compatible(
            "array",
            &PropType::Single("string".into())
        ));
    }

    #[test]
    fn types_compatible_multi() {
        let pt = PropType::Multi(vec!["string".into(), "null".into()]);
        assert!(types_compatible("string", &pt));
        assert!(types_compatible("integer", &pt));
        assert!(!types_compatible(
            "array",
            &PropType::Multi(vec!["string".into(), "integer".into()])
        ));
    }

    #[test]
    fn single_type_double_and_float_are_number() {
        assert!(single_type(&json!(3.14), "double"));
        assert!(single_type(&json!(3.14), "float"));
        assert!(single_type(&json!(42), "double"));
    }

    #[test]
    fn single_type_integer_rejects_fractional() {
        assert!(!single_type(&json!(3.14), "integer"));
    }

    #[test]
    fn single_type_integer_accepts_whole_float() {
        assert!(single_type(&json!(5.0), "integer"));
    }

    #[test]
    fn find_prop_schema_direct_lookup() {
        let mut props = HashMap::new();
        props.insert(
            "Name".into(),
            PropSchema {
                prop_type: Some(PropType::Single("string".into())),
                ..Default::default()
            },
        );
        let defs = HashMap::new();
        let result = find_prop_schema("Name", &props, &defs).expect("Name should be found");
        assert_eq!(result.prop_type.as_ref().unwrap().primary(), Some("string"));
    }

    #[test]
    fn find_prop_schema_nested_path() {
        let inner = PropSchema {
            prop_type: Some(PropType::Single("integer".into())),
            ..Default::default()
        };
        let mut inner_props = HashMap::new();
        inner_props.insert("Port".into(), inner);
        let outer = PropSchema {
            properties: inner_props,
            ..Default::default()
        };
        let mut props = HashMap::new();
        props.insert("Config".into(), outer);
        let defs = HashMap::new();
        let result =
            find_prop_schema("Config.Port", &props, &defs).expect("Config.Port should be found");
        assert_eq!(
            result.prop_type.as_ref().unwrap().primary(),
            Some("integer")
        );
    }

    #[test]
    fn find_prop_schema_missing_returns_none() {
        let props = HashMap::new();
        let defs = HashMap::new();
        assert!(
            find_prop_schema("Missing", &props, &defs).is_none(),
            "missing prop should return None"
        );
    }

    #[test]
    fn find_prop_schema_resolves_ref() {
        let mut props = HashMap::new();
        props.insert(
            "Config".into(),
            PropSchema {
                ref_name: Some("ConfigDef".into()),
                ..Default::default()
            },
        );
        let mut defs = HashMap::new();
        defs.insert(
            "ConfigDef".into(),
            PropSchema {
                prop_type: Some(PropType::Single("object".into())),
                ..Default::default()
            },
        );
        let result = find_prop_schema("Config", &props, &defs).expect("Config should be found");
        assert_eq!(result.prop_type.as_ref().unwrap().primary(), Some("object"));
    }

    #[test]
    fn find_prop_schema_deep_direct() {
        let mut props = HashMap::new();
        props.insert(
            "Name".into(),
            PropSchema {
                prop_type: Some(PropType::Single("string".into())),
                ..Default::default()
            },
        );
        let schema = CompiledSchema {
            type_name: "Test".into(),
            properties: props,
            ..Default::default()
        };
        assert!(
            find_prop_schema_deep("Name", &schema).is_some(),
            "direct property should be found"
        );
    }

    #[test]
    fn find_prop_schema_deep_searches_one_of() {
        let mut sub_props = HashMap::new();
        sub_props.insert(
            "Special".into(),
            PropSchema {
                prop_type: Some(PropType::Single("boolean".into())),
                ..Default::default()
            },
        );
        let schema = CompiledSchema {
            type_name: "Test".into(),
            one_of: vec![crate::compiled::SubSchema {
                properties: sub_props,
                ..Default::default()
            }],
            ..Default::default()
        };
        let result = find_prop_schema_deep("Special", &schema);
        assert!(
            result.is_some(),
            "expected to find Special in oneOf sub-schema"
        );
        assert_eq!(
            result.unwrap().prop_type.as_ref().unwrap().primary(),
            Some("boolean")
        );
    }

    #[test]
    fn find_prop_schema_deep_searches_if_then_else() {
        let mut then_props = HashMap::new();
        then_props.insert(
            "ConditionalProp".into(),
            PropSchema {
                prop_type: Some(PropType::Single("string".into())),
                ..Default::default()
            },
        );
        let schema = CompiledSchema {
            type_name: "Test".into(),
            if_then_else: vec![crate::compiled::IfThenElse {
                condition: Default::default(),
                then_schema: Some(crate::compiled::SubSchema {
                    properties: then_props,
                    ..Default::default()
                }),
                else_schema: None,
            }],
            ..Default::default()
        };
        assert!(
            find_prop_schema_deep("ConditionalProp", &schema).is_some(),
            "conditional property should be found via if-then-else"
        );
    }

    #[test]
    fn condition_matches_empty_condition_always_true() {
        let cond = ConditionSchema::default();
        let keys = vec!["A".into(), "B".into()];
        let model = Arc::new(SemanticModel::from_bytes(
            b"AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  R:\n    Type: AWS::CloudFormation::WaitConditionHandle"
        ).unwrap());
        let defs = HashMap::new();
        assert!(condition_matches(&cond, &keys, &model, "R", &defs));
    }

    #[test]
    fn condition_matches_required_key_missing() {
        let cond = ConditionSchema {
            required: vec!["MissingKey".into()],
            ..Default::default()
        };
        let keys = vec!["A".into()];
        let model = Arc::new(SemanticModel::from_bytes(
            b"AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  R:\n    Type: AWS::CloudFormation::WaitConditionHandle"
        ).unwrap());
        let defs = HashMap::new();
        assert!(!condition_matches(&cond, &keys, &model, "R", &defs));
    }

    #[test]
    fn gather_condition_matches_empty_true() {
        let cond = json!({});
        let ctx = json!({"a": 1});
        assert!(gather_condition_matches(&cond, &ctx));
    }

    #[test]
    fn gather_condition_matches_required_present() {
        let cond = json!({"required": ["a"]});
        let ctx = json!({"a": 1});
        assert!(gather_condition_matches(&cond, &ctx));
    }

    #[test]
    fn gather_condition_matches_required_missing() {
        let cond = json!({"required": ["b"]});
        let ctx = json!({"a": 1});
        assert!(!gather_condition_matches(&cond, &ctx));
    }

    #[test]
    fn gather_prop_matches_const() {
        assert!(gather_prop_matches(&json!("tcp"), &json!({"const": "tcp"})));
        assert!(!gather_prop_matches(
            &json!("udp"),
            &json!({"const": "tcp"})
        ));
    }

    #[test]
    fn gather_prop_matches_enum() {
        assert!(gather_prop_matches(
            &json!("a"),
            &json!({"enum": ["a", "b"]})
        ));
        assert!(!gather_prop_matches(
            &json!("c"),
            &json!({"enum": ["a", "b"]})
        ));
    }

    #[test]
    fn gather_prop_matches_nested_properties() {
        let actual = json!({"inner": {"key": "val"}});
        let constraint =
            json!({"properties": {"inner": {"properties": {"key": {"const": "val"}}}}});
        assert!(gather_prop_matches(&actual, &constraint));
    }
}
