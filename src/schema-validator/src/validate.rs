use crate::compiled::{CompiledSchema, ConditionSchema, PropSchema, PropType, SubSchema};
use crate::store::CompiledSchemaStore;
use diagnostics::message::{render_str_list, render_value, render_value_list};
use diagnostics::{Diagnostic, Phase, RegisteredDiagnostic, ViolationContext, resolve_section_span};
use rules::{
    CompiledPattern, IAM_ROLE_ARN_PATTERN, SECURITY_GROUP_NAME_PATTERN, compile_pattern, format_rule_for_format,
};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};
use template_model::SemanticModel;
use template_model::coercion::{CoerceResult, coerce_to_number, coerce_to_string, coerce_value, scalar_eq};
use template_model::consts::{
    FN_CONDITION, FN_FOR_EACH_KEY_PREFIX, FN_IF, FN_REF, INTRINSIC_FN_PATH_SEGMENTS, KEY_PROPERTIES, KEY_TYPE,
    PARAM_TYPE_COMMA_DELIMITED_LIST, PARAM_TYPE_NUMBER, PARAM_TYPE_STRING, SAM_FUNCTION_TYPE,
    SAM_SERVERLESS_TYPE_PREFIX,
};
use template_model::model::ResolvedResource;
use template_model::region_enums;
use template_model::resolver::{RefKind, ResolvedValue};

/// Properties that accept a string value when used with `aws cloudformation package`.
/// Type checks are skipped for these paths when the value is a string.
const PACKAGING_PROPERTY_PATHS: &[(&str, &str)] = &[
    ("AWS::Lambda::Function", "Properties.Code"),
    ("AWS::Lambda::LayerVersion", "Properties.Content"),
    ("AWS::ApiGateway::RestApi", "Properties.BodyS3Location"),
    ("AWS::ElasticBeanstalk::ApplicationVersion", "Properties.SourceBundle"),
    ("AWS::StepFunctions::StateMachine", "Properties.DefinitionS3Location"),
    ("AWS::AppSync::GraphQLSchema", "Properties.DefinitionS3Location"),
    ("AWS::AppSync::Resolver", "Properties.RequestMappingTemplateS3Location"),
    ("AWS::AppSync::Resolver", "Properties.ResponseMappingTemplateS3Location"),
    ("AWS::AppSync::FunctionConfiguration", "Properties.RequestMappingTemplateS3Location"),
    ("AWS::AppSync::FunctionConfiguration", "Properties.ResponseMappingTemplateS3Location"),
    ("AWS::CloudFormation::Stack", "Properties.TemplateURL"),
    ("AWS::CodeCommit::Repository", "Properties.Code.S3"),
];

/// Property paths where type validation is skipped entirely because
/// the property accepts free-form user-defined content.
const TYPE_CHECK_EXEMPT_PATHS: &[(&str, &str)] = &[
    ("AWS::Lambda::Function", "Properties.Environment.Variables"),
    ("AWS::Lambda::Function", "Properties.Environment"),
];

/// Returns true if the value is an unresolved or malformed intrinsic function:
/// a JSON object with a single *known* function key (`Fn::<name>`, `Ref`,
/// `Condition`, or an `Fn::ForEach::` loop key). Only known names are skipped —
/// a single-key object whose key merely starts with `Fn::` (e.g. a map entry
/// literally named `Fn::Custom`) is plain data and must be schema-validated
/// like any other object.
fn is_unresolved_intrinsic(val: &serde_json::Value) -> bool {
    let Some(obj) = val.as_object() else { return false };
    if obj.len() != 1 {
        return false;
    }
    let key = obj.keys().next().unwrap();
    INTRINSIC_FN_PATH_SEGMENTS.contains(&key.as_str())
        || key == FN_REF
        || key == FN_CONDITION
        || key.starts_with(FN_FOR_EACH_KEY_PREFIX)
}

pub fn validate_all_resources(
    store: &CompiledSchemaStore,
    model: &Arc<SemanticModel>,
    region: Option<&str>,
) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let relevant: HashSet<&str> = model.resources.values().map(|r| r.resource_type.as_str()).collect();

    validate_lifecycle(&mut out, store, model);

    for rtype in &relevant {
        // Custom resources, modules, and SAM resources (rewritten by the SAM
        // transform before deployment) are not region-scoped provider types, so
        // the region check skips them — CloudFormation validates the
        // post-transform template.
        if rtype.ends_with("::MODULE") || rtype.starts_with("Custom::") || rtype.starts_with(SAM_SERVERLESS_TYPE_PREFIX)
        {
            continue;
        }

        // Only flag a genuine regional provider type that is absent in the target
        // region. A type that appears in no region's map at all (e.g. an empty or
        // transform-generated placeholder type) is not a region-availability
        // problem and must not be reported here, or good templates regress. With
        // no region configured the type is validated against the union of all
        // regions: available if it exists in any region, so a type known in some
        // region is never flagged — the availability check only runs for a
        // configured region.
        if let Some(region) = region
            && store.is_known_in_any_region(rtype)
            && !store.is_available_in_region(rtype, region)
        {
            for rid in model.resources_of_type(rtype) {
                // A resource guarded by a Condition that cannot hold in the target
                // region is never created there, so its type's absence in that
                // region is not an error. The satisfiability check pins
                // AWS::Region to the target region and asks whether the condition
                // can hold there, so a condition like
                // `!Equals [AWS::Region, us-east-1]` is unsatisfiable at any other
                // region and the finding is skipped — even at the DEFAULT region,
                // where AWS::Region is otherwise a free SAT variable.
                if let Some(res) = model.resources.get(rid.as_str())
                    && let Some(cond) = res.condition.as_deref()
                    && !model.conditions.is_satisfiable_in_region(&[(cond.to_string(), true)], region)
                {
                    continue;
                }
                // Report the region-availability message at the Type node
                // (a Fatal F3006 here).
                out.push(build_diagnostic(
                    "F3006",
                    &format!("Resource type '{}' does not exist in '{}'", rtype, region),
                    model,
                    rid,
                    KEY_TYPE,
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
            // A structurally invalid logical ID (non-alphanumeric) is itself a
            // template error; CloudFormation rejects the resource outright before
            // its properties matter, so skip all property-level validation here to
            // avoid surfacing property diagnostics (e.g. format checks) for a
            // resource that cannot be created.
            if !is_valid_logical_id(rid) {
                continue;
            }
            // AWS::Serverless::* resources are rewritten by the SAM transform
            // before deployment, so their authored form does not have to satisfy
            // the raw resource schema (required properties, etc. are supplied or
            // relaxed during expansion). Validating the pre-transform shape would
            // flag requirements the transform fills in.
            if rtype.starts_with(SAM_SERVERLESS_TYPE_PREFIX) {
                continue;
            }
            validate_resource(&mut out, store, model, rid, res, schema, region);
            validate_extensions(&mut out, store, model, rid, res);
        }
    }
    out
}

/// CloudFormation logical IDs must be alphanumeric (`[A-Za-z0-9]+`). A resource
/// whose ID violates this is rejected outright, so property-level schema checks
/// against it would be noise.
fn is_valid_logical_id(rid: &str) -> bool {
    !rid.is_empty() && rid.bytes().all(|b| b.is_ascii_alphanumeric())
}

pub fn enrich_schema_context(diagnostics: &mut [Diagnostic], store: &CompiledSchemaStore, model: &Arc<SemanticModel>) {
    for d in diagnostics.iter_mut() {
        if d.phase != Some(Phase::Schema) {
            continue;
        }
        let Some(rid) = d.resource_logical_id().map(String::from) else {
            continue;
        };
        let Some(res) = model.resources.get(rid.as_str()) else {
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

        if let Some(source) = describe_resolution(model, &rid, d.property_path.as_deref().unwrap_or("")) {
            let ctx = d.context.get_or_insert_with(|| ViolationContext {
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
                $d.context.get_or_insert_with(|| ViolationContext {
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
                    ensure_ctx!(d).expected_constraint = Some(pt.primary().unwrap_or("unknown").to_string());
                }
            }
            "F3030" | "W3030" => {
                if let Some(ps) = prop_schema
                    && !ps.enum_values.is_empty()
                {
                    ensure_ctx!(d)
                        .extra
                        .get_or_insert_with(HashMap::new)
                        .insert("allowed_values".into(), serde_json::json!(ps.enum_values).into());
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
                    .insert("allowed_properties".into(), serde_json::json!(allowed).into());
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
            "W9054" => {
                ensure_ctx!(d).lifecycle = Some("write-only".into());
            }
            _ => {}
        }
    }
}

pub fn enrich_schema_context_standalone(diagnostics: &mut [Diagnostic], model: &Arc<SemanticModel>) {
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
        if compile_pattern(pat).is_some_and(|re| re.is_match(top)) {
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
    for sub in schema.one_of.iter().chain(schema.any_of.iter()).chain(schema.all_of.iter()) {
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

/// Resolves a schema lifecycle pointer (a dotted property path such as
/// `Source.Decryption.Url`, where `*` denotes an array element) against the
/// resource's resolved properties, returning the pointer when that leaf is
/// actually set in the template and `None` otherwise.
///
/// Lifecycle pointer lists frequently address a nested sub-property while the
/// top-level parent is a required, non-deprecated block; keying only off the
/// parent's presence would flag correct templates. The array-wildcard token is
/// translated to the resolver's `{}` form so a deprecated leaf inside any array
/// element is detected.
fn present_lifecycle_pointer(m: &Arc<SemanticModel>, rid: &str, base: &str, pointer: &str) -> Option<String> {
    let resolver_path = pointer.replace(".*.", ".{}.");
    m.resolve_deep(rid, &format!("{}.{}", base, resolver_path)).map(|_| pointer.to_string())
}

fn validate_resource(
    out: &mut Vec<Diagnostic>,
    store: &CompiledSchemaStore,
    m: &Arc<SemanticModel>,
    rid: &str,
    res: &ResolvedResource,
    schema: &CompiledSchema,
    region: Option<&str>,
) {
    let base = KEY_PROPERTIES;
    let defs = &schema.definitions;

    // Lifecycle pointers (deprecated/create-only/write-only) address a specific
    // property, which for many resources is a nested sub-property (e.g. MediaConnect
    // Flow deprecates only `Source.Decryption.Url`, never the required `Source`
    // itself). Matching on the leaf's actual presence — not merely the top-level
    // parent's — is required to avoid flagging correct templates.
    for dp in &schema.deprecated_properties {
        if let Some(pointer) = present_lifecycle_pointer(m, rid, base, dp) {
            out.push(build_diagnostic(
                "W9009",
                &format!("Property '{}' is deprecated", pointer),
                m,
                rid,
                &format!("{}.{}", base, pointer),
                None,
            ));
        }
    }

    for cp in &schema.create_only_properties {
        if let Some(pointer) = present_lifecycle_pointer(m, rid, base, cp) {
            out.push(build_diagnostic(
                "I9001",
                &format!("Property '{}' is create-only; updating it will cause resource replacement", pointer),
                m,
                rid,
                &format!("{}.{}", base, pointer),
                None,
            ));
        }
    }

    for wo in &schema.write_only_properties {
        for edge in m.graph.incoming(rid) {
            if let RefKind::GetAtt { attr } = &edge.kind
                && attr == wo
                && edge.source_resource.starts_with("__output__")
            {
                let output_name = edge.source_resource.strip_prefix("__output__").unwrap_or(&edge.source_resource);
                out.push(build_diagnostic(
                    "W9054",
                    &format!("Write-only property '{}' of '{}' is referenced in output '{}'", wo, rid, output_name),
                    m,
                    rid,
                    &format!("{}.{}", base, wo),
                    None,
                ));
            }
        }
    }

    // When the whole Properties block is a deploy-time intrinsic (e.g.
    // `Properties: !Ref AWS::NoValue`), the resolved view is empty and every
    // required property would look missing. The effective properties are not
    // known statically, so skip the key/required-property checks.
    let key_scenarios = if res.properties_dynamic { Vec::new() } else { resource_property_key_scenarios(m, rid, res) };
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
        validate_prop(out, store, m, rid, &res.resource_type, &prop_path, resolved, defs, &mut HashSet::new(), region);
    }

    // Also validate properties that exist only inside conditional branches —
    // when Properties is wrapped in Fn::If, res.properties has only the
    // synthetic "Fn::If" key so the loop above would miss per-branch props.
    let branch_property_names: HashSet<String> =
        key_scenarios.iter().flat_map(|(keys, _)| keys.iter().cloned()).collect();
    for prop_name in &branch_property_names {
        if res.properties.contains_key(prop_name) {
            continue;
        }
        let Some(prop_schema) = schema.properties.get(prop_name) else {
            continue;
        };
        let resolved = prop_schema.resolve(defs);
        let prop_path = format!("{}.{}", base, prop_name);
        validate_prop(out, store, m, rid, &res.resource_type, &prop_path, resolved, defs, &mut HashSet::new(), region);
    }

    let actual_keys: Vec<String> = res.properties.keys().cloned().collect();
    for ite in &schema.if_then_else {
        let matches = condition_matches(&ite.condition, &actual_keys, m, rid, defs);
        let sub = if matches { &ite.then_schema } else { &ite.else_schema };
        if let Some(sub) = sub {
            validate_sub_dependencies(out, m, rid, &actual_keys, sub, base);
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
                &format!("'{}' is a required property", req),
                m,
                rid,
                base_path,
                Some(&format!("Add the required property '{}'", req)),
            ));
        } else if base_path == KEY_PROPERTIES {
            check_required_not_null(out, m, rid, base_path, req);
        }
    }

    if additional_properties == Some(false)
        && !rtype.starts_with("Custom::")
        && rtype != "AWS::CloudFormation::CustomResource"
    {
        let known: HashSet<&str> = schema_props.keys().map(|s| s.as_str()).collect();

        let pattern_matchers: Vec<Option<std::sync::Arc<CompiledPattern>>> =
            pattern_props.keys().map(|p| compile_pattern(p)).collect();
        for key in actual_keys {
            if known.contains(key.as_str()) {
                continue;
            }
            let allowed_by_pattern =
                pattern_matchers.iter().any(|matcher| matcher.as_ref().is_none_or(|re| re.is_match(key)));
            if allowed_by_pattern {
                continue;
            }
            let suggestion = find_similar(key, &known);
            let msg = match suggestion {
                Some(s) => {
                    format!("Additional properties are not allowed ('{}' was unexpected. Did you mean '{}'?)", key, s)
                }
                None => format!("Additional properties are not allowed ('{}' was unexpected)", key),
            };
            out.push(build_diagnostic("F3002", &msg, m, rid, &format!("{}.{}", base_path, key), None));
        }
    }

    for (trigger, excluded) in dep_excl {
        if actual_keys.contains(trigger) {
            for dep in excluded {
                if actual_keys.contains(dep) {
                    out.push(build_diagnostic(
                        "F3020",
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
        let names = req_or.iter().map(|s| format!("'{}'", s)).collect::<Vec<_>>().join(", ");
        out.push(build_diagnostic(
            "F3058",
            &format!("One of [{}] is a required property", names),
            m,
            rid,
            base_path,
            None,
        ));
    }

    if !req_xor.is_empty() {
        // A property whose value resolves to `AWS::NoValue` (null) is removed by
        // CloudFormation at deploy time, so it does not count toward the
        // "exactly one" tally even though its key is present in the source. Count
        // only members that resolve to a concrete value in some satisfiable
        // scenario.
        let count =
            req_xor.iter().filter(|p| actual_keys.contains(p) && property_present(m, rid, base_path, p)).count();
        if count != 1 {
            let names = req_xor.iter().map(|s| format!("'{}'", s)).collect::<Vec<_>>().join(", ");
            out.push(build_diagnostic(
                "F3014",
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
            // Surface which property combinations would satisfy the schema, drawn
            // from each branch's required set, so the bare "not valid under any
            // schema" message is actionable. Branches with no required list (a
            // shape constraint rather than a required-property one) are omitted.
            let option_sets: Vec<String> = any_of
                .iter()
                .filter(|sub| !sub.required.is_empty())
                .map(|sub| {
                    let props = sub.required.iter().map(|p| format!("'{}'", p)).collect::<Vec<_>>().join(", ");
                    format!("[{}]", props)
                })
                .collect();
            let message = if option_sets.is_empty() {
                format!("Value is not valid under any of the given schemas for {}", rtype)
            } else {
                format!(
                    "Value is not valid under any of the given schemas for {rtype} - specify one of the following property sets: {}",
                    option_sets.join(" or ")
                )
            };
            out.push(build_diagnostic("F3017", &message, m, rid, base_path, None));
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
                "Value is not valid under any of the given schemas",
                m,
                rid,
                base_path,
                None,
            ));
        } else if valid_count > 1 {
            out.push(build_diagnostic(
                "F3018",
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
                &format!("'{}' is a required property", req),
                m,
                rid,
                base_path,
                Some(&format!("Add '{}'", req)),
            ));
        }
    }
    validate_sub_dependencies(out, m, rid, actual_keys, sub, base_path);
}

/// Validates the dependentRequired/dependentExcluded constraints of a subschema.
///
/// Split out from `validate_sub` so conditional (`if`/`then`) branches can still
/// enforce property co-dependencies without raising the unconditional structural
/// required check: a property that is required only when a sibling holds a
/// particular value is a semantic dependency, which dedicated resource-specific
/// rules own, not a Fatal structural violation.
fn validate_sub_dependencies(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    rid: &str,
    actual_keys: &[String],
    sub: &SubSchema,
    base_path: &str,
) {
    for (trigger, deps) in &sub.dependent_required {
        if actual_keys.contains(trigger) {
            for dep in deps {
                if !actual_keys.contains(dep) {
                    out.push(build_diagnostic(
                        "F3021",
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
    region: Option<&str>,
) {
    // Guard against circular $ref chains at validation time
    if let Some(ref rn) = schema.ref_name {
        if !visited.insert(rn.clone()) {
            return;
        }
        if let Some(resolved) = defs.get(rn) {
            validate_prop(out, store, m, rid, rtype, prop_path, resolved, defs, visited, region);
        }
        visited.remove(rn);
        return;
    }

    let scenarios = m.resolve_scenarios_json(rid, prop_path);

    let is_type_exempt = TYPE_CHECK_EXEMPT_PATHS.iter().any(|(rt, pp)| *rt == rtype && *pp == prop_path);

    if scenarios.is_empty() && !is_type_exempt {
        validate_reference_type(out, store, m, rid, prop_path, schema);
    }

    let res_suffix = describe_resolution(m, rid, prop_path).map(|s| format!(" (from {})", s)).unwrap_or_default();

    // Type check — coerce before rejecting since string↔number, string↔boolean,
    // bool→string, number→string are silently coerced at deploy time.
    // Successful coercion → Warn; failed coercion → Fatal.
    if let Some(ref pt) = schema.prop_type
        && !is_type_exempt
    {
        let is_packaging_path = PACKAGING_PROPERTY_PATHS.iter().any(|(rt, pp)| *rt == rtype && *pp == prop_path);
        // Skip type checks for array elements whose parent array or the element itself
        // came from an intrinsic function — those are validated by function-specific rules.
        let from_intrinsic = m.is_from_intrinsic(rid, prop_path)
            || prop_path
                .rsplit_once('.')
                .and_then(|(parent, seg)| seg.parse::<usize>().ok().map(|_| parent))
                .is_some_and(|parent| m.is_from_intrinsic(rid, parent));
        // A property whose value embeds an `Fn::If` expands into one scenario per
        // branch. When the value is the wrong type at the property level (e.g. a
        // list where an object is required), every branch fails the same check,
        // which would emit the same type diagnostic once per branch. Track the
        // (rule, expected-type) pairs already reported for this path so the
        // property-level mismatch is reported once, as a single observable error.
        let mut emitted_type_errors: HashSet<(&str, &str)> = HashSet::new();
        for (val, conds) in &scenarios {
            if !is_satisfiable(m, conds) || val.is_null() {
                continue;
            }
            // Skip unresolved/malformed intrinsics — already validated by structure rules
            if is_unresolved_intrinsic(val) {
                continue;
            }
            // Skip packaging properties when value is a string — valid with `package` command
            if is_packaging_path && val.is_string() {
                continue;
            }
            // Skip elements from intrinsic-resolved arrays
            if from_intrinsic {
                continue;
            }
            if !type_matches(val, pt) {
                let expected = pt.primary().unwrap_or("unknown");
                match coerce_value(val, expected) {
                    CoerceResult::Coerced(_, ref description) => {
                        if emitted_type_errors.insert(("W9003", expected)) {
                            out.push(build_diagnostic_conditional(
                                "W9003",
                                &format!(
                                    "{}{} is not of type '{}' - automatically coerced ({})",
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
                    }
                    _ => {
                        if emitted_type_errors.insert(("F3012", expected)) {
                            out.push(build_diagnostic_conditional(
                                "F3012",
                                &format!("{}{} is not of type '{}'", format_value(val), res_suffix, expected),
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
    }

    if !schema.enum_values.is_empty() {
        let prop_name = prop_path.strip_prefix("Properties.").unwrap_or(prop_path);
        // The regional allowed set for the effective scope: the configured region,
        // or the union of all regions when none is configured (so a value valid in
        // any region is accepted rather than only the platform default).
        let regional = store.region_enums().allowed_values(rtype, prop_name, region);
        for (val, conds) in &scenarios {
            if !is_satisfiable(m, conds) || val.is_null() {
                continue;
            }
            let matches = if let Some(regional_vals) = &regional {
                val.as_str().map(|s| regional_vals.contains(&s)).unwrap_or(false)
                    || enum_matches(val, &schema.enum_values)
            } else {
                enum_matches(val, &schema.enum_values)
            };
            if !matches {
                // Enum sets are snapshots of what a service accepts today; AWS adds
                // new values over time, so a value absent from the compiled schema may
                // still deploy successfully. Reporting this as a Warning (rather than a
                // guaranteed-failure Fatal) lets templates using a newer value proceed
                // and stay suppressible.
                let enum_desc = if regional.is_some() {
                    format!("allowed values for region '{}'", region_enums::region_label(region))
                } else {
                    format_allowed_values(&schema.enum_values)
                };
                out.push(build_diagnostic_conditional(
                    "W3030",
                    &format!("{}{} is not one of {}", format_value(val), res_suffix, enum_desc),
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
            if !scalar_eq(val, cv) {
                out.push(build_diagnostic_conditional(
                    "F3030",
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
        && let Some(re) = compile_pattern(pat)
    {
        // A value computed by an intrinsic (Fn::Sub/Fn::Join building, say, an S3
        // bucket name from AWS::Region) can't be pattern-checked the way a written
        // literal can, since its final value is only known at deploy time. Those
        // are covered by the Warning-level intrinsic rules rather than this Fatal
        // pattern check, so skip both parameter-sourced and intrinsic-sourced
        // values here.
        let from_param = m.is_from_parameter(rid, prop_path) || m.is_from_intrinsic(rid, prop_path);
        for (val, conds) in &scenarios {
            if !is_satisfiable(m, conds) || val.is_null() {
                continue;
            }
            if let Some(s) = coerce_to_string(val) {
                if s.contains("${") {
                    continue;
                }
                if s.contains("{{") && s.contains("resolve") {
                    continue;
                }
                if from_param {
                    continue;
                }
                if !re.is_match(&s) {
                    out.push(build_diagnostic_conditional(
                        "F3031",
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
        let Some(n) = coerce_to_number(val) else {
            continue;
        };
        if let Some(max) = schema.maximum
            && n > max
        {
            out.push(build_diagnostic_conditional(
                "F3034",
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
        let from_param = m.is_from_parameter(rid, prop_path) || m.is_from_intrinsic(rid, prop_path);
        for (val, conds) in &scenarios {
            if !is_satisfiable(m, conds) || val.is_null() {
                continue;
            }
            let Some(s) = coerce_to_string(val) else {
                continue;
            };
            if s.contains("${") {
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
                    // A null element is an `AWS::NoValue` that CloudFormation
                    // removes from the list at deploy time, so it is not a real
                    // member and two such elements are not a duplicate. Only the
                    // surviving concrete items are checked for uniqueness.
                    if item.is_null() {
                        continue;
                    }
                    if seen.contains(item) {
                        out.push(build_diagnostic_conditional(
                            "F3037",
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
        } else if !schema.required.is_empty()
            && !matches!(m.resolve_deep(rid, prop_path), Some(ResolvedValue::Conditional { .. }))
        {
            // Empty concrete object scenario (e.g. a literal `{}`) — still
            // validate required properties. An empty object has no keys but
            // required properties must still be present.
            //
            // The `Conditional` guard skips properties that are an `Fn::If`:
            // there the branch-aware required-property rule owns the check and
            // anchors the diagnostic at the branch path (`<prop>.Fn::If.<idx>`),
            // so reporting here too would duplicate that finding at the
            // un-qualified property path.
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
                validate_prop(out, store, m, rid, rtype, &sub_path, resolved, defs, visited, region);
            }
        }
    }

    if let Some(ref item_schema) = schema.items {
        let resolved = item_schema.resolve(defs);
        // Use per-index paths instead of wildcard {} to avoid dedup mismatches
        let mut did_per_index = false;
        {
            let arr_len = match m.resolve_deep(rid, prop_path).or_else(|| m.resolve(rid, prop_path).cloned()) {
                Some(ResolvedValue::List { items }) => Some(items.len()),
                Some(ResolvedValue::Concrete { value: ref v }) if v.is_array() => Some(v.as_array().unwrap().len()),
                _ => None,
            };
            if let Some(len) = arr_len {
                did_per_index = true;
                for idx in 0..len {
                    let idx_path = format!("{}.{}", prop_path, idx);
                    validate_prop(out, store, m, rid, rtype, &idx_path, resolved, defs, visited, region);
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
        if !did_per_index && (!resolved.dependent_excluded.is_empty() || !resolved.dependent_required.is_empty()) {
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
    let arr = match m.resolve_deep(rid, array_path).or_else(|| m.resolve(rid, array_path).cloned()) {
        Some(ResolvedValue::List { items }) => items,
        Some(ResolvedValue::Concrete { value: v }) => match v.into_inner() {
            serde_json::Value::Array(items) => {
                items.into_iter().map(|i| ResolvedValue::Concrete { value: i.into() }).collect()
            }
            _ => return,
        },
        _ => return,
    };
    for (idx, item) in arr.iter().enumerate() {
        let keys: Vec<String> = match item {
            ResolvedValue::Map { entries } => entries.iter().map(|e| e.key.clone()).collect(),
            ResolvedValue::Concrete { value: v } if v.is_object() => v.as_object().unwrap().keys().cloned().collect(),
            _ => continue,
        };
        let item_path = format!("{}.{}", array_path, idx);
        for (trigger, excluded) in &item_schema.dependent_excluded {
            if keys.iter().any(|k| k == trigger) {
                for dep in excluded {
                    if keys.iter().any(|k| k == dep) {
                        out.push(build_diagnostic(
                            "F3020",
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
    match m.resolve_deep(rid, path).or_else(|| m.resolve(rid, path).cloned()) {
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
            val.is_i64() || val.is_u64() || (val.is_f64() && val.as_f64().map(|f| f.fract() == 0.0).unwrap_or(false))
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
    allowed.iter().any(|a| scalar_eq(a, val))
}

/// True when property `prop` under `base` resolves to a concrete (non-null)
/// value in at least one satisfiable scenario. A property set to `AWS::NoValue`
/// resolves to null in every scenario and is treated as absent — CloudFormation
/// strips it before deployment. When resolution yields no scenarios (the value
/// is opaque/dynamic), the property is conservatively considered present so a
/// genuinely-specified property is never miscounted as absent.
fn property_present(m: &Arc<SemanticModel>, rid: &str, base: &str, prop: &str) -> bool {
    let scenarios = m.resolve_scenarios_json(rid, &format!("{}.{}", base, prop));
    if scenarios.is_empty() {
        return true;
    }
    scenarios.iter().any(|(val, conds)| is_satisfiable(m, conds) && !val.is_null())
}

fn check_required_not_null(out: &mut Vec<Diagnostic>, m: &Arc<SemanticModel>, rid: &str, base: &str, req: &str) {
    for (val, conds) in &m.resolve_scenarios_json(rid, &format!("{}.{}", base, req)) {
        if !is_satisfiable(m, conds) {
            continue;
        }
        if val.is_null() {
            out.push(build_diagnostic_conditional(
                "F3003",
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
    m.conditions.is_satisfiable(&conds.iter().map(|(k, v)| (k.clone(), *v)).collect::<Vec<_>>())
}

fn condition_map(conds: &HashMap<String, bool>) -> Option<HashMap<String, bool>> {
    if conds.is_empty() { None } else { Some(conds.clone()) }
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
    for (i, row) in dp.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in dp[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let c = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            dp[i][j] = (dp[i - 1][j] + 1).min(dp[i][j - 1] + 1).min(dp[i - 1][j - 1] + c);
        }
    }
    dp[a.len()][b.len()]
}

fn format_value(val: &serde_json::Value) -> String {
    render_value(val)
}

fn format_allowed_values(values: &[serde_json::Value]) -> String {
    render_value_list(values)
}

fn condition_matches(
    cond: &ConditionSchema,
    actual_keys: &[String],
    m: &Arc<SemanticModel>,
    rid: &str,
    defs: &HashMap<String, PropSchema>,
) -> bool {
    if !cond.any_of.is_empty() {
        return cond.any_of.iter().any(|sub| condition_matches(sub, actual_keys, m, rid, defs));
    }
    for req in &cond.required {
        if !actual_keys.iter().any(|k| k == req) {
            return false;
        }
    }
    for (prop_name, prop_schema) in &cond.properties {
        let resolved = prop_schema.resolve(defs);
        let prop_path = format!("Properties.{}", prop_name);
        // Check nested required sub-properties (e.g. Code requires ZipFile)
        if !resolved.required.is_empty() {
            for sub_req in &resolved.required {
                let sub_path = format!("{}.{}", prop_path, sub_req);
                let sub_scenarios = m.resolve_scenarios_json(rid, &sub_path);
                let sub_exists = sub_scenarios.iter().any(|(v, c)| is_satisfiable(m, c) && !v.is_null());
                if !sub_exists {
                    return false;
                }
            }
        }
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
        let compiled_pattern = resolved.pattern.as_ref().and_then(|pat| compile_pattern(pat));
        // If the schema has a pattern that could not be compiled by any strategy, the constraint
        // cannot be verified; treat the branch as non-matching rather than guessing.
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
                return scalar_eq(val, cv);
            }
            if let Some(ref re) = compiled_pattern {
                return coerce_to_string(val).map(|s| re.is_match(&s)).unwrap_or(false);
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
    let raw = m.resolve(rid, prop_path).cloned().or_else(|| m.resolve_deep(rid, prop_path));
    let Some(raw) = raw else { return };

    match &raw {
        ResolvedValue::Reference { target, kind } => {
            let target_type = m.resources.get(target.as_str()).map(|r| r.resource_type.as_str());
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
        }
        ResolvedValue::TypedDynamic { reason: _name, param_type } => {
            let source = cfn_param_type_to_schema_type(param_type);
            if !types_compatible(source, expected_type) {
                let expected = expected_type.primary().unwrap_or("unknown");
                // Parameters are coerced at deploy time — warn rather than error
                out.push(build_diagnostic(
                    "W9003",
                    &format!("Parameter type '{}' may not be compatible with expected type '{}'", param_type, expected),
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
        PARAM_TYPE_NUMBER => "number",
        PARAM_TYPE_STRING => "string",
        PARAM_TYPE_COMMA_DELIMITED_LIST => "array",
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

static FORMAT_PATTERNS: LazyLock<HashMap<&'static str, Arc<CompiledPattern>>> = LazyLock::new(|| {
    let sources: [(&str, &str); 13] = [
        ("AWS::EC2::VPC.Id", r"^vpc-[a-f0-9]{8,17}$"),
        ("AWS::EC2::Subnet.Id", r"^subnet-[a-f0-9]{8,17}$"),
        ("AWS::EC2::SecurityGroup.Id", r"^sg-[a-f0-9]{8,17}$"),
        ("AWS::EC2::Image.Id", r"^ami-([0-9a-z]{8}|[0-9a-z]{17})$"),
        ("AWS::IAM::Role.Arn", IAM_ROLE_ARN_PATTERN),
        ("AWS::Logs::LogGroup.Name", r"^[\.\-_/#A-Za-z0-9]{1,512}$"),
        ("AWS::EC2::SecurityGroup.Name", SECURITY_GROUP_NAME_PATTERN),
        ("AWS::EC2::KeyPair.KeyName", r"^[\x20-\x7E]{1,255}$"),
        ("AWS::EC2::AvailabilityZone.Name", r"^[a-z]{2}(-gov|-iso[a-z]*)?-[a-z]+-\d[a-z]$"),
        ("AWS::Route53::HostedZone.Id", r"^Z[A-Z0-9]{1,32}$"),
        ("AWS::EC2::Volume.Id", r"^vol-[a-f0-9]{8,17}$"),
        ("AWS::EC2::NetworkInterface.Id", r"^eni-[a-f0-9]{8,17}$"),
        ("AWS::SSM::Parameter.Name", r"^[a-zA-Z0-9_./-]{1,2048}$"),
    ];
    sources.into_iter().filter_map(|(fmt, pat)| compile_pattern(pat).map(|re| (fmt, re))).collect()
});

fn validate_format(out: &mut Vec<Diagnostic>, m: &Arc<SemanticModel>, rid: &str, prop_path: &str, format: &str) {
    let Some(re) = FORMAT_PATTERNS.get(format) else {
        return;
    };

    for (val, conds) in &m.resolve_scenarios_json(rid, prop_path) {
        if !is_satisfiable(m, conds) || val.is_null() {
            continue;
        }
        if let Some(s) = coerce_to_string(val) {
            if s.contains("${") {
                continue;
            }
            if m.is_from_parameter(rid, prop_path) {
                continue;
            }
            if !re.is_match(&s) {
                let rule_id = format_rule_for_format(format).unwrap_or("E1103");
                out.push(build_diagnostic_conditional(
                    rule_id,
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

fn validate_lifecycle(out: &mut Vec<Diagnostic>, store: &CompiledSchemaStore, model: &Arc<SemanticModel>) {
    let lifecycle = store.lifecycle();
    for (rid, res) in &model.resources {
        if let Some(entry) = lifecycle.resource_lifecycle(&res.resource_type) {
            let (rule_id, msg) = match (entry.status.as_str(), entry.date.as_deref()) {
                ("shutdown", Some(d)) => (
                    "E3710",
                    format!("Resource type '{}' is from a service that was shut down on {}", res.resource_type, d),
                ),
                ("shutdown", None) => (
                    "E3710",
                    format!("Resource type '{}' is from a service that has been shut down", res.resource_type),
                ),
                ("sunset", Some(d)) => (
                    "W3696",
                    format!(
                        "Resource type '{}' is from a service that will be shut down on {}. Plan to migrate to an alternative",
                        res.resource_type, d
                    ),
                ),
                ("sunset", None) => {
                    ("W3696", format!("Resource type '{}' is from a service that is sunsetting", res.resource_type))
                }
                ("maintenance", Some(d)) => (
                    "W3697",
                    format!(
                        "Resource type '{}' is from a service in maintenance mode since {}. Consider migrating to an alternative",
                        res.resource_type, d
                    ),
                ),
                ("maintenance", None) => {
                    ("W3697", format!("Resource type '{}' is from a service in maintenance mode", res.resource_type))
                }
                _ => continue,
            };
            out.push(build_diagnostic(rule_id, &msg, model, rid, "", None));
        }

        if (res.resource_type == "AWS::Lambda::Function" || res.resource_type == SAM_FUNCTION_TYPE)
            // Only a literal Runtime string is validated against the deprecation
            // list; a Runtime produced by an intrinsic (e.g. Fn::FindInMap)
            // resolves at deploy time and is handled by the intrinsic rules
            // instead.
            && !model.is_from_intrinsic(rid, "Properties.Runtime")
        {
            for (val, _) in &model.resolve_scenarios_json(rid, "Properties.Runtime") {
                let Some(runtime) = val.as_str() else {
                    continue;
                };
                // All three deprecation bands share one dated message; only the
                // rule id and severity differ by how far the runtime is through
                // its lifecycle. The band is a snapshot taken at data-sync time.
                let (rule_id, band) = if lifecycle.is_runtime_eol(runtime) {
                    ("E2533", true)
                } else if lifecycle.is_runtime_create_blocked(runtime) {
                    ("E2531", true)
                } else if lifecycle.is_runtime_deprecated(runtime) {
                    ("W2531", true)
                } else {
                    ("", false)
                };
                if band {
                    out.push(build_diagnostic(
                        rule_id,
                        &runtime_deprecation_message(lifecycle, runtime),
                        model,
                        rid,
                        "Properties.Runtime",
                        None,
                    ));
                }
            }
        }
    }
}

/// Builds the dated runtime-deprecation message CloudFormation reports for all
/// three bands: "Runtime 'X' was deprecated on 'D'. Creation was disabled on 'C'
/// and update on 'U'. Please consider updating to 'S'". A string value renders
/// single-quoted; a missing successor renders as bare `None` (Python `repr`).
fn runtime_deprecation_message(lifecycle: &crate::store::LifecycleStore, runtime: &str) -> String {
    let Some(dates) = lifecycle.runtime_lifecycle(runtime) else {
        return format!("Runtime '{}' is deprecated", runtime);
    };
    let successor = match &dates.successor {
        Some(s) => format!("'{}'", s),
        None => "None".to_string(),
    };
    format!(
        "Runtime '{}' was deprecated on '{}'. Creation was disabled on '{}' and update on '{}'. Please consider updating to {}",
        runtime, dates.deprecated, dates.create_block, dates.update_block, successor
    )
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
            // A reference may be a nested JSON pointer (e.g.
            // /RedrivePolicy/deadLetterTargetArn); convert it to the dotted
            // property path follow_ref expects.
            let prop_key = ref_path.trim_start_matches('/').replace('/', ".");
            model.follow_ref(rid, &format!("Properties.{}", prop_key)).map(String::from)
        } else {
            Some(rid.to_string())
        };

        let Some(target) = target_rid else { continue };

        if let Some(filter) = slot_obj.get("filter").and_then(|v| v.as_object())
            && let Some(expected_type) = filter.get("type").and_then(|v| v.as_str())
        {
            let actual_type = model.resources.get(&target).map(|r| r.resource_type.as_str());
            if actual_type != Some(expected_type) {
                continue;
            }
        }

        let mut slot_values = serde_json::Map::new();
        if let Some(props) = properties {
            for (prop_name, prop_def) in props {
                // A gather property spec is either a bare JSON-pointer string
                // ("/RestApiId") or an object ({"path": "/FifoQueue", "default":
                // false}). Both forms appear in the extension data; reading only
                // the object form silently drops the value for the string form
                // and makes the whole cross-resource check a no-op.
                let (path, default_val) = match prop_def {
                    serde_json::Value::String(p) => (Some(p.as_str()), None),
                    _ => (prop_def.get("path").and_then(|v| v.as_str()), prop_def.get("default").cloned()),
                };
                let resolved_path = path.map(|p| format!("Properties.{}", p.trim_start_matches('/').replace('/', ".")));

                let resolved = resolved_path
                    .as_ref()
                    .and_then(|p| model.resolve_scenarios_json(&target, p).into_iter().next().map(|(v, _)| v));
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

/// Whether an extension-required property is already reported by a dedicated
/// native rule under its own specific ID, so the generic F3003 must be
/// suppressed to avoid double-reporting. Keyed on `(resource type, required
/// property)`:
/// - S3 `AccessControl`→`OwnershipControls` is covered by the dedicated S3
///   access-control rule.
/// - ELBv2 Listener HTTPS/TLS→`Certificates` is covered by the dedicated
///   listener-certificate rule (E3676), which fires on the same trigger.
/// - RDS DBInstance `BackupRetentionPeriod` is a retention-period advisory the
///   dedicated retention rule (I3013) already emits; the extension carrying a
///   `then.required` for it must not additionally raise a Fatal F3003 (a
///   missing retention period is informational, never a required-property
///   error).
fn extension_required_covered_by_dedicated_rule(resource_type: &str, prop_name: &str) -> bool {
    matches!(
        (resource_type, prop_name),
        ("AWS::S3::Bucket", "OwnershipControls")
            | ("AWS::ElasticLoadBalancingV2::Listener", "Certificates")
            | ("AWS::RDS::DBInstance", "BackupRetentionPeriod")
    )
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
    let branch = if if_matches { ext.get("then") } else { ext.get("else") };
    let Some(branch_schema) = branch else { return };

    if let Some(required) = branch_schema.get("required").and_then(|v| v.as_array()) {
        for req in required {
            if let Some(prop_name) = req.as_str()
                && !res.properties.contains_key(prop_name)
            {
                // Some extensions express a requirement that a dedicated rule
                // already reports under its own specific ID (e.g. the S3
                // AccessControl→OwnershipControls extension is the dedicated S3
                // access-control rule). Emitting the generic F3003 on top of that
                // dedicated diagnostic would be a double-report, so skip it.
                if extension_required_covered_by_dedicated_rule(&res.resource_type, prop_name) {
                    continue;
                }
                // Dedup: compiled base schema's if_then_else may already have
                // emitted a required-property diagnostic for the same required property (the
                // extension schemas sometimes mirror the base schema's conditional
                // requirements). Skip to avoid double-reporting.
                let already_reported = out.iter().any(|d| {
                    d.rule_id == "F3003"
                        && d.resource_logical_id() == Some(rid)
                        && d.message.contains(&format!("'{}' is a required property", prop_name))
                });
                if already_reported {
                    continue;
                }
                out.push(build_diagnostic(
                    "F3003",
                    &format!("'{}' is a required property (from extension)", prop_name),
                    model,
                    rid,
                    KEY_PROPERTIES,
                    Some(&format!("Add '{}'", prop_name)),
                ));
            }
        }
    }

    if let Some(props) = branch_schema.get("properties").and_then(|v| v.as_object()) {
        for (prop_name, constraint) in props {
            if constraint == &serde_json::Value::Bool(false) && res.properties.contains_key(prop_name) {
                // Extension marks the property as non-applicable in this configuration.
                // CloudFormation does not reject such properties — it ignores them.
                // Emit as Info so the finding is surfaced but does not block deployment
                // or cause `good/` fixtures to fail the no-errors contract.
                out.push(build_diagnostic(
                    "I9002",
                    &format!("'{}' is ignored in this configuration (from extension)", prop_name),
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
                // NOTE: these extension enums use per-enum case
                // sensitivity — case-insensitive for engine names
                // (Engine: "MySQL" is accepted against "mysql") but case-sensitive
                // for others (ReplicaMode: "Mounted" is rejected against
                // "mounted"). Distinguishing them requires the per-rule mapping
                // (tracked with the extension→specific-ID work); until then keep
                // the case-insensitive fallback, since a false negative on
                // ReplicaMode is preferable to false positives on valid engines.
                let matches_enum = enum_vals.iter().any(|e| {
                    scalar_eq(e, val) || e.as_str().zip(val.as_str()).is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
                });
                if !matches_enum {
                    let allowed = render_str_list(enum_vals.iter().filter_map(|v| v.as_str()));
                    out.push(build_diagnostic(
                        "E9006",
                        &format!("'{}' is not one of {}", coerce_to_string(val).unwrap_or_default(), allowed),
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
fn match_constraint_value(constraint: &serde_json::Map<String, serde_json::Value>, val: &serde_json::Value) -> bool {
    if let Some(enum_vals) = constraint.get("enum").and_then(|v| v.as_array()) {
        return enum_vals.iter().any(|e| scalar_eq(e, val));
    }
    if let Some(cv) = constraint.get("const") {
        return scalar_eq(val, cv);
    }
    if let Some(pat) = constraint.get("pattern").and_then(|v| v.as_str()) {
        return val.as_str().and_then(|s| compile_pattern(pat).map(|re| re.is_match(s))).unwrap_or(false);
    }
    true
}

fn extension_condition_matches(if_schema: &serde_json::Value, model: &Arc<SemanticModel>, rid: &str) -> bool {
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
            let prop_path = format!("Properties.{}", prop_name);
            let scenarios = model.resolve_scenarios_json(rid, &prop_path);
            // A property schema of `false` means the property must be ABSENT for
            // the condition to hold (JSON Schema: `false` rejects any value). So
            // the `if` matches only when the property resolves to nothing in
            // every satisfiable scenario; if it is present anywhere, the
            // condition fails. (e.g. RDS read-replica: SourceDBInstanceIdentifier
            // present ⇒ the BackupRetentionPeriod requirement does not apply.)
            if constraint == &serde_json::Value::Bool(false) {
                let present = scenarios.iter().any(|(v, c)| is_satisfiable(model, c) && !v.is_null());
                if present {
                    return false;
                }
                continue;
            }
            if scenarios.is_empty() {
                return false;
            }
            let constraint_obj = match constraint.as_object() {
                Some(o) => o,
                None => continue,
            };
            // Check nested required sub-properties within the constraint
            if let Some(nested_required) = constraint_obj.get("required").and_then(|v| v.as_array()) {
                for sub_req in nested_required {
                    if let Some(sub_name) = sub_req.as_str() {
                        let sub_path = format!("{}.{}", prop_path, sub_name);
                        let sub_scenarios = model.resolve_scenarios_json(rid, &sub_path);
                        let sub_exists = sub_scenarios.iter().any(|(v, c)| is_satisfiable(model, c) && !v.is_null());
                        if !sub_exists {
                            return false;
                        }
                    }
                }
            }
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

fn resolve_data_in_schema(schema: &serde_json::Value, context: &serde_json::Value) -> serde_json::Value {
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
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(|v| resolve_data_in_schema(v, context)).collect())
        }
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
    // NOTE: this generic gather path only surfaces top-level const mismatches as
    // E3030. These cross-resource constraints belong under specific dedicated
    // rule IDs (E3699, E3707, E3709, …) and dedicated native rules already cover
    // the reachable cases (E3502, E3707, E3698, …). Broadening this path to also
    // unwrap `cfnContext` or evaluate bare `properties` schemas made it emit
    // generic E3030 duplicates alongside those dedicated rules; keep it scoped to
    // an explicit if/then/else so it does not double-report. Emitting the
    // per-resource IDs is tracked as a dedicated follow-up.
    if let Some(if_val) = obj.get("if") {
        let matches = gather_condition_matches(if_val, context);
        let branch = if matches { obj.get("then") } else { obj.get("else") };
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
        return scalar_eq(actual, cv);
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
            check_gather_property_constraints(out, model, rid, slot_name, &slot_val, slot_constraints);
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
                && !scalar_eq(prop_val, cv)
            {
                out.push(build_diagnostic(
                    "E3030",
                    &format!(
                        "Cross-resource constraint: {}.{} is {} but must be {} (from referenced resource)",
                        slot_name,
                        prop_name,
                        format_value(prop_val),
                        format_value(cv)
                    ),
                    model,
                    rid,
                    KEY_PROPERTIES,
                    None,
                ));
            }
            // Numeric cross-resource bounds (e.g. SQS VisibilityTimeout vs Lambda
            // Timeout, ESM BatchSize for FIFO queues) are reported by the dedicated
            // cross-resource rules at their specific locations. Emitting a generic
            // schema-bounds diagnostic here as well would double-report the same
            // issue, so the const equality check above is the only gather
            // constraint surfaced directly.
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
        ResolvedValue::Conditional { condition: cond, if_true: _, if_false: _ } => {
            Some(format!("Fn::If on condition '{}'", cond))
        }
        ResolvedValue::Dynamic { reason: desc } => Some(format!("dynamic ({})", desc)),
        ResolvedValue::TypedDynamic { reason: name, param_type: typ } => {
            Some(format!("parameter '{}' (type {})", name, typ))
        }
        _ => None,
    }
}

fn build_diagnostic(
    rule_id: &str,
    msg: &str,
    m: &Arc<SemanticModel>,
    rid: &str,
    prop: &str,
    fix: Option<&str>,
) -> Diagnostic {
    build_diagnostic_conditional(rule_id, msg, m, rid, prop, fix, None)
}

fn build_diagnostic_conditional(
    rule_id: &str,
    msg: &str,
    m: &Arc<SemanticModel>,
    rid: &str,
    prop: &str,
    fix: Option<&str>,
    conds: Option<HashMap<String, bool>>,
) -> Diagnostic {
    let span = if rid.is_empty() { resolve_section_span(rule_id, m.as_ref()) } else { m.resource_span(rid, prop) };
    RegisteredDiagnostic::new(rule_id, msg)
        .resource(rid, m.resources.get(rid).map(|r| r.resource_type.clone()))
        .property_path(prop)
        .location(span)
        .suggested_fix(fix)
        .condition_scenario(conds)
        .phase(Phase::Schema)
        .build()
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
        assert_eq!(find_similar("CompletelyDifferent", &known), None, "dissimilar name should not match");
    }

    #[test]
    fn find_similar_case_insensitive() {
        let known: HashSet<&str> = ["BucketName"].into_iter().collect();
        assert_eq!(find_similar("bucketname", &known), Some("BucketName"));
    }

    #[test]
    fn type_matches_string() {
        assert!(type_matches(&json!("hello"), &PropType::Single("string".into())));
        assert!(!type_matches(&json!(42), &PropType::Single("string".into())));
    }

    #[test]
    fn type_matches_integer() {
        assert!(type_matches(&json!(42), &PropType::Single("integer".into())));
        assert!(type_matches(&json!(42.0), &PropType::Single("integer".into())));
        assert!(!type_matches(&json!(42.5), &PropType::Single("integer".into())));
        assert!(!type_matches(&json!("42"), &PropType::Single("integer".into())));
    }

    #[test]
    fn type_matches_number() {
        assert!(type_matches(&json!(42), &PropType::Single("number".into())));
        assert!(type_matches(&json!(3.14), &PropType::Single("number".into())));
        assert!(!type_matches(&json!("3.14"), &PropType::Single("number".into())));
    }

    #[test]
    fn type_matches_boolean() {
        assert!(type_matches(&json!(true), &PropType::Single("boolean".into())));
        assert!(!type_matches(&json!("true"), &PropType::Single("boolean".into())));
    }

    #[test]
    fn type_matches_array() {
        assert!(type_matches(&json!([1, 2]), &PropType::Single("array".into())));
        assert!(!type_matches(&json!("[]"), &PropType::Single("array".into())));
    }

    #[test]
    fn type_matches_object() {
        assert!(type_matches(&json!({"a": 1}), &PropType::Single("object".into())));
        assert!(!type_matches(&json!("{}"), &PropType::Single("object".into())));
    }

    #[test]
    fn type_matches_null() {
        assert!(type_matches(&json!(null), &PropType::Single("null".into())));
        assert!(!type_matches(&json!("null"), &PropType::Single("null".into())));
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
        assert!(type_matches(&json!("anything"), &PropType::Single("custom_type".into())));
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
        assert_eq!(cfn_param_type_to_schema_type("List<AWS::EC2::Subnet::Id>"), "array");
    }

    #[test]
    fn param_type_ssm_parameter() {
        assert_eq!(cfn_param_type_to_schema_type("AWS::SSM::Parameter::Value<String>"), "string");
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
        assert_eq!(resolve_data_in_schema(&json!("plain"), &json!({})), json!("plain"));
        assert_eq!(resolve_data_in_schema(&json!(42), &json!({})), json!(42));
        assert_eq!(resolve_data_in_schema(&json!(null), &json!({})), json!(null));
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
        assert_eq!(resolve_data_in_schema(&schema, &context), json!({"const": 3306}));
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
        assert!(types_compatible("string", &PropType::Single("string".into())));
        assert!(!types_compatible("array", &PropType::Single("string".into())));
    }

    #[test]
    fn types_compatible_multi() {
        let pt = PropType::Multi(vec!["string".into(), "null".into()]);
        assert!(types_compatible("string", &pt));
        assert!(types_compatible("integer", &pt));
        assert!(!types_compatible("array", &PropType::Multi(vec!["string".into(), "integer".into()])));
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
            PropSchema { prop_type: Some(PropType::Single("string".into())), ..Default::default() },
        );
        let defs = HashMap::new();
        let result = find_prop_schema("Name", &props, &defs).expect("Name should be found");
        assert_eq!(result.prop_type.as_ref().unwrap().primary(), Some("string"));
    }

    #[test]
    fn find_prop_schema_nested_path() {
        let inner = PropSchema { prop_type: Some(PropType::Single("integer".into())), ..Default::default() };
        let mut inner_props = HashMap::new();
        inner_props.insert("Port".into(), inner);
        let outer = PropSchema { properties: inner_props, ..Default::default() };
        let mut props = HashMap::new();
        props.insert("Config".into(), outer);
        let defs = HashMap::new();
        let result = find_prop_schema("Config.Port", &props, &defs).expect("Config.Port should be found");
        assert_eq!(result.prop_type.as_ref().unwrap().primary(), Some("integer"));
    }

    #[test]
    fn find_prop_schema_missing_returns_none() {
        let props = HashMap::new();
        let defs = HashMap::new();
        assert!(find_prop_schema("Missing", &props, &defs).is_none(), "missing prop should return None");
    }

    #[test]
    fn find_prop_schema_resolves_ref() {
        let mut props = HashMap::new();
        props.insert("Config".into(), PropSchema { ref_name: Some("ConfigDef".into()), ..Default::default() });
        let mut defs = HashMap::new();
        defs.insert(
            "ConfigDef".into(),
            PropSchema { prop_type: Some(PropType::Single("object".into())), ..Default::default() },
        );
        let result = find_prop_schema("Config", &props, &defs).expect("Config should be found");
        assert_eq!(result.prop_type.as_ref().unwrap().primary(), Some("object"));
    }

    #[test]
    fn find_prop_schema_deep_direct() {
        let mut props = HashMap::new();
        props.insert(
            "Name".into(),
            PropSchema { prop_type: Some(PropType::Single("string".into())), ..Default::default() },
        );
        let schema = CompiledSchema { type_name: "Test".into(), properties: props, ..Default::default() };
        assert!(find_prop_schema_deep("Name", &schema).is_some(), "direct property should be found");
    }

    #[test]
    fn find_prop_schema_deep_searches_one_of() {
        let mut sub_props = HashMap::new();
        sub_props.insert(
            "Special".into(),
            PropSchema { prop_type: Some(PropType::Single("boolean".into())), ..Default::default() },
        );
        let schema = CompiledSchema {
            type_name: "Test".into(),
            one_of: vec![crate::compiled::SubSchema { properties: sub_props, ..Default::default() }],
            ..Default::default()
        };
        let result = find_prop_schema_deep("Special", &schema);
        assert!(result.is_some(), "expected to find Special in oneOf sub-schema");
        assert_eq!(result.unwrap().prop_type.as_ref().unwrap().primary(), Some("boolean"));
    }

    #[test]
    fn find_prop_schema_deep_searches_if_then_else() {
        let mut then_props = HashMap::new();
        then_props.insert(
            "ConditionalProp".into(),
            PropSchema { prop_type: Some(PropType::Single("string".into())), ..Default::default() },
        );
        let schema = CompiledSchema {
            type_name: "Test".into(),
            if_then_else: vec![crate::compiled::IfThenElse {
                condition: Default::default(),
                then_schema: Some(crate::compiled::SubSchema { properties: then_props, ..Default::default() }),
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
        let cond = ConditionSchema { required: vec!["MissingKey".into()], ..Default::default() };
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
        assert!(!gather_prop_matches(&json!("udp"), &json!({"const": "tcp"})));
    }

    #[test]
    fn gather_prop_matches_enum() {
        assert!(gather_prop_matches(&json!("a"), &json!({"enum": ["a", "b"]})));
        assert!(!gather_prop_matches(&json!("c"), &json!({"enum": ["a", "b"]})));
    }

    #[test]
    fn gather_prop_matches_nested_properties() {
        let actual = json!({"inner": {"key": "val"}});
        let constraint = json!({"properties": {"inner": {"properties": {"key": {"const": "val"}}}}});
        assert!(gather_prop_matches(&actual, &constraint));
    }
}
