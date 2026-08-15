use crate::compiled::{CompiledSchema, ConditionSchema, PropSchema, PropType, SubSchema};
use crate::store::CompiledSchemaStore;
use diagnostics::{Diagnostic, Phase, RegisteredDiagnostic, ViolationContext, resolve_section_span};
use rules::format_rule_for_format;
use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, LazyLock};
use template_model::coercion::{CoerceResult, coerce_to_number, coerce_to_string, coerce_value, scalar_eq};
use template_model::conditions::Satisfiability;
use template_model::consts::{
    FN_CONDITION, FN_FOR_EACH_KEY_PREFIX, FN_IF, FN_REF, INTRINSIC_FN_PATH_SEGMENTS, KEY_PROPERTIES, KEY_TYPE,
    PARAM_TYPE_COMMA_DELIMITED_LIST, PARAM_TYPE_NUMBER, PARAM_TYPE_STRING, SAM_FUNCTION_TYPE,
    SAM_SERVERLESS_TYPE_PREFIX,
};
use template_model::message::{render_str_list, render_value, render_value_list};
use template_model::model::ResolvedResource;
use template_model::region_enums;
use template_model::resolver::{RefKind, ResolvedValue};
use template_model::{
    CompiledPattern, IAM_ROLE_ARN_PATTERN, SECURITY_GROUP_NAME_PATTERN, SemanticModel, compile_pattern,
    is_custom_resource_type, resolved_value_to_json,
};

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
/// `Condition`, or an `Fn::ForEach::` loop key). Only known names are skipped -
/// a single-key object whose key merely starts with `Fn::` (e.g. a map entry
/// literally named `Fn::Custom`) is plain data and must be schema-validated
/// like any other object.
fn is_intrinsic_key(key: &str) -> bool {
    INTRINSIC_FN_PATH_SEGMENTS.contains(&key)
        || key == FN_REF
        || key == FN_CONDITION
        || key.starts_with(FN_FOR_EACH_KEY_PREFIX)
}

fn is_unresolved_intrinsic(val: &serde_json::Value) -> bool {
    let Some(obj) = val.as_object() else { return false };
    if obj.len() != 1 {
        return false;
    }
    is_intrinsic_key(obj.keys().next().unwrap())
}

pub fn validate_all_resources(
    store: &CompiledSchemaStore,
    model: &Arc<SemanticModel>,
    region: Option<&str>,
) -> Vec<Diagnostic> {
    reset_scenario_analysis_curtailments();
    let mut out = Vec::new();
    let relevant: HashSet<&str> = model.resources.values().map(|r| r.resource_type.as_str()).collect();

    validate_lifecycle(&mut out, store, model);

    for rtype in &relevant {
        // Custom resources, modules, and SAM resources (rewritten by the SAM
        // transform before deployment) are not region-scoped provider types, so
        // the region check skips them - CloudFormation validates the
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
        // region is never flagged - the availability check only runs for a
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
                // region and the finding is skipped - even at the DEFAULT region,
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
    for (resource_id, property_path) in take_scenario_analysis_curtailments() {
        out.push(build_diagnostic(
            "I9052",
            "Conditional schema analysis budget exhausted; validation of this property's condition scenarios was curtailed and some schema diagnostics may be omitted",
            model,
            &resource_id,
            &property_path,
            None,
        ));
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
                if let Some(ps) = prop_schema {
                    let allowed = if !ps.enum_values.is_empty() { &ps.enum_values } else { &ps.enum_case_insensitive };
                    if !allowed.is_empty() {
                        ensure_ctx!(d)
                            .extra
                            .get_or_insert_with(HashMap::new)
                            .insert("allowed_values".into(), serde_json::json!(allowed).into());
                    }
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
                let lifecycle = if schema.create_only_properties.iter().any(|pointer| pointer == prop_path) {
                    Some("create-only")
                } else if schema.conditional_create_only_properties.iter().any(|pointer| pointer == prop_path) {
                    Some("conditional-create-only")
                } else {
                    None
                };
                ctx.lifecycle = lifecycle.map(String::from);
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

/// Continues a property-path lookup into `resolved`, or returns it when the path
/// ends here. When resolution had to build an effective schema (a `$ref` with
/// constraints of its own), the sub-schema is cloned out of it so the result does
/// not borrow from the temporary.
fn descend<'a>(
    resolved: Cow<'a, PropSchema>,
    rest: Option<&str>,
    defs: &'a HashMap<String, PropSchema>,
) -> Option<Cow<'a, PropSchema>> {
    let Some(rest) = rest else {
        return Some(resolved);
    };
    match resolved {
        Cow::Borrowed(schema) => find_prop_schema(rest, &schema.properties, defs),
        Cow::Owned(schema) => {
            find_prop_schema(rest, &schema.properties, defs).map(|found| Cow::Owned(found.into_owned()))
        }
    }
}

fn find_prop_schema<'a>(
    path: &str,
    props: &'a HashMap<String, PropSchema>,
    defs: &'a HashMap<String, PropSchema>,
) -> Option<Cow<'a, PropSchema>> {
    let mut segments = path.splitn(2, '.');
    let top = segments.next()?;
    let rest = segments.next().filter(|r| !r.is_empty());

    if let Some(ps) = props.get(top) {
        return descend(ps.resolve(defs), rest, defs);
    }
    for (pat, ps) in props.iter() {
        if compile_pattern(pat).is_some_and(|re| re.is_match(top)) {
            return descend(ps.resolve(defs), rest, defs);
        }
    }
    None
}

fn find_prop_schema_deep<'a>(path: &str, schema: &'a CompiledSchema) -> Option<Cow<'a, PropSchema>> {
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
    // itself). Matching on the leaf's actual presence - not merely the top-level
    // parent's - is required to avoid flagging correct templates.
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

    for conditional_pointer in &schema.conditional_create_only_properties {
        // Unconditional list takes precedence: skip if already reported above.
        if schema.create_only_properties.contains(conditional_pointer) {
            continue;
        }
        if let Some(pointer) = present_lifecycle_pointer(m, rid, base, conditional_pointer) {
            out.push(build_diagnostic(
                "I9001",
                &format!(
                    "Property '{}' is conditionally create-only; updating it may cause resource replacement",
                    pointer
                ),
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
            scenario,
        );
    }

    for (prop_name, prop_schema) in &schema.properties {
        let resolved = prop_schema.resolve(defs);
        let prop_path = format!("{}.{}", base, prop_name);
        validate_prop(out, store, m, rid, &res.resource_type, &prop_path, &resolved, defs, region);
    }

    // Also validate properties that exist only inside conditional branches -
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
        validate_prop(out, store, m, rid, &res.resource_type, &prop_path, &resolved, defs, region);
    }

    let actual_keys: Vec<String> = res.properties.keys().cloned().collect();
    for ite in &schema.if_then_else {
        let matches = condition_matches(&ite.condition, &actual_keys, m, rid, defs);
        let sub = if matches { &ite.then_schema } else { &ite.else_schema };
        if let Some(sub) = sub {
            if ite.enforce_full_branch {
                // An overlay-stated conditional is enforced in full - its
                // `required` list, `additionalProperties`, dependency maps, and
                // property value constraints - so nothing the author wrote is
                // silently dropped.
                validate_sub(out, m, rid, &res.resource_type, &actual_keys, sub, defs, base, 0);
            } else {
                // Bundled conditionals enforce co-dependencies only: their
                // richer semantics are owned by dedicated resource-specific
                // rules, and enforcing them generically would double-report
                // (see `IfThenElse::enforce_full_branch`).
                validate_sub_dependencies(out, m, rid, &actual_keys, sub, base);
            }
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
        None,
    )
}

fn validate_required_groups(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    rid: &str,
    actual_keys: &[String],
    required_or: &[String],
    required_xor: &[String],
    base_path: &str,
) {
    if required_or.is_empty() && required_xor.is_empty() {
        return;
    }

    // Collect scenario assignments for group evaluation.
    // When an active SCENARIO_FILTER exists (inside validate_sub_under_assignment
    // for oneOf/anyOf branch matching), it seeds the expansion so nested
    // independent conditions are still evaluated across all their worlds
    // relative to the outer constraint.
    let members: Vec<&str> = required_or.iter().chain(required_xor.iter()).map(String::as_str).collect();
    let Some(assignments) = required_group_scenario_assignments(m, rid, &members, base_path) else {
        // Budget exceeded — fall back to targeted proof search that avoids
        // full Cartesian enumeration while still detecting provable violations.
        validate_required_groups_budget_fallback(out, m, rid, actual_keys, required_or, required_xor, base_path);
        return;
    };

    if !required_or.is_empty() {
        for assignment in &assignments {
            let any_present = required_or.iter().any(|property| {
                actual_keys.iter().any(|actual| actual == property)
                    && property_present_under(m, rid, base_path, property, assignment)
            });
            if !any_present {
                let names = required_or.iter().map(|name| format!("'{name}'")).collect::<Vec<_>>().join(", ");
                out.push(build_diagnostic_conditional(
                    "F3058",
                    &format!("One of [{names}] is a required property"),
                    m,
                    rid,
                    base_path,
                    None,
                    assignment_condition_map(assignment),
                ));
            }
        }
    }

    if !required_xor.is_empty() {
        for assignment in &assignments {
            let count = required_xor
                .iter()
                .filter(|property| {
                    actual_keys.iter().any(|actual| actual == property.as_str())
                        && property_present_under(m, rid, base_path, property, assignment)
                })
                .count();
            if count != 1 {
                let names = required_xor.iter().map(|name| format!("'{name}'")).collect::<Vec<_>>().join(", ");
                out.push(build_diagnostic_conditional(
                    "F3014",
                    &format!("Exactly one of [{names}] must be specified"),
                    m,
                    rid,
                    base_path,
                    None,
                    assignment_condition_map(assignment),
                ));
            }
        }
    }
}

/// Finds a concrete condition assignment proving that every authored member is
/// absent. Missing members are already absent and add no constraint. The search
/// explores only null alternatives and backtracks across nested conditionals,
/// so it does not materialize the full product of present and absent worlds.
fn all_members_absent_witness(
    m: &Arc<SemanticModel>,
    rid: &str,
    actual_keys: &[String],
    members: &[String],
    base_path: &str,
) -> Option<HashMap<String, bool>> {
    let seed = active_scenario_filter();
    if !assignment_is_proven_satisfiable(m, &seed) {
        return None;
    }

    let mut alternatives = Vec::new();
    for property in members {
        if !actual_keys.iter().any(|actual| actual == property) {
            continue;
        }
        let property_alternatives = property_presence_alternatives(m, rid, base_path, property, false, &seed);
        if property_alternatives.is_empty() {
            return None;
        }
        alternatives.push(property_alternatives);
    }
    alternatives.sort_by_key(Vec::len);
    compatible_alternative_witness(m, &alternatives, 0, &seed)
}

/// Finds a concrete condition assignment proving that two distinct authored
/// members are simultaneously present. Exactly-two is sufficient to prove a
/// requiredXor violation and avoids enumerating every other member's state.
fn multiple_members_present_witness(
    m: &Arc<SemanticModel>,
    rid: &str,
    actual_keys: &[String],
    members: &[String],
    base_path: &str,
) -> Option<HashMap<String, bool>> {
    let seed = active_scenario_filter();
    if !assignment_is_proven_satisfiable(m, &seed) {
        return None;
    }

    let present_alternatives: Vec<Vec<HashMap<String, bool>>> = members
        .iter()
        .filter(|property| actual_keys.iter().any(|actual| actual == property.as_str()))
        .map(|property| property_presence_alternatives(m, rid, base_path, property, true, &seed))
        .collect();

    for left in 0..present_alternatives.len() {
        for right in (left + 1)..present_alternatives.len() {
            for left_assignment in &present_alternatives[left] {
                let Some(left_merged) = try_merge_assignments(&seed, left_assignment) else {
                    continue;
                };
                if !assignment_is_proven_satisfiable(m, &left_merged) {
                    continue;
                }
                for right_assignment in &present_alternatives[right] {
                    let Some(merged) = try_merge_assignments(&left_merged, right_assignment) else {
                        continue;
                    };
                    if assignment_is_proven_satisfiable(m, &merged) {
                        return Some(merged);
                    }
                }
            }
        }
    }
    None
}

fn active_scenario_filter() -> HashMap<String, bool> {
    SCENARIO_FILTER.with(|filter| filter.borrow().clone().unwrap_or_default())
}

/// Returns the distinct reachable assignments under which one property is
/// present (`want_present`) or absent. Raw scenarios are used so dynamic values
/// still count as present, while only a concrete null represents
/// `AWS::NoValue` absence.
fn property_presence_alternatives(
    m: &Arc<SemanticModel>,
    rid: &str,
    base_path: &str,
    property: &str,
    want_present: bool,
    filter: &HashMap<String, bool>,
) -> Vec<HashMap<String, bool>> {
    if m.scenario_budget_exhausted() {
        return Vec::new();
    }
    let scenarios = outer_resolved_scenarios(m, rid, &format!("{base_path}.{property}"));
    let mut alternatives = Vec::new();
    let mut seen = HashSet::new();
    for (value, conditions) in scenarios {
        let present = !matches!(value, ResolvedValue::Concrete { value } if value.is_null());
        if present != want_present {
            continue;
        }
        let Some(merged) = try_merge_assignments(filter, &conditions) else {
            continue;
        };
        if assignment_is_proven_satisfiable(m, &merged) && seen.insert(canonical_assignment(&conditions)) {
            alternatives.push(conditions);
        }
    }
    alternatives
}

fn compatible_alternative_witness(
    m: &Arc<SemanticModel>,
    alternatives: &[Vec<HashMap<String, bool>>],
    index: usize,
    assignment: &HashMap<String, bool>,
) -> Option<HashMap<String, bool>> {
    let Some(group) = alternatives.get(index) else {
        return Some(assignment.clone());
    };
    for alternative in group {
        let Some(merged) = try_merge_assignments(assignment, alternative) else {
            continue;
        };
        if !assignment_is_proven_satisfiable(m, &merged) {
            continue;
        }
        if let Some(witness) = compatible_alternative_witness(m, alternatives, index + 1, &merged) {
            return Some(witness);
        }
    }
    None
}

/// A Fatal diagnostic requires an exact satisfiable witness. The condition
/// solver's ordinary boolean API intentionally maps budget exhaustion to
/// `true`; the tri-state API lets proof-producing validation decline to emit
/// when that answer is unknown.
fn assignment_is_proven_satisfiable(m: &Arc<SemanticModel>, assignment: &HashMap<String, bool>) -> bool {
    if assignment.is_empty() {
        return true;
    }
    let assumptions: Vec<(String, bool)> = assignment.iter().map(|(name, value)| (name.clone(), *value)).collect();
    matches!(m.conditions.satisfiability(&assumptions), Satisfiability::Satisfiable)
}

/// Targeted proof search for required groups after full world enumeration is
/// curtailed. Each emitted diagnostic carries one reachable violating world;
/// no conclusion depends on scenarios or SAT queries omitted by a budget.
fn validate_required_groups_budget_fallback(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    rid: &str,
    actual_keys: &[String],
    required_or: &[String],
    required_xor: &[String],
    base_path: &str,
) {
    if !required_or.is_empty()
        && let Some(witness) = all_members_absent_witness(m, rid, actual_keys, required_or, base_path)
    {
        let names = required_or.iter().map(|name| format!("'{name}'")).collect::<Vec<_>>().join(", ");
        out.push(build_diagnostic_conditional(
            "F3058",
            &format!("One of [{names}] is a required property"),
            m,
            rid,
            base_path,
            None,
            assignment_condition_map(&witness),
        ));
    }

    if required_xor.is_empty() {
        return;
    }
    let names = required_xor.iter().map(|name| format!("'{name}'")).collect::<Vec<_>>().join(", ");
    if let Some(witness) = all_members_absent_witness(m, rid, actual_keys, required_xor, base_path) {
        out.push(build_diagnostic_conditional(
            "F3014",
            &format!("Exactly one of [{names}] must be specified"),
            m,
            rid,
            base_path,
            None,
            assignment_condition_map(&witness),
        ));
    }
    if let Some(witness) = multiple_members_present_witness(m, rid, actual_keys, required_xor, base_path) {
        out.push(build_diagnostic_conditional(
            "F3014",
            &format!("Exactly one of [{names}] must be specified"),
            m,
            rid,
            base_path,
            None,
            assignment_condition_map(&witness),
        ));
    }
}

/// Collect the distinct condition assignments under which a `requiredOr` or
/// `requiredXor` group must be evaluated. Delegates to the generic
/// `property_scenario_assignments` helper with the group member paths.
fn required_group_scenario_assignments(
    m: &Arc<SemanticModel>,
    rid: &str,
    members: &[&str],
    base_path: &str,
) -> Option<Vec<HashMap<String, bool>>> {
    let paths: Vec<String> = members.iter().map(|name| format!("{}.{}", base_path, name)).collect();
    let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    property_scenario_assignments(m, rid, base_path, &refs)
}

const MAX_GROUP_SCENARIO_ASSIGNMENTS: usize = 256;
const MAX_GROUP_SCENARIO_MERGE_ATTEMPTS: usize = 4_096;

fn record_scenario_analysis_curtailment(resource_id: &str, property_path: &str) {
    SCENARIO_ANALYSIS_CURTAILMENTS.with(|curtailments| {
        curtailments.borrow_mut().insert((resource_id.to_string(), property_path.to_string()));
    });
}

fn reset_scenario_analysis_curtailments() {
    SCENARIO_ANALYSIS_CURTAILMENTS.with(|curtailments| curtailments.borrow_mut().clear());
}

fn take_scenario_analysis_curtailments() -> BTreeSet<(String, String)> {
    SCENARIO_ANALYSIS_CURTAILMENTS.with(|curtailments| std::mem::take(&mut *curtailments.borrow_mut()))
}

/// Computes the distinct satisfiable condition assignments under which a group
/// of property paths must be evaluated.
///
/// The active scenario filter seeds the expansion. Each property contributes
/// its distinct satisfiable alternatives, which are conflict-checked and
/// combined with prior assignments. Missing, dynamic, and opaque properties do
/// not add alternatives. Returns `None` when exact enumeration exceeds the
/// bounded work budget; callers then omit the group finding rather than infer a
/// schema violation from an incomplete set of condition worlds.
fn property_scenario_assignments(
    m: &Arc<SemanticModel>,
    rid: &str,
    group_path: &str,
    property_paths: &[&str],
) -> Option<Vec<HashMap<String, bool>>> {
    let seed: HashMap<String, bool> = SCENARIO_FILTER.with(|filter| filter.borrow().clone().unwrap_or_default());
    let mut assignments: Vec<HashMap<String, bool>> = vec![seed.clone()];

    for property_path in property_paths {
        let scenarios = m.resolve_scenarios_json(rid, property_path);
        if scenarios.is_empty() {
            continue;
        }

        let mut property_assignments = Vec::new();
        let mut seen_property_assignments = HashSet::new();
        for (_, conditions) in &scenarios {
            if !is_satisfiable(m, conditions) || !scenario_consistent_with_filter(m, conditions) {
                continue;
            }
            if seen_property_assignments.insert(canonical_assignment(conditions)) {
                if property_assignments.len() == MAX_GROUP_SCENARIO_ASSIGNMENTS {
                    record_scenario_analysis_curtailment(rid, group_path);
                    return None;
                }
                property_assignments.push(conditions.clone());
            }
        }

        if property_assignments.is_empty() {
            continue;
        }

        let mut next_assignments = Vec::new();
        let mut seen_assignments = HashSet::new();
        let mut merge_attempts = 0;
        for existing in &assignments {
            for alternative in &property_assignments {
                merge_attempts += 1;
                if merge_attempts > MAX_GROUP_SCENARIO_MERGE_ATTEMPTS {
                    record_scenario_analysis_curtailment(rid, group_path);
                    return None;
                }
                let Some(merged) = try_merge_assignments(existing, alternative) else {
                    continue;
                };
                if !is_satisfiable(m, &merged) || !scenario_consistent_with_filter(m, &merged) {
                    continue;
                }
                if seen_assignments.insert(canonical_assignment(&merged)) {
                    if next_assignments.len() == MAX_GROUP_SCENARIO_ASSIGNMENTS {
                        record_scenario_analysis_curtailment(rid, group_path);
                        return None;
                    }
                    next_assignments.push(merged);
                }
            }
        }

        if !next_assignments.is_empty() {
            assignments = next_assignments;
        }
    }

    Some(if assignments.is_empty() { vec![seed] } else { assignments })
}

fn canonical_assignment(assignment: &HashMap<String, bool>) -> Vec<(String, bool)> {
    let mut canonical: Vec<(String, bool)> = assignment.iter().map(|(name, value)| (name.clone(), *value)).collect();
    canonical.sort_unstable();
    canonical
}

/// Attempt to merge two condition assignments. Returns `None` if they
/// contradict (same condition name, different boolean value).
fn try_merge_assignments(a: &HashMap<String, bool>, b: &HashMap<String, bool>) -> Option<HashMap<String, bool>> {
    let mut merged = a.clone();
    for (name, val) in b {
        if let Some(existing) = merged.get(name) {
            if existing != val {
                return None; // Contradiction
            }
        } else {
            merged.insert(name.clone(), *val);
        }
    }
    Some(merged)
}

/// Whether a property resolves to a concrete non-null value in at least one
/// satisfiable scenario that is consistent with `assignment`. Restricts
/// evaluation to the scenarios reachable under a given condition assignment, so
/// that mutually exclusive branches are never mixed.
///
/// When called from within `validate_sub_under_assignment`, the active
/// `SCENARIO_FILTER` is also respected - a scenario must be consistent with
/// both the group assignment and the outer branch filter.
///
/// When resolution yields no scenarios (the value is opaque/dynamic), the
/// property is conservatively considered present.
fn property_present_under(
    m: &Arc<SemanticModel>,
    rid: &str,
    base: &str,
    prop: &str,
    assignment: &HashMap<String, bool>,
) -> bool {
    let scenarios = m.resolve_scenarios_json(rid, &format!("{}.{}", base, prop));
    if scenarios.is_empty() {
        return true;
    }
    scenarios.iter().any(|(val, conds)| {
        if !is_satisfiable(m, conds) {
            return false;
        }
        // Check consistency with the active SCENARIO_FILTER (outer oneOf/anyOf
        // assignment from validate_sub_under_assignment).
        if !scenario_consistent_with_filter(m, conds) {
            return false;
        }
        // Check no contradicting keys between scenario conditions and group assignment.
        for (name, value) in assignment {
            if let Some(scenario_value) = conds.get(name)
                && scenario_value != value
            {
                return false;
            }
        }
        // Verify the merged set is satisfiable.
        if !assignment.is_empty() {
            let mut merged = conds.clone();
            for (name, value) in assignment {
                merged.insert(name.clone(), *value);
            }
            if !is_satisfiable(m, &merged) {
                return false;
            }
        }
        !val.is_null()
    })
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
    scenario: Option<&HashMap<String, bool>>,
) {
    // When an outer key scenario is provided, install it as the SCENARIO_FILTER
    // for the duration of this call. This ensures requiredOr/requiredXor and
    // anyOf/oneOf evaluation inside this branch are constrained to the
    // condition world that produced this key set. Restore any previous filter
    // on exit so nested composition preserves outer constraints.
    let previous_filter = SCENARIO_FILTER.with(|f| f.borrow().clone());
    if let Some(outer_conds) = scenario {
        let merged = match &previous_filter {
            Some(existing) => {
                let mut combined = existing.clone();
                for (k, v) in outer_conds {
                    if let Some(prev) = combined.get(k) {
                        if prev != v {
                            // Contradictory condition: skip installing filter.
                            SCENARIO_FILTER.with(|f| *f.borrow_mut() = previous_filter.clone());
                            return;
                        }
                    } else {
                        combined.insert(k.clone(), *v);
                    }
                }
                combined
            }
            None => outer_conds.clone(),
        };
        SCENARIO_FILTER.with(|f| *f.borrow_mut() = Some(merged));
    }

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

    if additional_properties == Some(false) && !is_custom_resource_type(rtype) {
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

    validate_required_groups(out, m, rid, actual_keys, req_or, req_xor, base_path);

    for sub in all_of {
        validate_sub(out, m, rid, rtype, actual_keys, sub, defs, base_path, 0);
    }

    // anyOf/oneOf group decisions are made per template condition scenario. A
    // property valued through `Fn::If` has a different concrete value in each
    // reachable scenario, and each scenario may legitimately satisfy a
    // different branch - deciding the group from values across mutually
    // exclusive scenarios both invents findings (each scenario matches exactly
    // one branch, yet globally two branches look satisfied) and misses them (an
    // invalid scenario is masked by a valid sibling scenario).
    let group_assignments = if any_of.is_empty() && one_of.is_empty() {
        Some(Vec::new())
    } else {
        branch_scenario_assignments(m, rid, any_of.iter().chain(one_of.iter()), base_path)
    }
    .unwrap_or_default();

    if !any_of.is_empty() {
        for assignment in &group_assignments {
            let evaluations =
                evaluate_object_composition_branches(m, rid, rtype, actual_keys, any_of, defs, base_path, assignment);
            if evaluations.iter().all(|evaluation| !evaluation.matched) {
                out.push(build_composition_diagnostic(
                    "F3017",
                    CompositionKind::AnyOf,
                    &evaluations,
                    m,
                    rid,
                    base_path,
                    Some(rtype),
                    None,
                    assignment_condition_map(assignment),
                ));
            }
        }
    }

    if !one_of.is_empty() {
        for assignment in &group_assignments {
            let evaluations =
                evaluate_object_composition_branches(m, rid, rtype, actual_keys, one_of, defs, base_path, assignment);
            let match_count = evaluations.iter().filter(|evaluation| evaluation.matched).count();
            if match_count != 1 {
                out.push(build_composition_diagnostic(
                    "F3018",
                    CompositionKind::OneOf,
                    &evaluations,
                    m,
                    rid,
                    base_path,
                    Some(rtype),
                    None,
                    assignment_condition_map(assignment),
                ));
            }
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

    // Restore the previous SCENARIO_FILTER.
    SCENARIO_FILTER.with(|f| *f.borrow_mut() = previous_filter);
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
    // Deduplicate scenarios that produce the same key set - when both
    // branches of a condition have identical keys, the condition does not
    // affect key validation, so a single unconditioned entry suffices.
    let mut seen_keysets: HashMap<Vec<String>, HashMap<String, bool>> = HashMap::new();
    for (keys, conds) in out.drain(..) {
        seen_keysets
            .entry(keys)
            .and_modify(|existing| {
                // When two scenarios reach the same keys under complementary
                // assumptions, the result is unconditioned - drop shared vars
                // where the two assumption maps disagree.
                existing.retain(|k, v| conds.get(k) == Some(v));
            })
            .or_insert(conds);
    }
    seen_keysets.into_iter().collect()
}

/// Top-level properties of a resource may themselves be wrapped in an
/// `Fn::If` - e.g. `Properties: {Fn::If: [Cond, {a: 1}, {b: 2}]}`. Return one
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
    rtype: &str,
    actual_keys: &[String],
    sub: &SubSchema,
    defs: &HashMap<String, PropSchema>,
    base_path: &str,
    depth: usize,
) {
    // A conditional branch may itself be (or reference) a schema with further
    // conditionals, so recursion is bounded the same way value matching is: a
    // crafted definition graph must never exhaust the stack.
    if depth > MAX_MATCH_DEPTH {
        return;
    }
    // Resolve $ref in the branch - a branch that references a definition uses
    // the definition's constraints. A dangling ref (definition not found) makes
    // the branch fail validation (never vacuously match).
    let resolved;
    let effective_sub = if sub.ref_name.is_some() {
        resolved = sub.resolve(defs);
        if sub.ref_name.is_some() && resolved.ref_name.is_some() {
            // Dangling ref: definition not found → branch fails
            out.push(build_diagnostic(
                "F3003",
                &format!(
                    "Composition branch references undefined definition '{}'",
                    sub.ref_name.as_deref().unwrap_or("")
                ),
                m,
                rid,
                base_path,
                None,
            ));
            return;
        }
        &*resolved
    } else {
        sub
    };

    for req in &effective_sub.required {
        if !actual_keys.contains(req) {
            // A requirement a dedicated resource-specific rule already reports
            // under its own ID (e.g. the S3 access-control rule for
            // OwnershipControls) must not additionally raise the generic Fatal -
            // the same exclusion the extension-fragment path applies.
            if extension_required_covered_by_dedicated_rule(rtype, req) {
                continue;
            }
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

    // additionalProperties on the branch
    if effective_sub.additional_properties == Some(false) && !effective_sub.properties.is_empty() {
        let known: std::collections::HashSet<&str> = effective_sub.properties.keys().map(|s| s.as_str()).collect();
        let pattern_matchers: Vec<Option<std::sync::Arc<CompiledPattern>>> =
            effective_sub.pattern_properties.keys().map(|p| compile_pattern(p)).collect();
        for key in actual_keys {
            if known.contains(key.as_str()) {
                continue;
            }
            let allowed_by_pattern =
                pattern_matchers.iter().any(|matcher| matcher.as_ref().is_none_or(|re| re.is_match(key)));
            if allowed_by_pattern {
                continue;
            }
            out.push(build_diagnostic(
                "F3002",
                &format!("Additional properties are not allowed ('{}' was unexpected)", key),
                m,
                rid,
                &format!("{}.{}", base_path, key),
                None,
            ));
        }
    }

    validate_sub_dependencies(out, m, rid, actual_keys, effective_sub, base_path);

    validate_required_groups(
        out,
        m,
        rid,
        actual_keys,
        &effective_sub.required_or,
        &effective_sub.required_xor,
        base_path,
    );

    // Value-level matching: check each property constraint in the branch against
    // the concrete resolved values at base_path. This allows anyOf/oneOf branches
    // to discriminate by type, enum, const, numeric bounds, pattern, etc.
    validate_sub_value_constraints(out, m, rid, effective_sub, defs, base_path);

    // Draft-07 conditional constraints inside the branch: the instance must
    // satisfy `then` when the condition holds and `else` otherwise. Evaluated
    // recursively so a branch that consists of `if`/`then`/`else` participates
    // in anyOf/oneOf matching per draft-07 instead of matching vacuously.
    // Bundled conditionals stay dependencies-only here too (see
    // `IfThenElse::enforce_full_branch`).
    for ite in &effective_sub.if_then_else {
        let matches = condition_matches_at(&ite.condition, actual_keys, m, rid, defs, base_path);
        let branch = if matches { &ite.then_schema } else { &ite.else_schema };
        if let Some(branch_schema) = branch {
            if ite.enforce_full_branch {
                validate_sub(out, m, rid, rtype, actual_keys, branch_schema, defs, base_path, depth + 1);
            } else {
                validate_sub_dependencies(out, m, rid, actual_keys, branch_schema, base_path);
            }
        }
    }
}

/// Maximum depth for recursive `schema_value_matches` calls through nested
/// composition (allOf/anyOf/oneOf) and items. Prevents unbounded recursion
/// from cyclic or deeply nested schemas.
const MAX_MATCH_DEPTH: usize = 16;

/// Returns `true` when `value` satisfies all representable constraints in
/// `schema`. Designed for branch matching: when no satisfiable scenario
/// produces a matching value, the branch is non-matching.
///
/// Conservative: returns `true` (match) when a constraint cannot be evaluated
/// (e.g. a pattern that won't compile, an unknown format, a dynamic/opaque
/// value). The caller must never invent a mismatch from uncertainty.
fn schema_value_matches(
    value: &serde_json::Value,
    schema: &PropSchema,
    defs: &HashMap<String, PropSchema>,
    depth: usize,
) -> bool {
    schema_value_failure_reasons(value, schema, defs, depth, "").is_empty()
}

fn evaluate_value_composition_branches(
    value: &serde_json::Value,
    branches: &[SubSchema],
    defs: &HashMap<String, PropSchema>,
    property_path: &str,
) -> Vec<CompositionBranchEvaluation> {
    branches
        .iter()
        .enumerate()
        .map(|(index, branch)| {
            let failure_reasons = schema_value_failure_reasons(value, branch, defs, 0, property_path);
            let matched = failure_reasons.is_empty();
            CompositionBranchEvaluation::new(
                index + 1,
                matched,
                required_property_combinations(branch, defs, None),
                failure_reasons,
            )
        })
        .collect()
}

fn schema_value_failure_reasons(
    value: &serde_json::Value,
    schema: &PropSchema,
    defs: &HashMap<String, PropSchema>,
    depth: usize,
    property_path: &str,
) -> Vec<CompositionFailureReason> {
    if depth > MAX_MATCH_DEPTH || value.is_null() {
        return Vec::new();
    }

    let resolved;
    let effective = if schema.ref_name.is_some() {
        resolved = schema.resolve(defs);
        if resolved.ref_name.is_some() {
            return vec![CompositionFailureReason::new(
                format!(
                    "Composition branch references undefined definition '{}'",
                    schema.ref_name.as_deref().unwrap_or("")
                ),
                property_path,
            )];
        }
        &*resolved
    } else {
        schema
    };

    let mut reasons = Vec::new();
    if let Some(ref expected_type) = effective.prop_type
        && !type_matches(value, expected_type)
    {
        let coercible = expected_type
            .primary()
            .is_some_and(|expected| matches!(coerce_value(value, expected), CoerceResult::Coerced(_, _)));
        if !coercible {
            reasons.push(CompositionFailureReason::new(
                format!(
                    "{} has type '{}', expected type '{}'",
                    format_value(value),
                    json_value_type(value),
                    expected_type.names().collect::<Vec<_>>().join("|")
                ),
                property_path,
            ));
            return reasons;
        }
    }

    if !effective.enum_values.is_empty() && !enum_matches(value, &effective.enum_values) {
        reasons.push(CompositionFailureReason::new(
            format!("{} is not one of {}", format_value(value), format_allowed_values(&effective.enum_values)),
            property_path,
        ));
    }
    if !effective.enum_case_insensitive.is_empty()
        && !enum_matches_case_insensitive(value, &effective.enum_case_insensitive)
    {
        reasons.push(CompositionFailureReason::new(
            format!(
                "{} is not one of {} (case-insensitive)",
                format_value(value),
                format_allowed_values(&effective.enum_case_insensitive)
            ),
            property_path,
        ));
    }
    if !effective.not_enum.is_empty() && enum_matches(value, &effective.not_enum) {
        reasons.push(CompositionFailureReason::new(
            format!("{} must not be one of {}", format_value(value), format_allowed_values(&effective.not_enum)),
            property_path,
        ));
    }
    if let Some(ref expected) = effective.const_value
        && !scalar_eq(value, expected)
    {
        reasons.push(CompositionFailureReason::new(
            format!("{} must equal {}", format_value(value), format_value(expected)),
            property_path,
        ));
    }
    if let Some(ref pattern) = effective.pattern
        && let Some(compiled) = compile_pattern(pattern)
        && let Some(actual) = coerce_to_string(value)
        && !actual.contains("${")
        && !compiled.is_match(&actual)
    {
        reasons.push(CompositionFailureReason::new(
            format!("{} does not match pattern '{pattern}'", format_value(value)),
            property_path,
        ));
    }
    if let Some(ref format) = effective.format
        && let Some(actual) = coerce_to_string(value)
        && !actual.contains("${")
        && !format_value_matches(&actual, format)
    {
        reasons.push(CompositionFailureReason::new(
            format!("{} does not match format '{format}'", format_value(value)),
            property_path,
        ));
    }

    if let Some(number) = coerce_to_number(value) {
        if let Some(maximum) = effective.maximum
            && number > maximum
        {
            reasons.push(CompositionFailureReason::new(format!("{number} exceeds maximum {maximum}"), property_path));
        }
        if let Some(minimum) = effective.minimum
            && number < minimum
        {
            reasons.push(CompositionFailureReason::new(format!("{number} is below minimum {minimum}"), property_path));
        }
        if let Some(maximum) = effective.exclusive_maximum
            && number >= maximum
        {
            reasons.push(CompositionFailureReason::new(format!("{number} must be less than {maximum}"), property_path));
        }
        if let Some(minimum) = effective.exclusive_minimum
            && number <= minimum
        {
            reasons
                .push(CompositionFailureReason::new(format!("{number} must be greater than {minimum}"), property_path));
        }
        if let Some(multiple) = effective.multiple_of
            && multiple > 0.0
        {
            let remainder = (number / multiple).round() * multiple - number;
            let epsilon = multiple * 1e-9;
            if remainder.abs() > epsilon && (multiple - remainder.abs()).abs() > epsilon {
                reasons.push(CompositionFailureReason::new(
                    format!("{number} is not a multiple of {multiple}"),
                    property_path,
                ));
            }
        }
    }

    if (effective.min_length.is_some() || effective.max_length.is_some())
        && let Some(actual) = coerce_to_string(value)
        && !actual.contains("${")
    {
        let length = actual.chars().count() as u64;
        if let Some(maximum) = effective.max_length
            && length > maximum
        {
            reasons.push(CompositionFailureReason::new(
                format!("String length {length} exceeds maximum {maximum}"),
                property_path,
            ));
        }
        if let Some(minimum) = effective.min_length
            && length < minimum
        {
            reasons.push(CompositionFailureReason::new(
                format!("String length {length} is below minimum {minimum}"),
                property_path,
            ));
        }
    }

    if let Some(items) = value.as_array() {
        let length = items.iter().filter(|item| !item.is_null()).count() as u64;
        if let Some(maximum) = effective.max_items
            && length > maximum
        {
            reasons.push(CompositionFailureReason::new(
                format!("Array length {length} exceeds maximum {maximum}"),
                property_path,
            ));
        }
        if let Some(minimum) = effective.min_items
            && length < minimum
        {
            reasons.push(CompositionFailureReason::new(
                format!("Array length {length} is below minimum {minimum}"),
                property_path,
            ));
        }
        if effective.unique_items == Some(true) {
            let mut duplicate_found = false;
            for (index, item) in items.iter().enumerate() {
                if item.is_null() {
                    continue;
                }
                if items[..index].iter().any(|previous| !previous.is_null() && previous == item) {
                    duplicate_found = true;
                    break;
                }
            }
            if duplicate_found {
                reasons.push(CompositionFailureReason::new("Array items must be unique", property_path));
            }
        }
        if let Some(ref item_schema) = effective.items {
            for (index, item) in items.iter().enumerate() {
                if !schema_value_matches(item, item_schema, defs, depth + 1) {
                    let item_path = append_property_path(property_path, &index.to_string());
                    reasons.extend(schema_value_failure_reasons(item, item_schema, defs, depth + 1, &item_path));
                }
            }
        }
    }

    if let Some(object) = value.as_object() {
        let property_count = object.len() as u64;
        if let Some(maximum) = effective.max_properties
            && property_count > maximum
        {
            reasons.push(CompositionFailureReason::new(
                format!("Object has {property_count} properties, maximum is {maximum}"),
                property_path,
            ));
        }
        if let Some(minimum) = effective.min_properties
            && property_count < minimum
        {
            reasons.push(CompositionFailureReason::new(
                format!("Object has {property_count} properties, minimum is {minimum}"),
                property_path,
            ));
        }
        for required in &effective.required {
            if !object.contains_key(required) {
                reasons
                    .push(CompositionFailureReason::new(format!("'{required}' is a required property"), property_path));
            }
        }
        for (trigger, dependencies) in &effective.dependent_required {
            if object.contains_key(trigger) {
                for dependency in dependencies {
                    if !object.contains_key(dependency) {
                        reasons.push(CompositionFailureReason::new(
                            format!("'{dependency}' is a dependency of '{trigger}'"),
                            property_path,
                        ));
                    }
                }
            }
        }
        for (trigger, excluded) in &effective.dependent_excluded {
            if object.contains_key(trigger) {
                for property in excluded {
                    if object.contains_key(property) {
                        reasons.push(CompositionFailureReason::new(
                            format!("'{property}' should not be included with '{trigger}'"),
                            append_property_path(property_path, property),
                        ));
                    }
                }
            }
        }
        if !effective.required_or.is_empty()
            && !effective
                .required_or
                .iter()
                .any(|property| object.get(property.as_str()).is_some_and(|candidate| !candidate.is_null()))
        {
            reasons.push(CompositionFailureReason::new(
                format!(
                    "At least one of {} is required",
                    effective.required_or.iter().map(|property| format!("'{property}'")).collect::<Vec<_>>().join(", ")
                ),
                property_path,
            ));
        }
        if !effective.required_xor.is_empty() {
            let present = effective
                .required_xor
                .iter()
                .filter(|property| object.get(property.as_str()).is_some_and(|candidate| !candidate.is_null()))
                .count();
            if present != 1 {
                reasons.push(CompositionFailureReason::new(
                    format!(
                        "Exactly one of {} is required, but {present} are present",
                        effective
                            .required_xor
                            .iter()
                            .map(|property| format!("'{property}'"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    property_path,
                ));
            }
        }
        if effective.additional_properties == Some(false)
            && (!effective.properties.is_empty() || !effective.pattern_properties.is_empty())
        {
            let pattern_matchers: Vec<Option<Arc<CompiledPattern>>> =
                effective.pattern_properties.keys().map(|pattern| compile_pattern(pattern)).collect();
            for property in object.keys() {
                if effective.properties.contains_key(property) {
                    continue;
                }
                let allowed = pattern_matchers
                    .iter()
                    .any(|matcher| matcher.as_ref().is_none_or(|compiled| compiled.is_match(property)));
                if !allowed {
                    reasons.push(CompositionFailureReason::new(
                        format!("Additional property '{property}' is not allowed"),
                        append_property_path(property_path, property),
                    ));
                }
            }
        }
        for (property, property_schema) in &effective.properties {
            if let Some(property_value) = object.get(property)
                && !schema_value_matches(property_value, property_schema, defs, depth + 1)
            {
                let child_path = append_property_path(property_path, property);
                reasons.extend(schema_value_failure_reasons(
                    property_value,
                    property_schema,
                    defs,
                    depth + 1,
                    &child_path,
                ));
            }
        }
    }

    for branch in &effective.all_of {
        if !schema_value_matches(value, branch, defs, depth + 1) {
            reasons.extend(schema_value_failure_reasons(value, branch, defs, depth + 1, property_path));
        }
    }
    if !effective.any_of.is_empty()
        && !effective.any_of.iter().any(|branch| schema_value_matches(value, branch, defs, depth + 1))
    {
        for branch in &effective.any_of {
            reasons.extend(schema_value_failure_reasons(value, branch, defs, depth + 1, property_path));
        }
    }
    if !effective.one_of.is_empty() {
        let matching: Vec<usize> = effective
            .one_of
            .iter()
            .enumerate()
            .filter_map(|(index, branch)| schema_value_matches(value, branch, defs, depth + 1).then_some(index + 1))
            .collect();
        if matching.is_empty() {
            for branch in &effective.one_of {
                reasons.extend(schema_value_failure_reasons(value, branch, defs, depth + 1, property_path));
            }
        } else if matching.len() > 1 {
            reasons.push(CompositionFailureReason::new(
                format!(
                    "Value matches nested oneOf branches {}; exactly one must match",
                    render_branch_numbers(&matching)
                ),
                property_path,
            ));
        }
    }
    for conditional in effective.if_then_else.iter().filter(|conditional| conditional.enforce_full_branch) {
        if let Some(object) = value.as_object() {
            let object_keys: Vec<String> = object.keys().cloned().collect();
            let condition_matches =
                condition_schema_value_matches(&conditional.condition, object, &object_keys, defs, depth + 1);
            let branch = if condition_matches { &conditional.then_schema } else { &conditional.else_schema };
            if let Some(branch_schema) = branch
                && !schema_value_matches(value, branch_schema, defs, depth + 1)
            {
                reasons.extend(schema_value_failure_reasons(value, branch_schema, defs, depth + 1, property_path));
            }
        }
    }

    deduplicate_composition_reasons(reasons)
}

fn append_property_path(base: &str, segment: &str) -> String {
    if base.is_empty() { segment.to_string() } else { format!("{base}.{segment}") }
}

fn json_value_type(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(number) if number.is_i64() || number.is_u64() => "integer",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Evaluate a `ConditionSchema` against a concrete object value for use in
/// `schema_value_matches`. Mirrors the logic of `condition_matches` but
/// operates on concrete JSON values rather than the semantic model.
fn condition_schema_value_matches(
    cond: &ConditionSchema,
    obj: &serde_json::Map<String, serde_json::Value>,
    obj_keys: &[String],
    defs: &HashMap<String, PropSchema>,
    depth: usize,
) -> bool {
    if depth > MAX_MATCH_DEPTH {
        return true; // conservative
    }

    // anyOf conditions
    if !cond.any_of.is_empty() {
        return cond.any_of.iter().any(|sub| condition_schema_value_matches(sub, obj, obj_keys, defs, depth + 1));
    }

    // The instance evaluated here is always a JSON object, so a condition
    // stating any other `type` cannot match.
    if let Some(ref required_type) = cond.prop_type
        && !required_type.names().any(|name| name == "object")
    {
        return false;
    }

    // required keys
    for req in &cond.required {
        if !obj_keys.iter().any(|k| k == req) {
            return false;
        }
    }

    // property constraints
    for (prop_name, prop_schema) in &cond.properties {
        let resolved = prop_schema.resolve(defs);
        if let Some(prop_value) = obj.get(prop_name) {
            if !schema_value_matches(prop_value, &resolved, defs, depth + 1) {
                return false;
            }
        } else {
            // Property not present but the condition constrains it - only fail
            // if the constraint is a concrete value check (enum/const/pattern).
            let has_value_constraint = !resolved.enum_values.is_empty()
                || !resolved.enum_case_insensitive.is_empty()
                || resolved.const_value.is_some()
                || resolved.pattern.is_some();
            if has_value_constraint {
                return false;
            }
        }
    }

    true
}

/// Check value-level constraints in a composition branch against the concrete
/// resolved values at `base_path`. This produces a synthetic diagnostic into
/// `out` when no satisfiable scenario matches the branch's property value
/// constraints - making the branch non-matching for anyOf/oneOf evaluation.
///
/// Called after structural checks (required/additional/dependencies) so that
/// structural failures are not duplicated: if structural checks already failed,
/// this function still runs to add value mismatches but only emits them if the
/// branch has property-level constraints that go beyond structure.
fn validate_sub_value_constraints(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    rid: &str,
    sub: &SubSchema,
    defs: &HashMap<String, PropSchema>,
    base_path: &str,
) {
    // Only check if the branch has property constraints with value-level fields.
    // Branches that only define required/additionalProperties at the branch
    // level are already fully covered by the structural checks above. The
    // per-field predicate is exhaustive (`PropSchema::constrains_value`), so a
    // constraint field can never be silently skipped here.
    let has_value_constraints =
        sub.properties.values().any(|ps| ps.resolve(defs).constrains_value()) || sub_self_constrains_value(sub);
    if !has_value_constraints {
        return;
    }

    // Check per-property value constraints in the branch
    for (prop_name, prop_schema) in &sub.properties {
        let resolved = prop_schema.resolve(defs);
        let prop_path = format!("{}.{}", base_path, prop_name);
        // Only scenarios consistent with the active group assignment (if any)
        // participate: a value from a mutually exclusive `Fn::If` branch must
        // not decide this assignment's branch match.
        let scenarios: Vec<(serde_json::Value, HashMap<String, bool>)> = m
            .resolve_scenarios_json(rid, &prop_path)
            .into_iter()
            .filter(|(_, conds)| scenario_consistent_with_filter(m, conds))
            .collect();

        // When the property is absent from the template and not required, it
        // does not contribute a mismatch - the constraint is vacuously true.
        if scenarios.is_empty() {
            continue;
        }

        // Check if ANY satisfiable scenario matches the branch constraint
        let any_scenario_matches = scenarios.iter().any(|(val, conds)| {
            if !is_satisfiable(m, conds) || val.is_null() {
                return true; // conservative: unsatisfiable or null doesn't cause mismatch
            }
            schema_value_matches(val, &resolved, defs, 0)
        });

        if !any_scenario_matches {
            // This diagnostic remains internal to an anyOf/oneOf decision and is
            // surfaced directly only for allOf. Preserve the concrete constraint
            // failure so the primary composition finding can explain this branch.
            let (offending, failure_detail) = scenarios
                .iter()
                .find(|(val, conds)| is_satisfiable(m, conds) && !val.is_null())
                .map(|(val, _)| {
                    let reasons = schema_value_failure_reasons(val, &resolved, defs, 0, &prop_path);
                    (format_value(val), render_composition_reasons(&reasons, &prop_path))
                })
                .unwrap_or_else(|| ("Value".to_string(), describe_prop_constraints(&resolved)));
            out.push(build_diagnostic(
                "F3017",
                &format!(
                    "{offending} at '{prop_name}' does not satisfy the composition branch constraint ({}): {failure_detail}",
                    describe_prop_constraints(&resolved)
                ),
                m,
                rid,
                &prop_path,
                None,
            ));
        }
    }

    // Also check branch-level scalar constraints (type/enum/const on the branch
    // itself, not on a named property - used when the branch constrains the value
    // at the composition point rather than a sub-property).
    let branch_has_scalar_self_constraint = sub_self_constrains_value(sub);
    if branch_has_scalar_self_constraint {
        let scenarios: Vec<(serde_json::Value, HashMap<String, bool>)> = m
            .resolve_scenarios_json(rid, base_path)
            .into_iter()
            .filter(|(_, conds)| scenario_consistent_with_filter(m, conds))
            .collect();
        if !scenarios.is_empty() {
            let any_scenario_matches = scenarios.iter().any(|(val, conds)| {
                if !is_satisfiable(m, conds) || val.is_null() {
                    return true;
                }
                schema_value_matches(val, sub, defs, 0)
            });
            if !any_scenario_matches {
                let (offending, failure_detail) = scenarios
                    .iter()
                    .find(|(val, conds)| is_satisfiable(m, conds) && !val.is_null())
                    .map(|(val, _)| {
                        let reasons = schema_value_failure_reasons(val, sub, defs, 0, base_path);
                        (format_value(val), render_composition_reasons(&reasons, base_path))
                    })
                    .unwrap_or_else(|| ("Value".to_string(), describe_prop_constraints(sub)));
                out.push(build_diagnostic(
                    "F3017",
                    &format!(
                        "{offending} does not satisfy the composition branch constraint ({}): {failure_detail}",
                        describe_prop_constraints(sub)
                    ),
                    m,
                    rid,
                    base_path,
                    None,
                ));
            }
        }
    }
}

/// The distinct template-condition assignments under which an `anyOf`/`oneOf`
/// group must be decided. Delegates to the generic `property_scenario_assignments`
/// helper with the union of property paths referenced by all branches.
fn branch_scenario_assignments<'a>(
    m: &Arc<SemanticModel>,
    rid: &str,
    branches: impl Iterator<Item = &'a SubSchema>,
    base_path: &str,
) -> Option<Vec<HashMap<String, bool>>> {
    let mut property_names: Vec<&String> = Vec::new();
    for branch in branches {
        property_names.extend(branch.properties.keys());
        property_names.extend(&branch.required_or);
        property_names.extend(&branch.required_xor);
    }
    property_names.sort();
    property_names.dedup();

    let paths: Vec<String> = property_names.iter().map(|name| format!("{}.{}", base_path, name)).collect();
    let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    property_scenario_assignments(m, rid, base_path, &refs)
}

/// The scenario tag for a group diagnostic: `None` for the unconditional
/// assignment (matching the untagged diagnostics emitted before scenario-aware
/// grouping), the assignment itself otherwise.
fn assignment_condition_map(assignment: &HashMap<String, bool>) -> Option<HashMap<String, bool>> {
    if assignment.is_empty() { None } else { Some(assignment.clone()) }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompositionKind {
    AnyOf,
    OneOf,
}

impl CompositionKind {
    fn name(self) -> &'static str {
        match self {
            CompositionKind::AnyOf => "anyOf",
            CompositionKind::OneOf => "oneOf",
        }
    }

    fn expected_constraint(self) -> &'static str {
        match self {
            CompositionKind::AnyOf => "at least one anyOf branch",
            CompositionKind::OneOf => "exactly one oneOf branch",
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct CompositionFailureReason {
    message: String,
    property_path: String,
}

impl CompositionFailureReason {
    fn new(message: impl Into<String>, property_path: impl Into<String>) -> Self {
        Self { message: message.into(), property_path: property_path.into() }
    }
}

#[derive(Clone, Debug)]
struct CompositionBranchEvaluation {
    branch: usize,
    matched: bool,
    required_property_combinations: Vec<Vec<String>>,
    failure_reasons: Vec<CompositionFailureReason>,
}

impl CompositionBranchEvaluation {
    fn new(
        branch: usize,
        matched: bool,
        mut required_property_combinations: Vec<Vec<String>>,
        failure_reasons: Vec<CompositionFailureReason>,
    ) -> Self {
        for combination in &mut required_property_combinations {
            combination.sort();
            combination.dedup();
        }
        required_property_combinations.retain(|combination| !combination.is_empty());
        required_property_combinations.sort();
        required_property_combinations.dedup();
        Self {
            branch,
            matched,
            required_property_combinations,
            failure_reasons: deduplicate_composition_reasons(failure_reasons),
        }
    }
}

fn deduplicate_composition_reasons(mut reasons: Vec<CompositionFailureReason>) -> Vec<CompositionFailureReason> {
    reasons.sort();
    reasons.dedup();
    reasons
}

#[allow(clippy::too_many_arguments)]
fn evaluate_object_composition_branches(
    m: &Arc<SemanticModel>,
    rid: &str,
    rtype: &str,
    actual_keys: &[String],
    branches: &[SubSchema],
    defs: &HashMap<String, PropSchema>,
    base_path: &str,
    assignment: &HashMap<String, bool>,
) -> Vec<CompositionBranchEvaluation> {
    branches
        .iter()
        .enumerate()
        .map(|(index, branch)| {
            let mut branch_diagnostics = Vec::new();
            validate_sub_under_assignment(
                &mut branch_diagnostics,
                m,
                rid,
                rtype,
                actual_keys,
                branch,
                defs,
                base_path,
                assignment,
            );
            let matched = branch_diagnostics.is_empty();
            let mut failure_reasons: Vec<CompositionFailureReason> = branch_diagnostics
                .into_iter()
                .map(|diagnostic| {
                    CompositionFailureReason::new(
                        diagnostic.message,
                        diagnostic.property_path.unwrap_or_else(|| base_path.to_string()),
                    )
                })
                .collect();
            if !matched && failure_reasons.is_empty() {
                failure_reasons.push(CompositionFailureReason::new("The branch schema was not satisfied", base_path));
            }
            CompositionBranchEvaluation::new(
                index + 1,
                matched,
                required_property_combinations(branch, defs, Some(rtype)),
                failure_reasons,
            )
        })
        .collect()
}

fn required_property_combinations(
    branch: &SubSchema,
    defs: &HashMap<String, PropSchema>,
    rtype: Option<&str>,
) -> Vec<Vec<String>> {
    let resolved;
    let effective = if branch.ref_name.is_some() {
        resolved = branch.resolve(defs);
        if resolved.ref_name.is_some() {
            return Vec::new();
        }
        &*resolved
    } else {
        branch
    };

    let mut base: Vec<String> = effective
        .required
        .iter()
        .filter(|property| {
            rtype.is_none_or(|resource_type| !extension_required_covered_by_dedicated_rule(resource_type, property))
        })
        .cloned()
        .collect();
    base.sort();
    base.dedup();

    let mut combinations = vec![base];
    expand_required_choice_group(&mut combinations, &effective.required_or, false);
    expand_required_choice_group(&mut combinations, &effective.required_xor, true);
    if effective.required.is_empty() && effective.required_or.is_empty() && effective.required_xor.is_empty() {
        return Vec::new();
    }
    combinations
}

fn expand_required_choice_group(combinations: &mut Vec<Vec<String>>, choices: &[String], exactly_one: bool) {
    if choices.is_empty() {
        return;
    }
    let mut expanded = Vec::new();
    for combination in combinations.iter() {
        let present = choices.iter().filter(|choice| combination.contains(choice)).count();
        if present > 0 {
            if !exactly_one || present == 1 {
                expanded.push(combination.clone());
            }
            continue;
        }
        for choice in choices {
            let mut candidate = combination.clone();
            candidate.push(choice.clone());
            expanded.push(candidate);
        }
    }
    *combinations = expanded;
}

#[allow(clippy::too_many_arguments)]
fn build_composition_diagnostic(
    rule_id: &str,
    kind: CompositionKind,
    evaluations: &[CompositionBranchEvaluation],
    m: &Arc<SemanticModel>,
    rid: &str,
    property_path: &str,
    resource_type: Option<&str>,
    actual_value: Option<&serde_json::Value>,
    condition_scenario: Option<HashMap<String, bool>>,
) -> Diagnostic {
    let matching_branches: Vec<usize> =
        evaluations.iter().filter(|evaluation| evaluation.matched).map(|evaluation| evaluation.branch).collect();
    let match_count = matching_branches.len();
    let branch_count = evaluations.len();
    let match_outcome = if match_count == 0 { "zeroMatches" } else { "multipleMatches" };

    let target = resource_type.map(|rtype| format!(" for {rtype}")).unwrap_or_default();
    let mut message = match (kind, match_count) {
        (CompositionKind::AnyOf, _) => format!(
            "Value is not valid under any of the {branch_count} anyOf schemas{target} (0 branches matched; at least one is required)."
        ),
        (CompositionKind::OneOf, 0) => format!(
            "Value is not valid under any of the {branch_count} oneOf schemas{target} (0 branches matched; exactly one is required)."
        ),
        (CompositionKind::OneOf, _) => format!(
            "Value is valid under more than one of the {branch_count} oneOf schemas{target} ({match_count} branches matched; exactly one is required). Matching branches: {}.",
            render_branch_numbers(&matching_branches)
        ),
    };

    let mut valid_combinations: Vec<Vec<String>> =
        evaluations.iter().flat_map(|evaluation| evaluation.required_property_combinations.iter().cloned()).collect();
    valid_combinations.sort();
    valid_combinations.dedup();
    if !valid_combinations.is_empty() {
        message.push_str(" Required property combinations: ");
        message.push_str(
            &valid_combinations
                .iter()
                .map(|combination| {
                    format!(
                        "[{}]",
                        combination.iter().map(|property| format!("'{property}'")).collect::<Vec<_>>().join(", ")
                    )
                })
                .collect::<Vec<_>>()
                .join(" or "),
        );
        message.push('.');
    }

    if match_count == 0 {
        let failure_summaries: Vec<String> = evaluations
            .iter()
            .filter(|evaluation| !evaluation.matched)
            .map(|evaluation| {
                let reasons = render_composition_reasons(&evaluation.failure_reasons, property_path);
                format!("branch {}: {reasons}", evaluation.branch)
            })
            .collect();
        if !failure_summaries.is_empty() {
            message.push_str(" Branch failures: ");
            message.push_str(&failure_summaries.join("; "));
            message.push('.');
        }
    }

    let mut extra = HashMap::new();
    extra.insert("compositionKind".to_string(), serde_json::json!(kind.name()).into());
    extra.insert("matchOutcome".to_string(), serde_json::json!(match_outcome).into());
    extra.insert("branchCount".to_string(), serde_json::json!(branch_count).into());
    extra.insert("matchCount".to_string(), serde_json::json!(match_count).into());
    if !valid_combinations.is_empty() {
        extra.insert("validPropertyCombinations".to_string(), serde_json::json!(valid_combinations).into());
    }
    if !matching_branches.is_empty() {
        extra.insert("matchingBranches".to_string(), serde_json::json!(matching_branches).into());
    }
    let branch_failures: Vec<serde_json::Value> = evaluations
        .iter()
        .filter(|evaluation| !evaluation.matched)
        .map(|evaluation| {
            let reasons: Vec<serde_json::Value> = evaluation
                .failure_reasons
                .iter()
                .map(|reason| {
                    serde_json::json!({
                        "message": reason.message,
                        "propertyPath": reason.property_path,
                    })
                })
                .collect();
            serde_json::json!({
                "branch": evaluation.branch,
                "reasons": reasons,
            })
        })
        .collect();
    if !branch_failures.is_empty() {
        extra.insert("branchFailures".to_string(), serde_json::json!(branch_failures).into());
    }

    let mut diagnostic =
        build_diagnostic_conditional(rule_id, &message, m, rid, property_path, None, condition_scenario);
    diagnostic.context = Some(ViolationContext {
        actual_value: actual_value.cloned().map(Into::into),
        expected_constraint: Some(kind.expected_constraint().to_string()),
        property: None,
        lifecycle: None,
        resolution_source: None,
        extra: Some(extra),
    });
    diagnostic
}

fn render_branch_numbers(branches: &[usize]) -> String {
    branches.iter().map(usize::to_string).collect::<Vec<_>>().join(", ")
}

fn render_composition_reasons(reasons: &[CompositionFailureReason], default_path: &str) -> String {
    reasons
        .iter()
        .map(|reason| {
            if reason.property_path.is_empty() || reason.property_path == default_path {
                reason.message.clone()
            } else {
                format!("at '{}': {}", reason.property_path, reason.message)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Runs `validate_sub` restricted to one condition assignment: only value
/// scenarios consistent with `assignment` participate in branch matching, so a
/// value from a mutually exclusive `Fn::If` branch cannot decide this one.
///
/// Preserves and restores any previously active SCENARIO_FILTER so that nested
/// composition (e.g. requiredXor inside a oneOf branch inside an outer oneOf)
/// retains the outer constraint rather than clearing it.
#[allow(clippy::too_many_arguments)]
fn validate_sub_under_assignment(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    rid: &str,
    rtype: &str,
    actual_keys: &[String],
    sub: &SubSchema,
    defs: &HashMap<String, PropSchema>,
    base_path: &str,
    assignment: &HashMap<String, bool>,
) {
    SCENARIO_FILTER.with(|filter| {
        let previous = filter.borrow().clone();
        // Merge the new assignment with any existing outer filter using
        // conflict-safe merge: never overwrite a contradictory prior condition.
        let merged = match &previous {
            Some(outer) => {
                let mut combined = outer.clone();
                for (k, v) in assignment {
                    if let Some(prev) = combined.get(k) {
                        if prev != v {
                            // Contradictory: skip this assignment entirely.
                            return;
                        }
                    } else {
                        combined.insert(k.clone(), *v);
                    }
                }
                combined
            }
            None => assignment.clone(),
        };
        *filter.borrow_mut() = Some(merged);
        validate_sub(out, m, rid, rtype, actual_keys, sub, defs, base_path, 0);
        *filter.borrow_mut() = previous;
    });
}

thread_local! {
    /// Resource paths where exact conditional schema analysis exceeded its work
    /// budget. Kept separately from branch diagnostics so the advisory cannot
    /// make an otherwise matching composition branch appear invalid.
    static SCENARIO_ANALYSIS_CURTAILMENTS: std::cell::RefCell<BTreeSet<(String, String)>> =
        const { std::cell::RefCell::new(BTreeSet::new()) };

    /// The condition assignment the current branch-matching pass is scoped to.
    ///
    /// Threaded as task-local state rather than a parameter because
    /// `validate_sub` recurses through conditional branches and nested
    /// composition, and the filter applies uniformly to every value lookup
    /// underneath one group decision.
    static SCENARIO_FILTER: std::cell::RefCell<Option<HashMap<String, bool>>> = const { std::cell::RefCell::new(None) };
}

/// Whether a value scenario's conditions are consistent with the active
/// assignment (if any): no contradicting keys, and the union satisfiable.
fn scenario_consistent_with_filter(m: &Arc<SemanticModel>, conds: &HashMap<String, bool>) -> bool {
    SCENARIO_FILTER.with(|filter| {
        let borrowed = filter.borrow();
        let Some(assignment) = borrowed.as_ref() else {
            return true;
        };
        for (name, value) in assignment {
            if let Some(scenario_value) = conds.get(name)
                && scenario_value != value
            {
                return false;
            }
        }
        let mut merged = conds.clone();
        for (name, value) in assignment {
            merged.insert(name.clone(), *value);
        }
        is_satisfiable(m, &merged)
    })
}

/// Whether a composition branch states value constraints on the instance
/// itself (rather than on named properties). Destructured exhaustively so a
/// newly added constraint field cannot be silently skipped.
///
/// Structural fields - `properties`, `required`, `additional_properties`,
/// `pattern_properties`, and the dependency maps - are deliberately excluded:
/// `validate_sub` enforces them directly with their own rule IDs, and running
/// the value matcher for them here would double-report. `ref_name` is excluded
/// because the caller resolves the branch before the self-check, and
/// `description` never constrains.
fn sub_self_constrains_value(sub: &PropSchema) -> bool {
    let PropSchema {
        ref_name: _,
        prop_type,
        enum_values,
        enum_case_insensitive,
        not_enum,
        const_value,
        pattern,
        minimum,
        maximum,
        exclusive_minimum,
        exclusive_maximum,
        multiple_of,
        min_length,
        max_length,
        min_items,
        max_items,
        unique_items,
        min_properties,
        max_properties,
        format,
        description: _,
        properties: _,
        required: _,
        required_present: _,
        additional_properties: _,
        pattern_properties: _,
        items,
        all_of,
        any_of,
        one_of,
        if_then_else,
        dependent_required: _,
        dependent_excluded: _,
        required_or: _,
        required_xor: _,
    } = sub;
    prop_type.is_some()
        || !enum_values.is_empty()
        || !enum_case_insensitive.is_empty()
        || !not_enum.is_empty()
        || const_value.is_some()
        || pattern.is_some()
        || minimum.is_some()
        || maximum.is_some()
        || exclusive_minimum.is_some()
        || exclusive_maximum.is_some()
        || multiple_of.is_some()
        || min_length.is_some()
        || max_length.is_some()
        || min_items.is_some()
        || max_items.is_some()
        || unique_items == &Some(true)
        || min_properties.is_some()
        || max_properties.is_some()
        || format.is_some()
        || items.is_some()
        || !all_of.is_empty()
        || !any_of.is_empty()
        || !one_of.is_empty()
        || !if_then_else.is_empty()
}

/// A short, human-readable summary of the constraints a property schema states,
/// for composition-branch diagnostics. Names the checks a value would have to
/// satisfy, most specific first.
fn describe_prop_constraints(schema: &PropSchema) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(ref pt) = schema.prop_type {
        parts.push(format!("type '{}'", pt.names().collect::<Vec<_>>().join("|")));
    }
    if !schema.enum_values.is_empty() {
        parts.push(format!("one of {}", format_allowed_values(&schema.enum_values)));
    }
    if !schema.enum_case_insensitive.is_empty() {
        parts.push(format!("one of {} (case-insensitive)", format_allowed_values(&schema.enum_case_insensitive)));
    }
    if !schema.not_enum.is_empty() {
        parts.push(format!("none of {}", format_allowed_values(&schema.not_enum)));
    }
    if let Some(ref cv) = schema.const_value {
        parts.push(format!("exactly {cv}"));
    }
    if let Some(ref pattern) = schema.pattern {
        parts.push(format!("pattern '{pattern}'"));
    }
    if let Some(min) = schema.minimum {
        parts.push(format!("minimum {min}"));
    }
    if let Some(max) = schema.maximum {
        parts.push(format!("maximum {max}"));
    }
    if let Some(min) = schema.exclusive_minimum {
        parts.push(format!("exclusiveMinimum {min}"));
    }
    if let Some(max) = schema.exclusive_maximum {
        parts.push(format!("exclusiveMaximum {max}"));
    }
    if let Some(mult) = schema.multiple_of {
        parts.push(format!("multipleOf {mult}"));
    }
    if let Some(min) = schema.min_length {
        parts.push(format!("minLength {min}"));
    }
    if let Some(max) = schema.max_length {
        parts.push(format!("maxLength {max}"));
    }
    if let Some(min) = schema.min_items {
        parts.push(format!("minItems {min}"));
    }
    if let Some(max) = schema.max_items {
        parts.push(format!("maxItems {max}"));
    }
    if let Some(min) = schema.min_properties {
        parts.push(format!("minProperties {min}"));
    }
    if let Some(max) = schema.max_properties {
        parts.push(format!("maxProperties {max}"));
    }
    if !schema.required.is_empty() {
        parts.push(format!(
            "requires {}",
            schema.required.iter().map(|p| format!("'{p}'")).collect::<Vec<_>>().join(", ")
        ));
    }
    if schema.items.is_some() {
        parts.push("an item schema".to_string());
    }
    if !schema.properties.is_empty() {
        parts.push("nested property constraints".to_string());
    }
    if !schema.all_of.is_empty() || !schema.any_of.is_empty() || !schema.one_of.is_empty() {
        parts.push("nested composition".to_string());
    }
    if !schema.if_then_else.is_empty() {
        parts.push("a conditional constraint".to_string());
    }
    if parts.is_empty() { "the branch schema".to_string() } else { parts.join(", ") }
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

fn collect_outer_resolved_scenarios(
    value: &ResolvedValue,
    assumptions: &HashMap<String, bool>,
    scenarios: &mut Vec<(ResolvedValue, HashMap<String, bool>)>,
) {
    match value {
        ResolvedValue::Conditional { condition, if_true, if_false } => match assumptions.get(condition) {
            Some(true) => collect_outer_resolved_scenarios(if_true, assumptions, scenarios),
            Some(false) => collect_outer_resolved_scenarios(if_false, assumptions, scenarios),
            None => {
                let mut true_assumptions = assumptions.clone();
                true_assumptions.insert(condition.clone(), true);
                collect_outer_resolved_scenarios(if_true, &true_assumptions, scenarios);
                let mut false_assumptions = assumptions.clone();
                false_assumptions.insert(condition.clone(), false);
                collect_outer_resolved_scenarios(if_false, &false_assumptions, scenarios);
            }
        },
        ResolvedValue::Enum { variants } => {
            for variant in variants {
                collect_outer_resolved_scenarios(variant, assumptions, scenarios);
            }
        }
        _ => scenarios.push((value.clone(), assumptions.clone())),
    }
}

fn outer_resolved_scenarios(
    model: &Arc<SemanticModel>,
    resource_id: &str,
    property_path: &str,
) -> Vec<(ResolvedValue, HashMap<String, bool>)> {
    let Some(value) =
        model.resolve_deep(resource_id, property_path).or_else(|| model.resolve(resource_id, property_path).cloned())
    else {
        return model.resolve_scenarios(resource_id, property_path);
    };
    let mut scenarios = Vec::new();
    collect_outer_resolved_scenarios(&value, &HashMap::new(), &mut scenarios);
    scenarios
}

fn collect_outer_value_scenarios(
    value: &ResolvedValue,
    assumptions: &HashMap<String, bool>,
    scenarios: &mut Vec<(serde_json::Value, HashMap<String, bool>)>,
) {
    match value {
        ResolvedValue::Conditional { condition, if_true, if_false } => match assumptions.get(condition) {
            Some(true) => collect_outer_value_scenarios(if_true, assumptions, scenarios),
            Some(false) => collect_outer_value_scenarios(if_false, assumptions, scenarios),
            None => {
                let mut true_assumptions = assumptions.clone();
                true_assumptions.insert(condition.clone(), true);
                collect_outer_value_scenarios(if_true, &true_assumptions, scenarios);
                let mut false_assumptions = assumptions.clone();
                false_assumptions.insert(condition.clone(), false);
                collect_outer_value_scenarios(if_false, &false_assumptions, scenarios);
            }
        },
        ResolvedValue::Enum { variants } => {
            for variant in variants {
                collect_outer_value_scenarios(variant, assumptions, scenarios);
            }
        }
        ResolvedValue::Reference { .. } | ResolvedValue::Dynamic { .. } | ResolvedValue::TypedDynamic { .. } => {}
        ResolvedValue::Concrete { .. } | ResolvedValue::List { .. } | ResolvedValue::Map { .. } => {
            scenarios.push((resolved_value_to_json(value), assumptions.clone()));
        }
    }
}

fn schema_requires_nested_value_scenarios(schema: &PropSchema) -> bool {
    let has_composite_value = |value: &serde_json::Value| value.is_array() || value.is_object();
    schema.min_items.is_some()
        || schema.max_items.is_some()
        || schema.unique_items == Some(true)
        || schema.min_properties.is_some()
        || schema.max_properties.is_some()
        || schema.enum_values.iter().any(has_composite_value)
        || schema.enum_case_insensitive.iter().any(has_composite_value)
        || schema.not_enum.iter().any(has_composite_value)
        || schema.const_value.as_ref().is_some_and(has_composite_value)
}

fn validation_scenarios(
    model: &Arc<SemanticModel>,
    resource_id: &str,
    property_path: &str,
    schema: &PropSchema,
) -> Vec<(serde_json::Value, HashMap<String, bool>)> {
    if schema_requires_nested_value_scenarios(schema) {
        return model.resolve_scenarios_json(resource_id, property_path);
    }
    let Some(value) =
        model.resolve_deep(resource_id, property_path).or_else(|| model.resolve(resource_id, property_path).cloned())
    else {
        return model.resolve_scenarios_json(resource_id, property_path);
    };
    let mut scenarios = Vec::new();
    collect_outer_value_scenarios(&value, &HashMap::new(), &mut scenarios);
    scenarios
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
    region: Option<&str>,
) {
    let scenarios = validation_scenarios(m, rid, prop_path, schema);

    let is_type_exempt = TYPE_CHECK_EXEMPT_PATHS.iter().any(|(rt, pp)| *rt == rtype && *pp == prop_path);

    if scenarios.is_empty() && !is_type_exempt {
        validate_reference_type(out, store, m, rid, prop_path, schema);
    }

    let res_suffix = describe_resolution(m, rid, prop_path).map(|s| format!(" (from {})", s)).unwrap_or_default();

    // Type check - coerce before rejecting since string↔number, string↔boolean,
    // bool→string, number→string are silently coerced at deploy time.
    // Successful coercion → Warn; failed coercion → Fatal.
    if let Some(ref pt) = schema.prop_type
        && !is_type_exempt
    {
        let is_packaging_path = PACKAGING_PROPERTY_PATHS.iter().any(|(rt, pp)| *rt == rtype && *pp == prop_path);
        // Skip type checks for array elements whose parent array or the element itself
        // came from an intrinsic function - those are validated by function-specific rules.
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
            // Skip unresolved/malformed intrinsics - already validated by structure rules
            if is_unresolved_intrinsic(val) {
                continue;
            }
            // Skip packaging properties when value is a string - valid with `package` command
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

    if !schema.enum_case_insensitive.is_empty() {
        for (val, conds) in &scenarios {
            if !is_satisfiable(m, conds) || val.is_null() {
                continue;
            }
            if !enum_matches_case_insensitive(val, &schema.enum_case_insensitive) {
                // Same open-world Warning treatment as the exact-match enum
                // check above; the suffix tells the author any casing of the
                // listed values is accepted.
                out.push(build_diagnostic_conditional(
                    "W3030",
                    &format!(
                        "{}{} is not one of {} (case-insensitive)",
                        format_value(val),
                        res_suffix,
                        format_allowed_values(&schema.enum_case_insensitive)
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

    if !schema.not_enum.is_empty() {
        for (val, conds) in &scenarios {
            if !is_satisfiable(m, conds) || val.is_null() {
                continue;
            }
            if enum_matches(val, &schema.not_enum) {
                out.push(build_diagnostic_conditional(
                    "F3030",
                    &format!("{} must not be one of {}", format_value(val), format_allowed_values(&schema.not_enum)),
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
        validate_format(out, m, rid, prop_path, fmt, &scenarios);
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
        if let Some(mult) = schema.multiple_of
            && mult > 0.0
        {
            // Tolerant check for floating-point multipleOf: compute the
            // remainder and accept if it is within a small epsilon of zero
            // or the divisor itself (handles e.g. 0.3 / 0.1 = 2.9999...).
            let remainder = (n / mult).round() * mult - n;
            let epsilon = mult * 1e-9;
            if remainder.abs() > epsilon && (mult - remainder.abs()).abs() > epsilon {
                out.push(build_diagnostic_conditional(
                    "F3034",
                    &format!("{} is not a multiple of {}", n, mult),
                    m,
                    rid,
                    prop_path,
                    None,
                    condition_map(conds),
                ));
            }
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
            let len = s.chars().count() as u64;
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
            let len = arr.iter().filter(|item| !item.is_null()).count() as u64;
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

    if schema.unique_items == Some(true) {
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
        || !schema.required_or.is_empty()
        || !schema.required_xor.is_empty()
        || !schema.all_of.is_empty()
        || !schema.any_of.is_empty()
        || !schema.one_of.is_empty()
        || !schema.if_then_else.is_empty()
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
                &schema.required_or,
                &schema.required_xor,
                &schema.all_of,
                &schema.any_of,
                &schema.one_of,
                &nested_keys,
                prop_path,
            );
            // Property-level if/then/else on an object property: evaluate the
            // condition against the nested keys and enforce the selected branch
            // - in full for an overlay-stated conditional, dependencies-only
            // for a bundled one (see `IfThenElse::enforce_full_branch`).
            for ite in &schema.if_then_else {
                let matches = condition_matches_at(&ite.condition, &nested_keys, m, rid, defs, prop_path);
                let sub = if matches { &ite.then_schema } else { &ite.else_schema };
                if let Some(sub) = sub {
                    if ite.enforce_full_branch {
                        validate_sub(out, m, rid, rtype, &nested_keys, sub, defs, prop_path, 0);
                    } else {
                        validate_sub_dependencies(out, m, rid, &nested_keys, sub, prop_path);
                    }
                }
            }
        } else if !matches!(m.resolve_deep(rid, prop_path), Some(ResolvedValue::Conditional { .. })) {
            // An empty concrete object has no collected keys, but its object
            // constraints and composition branches still need evaluation.
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
                        &schema.required_or,
                        &schema.required_xor,
                        &schema.all_of,
                        &schema.any_of,
                        &schema.one_of,
                        &keys,
                        prop_path,
                    );
                }
            }
        }

        // Property-level scalar composition: when the value is not an object
        // (nested_keys is empty) but the property schema carries anyOf/oneOf/
        // allOf/if_then_else, validate each concrete scenario against the
        // composition branches using schema_value_matches. This covers schemas
        // like KMS key identifiers where anyOf branches discriminate by format.
        // Skip when any scenario has an array/object value - those are validated
        // through the object-key or items paths instead.
        let has_scalar_composition = !schema.all_of.is_empty()
            || !schema.any_of.is_empty()
            || !schema.one_of.is_empty()
            || !schema.if_then_else.is_empty();
        if has_scalar_composition && nested_keys.is_empty() {
            let has_only_scalars = scenarios.iter().all(|(val, conds)| {
                !is_satisfiable(m, conds)
                    || val.is_null()
                    || is_unresolved_intrinsic(val)
                    || (!val.is_object() && !val.is_array())
            });
            if has_only_scalars {
                validate_prop_composition(out, m, rid, prop_path, schema, defs, &scenarios);
            }
        }
        for (pn, ps) in &schema.properties {
            let resolved = ps.resolve(defs);
            let sub_path = format!("{}.{}", prop_path, pn);
            let sub_scenarios = m.resolve_scenarios_json(rid, &sub_path);
            if !sub_scenarios.is_empty() || m.resolve_deep(rid, &sub_path).is_some() {
                validate_prop(out, store, m, rid, rtype, &sub_path, &resolved, defs, region);
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
                    validate_prop(out, store, m, rid, rtype, &idx_path, &resolved, defs, region);
                }
            } else {
                validate_prop(out, store, m, rid, rtype, &format!("{}.{{}}", prop_path), &resolved, defs, region);
            }
        }
        if !did_per_index && (!resolved.dependent_excluded.is_empty() || !resolved.dependent_required.is_empty()) {
            validate_array_item_constraints(out, m, rid, prop_path, &resolved);
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
            if entries.len() == 1 && is_intrinsic_key(&entries[0].key) {
                return Vec::new();
            }
            for e in &entries {
                keys.insert(e.key.clone());
            }
        }
        Some(ResolvedValue::Concrete { value: ref v }) if is_unresolved_intrinsic(v) => return Vec::new(),
        Some(ResolvedValue::Concrete { value: ref v }) if v.is_object() => {
            for k in v.as_object().unwrap().keys() {
                keys.insert(k.clone());
            }
        }
        _ => {}
    }
    if keys.is_empty() {
        for (val, conds) in &m.resolve_scenarios_json(rid, path) {
            if !is_satisfiable(m, conds) || val.is_null() || is_unresolved_intrinsic(val) {
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

/// Like [`enum_matches`] but string values match regardless of casing;
/// non-string values fall back to exact scalar comparison.
fn enum_matches_case_insensitive(val: &serde_json::Value, allowed: &[serde_json::Value]) -> bool {
    allowed.iter().any(|a| match (a.as_str(), val.as_str()) {
        (Some(allowed_str), Some(val_str)) => allowed_str.eq_ignore_ascii_case(val_str),
        _ => scalar_eq(a, val),
    })
}

fn check_required_not_null(out: &mut Vec<Diagnostic>, m: &Arc<SemanticModel>, rid: &str, base: &str, req: &str) {
    for (value, conds) in &outer_resolved_scenarios(m, rid, &format!("{}.{}", base, req)) {
        if !is_satisfiable(m, conds) {
            continue;
        }
        if matches!(value, ResolvedValue::Concrete { value } if value.is_null()) {
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
    condition_matches_at(cond, actual_keys, m, rid, defs, KEY_PROPERTIES)
}

/// Evaluates a condition schema against the actual keys present at `base_path`.
/// `base_path` is the model path prefix for resolving property values (e.g.
/// `"Properties"` at the resource level, or `"Properties.Config"` for a nested
/// object property).
fn condition_matches_at(
    cond: &ConditionSchema,
    actual_keys: &[String],
    m: &Arc<SemanticModel>,
    rid: &str,
    defs: &HashMap<String, PropSchema>,
    base_path: &str,
) -> bool {
    if !cond.any_of.is_empty() {
        return cond.any_of.iter().any(|sub| condition_matches_at(sub, actual_keys, m, rid, defs, base_path));
    }
    if let Some(ref required_type) = cond.prop_type
        && !required_type.names().any(|name| name == "object")
    {
        return false;
    }
    for required_property in &cond.required {
        if !actual_keys.iter().any(|key| key == required_property)
            || !property_present_under(m, rid, base_path, required_property, &HashMap::new())
        {
            return false;
        }
    }
    for (property_name, property_schema) in &cond.properties {
        let resolved_schema = property_schema.resolve(defs);
        let property_path = format!("{}.{}", base_path, property_name);
        let scenarios = m.resolve_scenarios_json(rid, &property_path);
        let has_concrete_constraint = resolved_schema.pattern.is_some()
            || !resolved_schema.enum_values.is_empty()
            || !resolved_schema.not_enum.is_empty()
            || resolved_schema.const_value.is_some();
        if scenarios.is_empty() {
            if has_concrete_constraint {
                return false;
            }
            continue;
        }
        let reachable_scenarios: Vec<_> = scenarios
            .iter()
            .filter(|(_, conditions)| is_satisfiable(m, conditions) && scenario_consistent_with_filter(m, conditions))
            .collect();
        if reachable_scenarios.is_empty() || reachable_scenarios.iter().all(|(value, _)| value.is_null()) {
            continue;
        }
        for nested_required_property in &resolved_schema.required {
            let nested_path = format!("{}.{}", property_path, nested_required_property);
            let nested_property_exists =
                m.resolve_scenarios_json(rid, &nested_path).iter().any(|(value, conditions)| {
                    is_satisfiable(m, conditions) && scenario_consistent_with_filter(m, conditions) && !value.is_null()
                });
            if !nested_property_exists {
                return false;
            }
        }
        let compiled_pattern = resolved_schema.pattern.as_ref().and_then(|pattern| compile_pattern(pattern));
        if resolved_schema.pattern.is_some() && compiled_pattern.is_none() {
            return false;
        }
        let any_match = reachable_scenarios.iter().any(|(value, _)| {
            if value.is_null() {
                return true;
            }
            if !resolved_schema.enum_values.is_empty() && !enum_matches(value, &resolved_schema.enum_values) {
                return false;
            }
            if !resolved_schema.not_enum.is_empty() && enum_matches(value, &resolved_schema.not_enum) {
                return false;
            }
            if let Some(ref expected) = resolved_schema.const_value
                && !scalar_eq(value, expected)
            {
                return false;
            }
            if let Some(ref pattern) = compiled_pattern
                && !coerce_to_string(value).map(|text| pattern.is_match(&text)).unwrap_or(false)
            {
                return false;
            }
            if let Some(ref expected_type) = resolved_schema.prop_type
                && !type_matches(value, expected_type)
            {
                return false;
            }
            condition_bounds_match(value, &resolved_schema)
        });
        if !any_match {
            return false;
        }
    }
    true
}

/// Whether `val` satisfies the length/count bounds a condition property states.
///
/// Draft-07 scopes each bound to one instance type - `minItems` to arrays,
/// `minLength` to strings, `minProperties` to objects - and an instance of any
/// other type passes vacuously.
fn condition_bounds_match(val: &serde_json::Value, schema: &PropSchema) -> bool {
    if let Some(items) = val.as_array() {
        let len = items.iter().filter(|item| !item.is_null()).count() as u64;
        if schema.min_items.is_some_and(|min| len < min) || schema.max_items.is_some_and(|max| len > max) {
            return false;
        }
    }
    if let Some(text) = val.as_str() {
        let len = text.chars().count() as u64;
        if schema.min_length.is_some_and(|min| len < min) || schema.max_length.is_some_and(|max| len > max) {
            return false;
        }
    }
    if let Some(members) = val.as_object() {
        let len = members.len() as u64;
        if schema.min_properties.is_some_and(|min| len < min) || schema.max_properties.is_some_and(|max| len > max) {
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
                // Parameters are coerced at deploy time - warn rather than error
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

/// Additional format patterns used for composition branch discrimination.
/// These cover formats observed in upstream schemas that appear inside
/// anyOf/oneOf branches (e.g. KMS key identifiers, network CIDRs).
/// Formats already in `FORMAT_PATTERNS` are reused from there.
static BRANCH_FORMAT_PATTERNS: LazyLock<HashMap<&'static str, Arc<CompiledPattern>>> = LazyLock::new(|| {
    let sources: &[(&str, &str)] = &[
        // KMS key ARN: arn:partition:kms:region:account:key/<key-id>, where the
        // key ID is a UUID or a multi-Region `mrk-` + 32 hex digits. An alias ARN
        // (arn:...:alias/<name>) identifies a key just as a key ARN does, and
        // key-identifier properties whose composition carries this format accept
        // alias ARNs, so the ARN branch admits both suffix forms.
        (
            "AWS::KMS::Key.Arn",
            r"^arn:aws[a-zA-Z-]*:kms:[a-z0-9-]+:\d{12}:(key/(mrk-[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})|alias/[a-zA-Z0-9:/_-]{1,250})$",
        ),
        // KMS key ID: standard UUID, multi-Region `mrk-` + 32 hex digits (no
        // dashes), or an alias name - the scalar identifiers KMS accepts for a key
        (
            "AWS::KMS::Key.Id",
            r"^(mrk-[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}|alias/[a-zA-Z0-9:/_-]{1,250})$",
        ),
        // KMS alias name: alias/<name>, at most 256 chars including the prefix
        ("AWS::KMS::Alias.AliasName", r"^alias/[a-zA-Z0-9:/_-]{1,250}$"),
        // Security group name
        ("AWS::EC2::SecurityGroup.Name", SECURITY_GROUP_NAME_PATTERN),
        // IPv4 CIDR notation
        ("ipv4-network", r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$"),
        // IPv6 CIDR notation (simplified - accepts valid hex groups with prefix length)
        ("ipv6-network", r"^[0-9a-fA-F:]+/\d{1,3}$"),
        // ISO 8601 date-time
        ("date-time", r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$"),
        // Timestamp (same as date-time for validation purposes)
        ("timestamp", r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$"),
    ];
    sources.iter().filter_map(|(fmt, pat)| compile_pattern(pat).map(|re| (*fmt, re))).collect()
});

/// Returns true when a string value matches the given format constraint for
/// branch discrimination in `schema_value_matches`. Reuses `FORMAT_PATTERNS`
/// for known diagnostic formats, falls back to `BRANCH_FORMAT_PATTERNS` for
/// composition-specific formats. Unknown formats are treated as annotations
/// (conservative true - no mismatch).
///
/// List-level formats (e.g. `.Ids`, `.Names`) are handled by matching each
/// element against the singular form when the value is a scalar string.
fn format_value_matches(value: &str, format: &str) -> bool {
    // Try the main diagnostic format patterns first
    if let Some(re) = FORMAT_PATTERNS.get(format) {
        return re.is_match(value);
    }
    // Try the branch-discrimination patterns
    if let Some(re) = BRANCH_FORMAT_PATTERNS.get(format) {
        return re.is_match(value);
    }
    // List-level formats: validate individual items against the singular form
    match format {
        "AWS::EC2::SecurityGroup.Ids" => {
            FORMAT_PATTERNS.get("AWS::EC2::SecurityGroup.Id").is_none_or(|re| re.is_match(value))
        }
        "AWS::EC2::SecurityGroup.Names" => {
            FORMAT_PATTERNS.get("AWS::EC2::SecurityGroup.Name").is_none_or(|re| re.is_match(value))
        }
        // json format: value must be syntactically valid JSON
        "json" => serde_json::from_str::<serde_json::Value>(value).is_ok(),
        // Unknown formats are annotations - conservative true
        _ => true,
    }
}

/// Validates property-level composition (anyOf/oneOf/allOf/if_then_else) when
/// the property value is a scalar (no nested object keys). Uses
/// `schema_value_matches` to test each concrete satisfiable scenario against
/// the composition branches, emitting F3017/F3018 diagnostics with condition
/// scenarios. Dynamic/unresolved values are treated conservatively (no false
/// positives).
fn validate_prop_composition(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    rid: &str,
    prop_path: &str,
    schema: &PropSchema,
    defs: &HashMap<String, PropSchema>,
    scenarios: &[(serde_json::Value, HashMap<String, bool>)],
) {
    // allOf: every branch must match for every satisfiable scenario
    for branch in &schema.all_of {
        for (val, conds) in scenarios {
            if !is_satisfiable(m, conds) || val.is_null() || is_unresolved_intrinsic(val) {
                continue;
            }
            if !schema_value_matches(val, branch, defs, 0) {
                out.push(build_diagnostic_conditional(
                    "F3017",
                    "Value does not satisfy allOf constraint",
                    m,
                    rid,
                    prop_path,
                    None,
                    condition_map(conds),
                ));
                break;
            }
        }
    }

    // anyOf: at least one branch must match for each satisfiable scenario
    if !schema.any_of.is_empty() {
        for (val, conds) in scenarios {
            if !is_satisfiable(m, conds) || val.is_null() || is_unresolved_intrinsic(val) {
                continue;
            }
            let evaluations = evaluate_value_composition_branches(val, &schema.any_of, defs, prop_path);
            if evaluations.iter().all(|evaluation| !evaluation.matched) {
                out.push(build_composition_diagnostic(
                    "F3017",
                    CompositionKind::AnyOf,
                    &evaluations,
                    m,
                    rid,
                    prop_path,
                    None,
                    Some(val),
                    condition_map(conds),
                ));
            }
        }
    }

    // oneOf: exactly one branch must match for each satisfiable scenario
    if !schema.one_of.is_empty() {
        for (val, conds) in scenarios {
            if !is_satisfiable(m, conds) || val.is_null() || is_unresolved_intrinsic(val) {
                continue;
            }
            let evaluations = evaluate_value_composition_branches(val, &schema.one_of, defs, prop_path);
            let match_count = evaluations.iter().filter(|evaluation| evaluation.matched).count();
            if match_count != 1 {
                out.push(build_composition_diagnostic(
                    "F3018",
                    CompositionKind::OneOf,
                    &evaluations,
                    m,
                    rid,
                    prop_path,
                    None,
                    Some(val),
                    condition_map(conds),
                ));
            }
        }
    }

    // if/then/else: evaluate condition and enforce the selected branch. Only
    // overlay-stated conditionals participate; bundled ones are owned by
    // dedicated rules (see `IfThenElse::enforce_full_branch`).
    for ite in schema.if_then_else.iter().filter(|ite| ite.enforce_full_branch) {
        for (val, conds) in scenarios {
            if !is_satisfiable(m, conds) || val.is_null() || is_unresolved_intrinsic(val) {
                continue;
            }
            // For scalar if/then/else, the condition evaluates against the value
            // itself when the value is an object, otherwise conservative (condition
            // passes, only then-branch is checked).
            let cond_matches = if let Some(obj) = val.as_object() {
                let obj_keys: Vec<String> = obj.keys().cloned().collect();
                condition_schema_value_matches(&ite.condition, obj, &obj_keys, defs, 0)
            } else {
                // Scalar value: condition cannot meaningfully constrain it
                // (conditions check object keys/properties); treat as matching
                // and validate the then-branch.
                true
            };
            let branch = if cond_matches { &ite.then_schema } else { &ite.else_schema };
            if let Some(branch_schema) = branch
                && !schema_value_matches(val, branch_schema, defs, 0)
            {
                out.push(build_diagnostic_conditional(
                    "F3017",
                    "Value does not satisfy conditional schema constraint",
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

fn validate_format(
    out: &mut Vec<Diagnostic>,
    m: &Arc<SemanticModel>,
    rid: &str,
    prop_path: &str,
    format: &str,
    scenarios: &[(serde_json::Value, HashMap<String, bool>)],
) {
    let Some(re) = FORMAT_PATTERNS.get(format) else {
        return;
    };

    for (val, conds) in scenarios {
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
                // CloudFormation does not reject such properties - it ignores them.
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
                // sensitivity - case-insensitive for engine names
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
    let top_level_path;
    let (val, value_path) = match m.resolve(rid, prop_path) {
        Some(val) => (val, prop_path),
        None => {
            let stripped = prop_path.strip_prefix("Properties.")?;
            let top = stripped.split('.').next()?;
            let val = m.resources.get(rid)?.properties.get(top)?;
            top_level_path = format!("Properties.{}", top);
            (val, top_level_path.as_str())
        }
    };
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
        // A typed value that is unknown until deployment is only a parameter when
        // the model says a parameter produced it. A cross-stack import and a
        // dynamic reference are just as unknown and carry the same declared type,
        // so naming them a parameter would report something the template does not
        // contain - and would print the explanation where a name belongs.
        ResolvedValue::TypedDynamic { reason: desc, param_type: typ } => match m.parameter_name_at(rid, value_path) {
            Some(parameter) => Some(format!("parameter '{}' (type {})", parameter, typ)),
            None => Some(format!("dynamic ({})", desc)),
        },
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
    fn enum_matches_case_insensitive_any_casing() {
        let allowed = [json!("managed"), json!("unmanaged")];
        assert!(enum_matches_case_insensitive(&json!("managed"), &allowed));
        assert!(enum_matches_case_insensitive(&json!("MANAGED"), &allowed));
        assert!(enum_matches_case_insensitive(&json!("Unmanaged"), &allowed));
    }

    #[test]
    fn enum_matches_case_insensitive_rejects_unlisted_value() {
        let allowed = [json!("managed"), json!("unmanaged")];
        assert!(!enum_matches_case_insensitive(&json!("BOGUS"), &allowed));
    }

    #[test]
    fn enum_matches_case_insensitive_non_string_uses_exact_comparison() {
        assert!(enum_matches_case_insensitive(&json!(42), &[json!(42)]));
        assert!(!enum_matches_case_insensitive(&json!(43), &[json!(42)]));
    }

    fn store_with_case_insensitive_mode_enum() -> CompiledSchemaStore {
        let mode =
            PropSchema { enum_case_insensitive: vec![json!("managed"), json!("unmanaged")], ..Default::default() };
        let mut properties = HashMap::new();
        properties.insert("Mode".to_string(), mode);
        let mut store = CompiledSchemaStore::new();
        store.insert_schema(CompiledSchema {
            type_name: "AWS::Fake::Type".to_string(),
            properties,
            ..Default::default()
        });
        store
    }

    fn diagnostics_for_mode_value(mode_value: &str) -> Vec<Diagnostic> {
        let template = format!(
            r#"{{"Resources":{{"Widget":{{"Type":"AWS::Fake::Type","Properties":{{"Mode":"{}"}}}}}}}}"#,
            mode_value
        );
        let model = Arc::new(SemanticModel::from_bytes(template.as_bytes()).expect("template parses"));
        validate_all_resources(&store_with_case_insensitive_mode_enum(), &model, None)
    }

    #[test]
    fn case_insensitive_enum_accepts_any_casing_of_allowed_value() {
        for accepted in ["managed", "MANAGED", "Unmanaged"] {
            let w3030: Vec<Diagnostic> =
                diagnostics_for_mode_value(accepted).into_iter().filter(|d| d.rule_id == "W3030").collect();
            assert!(w3030.is_empty(), "'{accepted}' must not fire W3030, got: {w3030:?}");
        }
    }

    #[test]
    fn case_insensitive_enum_flags_unlisted_value_with_marked_message() {
        let diags = diagnostics_for_mode_value("BOGUS");
        let w3030 = diags.iter().find(|d| d.rule_id == "W3030").expect("W3030 fires for a value not in the enum");
        assert_eq!(w3030.severity, rules::Severity::Warn);
        assert_eq!(w3030.property_path.as_deref(), Some("Properties.Mode"));
        assert_eq!(w3030.message, "'BOGUS' is not one of ['managed', 'unmanaged'] (case-insensitive)");
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
                enforce_full_branch: false,
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
    fn schema_value_matches_required_groups_with_null_members_absent() {
        let defs = HashMap::new();
        let required_or = PropSchema { required_or: vec!["A".into(), "B".into()], ..Default::default() };
        assert!(schema_value_matches(&json!({ "A": 1 }), &required_or, &defs, 0));
        assert!(!schema_value_matches(&json!({ "A": null }), &required_or, &defs, 0));

        let required_xor = PropSchema { required_xor: vec!["A".into(), "B".into()], ..Default::default() };
        assert!(schema_value_matches(&json!({ "A": 1, "B": null }), &required_xor, &defs, 0));
        assert!(!schema_value_matches(&json!({ "A": 1, "B": 2 }), &required_xor, &defs, 0));
        assert!(!schema_value_matches(&json!({ "A": null, "B": null }), &required_xor, &defs, 0));
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
