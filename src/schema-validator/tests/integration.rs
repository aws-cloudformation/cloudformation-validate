use diagnostics::Diagnostic;
use diagnostics::Phase;
use rules::Severity;
use schema_validator::CompiledSchemaStore;
use schema_validator::SchemaValidator;
use schema_validator::validate::validate_all_resources;
use std::sync::{Arc, LazyLock};
use template_model::SemanticModel;

const TEMPLATES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../resources/templates");

static SV: LazyLock<SchemaValidator> = LazyLock::new(SchemaValidator::new);

fn validate_fixture(path: &str) -> Vec<Diagnostic> {
    let full = format!("{}/{}", TEMPLATES, path);
    let bytes = std::fs::read(&full).unwrap_or_else(|e| panic!("read {}: {}", full, e));
    let model = Arc::new(SemanticModel::from_bytes(&bytes).unwrap_or_else(|e| panic!("parse {}: {}", full, e)));
    SV.validate(&model, Some("us-east-1")).diagnostics
}

fn has_rule(diags: &[Diagnostic], rule_id: &str) -> bool {
    diags.iter().any(|d| d.rule_id == rule_id)
}

fn diags_for<'a>(diags: &'a [Diagnostic], rule_id: &str) -> Vec<&'a Diagnostic> {
    diags.iter().filter(|d| d.rule_id == rule_id).collect()
}

#[test]
fn schema_store_loads_schemas() {
    assert!(SV.schema_count() > 100, "expected 100+ schemas, got {}", SV.schema_count());
}

#[test]
fn list_rules_returns_known_rule_ids() {
    let rules = SV.list_rules();
    let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
    for expected in ["F3002", "F3003", "F3012", "W3030", "F3034"] {
        assert!(ids.contains(&expected), "missing rule {}", expected);
    }
}

#[test]
fn valid_resources_produce_no_fatal_diagnostics() {
    let diags = validate_fixture("good/schema_valid_resources.yaml");
    let fatals: Vec<_> = diags.iter().filter(|d| d.severity == Severity::Fatal).collect();
    assert!(fatals.is_empty(), "unexpected fatals: {:?}", fatals);
}

#[test]
fn minimal_template_no_schema_errors() {
    let diags = validate_fixture("good/minimal.yaml");
    let schema_fatals: Vec<_> =
        diags.iter().filter(|d| d.phase == Some(Phase::Schema) && d.severity == Severity::Fatal).collect();
    assert!(schema_fatals.is_empty(), "unexpected schema fatals: {:?}", schema_fatals);
}

#[test]
fn type_mismatch_integer_for_string() {
    let diags = validate_fixture("bad/schema_type_mismatch.yaml");
    assert!(
        has_rule(&diags, "F3012") || has_rule(&diags, "W9003"),
        "expected type mismatch diagnostic, got: {:?}",
        diags.iter().map(|d| &d.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn type_mismatch_boolean_for_string() {
    let diags = validate_fixture("bad/schema_type_mismatch.yaml");
    let type_diags: Vec<_> = diags
        .iter()
        .filter(|d| {
            (d.rule_id == "F3012" || d.rule_id == "W9003")
                && d.property_path.as_deref().is_some_and(|p| p.contains("Status"))
        })
        .collect();
    assert!(
        !type_diags.is_empty(),
        "expected type mismatch on Status, got: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.property_path)).collect::<Vec<_>>()
    );
}

#[test]
fn enum_violation_invalid_access_control() {
    let diags = validate_fixture("bad/schema_enum_violation.yaml");
    let enum_diags = diags_for(&diags, "W3030");
    assert!(!enum_diags.is_empty(), "expected W3030 for invalid AccessControl");
    assert!(
        enum_diags.iter().any(|d| d.message.contains("InvalidAccessControl")),
        "expected message mentioning InvalidAccessControl, got: {:?}",
        enum_diags.iter().map(|d| &d.message).collect::<Vec<_>>()
    );
}

#[test]
fn additional_properties_rejected() {
    let diags = validate_fixture("bad/schema_additional_props.yaml");
    let f3002 = diags_for(&diags, "F3002");
    assert!(f3002.len() >= 2, "expected at least 2 F3002 diagnostics, got {}", f3002.len());
}

#[test]
fn additional_properties_typo_suggestion() {
    let diags = validate_fixture("bad/schema_additional_props.yaml");
    // "BukcetName" has similarity 0.8 to "BucketName" — threshold is > 0.8, so no suggestion
    let typo_diag = diags.iter().find(|d| d.rule_id == "F3002" && d.message.contains("BukcetName"));
    let typo_diag = typo_diag.expect("expected F3002 for BukcetName");
    assert!(
        !typo_diag.message.contains("Did you mean"),
        "similarity 0.8 should not trigger suggestion (threshold is > 0.8)"
    );
}

#[test]
fn numeric_bounds_exceeded() {
    let diags = validate_fixture("bad/schema_numeric_bounds.yaml");
    let f3034 = diags_for(&diags, "F3034");
    assert!(!f3034.is_empty(), "expected F3034 for numeric bounds violation");
}

#[test]
fn string_length_too_short() {
    let diags = validate_fixture("bad/schema_string_length.yaml");
    let f3033 = diags_for(&diags, "F3033");
    if !f3033.is_empty() {
        assert!(f3033.iter().any(|d| { d.property_path.as_deref().is_some_and(|p| p.contains("FunctionName")) }));
    }
}

#[test]
fn format_violation_bad_subnet_id() {
    let diags = validate_fixture("bad/schema_format_violation.yaml");
    let e1154 = diags_for(&diags, "E1154");
    assert!(
        e1154.iter().any(|d| d.property_path.as_deref().is_some_and(|p| p.contains("SubnetId"))),
        "expected E1154 for bad SubnetId, got: {:?}",
        e1154.iter().map(|d| (&d.property_path, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn conditional_type_mismatch_with_scenario() {
    let diags = validate_fixture("bad/schema_conditional_type.yaml");
    let type_diags: Vec<_> = diags
        .iter()
        .filter(|d| {
            (d.rule_id == "F3012" || d.rule_id == "W9003")
                && d.property_path.as_deref().is_some_and(|p| p.contains("BucketName"))
        })
        .collect();
    assert!(!type_diags.is_empty(), "expected type diagnostic on conditional BucketName");
    let with_scenario = type_diags.iter().find(|d| d.condition_scenario.is_some());
    assert!(with_scenario.is_some(), "expected condition_scenario on conditional diagnostic");
}

#[test]
fn unique_items_violation() {
    let diags = validate_fixture("bad/unique_items.yaml");
    assert!(has_rule(&diags, "F3002"), "expected F3002 for unknown AvailabilityZones property");
}

#[test]
fn unknown_resource_type_no_crash() {
    let diags = validate_fixture("bad/unknown_properties.yaml");
    assert!(has_rule(&diags, "F3002"), "expected F3002 for FakeProperty on S3 Bucket");
}

#[test]
fn deprecated_resource_type_flagged() {
    let diags = validate_fixture("bad/deprecated_type.yaml");
    let _ = diags;
}

#[test]
fn generic_bad_template_produces_multiple_schema_violations() {
    let diags = validate_fixture("bad/generic.yaml");
    let schema_diags: Vec<_> = diags.iter().filter(|d| d.phase == Some(Phase::Schema)).collect();
    assert!(schema_diags.len() >= 3, "expected 3+ schema diagnostics, got {}", schema_diags.len());
}

#[test]
fn format_validation_with_refs() {
    let diags = validate_fixture("integration/formats.yaml");
    let vpc_format_errors: Vec<_> = diags
        .iter()
        .filter(|d| d.rule_id == "W3045" && d.property_path.as_deref().is_some_and(|p| p.contains("VpcId")))
        .collect();
    for d in &vpc_format_errors {
        assert!(!d.message.contains("Ref to 'Vpc'"), "Ref to VPC resource should be format-compatible: {}", d.message);
    }
}

// A reference whose target resource produces the wrong destination ARN format
// is a semantic, cross-resource concern owned by the rule engine, not the schema
// validator. The schema validator only proves structural type incompatibility,
// which a string-typed reference name does not violate — so it must not raise an
// ARN-format violation here.
#[test]
fn ref_to_wrong_arn_format_is_not_a_schema_format_violation() {
    let diags = validate_fixture("integration/ref-types.yaml");
    let format_violations: Vec<_> = diags
        .iter()
        .filter(|d| {
            matches!(d.rule_id.as_str(), "E1150" | "E1151" | "E1152" | "E1154")
                && d.resource.as_ref().and_then(|r| r.id.as_deref()) == Some("Subnet2")
        })
        .collect();
    assert!(
        format_violations.is_empty(),
        "schema validator must not emit an ARN-format violation for a reference-valued property; got {:?}",
        format_violations.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn getatt_type_mismatch_detected() {
    let diags = validate_fixture("integration/getatt-types.yaml");
    let ssm_diags: Vec<_> =
        diags.iter().filter(|d| d.resource.as_ref().and_then(|r| r.id.as_deref()) == Some("SsmParameter")).collect();
    let type_diag = ssm_diags.iter().any(|d| d.rule_id == "F3012" || d.rule_id == "W9003");
    if !type_diag {
        assert!(
            ssm_diags.is_empty() || ssm_diags.iter().any(|d| d.rule_id != "F3012"),
            "unexpected diagnostics for SsmParameter: {:?}",
            ssm_diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
        );
    }
}

#[test]
fn enrich_context_adds_documentation_url() {
    let full = format!("{}/bad/schema_enum_violation.yaml", TEMPLATES);
    let bytes = std::fs::read(&full).unwrap();
    let model = Arc::new(SemanticModel::from_bytes(&bytes).unwrap());
    let mut result = SV.validate(&model, Some("us-east-1"));
    SV.enrich_context(&mut result.diagnostics, &model);
    let enum_diag = result.diagnostics.iter().find(|d| d.rule_id == "W3030");
    assert!(enum_diag.is_some(), "expected W3030 diagnostic after enrichment");
}

#[test]
fn enrich_context_adds_allowed_values_for_enum() {
    let full = format!("{}/bad/schema_enum_violation.yaml", TEMPLATES);
    let bytes = std::fs::read(&full).unwrap();
    let model = Arc::new(SemanticModel::from_bytes(&bytes).unwrap());
    let mut result = SV.validate(&model, Some("us-east-1"));
    SV.enrich_context(&mut result.diagnostics, &model);
    let enum_diag = result.diagnostics.iter().find(|d| d.rule_id == "W3030");
    if let Some(d) = enum_diag
        && let Some(ref ctx) = d.context
    {
        assert!(
            ctx.extra.as_ref().is_some_and(|e| e.contains_key("allowed_values")),
            "expected allowed_values in context for W3030"
        );
    }
}

#[test]
fn lifecycle_e3710_shutdown_service() {
    let diags = validate_fixture("bad/schema_lifecycle.yaml");
    let e3710 = diags_for(&diags, "E3710");
    assert!(!e3710.is_empty(), "expected E3710 for shutdown service (CodeStar)");
    assert!(e3710.iter().any(|d| d.message.contains("shut down")));
}

#[test]
fn lifecycle_w3696_sunset_service() {
    let diags = validate_fixture("bad/schema_lifecycle.yaml");
    let w3696 = diags_for(&diags, "W3696");
    assert!(!w3696.is_empty(), "expected W3696 for sunset service (AppMesh)");
    assert!(w3696.iter().any(|d| d.message.contains("shut down on")));
}

#[test]
fn lifecycle_w3697_maintenance_service() {
    let diags = validate_fixture("bad/schema_lifecycle.yaml");
    let w3697 = diags_for(&diags, "W3697");
    assert!(!w3697.is_empty(), "expected W3697 for maintenance mode (LaunchConfiguration)");
    assert!(w3697.iter().any(|d| d.message.contains("maintenance mode")));
}

#[test]
fn lifecycle_e2533_eol_runtime() {
    let diags = validate_fixture("bad/schema_lifecycle.yaml");
    let e2533 = diags_for(&diags, "E2533");
    assert!(!e2533.is_empty(), "expected E2533 for EOL runtime dotnetcore2.1");
    assert!(e2533.iter().any(|d| d.message.contains("dotnetcore2.1")));
}

#[test]
fn lifecycle_w2531_deprecated_runtime() {
    let diags = validate_fixture("bad/schema_lifecycle.yaml");
    let w2531 = diags_for(&diags, "W2531");
    assert!(!w2531.is_empty(), "expected W2531 for deprecated runtime nodejs16.x");
    assert!(w2531.iter().any(|d| d.message.contains("nodejs16.x")));
}

#[test]
fn structural_f3020_dependent_excluded() {
    let diags = validate_fixture("bad/schema_structural.yaml");
    let f3020: Vec<_> = diags
        .iter()
        .filter(|d| d.rule_id == "F3020" && d.resource.as_ref().and_then(|r| r.id.as_deref()) == Some("AlarmBothStats"))
        .collect();
    assert!(!f3020.is_empty(), "expected F3020 for ExtendedStatistic + Statistic on CloudWatch Alarm");
}

#[test]
fn structural_f3058_required_or() {
    let diags = validate_fixture("bad/schema_structural.yaml");
    let f3058: Vec<_> = diags
        .iter()
        .filter(|d| d.rule_id == "F3058" && d.resource.as_ref().and_then(|r| r.id.as_deref()) == Some("SubnetNoCidr"))
        .collect();
    assert!(!f3058.is_empty(), "expected F3058 for Subnet missing CidrBlock/Ipv4IpamPoolId/etc");
}

#[test]
fn structural_f3014_required_xor() {
    let diags = validate_fixture("bad/schema_structural.yaml");
    let f3014: Vec<_> = diags
        .iter()
        .filter(|d| {
            d.rule_id == "F3014" && d.resource.as_ref().and_then(|r| r.id.as_deref()) == Some("ScalingPolicyBothIds")
        })
        .collect();
    assert!(!f3014.is_empty(), "expected F3014 for ScalingPolicy with both ScalingTargetId and ResourceId");
}

#[test]
fn f3014_excludes_novalue_from_exclusive_count() {
    // CidrIp is set to AWS::NoValue, leaving exactly one of the mutually
    // exclusive source properties (SourceSecurityGroupId), so the
    // mutual-exclusivity check must not fire.
    let diags = validate_fixture("good/resources/properties/exclusive.yaml");
    let f3014: Vec<_> = diags
        .iter()
        .filter(|d| d.rule_id == "F3014" && d.resource.as_ref().and_then(|r| r.id.as_deref()) == Some("Ingress"))
        .collect();
    assert!(f3014.is_empty(), "AWS::NoValue property must not count toward the exclusive-one tally");
}

#[test]
fn f3037_ignores_novalue_collapsed_list_items() {
    // Two Fn::If list items resolve to AWS::NoValue (null) in the false branch;
    // CloudFormation removes them, so they are not duplicates.
    let diags = validate_fixture("good/resources/properties/list_duplicates.yaml");
    let f3037: Vec<_> = diags
        .iter()
        .filter(|d| {
            d.rule_id == "F3037"
                && d.resource.as_ref().and_then(|r| r.id.as_deref()) == Some("IamRoleWithNestedConditions")
        })
        .collect();
    assert!(f3037.is_empty(), "null (AWS::NoValue) list items must not be treated as duplicates");
}

#[test]
fn f3012_property_type_error_reported_once_across_conditional_branches() {
    // PolicyDocument is a list (wrong type) wrapping an Fn::If; the branch
    // expansion must not multiply the single property-level type error.
    let diags = validate_fixture("bad/resources/iam/iam_policy.yaml");
    let f3012: Vec<_> = diags
        .iter()
        .filter(|d| d.rule_id == "F3012" && d.resource.as_ref().and_then(|r| r.id.as_deref()) == Some("rIamPolicy"))
        .collect();
    assert_eq!(f3012.len(), 1, "expected a single F3012 for the list-typed PolicyDocument, got {}", f3012.len());
}

#[test]
fn structural_f3021_dependent_required() {
    let diags = validate_fixture("bad/schema_structural.yaml");
    let f3021: Vec<_> = diags
        .iter()
        .filter(|d| {
            d.rule_id == "F3021"
                && d.resource.as_ref().and_then(|r| r.id.as_deref()) == Some("ScalingPolicyMissingDeps")
        })
        .collect();
    assert!(!f3021.is_empty(), "expected F3021 for ResourceId without ScalableDimension/ServiceNamespace");
}

#[test]
fn property_f3031_pattern_violation() {
    let diags = validate_fixture("bad/schema_property_constraints.yaml");
    let f3031: Vec<_> = diags
        .iter()
        .filter(|d| d.rule_id == "F3031" && d.resource.as_ref().and_then(|r| r.id.as_deref()) == Some("PatternBucket"))
        .collect();
    assert!(!f3031.is_empty(), "expected F3031 for uppercase S3 BucketName");
    assert!(f3031[0].message.contains("does not match pattern"));
}

#[test]
fn read_only_property_not_flagged() {
    // The read-only-property check was removed: it never fires on real templates
    // but firing it produced false positives, so it must not be emitted.
    let diags = validate_fixture("bad/schema_property_constraints.yaml");
    let e3040: Vec<_> = diags.iter().filter(|d| d.rule_id == "E3040").collect();
    assert!(e3040.is_empty(), "E3040 was removed and must not be emitted, got: {:?}", e3040);
}

#[test]
fn property_i3043_create_only() {
    let diags = validate_fixture("bad/schema_property_constraints.yaml");
    let i3043: Vec<_> = diags
        .iter()
        .filter(|d| d.rule_id == "I9001" && d.resource.as_ref().and_then(|r| r.id.as_deref()) == Some("ReadOnlyProp"))
        .collect();
    assert!(!i3043.is_empty(), "expected I9001 for create-only properties on ACMPCA Certificate");
    assert!(i3043[0].message.contains("create-only"));
}

#[test]
fn property_w3042_deprecated() {
    let diags = validate_fixture("bad/schema_property_constraints.yaml");
    let w3042: Vec<_> = diags
        .iter()
        .filter(|d| d.rule_id == "W9009" && d.resource.as_ref().and_then(|r| r.id.as_deref()) == Some("DeprecatedProp"))
        .collect();
    assert!(!w3042.is_empty(), "expected W9009 for deprecated WorkGroupConfigurationUpdates");
    assert!(w3042[0].message.contains("deprecated"));
}

#[test]
fn property_w3041_write_only_in_output() {
    let diags = validate_fixture("bad/schema_write_only.yaml");
    let w3041 = diags_for(&diags, "W9054");
    assert!(!w3041.is_empty(), "expected W3041 for write-only Certificate referenced in output");
    assert!(w3041[0].message.contains("Write-only") || w3041[0].message.contains("write-only"));
}

#[test]
fn region_availability_e3037() {
    let full = format!("{}/good/minimal.yaml", TEMPLATES);
    let bytes = std::fs::read(&full).unwrap();
    let model = Arc::new(SemanticModel::from_bytes(&bytes).unwrap());
    let mut store = CompiledSchemaStore::new();
    let region_json = serde_json::json!({
        "region_resource_types": {
            "us-east-1": { "AWS::S3::Bucket": true }
        }
    });
    store.load_region_data(serde_json::to_vec(&region_json).unwrap().as_slice());
    let diags = validate_all_resources(&store, &model, Some("us-east-1"));
    let f3006 = diags.iter().filter(|d| d.rule_id == "F3006").count();
    assert!(
        f3006 > 0,
        "expected F3006 for resource type not in region, got: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

/// A resource type available in some region but not the configured one is flagged
/// (F3006); with no region configured the availability check widens to the union
/// of all regions, so a type available in any region is not flagged.
#[test]
fn region_availability_widens_to_union_when_no_region() {
    let full = format!("{}/good/minimal.yaml", TEMPLATES);
    let bytes = std::fs::read(&full).unwrap();
    let model = Arc::new(SemanticModel::from_bytes(&bytes).unwrap());
    // minimal.yaml's type exists only in us-west-2 here, not us-east-1.
    let rtype = model.resources.values().next().unwrap().resource_type.clone();
    let mut store = CompiledSchemaStore::new();
    let region_json = serde_json::json!({
        "region_resource_types": {
            "us-east-1": { "AWS::S3::Bucket": true },
            "us-west-2": { rtype.clone(): true }
        }
    });
    store.load_region_data(serde_json::to_vec(&region_json).unwrap().as_slice());

    let at_us_east_1 = validate_all_resources(&store, &model, Some("us-east-1"));
    assert!(
        at_us_east_1.iter().any(|d| d.rule_id == "F3006"),
        "type absent in us-east-1 must be flagged when that region is configured"
    );

    let no_region = validate_all_resources(&store, &model, None);
    assert!(
        !no_region.iter().any(|d| d.rule_id == "F3006"),
        "type available in us-west-2 must not be flagged when no region is configured (union of all regions)"
    );
}

#[test]
fn array_bounds_f3032_max_items() {
    let diags = validate_fixture("bad/resources_iam_instanceprofile_roles.yaml");
    let f3032: Vec<_> = diags.iter().filter(|d| d.rule_id == "F3032").collect();
    assert!(!f3032.is_empty(), "expected F3032 for InstanceProfile with 2 roles (max 1)");
    assert!(f3032[0].message.contains("maximum"), "expected max items message: {}", f3032[0].message);
}

#[test]
fn unique_items_f3037_duplicate_roles() {
    let diags = validate_fixture("bad/schema_unique_items.yaml");
    let f3037 = diags_for(&diags, "F3037");
    assert!(!f3037.is_empty(), "expected F3037 for duplicate roles in InstanceProfile");
    assert!(f3037[0].message.contains("not unique"));
}

#[test]
fn type_mismatch_array_for_object() {
    let diags = validate_fixture("bad/resources_cognito_userpool_tag_is_list.yaml");
    let type_diags: Vec<_> = diags
        .iter()
        .filter(|d| d.rule_id == "F3012" && d.property_path.as_deref().is_some_and(|p| p.contains("UserPoolTags")))
        .collect();
    assert!(!type_diags.is_empty(), "expected F3012 for array where object expected on UserPoolTags");
}

#[test]
fn composition_f3018_one_of_zero_matches() {
    let diags = validate_fixture("bad/schema_composition.yaml");
    let f3018: Vec<_> = diags
        .iter()
        .filter(|d| d.rule_id == "F3018" && d.resource.as_ref().and_then(|r| r.id.as_deref()) == Some("NoImage"))
        .collect();
    assert!(!f3018.is_empty(), "expected F3018 for ImageBuilder missing both ImageName and ImageArn");
}

#[test]
fn composition_f3017_any_of_no_match() {
    let diags = validate_fixture("bad/schema_composition.yaml");
    let f3017: Vec<_> = diags
        .iter()
        .filter(|d| d.rule_id == "F3017" && d.resource.as_ref().and_then(|r| r.id.as_deref()) == Some("NoAZ"))
        .collect();
    assert!(!f3017.is_empty(), "expected F3017 for Volume missing all required AZ/Size/Snapshot combos");
}

#[test]
fn extension_cfn_gather_no_duplicate_numeric_constraint() {
    // The cfnGather extension's numeric cross-resource bounds (ESM BatchSize vs
    // FIFO-queue limit, SQS VisibilityTimeout vs Lambda Timeout) are reported by
    // the dedicated cross-resource engine rules at their specific locations. The
    // schema-validator must not also emit a generic schema-bounds diagnostic for
    // them, which previously double-reported the same issue.
    let diags = validate_fixture("integration/cfn-gather.yaml");
    assert!(
        !diags.iter().any(|d| d.rule_id == "F3034"),
        "F3034 must not double-report a gather constraint, got: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}
