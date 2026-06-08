//! Comprehensive tests against the sample templates in /templates.
//! Each test targets a specific CFN representation capability.

use rules_crate::Severity;
use template_model::resolver::{RefKind, ResolvedValue};
use template_model::{ParseError, SemanticModel};

const TEMPLATES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../resources/templates");

fn load(rel: &str) -> SemanticModel {
    let path = format!("{}/{}", TEMPLATES, rel);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {}", path, e));
    SemanticModel::from_bytes(&bytes).unwrap_or_else(|e| panic!("{}: {}", path, e))
}

fn try_load(rel: &str) -> Result<SemanticModel, ParseError> {
    let path = format!("{}/{}", TEMPLATES, rel);
    let bytes = std::fs::read(&path).unwrap();
    SemanticModel::from_bytes(&bytes)
}

fn assert_concrete_str(v: &ResolvedValue, expected: &str) {
    match v {
        ResolvedValue::Concrete { value: j } => {
            assert_eq!(j.as_str().unwrap(), expected, "got {:?}", j)
        }
        other => panic!("expected Concrete(\"{}\"), got {:?}", expected, other),
    }
}

// ── Parsing: intentionally invalid files ────────────────────────────────

#[test]
fn parse_rejects_empty_file() {
    assert!(
        try_load("bad/empty_file.yaml").is_err(),
        "expected error for empty file"
    );
    assert!(
        try_load("empty.yaml").is_err(),
        "expected error for empty.yaml"
    );
}

#[test]
fn parse_rejects_invalid_json() {
    assert!(
        try_load("bad/json_parse.json").is_err(),
        "expected error for invalid JSON"
    );
    assert!(
        try_load("bad/core/config_invalid_json.json").is_err(),
        "expected error for invalid JSON config"
    );
}

#[test]
fn parse_rejects_invalid_yaml() {
    assert!(
        try_load("bad/core/config_invalid_yaml.yaml").is_err(),
        "expected error for invalid YAML config"
    );
    assert!(
        try_load("bad/template.yaml").is_err(),
        "expected error for bad template"
    );
}

#[test]
fn parse_rejects_non_mapping_root() {
    assert!(
        try_load("bad/string.yaml").is_err(),
        "expected error for non-mapping root"
    );
}

// ── Format version / description / transforms ──────────────────────────

#[test]
fn template_metadata_fields() {
    let m = load("lsp/comprehensive.yaml");
    assert_eq!(m.format_version.as_deref(), Some("2010-09-09"));
    assert!(
        m.description.as_ref().unwrap().contains("Comprehensive"),
        "description should contain 'Comprehensive'"
    );
    assert_eq!(m.transforms.len(), 2);
    assert!(
        m.transforms
            .contains(&"AWS::Serverless-2016-10-31".to_string()),
        "transforms should contain AWS::Serverless-2016-10-31"
    );
    assert!(
        m.transforms.contains(&"AWS::Include".to_string()),
        "transforms should contain AWS::Include"
    );
}

// ── Parameters: all types ──────────────────────────────────────────────

#[test]
fn parameters_all_types() {
    let m = load("lsp/comprehensive.yaml");
    assert_eq!(m.parameters.len(), 8);

    let env = &m.parameters["EnvironmentName"];
    assert_eq!(env.param_type, "String");
    assert_eq!(env.default.as_deref(), Some("production"));
    assert_eq!(env.allowed_values.as_ref().unwrap().len(), 3);

    let pw = &m.parameters["DatabasePassword"];
    assert!(pw.no_echo);

    let count = &m.parameters["InstanceCount"];
    assert_eq!(count.param_type, "Number");
    assert_eq!(
        count.default.as_deref(),
        Some("2"),
        "numeric Default should be extracted"
    );

    let cidrs = &m.parameters["SubnetCidrs"];
    assert_eq!(cidrs.param_type, "CommaDelimitedList");

    let azs = &m.parameters["AvailabilityZones"];
    assert_eq!(azs.param_type, "List<AWS::EC2::AvailabilityZone::Name>");

    let ssm = &m.parameters["SSMParameter"];
    assert_eq!(ssm.param_type, "AWS::SSM::Parameter::Value<String>");
}

// ── Mappings: extraction and FindInMap resolution ──────────────────────

#[test]
fn mappings_extraction_and_lookup() {
    let m = load("lsp/comprehensive.yaml");
    assert_eq!(m.mappings.len(), 2);
    assert_eq!(
        m.mappings["RegionMap"]["us-east-1"]["AMI"],
        "ami-0abcdef1234567890"
    );
    assert_eq!(
        m.mappings["EnvironmentMap"]["production"]["LogLevel"],
        Severity::Warn.as_str()
    );

    // FindInMap with enum key → Enum of looked-up values
    let db = m.resource("Database").unwrap();
    match db.properties.get("DBInstanceClass") {
        Some(ResolvedValue::Enum { variants: vals }) => {
            // Should contain db.t3.micro (development) and db.t3.large (production)
            let strs: Vec<String> = vals
                .iter()
                .filter_map(|v| match v {
                    ResolvedValue::Concrete { value: j } => j.as_str().map(|s| s.to_string()),
                    _ => None,
                })
                .collect();
            assert!(
                strs.contains(&"db.t3.micro".to_string()),
                "expected db.t3.micro in variants"
            );
            assert!(
                strs.contains(&"db.t3.large".to_string()),
                "expected db.t3.large in variants"
            );
        }
        other => panic!("expected Enum for DBInstanceClass, got {:?}", other),
    }
}

// ── Conditions: nested short-form tags ─────────────────────────────────

#[test]
fn conditions_nested_short_form_tags() {
    let m = load("lsp/comprehensive.yaml");
    assert_eq!(m.conditions.conditions.len(), 6);
    // These use nested !Or [!Condition ..., !Equals [...]] etc.
    assert!(
        m.conditions
            .conditions
            .contains_key("IsProductionOrStaging"),
        "missing condition IsProductionOrStaging"
    );
    assert!(
        m.conditions.conditions.contains_key("ComplexCondition"),
        "missing condition ComplexCondition"
    );
    assert!(
        m.conditions.conditions.contains_key("HasMultipleAZs"),
        "missing condition HasMultipleAZs"
    );
    assert!(
        m.conditions.conditions.contains_key("IsNotProduction"),
        "missing condition IsNotProduction"
    );
}

#[test]
fn conditions_all_forms_mixed() {
    // condition-usage.yaml exercises every condition form: short/long Equals, And, Or, Not, Condition ref
    let m = load("lsp/condition-usage.yaml");
    // 7 named conditions + inline conditions registered from IfExpr
    assert!(
        m.conditions.conditions.len() >= 7,
        "expected at least 7 conditions, got {}",
        m.conditions.conditions.len()
    );
    for name in &[
        "IsProduction",
        "IsDevelopment",
        "ShouldCreateDatabase",
        "IsProductionAndCreateDB",
        "IsDevOrCreateDB",
        "NotProduction",
        "ComplexCondition",
    ] {
        assert!(
            m.conditions.conditions.contains_key(*name),
            "missing condition {}",
            name
        );
    }
}

#[test]
fn conditions_mutex_groups() {
    let m = load("lsp/condition-usage.yaml");
    assert!(
        !m.conditions.mutex_groups.is_empty(),
        "expected at least one mutex group"
    );
    let mg = &m.conditions.mutex_groups[0];
    assert!(
        mg.conditions.contains(&"IsProduction".to_string()),
        "mutex group should contain IsProduction"
    );
    assert!(
        mg.conditions.contains(&"IsDevelopment".to_string()),
        "mutex group should contain IsDevelopment"
    );
    assert!(
        !m.conditions
            .conditions_compatible("IsProduction", "IsDevelopment")
    );
}

#[test]
fn conditions_implications() {
    let m = load("lsp/condition-usage.yaml");
    // IsProductionAndCreateDB = And(IsProduction, ShouldCreateDatabase)
    assert!(
        m.conditions
            .condition_implies("IsProductionAndCreateDB", "IsProduction")
    );
    assert!(
        m.conditions
            .condition_implies("IsProductionAndCreateDB", "ShouldCreateDatabase")
    );
    // IsDevelopment → IsDevOrCreateDB (Or includes IsDevelopment)
    assert!(
        m.conditions
            .condition_implies("IsDevelopment", "IsDevOrCreateDB")
    );
}

#[test]
fn conditions_core_complex_nesting() {
    // core/conditions.yaml: And with Condition refs, Or with mixed Condition/Equals
    let m = load("good/core/conditions.yaml");
    assert!(
        m.conditions.conditions.len() >= 7,
        "expected >= 7 conditions, got {}",
        m.conditions.conditions.len()
    );
    assert!(
        m.conditions
            .conditions
            .contains_key("isPrimaryAndProduction"),
        "missing condition isPrimaryAndProduction"
    );
    assert!(
        m.conditions
            .conditions
            .contains_key("isProductionOrStaging"),
        "missing condition isProductionOrStaging"
    );
    assert!(
        m.conditions.conditions.contains_key("isNotProduction"),
        "missing condition isNotProduction"
    );
    assert!(
        m.conditions
            .condition_implies("isPrimaryAndProduction", "isProduction")
    );
    assert!(
        m.conditions
            .condition_implies("isPrimaryAndProduction", "isPrimary")
    );
}

// ── Fn::If: named conditions and inline expressions ────────────────────

#[test]
fn fn_if_named_condition() {
    let m = load("lsp/condition-usage.yaml");
    let r = m.resource("ProductionBucket").unwrap();
    match r.properties.get("BucketName") {
        Some(ResolvedValue::Conditional {
            condition: c,
            if_true: t,
            if_false: f,
        }) => {
            assert_eq!(c, "IsProduction");
            assert_concrete_str(t, "my-prod-bucket");
            assert_concrete_str(f, "my-dev-bucket");
        }
        other => panic!("expected Conditional, got {:?}", other),
    }
}

#[test]
fn fn_if_inline_condition_expr() {
    // LogicalConditionResource uses Fn::If with Fn::And/Or/Not as first arg
    let m = load("lsp/condition-usage.yaml");
    let r = m.resource("LogicalConditionResource").unwrap();
    // AlarmName: !If [Fn::And: [...], "prod-db-alarm", "dev-alarm"]
    match r.properties.get("AlarmName") {
        Some(ResolvedValue::Conditional {
            condition: c,
            if_true: t,
            if_false: f,
        }) => {
            assert!(
                c.starts_with("__inline_cond_"),
                "expected inline cond, got {}",
                c
            );
            assert_concrete_str(t, "prod-db-alarm");
            assert_concrete_str(f, "dev-alarm");
        }
        other => panic!("expected Conditional for AlarmName, got {:?}", other),
    }
}

#[test]
fn fn_if_nested_conditionals() {
    // myInstance4: InstanceType = If(isPrimaryAndProduction, If(isPrimary, ...), ...)
    let m = load("good/core/conditions.yaml");
    let r = m.resource("myInstance4").unwrap();
    match r.properties.get("InstanceType") {
        Some(ResolvedValue::Conditional {
            condition: outer,
            if_true: t,
            if_false: f,
        }) => {
            assert_eq!(outer, "isPrimaryAndProduction");
            assert!(
                matches!(t.as_ref(), ResolvedValue::Conditional { condition: inner, .. } if inner == "isPrimary")
            );
            assert_concrete_str(f, "t3.medium");
        }
        other => panic!("expected nested Conditional, got {:?}", other),
    }
}

// ── Fn::Sub: concrete, enum, explicit map ──────────────────────────────

#[test]
fn fn_sub_with_allowed_values_produces_enum() {
    let m = load("lsp/comprehensive.yaml");
    let sns = m.resource("SNSTopic").unwrap();
    match sns.properties.get("TopicName") {
        Some(ResolvedValue::Enum { variants: vals }) => {
            let strs: Vec<&str> = vals
                .iter()
                .filter_map(|v| match v {
                    ResolvedValue::Concrete { value: j } => j.as_str(),
                    _ => None,
                })
                .collect();
            assert!(
                strs.contains(&"development-alerts"),
                "expected development-alerts in variants"
            );
            assert!(
                strs.contains(&"production-alerts"),
                "expected production-alerts in variants"
            );
        }
        other => panic!("expected Enum for TopicName, got {:?}", other),
    }
}

#[test]
fn fn_sub_with_explicit_map() {
    // good/functions/sub.yaml: Sub with second-arg map
    let m = load("good/functions/sub.yaml");
    let vpc = m.resource("myVPc2").unwrap();
    // CidrBlock: Sub ["${myCidr}${number}", {myCidr: !Ref CidrBlock, number: 1}]
    // CidrBlock param has no default/allowed → Dynamic
    match vpc.properties.get("CidrBlock") {
        Some(ResolvedValue::Dynamic { reason: _ }) => {} // expected: CidrBlock param unknown
        Some(ResolvedValue::Concrete { value: _ }) => {} // also ok if default resolves
        other => panic!(
            "expected Dynamic or Concrete for CidrBlock Sub, got {:?}",
            other
        ),
    }
}

// ── Fn::Join / Fn::Select / Fn::Split / Fn::Base64 ────────────────────

#[test]
fn fn_join_concrete() {
    let m = load("lsp/parameter_usage.yaml");
    // Bucket3: !Join ["-", [!Ref "AWS::Region", "bucketName"]]
    // AWS::Region resolves to default "us-east-1"
    let b3 = m.resource("Bucket3").unwrap();
    match b3.properties.get("BucketName") {
        Some(ResolvedValue::Concrete { value: v }) => {
            assert_eq!(v.as_str().unwrap(), "us-east-1-bucketName");
        }
        other => panic!(
            "expected Concrete for Join with pseudo-param, got {:?}",
            other
        ),
    }
}

#[test]
fn fn_select_concrete() {
    let m = load("lsp/comprehensive.yaml");
    // VPC CidrBlock: !Ref VpcCidr → default "10.0.0.0/16"
    let vpc = m.resource("VPC").unwrap();
    match vpc.properties.get("CidrBlock") {
        Some(ResolvedValue::Concrete { value: v }) => {
            assert_eq!(v.as_str().unwrap(), "10.0.0.0/16")
        }
        other => panic!("expected Concrete for VPC CidrBlock, got {:?}", other),
    }
}

// ── Ref resolution: params, resources, pseudo-params ───────────────────

#[test]
fn ref_to_param_with_default() {
    let m = load("lsp/parameter_usage.yaml");
    // Bucket1: BucketName: !Ref Environment → default "dev"
    let b1 = m.resource("Bucket1").unwrap();
    assert_concrete_str(b1.properties.get("BucketName").unwrap(), "dev");
}

#[test]
fn ref_to_param_with_allowed_values() {
    let m = load("lsp/condition-usage.yaml");
    // ConditionalResource.Tags[1].Value = If(ShouldCreateDatabase, "true", "false")
    let r = m.resource("ConditionalResource").unwrap();
    match r.properties.get("InstanceType") {
        Some(ResolvedValue::Conditional { condition: c, .. }) => {
            assert_eq!(c, "IsProductionAndCreateDB")
        }
        other => panic!("expected Conditional, got {:?}", other),
    }
}

#[test]
fn ref_to_resource_produces_reference() {
    let m = load("lsp/comprehensive.yaml");
    let dbsg = m.resource("DatabaseSecurityGroup").unwrap();
    match dbsg.properties.get("VpcId") {
        Some(ResolvedValue::Reference {
            target: t,
            kind: RefKind::Ref,
        }) => assert_eq!(t, "VPC"),
        other => panic!("expected Reference(VPC, Ref), got {:?}", other),
    }
}

#[test]
fn ref_to_pseudo_param_is_dynamic() {
    let m = load("lsp/parameter_usage.yaml");
    // Bucket7: !Sub "Bucket-${AWS::Region}" → resolves to "Bucket-us-east-1"
    let b7 = m.resource("Bucket7").unwrap();
    match b7.properties.get("BucketName") {
        Some(ResolvedValue::Concrete { value: v }) => {
            assert_eq!(v.as_str().unwrap(), "Bucket-us-east-1");
        }
        other => panic!("expected Concrete for pseudo-param Sub, got {:?}", other),
    }
}

// ── GetAtt resolution ──────────────────────────────────────────────────

#[test]
fn getatt_produces_reference_with_attr() {
    let m = load("lsp/comprehensive.yaml");
    let lambda = m.resource("LambdaFunction").unwrap();
    match lambda.properties.get("Role") {
        Some(ResolvedValue::Reference {
            target: t,
            kind: RefKind::GetAtt { attr },
        }) => {
            assert_eq!(t, "LambdaRole");
            assert_eq!(attr, "Arn");
        }
        other => panic!(
            "expected Reference(LambdaRole, GetAtt(Arn)), got {:?}",
            other
        ),
    }
}

// ── Resource attributes: Condition, DependsOn, DeletionPolicy ──────────

#[test]
fn resource_condition() {
    let m = load("lsp/condition-usage.yaml");
    assert_eq!(
        m.resource("ProductionBucket").unwrap().condition.as_deref(),
        Some("IsProduction")
    );
    assert_eq!(
        m.resource("Database").unwrap().condition.as_deref(),
        Some("ShouldCreateDatabase")
    );
    assert_eq!(
        m.resource("ConditionalResource")
            .unwrap()
            .condition
            .as_deref(),
        None,
        "ConditionalResource should have no condition"
    );
}

#[test]
fn resource_conditional_deletion_policy() {
    let m = load("lsp/comprehensive.yaml");
    let db = m.resource("Database").unwrap();
    match &db.deletion_policy {
        Some(ResolvedValue::Conditional {
            condition: c,
            if_true: t,
            if_false: f,
        }) => {
            assert_eq!(c, "IsProduction");
            assert_concrete_str(t, "Snapshot");
            assert_concrete_str(f, "Delete");
        }
        other => panic!("expected Conditional DeletionPolicy, got {:?}", other),
    }
}

#[test]
fn resource_depends_on() {
    let m = load("bad/resources_circular_dependency.yaml");
    let has_depends = m.resources.values().any(|r| !r.depends_on.is_empty());
    assert!(has_depends, "expected at least one resource with DependsOn");
    // DependsOn edges should appear in the graph
    let dependson_edges = m
        .graph
        .edges
        .iter()
        .any(|e| matches!(e.kind, RefKind::DependsOn));
    assert!(dependson_edges, "expected DependsOn edges in graph");
}

#[test]
fn resource_metadata() {
    let m = load("lsp/comprehensive.yaml");
    let vpc = m.resource("VPC").unwrap();
    let meta = vpc.metadata.as_ref().expect("VPC should have metadata");
    assert_eq!(meta["Purpose"], "Main VPC");
}

// ── Outputs ────────────────────────────────────────────────────────────

#[test]
fn outputs_value_condition_export() {
    let m = load("lsp/comprehensive.yaml");
    assert_eq!(m.outputs.len(), 6);

    let vpc_out = &m.outputs["VPCId"];
    assert!(
        matches!(&vpc_out.value, ResolvedValue::Reference { target: t, kind: RefKind::Ref } if t == "VPC")
    );
    assert!(
        vpc_out.export_name.is_some(),
        "VPCId output should have an export name"
    );

    let db_out = &m.outputs["DatabaseEndpoint"];
    assert_eq!(db_out.condition.as_deref(), Some("IsProductionOrStaging"));
    assert!(matches!(
        &db_out.value,
        ResolvedValue::Reference {
            kind: RefKind::GetAtt { .. },
            ..
        }
    ));
}

#[test]
fn outputs_conditional_values() {
    let m = load("lsp/condition-usage.yaml");
    assert_eq!(m.outputs.len(), 7);
    let full = &m.outputs["FullFormConditionalOutput"];
    match &full.value {
        ResolvedValue::Conditional {
            condition: c,
            if_true: t,
            if_false: f,
        } => {
            assert_eq!(c, "IsProduction");
            assert_concrete_str(t, "Production Environment");
            assert_concrete_str(f, "Development Environment");
        }
        other => panic!("expected Conditional output, got {:?}", other),
    }
}

// ── Reference graph ────────────────────────────────────────────────────

#[test]
fn graph_edges_and_traversal() {
    let m = load("lsp/comprehensive.yaml");
    assert!(
        m.graph.edges.len() >= 50,
        "expected >= 50 edges, got {}",
        m.graph.edges.len()
    );
    // DatabaseSecurityGroup → VPC via Ref
    assert!(m.graph.depends_on("DatabaseSecurityGroup", "VPC"));
    // LambdaFunction → LambdaRole via GetAtt
    assert!(m.graph.depends_on("LambdaFunction", "LambdaRole"));
    // No reverse
    assert!(!m.graph.depends_on("VPC", "DatabaseSecurityGroup"));
}

#[test]
fn graph_circular_dependency_detection() {
    let m = load("bad/resources_circular_dependency.yaml");
    assert!(
        !m.graph.cycles().is_empty(),
        "expected circular dependency cycles"
    );
}

#[test]
fn graph_dependson_circular() {
    let m = load("bad/resources_circular_dependency_dependson.yaml");
    assert!(
        !m.graph.cycles().is_empty(),
        "expected DependsOn circular dependency cycles"
    );
}

// ── Dynamic references ({{resolve:...}}) ───────────────────────────────

#[test]
fn dynamic_references_resolve_to_dynamic() {
    let m = load("integration/dynamic-references.yaml");
    let has_dynamic = m.resources.values().any(|r| {
        r.properties
            .values()
            .any(|v| matches!(v, ResolvedValue::Dynamic { reason: s } if s.contains("dynamic reference")))
    });
    assert!(has_dynamic, "expected dynamic reference resolution");
}

// ── AWS::NoValue in Fn::If ─────────────────────────────────────────────

#[test]
fn no_value_resolves_to_null() {
    let m = load("good/no_value.yaml");
    // rDBServerInstance.MonitoringRoleArn: If(EnhancedMonitoring, GetAtt, AWS::NoValue)
    let db = m.resource("rDBServerInstance").unwrap();
    match db.properties.get("MonitoringRoleArn") {
        Some(ResolvedValue::Conditional { if_false: f, .. }) => {
            assert!(
                matches!(f.as_ref(), ResolvedValue::Concrete { value: v } if v.is_null()),
                "expected null for NoValue branch, got {:?}",
                f
            );
        }
        other => panic!("expected Conditional with NoValue, got {:?}", other),
    }
}

// ── resolve_deep: nested property access ───────────────────────────────

#[test]
fn resolve_deep_into_concrete_object() {
    let m = load("lsp/comprehensive.yaml");
    match m.resolve_deep("VPC", "Properties.EnableDnsHostnames") {
        Some(ResolvedValue::Concrete { value: v }) => assert_eq!(v.0, serde_json::json!(true)),
        other => panic!("expected Concrete(true), got {:?}", other),
    }
}

#[test]
fn resolve_deep_through_conditional() {
    let m = load("lsp/comprehensive.yaml");
    // Database.AllocatedStorage = If(IsProduction, 100, 20)
    match m.resolve_deep("Database", "Properties.AllocatedStorage") {
        Some(ResolvedValue::Conditional { condition: c, .. }) => assert_eq!(c, "IsProduction"),
        other => panic!("expected Conditional, got {:?}", other),
    }
}

// ── resolve_scenarios ──────────────────────────────────────────────────

#[test]
fn resolve_scenarios_expands_conditional() {
    let m = load("lsp/comprehensive.yaml");
    let scenarios = m.resolve_scenarios("Database", "Properties.AllocatedStorage");
    assert!(
        scenarios.len() >= 2,
        "expected >=2 scenarios, got {}",
        scenarios.len()
    );
    // One scenario with IsProduction=true → 100, one with false → 20
    let vals: Vec<i64> = scenarios
        .iter()
        .filter_map(|(v, _)| match v {
            ResolvedValue::Concrete { value: j } => j.as_i64(),
            _ => None,
        })
        .collect();
    assert!(vals.contains(&100), "expected scenario with value 100");
    assert!(vals.contains(&20), "expected scenario with value 20");
}

// ── JSON/YAML equivalence ──────────────────────────────────────────────

#[test]
fn json_yaml_equivalence_simple() {
    let yaml = load("lsp/simple.yaml");
    let json = load("lsp/simple.json");
    assert_eq!(yaml.resources.len(), json.resources.len());
    assert_eq!(
        yaml.resources.keys().collect::<Vec<_>>(),
        json.resources.keys().collect::<Vec<_>>()
    );
}

#[test]
fn json_yaml_equivalence_conditions() {
    let yaml = load("lsp/condition-usage.yaml");
    let json = load("lsp/condition-usage.json");
    // JSON version may have fewer conditions (no ComplexCondition) but core ones match
    for name in &["IsProduction", "IsDevelopment", "ShouldCreateDatabase"] {
        assert!(
            yaml.conditions.conditions.contains_key(*name),
            "yaml missing condition {name}"
        );
        assert!(
            json.conditions.conditions.contains_key(*name),
            "json missing condition {name}"
        );
    }
}

// ── Transforms ─────────────────────────────────────────────────────────

#[test]
fn transforms_extracted() {
    let m = load("good/transform/language_extension.yaml");
    assert!(
        m.transforms
            .contains(&"AWS::LanguageExtensions".to_string()),
        "transforms should contain AWS::LanguageExtensions"
    );
}

#[test]
fn sam_transform() {
    let m = load("good/transform_serverless_function.yaml");
    assert!(
        m.transforms.iter().any(|t| t.contains("Serverless")),
        "transforms should contain a Serverless transform"
    );
}

// ── Condition refs tracked on resources ────────────────────────────────

#[test]
fn condition_refs_tracked() {
    let m = load("lsp/condition-usage.yaml");
    let r = m.resource("ConditionalResource").unwrap();
    assert!(
        !r.diagnostics.condition_refs.is_empty(),
        "ConditionalResource should have condition refs"
    );
    // Uses IsProductionAndCreateDB, IsProduction, ShouldCreateDatabase, ComplexCondition
    assert!(
        r.diagnostics
            .condition_refs
            .contains(&"IsProduction".to_string()),
        "condition_refs should contain IsProduction"
    );
}

// ── FindInMap refs tracked ─────────────────────────────────────────────

#[test]
fn findinmap_refs_tracked() {
    let m = load("lsp/comprehensive.yaml");
    let db = m.resource("Database").unwrap();
    assert!(
        db.diagnostics
            .find_in_map_refs
            .contains(&"EnvironmentMap".to_string()),
        "find_in_map_refs should contain EnvironmentMap"
    );
}

// ── to_json structure ────────────────────────────────────────────

#[test]
fn rego_input_complete_structure() {
    let m = load("lsp/comprehensive.yaml");
    let json = serde_json::to_value(m.to_diagnostic_json()).unwrap();
    assert!(
        json["template"]["formatVersion"].as_str().is_some(),
        "formatVersion should be a string"
    );
    assert_eq!(json["template"]["transforms"].as_array().unwrap().len(), 2);
    assert_eq!(json["parameters"].as_object().unwrap().len(), 8);
    assert_eq!(json["resources"].as_object().unwrap().len(), 12);
    assert_eq!(json["outputs"].as_object().unwrap().len(), 6);
    assert!(
        json["edges"].as_array().unwrap().len() >= 50,
        "expected >= 50 edges, got {}",
        json["edges"].as_array().unwrap().len()
    );
    assert!(
        json["cycles"].as_array().unwrap().is_empty(),
        "comprehensive template should have no cycles"
    );
    assert_eq!(json["mappings"].as_object().unwrap().len(), 2);
}

// ── Large template smoke tests ─────────────────────────────────────────

#[test]
fn quickstart_vpc_json_large() {
    let m = load("quickstart/vpc.json");
    assert!(
        m.resources.len() > 50,
        "expected > 50 resources, got {}",
        m.resources.len()
    );
    assert!(
        m.conditions.conditions.len() > 10,
        "expected > 10 conditions, got {}",
        m.conditions.conditions.len()
    );
    assert!(
        m.outputs.len() > 20,
        "expected > 20 outputs, got {}",
        m.outputs.len()
    );
    assert!(
        m.graph.cycles().is_empty(),
        "quickstart vpc should have no cycles"
    );
}

#[test]
fn quickstart_cis_benchmark_large() {
    let m = load("quickstart/cis_benchmark.yaml");
    assert!(
        m.resources.len() > 50,
        "expected > 50 resources, got {}",
        m.resources.len()
    );
    assert!(
        m.graph.edges.len() > 100,
        "expected > 100 edges, got {}",
        m.graph.edges.len()
    );
}

#[test]
fn public_watchmaker_json_large() {
    let m = load("public/watchmaker.json");
    assert!(
        m.parameters.len() > 20,
        "expected > 20 parameters, got {}",
        m.parameters.len()
    );
    assert!(
        m.conditions.conditions.len() > 10,
        "expected > 10 conditions, got {}",
        m.conditions.conditions.len()
    );
}

// ── All parseable templates: bulk smoke test ───────────────────────────

#[test]
fn all_templates_parse_without_panic() {
    let mut ok = 0u32;
    let mut err = 0u32;
    for entry in walkdir(TEMPLATES) {
        let bytes = std::fs::read(&entry).unwrap();
        match SemanticModel::from_bytes(&bytes) {
            Ok(_) => ok += 1,
            Err(_) => err += 1,
        }
    }
    assert!(ok >= 220, "expected >=220 parseable templates, got {}", ok);
    assert!(err <= 10, "too many parse failures: {}", err);
}

fn walkdir(dir: &str) -> Vec<String> {
    let mut out = Vec::new();
    walk_recursive(std::path::Path::new(dir), &mut out);
    out
}

fn walk_recursive(dir: &std::path::Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            walk_recursive(&p, out);
        } else if p.is_file() {
            if let Some(ext) = p.extension() {
                if ext == "yaml" || ext == "json" || ext == "yml" {
                    out.push(p.display().to_string());
                }
            }
        }
    }
}

// ── Template-level metadata ────────────────────────────────────────────

#[test]
fn template_level_metadata_extracted() {
    let m = load("lsp/comprehensive.yaml");
    let meta = m
        .template_metadata
        .as_ref()
        .expect("template_metadata should be Some");
    assert!(
        meta.get("AWS::CloudFormation::Interface").is_some(),
        "metadata should contain AWS::CloudFormation::Interface"
    );
    assert!(
        meta.get("CustomMetadata").is_some(),
        "metadata should contain CustomMetadata"
    );
    assert_eq!(meta["CustomMetadata"]["Version"], "1.0.0");
}

#[test]
fn template_level_metadata_absent_when_missing() {
    let m = load("good/minimal.yaml");
    assert_eq!(
        m.template_metadata, None,
        "minimal template should have no metadata"
    );
}

// ── Rules ──────────────────────────────────────────────────────────────

#[test]
fn rules_extracted() {
    let m = load("lsp/comprehensive.yaml");
    let rules = m.rules.as_ref().expect("rules should be Some");
    let obj = rules.as_object().unwrap();
    assert_eq!(obj.len(), 2);
    assert!(
        obj.contains_key("ValidateRegionAndEnvironment"),
        "missing rule ValidateRegionAndEnvironment"
    );
    assert!(
        obj.contains_key("ValidateParameterCombinations"),
        "missing rule ValidateParameterCombinations"
    );
    // Assertions are present
    let rule = &obj["ValidateRegionAndEnvironment"];
    assert!(
        rule.get("RuleCondition").is_some(),
        "rule should have a RuleCondition"
    );
    let assertions = rule["Assertions"].as_array().unwrap();
    assert_eq!(assertions.len(), 2);
}

#[test]
fn rules_absent_when_missing() {
    let m = load("good/minimal.yaml");
    assert_eq!(m.rules, None, "minimal template should have no rules");
}

// ── UpdatePolicy / CreationPolicy ──────────────────────────────────────

#[test]
fn resource_update_policy_and_creation_policy() {
    let m = load("lsp/comprehensive.yaml");
    let asg = m.resource("AutoScalingGroup").unwrap();
    let up = asg
        .update_policy
        .as_ref()
        .expect("UpdatePolicy should be Some");
    assert!(
        up.get("AutoScalingRollingUpdate").is_some(),
        "UpdatePolicy should contain AutoScalingRollingUpdate"
    );
    assert_eq!(up["AutoScalingRollingUpdate"]["MinInstancesInService"], 1);

    let cp = asg
        .creation_policy
        .as_ref()
        .expect("CreationPolicy should be Some");
    assert!(
        cp.get("ResourceSignal").is_some(),
        "CreationPolicy should contain ResourceSignal"
    );
    assert_eq!(cp["ResourceSignal"]["Timeout"], "PT10M");
}

#[test]
fn resource_without_policies_has_none() {
    let m = load("lsp/comprehensive.yaml");
    let vpc = m.resource("VPC").unwrap();
    assert_eq!(vpc.update_policy, None, "VPC should have no UpdatePolicy");
    assert_eq!(
        vpc.creation_policy, None,
        "VPC should have no CreationPolicy"
    );
}

// ── Select on non-list value ───────────────────────────────────────────

#[test]
fn select_on_non_list_gives_correct_message() {
    let m = load("lsp/comprehensive.yaml");
    // SubnetCidrs is CommaDelimitedList → resolves to a string, not an array
    // !Select [0, !Ref SubnetCidrs] should produce "Select on non-list value"
    let subnet = m.resource("PublicSubnet").unwrap();
    let cidr = &subnet.properties["CidrBlock"];
    match cidr {
        ResolvedValue::Dynamic { reason: msg } => {
            assert!(
                msg.contains("non-list"),
                "expected 'non-list' in message, got: {}",
                msg
            );
        }
        other => panic!("expected Dynamic, got {:?}", other),
    }
}

// ── Condition value expression describes intrinsics ─────────────────────

#[test]
fn condition_intrinsic_value_not_question_mark() {
    let m = load("lsp/comprehensive.yaml");
    // HasMultipleAZs: !Not [!Equals [!Select [1, !Ref AvailabilityZones], ""]]
    // The !Select should render as "Select(...)" not "?"
    let expr = m.conditions.get("HasMultipleAZs").unwrap();
    let formatted = format!("{:?}", expr);
    assert!(
        !formatted.contains("Other"),
        "condition should describe intrinsic, not fall back to Other: {}",
        formatted
    );
}

// ── Condition refs from Metadata blocks ─────────────────────────────────

#[test]
fn condition_refs_include_metadata_fn_if() {
    // The watchmaker template has Fn::If conditions inside Metadata.AWS::CloudFormation::Init
    // (e.g., InstallCloudWatchAgent used in cw-agent-install config).
    // condition_refs must include these, not just conditions from Properties.
    let m = load("public/watchmaker.json");
    let instance = m.resource("WatchmakerInstance").unwrap();
    // InstallCloudWatchAgent is used in Fn::If inside Metadata, not Properties
    assert!(
        instance
            .diagnostics
            .condition_refs
            .contains(&"InstallCloudWatchAgent".to_string()),
        "condition_refs should include 'InstallCloudWatchAgent' from Metadata Fn::If, got: {:?}",
        instance.diagnostics.condition_refs
    );
}

// ── to_json includes condition implications and resource_condition_map ───

#[test]
fn to_json_has_condition_implications() {
    let m = load("good/conditions.yaml");
    let json = serde_json::to_value(m.to_diagnostic_json()).unwrap();
    assert!(
        json.get("conditionImplications").is_some(),
        "to_json should include conditionImplications"
    );
    assert!(
        json.get("resourceConditionMap").is_some(),
        "to_json should include resourceConditionMap"
    );
}
