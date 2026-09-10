use cloudformation_validate::{
    AdditionalSchemaSource, CelEngine, EngineConfig, ExternalRuleSource, RegoEngine, ReportStatus, SchemaValidator,
    SchemaValidatorConfig, SemanticModel, Severity, ValidateConfig, ValidationEngine, ValidationReport,
    validate_bytes_with_path, version,
};

const GOOD_TEMPLATE: &[u8] = br#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Bucket:
    Type: AWS::S3::Bucket
"#;

const UNENCRYPTED_BUCKET: &[u8] = br#"
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-test-bucket
"#;

const TEMPLATE_WITH_OVERLAY_PROPERTY: &[u8] = br#"
Resources:
  Function:
    Type: AWS::Lambda::Function
    Properties:
      Code:
        ZipFile: "exports.handler = async () => {};"
      Role: arn:aws:iam::123456789012:role/lambda-role
      Runtime: nodejs18.x
      Handler: index.handler
      TestForOverride: enabled
"#;

const LAMBDA_OVERLAY_SCHEMA: &str = r#"{
  "typeName": "AWS::Lambda::Function",
  "properties": {"TestForOverride": {"type": "string"}}
}"#;

const REGO_CUSTOM_RULE: &str = r#"
package custom_test
import rego.v1
violation contains v if {
    some name, resource in input.resources
    resource.resourceType == "AWS::S3::Bucket"
    not resource.properties.BucketEncryption
    v := {
        "rule_id": "CUSTOM001",
        "severity": "error",
        "message": "S3 bucket must have encryption configured",
        "resource_id": name,
    }
}
"#;

const CEL_CUSTOM_RULE: &str = r#"{
  "rules": [{
    "rule_id": "CUSTOM001",
    "severity": "ERROR",
    "resource_type": "AWS::S3::Bucket",
    "expression": "!has(properties.BucketEncryption)",
    "message": "S3 bucket must have encryption configured"
  }]
}"#;

const GUARD_RULE: &str = r#"
rule check_bucket_encryption {
    AWS::S3::Bucket {
        Properties.BucketEncryption EXISTS
        <<S3 bucket must have encryption configured>>
    }
}
"#;

fn validate(
    engine: &dyn ValidationEngine,
    schema_validator: &SchemaValidator,
    template: &[u8],
    config: ValidateConfig,
) -> ValidationReport {
    validate_bytes_with_path(engine, schema_validator, template, config, "template.yaml".to_string())
        .expect("the public facade must return a validation report")
}

fn diagnostic_signatures(report: &ValidationReport) -> Vec<(String, Severity, String)> {
    report
        .diagnostics
        .iter()
        .map(|diagnostic| (diagnostic.rule_id.clone(), diagnostic.severity, diagnostic.message.clone()))
        .collect()
}

fn both_engines(config: EngineConfig) -> Vec<Box<dyn ValidationEngine>> {
    vec![
        Box::new(RegoEngine::new(config.clone()).expect("Rego engine must initialize")),
        Box::new(CelEngine::new(config).expect("CEL engine must initialize")),
    ]
}

#[test]
fn facade_version_matches_cargo_package_version() {
    assert_eq!(version(), env!("CARGO_PKG_VERSION"));
}

#[test]
fn engine_names_and_rule_lists_match() {
    let engines = both_engines(EngineConfig::default());
    assert_eq!(engines[0].engine_name(), "rego");
    assert_eq!(engines[1].engine_name(), "cel");

    let listings: Vec<Vec<_>> = engines
        .iter()
        .map(|engine| {
            let rules = engine.list_rules();
            assert!(!rules.is_empty(), "built-in rule listing must not be empty");
            assert!(rules.windows(2).all(|pair| pair[0].id <= pair[1].id), "rules must be sorted by ID");
            rules
                .into_iter()
                .map(|rule| (rule.id, rule.severity, rule.category, rule.description, rule.origin))
                .collect()
        })
        .collect();
    assert_eq!(listings[0], listings[1]);
}

#[test]
fn good_template_passes_both_engines_with_the_file_label() {
    let schema_validator = SchemaValidator::default();
    for engine in both_engines(EngineConfig::default()) {
        let report = validate(engine.as_ref(), &schema_validator, GOOD_TEMPLATE, ValidateConfig::default());
        assert_eq!(report.status, ReportStatus::Ok);
        assert_eq!(report.file_path, "template.yaml");
        assert!(
            report
                .diagnostics
                .iter()
                .all(|diagnostic| !matches!(diagnostic.severity, Severity::Error | Severity::Fatal)),
            "good template must not produce errors: {:?}",
            report.diagnostics
        );
    }
}

#[test]
fn both_engines_return_identical_diagnostics() {
    let schema_validator = SchemaValidator::default();
    let engines = both_engines(EngineConfig::default());
    let reports: Vec<_> = engines
        .iter()
        .map(|engine| validate(engine.as_ref(), &schema_validator, UNENCRYPTED_BUCKET, ValidateConfig::default()))
        .collect();

    assert!(!reports[0].diagnostics.is_empty(), "unencrypted bucket must produce diagnostics");
    assert_eq!(diagnostic_signatures(&reports[0]), diagnostic_signatures(&reports[1]));
    assert!(
        reports[0]
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.entity.as_ref().is_some_and(|entity| entity.logical_id == "MyBucket") })
    );
}

#[test]
fn schema_validator_exposes_bundled_schemas_and_rules() {
    let validator = SchemaValidator::default();
    assert!(validator.schema_count() > 0);
    let rules = validator.list_rules();
    assert!(!rules.is_empty());
    assert!(rules.iter().all(|rule| !rule.id.is_empty()));
}

#[test]
fn severity_threshold_filters_lower_diagnostics() {
    let schema_validator = SchemaValidator::default();
    let engine = RegoEngine::new(EngineConfig::default()).expect("Rego engine must initialize");
    let config = ValidateConfig { severity_level: Severity::Error, ..ValidateConfig::default() };
    let report = validate(&engine, &schema_validator, UNENCRYPTED_BUCKET, config);

    assert!(
        report.diagnostics.iter().all(|diagnostic| matches!(diagnostic.severity, Severity::Error | Severity::Fatal))
    );
}

#[test]
fn detailed_metadata_counts_and_performance_are_populated() {
    let schema_validator = SchemaValidator::default();
    let engine = RegoEngine::new(EngineConfig::default()).expect("Rego engine must initialize");
    let report = validate(&engine, &schema_validator, UNENCRYPTED_BUCKET, ValidateConfig::default());
    let counts = &report.metadata.counts;
    let diagnostic_count = counts.fatal + counts.errors + counts.warnings + counts.informational + counts.debug;

    assert_eq!(report.diagnostics.len() as u32, diagnostic_count);
    assert!(report.performance.validate_total.duration_ms > 0.0);
    assert!(report.performance.schema_validate.duration_ms >= 0.0);
    assert!(report.performance.rule_evaluation.duration_ms >= 0.0);
}

#[test]
fn additional_schema_config_applies_to_both_engines() {
    let baseline_validator = SchemaValidator::default();
    for baseline_engine in both_engines(EngineConfig::default()) {
        let baseline = validate(
            baseline_engine.as_ref(),
            &baseline_validator,
            TEMPLATE_WITH_OVERLAY_PROPERTY,
            ValidateConfig::default(),
        );
        assert!(baseline.diagnostics.iter().any(|diagnostic| diagnostic.rule_id == "F3002"));
    }

    let source = AdditionalSchemaSource { type_name: None, schema: LAMBDA_OVERLAY_SCHEMA.to_string() };
    let schema_config = SchemaValidatorConfig::new().with_additional_schemas([source]);
    let schema_validator = SchemaValidator::new(schema_config.clone()).expect("overlay schema must apply");
    let engine_config = EngineConfig::new().with_schema_validator_config(schema_config);
    for engine in both_engines(engine_config) {
        let report =
            validate(engine.as_ref(), &schema_validator, TEMPLATE_WITH_OVERLAY_PROPERTY, ValidateConfig::default());
        assert!(!report.diagnostics.iter().any(|diagnostic| diagnostic.rule_id == "F3002"));
    }
}

#[test]
fn engine_native_custom_rules_fire() {
    let schema_validator = SchemaValidator::default();
    let engines: Vec<Box<dyn ValidationEngine>> = vec![
        Box::new(
            RegoEngine::new(EngineConfig::new().with_custom_rules([ExternalRuleSource {
                name: "custom.rego".to_string(),
                content: REGO_CUSTOM_RULE.to_string(),
            }]))
            .expect("custom Rego rule must compile"),
        ),
        Box::new(
            CelEngine::new(EngineConfig::new().with_custom_rules([ExternalRuleSource {
                name: "custom.json".to_string(),
                content: CEL_CUSTOM_RULE.to_string(),
            }]))
            .expect("custom CEL rule must compile"),
        ),
    ];

    for engine in engines {
        let report = validate(engine.as_ref(), &schema_validator, UNENCRYPTED_BUCKET, ValidateConfig::default());
        let hits: Vec<_> = report.diagnostics.iter().filter(|diagnostic| diagnostic.rule_id == "CUSTOM001").collect();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].message, "S3 bucket must have encryption configured");
    }
}

#[test]
fn guard_rule_fires_on_both_engines() {
    let schema_validator = SchemaValidator::default();
    let config = EngineConfig::new().with_guard_rules([ExternalRuleSource {
        name: "encryption.guard".to_string(),
        content: GUARD_RULE.to_string(),
    }]);

    for engine in both_engines(config) {
        let report = validate(engine.as_ref(), &schema_validator, UNENCRYPTED_BUCKET, ValidateConfig::default());
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.message.to_ascii_lowercase().contains("encryption") })
        );
    }
}

#[test]
fn semantic_model_is_available_through_the_facade() {
    let model = SemanticModel::from_bytes(UNENCRYPTED_BUCKET).expect("template must parse");
    let bucket = model.resources.get("MyBucket").expect("MyBucket resource must exist");
    assert_eq!(bucket.resource_type, "AWS::S3::Bucket");
    assert!(model.parameters.is_empty());
    assert!(model.outputs.is_empty());
    assert!(model.conditions.names().next().is_none());
    assert!(model.transforms.is_empty());
}
