use cel_engine::CelEngine;
use diagnostics::Diagnostic;
use rego_engine::RegoEngine;
use schema_validator::SchemaValidator;
use std::sync::LazyLock;
use validation_engine::{EngineConfig, ValidateConfig, ValidationEngine, validate_bytes};

static SCHEMA_VALIDATOR: LazyLock<SchemaValidator> = LazyLock::new(SchemaValidator::default);
static REGO: LazyLock<RegoEngine> = LazyLock::new(|| RegoEngine::new(EngineConfig::default()).unwrap());
static CEL: LazyLock<CelEngine> = LazyLock::new(|| CelEngine::new(EngineConfig::default()).unwrap());

fn validate(engine: &dyn ValidationEngine, template: &str) -> Vec<Diagnostic> {
    validate_bytes(engine, &SCHEMA_VALIDATOR, template.as_bytes(), ValidateConfig::default())
        .expect("validation should succeed")
        .diagnostics
}

fn signatures(diagnostics: &[Diagnostic]) -> Vec<String> {
    let mut signatures = diagnostics
        .iter()
        .map(|diagnostic| {
            serde_json::to_string(&diagnostic.to_detailed()).expect("diagnostic serialization should succeed")
        })
        .collect::<Vec<_>>();
    signatures.sort();
    signatures
}

fn validate_with_parity(template: &str) -> Vec<Diagnostic> {
    let rego = validate(&*REGO, template);
    let cel = validate(&*CEL, template);
    assert_eq!(signatures(&rego), signatures(&cel), "engine diagnostics must match exactly");
    rego
}

#[test]
fn malformed_resource_condition_does_not_create_primary_identifier_conflict() {
    let template = r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  InvalidCondition:
    Type: AWS::S3::Bucket
    Condition: true
    Properties:
      BucketName: shared-name
  ValidResource:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: shared-name
"#;

    let diagnostics = validate_with_parity(template);
    assert!(
        diagnostics.iter().any(|diagnostic| {
            diagnostic.rule_id == "E3001" && diagnostic.resource_logical_id() == Some("InvalidCondition")
        }),
        "the malformed condition must retain its structural diagnostic"
    );
    assert!(
        diagnostics.iter().all(|diagnostic| diagnostic.rule_id != "E3019"),
        "a resource whose deployment condition is malformed cannot participate in a coexistence check"
    );
}

#[test]
fn inline_if_condition_expression_does_not_create_unreachable_branch_warning() {
    let template = r#"
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  Environment:
    Type: String
Conditions:
  IsProduction: !Equals [!Ref Environment, production]
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Condition: IsProduction
    Properties:
      BucketName:
        Fn::If:
          - Fn::Not:
              - Condition: IsProduction
          - impossible-name
          - production-name
"#;

    let diagnostics = validate_with_parity(template);
    assert!(
        diagnostics.iter().any(|diagnostic| diagnostic.rule_id == "E1028"),
        "the invalid first argument must retain its syntax diagnostic"
    );
    assert!(
        diagnostics.iter().all(|diagnostic| diagnostic.rule_id != "W1028"),
        "invalid inline syntax must not participate in reachability analysis"
    );
}

#[test]
fn unrelated_resource_shape_defects_still_participate_in_primary_identifier_checks() {
    let template = r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  UnknownAttribute:
    Type: AWS::S3::Bucket
    Bogus: value
    Properties:
      BucketName: shared-name
  MalformedDependsOn:
    Type: AWS::S3::Bucket
    DependsOn: 123
    Properties:
      BucketName: shared-name
"#;

    let diagnostics = validate_with_parity(template);
    for resource_id in ["UnknownAttribute", "MalformedDependsOn"] {
        assert!(
            diagnostics.iter().any(|diagnostic| {
                diagnostic.rule_id == "E3001" && diagnostic.resource_logical_id() == Some(resource_id)
            }),
            "the resource-shape defect must remain visible for {resource_id}"
        );
        assert!(
            diagnostics.iter().any(|diagnostic| {
                diagnostic.rule_id == "E3019" && diagnostic.resource_logical_id() == Some(resource_id)
            }),
            "an unrelated shape defect must not disable coexistence analysis for {resource_id}"
        );
    }
}
