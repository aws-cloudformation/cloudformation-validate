//! End-to-end overlay tests through the full pipeline, on both engines.
//!
//! The overlay is configured once, on `EngineConfig`, and both the engine and the
//! schema validator are built from it. These tests assert the two things unit
//! tests on the merge cannot: that a configured overlay reaches validation at all,
//! and that the engines and the schema store agree about the resource types an
//! overlay introduces.

use cel_engine::CelEngine;
use diagnostics::Diagnostic;
use rego_engine::RegoEngine;
use validation_engine::{
    AdditionalSchemaSource, EngineConfig, ValidationEngine, schema_validator_from_config, validate_bytes,
};

/// A Lambda function using a property no registry schema will ever have.
const LAMBDA_WITH_OVERRIDE_PROP: &[u8] = br#"
Resources:
  Fn:
    Type: AWS::Lambda::Function
    Properties:
      Code:
        ZipFile: "exports.handler = async () => {};"
      Role: arn:aws:iam::123456789012:role/lambda-role
      Runtime: nodejs18.x
      Handler: index.handler
      TestForOverride: enabled
"#;

const OVERRIDE_PROP_SCHEMA: &str = r#"{
  "typeName": "AWS::Lambda::Function",
  "properties": { "TestForOverride": { "type": "string" } }
}"#;

/// A template whose only resource type comes from an overlay.
const OVERLAY_ONLY_TEMPLATE: &[u8] = br#"
Resources:
  R:
    Type: AWS::Test::OverlayOnly
    Properties:
      Name: thing
"#;

const OVERLAY_ONLY_SCHEMA: &str = r#"{
  "typeName": "AWS::Test::OverlayOnly",
  "properties": { "Name": { "type": "string" } },
  "required": ["Name"],
  "additionalProperties": false
}"#;

fn config_with(schema: &str) -> EngineConfig {
    EngineConfig {
        additional_schemas: vec![AdditionalSchemaSource { type_name: String::new(), schema: schema.to_string() }],
        ..Default::default()
    }
}

/// Runs the full pipeline on both engines, returning `(rego, cel)` diagnostics.
fn validate_on_both_engines(config: EngineConfig, template: &[u8]) -> (Vec<Diagnostic>, Vec<Diagnostic>) {
    let run = |engine: &dyn ValidationEngine| {
        let validator = schema_validator_from_config(&config).expect("the configured overlay must build a validator");
        validate_bytes(engine, &validator, template, Default::default()).expect("validation must succeed").diagnostics
    };
    let rego = RegoEngine::new(config.clone()).expect("rego engine builds");
    let cel = CelEngine::new(config.clone()).expect("cel engine builds");
    (run(&rego), run(&cel))
}

fn rule_ids(diagnostics: &[Diagnostic]) -> Vec<&str> {
    diagnostics.iter().map(|d| d.rule_id.as_str()).collect()
}

#[test]
fn configured_overlay_reaches_schema_validation_on_both_engines() {
    let (rego_baseline, cel_baseline) = validate_on_both_engines(EngineConfig::default(), LAMBDA_WITH_OVERRIDE_PROP);
    assert!(
        rule_ids(&rego_baseline).contains(&"F3002") && rule_ids(&cel_baseline).contains(&"F3002"),
        "without an overlay both engines must report the unknown property"
    );

    let (rego, cel) = validate_on_both_engines(config_with(OVERRIDE_PROP_SCHEMA), LAMBDA_WITH_OVERRIDE_PROP);
    for (engine, diagnostics) in [("rego", &rego), ("cel", &cel)] {
        assert!(
            !rule_ids(diagnostics).contains(&"F3002"),
            "{engine}: the configured overlay must suppress the unknown-property finding, got: {:?}",
            diagnostics.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
        );
    }
}

#[test]
fn overlay_resource_type_is_known_to_both_engines() {
    let (rego_baseline, cel_baseline) = validate_on_both_engines(EngineConfig::default(), OVERLAY_ONLY_TEMPLATE);
    assert!(
        rule_ids(&rego_baseline).contains(&"F3006") && rule_ids(&cel_baseline).contains(&"F3006"),
        "without an overlay both engines must report the unknown resource type"
    );

    let (rego, cel) = validate_on_both_engines(config_with(OVERLAY_ONLY_SCHEMA), OVERLAY_ONLY_TEMPLATE);
    for (engine, diagnostics) in [("rego", &rego), ("cel", &cel)] {
        assert!(
            !rule_ids(diagnostics).contains(&"F3006"),
            "{engine}: a type introduced by an overlay must not be reported as unknown, got: {:?}",
            diagnostics.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
        );
    }
    assert_eq!(rule_ids(&rego), rule_ids(&cel), "both engines must agree on the overlay-only type");
}

#[test]
fn a_malformed_overlay_fails_construction_on_both_engines() {
    let config = config_with(r#"{"typeName":"AWS::Test::T","properties":{"P":{"type":}}}"#);
    assert!(schema_validator_from_config(&config).is_err(), "invalid JSON must fail validator construction");
    assert!(RegoEngine::new(config.clone()).is_err(), "invalid JSON must fail rego engine construction");
    assert!(CelEngine::new(config).is_err(), "invalid JSON must fail cel engine construction");
}
