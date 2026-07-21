//! End-to-end tests for schema overlay support (`SchemaValidator::with_additional_schemas`).
//!
//! These exercise the public API the WASM/JVM bindings use: an overlay schema in
//! raw CloudFormation registry format is merged on top of the bundled schemas so
//! templates using pre-GA properties validate without false positives.
//!
//! The overlay property is deliberately named `TestForOverride` — a name that
//! will never exist in the real `AWS::Lambda::Function` registry schema — so the
//! test keeps exercising the overlay path even after any specific pre-GA property
//! (e.g. `AcceleratorConfig`) is published and merged into the bundled schemas.

use diagnostics::Diagnostic;
use schema_validator::SchemaValidator;
use serde_json::Value;
use std::sync::Arc;
use template_model::SemanticModel;

/// A Lambda function that uses the synthetic pre-GA `TestForOverride` property,
/// which is not in the bundled `AWS::Lambda::Function` schema (which has
/// `additionalProperties: false`).
const LAMBDA_WITH_OVERRIDE_PROP: &str = r#"
Resources:
  Fn:
    Type: AWS::Lambda::Function
    Properties:
      Code:
        ZipFile: "exports.handler = async () => {};"
      Role: arn:aws:iam::123456789012:role/lambda-role
      Runtime: nodejs18.x
      Handler: index.handler
      TestForOverride:
        TestOverrideValue: 24
"#;

/// The temporary/overlay schema spec2cdk would ship for the pre-GA property.
const OVERRIDE_PROP_OVERLAY: &str = r#"{
  "typeName": "AWS::Lambda::Function",
  "properties": {
    "TestForOverride": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "TestOverrideValue": { "type": "integer", "enum": [3, 6, 12, 16, 24, 48, 96] }
      },
      "required": ["TestOverrideValue"]
    }
  }
}"#;

/// A Lambda function whose `PackageType` uses a value not in the bundled enum
/// (`["Image", "Zip"]`).
const LAMBDA_WITH_NEW_PACKAGE_TYPE: &str = r#"
Resources:
  Fn:
    Type: AWS::Lambda::Function
    Properties:
      Code:
        ZipFile: "exports.handler = async () => {};"
      Role: arn:aws:iam::123456789012:role/lambda-role
      Runtime: nodejs18.x
      Handler: index.handler
      PackageType: NewPreGaMode
"#;

const PACKAGE_TYPE_ENUM_OVERLAY: &str = r#"{
  "typeName": "AWS::Lambda::Function",
  "properties": {
    "PackageType": { "type": "string", "enum": ["Image", "Zip", "NewPreGaMode"] }
  }
}"#;

fn overlay(json: &str) -> Value {
    serde_json::from_str(json).expect("test overlay must be valid JSON")
}

fn model(template: &str) -> Arc<SemanticModel> {
    Arc::new(SemanticModel::from_bytes(template.as_bytes()).expect("template must parse"))
}

fn validate(sv: &SchemaValidator, template: &str) -> Vec<Diagnostic> {
    sv.validate(&model(template), Some("us-east-1")).diagnostics
}

fn mentions(diags: &[Diagnostic], rule_id: &str, needle: &str) -> bool {
    diags.iter().any(|d| {
        d.rule_id == rule_id
            && (d.message.contains(needle) || d.property_path.as_deref().is_some_and(|p| p.contains(needle)))
    })
}

#[test]
fn bundled_schema_flags_pre_ga_property_as_f3002() {
    // Sanity check: without an overlay, the pre-GA property is a false positive.
    let sv = SchemaValidator::new();
    let diags = validate(&sv, LAMBDA_WITH_OVERRIDE_PROP);
    assert!(
        mentions(&diags, "F3002", "TestForOverride"),
        "expected F3002 for TestForOverride without overlay, got: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.property_path)).collect::<Vec<_>>()
    );
}

#[test]
fn overlay_new_property_suppresses_f3002() {
    let sv = SchemaValidator::with_additional_schemas([("AWS::Lambda::Function", overlay(OVERRIDE_PROP_OVERLAY))]);
    let diags = validate(&sv, LAMBDA_WITH_OVERRIDE_PROP);
    assert!(
        !mentions(&diags, "F3002", "TestForOverride"),
        "TestForOverride should be accepted with the overlay, got: {:?}",
        diags.iter().filter(|d| d.rule_id == "F3002").map(|d| &d.property_path).collect::<Vec<_>>()
    );
}

#[test]
fn bundled_schema_flags_new_enum_value_as_w3030() {
    let sv = SchemaValidator::new();
    let diags = validate(&sv, LAMBDA_WITH_NEW_PACKAGE_TYPE);
    assert!(
        mentions(&diags, "W3030", "NewPreGaMode"),
        "expected W3030 for the new PackageType value without overlay, got: {:?}",
        diags.iter().filter(|d| d.rule_id == "W3030").map(|d| &d.message).collect::<Vec<_>>()
    );
}

#[test]
fn overlay_enum_override_suppresses_w3030() {
    let sv = SchemaValidator::with_additional_schemas([("AWS::Lambda::Function", overlay(PACKAGE_TYPE_ENUM_OVERLAY))]);
    let diags = validate(&sv, LAMBDA_WITH_NEW_PACKAGE_TYPE);
    assert!(
        !mentions(&diags, "W3030", "NewPreGaMode"),
        "the new PackageType enum value should be accepted with the overlay, got: {:?}",
        diags.iter().filter(|d| d.rule_id == "W3030").map(|d| &d.message).collect::<Vec<_>>()
    );
}

#[test]
fn overlay_inserts_brand_new_resource_type() {
    // A typeName not in the bundled registry is inserted verbatim.
    let new_type = overlay(r#"{ "typeName": "AWS::Test::OverlayOnly", "properties": { "Name": { "type": "string" } } }"#);
    let sv = SchemaValidator::with_additional_schemas([("AWS::Test::OverlayOnly", new_type)]);
    assert_eq!(sv.schema_count(), SchemaValidator::new().schema_count() + 1, "a new resource type should be added");
}

#[test]
fn no_overlays_matches_default_construction() {
    let overlaid = SchemaValidator::with_additional_schemas(Vec::<(String, Value)>::new());
    assert_eq!(overlaid.schema_count(), SchemaValidator::new().schema_count());
}
