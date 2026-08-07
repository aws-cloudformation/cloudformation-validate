//! End-to-end overlay tests through the full pipeline, on both engines.
//!
//! The overlay is configured once, on `EngineConfig`, and both the engine and the
//! schema validator are built from it. These tests assert the two things unit
//! tests on the merge cannot: that a configured overlay reaches validation at all,
//! and that the engines and the schema store agree about the resource types an
//! overlay introduces.

use cel_engine::CelEngine;
use data_source::AdditionalSchemaSource;
use diagnostics::Diagnostic;
use rego_engine::RegoEngine;
use schema_validator::SchemaValidator;
use validation_engine::{EngineConfig, ValidationEngine, validate_bytes};

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

/// Template using GetAtt on an overlay-introduced readOnly attribute. The
/// attribute value is consumed by a resource property, not merely by an Output.
const GETATT_TEMPLATE: &[u8] = br#"
Resources:
  Source:
    Type: AWS::S3::Bucket
  Consumer:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: !GetAtt Source.TestForOverride
"#;

const GETATT_SOURCE_SCHEMA: &str = r#"{
  "typeName": "AWS::S3::Bucket",
  "properties": {
    "TestForOverride": { "type": "string" }
  },
  "readOnlyProperties": ["/properties/TestForOverride"]
}"#;

/// Template that creates two resources with duplicate primary identifiers.
const DUPLICATE_PRIMARY_ID_TEMPLATE: &[u8] = br#"
Resources:
  First:
    Type: AWS::Test::DupId
    Properties:
      Name: same-name
  Second:
    Type: AWS::Test::DupId
    Properties:
      Name: same-name
"#;

const DUPLICATE_PRIMARY_ID_SCHEMA: &str = r#"{
  "typeName": "AWS::Test::DupId",
  "properties": {
    "Name": { "type": "string" }
  },
  "required": ["Name"],
  "primaryIdentifier": ["/properties/Name"],
  "additionalProperties": false
}"#;

/// Template that triggers schema validation on a type with overlay-defined
/// property constraints - the schema validator uses the merged metadata.
const SCHEMA_METADATA_TEMPLATE: &[u8] = br#"
Resources:
  R:
    Type: AWS::Test::MetadataCheck
    Properties:
      Name: x
      Port: 99999
"#;

const SCHEMA_METADATA_SCHEMA: &str = r#"{
  "typeName": "AWS::Test::MetadataCheck",
  "properties": {
    "Name": { "type": "string", "minLength": 3, "maxLength": 10 },
    "Port": { "type": "integer", "minimum": 1, "maximum": 65535 }
  },
  "required": ["Name", "Port"],
  "primaryIdentifier": ["/properties/Name"],
  "additionalProperties": false
}"#;

const REF_TYPE_MISMATCH_TEMPLATE: &[u8] = br#"
Resources:
  Source:
    Type: AWS::Test::IntegerSource
    Properties:
      Id: 42
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      ObjectLockEnabled: !Ref Source
"#;

const INTEGER_SOURCE_SCHEMA: &str = r#"{
  "typeName": "AWS::Test::IntegerSource",
  "properties": { "Id": { "type": "integer" } },
  "required": ["Id"],
  "primaryIdentifier": ["/properties/Id"],
  "additionalProperties": false
}"#;

const TAGGABLE_OVERLAY_TEMPLATE: &[u8] = br#"
Resources:
  R:
    Type: AWS::Test::TaggableOverlay
    Properties:
      Name: example
"#;

const TAGGABLE_OVERLAY_SCHEMA: &str = r#"{
  "typeName": "AWS::Test::TaggableOverlay",
  "properties": {
    "Name": { "type": "string" },
    "Tags": { "type": "array", "items": { "type": "object" } }
  },
  "required": ["Name"],
  "additionalProperties": false
}"#;

const DANGLING_REFERENCE_SCHEMA: &str = r##"{
  "typeName": "AWS::Test::Dangling",
  "properties": { "P": { "$ref": "#/definitions/NotDefined" } }
}"##;

const FORWARD_REFERENCE_SCHEMA: &str = r##"{
  "typeName": "AWS::Test::ForwardRef",
  "properties": { "P": { "$ref": "#/definitions/SuppliedLater" } }
}"##;

const FORWARD_REFERENCE_DEFINITION_SCHEMA: &str = r#"{
  "typeName": "AWS::Test::ForwardRef",
  "definitions": { "SuppliedLater": { "type": "string" } }
}"#;

const ADDITIONAL_SCHEMA_SOURCES_DIR: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../resources/additional_schema_sources");

const FIXTURE_SCHEMA_VALIDATION_TEMPLATE: &[u8] = br#"
Resources:
  Function:
    Type: AWS::Lambda::Function
    Properties:
      Code:
        ZipFile: "exports.handler = async () => {};"
      Handler: index.handler
      Role: arn:aws:iam::123456789012:role/lambda-role
      Runtime: nodejs20.x
      AdditionalSchemaProperty: enabled
  Widget:
    Type: AWS::Test::Widget
    Properties:
      Name: x
      Port: 70000
      Tags:
        - Key: environment
          Value: test
"#;

const FIXTURE_ENGINE_METADATA_TEMPLATE: &[u8] = br#"
Resources:
  FirstWidget:
    Type: AWS::Test::Widget
    Properties:
      Name: shared-name
      Port: 443
  SecondWidget:
    Type: AWS::Test::Widget
    Properties:
      Name: shared-name
      Port: 8443
  Consumer:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: !GetAtt FirstWidget.Endpoint
"#;

fn config_with_schemas(schemas: &[&str]) -> EngineConfig {
    EngineConfig {
        schema_validator_config: Some(schema_validator::SchemaValidatorConfig {
            additional_schemas: schemas
                .iter()
                .map(|schema| AdditionalSchemaSource { type_name: None, schema: (*schema).to_string() })
                .collect(),
        }),
        ..Default::default()
    }
}

fn config_with(schema: &str) -> EngineConfig {
    config_with_schemas(&[schema])
}

fn config_from_fixture_directory() -> EngineConfig {
    let sources = cfn_validate::load_additional_schema_sources(&[ADDITIONAL_SCHEMA_SOURCES_DIR.to_string()])
        .expect("fixture schema directory must load");
    EngineConfig {
        schema_validator_config: Some(schema_validator::SchemaValidatorConfig { additional_schemas: sources }),
        ..Default::default()
    }
}

/// Runs the full pipeline on both engines, returning `(rego, cel)` diagnostics.
fn validate_on_both_engines(config: EngineConfig, template: &[u8]) -> (Vec<Diagnostic>, Vec<Diagnostic>) {
    let schema_config = config.schema_validator_config.clone().unwrap_or_default();
    let validator = SchemaValidator::new(schema_config).expect("the configured overlay must build a validator");
    let mut engine_config = config;
    engine_config.schema_validator_config = None;
    let rego = RegoEngine::new_with_schema_validator(engine_config.clone(), &validator).expect("rego engine builds");
    let cel = CelEngine::new_with_schema_validator(engine_config, &validator).expect("cel engine builds");
    let run = |engine: &dyn ValidationEngine| {
        validate_bytes(engine, &validator, template, Default::default()).expect("validation must succeed").diagnostics
    };
    (run(&rego), run(&cel))
}

fn assert_engine_parity(rego: &[Diagnostic], cel: &[Diagnostic]) {
    let rego_diagnostics = serde_json::to_value(rego).expect("rego diagnostics serialize");
    let cel_diagnostics = serde_json::to_value(cel).expect("cel diagnostics serialize");
    assert_eq!(rego_diagnostics, cel_diagnostics, "both engines must produce identical diagnostics");
}

#[test]
fn fixture_sources_reach_schema_validation_on_both_engines() {
    let (rego, cel) = validate_on_both_engines(config_from_fixture_directory(), FIXTURE_SCHEMA_VALIDATION_TEMPLATE);

    for (engine, diagnostics) in [("rego", &rego), ("cel", &cel)] {
        let ids = rule_ids(diagnostics);
        assert!(!ids.contains(&"F3002"), "{engine}: the Lambda extension and composed Tags property must be valid");
        assert!(!ids.contains(&"F3006"), "{engine}: the source-introduced widget type must be known");
        assert!(ids.contains(&"F3033"), "{engine}: the fixture's string constraint must be enforced");
        assert!(ids.contains(&"F3034"), "{engine}: the fixture's numeric constraint must be enforced");
    }
    assert_engine_parity(&rego, &cel);
}

#[test]
fn fixture_source_metadata_reaches_both_rule_engines() {
    let (rego, cel) = validate_on_both_engines(config_from_fixture_directory(), FIXTURE_ENGINE_METADATA_TEMPLATE);

    for (engine, diagnostics) in [("rego", &rego), ("cel", &cel)] {
        let ids = rule_ids(diagnostics);
        assert!(ids.contains(&"E3019"), "{engine}: the fixture's primary identifier must detect duplicates");
        assert!(ids.contains(&"I9040"), "{engine}: the fixture's Tags metadata must reach advisory rules");
        assert!(!ids.contains(&"E9004"), "{engine}: the fixture's read-only Endpoint attribute must be valid");
        assert!(!ids.contains(&"F3006"), "{engine}: the source-introduced widget type must be known");
    }
    assert_engine_parity(&rego, &cel);
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
    let schema_config = config.schema_validator_config.clone().unwrap_or_default();
    assert!(SchemaValidator::new(schema_config).is_err(), "invalid JSON must fail validator construction");
    assert!(RegoEngine::new(config.clone()).is_err(), "invalid JSON must fail rego engine construction");
    assert!(CelEngine::new(config).is_err(), "invalid JSON must fail cel engine construction");
}

#[test]
fn a_final_dangling_reference_fails_all_constructors() {
    let config = config_with(DANGLING_REFERENCE_SCHEMA);
    let schema_config = config.schema_validator_config.clone().unwrap_or_default();
    assert!(SchemaValidator::new(schema_config).is_err(), "the validator must reject a final dangling reference");
    assert!(RegoEngine::new(config.clone()).is_err(), "the rego engine must reject a final dangling reference");
    assert!(CelEngine::new(config).is_err(), "the cel engine must reject a final dangling reference");
}

#[test]
fn a_forward_reference_resolved_by_a_later_overlay_reaches_all_constructors() {
    let config = config_with_schemas(&[FORWARD_REFERENCE_SCHEMA, FORWARD_REFERENCE_DEFINITION_SCHEMA]);
    let schema_config = config.schema_validator_config.clone().unwrap_or_default();
    SchemaValidator::new(schema_config).expect("the validator must accept a resolved forward reference");
    RegoEngine::new(config.clone()).expect("the rego engine must accept a resolved forward reference");
    CelEngine::new(config).expect("the cel engine must accept a resolved forward reference");
}

/// GetAtt on an overlay-introduced readOnly attribute consumed by a resource
/// property must not produce an invalid-attribute finding.
#[test]
fn overlay_getatt_attribute_is_valid_in_resource_property() {
    let (rego_baseline, cel_baseline) = validate_on_both_engines(EngineConfig::default(), GETATT_TEMPLATE);
    for (engine, diagnostics) in [("rego", &rego_baseline), ("cel", &cel_baseline)] {
        assert!(
            rule_ids(diagnostics).contains(&"E9004"),
            "{engine}: the unpublished attribute must fail before the overlay, got: {:?}",
            diagnostics.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
        );
    }

    let (rego, cel) = validate_on_both_engines(config_with(GETATT_SOURCE_SCHEMA), GETATT_TEMPLATE);
    for (engine, diagnostics) in [("rego", &rego), ("cel", &cel)] {
        assert!(
            !rule_ids(diagnostics).contains(&"E9004"),
            "{engine}: GetAtt on overlay readOnly attribute must be valid, got: {:?}",
            diagnostics.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
        );
    }
    assert_eq!(rule_ids(&rego), rule_ids(&cel), "both engines must produce identical diagnostics");
}

/// Duplicate primary identifiers on an overlay-introduced type must fire the
/// duplicate-resource rule on both engines.
#[test]
fn overlay_duplicate_primary_identifiers_detected() {
    let (rego, cel) = validate_on_both_engines(config_with(DUPLICATE_PRIMARY_ID_SCHEMA), DUPLICATE_PRIMARY_ID_TEMPLATE);
    for (engine, diagnostics) in [("rego", &rego), ("cel", &cel)] {
        // Must not report unknown type
        assert!(!rule_ids(diagnostics).contains(&"F3006"), "{engine}: overlay type must be known");
        // Must detect duplicate primary identifiers
        assert!(
            rule_ids(diagnostics).contains(&"E3019"),
            "{engine}: duplicate primary identifiers must be detected, got rules: {:?}",
            rule_ids(diagnostics)
        );
    }
    // Parity
    let rego_ids: Vec<&str> = rego.iter().filter(|d| d.rule_id == "E3019").map(|d| d.rule_id.as_str()).collect();
    let cel_ids: Vec<&str> = cel.iter().filter(|d| d.rule_id == "E3019").map(|d| d.rule_id.as_str()).collect();
    assert_eq!(rego_ids, cel_ids, "both engines must agree on duplicate primary ID diagnostics");
}

#[test]
fn overlay_property_constraints_are_enforced() {
    let (rego, cel) = validate_on_both_engines(config_with(SCHEMA_METADATA_SCHEMA), SCHEMA_METADATA_TEMPLATE);
    for (engine, diagnostics) in [("rego", &rego), ("cel", &cel)] {
        // Must not report unknown type
        assert!(!rule_ids(diagnostics).contains(&"F3006"), "{engine}: overlay type must be known");
        // The Name "x" is only 1 char but minLength is 3 - triggers string length violation
        let constraint_diags: Vec<&Diagnostic> =
            diagnostics.iter().filter(|d| d.rule_id == "F3033" || d.rule_id == "F3034").collect();
        assert!(
            !constraint_diags.is_empty(),
            "{engine}: constraint violation (minLength) on overlay type must trigger a schema finding, got rules: {:?}",
            rule_ids(diagnostics)
        );
    }
}

#[test]
fn overlay_ref_return_type_is_checked() {
    let (rego, cel) = validate_on_both_engines(config_with(INTEGER_SOURCE_SCHEMA), REF_TYPE_MISMATCH_TEMPLATE);
    for (engine, diagnostics) in [("rego", &rego), ("cel", &cel)] {
        assert!(
            rule_ids(diagnostics).contains(&"F3012"),
            "{engine}: an integer Ref passed to a boolean property must fail, got: {:?}",
            diagnostics.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
        );
    }
    assert_eq!(rule_ids(&rego), rule_ids(&cel), "both engines must agree on Ref return-type validation");
}

#[test]
fn overlay_schema_metadata_reaches_both_rule_engines() {
    let (rego, cel) = validate_on_both_engines(config_with(TAGGABLE_OVERLAY_SCHEMA), TAGGABLE_OVERLAY_TEMPLATE);
    for (engine, diagnostics) in [("rego", &rego), ("cel", &cel)] {
        assert!(
            rule_ids(diagnostics).contains(&"I9040"),
            "{engine}: the tag advisory must see the overlay-defined Tags property, got: {:?}",
            diagnostics.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
        );
    }
    assert_eq!(rule_ids(&rego), rule_ids(&cel), "both engines must agree on overlay schema metadata");
}

/// A DocDB cluster whose Port is surfaced through an Output GetAtt. The
/// bundled data corrects Port's GetAtt return type from the provider-schema
/// `integer` to the `string` CloudFormation actually returns.
const DOCDB_PORT_OUTPUT_TEMPLATE: &[u8] = br#"
Resources:
  Cluster:
    Type: AWS::DocDB::DBCluster
    Properties:
      MasterUsername: admin
      MasterUserPassword: SuperSecret1
Outputs:
  DocDBClusterPort:
    Value: !GetAtt Cluster.Port
"#;

/// An overlay that merely adds a property to the corrected type.
const DOCDB_UNRELATED_OVERLAY: &str = r#"{
  "typeName": "AWS::DocDB::DBCluster",
  "properties": { "OverlayOnlyProbe": { "type": "string" } }
}"#;

#[test]
fn overlay_on_a_corrected_type_preserves_getatt_return_type_overrides() {
    // Baseline: the hand-maintained correction makes the Port output a string,
    // so no non-string-output finding fires.
    let (rego_baseline, cel_baseline) = validate_on_both_engines(EngineConfig::default(), DOCDB_PORT_OUTPUT_TEMPLATE);
    for (engine, diagnostics) in [("rego", &rego_baseline), ("cel", &cel_baseline)] {
        assert!(
            !rule_ids(diagnostics).contains(&"F6101"),
            "{engine}: the bundled GetAtt return-type correction must hold without overlays, got: {:?}",
            diagnostics.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
        );
    }

    // An unrelated overlay on the same type must not clobber the correction by
    // re-deriving Port's type from the raw provider schema.
    let (rego, cel) = validate_on_both_engines(config_with(DOCDB_UNRELATED_OVERLAY), DOCDB_PORT_OUTPUT_TEMPLATE);
    for (engine, diagnostics) in [("rego", &rego), ("cel", &cel)] {
        assert!(
            !rule_ids(diagnostics).contains(&"F6101"),
            "{engine}: overlaying a corrected type must preserve the GetAtt return-type override, got: {:?}",
            diagnostics.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
        );
    }
    assert_eq!(rule_ids(&rego), rule_ids(&cel), "both engines must agree on the corrected type");
}
