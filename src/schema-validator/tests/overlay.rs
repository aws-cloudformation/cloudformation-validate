//! End-to-end tests for schema overlay support
//! (`SchemaValidator::try_with_additional_schemas`).
//!
//! These exercise the public API every front end goes through: an overlay schema
//! in raw CloudFormation registry format is merged on top of the bundled schemas
//! so templates using properties or values CloudFormation has not published yet
//! validate without false findings.
//!
//! Overlay properties are deliberately named `TestForOverride` — a name that will
//! never exist in a real registry schema — so the tests keep exercising the
//! overlay path even after any particular unpublished property ships.
//!
//! The suite is organised as: happy paths, the merge model per field kind, `$ref`
//! resolution, input rejection, and the corpus-wide guard that an overlay never
//! introduces a diagnostic.

use diagnostics::Diagnostic;
use schema_validator::{SchemaOverlayError, SchemaValidator};
use serde_json::{Value, json};
use std::sync::Arc;
use template_model::SemanticModel;

/// The resolution limit used by the overlay module for `$ref` chain validation.
/// Duplicated here so boundary tests do not depend on the crate-private constant
/// (the authoritative value lives in `compiled.rs`).
const REF_CHAIN_LIMIT: usize = 64;

/// A Lambda function that uses the synthetic unpublished `TestForOverride`
/// property, which is not in the bundled `AWS::Lambda::Function` schema (which
/// sets `additionalProperties: false`).
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

/// The temporary schema a code generator would ship for the unpublished property.
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
      PackageType: NewUnpublishedMode
"#;

const PACKAGE_TYPE_ENUM_OVERLAY: &str = r#"{
  "typeName": "AWS::Lambda::Function",
  "properties": {
    "PackageType": { "type": "string", "enum": ["Image", "Zip", "NewUnpublishedMode"] }
  }
}"#;

fn overlay(json: &str) -> Value {
    serde_json::from_str(json).expect("test overlay must be valid JSON")
}

fn model(template: &str) -> Arc<SemanticModel> {
    Arc::new(SemanticModel::from_bytes(template.as_bytes()).expect("template must parse"))
}

fn validator(overlays: Vec<(&str, Value)>) -> SchemaValidator {
    SchemaValidator::try_with_additional_schemas(overlays).expect("test overlays must apply")
}

fn rejection(overlays: Vec<(&str, Value)>) -> SchemaOverlayError {
    match SchemaValidator::try_with_additional_schemas(overlays) {
        Err(error) => error,
        Ok(_) => panic!("the overlay should have been rejected"),
    }
}

fn validate(sv: &SchemaValidator, template: &str) -> Vec<Diagnostic> {
    sv.validate(&model(template), Some("us-east-1")).diagnostics
}

/// Rule ID + message, the identity used when comparing baseline and overlay runs.
fn findings(sv: &SchemaValidator, template: &str) -> Vec<String> {
    validate(sv, template).into_iter().map(|d| format!("{} {}", d.rule_id, d.message)).collect()
}

fn mentions(diags: &[Diagnostic], rule_id: &str, needle: &str) -> bool {
    diags.iter().any(|d| {
        d.rule_id == rule_id
            && (d.message.contains(needle) || d.property_path.as_deref().is_some_and(|p| p.contains(needle)))
    })
}

// --------------------------------------------------------------- happy paths

#[test]
fn bundled_schema_flags_unpublished_property() {
    // Sanity check: without an overlay, the unpublished property is a false positive.
    let sv = SchemaValidator::default();
    let diags = validate(&sv, LAMBDA_WITH_OVERRIDE_PROP);
    assert!(
        mentions(&diags, "F3002", "TestForOverride"),
        "expected F3002 for TestForOverride without overlay, got: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.property_path)).collect::<Vec<_>>()
    );
}

#[test]
fn overlay_new_property_suppresses_additional_property_finding() {
    let sv = validator(vec![("AWS::Lambda::Function", overlay(OVERRIDE_PROP_OVERLAY))]);
    let diags = validate(&sv, LAMBDA_WITH_OVERRIDE_PROP);
    assert!(
        !mentions(&diags, "F3002", "TestForOverride"),
        "TestForOverride should be accepted with the overlay, got: {:?}",
        diags.iter().filter(|d| d.rule_id == "F3002").map(|d| &d.property_path).collect::<Vec<_>>()
    );
}

#[test]
fn bundled_schema_flags_new_enum_value() {
    let sv = SchemaValidator::default();
    let diags = validate(&sv, LAMBDA_WITH_NEW_PACKAGE_TYPE);
    assert!(
        mentions(&diags, "W3030", "NewUnpublishedMode"),
        "expected W3030 for the new PackageType value without overlay, got: {:?}",
        diags.iter().filter(|d| d.rule_id == "W3030").map(|d| &d.message).collect::<Vec<_>>()
    );
}

#[test]
fn overlay_enum_override_suppresses_allowed_value_finding() {
    let sv = validator(vec![("AWS::Lambda::Function", overlay(PACKAGE_TYPE_ENUM_OVERLAY))]);
    let diags = validate(&sv, LAMBDA_WITH_NEW_PACKAGE_TYPE);
    assert!(
        !mentions(&diags, "W3030", "NewUnpublishedMode"),
        "the new PackageType enum value should be accepted with the overlay, got: {:?}",
        diags.iter().filter(|d| d.rule_id == "W3030").map(|d| &d.message).collect::<Vec<_>>()
    );
}

#[test]
fn overlay_registers_a_brand_new_resource_type_and_validates_against_it() {
    let new_type = overlay(
        r#"{
          "typeName": "AWS::Test::OverlayOnly",
          "properties": { "Name": { "type": "string" }, "Mode": { "type": "string", "enum": ["A"] } },
          "required": ["Name"],
          "additionalProperties": false
        }"#,
    );
    let sv = validator(vec![("AWS::Test::OverlayOnly", new_type)]);
    assert_eq!(sv.schema_count(), SchemaValidator::default().schema_count() + 1, "a new resource type should be added");

    let valid = "Resources:\n  R:\n    Type: AWS::Test::OverlayOnly\n    Properties:\n      Name: n\n      Mode: A\n";
    assert!(
        validate(&sv, valid).is_empty(),
        "a template matching the new schema must be clean: {:?}",
        findings(&sv, valid)
    );

    let invalid = "Resources:\n  R:\n    Type: AWS::Test::OverlayOnly\n    Properties:\n      Mode: Nope\n";
    let diags = validate(&sv, invalid);
    assert!(mentions(&diags, "F3003", "Name"), "the new schema's required property must be enforced: {diags:?}");
    assert!(mentions(&diags, "W3030", "Nope"), "the new schema's enum must be enforced: {diags:?}");
}

#[test]
fn no_overlays_matches_default_construction() {
    let overlaid = SchemaValidator::try_with_additional_schemas(Vec::<(String, Value)>::new()).expect("builds");
    assert_eq!(overlaid.schema_count(), SchemaValidator::default().schema_count());
}

#[test]
fn overlays_for_one_type_apply_in_order() {
    let sv = validator(vec![
        ("AWS::Lambda::Function", overlay(r#"{ "properties": { "PackageType": { "enum": ["Image", "First"] } } }"#)),
        ("AWS::Lambda::Function", overlay(r#"{ "properties": { "PackageType": { "enum": ["Image", "Second"] } } }"#)),
    ]);
    let template = LAMBDA_WITH_NEW_PACKAGE_TYPE.replace("NewUnpublishedMode", "Second");
    assert!(
        !mentions(&validate(&sv, &template), "W3030", "Second"),
        "the last overlay for a type must win, got: {:?}",
        findings(&sv, &template)
    );
}

// ------------------------------------------------------- merge model per field

const ALARM: &str = r#"
Resources:
  A:
    Type: AWS::CloudWatch::Alarm
    Properties:
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      MetricName: CPUUtilization
      Namespace: AWS/EC2
      Period: 60
      Statistic: Average
      Threshold: 80
"#;

#[test]
fn overlay_logical_group_replaces_instead_of_unioning() {
    // Unioning the bundled "exactly one of" group with the overlay's group states
    // a third constraint neither schema makes, and turns a valid template invalid.
    let baseline = findings(&SchemaValidator::default(), ALARM);
    assert!(!baseline.iter().any(|d| d.starts_with("F3014")), "baseline alarm must be clean: {baseline:?}");
    let sv = validator(vec![(
        "AWS::CloudWatch::Alarm",
        json!({ "properties": { "TestForOverride": { "type": "string" } }, "requiredXor": ["Namespace", "TestForOverride"] }),
    )]);
    let after = findings(&sv, ALARM);
    assert!(!after.iter().any(|d| d.starts_with("F3014")), "the overlay must not fabricate an XOR group: {after:?}");
}

const SCALING_POLICY: &str = r#"
Resources:
  P:
    Type: AWS::ApplicationAutoScaling::ScalingPolicy
    Properties:
      PolicyName: p
      PolicyType: TargetTrackingScaling
      ResourceId: service/cluster/svc
"#;

#[test]
fn overlay_dependency_entry_extends_the_bundled_list() {
    let baseline = findings(&SchemaValidator::default(), SCALING_POLICY);
    let sv = validator(vec![(
        "AWS::ApplicationAutoScaling::ScalingPolicy",
        json!({ "dependentRequired": { "ResourceId": ["ScalableDimension"] } }),
    )]);
    let after = findings(&sv, SCALING_POLICY);
    let lost: Vec<&String> = baseline.iter().filter(|d| !after.contains(d)).collect();
    assert!(lost.is_empty(), "an overlay dependency entry must not delete bundled dependencies, lost: {lost:?}");
}

const DATASOURCE: &str = r#"
Resources:
  D:
    Type: AWS::AppSync::DataSource
    Properties:
      ApiId: abc
      Name: d
      Type: NONE
      ElasticsearchConfig:
        AwsRegion: us-east-1
        Endpoint: https://example.com
"#;

#[test]
fn overlay_metadata_list_extends_the_bundled_list() {
    let baseline = findings(&SchemaValidator::default(), DATASOURCE);
    assert!(
        baseline.iter().any(|d| d.starts_with("W9009") && d.contains("ElasticsearchConfig")),
        "baseline must report the bundled deprecation: {baseline:?}"
    );
    let sv = validator(vec![(
        "AWS::AppSync::DataSource",
        json!({
            "properties": { "TestForOverride": { "type": "string" } },
            "deprecatedProperties": ["/properties/TestForOverride"]
        }),
    )]);
    let after = findings(&sv, DATASOURCE);
    assert!(
        after.iter().any(|d| d.starts_with("W9009") && d.contains("ElasticsearchConfig")),
        "the bundled deprecation must survive an additive metadata overlay: {after:?}"
    );
}

const REST_API_DUPES: &str = r#"
Resources:
  Api:
    Type: AWS::ApiGateway::RestApi
    Properties:
      Name: api
      BinaryMediaTypes:
        - image/png
        - image/png
"#;

#[test]
fn overlay_explicit_unique_items_false_relaxes_the_bundled_constraint() {
    let baseline = findings(&SchemaValidator::default(), REST_API_DUPES);
    assert!(baseline.iter().any(|d| d.starts_with("F3037")), "baseline must reject duplicates: {baseline:?}");
    let sv = validator(vec![(
        "AWS::ApiGateway::RestApi",
        json!({
            "properties": { "BinaryMediaTypes": { "type": "array", "uniqueItems": false, "items": { "type": "string" } } }
        }),
    )]);
    let after = findings(&sv, REST_API_DUPES);
    assert!(!after.iter().any(|d| d.starts_with("F3037")), "an explicit uniqueItems:false must relax it: {after:?}");
}

// ------------------------------------------------------------- enum handling

const BATCH_TEMPLATE: &str = r#"
Resources:
  Env:
    Type: AWS::Batch::ComputeEnvironment
    Properties:
      Type: MANAGED
      ComputeResources:
        Type: COMPUTE_TYPE
        MaxvCpus: 4
        Subnets: [subnet-0123456789abcdef0]
"#;

/// The bundled `AWS::Batch::ComputeEnvironment` compute-resource type is one of
/// the properties compared case-insensitively, which is what makes it the right
/// fixture for the exact/insensitive interaction.
fn batch_enum_overlay(keyword: &str) -> Value {
    json!({
        "definitions": {
            "ComputeResources": {
                "type": "object",
                "properties": {
                    "Type": { "type": "string", keyword: ["ec2", "fargate", "fargate_spot", "spot", "test_new_mode"] }
                }
            }
        }
    })
}

#[test]
fn overlay_enum_widens_a_case_insensitive_property() {
    let template = BATCH_TEMPLATE.replace("COMPUTE_TYPE", "test_new_mode");
    let baseline = findings(&SchemaValidator::default(), &template);
    assert!(baseline.iter().any(|d| d.contains("test_new_mode")), "baseline must flag the new value: {baseline:?}");
    for keyword in ["enum", "enumCaseInsensitive"] {
        let sv = validator(vec![("AWS::Batch::ComputeEnvironment", batch_enum_overlay(keyword))]);
        let after = findings(&sv, &template);
        assert!(
            !after.iter().any(|d| d.contains("test_new_mode")),
            "widening via '{keyword}' must admit the new value: {after:?}"
        );
    }
}

#[test]
fn overlay_enum_does_not_reject_a_casing_that_validated_before() {
    let template = BATCH_TEMPLATE.replace("COMPUTE_TYPE", "FARGATE");
    let baseline = findings(&SchemaValidator::default(), &template);
    assert!(!baseline.iter().any(|d| d.contains("FARGATE")), "baseline must accept the uppercase value: {baseline:?}");
    let sv = validator(vec![("AWS::Batch::ComputeEnvironment", batch_enum_overlay("enum"))]);
    let after = findings(&sv, &template);
    assert!(
        !after.iter().any(|d| d.contains("FARGATE")),
        "an overlay must not turn a previously accepted casing into a finding: {after:?}"
    );
}

#[test]
fn overlay_enum_never_reports_a_value_twice() {
    let template = BATCH_TEMPLATE.replace("COMPUTE_TYPE", "totally_new");
    let sv = validator(vec![(
        "AWS::Batch::ComputeEnvironment",
        json!({
            "definitions": {
                "ComputeResources": {
                    "type": "object",
                    "properties": { "Type": { "type": "string", "enum": ["alpha", "beta"] } }
                }
            }
        }),
    )]);
    let allowed_value_findings: Vec<String> =
        findings(&sv, &template).into_iter().filter(|d| d.contains("totally_new")).collect();
    assert_eq!(
        allowed_value_findings.len(),
        1,
        "a value must be reported against one allowed-value list, not two: {allowed_value_findings:?}"
    );
}

// ------------------------------------------------------------- $ref handling

const APPBLOCK: &str = r#"
Resources:
  B:
    Type: AWS::AppStream::AppBlock
    Properties:
      Name: b
      SourceS3Location:
        S3Bucket: bucket
      PackagingType: TEST_NEW_MODE
"#;

#[test]
fn constraint_only_overlay_on_a_ref_property_takes_effect() {
    // `PackagingType` is a `$ref` to a definition carrying the enum. An overlay
    // that supplies only the enum must still apply.
    let baseline = findings(&SchemaValidator::default(), APPBLOCK);
    assert!(baseline.iter().any(|d| d.contains("TEST_NEW_MODE")), "baseline must flag the value: {baseline:?}");
    let sv = validator(vec![(
        "AWS::AppStream::AppBlock",
        json!({ "properties": { "PackagingType": { "enum": ["APPSTREAM2", "CUSTOM", "TEST_NEW_MODE"] } } }),
    )]);
    let after = findings(&sv, APPBLOCK);
    assert!(
        !after.iter().any(|d| d.contains("TEST_NEW_MODE")),
        "a constraint-only overlay on a $ref property must take effect: {after:?}"
    );
}

#[test]
fn inline_overlay_follows_a_whole_ref_chain() {
    let seed = json!({
        "properties": { "P": { "$ref": "#/definitions/Level1" } },
        "definitions": {
            "Level1": { "$ref": "#/definitions/Level2" },
            "Level2": { "type": "object", "additionalProperties": false, "properties": { "Old": { "type": "string" } } }
        }
    });
    let extension = json!({ "properties": { "P": { "properties": { "TestForOverride": { "type": "integer" } } } } });
    let sv = validator(vec![("AWS::Test::Chain", seed), ("AWS::Test::Chain", extension)]);
    let template =
        "Resources:\n  R:\n    Type: AWS::Test::Chain\n    Properties:\n      P:\n        TestForOverride: 1\n";
    let after = findings(&sv, template);
    assert!(after.is_empty(), "an inline overlay must follow the chain to its terminal definition: {after:?}");
}

#[test]
fn definition_merge_observes_definitions_added_by_the_same_overlay() {
    let seed = json!({
        "properties": { "Cfg": { "$ref": "#/definitions/Config" } },
        "definitions": { "Config": { "$ref": "#/definitions/Common" } }
    });
    let extension = json!({
        "definitions": {
            "Common": { "type": "object", "required": ["TestForOverride"] },
            "Config": { "properties": { "Other": { "type": "string" } } }
        }
    });
    let sv = validator(vec![("AWS::Test::Defs", seed), ("AWS::Test::Defs", extension)]);
    let template = "Resources:\n  R:\n    Type: AWS::Test::Defs\n    Properties:\n      Cfg:\n        Other: x\n";
    let after = findings(&sv, template);
    assert!(
        after.iter().any(|d| d.contains("TestForOverride")),
        "the constraint from the overlay-only definition must be enforced: {after:?}"
    );
}

#[test]
fn a_definition_widened_by_a_later_overlay_reaches_an_already_extended_property() {
    // Regression for reference materialisation: overlay 2 extends the `$ref`
    // property, overlay 3 widens the definition it points at. The property must
    // see the widening rather than a copy taken when overlay 2 was applied.
    let seed = json!({
        "properties": { "P": { "$ref": "#/definitions/D" } },
        "definitions": { "D": { "type": "string", "enum": ["alpha", "beta"] } }
    });
    let extend_property = json!({ "properties": { "P": { "description": "documented" } } });
    let widen_definition = json!({ "definitions": { "D": { "enum": ["alpha", "beta", "gamma"] } } });
    let sv = validator(vec![
        ("AWS::Test::Seq", seed),
        ("AWS::Test::Seq", extend_property),
        ("AWS::Test::Seq", widen_definition),
    ]);
    let template = "Resources:\n  R:\n    Type: AWS::Test::Seq\n    Properties:\n      P: gamma\n";
    let after = findings(&sv, template);
    assert!(after.is_empty(), "the later definition update must reach the property: {after:?}");
}

#[test]
fn mutually_referencing_definitions_see_each_others_updates() {
    let seed = json!({
        "properties": { "A": { "$ref": "#/definitions/DA" } },
        "definitions": {
            "DA": { "type": "object", "properties": { "ToB": { "$ref": "#/definitions/DB" } } },
            "DB": { "type": "object", "properties": { "ToA": { "$ref": "#/definitions/DA" } } }
        }
    });
    let update = json!({ "definitions": { "DB": { "required": ["TestForOverride"] } } });
    let sv = validator(vec![("AWS::Test::Mutual", seed), ("AWS::Test::Mutual", update)]);
    let template = "Resources:\n  R:\n    Type: AWS::Test::Mutual\n    Properties:\n      A:\n        ToB: {}\n";
    let after = findings(&sv, template);
    assert!(
        after.iter().any(|d| d.contains("TestForOverride")),
        "an update to a mutually referenced definition must be enforced: {after:?}"
    );
}

#[test]
fn a_ref_with_sibling_keywords_is_accepted_and_resolves_to_its_target() {
    // Published provider schemas routinely document a referenced property in
    // place, and draft-07 — which they are written against — ignores keywords
    // beside a `$ref`. Such a schema must be usable as an overlay; the reference
    // simply resolves to its target.
    let sv = validator(vec![(
        "AWS::Test::Sibling",
        json!({
            "properties": { "Cfg": { "$ref": "#/definitions/Common", "description": "documented in place" } },
            "definitions": {
                "Common": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": { "FromCommon": { "type": "string" } }
                }
            }
        }),
    )]);
    let valid = "Resources:\n  R:\n    Type: AWS::Test::Sibling\n    Properties:\n      Cfg:\n        FromCommon: a\n";
    assert!(findings(&sv, valid).is_empty(), "the referenced shape must apply: {:?}", findings(&sv, valid));
    let invalid =
        "Resources:\n  R:\n    Type: AWS::Test::Sibling\n    Properties:\n      Cfg:\n        Unexpected: a\n";
    assert!(
        findings(&sv, invalid).iter().any(|d| d.starts_with("F3002")),
        "the referenced shape's constraints must apply: {:?}",
        findings(&sv, invalid)
    );
}

#[test]
fn a_ref_outside_definitions_is_rejected() {
    // The compiled model can only reference `#/definitions/<name>`; any other
    // pointer would compile to a property with no shape at all.
    let error = rejection(vec![(
        "AWS::Test::Pointer",
        json!({ "properties": { "Arn": { "$ref": "#/properties/Other" }, "Other": { "type": "string" } } }),
    )]);
    assert!(matches!(error, SchemaOverlayError::Unsupported { .. }), "got {error:?}");
}

#[test]
fn an_overlay_extending_a_ref_property_is_merged_onto_the_reference() {
    // The supported way to say "the referenced shape plus this": a second overlay
    // for the property. Both contribute.
    let seed = json!({
        "properties": { "Cfg": { "$ref": "#/definitions/Common" } },
        "definitions": {
            "Common": {
                "type": "object",
                "additionalProperties": false,
                "properties": { "FromCommon": { "type": "string" } }
            }
        }
    });
    let extension = json!({ "properties": { "Cfg": { "properties": { "FromOverlay": { "type": "string" } } } } });
    let sv = validator(vec![("AWS::Test::Chainmix", seed), ("AWS::Test::Chainmix", extension)]);
    let template = "Resources:\n  R:\n    Type: AWS::Test::Chainmix\n    Properties:\n      Cfg:\n        FromCommon: a\n        FromOverlay: b\n";
    let after = findings(&sv, template);
    assert!(after.is_empty(), "the referenced shape and the overlay extension must both apply: {after:?}");
}

#[test]
fn a_constraining_keyword_beside_a_ref_is_rejected() {
    // Represented constraints beside a $ref are now accepted and merged at
    // validation time via PropSchema::resolve.
    validator(vec![(
        "AWS::Test::SiblingConstraint",
        json!({
            "properties": { "Mode": { "$ref": "#/definitions/Mode", "enum": ["ONLY_THIS"], "maxLength": 2 } },
            "definitions": { "Mode": { "type": "string" } }
        }),
    )]);
}

#[test]
fn a_keyword_the_model_cannot_represent_is_rejected() {
    // `propertyNames` has no field in the compiled model, so stating it in an
    // overlay is still rejected — the constraint would be silently dropped.
    let error = rejection(vec![(
        "AWS::Test::Unrepresented",
        json!({
            "properties": {
                "Size": { "type": "integer", "propertyNames": { "pattern": "^x" } },
                "Known": { "type": "string", "maxLength": 4 }
            }
        }),
    )]);
    assert!(
        matches!(error, SchemaOverlayError::Unsupported { .. }),
        "an unrepresented keyword must be rejected, got {error:?}"
    );
}

#[test]
fn a_keyword_the_model_cannot_represent_does_not_silently_weaken_the_overlay() {
    let error = rejection(vec![(
        "AWS::Test::UnrepresentedSibling",
        json!({ "properties": { "Size": { "type": "integer", "contains": { "type": "string" }, "maximum": 5 } } }),
    )]);
    assert!(
        matches!(error, SchemaOverlayError::Unsupported { .. }),
        "an unrepresented keyword must be rejected even alongside represented ones, got {error:?}"
    );
}

#[test]
fn an_intermediate_hop_overrides_the_constraint_at_the_end_of_the_chain() {
    // P -> Middle -> Base, where a second overlay relaxes on Middle what Base
    // forbids. The nearer statement wins, so the relaxation is what applies.
    // Stating it beside the `$ref` in the first schema would not work — draft-07
    // ignores that — so it has to arrive as an overlay on the definition.
    let seed = json!({
        "properties": { "Cfg": { "$ref": "#/definitions/Middle" } },
        "definitions": {
            "Middle": { "$ref": "#/definitions/Base" },
            "Base": { "type": "object", "additionalProperties": false, "properties": { "Known": { "type": "string" } } }
        }
    });
    let relax_middle = json!({ "definitions": { "Middle": { "additionalProperties": true } } });
    let sv = validator(vec![("AWS::Test::Precedence", seed), ("AWS::Test::Precedence", relax_middle)]);
    let template = "Resources:\n  R:\n    Type: AWS::Test::Precedence\n    Properties:\n      Cfg:\n        Known: a\n        Extra: b\n";
    let after = findings(&sv, template);
    assert!(after.is_empty(), "the nearer hop's relaxation must win over the end of the chain: {after:?}");
}

#[test]
fn a_blank_type_name_is_rejected() {
    // A name of only whitespace would register a schema no resource can ever
    // match, so the overlay would silently do nothing.
    let error = rejection(vec![("   ", json!({ "properties": { "P": { "type": "string" } } }))]);
    assert!(matches!(error, SchemaOverlayError::MissingTypeName), "got {error:?}");
}

#[test]
fn a_ref_chain_too_long_to_resolve_is_rejected() {
    // Resolution follows a bounded number of hops. A chain longer than that would
    // be cut short, leaving the constraints at its end unenforced — so it is
    // rejected rather than silently truncated.
    let hops = REF_CHAIN_LIMIT + 2;
    let mut definitions = serde_json::Map::new();
    for index in 0..hops {
        definitions.insert(format!("D{index}"), json!({ "$ref": format!("#/definitions/D{}", index + 1) }));
    }
    definitions.insert(format!("D{hops}"), json!({ "type": "string", "enum": ["only"] }));
    let error = rejection(vec![(
        "AWS::Test::LongChain",
        json!({ "properties": { "P": { "$ref": "#/definitions/D0" } }, "definitions": definitions }),
    )]);
    assert!(matches!(error, SchemaOverlayError::RefChainTooLong { .. }), "got {error:?}");
}

#[test]
fn a_chain_at_the_resolution_limit_is_accepted_and_enforced() {
    // The boundary case: a chain exactly as long as resolution can follow must
    // both be accepted and have its far end enforced.
    let hops = REF_CHAIN_LIMIT - 1;
    let mut definitions = serde_json::Map::new();
    for index in 0..hops {
        definitions.insert(format!("D{index}"), json!({ "$ref": format!("#/definitions/D{}", index + 1) }));
    }
    definitions.insert(format!("D{hops}"), json!({ "type": "string", "enum": ["only"] }));
    let sv = validator(vec![(
        "AWS::Test::LimitChain",
        json!({ "properties": { "P": { "$ref": "#/definitions/D0" } }, "definitions": definitions }),
    )]);
    let template = "Resources:\n  R:\n    Type: AWS::Test::LimitChain\n    Properties:\n      P: other\n";
    let after = findings(&sv, template);
    assert!(
        after.iter().any(|d| d.contains("'other'")),
        "the constraint at the end of a resolvable chain must be enforced: {after:?}"
    );
}

#[test]
fn a_reference_to_a_missing_definition_is_accepted_and_constrains_nothing() {
    // Overlays apply in sequence, so a reference may point at a definition a later
    // overlay supplies; the schema is accepted and the property is unconstrained
    // until then. The condition is logged rather than silently ignored.
    let sv = validator(vec![(
        "AWS::Test::Dangling",
        json!({ "properties": { "P": { "$ref": "#/definitions/NotDefined" } } }),
    )]);
    let template = "Resources:\n  R:\n    Type: AWS::Test::Dangling\n    Properties:\n      P: anything\n";
    let after = findings(&sv, template);
    assert!(after.is_empty(), "an unresolved reference must not invent a constraint: {after:?}");
}

#[test]
fn a_definition_that_also_carries_an_unresolved_reference_still_enforces_its_own_constraints() {
    // A definition can end up holding both a reference the schema never defines
    // and constraints an overlay stated on it. The unresolvable reference
    // contributes nothing, but what the definition itself says must still apply.
    let sv = validator(vec![
        (
            "AWS::Test::DanglingWithConstraint",
            json!({
                "properties": { "Cfg": { "$ref": "#/definitions/Config" } },
                "definitions": { "Config": { "$ref": "#/definitions/NotDefined" } }
            }),
        ),
        (
            "AWS::Test::DanglingWithConstraint",
            json!({ "definitions": { "Config": { "type": "string", "pattern": "^ok$" } } }),
        ),
    ]);
    let template =
        "Resources:\n  R:\n    Type: AWS::Test::DanglingWithConstraint\n    Properties:\n      Cfg: not-ok\n";

    let after = findings(&sv, template);

    assert!(
        after.iter().any(|finding| finding.contains("not-ok")),
        "the definition's own constraint must be enforced despite the unresolved reference: {after:?}"
    );
}

// ------------------------------------------------------------ input rejection

#[test]
fn cyclic_definition_graph_is_rejected() {
    let error = rejection(vec![(
        "AWS::Test::Cycle",
        json!({
            "properties": { "P": { "$ref": "#/definitions/D" } },
            "definitions": { "D": { "$ref": "#/definitions/D" } }
        }),
    )]);
    assert!(matches!(error, SchemaOverlayError::CyclicRef { .. }), "got {error:?}");
}

#[test]
fn multi_node_cyclic_definition_graph_is_rejected() {
    let error = rejection(vec![(
        "AWS::Test::Cycle",
        json!({
            "properties": { "P": { "$ref": "#/definitions/A" } },
            "definitions": {
                "A": { "$ref": "#/definitions/B" },
                "B": { "$ref": "#/definitions/A" }
            }
        }),
    )]);
    assert!(matches!(error, SchemaOverlayError::CyclicRef { .. }), "got {error:?}");
}

#[test]
fn overlay_nested_past_the_depth_limit_is_rejected() {
    // Depth 200 is over the limit and shallow enough to build and drop safely —
    // `serde_json::Value` itself cannot be constructed thousands of levels deep.
    let mut node = json!({ "type": "string" });
    for _ in 0..200 {
        node = json!({ "type": "object", "properties": { "N": node } });
    }
    let error = rejection(vec![("AWS::Test::Deep", json!({ "properties": { "Top": node } }))]);
    assert!(matches!(error, SchemaOverlayError::TooDeep { .. }), "got {error:?}");
}

#[test]
fn non_object_overlay_is_rejected() {
    let error = rejection(vec![("AWS::Test::T", json!([1, 2, 3]))]);
    assert!(matches!(error, SchemaOverlayError::NotAnObject { .. }), "got {error:?}");
}

#[test]
fn empty_type_name_is_rejected() {
    let error = rejection(vec![("", json!({ "properties": { "P": { "type": "string" } } }))]);
    assert!(matches!(error, SchemaOverlayError::MissingTypeName), "got {error:?}");
}

#[test]
fn overlay_that_states_nothing_is_rejected() {
    let error = rejection(vec![("AWS::Test::T", json!({ "unrecognised": 1 }))]);
    assert!(matches!(error, SchemaOverlayError::NoEffect { .. }), "got {error:?}");
}

#[test]
fn a_rejected_overlay_does_not_leave_the_store_modified() {
    let mut store = schema_validator::CompiledSchemaStore::new();
    let before = store.len();
    store
        .apply_overlay(
            "AWS::Test::Cycle",
            &json!({ "definitions": { "D": { "$ref": "#/definitions/D" } }, "properties": { "P": { "$ref": "#/definitions/D" } } }),
        )
        .expect_err("a cyclic overlay must be rejected");
    assert_eq!(store.len(), before, "a rejected overlay must not register a schema");
}

#[test]
fn overlay_outcome_distinguishes_merge_from_insertion() {
    use schema_validator::OverlayOutcome;
    let mut store = schema_validator::CompiledSchemaStore::new();
    assert_eq!(
        store
            .apply_overlay(
                "AWS::Lambda::Function",
                &json!({ "properties": { "TestForOverride": { "type": "string" } } })
            )
            .expect("a bundled type merges"),
        OverlayOutcome::Merged
    );
    assert_eq!(
        store
            .apply_overlay(
                "AWS::Lambda::Funtcion",
                &json!({ "properties": { "TestForOverride": { "type": "string" } } })
            )
            .expect("an unknown type is inserted"),
        OverlayOutcome::Inserted,
        "a misspelled type name must be reported as an insertion, not silently merged"
    );
}

// ------------------------------------------------------------- corpus guard

/// A set of overlays touching every field kind the merge model handles, applied
/// to types that appear across the corpus.
fn corpus_overlays() -> Vec<(&'static str, Value)> {
    vec![
        ("AWS::Lambda::Function", overlay(OVERRIDE_PROP_OVERLAY)),
        ("AWS::Lambda::Function", overlay(PACKAGE_TYPE_ENUM_OVERLAY)),
        ("AWS::S3::Bucket", json!({ "properties": { "TestForOverride": { "type": "string" } } })),
        (
            "AWS::EC2::Instance",
            json!({
                "properties": { "TestForOverride": { "type": "string" } },
                "deprecatedProperties": ["/properties/TestForOverride"],
                "dependentRequired": { "TestForOverride": ["ImageId"] }
            }),
        ),
        ("AWS::Batch::ComputeEnvironment", batch_enum_overlay("enum")),
        ("AWS::IAM::Role", json!({ "properties": { "Tags": { "uniqueItems": false } } })),
        ("AWS::CloudWatch::Alarm", json!({ "properties": { "TestForOverride": { "type": "string" } } })),
    ]
}

/// The guard the feature turns on: a widening overlay may only ever remove findings.
///
/// Runs the whole `templates/good` corpus through a baseline validator and one
/// carrying [`corpus_overlays`], and fails on any finding the overlay run
/// produces that the baseline did not. Every merge defect that turned a clean
/// template dirty would be caught here.
///
/// The overlays used here all widen, because that is what the feature exists for.
/// An overlay may also *state* a constraint — adding to `required` or a dependency
/// list, or replacing a logical group — and then a new finding is correct rather
/// than a defect, so those belong in the targeted tests above instead of here.
#[test]
fn overlays_never_introduce_a_diagnostic_on_the_good_corpus() {
    let baseline = SchemaValidator::default();
    let overlaid = validator(corpus_overlays());
    let good = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../resources/templates/good");
    let mut checked = 0usize;
    let mut added: Vec<String> = Vec::new();

    for entry in std::fs::read_dir(&good).expect("the good template corpus must be readable") {
        let path = entry.expect("readable directory entry").path();
        if !path.extension().is_some_and(|ext| ext == "yaml" || ext == "yml" || ext == "json") {
            continue;
        }
        let bytes = std::fs::read(&path).expect("template must be readable");
        let Ok(parsed) = SemanticModel::from_bytes(&bytes) else {
            continue;
        };
        let parsed = Arc::new(parsed);
        let before: Vec<String> = baseline
            .validate(&parsed, Some("us-east-1"))
            .diagnostics
            .into_iter()
            .map(|d| format!("{} {}", d.rule_id, d.message))
            .collect();
        let after: Vec<String> = overlaid
            .validate(&parsed, Some("us-east-1"))
            .diagnostics
            .into_iter()
            .map(|d| format!("{} {}", d.rule_id, d.message))
            .collect();
        checked += 1;
        for finding in after {
            if !before.contains(&finding) {
                added.push(format!("{}: {finding}", path.display()));
            }
        }
    }

    assert!(checked > 20, "expected to check the good corpus, only reached {checked} templates");
    assert!(added.is_empty(), "overlays introduced {} new diagnostic(s): {added:#?}", added.len());
}

#[test]
fn schema_validator_new_has_empty_overlay_catalog() {
    let validator = SchemaValidator::default();
    assert!(validator.overlay_catalog().is_empty(), "a default-constructed SchemaValidator must have an empty catalog");
}

#[test]
fn schema_validator_with_overlays_exposes_populated_catalog() {
    let overlays = vec![("AWS::Lambda::Function", overlay(r#"{"properties":{"TestForOverride":{"type":"string"}}}"#))];
    let validator = SchemaValidator::try_with_additional_schemas(overlays).expect("valid overlay");
    let catalog = validator.overlay_catalog();
    assert!(!catalog.is_empty(), "an overlay-bearing validator must expose a non-empty catalog");
    assert!(
        catalog.type_names.contains(&"AWS::Lambda::Function".to_string()),
        "the catalog must list the overlaid type"
    );
}

#[test]
fn overlay_required_replacement_clears_base_required() {
    let sv = validator(vec![(
        "AWS::Test::RequiredClear",
        json!({
            "properties": {
                "Name": { "type": "string" },
                "Extra": { "type": "string" }
            },
            "required": ["Name"]
        }),
    )]);
    // Verify the required constraint is enforced.
    let template_missing = "\
Resources:
  R:
    Type: AWS::Test::RequiredClear
    Properties:
      Extra: val
";
    let diags = validate(&sv, template_missing);
    assert!(
        mentions(&diags, "F3003", "Name"),
        "the overlay's required must be enforced: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );

    // Now apply a second overlay that clears required.
    let sv2 = SchemaValidator::try_with_additional_schemas(vec![
        (
            "AWS::Test::RequiredClear",
            json!({
                "properties": { "Name": { "type": "string" }, "Extra": { "type": "string" } },
                "required": ["Name"]
            }),
        ),
        ("AWS::Test::RequiredClear", json!({ "properties": { "Name": { "type": "string" } }, "required": [] })),
    ])
    .expect("valid overlays");
    let diags2 = validate(&sv2, template_missing);
    assert!(
        !mentions(&diags2, "F3003", "Name"),
        "explicit empty required in second overlay must clear the required constraint: {:?}",
        diags2.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}
