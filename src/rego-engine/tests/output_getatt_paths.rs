//! Integration tests for precise output-value source paths from
//! top-level DiagnosticModel.edges.
//!
//! Verifies that the Rego engine uses the `sourcePath` from edges (where source
//! is `__output__<name>` and kind is GetAtt) rather than the generic
//! `Outputs/<name>/Value` path. Covers direct dotted-string GetAtt, list-form
//! GetAtt, nested map/list, Fn::Sub implicit GetAtt, and no duplicate
//! container+literal diagnostics.

use diagnostics::Diagnostic;
use rego_engine::RegoEngine;
use schema_validator::SchemaValidator;
use std::sync::LazyLock;
use validation_engine::{EngineConfig, ValidateConfig, validate_bytes};

static SV: LazyLock<SchemaValidator> = LazyLock::new(SchemaValidator::default);

fn f6101_diagnostics(template: &str) -> Vec<Diagnostic> {
    let engine = RegoEngine::new(EngineConfig::default()).unwrap();
    let report = validate_bytes(&engine, &SV, template.as_bytes(), ValidateConfig::default()).unwrap();
    report.diagnostics.into_iter().filter(|d| d.rule_id == "F6101").collect()
}

fn f6101_getatt_diagnostics(template: &str) -> Vec<Diagnostic> {
    f6101_diagnostics(template).into_iter().filter(|d| d.message.contains("GetAtt")).collect()
}

fn f6101_paths(template: &str) -> Vec<String> {
    let mut paths: Vec<String> =
        f6101_getatt_diagnostics(template).into_iter().map(|d| d.property_path.unwrap_or_default()).collect();
    paths.sort();
    paths
}

/// Direct dotted-string GetAtt in output: `!GetAtt Res.Attr`
/// Path should include the terminal intrinsic: `Outputs/<name>/Value.Fn::GetAtt`.
#[test]
fn direct_dotted_string_getatt() {
    let template = r#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  CapacityReservation:
    Type: AWS::EC2::CapacityReservation
    Properties:
      AvailabilityZone: us-east-1a
      InstanceCount: 1
      InstanceType: t2.micro
      InstancePlatform: Linux/UNIX
Outputs:
  DottedString:
    Value: !GetAtt CapacityReservation.InstanceCount
"#;
    let paths = f6101_paths(template);
    assert_eq!(paths, vec!["Outputs/DottedString/Value.Fn::GetAtt"]);
    let diags = f6101_getatt_diagnostics(template);
    assert_eq!(diags.len(), 1);
    assert!(diags[0].message.contains("CapacityReservation.InstanceCount"));
    assert!(diags[0].message.contains("integer"));
}

/// List-form GetAtt in output: `Fn::GetAtt: [Res, Attr]`
/// Path should include the terminal intrinsic: `Outputs/<name>/Value.Fn::GetAtt`.
#[test]
fn list_form_getatt() {
    let template = r#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  CapacityReservation:
    Type: AWS::EC2::CapacityReservation
    Properties:
      AvailabilityZone: us-east-1a
      InstanceCount: 1
      InstanceType: t2.micro
      InstancePlatform: Linux/UNIX
Outputs:
  ListForm:
    Value:
      Fn::GetAtt:
        - CapacityReservation
        - InstanceCount
"#;
    let paths = f6101_paths(template);
    assert_eq!(paths, vec!["Outputs/ListForm/Value.Fn::GetAtt"]);
}

/// GetAtt nested inside Fn::Join: path includes the terminal intrinsic after
/// the join list element position, e.g. `Outputs/<name>/Value.Fn::Join.1.0.Fn::GetAtt`.
#[test]
fn nested_in_join() {
    let template = r#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  CapacityReservation:
    Type: AWS::EC2::CapacityReservation
    Properties:
      AvailabilityZone: us-east-1a
      InstanceCount: 1
      InstanceType: t2.micro
      InstancePlatform: Linux/UNIX
Outputs:
  JoinOutput:
    Value:
      Fn::Join:
        - ""
        - - !GetAtt CapacityReservation.InstanceCount
"#;
    let paths = f6101_paths(template);
    assert_eq!(paths, vec!["Outputs/JoinOutput/Value.Fn::Join.1.0.Fn::GetAtt"]);
}

/// Implicit GetAtt inside Fn::Sub: `${Resource.Attr}` in a Sub string.
/// Path should include the terminal intrinsic: `Outputs/<name>/Value.Fn::Sub`.
#[test]
fn fn_sub_implicit_getatt() {
    let template = r#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  CapacityReservation:
    Type: AWS::EC2::CapacityReservation
    Properties:
      AvailabilityZone: us-east-1a
      InstanceCount: 1
      InstanceType: t2.micro
      InstancePlatform: Linux/UNIX
Outputs:
  SubOutput:
    Value:
      Fn::Sub: "Count is ${CapacityReservation.InstanceCount}"
"#;
    let paths = f6101_paths(template);
    assert_eq!(paths, vec!["Outputs/SubOutput/Value.Fn::Sub"]);
}

/// GetAtt inside a literal list output value should NOT produce a duplicate
/// The parse-time "value must be a string, not a list" diagnostic
/// already covers it. The string-position filter prevents the engine rule from
/// firing on this edge.
#[test]
fn no_duplicate_container_and_literal() {
    let template = r#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  CapacityReservation:
    Type: AWS::EC2::CapacityReservation
    Properties:
      AvailabilityZone: us-east-1a
      InstanceCount: 1
      InstanceType: t2.micro
      InstancePlatform: Linux/UNIX
Outputs:
  ListOutput:
    Value:
      - !GetAtt CapacityReservation.InstanceCount
      - "other"
"#;
    // The only finding should be the parse-time "value must be a string, not a list" diagnostic.
    let all_f6101 = f6101_diagnostics(template);
    assert_eq!(all_f6101.len(), 1);
    assert!(all_f6101[0].message.contains("not a list"));
    // No GetAtt-specific finding should fire.
    let getatt_f6101 = f6101_getatt_diagnostics(template);
    assert_eq!(getatt_f6101.len(), 0);
}

/// Combined template with all forms produces exactly four GetAtt-specific
/// diagnostics with precise paths.
#[test]
fn combined_all_forms() {
    let template = r#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  CapacityReservation:
    Type: AWS::EC2::CapacityReservation
    Properties:
      AvailabilityZone: us-east-1a
      InstanceCount: 1
      InstanceType: t2.micro
      InstancePlatform: Linux/UNIX
Outputs:
  DottedString:
    Value: !GetAtt CapacityReservation.InstanceCount
  ListForm:
    Value:
      Fn::GetAtt:
        - CapacityReservation
        - InstanceCount
  NestedJoin:
    Value:
      Fn::Join:
        - ""
        - - !GetAtt CapacityReservation.InstanceCount
  SubImplicit:
    Value:
      Fn::Sub: "Count is ${CapacityReservation.InstanceCount}"
"#;
    let diags = f6101_getatt_diagnostics(template);
    assert_eq!(diags.len(), 4);
    let paths = f6101_paths(template);
    assert_eq!(
        paths,
        vec![
            "Outputs/DottedString/Value.Fn::GetAtt",
            "Outputs/ListForm/Value.Fn::GetAtt",
            "Outputs/NestedJoin/Value.Fn::Join.1.0.Fn::GetAtt",
            "Outputs/SubImplicit/Value.Fn::Sub",
        ]
    );
}

/// Regression: output name starting with "Value" must not confuse the
/// `/Value` splitting. The GetAtt nested in a Join under output `ValueFoo`
/// must produce `Outputs/ValueFoo/Value.Fn::Join.1.0`, not a path that
/// incorrectly parses "Foo/Value.Fn::Join.1.0" as the tail.
#[test]
fn value_prefixed_output_name_join_getatt() {
    let template = r#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  CapacityReservation:
    Type: AWS::EC2::CapacityReservation
    Properties:
      AvailabilityZone: us-east-1a
      InstanceCount: 1
      InstanceType: t2.micro
      InstancePlatform: Linux/UNIX
Outputs:
  ValueFoo:
    Value:
      Fn::Join:
        - ""
        - - !GetAtt CapacityReservation.InstanceCount
"#;
    let paths = f6101_paths(template);
    assert_eq!(paths, vec!["Outputs/ValueFoo/Value.Fn::Join.1.0.Fn::GetAtt"]);
}
