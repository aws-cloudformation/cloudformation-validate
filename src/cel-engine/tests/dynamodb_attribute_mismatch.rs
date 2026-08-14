use cel_engine::CelEngine;
use diagnostics::Diagnostic;
use rules::Severity;
use schema_validator::SchemaValidator;
use std::sync::LazyLock;
use validation_engine::{EngineConfig, ValidateConfig, validate_bytes};

static SV: LazyLock<SchemaValidator> = LazyLock::new(SchemaValidator::default);

fn validate(template: &str) -> Vec<Diagnostic> {
    let engine = CelEngine::new(EngineConfig::default()).unwrap();
    let report = validate_bytes(&engine, &SV, template.as_bytes(), ValidateConfig::default()).unwrap();
    report.diagnostics.into_iter().filter(|d| d.rule_id == "E3039").collect()
}

#[test]
fn table_only_missing_definition() {
    let template = r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: test
      AttributeDefinitions:
        - AttributeName: pk
          AttributeType: S
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
        - AttributeName: sk
          KeyType: RANGE
"#;
    let findings = validate(template);
    assert_eq!(findings.len(), 1, "Expected 1 finding, got: {:?}", findings);
    let d = &findings[0];
    assert_eq!(d.rule_id, "E3039");
    assert_eq!(d.severity, Severity::Error);
    assert_eq!(d.property_path.as_deref(), Some("Properties"));
    assert_eq!(d.entity.as_ref().unwrap().logical_id, "MyTable");
    assert_eq!(d.message, "AttributeDefinitions does not match KeySchema attributes. missing definitions: [sk]");
}

#[test]
fn gsi_missing_definition() {
    let template = r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: test
      AttributeDefinitions:
        - AttributeName: pk
          AttributeType: S
        - AttributeName: sk
          AttributeType: S
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
        - AttributeName: sk
          KeyType: RANGE
      GlobalSecondaryIndexes:
        - IndexName: gsi1
          KeySchema:
            - AttributeName: gsi_pk
              KeyType: HASH
          Projection:
            ProjectionType: ALL
"#;
    let findings = validate(template);
    assert_eq!(findings.len(), 1, "Expected 1 finding, got: {:?}", findings);
    let d = &findings[0];
    assert_eq!(d.rule_id, "E3039");
    assert_eq!(d.severity, Severity::Error);
    assert_eq!(d.property_path.as_deref(), Some("Properties"));
    assert_eq!(d.entity.as_ref().unwrap().logical_id, "MyTable");
    assert!(d.message.contains("missing definitions: [gsi_pk]"), "Expected missing gsi_pk, got: {}", d.message);
}

#[test]
fn lsi_missing_definition() {
    let template = r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: test
      AttributeDefinitions:
        - AttributeName: pk
          AttributeType: S
        - AttributeName: sk
          AttributeType: S
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
        - AttributeName: sk
          KeyType: RANGE
      LocalSecondaryIndexes:
        - IndexName: lsi1
          KeySchema:
            - AttributeName: pk
              KeyType: HASH
            - AttributeName: lsi_sk
              KeyType: RANGE
          Projection:
            ProjectionType: ALL
"#;
    let findings = validate(template);
    assert_eq!(findings.len(), 1, "Expected 1 finding, got: {:?}", findings);
    let d = &findings[0];
    assert_eq!(d.rule_id, "E3039");
    assert_eq!(d.severity, Severity::Error);
    assert_eq!(d.property_path.as_deref(), Some("Properties"));
    assert_eq!(d.entity.as_ref().unwrap().logical_id, "MyTable");
    assert!(d.message.contains("missing definitions: [lsi_sk]"), "Expected missing lsi_sk, got: {}", d.message);
}

#[test]
fn unused_definition() {
    let template = r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: test
      AttributeDefinitions:
        - AttributeName: pk
          AttributeType: S
        - AttributeName: sk
          AttributeType: S
        - AttributeName: extra
          AttributeType: N
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
        - AttributeName: sk
          KeyType: RANGE
"#;
    let findings = validate(template);
    assert_eq!(findings.len(), 1, "Expected 1 finding, got: {:?}", findings);
    let d = &findings[0];
    assert_eq!(d.rule_id, "E3039");
    assert_eq!(d.severity, Severity::Error);
    assert_eq!(d.property_path.as_deref(), Some("Properties"));
    assert_eq!(d.entity.as_ref().unwrap().logical_id, "MyTable");
    assert_eq!(d.message, "AttributeDefinitions does not match KeySchema attributes. unused definitions: [extra]");
}

#[test]
fn combined_missing_and_unused() {
    let template = r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: test
      AttributeDefinitions:
        - AttributeName: pk
          AttributeType: S
        - AttributeName: extra
          AttributeType: N
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
        - AttributeName: sk
          KeyType: RANGE
"#;
    let findings = validate(template);
    assert_eq!(findings.len(), 1, "Expected 1 finding, got: {:?}", findings);
    let d = &findings[0];
    assert_eq!(d.rule_id, "E3039");
    assert_eq!(d.severity, Severity::Error);
    assert_eq!(d.property_path.as_deref(), Some("Properties"));
    assert_eq!(d.entity.as_ref().unwrap().logical_id, "MyTable");
    assert_eq!(
        d.message,
        "AttributeDefinitions does not match KeySchema attributes. missing definitions: [sk]; unused definitions: [extra]"
    );
}

#[test]
fn duplicate_references_set_semantics() {
    // The same attribute referenced in both table KeySchema and GSI KeySchema
    // should not cause duplication issues -- set semantics deduplicate.
    let template = r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: test
      AttributeDefinitions:
        - AttributeName: pk
          AttributeType: S
        - AttributeName: sk
          AttributeType: S
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
        - AttributeName: sk
          KeyType: RANGE
      GlobalSecondaryIndexes:
        - IndexName: gsi1
          KeySchema:
            - AttributeName: sk
              KeyType: HASH
            - AttributeName: pk
              KeyType: RANGE
          Projection:
            ProjectionType: ALL
"#;
    let findings = validate(template);
    assert_eq!(findings.len(), 0, "Expected no findings, got: {:?}", findings);
}

#[test]
fn fully_valid_table_gsi_lsi() {
    let template = r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: test
      AttributeDefinitions:
        - AttributeName: pk
          AttributeType: S
        - AttributeName: sk
          AttributeType: S
        - AttributeName: gsi_pk
          AttributeType: S
        - AttributeName: lsi_sk
          AttributeType: N
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
        - AttributeName: sk
          KeyType: RANGE
      GlobalSecondaryIndexes:
        - IndexName: gsi1
          KeySchema:
            - AttributeName: gsi_pk
              KeyType: HASH
            - AttributeName: sk
              KeyType: RANGE
          Projection:
            ProjectionType: ALL
      LocalSecondaryIndexes:
        - IndexName: lsi1
          KeySchema:
            - AttributeName: pk
              KeyType: HASH
            - AttributeName: lsi_sk
              KeyType: RANGE
          Projection:
            ProjectionType: ALL
"#;
    let findings = validate(template);
    assert_eq!(findings.len(), 0, "Expected no findings, got: {:?}", findings);
}

#[test]
fn dynamic_gsi_authored_but_unresolvable_no_finding() {
    // GSI property is authored via a Ref (dynamic value that cannot resolve to
    // an array). The rule should skip this table conservatively rather than
    // treating the index as absent and reporting false positives.
    // gsi_pk is defined but only referenced by the unresolvable GSI -- without
    // the conservative guard, this would falsely emit an unused-definition finding.
    let template = r#"
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  GSIs:
    Type: String
Resources:
  MyTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: test
      AttributeDefinitions:
        - AttributeName: pk
          AttributeType: S
        - AttributeName: gsi_pk
          AttributeType: S
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
      GlobalSecondaryIndexes: !Ref GSIs
"#;
    let findings = validate(template);
    assert_eq!(findings.len(), 0, "Dynamic GSI should suppress finding, got: {:?}", findings);
}

#[test]
fn malformed_index_key_schema_no_finding() {
    // A GSI item is present but its KeySchema cannot resolve to the expected
    // array shape (it is a Ref). The rule should bail conservatively.
    // gsi_pk is defined but only referenced by the unresolvable index KeySchema
    // -- without the conservative guard, this would falsely emit an
    // unused-definition finding.
    let template = r#"
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  KeySchemaParam:
    Type: String
Resources:
  MyTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: test
      AttributeDefinitions:
        - AttributeName: pk
          AttributeType: S
        - AttributeName: gsi_pk
          AttributeType: S
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
      GlobalSecondaryIndexes:
        - IndexName: gsi1
          KeySchema: !Ref KeySchemaParam
          Projection:
            ProjectionType: ALL
"#;
    let findings = validate(template);
    assert_eq!(findings.len(), 0, "Malformed index KeySchema should suppress finding, got: {:?}", findings);
}

#[test]
fn conditional_gsi_reports_missing_table_key_suppresses_unused() {
    // GSI is behind a condition so its content is unresolvable. The table
    // KeySchema references 'sk' which is NOT in AttributeDefinitions —
    // that is always wrong regardless of the index. But 'gsi_pk' should
    // NOT be reported unused because the conditional index might use it.
    let template = r#"
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  AddGSI:
    Type: String
Conditions:
  CreateGSI: !Equals [!Ref AddGSI, "true"]
Resources:
  MyTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: test
      AttributeDefinitions:
        - AttributeName: pk
          AttributeType: S
        - AttributeName: gsi_pk
          AttributeType: S
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
        - AttributeName: sk
          KeyType: RANGE
      GlobalSecondaryIndexes: !If
        - CreateGSI
        - - IndexName: gsi1
            KeySchema:
              - AttributeName: gsi_pk
                KeyType: HASH
            Projection:
              ProjectionType: ALL
        - !Ref AWS::NoValue
"#;
    let findings = validate(template);
    assert_eq!(findings.len(), 1, "Expected 1 finding for missing 'sk', got: {:?}", findings);
    let d = &findings[0];
    assert_eq!(d.rule_id, "E3039");
    assert!(d.message.contains("missing definitions: [sk]"), "Expected missing sk, got: {}", d.message);
    assert!(!d.message.contains("unused"), "unused must be suppressed when index is unresolvable: {}", d.message);
}

#[test]
fn conditional_gsi_no_finding_when_table_keys_are_defined() {
    // All table KeySchema attributes are defined, and gsi_pk is also defined
    // for the conditional index. No finding should fire.
    let template = r#"
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  AddGSI:
    Type: String
Conditions:
  CreateGSI: !Equals [!Ref AddGSI, "true"]
Resources:
  MyTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: test
      AttributeDefinitions:
        - AttributeName: pk
          AttributeType: S
        - AttributeName: gsi_pk
          AttributeType: S
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
      GlobalSecondaryIndexes: !If
        - CreateGSI
        - - IndexName: gsi1
            KeySchema:
              - AttributeName: gsi_pk
                KeyType: HASH
            Projection:
              ProjectionType: ALL
        - !Ref AWS::NoValue
"#;
    let findings = validate(template);
    assert_eq!(findings.len(), 0, "No finding expected when table keys are defined, got: {:?}", findings);
}
