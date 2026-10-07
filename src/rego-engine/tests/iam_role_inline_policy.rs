//! Tests verifying that the Rego engine invokes shared identity-policy structural validation.
//!
//! The shared validator now covers all statement-level checks including missing Effect,
//! invalid Effect values, missing Action/NotAction, empty Action arrays, duplicate Sid,
//! and the Condition operator schema.

use diagnostics::ValidationReport;
use rego_engine::RegoEngine;
use schema_validator::SchemaValidator;
use std::sync::LazyLock;
use validation_engine::{EngineConfig, ValidateConfig, validate_bytes};

static ENGINE: LazyLock<RegoEngine> = LazyLock::new(|| RegoEngine::new(EngineConfig::default()).unwrap());
static SV: LazyLock<SchemaValidator> = LazyLock::new(SchemaValidator::default);

fn validate(template: &str) -> ValidationReport {
    validate_bytes(&*ENGINE, &SV, template.as_bytes(), ValidateConfig::default()).unwrap()
}

fn diags_for_rule<'a>(report: &'a ValidationReport, rule_id: &str) -> Vec<&'a diagnostics::Diagnostic> {
    report.diagnostics.iter().filter(|d| d.rule_id == rule_id).collect()
}

// ---------------------------------------------------------------------------
// Valid templates should have no structural identity-policy findings.
// ---------------------------------------------------------------------------

#[test]
fn valid_role_inline_policies_no_findings() {
    let report = validate(
        r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: InlineOne
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: s3:GetObject
                Resource: '*'
        - PolicyName: InlineTwo
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Deny
                Action: s3:DeleteBucket
                Resource: '*'
              - Effect: Allow
                NotAction: s3:PutObject
                Resource: '*'
"#,
    );
    let e3510 = diags_for_rule(&report, "E3510");
    assert!(e3510.is_empty(), "Expected no E3510 findings, got: {e3510:?}");
}

#[test]
fn valid_multiple_roles_no_findings() {
    let report = validate(
        r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  RoleA:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: PolicyA
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: logs:CreateLogGroup
                Resource: '*'
  RoleB:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: PolicyB
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Deny
                Action: iam:*
                Resource: '*'
"#,
    );
    let e3510 = diags_for_rule(&report, "E3510");
    assert!(e3510.is_empty(), "Expected no E3510 findings, got: {e3510:?}");
}

// ---------------------------------------------------------------------------
// Missing Effect in an inline policy statement
// ---------------------------------------------------------------------------

#[test]
fn missing_effect_in_role_inline_policy() {
    let report = validate(
        r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: BadPolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Action: s3:GetObject
                Resource: '*'
"#,
    );
    let hits = diags_for_rule(&report, "E3510");
    assert!(
        hits.iter().any(|d| d.message.contains("'Effect' is a required property")),
        "Expected E3510 for missing Effect, got: {hits:?}"
    );
}

#[test]
fn multiple_inline_policies_missing_effect() {
    let report = validate(
        r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: PolicyOne
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Action: s3:GetObject
                Resource: '*'
        - PolicyName: PolicyTwo
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: s3:PutObject
                Resource: '*'
              - Action: logs:*
                Resource: '*'
"#,
    );
    let effect_findings: Vec<_> = diags_for_rule(&report, "E3510")
        .into_iter()
        .filter(|d| d.message.contains("'Effect' is a required property"))
        .collect();
    assert_eq!(effect_findings.len(), 2, "Expected 2 missing-Effect findings, got: {effect_findings:?}");
}

// ---------------------------------------------------------------------------
// Invalid Effect value
// ---------------------------------------------------------------------------

#[test]
fn invalid_effect_in_role_inline_policy() {
    let report = validate(
        r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: BadEffect
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Maybe
                Action: s3:GetObject
                Resource: '*'
"#,
    );
    let hits = diags_for_rule(&report, "E3510");
    assert!(
        hits.iter().any(|d| d.message.contains("'Maybe' is not one of")),
        "Expected E3510 for invalid Effect, got: {hits:?}"
    );
}

#[test]
fn multiple_invalid_effects_across_policies() {
    let report = validate(
        r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: PolicyA
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Grant
                Action: s3:GetObject
                Resource: '*'
        - PolicyName: PolicyB
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Reject
                Action: logs:*
                Resource: '*'
"#,
    );
    let effect_findings: Vec<_> =
        diags_for_rule(&report, "E3510").into_iter().filter(|d| d.message.contains("is not one of")).collect();
    assert_eq!(effect_findings.len(), 2, "Expected 2 invalid-Effect findings, got: {effect_findings:?}");
}

// ---------------------------------------------------------------------------
// Missing Action/NotAction
// ---------------------------------------------------------------------------

#[test]
fn missing_action_in_role_inline_policy() {
    let report = validate(
        r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: NoAction
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Resource: '*'
"#,
    );
    let hits = diags_for_rule(&report, "E3510");
    assert!(
        hits.iter().any(|d| d.message.contains("['Action', 'NotAction']")),
        "Expected E3510 for missing Action/NotAction, got: {hits:?}"
    );
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn dynamic_effect_value_no_false_positive() {
    let report = validate(
        r#"
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  EffectParam:
    Type: String
    AllowedValues:
      - Allow
      - Deny
Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: DynamicEffect
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: !Ref EffectParam
                Action: s3:GetObject
                Resource: '*'
"#,
    );
    let e3510 = diags_for_rule(&report, "E3510");
    assert!(e3510.is_empty(), "Dynamic effect (Ref) must not produce E3510 false positive: {e3510:?}");
}

#[test]
fn role_without_policies_property_no_findings() {
    let report = validate(
        r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
"#,
    );
    let e3510 = diags_for_rule(&report, "E3510");
    assert!(e3510.is_empty(), "Expected no E3510, got: {e3510:?}");
}

#[test]
fn notaction_satisfies_action_requirement() {
    let report = validate(
        r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: WithNotAction
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                NotAction: s3:DeleteBucket
                Resource: '*'
"#,
    );
    let action_findings: Vec<_> = diags_for_rule(&report, "E3510")
        .into_iter()
        .filter(|d| d.message.contains("['Action', 'NotAction']"))
        .collect();
    assert!(action_findings.is_empty(), "NotAction should satisfy requirement, got: {action_findings:?}");
}

#[test]
fn iam_policy_resource_fires_e3510() {
    let report = validate(
        r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: TestPolicy
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Resource: '*'
      Groups:
        - MyGroup
"#,
    );
    let hits = diags_for_rule(&report, "E3510");
    assert!(
        hits.iter().any(|d| d.message.contains("'Effect' is a required property")),
        "Expected E3510 for missing Effect on IAM::Policy, got: {hits:?}"
    );
    assert!(
        hits.iter().any(|d| d.message.contains("['Action', 'NotAction']")),
        "Expected E3510 for missing Action on IAM::Policy, got: {hits:?}"
    );
}
