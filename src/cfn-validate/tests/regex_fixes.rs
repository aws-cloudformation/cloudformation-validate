mod common;

use cel_engine::CelEngine;
use rego_engine::RegoEngine;
use rules::Severity;
use schema_validator::SchemaValidator;
use std::sync::LazyLock;
use validation_engine::{EngineConfig, ValidationEngine, validate_bytes};

static REGO: LazyLock<RegoEngine> = LazyLock::new(|| RegoEngine::new(EngineConfig::default()).unwrap());
static CEL: LazyLock<CelEngine> = LazyLock::new(|| CelEngine::new(EngineConfig::default()).unwrap());
static SCHEMA_VALIDATOR: LazyLock<SchemaValidator> = LazyLock::new(SchemaValidator::new);

/// Rule IDs (with severity) emitted for `template`, sorted, for one engine.
fn diagnostics_for(engine: &dyn ValidationEngine, template: &str) -> Vec<(String, Severity)> {
    let report = validate_bytes(engine, &SCHEMA_VALIDATOR, template.as_bytes(), Default::default())
        .expect("template validates without error");
    let mut ids: Vec<(String, Severity)> = report.diagnostics.iter().map(|d| (d.rule_id.clone(), d.severity)).collect();
    ids.sort();
    ids
}

/// Validate through both engines, assert they agree, and return the shared rule-id set.
fn diagnostics_both_engines(template: &str) -> Vec<(String, Severity)> {
    let rego = diagnostics_for(&*REGO as &dyn ValidationEngine, template);
    let cel = diagnostics_for(&*CEL as &dyn ValidationEngine, template);
    assert_eq!(rego, cel, "engines diverged for template:\n{template}\nrego={rego:?}\ncel={cel:?}");
    rego
}

fn has_rule(diagnostics: &[(String, Severity)], rule_id: &str) -> bool {
    diagnostics.iter().any(|(id, _)| id == rule_id)
}

/// A schema `pattern` using a negative lookahead (`^(?!aws:).+$`) must still be enforced: an
/// AppRunner tag key of `aws:reserved` violates it, so F3031 fires in both engines.
#[test]
fn lookahead_schema_pattern_is_enforced() {
    let template = r#"
Resources:
  Service:
    Type: AWS::AppRunner::Service
    Properties:
      SourceConfiguration:
        ImageRepository:
          ImageIdentifier: public.ecr.aws/aws-containers/hello-app-runner:latest
          ImageRepositoryType: ECR_PUBLIC
      Tags:
        - Key: "aws:reserved"
          Value: "nope"
"#;
    let diagnostics = diagnostics_both_engines(template);
    assert!(has_rule(&diagnostics, "F3031"), "lookahead tag-key pattern must be enforced: {diagnostics:?}");
}

/// A well-formed AppRunner tag key must NOT trigger the pattern rule (no false positive).
#[test]
fn lookahead_schema_pattern_allows_valid_value() {
    let template = r#"
Resources:
  Service:
    Type: AWS::AppRunner::Service
    Properties:
      SourceConfiguration:
        ImageRepository:
          ImageIdentifier: public.ecr.aws/aws-containers/hello-app-runner:latest
          ImageRepositoryType: ECR_PUBLIC
      Tags:
        - Key: "team"
          Value: "platform"
"#;
    let diagnostics = diagnostics_both_engines(template);
    assert!(!has_rule(&diagnostics, "F3031"), "valid tag key must not fire pattern rule: {diagnostics:?}");
}

/// An invalid Security Group name must fire E1153 exactly once, via the shared schema-format path.
#[test]
fn security_group_name_format_enforced_in_both_engines() {
    let template = "
Resources:
  SG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: test
      GroupName: \"invalid\tname\"
";
    let diagnostics = diagnostics_both_engines(template);
    let e1153_count = diagnostics.iter().filter(|(id, _)| id == "E1153").count();
    assert_eq!(e1153_count, 1, "E1153 must fire exactly once per engine: {diagnostics:?}");
}

/// An `AllowedPattern` that is valid service-side but uses PCRE syntax Rust's regex rejects (`\A..\Z`)
/// must NOT trigger I2003 ("invalid regex") or a spurious F2015 default-match failure.
#[test]
fn pcre_allowed_pattern_is_not_flagged_invalid() {
    let template = r"
Parameters:
  Hex:
    Type: String
    AllowedPattern: '\A[0-9a-fA-F]+\Z'
    Default: 'abc123'
Resources:
  Topic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: !Ref Hex
";
    let diagnostics = diagnostics_both_engines(template);
    assert!(!has_rule(&diagnostics, "I2003"), "service-valid pattern must not be flagged invalid: {diagnostics:?}");
    assert!(!has_rule(&diagnostics, "F2015"), "matching default must not fire F2015: {diagnostics:?}");
}

/// A lookahead `AllowedPattern` with a default that genuinely does not match must fire F2015 (the
/// constraint was previously dropped because the pattern would not compile).
#[test]
fn lookahead_allowed_pattern_default_mismatch_fires_f2015() {
    let template = r"
Parameters:
  Name:
    Type: String
    AllowedPattern: '^(?!aws:).+$'
    Default: 'aws:reserved'
Resources:
  Topic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: !Ref Name
";
    let diagnostics = diagnostics_both_engines(template);
    assert!(has_rule(&diagnostics, "F2015"), "non-matching default must fire F2015: {diagnostics:?}");
}

/// A genuinely malformed `AllowedPattern` must still fire I2003.
#[test]
fn malformed_allowed_pattern_fires_i2003() {
    let template = r"
Parameters:
  P:
    Type: String
    AllowedPattern: '^(unbalanced['
    Default: 'x'
Resources:
  Topic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: !Ref P
";
    let diagnostics = diagnostics_both_engines(template);
    assert!(has_rule(&diagnostics, "I2003"), "malformed pattern must fire I2003: {diagnostics:?}");
}

/// A `rate(1 minutes)` schedule (plural unit for a value of 1) is invalid service-side and must fire
/// E3027; the previous loose regex accepted it.
#[test]
fn schedule_rate_unit_agreement_enforced() {
    let template = r"
Resources:
  Rule:
    Type: AWS::Events::Rule
    Properties:
      ScheduleExpression: 'rate(1 minutes)'
      State: ENABLED
";
    let diagnostics = diagnostics_both_engines(template);
    assert!(has_rule(&diagnostics, "E3027"), "invalid rate unit must fire E3027: {diagnostics:?}");
}

/// A valid `rate(5 minutes)` must NOT fire E3027.
#[test]
fn valid_schedule_rate_is_clean() {
    let template = r"
Resources:
  Rule:
    Type: AWS::Events::Rule
    Properties:
      ScheduleExpression: 'rate(5 minutes)'
      State: ENABLED
";
    let diagnostics = diagnostics_both_engines(template);
    assert!(!has_rule(&diagnostics, "E3027"), "valid rate must not fire E3027: {diagnostics:?}");
}

/// A Route53 A record with a leading-zero octet (`010.0.0.1`) is not a valid IPv4 address and must
/// fire E3023.
#[test]
fn route53_a_record_rejects_leading_zero_octet() {
    let template = r#"
Resources:
  Record:
    Type: AWS::Route53::RecordSet
    Properties:
      HostedZoneId: Z123456789
      Name: test.example.com
      Type: A
      TTL: "300"
      ResourceRecords:
        - "010.0.0.1"
"#;
    let diagnostics = diagnostics_both_engines(template);
    assert!(has_rule(&diagnostics, "E3023"), "leading-zero IPv4 octet must fire E3023: {diagnostics:?}");
}

/// A Route53 MX record with an out-of-range preference (`70000`) must fire E3023; the previous
/// unbounded `\d+` accepted it.
#[test]
fn route53_mx_record_rejects_out_of_range_priority() {
    let template = r#"
Resources:
  Record:
    Type: AWS::Route53::RecordSet
    Properties:
      HostedZoneId: Z123456789
      Name: test.example.com
      Type: MX
      TTL: "300"
      ResourceRecords:
        - "70000 mail.example.com."
"#;
    let diagnostics = diagnostics_both_engines(template);
    assert!(has_rule(&diagnostics, "E3023"), "out-of-range MX preference must fire E3023: {diagnostics:?}");
}

// The following guard against regressions found while re-verifying the regex fix. Each exercises an
// edge case the template corpus does not contain.

/// A `\p{Print}`-patterned property value containing a format (`Cf`) character — e.g. a zero-width
/// space — is valid service-side, so the expansion must not narrow it away and fire a spurious
/// pattern violation.
#[test]
fn print_class_accepts_format_characters() {
    let template = "
Resources:
  Policy:
    Type: AWS::ApplicationAutoScaling::ScalingPolicy
    Properties:
      PolicyName: \"scale\u{200B}out\"
      PolicyType: TargetTrackingScaling
      ScalingTargetId: my-target
";
    let diagnostics = diagnostics_both_engines(template);
    assert!(!has_rule(&diagnostics, "F3031"), "\\p{{Print}} must accept a Cf character: {diagnostics:?}");
    assert!(!has_rule(&diagnostics, "E3031"), "\\p{{Print}} must accept a Cf character: {diagnostics:?}");
}

/// A `rate()` value with a leading-zero amount (`rate(01 minutes)`) is invalid service-side (the
/// unit must be singular for an amount of 1) and must fire E3027. Leading zeros are a numeric-parse
/// edge case, so this guards that the amount is still recognized.
#[test]
fn schedule_rate_leading_zero_amount_fires_in_both_engines() {
    let template = r"
Resources:
  Rule:
    Type: AWS::Events::Rule
    Properties:
      ScheduleExpression: 'rate(01 minutes)'
      State: ENABLED
";
    let diagnostics = diagnostics_both_engines(template);
    assert!(
        has_rule(&diagnostics, "E3027"),
        "leading-zero rate amount must fire E3027 in both engines: {diagnostics:?}"
    );
}

/// An IAM role ARN whose role name contains a legal-but-unusual character (a space) satisfies the
/// `AWS::IAM::Role.Arn` schema format (E1156), whose role-name segment is unrestricted (`.+`).
/// E1156 must not fire on it.
#[test]
fn iam_role_arn_format_accepts_unrestricted_role_name() {
    let template = r#"
Resources:
  TaskDef:
    Type: AWS::ECS::TaskDefinition
    Properties:
      TaskRoleArn: "arn:aws:iam::123456789012:role/my role"
"#;
    let diagnostics = diagnostics_both_engines(template);
    assert!(!has_rule(&diagnostics, "E1156"), "E1156 format must accept an unrestricted role name: {diagnostics:?}");
}

/// An IAM role ARN with an empty/non-`aws` partition (`arn::iam::…`) violates the E1156 format,
/// which requires the `aws` partition. E1156 must fire in both engines.
#[test]
fn iam_role_arn_format_requires_aws_partition() {
    let template = r#"
Resources:
  TaskDef:
    Type: AWS::ECS::TaskDefinition
    Properties:
      TaskRoleArn: "arn::iam::123456789012:role/x"
"#;
    let diagnostics = diagnostics_both_engines(template);
    assert!(has_rule(&diagnostics, "E1156"), "E1156 format must require the aws partition: {diagnostics:?}");
}
