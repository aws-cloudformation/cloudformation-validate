use cel_engine::CelEngine;
use diagnostics::Diagnostic;
use rego_engine::RegoEngine;
use schema_validator::SchemaValidator;
use validation_engine::{EngineConfig, ValidateConfig, ValidationEngine, validate_bytes};

fn selected_findings(engine: &dyn ValidationEngine, template: &str, rule_ids: &[&str]) -> Vec<String> {
    let validator = SchemaValidator::default();
    let report = validate_bytes(engine, &validator, template.as_bytes(), ValidateConfig::default()).unwrap();
    let mut findings: Vec<String> = report
        .diagnostics
        .iter()
        .filter(|diagnostic| rule_ids.contains(&diagnostic.rule_id.as_str()))
        .map(diagnostic_identity)
        .collect();
    findings.sort();
    findings
}

fn diagnostic_identity(diagnostic: &Diagnostic) -> String {
    format!(
        "{}|{:?}|{}|{}",
        diagnostic.rule_id,
        diagnostic.severity,
        diagnostic.property_path.as_deref().unwrap_or(""),
        diagnostic.message
    )
}

fn engines() -> (RegoEngine, CelEngine) {
    (RegoEngine::new(EngineConfig::default()).unwrap(), CelEngine::new(EngineConfig::default()).unwrap())
}

#[test]
fn fargate_scalar_gating_is_identical() {
    let template = r#"
Resources:
  IntegralFloat:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: 256.0
      Memory: 512.0
      ContainerDefinitions: [{Name: app, Image: nginx}]
  NonIntegralFloat:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: 256.5
      Memory: 512
      ContainerDefinitions: [{Name: app, Image: nginx}]
  CompositeCpu:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: [256]
      Memory: 512
      ContainerDefinitions: [{Name: app, Image: nginx}]
  InvalidCpu:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: "128"
      Memory: "512"
      ContainerDefinitions: [{Name: app, Image: nginx}]
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3047", "E3048"]);
    let cel_findings = selected_findings(&cel, template, &["E3047", "E3048"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 2, "only the offered-size violations should be reported: {rego_findings:?}");
    assert!(rego_findings.iter().all(|finding| finding.contains("Properties.Cpu")));
}

#[test]
fn dynamic_throughput_is_not_reported_missing() {
    let template = r#"
Parameters:
  Throughput:
    Type: String
Resources:
  Table:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: PROVISIONED
      AttributeDefinitions: [{AttributeName: id, AttributeType: S}]
      KeySchema: [{AttributeName: id, KeyType: HASH}]
      ProvisionedThroughput: !Ref Throughput
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3639"]);
    let cel_findings = selected_findings(&cel, template, &["E3639"]);
    assert_eq!(rego_findings, cel_findings);
    assert!(rego_findings.is_empty(), "dynamic throughput may be present at deployment: {rego_findings:?}");
}

#[test]
fn dynamic_iam_field_does_not_hide_literal_defect() {
    let template = r#"
Parameters:
  RuntimeAction:
    Type: String
  BucketArn:
    Type: String
Resources:
  IntrinsicPolicy:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal: {Service: lambda.amazonaws.com}
            Action: sts:AssumeRole
      Policies:
        - PolicyName: intrinsic
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action: s3:GetObject
                Resource: !Join ["", [!Ref BucketArn, "/*"]]
  InvalidSibling:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal: {Service: lambda.amazonaws.com}
            Action: sts:AssumeRole
      Policies:
        - PolicyName: invalid
          PolicyDocument:
            Statement:
              - Effect: DefinitelyNotAllow
                Action: !Ref RuntimeAction
                Resource: "*"
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3510"]);
    let cel_findings = selected_findings(&cel, template, &["E3510"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 1, "only the literal Effect defect should be reported: {rego_findings:?}");
    assert!(rego_findings[0].contains("Statement.0.Effect"));
}

#[test]
fn sso_not_action_warning_is_identical() {
    let template = r#"
Resources:
  PermissionSet:
    Type: AWS::SSO::PermissionSet
    Properties:
      InstanceArn: arn:aws:sso:::instance/ssoins-1234567890123456
      Name: RestrictedAdministration
      InlinePolicy:
        Statement:
          - Effect: Allow
            NotAction: iam:DeleteUser
            Resource: "*"
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["W2512"]);
    let cel_findings = selected_findings(&cel, template, &["W2512"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 1, "the Allow/NotAction statement should produce one warning");
}

#[test]
fn empty_identity_policy_document_is_identical() {
    let template = r#"
Resources:
  EmptyPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: Empty
      Roles: [ExampleRole]
      PolicyDocument: {}
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3510"]);
    let cel_findings = selected_findings(&cel, template, &["E3510"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 1, "the empty document should produce one required-Statement finding");
}
