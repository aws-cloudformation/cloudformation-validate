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
        "{}|{:?}|{}|{}|{}",
        diagnostic.rule_id,
        diagnostic.severity,
        diagnostic.resource_logical_id().unwrap_or(""),
        diagnostic.property_path.as_deref().unwrap_or(""),
        diagnostic.message
    )
}

fn engines() -> (RegoEngine, CelEngine) {
    (RegoEngine::new(EngineConfig::default()).unwrap(), CelEngine::new(EngineConfig::default()).unwrap())
}

#[test]
fn only_terminal_module_suffix_is_exempt_from_unknown_aws_type_validation() {
    let template = r#"
Resources:
  ValidModule:
    Type: AWS::S3::Bucket::MODULE
    Properties: {}
  UnknownType:
    Type: AWS::NotAService::NotAResource
    Properties: {}
  ModuleInMiddle:
    Type: AWS::S3::MODULE::Bucket
    Properties: {}
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["F3006"]);
    let cel_findings = selected_findings(&cel, template, &["F3006"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 2, "only unknown non-module types should be rejected: {rego_findings:?}");
    assert!(rego_findings.iter().any(|finding| finding.contains("AWS::NotAService::NotAResource")));
    assert!(rego_findings.iter().any(|finding| finding.contains("AWS::S3::MODULE::Bucket")));
    assert!(rego_findings.iter().all(|finding| !finding.contains("AWS::S3::Bucket::MODULE")));
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
fn conditional_fargate_task_sizes_check_both_branch_orders() {
    let template = r#"
Conditions:
  UseFirst: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  CpuInvalidThenValid:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: !If [UseFirst, "512", "256"]
      Memory: "512"
      ContainerDefinitions: [{Name: app, Image: nginx}]
  CpuValidThenInvalid:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: !If [UseFirst, "256", "512"]
      Memory: "512"
      ContainerDefinitions: [{Name: app, Image: nginx}]
  CorrelatedFargateThenEc2:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: !If [UseFirst, [FARGATE], [EC2]]
      NetworkMode: !If [UseFirst, awsvpc, bridge]
      Cpu: !If [UseFirst, "256", "512"]
      Memory: "512"
      ContainerDefinitions: [{Name: app, Image: nginx}]
  CorrelatedEc2ThenFargate:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: !If [UseFirst, [EC2], [FARGATE]]
      NetworkMode: !If [UseFirst, bridge, awsvpc]
      Cpu: !If [UseFirst, "512", "256"]
      Memory: "512"
      ContainerDefinitions: [{Name: app, Image: nginx}]
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3047"]);
    let cel_findings = selected_findings(&cel, template, &["E3047"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 2, "each reachable invalid Fargate deployment must be reported: {rego_findings:?}");
    assert!(rego_findings.iter().any(|finding| finding.contains("CpuInvalidThenValid")));
    assert!(rego_findings.iter().any(|finding| finding.contains("CpuValidThenInvalid")));
    assert!(rego_findings.iter().all(|finding| !finding.contains("Correlated")));
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

#[test]
fn sam_application_requires_both_stateful_resource_policies() {
    let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  NestedApplication:
    Type: AWS::Serverless::Application
    Properties:
      Location: https://example.com/nested-template.yaml
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["I3011"]);
    let cel_findings = selected_findings(&cel, template, &["I3011"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 2, "the generated stack needs both lifecycle policies: {rego_findings:?}");
    assert!(rego_findings.iter().any(|finding| finding.contains("'DeletionPolicy'")));
    assert!(rego_findings.iter().any(|finding| finding.contains("'UpdateReplacePolicy'")));
}

#[test]
fn sam_simple_table_requires_both_stateful_resource_policies() {
    let template = r#"
Transform: AWS::Serverless-2016-10-31
Resources:
  Table:
    Type: AWS::Serverless::SimpleTable
    Properties:
      TableName: example-table
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["I3011"]);
    let cel_findings = selected_findings(&cel, template, &["I3011"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 2, "the generated table needs both lifecycle policies: {rego_findings:?}");
    assert!(rego_findings.iter().any(|finding| finding.contains("'DeletionPolicy'")));
    assert!(rego_findings.iter().any(|finding| finding.contains("'UpdateReplacePolicy'")));
}

#[test]
fn omitted_dynamodb_billing_mode_requires_provisioned_throughput() {
    let template = r#"
Resources:
  Table:
    Type: AWS::DynamoDB::Table
    Properties:
      AttributeDefinitions:
        - AttributeName: id
          AttributeType: S
      KeySchema:
        - AttributeName: id
          KeyType: HASH
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3639"]);
    let cel_findings = selected_findings(&cel, template, &["E3639"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 1, "omitted BillingMode defaults to provisioned: {rego_findings:?}");
    assert!(rego_findings[0].contains("Properties.ProvisionedThroughput"));
    assert!(rego_findings[0].contains("BillingMode defaults to 'PROVISIONED'"));
}

#[test]
fn explicit_dynamodb_provisioned_mode_uses_explicit_requirement_message() {
    let template = r#"
Resources:
  Table:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: PROVISIONED
      AttributeDefinitions: [{AttributeName: id, AttributeType: S}]
      KeySchema: [{AttributeName: id, KeyType: HASH}]
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3639"]);
    let cel_findings = selected_findings(&cel, template, &["E3639"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 1, "explicit PROVISIONED mode requires throughput: {rego_findings:?}");
    assert!(rego_findings[0].contains("BillingMode is 'PROVISIONED'"));
    assert!(!rego_findings[0].contains("defaults"));
}

#[test]
fn conditional_provisioned_throughput_checks_every_reachable_branch() {
    let template = r#"
Conditions:
  UseProvisioned: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  ExplicitValueThenRemoved:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: PROVISIONED
      AttributeDefinitions: [{AttributeName: id, AttributeType: S}]
      KeySchema: [{AttributeName: id, KeyType: HASH}]
      ProvisionedThroughput: !If
        - UseProvisioned
        - {ReadCapacityUnits: 5, WriteCapacityUnits: 5}
        - !Ref AWS::NoValue
  ExplicitRemovedThenValue:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: PROVISIONED
      AttributeDefinitions: [{AttributeName: id, AttributeType: S}]
      KeySchema: [{AttributeName: id, KeyType: HASH}]
      ProvisionedThroughput: !If
        - UseProvisioned
        - !Ref AWS::NoValue
        - {ReadCapacityUnits: 5, WriteCapacityUnits: 5}
  DefaultValueThenRemoved:
    Type: AWS::DynamoDB::Table
    Properties:
      AttributeDefinitions: [{AttributeName: id, AttributeType: S}]
      KeySchema: [{AttributeName: id, KeyType: HASH}]
      ProvisionedThroughput: !If
        - UseProvisioned
        - {ReadCapacityUnits: 5, WriteCapacityUnits: 5}
        - !Ref AWS::NoValue
  DefaultRemovedThenValue:
    Type: AWS::DynamoDB::Table
    Properties:
      AttributeDefinitions: [{AttributeName: id, AttributeType: S}]
      KeySchema: [{AttributeName: id, KeyType: HASH}]
      ProvisionedThroughput: !If
        - UseProvisioned
        - !Ref AWS::NoValue
        - {ReadCapacityUnits: 5, WriteCapacityUnits: 5}
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3639"]);
    let cel_findings = selected_findings(&cel, template, &["E3639"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 4, "every reachable missing-throughput branch must be reported: {rego_findings:?}");
    assert_eq!(rego_findings.iter().filter(|finding| finding.contains("defaults")).count(), 2);
    assert_eq!(rego_findings.iter().filter(|finding| !finding.contains("defaults")).count(), 2);
}

#[test]
fn correlated_billing_mode_and_throughput_scenarios_are_valid() {
    let template = r#"
Conditions:
  UseProvisioned: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  ProvisionedThenOnDemand:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: !If [UseProvisioned, PROVISIONED, PAY_PER_REQUEST]
      AttributeDefinitions: [{AttributeName: id, AttributeType: S}]
      KeySchema: [{AttributeName: id, KeyType: HASH}]
      ProvisionedThroughput: !If
        - UseProvisioned
        - {ReadCapacityUnits: 5, WriteCapacityUnits: 5}
        - !Ref AWS::NoValue
  OnDemandThenProvisioned:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: !If [UseProvisioned, PAY_PER_REQUEST, PROVISIONED]
      AttributeDefinitions: [{AttributeName: id, AttributeType: S}]
      KeySchema: [{AttributeName: id, KeyType: HASH}]
      ProvisionedThroughput: !If
        - UseProvisioned
        - !Ref AWS::NoValue
        - {ReadCapacityUnits: 5, WriteCapacityUnits: 5}
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3639"]);
    let cel_findings = selected_findings(&cel, template, &["E3639"]);
    assert_eq!(rego_findings, cel_findings);
    assert!(rego_findings.is_empty(), "throughput is present in every PROVISIONED world: {rego_findings:?}");
}

#[test]
fn conditional_fargate_compatibility_checks_both_branch_orders() {
    let template = r#"
Conditions:
  UseFirst: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  FargateThenEc2MissingNetworkMode:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: !If [UseFirst, [FARGATE], [EC2]]
      Cpu: '256'
      Memory: '512'
      ContainerDefinitions: [{Name: app, Image: nginx, Essential: true}]
  Ec2ThenFargateMissingNetworkMode:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: !If [UseFirst, [EC2], [FARGATE]]
      Cpu: '256'
      Memory: '512'
      ContainerDefinitions: [{Name: app, Image: nginx, Essential: true}]
  CorrelatedFargateThenEc2:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: !If [UseFirst, [FARGATE], [EC2]]
      NetworkMode: !If [UseFirst, awsvpc, bridge]
      Cpu: '256'
      Memory: '512'
      ContainerDefinitions: [{Name: app, Image: nginx, Essential: true}]
  CorrelatedEc2ThenFargate:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: !If [UseFirst, [EC2], [FARGATE]]
      NetworkMode: !If [UseFirst, bridge, awsvpc]
      Cpu: '256'
      Memory: '512'
      ContainerDefinitions: [{Name: app, Image: nginx, Essential: true}]
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3048"]);
    let cel_findings = selected_findings(&cel, template, &["E3048"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 2, "only the two missing NetworkMode resources should fail: {rego_findings:?}");
    assert!(rego_findings.iter().all(|finding| finding.contains("NetworkMode to be specified")));
}

#[test]
fn identity_policy_id_is_rejected_regardless_of_scalar_type() {
    let template = r#"
Resources:
  StringId:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Id: identity-policy-id
        Statement: [{Effect: Allow, Action: s3:GetObject, Resource: "*"}]
  NumericId:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Id: 123
        Statement: [{Effect: Allow, Action: s3:GetObject, Resource: "*"}]
  BooleanId:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Id: true
        Statement: [{Effect: Allow, Action: s3:GetObject, Resource: "*"}]
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3510"]);
    let cel_findings = selected_findings(&cel, template, &["E3510"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 3, "identity-policy Id is forbidden regardless of value type: {rego_findings:?}");
    assert!(rego_findings.iter().all(|finding| finding.contains("Properties.PolicyDocument.Id")));
    assert!(
        rego_findings
            .iter()
            .all(|finding| finding.contains("Additional properties are not allowed ('Id' was unexpected)"))
    );
}

#[test]
fn resource_policy_string_id_is_allowed() {
    let template = r#"
Resources:
  Bucket:
    Type: AWS::S3::Bucket
  Policy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref Bucket
      PolicyDocument:
        Version: "2012-10-17"
        Id: resource-policy-id
        Statement:
          - Effect: Allow
            Principal: "*"
            Action: s3:GetObject
            Resource: "*"
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3510", "E3512"]);
    let cel_findings = selected_findings(&cel, template, &["E3510", "E3512"]);
    assert_eq!(rego_findings, cel_findings);
    assert!(rego_findings.is_empty(), "resource-based policies may contain a string Id: {rego_findings:?}");
}
