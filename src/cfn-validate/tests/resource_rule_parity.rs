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
fn whole_properties_fargate_requirements_follow_effective_branch() {
    let template = r#"
Conditions:
  IsFargate: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  ValidConditionalProperties:
    Type: AWS::ECS::TaskDefinition
    Properties: !If
      - IsFargate
      - RequiresCompatibilities: [FARGATE]
        NetworkMode: awsvpc
        Cpu: '256'
        Memory: '512'
        ContainerDefinitions: [{Name: app, Image: nginx, Essential: true}]
      - RequiresCompatibilities: [EC2]
        NetworkMode: bridge
        ContainerDefinitions: [{Name: app, Image: nginx, Essential: true}]
  MissingFargateProperties:
    Type: AWS::ECS::TaskDefinition
    Properties: !If
      - IsFargate
      - RequiresCompatibilities: [FARGATE]
        ContainerDefinitions: [{Name: app, Image: nginx, Essential: true}]
      - RequiresCompatibilities: [EC2]
        NetworkMode: bridge
        Cpu: '256'
        Memory: '512'
        ContainerDefinitions: [{Name: app, Image: nginx, Essential: true}]
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3048"]);
    let cel_findings = selected_findings(&cel, template, &["E3048"]);

    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 3, "only the incomplete Fargate branch should fail: {rego_findings:?}");
    assert!(rego_findings.iter().all(|finding| finding.contains("MissingFargateProperties")));
    assert!(rego_findings.iter().any(|finding| finding.contains("NetworkMode to be specified")));
    assert!(rego_findings.iter().any(|finding| finding.contains("Cpu to be specified")));
    assert!(rego_findings.iter().any(|finding| finding.contains("Memory to be specified")));
    assert!(rego_findings.iter().all(|finding| !finding.contains("ValidConditionalProperties")));
}

#[test]
fn fargate_placement_constraints_follow_compatible_scenarios() {
    let template = r#"
Parameters:
  PlacementExpression:
    Type: String
Conditions:
  IsFargate: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  Ec2OnlyPlacement:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: !If [IsFargate, [FARGATE], [EC2]]
      NetworkMode: !If [IsFargate, awsvpc, bridge]
      Cpu: '256'
      Memory: '512'
      PlacementConstraints: !If
        - IsFargate
        - !Ref AWS::NoValue
        - - Type: memberOf
            Expression: !Ref PlacementExpression
      ContainerDefinitions: [{Name: app, Image: nginx, Essential: true}]
  DirectFargatePlacement:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: '256'
      Memory: '512'
      PlacementConstraints:
        - Type: memberOf
          Expression: !Ref PlacementExpression
      ContainerDefinitions: [{Name: app, Image: nginx, Essential: true}]
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3048"]);
    let cel_findings = selected_findings(&cel, template, &["E3048"]);

    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 1, "only direct Fargate placement should fail: {rego_findings:?}");
    assert!(rego_findings[0].contains("DirectFargatePlacement"));
    assert!(rego_findings[0].contains("does not support PlacementConstraints"));
    assert!(!rego_findings[0].contains("Ec2OnlyPlacement"));
}

#[test]
fn conditional_fargate_logdriver_checks_all_branches() {
    let template = r#"
Conditions:
  UseSyslog: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  ConditionalBadDriver:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: '256'
      Memory: '512'
      ContainerDefinitions:
        - Name: app
          Image: nginx
          Essential: true
          LogConfiguration:
            LogDriver: !If [UseSyslog, syslog, awslogs]
  ConditionalGoodDrivers:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: '256'
      Memory: '512'
      ContainerDefinitions:
        - Name: app
          Image: nginx
          Essential: true
          LogConfiguration:
            LogDriver: !If [UseSyslog, awslogs, splunk]
  CorrelatedFargateEc2LogDriver:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: !If [UseSyslog, [FARGATE], [EC2]]
      NetworkMode: !If [UseSyslog, awsvpc, bridge]
      Cpu: '256'
      Memory: '512'
      ContainerDefinitions:
        - Name: app
          Image: nginx
          Essential: true
          LogConfiguration:
            LogDriver: !If [UseSyslog, awslogs, syslog]
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3048"]);
    let cel_findings = selected_findings(&cel, template, &["E3048"]);
    assert_eq!(rego_findings, cel_findings);
    // Only ConditionalBadDriver should fire (syslog branch is invalid for Fargate).
    // ConditionalGoodDrivers: both branches valid. CorrelatedFargateEc2LogDriver:
    // syslog is in the EC2 branch which is not reachable under a Fargate scenario.
    assert_eq!(rego_findings.len(), 1, "only the syslog branch in Fargate should fire: {rego_findings:?}");
    assert!(rego_findings[0].contains("syslog"));
    assert!(rego_findings[0].contains("ConditionalBadDriver"));
}

#[test]
fn conditional_fargate_logdriver_checks_second_container_list_branch() {
    let template = r#"
Conditions:
  UseFirst: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  ConditionalContainerList:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: '256'
      Memory: '512'
      ContainerDefinitions: !If
        - UseFirst
        - - Name: valid
            Image: nginx
            Essential: true
            LogConfiguration:
              LogDriver: awslogs
        - - Name: invalid
            Image: nginx
            Essential: true
            LogConfiguration:
              LogDriver: syslog
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3048"]);
    let cel_findings = selected_findings(&cel, template, &["E3048"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 1, "the invalid second list branch must be checked: {rego_findings:?}");
    assert!(rego_findings[0].contains("syslog"));
}

#[test]
fn conditional_fargate_logdriver_deduplicates_identical_findings() {
    let template = r#"
Conditions:
  CFirst: !Equals [!Ref AWS::Region, us-east-1]
  CSecond: !Equals [!Ref AWS::Region, us-west-2]
Resources:
  MultiConditionBadDriver:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: '256'
      Memory: '512'
      ContainerDefinitions:
        - Name: app
          Image: nginx
          Essential: true
          LogConfiguration:
            LogDriver: syslog
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3048"]);
    let cel_findings = selected_findings(&cel, template, &["E3048"]);
    assert_eq!(rego_findings, cel_findings);
    // Only one finding even though unconditional Fargate means the finding
    // is reachable under every world.
    let logdriver_findings: Vec<_> = rego_findings.iter().filter(|f| f.contains("log driver")).collect();
    assert_eq!(logdriver_findings.len(), 1, "should deduplicate: {logdriver_findings:?}");
}

#[test]
fn dynamodb_conditional_index_reports_missing_definitions() {
    let template = r#"
Parameters:
  AddGSI:
    Type: String
Conditions:
  CreateGSI: !Equals [!Ref AddGSI, "true"]
Resources:
  TableWithConditionalGSI:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: pk
          AttributeType: S
        - AttributeName: gsi_pk
          AttributeType: S
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
        - AttributeName: missing_sk
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
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3039"]);
    let cel_findings = selected_findings(&cel, template, &["E3039"]);
    assert_eq!(rego_findings, cel_findings);
    // missing_sk is in table KeySchema but not in AttributeDefinitions — always wrong.
    assert_eq!(rego_findings.len(), 1, "Expected missing definition finding: {rego_findings:?}");
    assert!(rego_findings[0].contains("missing definitions: [missing_sk]"));
    // gsi_pk should NOT be reported as unused because the conditional index could use it.
    assert!(!rego_findings[0].contains("unused"), "unused must be suppressed: {rego_findings:?}");
}

#[test]
fn dynamodb_conditional_index_false_branch_reports_missing_definition() {
    let template = r#"
Parameters:
  AddGSI:
    Type: String
Conditions:
  CreateGSI: !Equals [!Ref AddGSI, "true"]
Resources:
  TableWithConditionalGSI:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: pk
          AttributeType: S
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
      GlobalSecondaryIndexes: !If
        - CreateGSI
        - !Ref AWS::NoValue
        - - IndexName: gsi1
            KeySchema:
              - AttributeName: missing_gsi_pk
                KeyType: HASH
            Projection:
              ProjectionType: ALL
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3039"]);
    let cel_findings = selected_findings(&cel, template, &["E3039"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 1, "Expected missing definition finding: {rego_findings:?}");
    assert!(rego_findings[0].contains("missing definitions: [missing_gsi_pk]"));
}

#[test]
fn dynamodb_conditional_index_no_false_positive_when_valid() {
    let template = r#"
Parameters:
  AddGSI:
    Type: String
Conditions:
  CreateGSI: !Equals [!Ref AddGSI, "true"]
Resources:
  ValidTableWithConditionalGSI:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: PAY_PER_REQUEST
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
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3039"]);
    let cel_findings = selected_findings(&cel, template, &["E3039"]);
    assert_eq!(rego_findings, cel_findings);
    // Table KeySchema only uses pk (defined), gsi_pk is for the conditional index.
    // No missing and no unused (index might use gsi_pk).
    assert!(rego_findings.is_empty(), "Valid table should not fire: {rego_findings:?}");
}

#[test]
fn dynamodb_unknown_gsi_does_not_skip_concrete_lsi_attributes() {
    let template = r#"
Parameters:
  GsiAttribute:
    Type: String
Resources:
  Table:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - {AttributeName: pk, AttributeType: S}
        - {AttributeName: sk, AttributeType: S}
      KeySchema:
        - {AttributeName: pk, KeyType: HASH}
        - {AttributeName: sk, KeyType: RANGE}
      GlobalSecondaryIndexes:
        - IndexName: dynamic
          KeySchema:
            - {AttributeName: !Ref GsiAttribute, KeyType: HASH}
          Projection: {ProjectionType: ALL}
      LocalSecondaryIndexes:
        - IndexName: concrete
          KeySchema:
            - {AttributeName: pk, KeyType: HASH}
            - {AttributeName: lsi_sort, KeyType: RANGE}
          Projection: {ProjectionType: ALL}
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3039"]);
    let cel_findings = selected_findings(&cel, template, &["E3039"]);

    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 1, "the concrete LSI reference must still be validated: {rego_findings:?}");
    assert!(rego_findings[0].contains("missing definitions: [lsi_sort]"));
    assert!(!rego_findings[0].contains("unused definitions"));
}

#[test]
fn identity_policy_novalue_required_members_are_checked_per_scenario() {
    let template = r#"
Conditions:
  UsePositiveMember: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  MissingAction:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: !If [UsePositiveMember, s3:GetObject, !Ref AWS::NoValue]
            Resource: "*"
  MissingResource:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: s3:GetObject
            Resource: !If [UsePositiveMember, "*", !Ref AWS::NoValue]
  MutuallyExclusiveActions:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: !If [UsePositiveMember, s3:GetObject, !Ref AWS::NoValue]
            NotAction: !If [UsePositiveMember, !Ref AWS::NoValue, s3:DeleteObject]
            Resource: "*"
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3510"]);
    let cel_findings = selected_findings(&cel, template, &["E3510"]);

    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 2, "only scenarios with a removed required member should fail: {rego_findings:?}");
    assert!(rego_findings.iter().any(|finding| {
        finding.contains("MissingAction")
            && finding.contains("Only one of ['Action', 'NotAction'] is a required property")
    }));
    assert!(rego_findings.iter().any(|finding| {
        finding.contains("MissingResource")
            && finding.contains("Only one of ['Resource', 'NotResource'] is a required property")
    }));
    assert!(rego_findings.iter().all(|finding| !finding.contains("MutuallyExclusiveActions")));
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
fn identity_policy_conditional_and_intrinsic_sibling_findings_are_identical() {
    let template = r#"
Parameters:
  ResourceArn:
    Type: String
Conditions:
  UseValid: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  ConditionalPolicy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: s3:GetObject
            Resource: !If [UseValid, "arn:aws:s3:::bucket/*", "not-an-arn"]
  SiblingPolicy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: s3:GetObject
            Resource:
              - !Ref ResourceArn
              - also-not-an-arn
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3510"]);
    let cel_findings = selected_findings(&cel, template, &["E3510"]);

    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 2, "both authored invalid branches must be reported: {rego_findings:?}");
    assert!(
        rego_findings.iter().any(|finding| finding.contains("ConditionalPolicy") && finding.contains("not-an-arn"))
    );
    assert!(
        rego_findings.iter().any(|finding| {
            finding.contains("SiblingPolicy")
                && finding.contains("Properties.PolicyDocument.Statement.0.Resource.1")
                && finding.contains("also-not-an-arn")
        }),
        "the intrinsic list item must not suppress its literal sibling: {rego_findings:?}"
    );
}

#[test]
fn identity_policy_resource_arn_boundaries_are_identical() {
    let template = r#"
Resources:
  InvalidResources:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Statement:
          - {Effect: Allow, Action: s3:GetObject, Resource: 'not-an-arn-${aws:username}'}
          - {Effect: Allow, Action: s3:GetObject, Resource: 'arn:aws:*:::bucket/key'}
          - {Effect: Allow, Action: s3:GetObject, Resource: 'arn:aws:s3:us-east-1:${aws:username}:bucket/key'}
  ValidResources:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Statement:
          - {Effect: Allow, Action: sqs:SendMessage, Resource: 'arn:aws:sqs'}
          - {Effect: Allow, Action: iam:GetUser, Resource: 'arn:${AWS::Partition}:iam::${AWS::AccountId}:user/${aws:username}'}
          - {Effect: Allow, Action: s3:GetObject, Resource: 'arn:*:s3:::bucket/key'}
          - {Effect: Allow, Action: s3:GetObject, Resource: '*'}
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3510"]);
    let cel_findings = selected_findings(&cel, template, &["E3510"]);

    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 3, "only the three malformed resource strings should fail: {rego_findings:?}");
    assert!(rego_findings.iter().all(|finding| finding.contains("InvalidResources")));
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
