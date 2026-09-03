use cel_engine::CelEngine;
use diagnostics::Diagnostic;
use rego_engine::RegoEngine;
use schema_validator::SchemaValidator;
use template_model::PseudoParameterOverrides;
use validation_engine::{EngineConfig, ValidateConfig, ValidationEngine, validate_bytes};

fn selected_findings(engine: &dyn ValidationEngine, template: &str, rule_ids: &[&str]) -> Vec<String> {
    selected_findings_with_config(engine, template, rule_ids, ValidateConfig::default())
}

fn selected_findings_with_config(
    engine: &dyn ValidationEngine,
    template: &str,
    rule_ids: &[&str],
    config: ValidateConfig,
) -> Vec<String> {
    let validator = SchemaValidator::default();
    let report = validate_bytes(engine, &validator, template.as_bytes(), config).unwrap();
    let mut findings: Vec<String> = report
        .diagnostics
        .iter()
        .filter(|diagnostic| rule_ids.contains(&diagnostic.rule_id.as_str()))
        .map(diagnostic_identity)
        .collect();
    findings.sort();
    findings
}

fn selected_findings_with_spans(engine: &dyn ValidationEngine, template: &str, rule_ids: &[&str]) -> Vec<String> {
    let validator = SchemaValidator::default();
    let report = validate_bytes(engine, &validator, template.as_bytes(), ValidateConfig::default()).unwrap();
    let mut findings: Vec<String> = report
        .diagnostics
        .iter()
        .filter(|diagnostic| rule_ids.contains(&diagnostic.rule_id.as_str()))
        .map(|diagnostic| format!("{}|{:?}", diagnostic_identity(diagnostic), diagnostic.location))
        .collect();
    findings.sort();
    findings
}

fn diagnostic_identity(diagnostic: &Diagnostic) -> String {
    format!(
        "{}|{:?}|{}|{}|{}|{}",
        diagnostic.rule_id,
        diagnostic.severity,
        diagnostic.resource_logical_id().unwrap_or(""),
        diagnostic.property_path.as_deref().unwrap_or(""),
        diagnostic.message,
        diagnostic.suggested_fix.as_deref().unwrap_or("")
    )
}

fn engines() -> (RegoEngine, CelEngine) {
    (RegoEngine::new(EngineConfig::default()).unwrap(), CelEngine::new(EngineConfig::default()).unwrap())
}

#[test]
fn redundant_substitution_has_identical_intrinsic_path_and_span() {
    let template = "Resources:\n  Instance:\n    Type: AWS::EC2::Instance\n    Metadata:\n      Files:\n        /etc/awslogs/awslogs.conf:\n          content:\n            Fn::Sub: no-vars\n";
    let (rego, cel) = engines();
    let rego_findings = selected_findings_with_spans(&rego, template, &["W1020"]);
    let cel_findings = selected_findings_with_spans(&cel, template, &["W1020"]);

    assert_eq!(rego_findings, cel_findings, "redundant substitutions must have identical diagnostics");
    assert_eq!(rego_findings.len(), 1, "expected one redundant substitution: {rego_findings:?}");
    assert!(rego_findings[0].contains("|Instance|Metadata.Files./etc/awslogs/awslogs.conf.content.Fn::Sub|"));
    assert!(rego_findings[0].contains("start_line: 8"), "expected the authored Fn::Sub line: {rego_findings:?}");
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
fn parameter_type_support_classification_matches_service_behavior() {
    let template = r#"
Parameters:
  Documented:
    Type: AWS::SSM::Parameter::Value<String>
  AcceptedSsm:
    Type: AWS::SSM::Parameter::Value<AWS::FakeService::FakeResource>
  AcceptedSsmList:
    Type: AWS::SSM::Parameter::Value<List<AWS::FakeService::FakeResource>>
  AcceptedList:
    Type: List<AWS::FakeService::FakeResource>
  RejectedTest:
    Type: AWS::SSM::Parameter::Value<Test>
  RejectedBoolean:
    Type: AWS::SSM::Parameter::Value<Boolean>
  RejectedList:
    Type: List<Test>
  Invalid:
    Type: NotAType
Resources: {}
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["F2002", "W2002"]);
    let cel_findings = selected_findings(&cel, template, &["F2002", "W2002"]);

    assert_eq!(rego_findings, cel_findings, "parameter type diagnostics must match across engines");
    assert_eq!(rego_findings.iter().filter(|finding| finding.starts_with("W2002|")).count(), 3);
    assert_eq!(rego_findings.iter().filter(|finding| finding.starts_with("F2002|")).count(), 4);
    for parameter in ["AcceptedSsm", "AcceptedSsmList", "AcceptedList"] {
        assert!(rego_findings.iter().any(|finding| finding.starts_with("W2002|") && finding.contains(parameter)));
    }
    for parameter in ["RejectedTest", "RejectedBoolean", "RejectedList", "Invalid"] {
        assert!(rego_findings.iter().any(|finding| finding.starts_with("F2002|") && finding.contains(parameter)));
    }
    assert!(rego_findings.iter().all(|finding| !finding.contains("Parameter 'Documented'")));
}

#[test]
fn unsupported_lifecycle_attributes_have_identical_authored_paths() {
    let template = r#"
Resources:
  UnsupportedBucket:
    Type: AWS::S3::Bucket
    CreationPolicy:
      ResourceSignal:
        Count: 1
    UpdatePolicy:
      AutoScalingRollingUpdate:
        MinInstancesInService: 1
  UnsupportedTopic:
    Type: AWS::SNS::Topic
    CreationPolicy:
      ResourceSignal:
        Count: 1
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3016", "E3055"]);
    let cel_findings = selected_findings(&cel, template, &["E3016", "E3055"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 3, "each unsupported lifecycle attribute should be reported: {rego_findings:?}");
    assert!(rego_findings.iter().any(|finding| finding.contains("|UnsupportedBucket|CreationPolicy|")));
    assert!(rego_findings.iter().any(|finding| finding.contains("|UnsupportedBucket|UpdatePolicy|")));
    assert!(rego_findings.iter().any(|finding| finding.contains("|UnsupportedTopic|CreationPolicy|")));
}

#[test]
fn statically_removed_update_policy_is_not_reported() {
    let template = r#"
Conditions:
  Never: !Equals [always, never]
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    UpdatePolicy: !If
      - Never
      - AutoScalingRollingUpdate:
          MinInstancesInService: 1
      - !Ref AWS::NoValue
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3016"]);
    let cel_findings = selected_findings(&cel, template, &["E3016"]);
    assert_eq!(rego_findings, cel_findings);
    assert!(rego_findings.is_empty(), "an unreachable policy branch must not count as present: {rego_findings:?}");
}

#[test]
fn scalar_update_policy_has_structure_and_policy_diagnostics() {
    let template = r#"
Resources:
  ScalarUpdatePolicy:
    Type: AWS::AutoScaling::AutoScalingGroup
    UpdatePolicy: 7
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3001", "E3016"]);
    let cel_findings = selected_findings(&cel, template, &["E3001", "E3016"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 2, "both compatibility diagnostics must be emitted: {rego_findings:?}");
    assert!(rego_findings.iter().any(|finding| finding.starts_with("E3001|")));
    assert!(rego_findings.iter().any(|finding| {
        finding.starts_with("E3016|") && finding.contains("|ScalarUpdatePolicy|UpdatePolicy|7 is not of type 'object'|")
    }));
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
  DecimalEquivalent:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: "+2.0 vCPU"
      Memory: "+4.0 GB"
      ContainerDefinitions: [{Name: app, Image: nginx}]
  LeadingZeroEquivalent:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: "02 vCPU"
      Memory: "04 GB"
      ContainerDefinitions: [{Name: app, Image: nginx}]
  InvalidCpu:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: "128"
      Memory: "512"
      ContainerDefinitions: [{Name: app, Image: nginx}]
  ScientificCpu:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: "2e0 vCPU"
      Memory: "4 GB"
      ContainerDefinitions: [{Name: app, Image: nginx}]
  ScientificMemory:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: "2 vCPU"
      Memory: "4e0 GB"
      ContainerDefinitions: [{Name: app, Image: nginx}]
  LeadingCpuWhitespace:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: " 2 vCPU"
      Memory: "4 GB"
      ContainerDefinitions: [{Name: app, Image: nginx}]
  LeadingMemoryWhitespace:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: "2 vCPU"
      Memory: " 4 GB"
      ContainerDefinitions: [{Name: app, Image: nginx}]
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3047", "E3048"]);
    let cel_findings = selected_findings(&cel, template, &["E3047", "E3048"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 8, "only invalid scalar spellings and sizes should fire: {rego_findings:?}");
    for clean_resource in
        ["IntegralFloat", "NonIntegralFloat", "CompositeCpu", "DecimalEquivalent", "LeadingZeroEquivalent"]
    {
        assert!(
            rego_findings.iter().all(|finding| !finding.contains(clean_resource)),
            "{clean_resource} must not produce Fargate size findings: {rego_findings:?}"
        );
    }
    for (invalid_resource, expected_count) in [
        ("InvalidCpu", 2),
        ("ScientificCpu", 2),
        ("ScientificMemory", 1),
        ("LeadingCpuWhitespace", 2),
        ("LeadingMemoryWhitespace", 1),
    ] {
        assert_eq!(
            rego_findings.iter().filter(|finding| finding.contains(invalid_resource)).count(),
            expected_count,
            "{invalid_resource} must produce the expected Fargate size findings: {rego_findings:?}"
        );
    }
    let cpu_value_findings = rego_findings.iter().filter(|finding| finding.starts_with("E3048|")).collect::<Vec<_>>();
    assert_eq!(cpu_value_findings.len(), 3, "expected one Cpu value finding per invalid Cpu: {rego_findings:?}");
    assert!(cpu_value_findings.iter().all(|finding| {
        finding.contains(
            "Valid sizes are ['256', '512', '1024', '2048', '4096', '8192', '16384', '32768'] CPU units or ['0.25', '0.5', '1', '2', '4', '8', '16', '32'] vCPU.",
        ) && finding.contains("Use a valid Fargate Cpu size in CPU units or vCPU")
            && !finding.contains("Must be one of")
    }));
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
    assert_eq!(rego_findings.len(), 2, "both index-presence worlds must be checked: {rego_findings:?}");
    assert!(rego_findings.iter().all(|finding| finding.contains("missing definitions: [missing_sk]")));
    assert_eq!(
        rego_findings.iter().filter(|finding| finding.contains("unused definitions: [gsi_pk]")).count(),
        1,
        "the index-absent world must expose its unused definition: {rego_findings:?}"
    );
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
fn dynamodb_conditional_index_reports_unused_definition_when_absent() {
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
    assert_eq!(rego_findings.len(), 1, "the index-absent world must be reported: {rego_findings:?}");
    assert!(rego_findings[0].contains("unused definitions: [gsi_pk]"));
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
fn identity_policy_scenario_gap_findings_match_with_exact_spans() {
    let template = r#"
Parameters:
  WholeArn:
    Type: String
    Default: not-an-arn
Conditions:
  IsProd: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  IdenticalBranches:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: s3:GetObject
            Resource: !If
              - IsProd
              - not-an-arn
              - not-an-arn
  LiteralAndMalformedSub:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: s3:GetObject
            Resource: !If
              - IsProd
              - !Sub 'bad-${AWS::AccountId}'
              - also-not-an-arn
  ValidSub:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Statement:
          - {Effect: Allow, Action: s3:GetObject, Resource: !Sub 'arn:${AWS::Partition}:s3:::bucket/*'}
  IndeterminateSub:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Statement:
          - {Effect: Allow, Action: s3:GetObject, Resource: !Sub '${WholeArn}'}
  RawPlaceholders:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Statement:
          - {Effect: Allow, Action: s3:GetObject, Resource: 'arn:aws:s3:::${BucketName}/*'}
          - {Effect: Deny, Action: s3:DeleteObject, NotResource: 'arn:aws:s3:::${ProtectedBucket}/*'}
  ShiftedLiteralNull:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action:
              - !If [IsProd, !Ref AWS::NoValue, s3:GetObject]
              - null
            Resource: '*'
  EmptyNotAction:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            NotAction:
              - !If [IsProd, !Ref AWS::NoValue, s3:GetObject]
              - !If [IsProd, !Ref AWS::NoValue, s3:PutObject]
            Resource: '*'
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings_with_spans(&rego, template, &["E3510"]);
    let cel_findings = selected_findings_with_spans(&cel, template, &["E3510"]);

    assert_eq!(rego_findings, cel_findings, "IAM diagnostics must match through source spans");
    assert_eq!(rego_findings.len(), 8, "expected every and only authored IAM defect: {rego_findings:#?}");
    assert_eq!(
        rego_findings.iter().filter(|finding| finding.contains("IdenticalBranches")).count(),
        2,
        "identical branches must remain distinct by source span: {rego_findings:#?}"
    );
    assert_eq!(
        rego_findings.iter().filter(|finding| finding.contains("LiteralAndMalformedSub")).count(),
        2,
        "both the malformed Sub and literal branch must fire: {rego_findings:#?}"
    );
    assert_eq!(rego_findings.iter().filter(|finding| finding.contains("RawPlaceholders")).count(), 2);
    assert!(rego_findings.iter().any(|finding| {
        finding.contains("ShiftedLiteralNull")
            && finding.contains("Properties.PolicyDocument.Statement.0.Action.1")
            && finding.contains("not of type 'string'")
    }));
    assert!(rego_findings.iter().any(|finding| {
        finding.contains("EmptyNotAction")
            && finding.contains("Properties.PolicyDocument.Statement.0.NotAction")
            && finding.contains("too short")
    }));
    assert!(rego_findings.iter().all(|finding| !finding.contains("ValidSub")));
    assert!(rego_findings.iter().all(|finding| !finding.contains("IndeterminateSub")));
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
          - {Effect: Allow, Action: iam:GetUser, Resource: !Sub 'arn:${AWS::Partition}:iam::${AWS::AccountId}:user/${aws:username}'}
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

#[test]
fn e3510_conditional_whole_policies_validates_both_branches() {
    let template = r#"
Parameters:
  Env:
    Type: String
    Default: prod
Conditions:
  IsProd: !Equals [!Ref Env, prod]
Resources:
  Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies: !If
        - IsProd
        - - PolicyName: P1
            PolicyDocument:
              Version: '2012-10-17'
              Statement:
                - Effect: Allow
                  Action: s3:GetObject
                  Resource: not-an-arn
          - PolicyName: P2
            PolicyDocument:
              Version: '2012-10-17'
              Statement:
                - Effect: Allow
                  Action: logs:*
                  Resource: '*'
        - - PolicyName: Dev
            PolicyDocument:
              Version: '2012-10-17'
              Statement:
                - Effect: Allow
                  Action: s3:*
                  Resource: also-bad
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3510"]);
    let cel_findings = selected_findings(&cel, template, &["E3510"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 2, "both branches with bad ARNs must fire: {rego_findings:?}");
}

#[test]
fn w2512_conditional_whole_policies_notaction_branch() {
    let template = r#"
Parameters:
  Env:
    Type: String
    Default: prod
Conditions:
  IsProd: !Equals [!Ref Env, prod]
Resources:
  Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies: !If
        - IsProd
        - - PolicyName: ProdWide
            PolicyDocument:
              Version: '2012-10-17'
              Statement:
                - Effect: Allow
                  NotAction: iam:*
                  Resource: '*'
        - - PolicyName: DevNarrow
            PolicyDocument:
              Version: '2012-10-17'
              Statement:
                - Effect: Allow
                  Action: s3:GetObject
                  Resource: '*'
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["W2512"]);
    let cel_findings = selected_findings(&cel, template, &["W2512"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 1, "NotAction in one branch must fire: {rego_findings:?}");
}

#[test]
fn w2512_single_object_statement_fires() {
    let template = r#"
Resources:
  Policy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          Effect: Allow
          NotAction: iam:*
          Resource: '*'
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["W2512"]);
    let cel_findings = selected_findings(&cel, template, &["W2512"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 1, "single-object Statement with NotAction must fire: {rego_findings:?}");
}

#[test]
fn w2512_novalue_branch_does_not_false_positive() {
    let template = r#"
Parameters:
  Env:
    Type: String
    Default: prod
Conditions:
  IsProd: !Equals [!Ref Env, prod]
Resources:
  Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies: !If
        - IsProd
        - - PolicyName: P1
            PolicyDocument:
              Version: '2012-10-17'
              Statement:
                - Effect: Allow
                  Action: s3:GetObject
                  Resource: '*'
        - !Ref AWS::NoValue
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["W2512"]);
    let cel_findings = selected_findings(&cel, template, &["W2512"]);
    assert_eq!(rego_findings, cel_findings);
    assert!(rego_findings.is_empty(), "NoValue branch must not false-positive: {rego_findings:?}");
}

#[test]
fn e3510_novalue_branch_suppressed() {
    let template = r#"
Parameters:
  Env:
    Type: String
    Default: prod
Conditions:
  IsProd: !Equals [!Ref Env, prod]
Resources:
  Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies: !If
        - IsProd
        - - PolicyName: P1
            PolicyDocument:
              Version: '2012-10-17'
              Statement:
                - Effect: Allow
                  Action: s3:GetObject
                  Resource: '*'
        - !Ref AWS::NoValue
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3510"]);
    let cel_findings = selected_findings(&cel, template, &["E3510"]);
    assert_eq!(rego_findings, cel_findings);
    assert!(rego_findings.is_empty(), "NoValue Policies branch must not fire E3510: {rego_findings:?}");
}

#[test]
fn e3510_different_branch_list_lengths() {
    let template = r#"
Parameters:
  Env:
    Type: String
    Default: prod
Conditions:
  IsProd: !Equals [!Ref Env, prod]
Resources:
  Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies: !If
        - IsProd
        - - PolicyName: P1
            PolicyDocument:
              Version: '2012-10-17'
              Statement:
                - Effect: Allow
                  Action: s3:Get*
                  Resource: '*'
          - PolicyName: P2
            PolicyDocument:
              Version: '2012-10-17'
              Statement:
                - Effect: Allow
                  Action: logs:*
                  Resource: '*'
        - - PolicyName: SingleDev
            PolicyDocument:
              Version: '2012-10-17'
              Statement:
                - Effect: Allow
                  Action: s3:*
                  Resource: '*'
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3510"]);
    let cel_findings = selected_findings(&cel, template, &["E3510"]);
    assert_eq!(rego_findings, cel_findings);
    assert!(rego_findings.is_empty(), "valid templates with different branch lengths must not fire: {rego_findings:?}");
}

#[test]
fn w2512_dynamic_and_reachability_boundaries() {
    let template = r#"
Parameters:
  Unknown:
    Type: String
  Env:
    Type: String
    Default: prod
Conditions:
  IsProd: !Equals [!Ref Env, prod]
Resources:
  WholeDocument:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument: !Ref Unknown
  UnknownStatement:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Statement: !Ref Unknown
  UnknownEffect:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Statement:
          Effect: !Ref Unknown
          NotAction: iam:*
          Resource: '*'
  RemovedNotAction:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Statement:
          Effect: Allow
          Action: s3:GetObject
          NotAction: !Ref AWS::NoValue
          Resource: '*'
  DenyNotAction:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Statement:
          Effect: Deny
          NotAction: iam:*
          Resource: '*'
  UnknownNotAction:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Statement:
          Effect: Allow
          NotAction: !Ref Unknown
          Resource: '*'
  CorrelatedPolicy:
    Type: AWS::IAM::ManagedPolicy
    Condition: IsProd
    Properties:
      PolicyDocument:
        Statement: !If
          - IsProd
          - Effect: Allow
            Action: s3:GetObject
            Resource: '*'
          - Effect: Allow
            NotAction: iam:*
            Resource: '*'
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["W2512"]);
    let cel_findings = selected_findings(&cel, template, &["W2512"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(
        rego_findings.len(),
        1,
        "only the authored unknown NotAction value is definitely in use: {rego_findings:?}"
    );
    assert!(rego_findings[0].contains("UnknownNotAction"));
}

#[test]
fn fargate_whole_properties_placement_follows_compatible_branch() {
    let template = r#"
Conditions:
  IsFargate: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  PlacementInFargateBranch:
    Type: AWS::ECS::TaskDefinition
    Properties: !If
      - IsFargate
      - RequiresCompatibilities: [FARGATE]
        NetworkMode: awsvpc
        Cpu: '256'
        Memory: '512'
        PlacementConstraints: [{Type: memberOf, Expression: 'attribute:ecs.instance-type =~ t3.*'}]
        ContainerDefinitions: [{Name: app, Image: nginx}]
      - RequiresCompatibilities: [EC2]
        ContainerDefinitions: [{Name: app, Image: nginx}]
  PlacementOnlyInEc2Branch:
    Type: AWS::ECS::TaskDefinition
    Properties: !If
      - IsFargate
      - RequiresCompatibilities: [FARGATE]
        NetworkMode: awsvpc
        Cpu: '256'
        Memory: '512'
        ContainerDefinitions: [{Name: app, Image: nginx}]
      - RequiresCompatibilities: [EC2]
        PlacementConstraints: [{Type: memberOf, Expression: 'attribute:ecs.instance-type =~ t3.*'}]
        ContainerDefinitions: [{Name: app, Image: nginx}]
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3048"]);
    let cel_findings = selected_findings(&cel, template, &["E3048"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 1, "only Fargate-compatible placement is unsupported: {rego_findings:?}");
    assert!(rego_findings[0].contains("PlacementInFargateBranch"));
}

#[test]
fn dynamodb_whole_properties_correlates_billing_mode_and_throughput() {
    let template = r#"
Conditions:
  OnDemand: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  InvalidDefaultBranch:
    Type: AWS::DynamoDB::Table
    Properties: !If
      - OnDemand
      - BillingMode: PAY_PER_REQUEST
      - {}
  ValidCorrelated:
    Type: AWS::DynamoDB::Table
    Properties: !If
      - OnDemand
      - BillingMode: PAY_PER_REQUEST
      - ProvisionedThroughput: {ReadCapacityUnits: 1, WriteCapacityUnits: 1}
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3639"]);
    let cel_findings = selected_findings(&cel, template, &["E3639"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 1, "only the defaulted branch without throughput is invalid: {rego_findings:?}");
    assert!(rego_findings[0].contains("InvalidDefaultBranch"));
}

#[test]
fn dynamodb_conditional_gsi_and_lsi_check_absent_worlds() {
    let template = r#"
Conditions:
  HasGSI: !Equals [!Ref AWS::Region, us-east-1]
  HasLSI: !Equals [!Ref AWS::Region, us-west-2]
Resources:
  ConditionalGSI:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - {AttributeName: pk, AttributeType: S}
        - {AttributeName: gsi_key, AttributeType: S}
      KeySchema: [{AttributeName: pk, KeyType: HASH}]
      GlobalSecondaryIndexes: !If
        - HasGSI
        - - IndexName: by-gsi
            KeySchema: [{AttributeName: gsi_key, KeyType: HASH}]
            Projection: {ProjectionType: ALL}
        - !Ref AWS::NoValue
  ConditionalLSI:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - {AttributeName: pk, AttributeType: S}
        - {AttributeName: sk, AttributeType: S}
        - {AttributeName: lsi_key, AttributeType: S}
      KeySchema:
        - {AttributeName: pk, KeyType: HASH}
        - {AttributeName: sk, KeyType: RANGE}
      LocalSecondaryIndexes: !If
        - HasLSI
        - - IndexName: by-lsi
            KeySchema:
              - {AttributeName: pk, KeyType: HASH}
              - {AttributeName: lsi_key, KeyType: RANGE}
            Projection: {ProjectionType: ALL}
        - !Ref AWS::NoValue
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3039"]);
    let cel_findings = selected_findings(&cel, template, &["E3039"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 2, "each absent-index world must expose its unused definition: {rego_findings:?}");
    assert!(rego_findings.iter().any(|finding| finding.contains("unused definitions: [gsi_key]")));
    assert!(rego_findings.iter().any(|finding| finding.contains("unused definitions: [lsi_key]")));
}

#[test]
fn tagging_follows_reachable_whole_properties_scenarios() {
    let template = r#"
Conditions:
  UseFirst: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  TaggedInBothWorlds:
    Type: AWS::S3::Bucket
    Properties: !If
      - UseFirst
      - Tags: [{Key: Name, Value: first}]
      - Tags: [{Key: Name, Value: second}]
  MissingInOneWorld:
    Type: AWS::S3::Bucket
    Properties: !If
      - UseFirst
      - Tags: [{Key: Name, Value: tagged}]
      - {}
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["I9040"]);
    let cel_findings = selected_findings(&cel, template, &["I9040"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 1, "only a reachable untagged world should be reported: {rego_findings:?}");
    assert!(rego_findings[0].contains("MissingInOneWorld"));
}

#[test]
fn snapstart_support_and_recommendations_respect_the_configured_region() {
    let template = include_str!("../../resources/templates/bad/E2530_I2530_snapstart_sourced_tables.yaml");
    let config = ValidateConfig {
        pseudo_parameter_overrides: PseudoParameterOverrides {
            region: Some("us-gov-west-1".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    let (rego, cel) = engines();
    let rego_findings = selected_findings_with_config(&rego, template, &["E2530", "I2530"], config.clone());
    let cel_findings = selected_findings_with_config(&cel, template, &["E2530", "I2530"], config);

    assert_eq!(rego_findings, cel_findings, "SnapStart diagnostics must be identical in a configured region");
    assert_eq!(rego_findings.len(), 3, "expected one runtime and two region findings: {rego_findings:?}");
    assert!(rego_findings.iter().all(|finding| finding.starts_with("E2530|")));
    assert_eq!(rego_findings.iter().filter(|finding| finding.contains("not supported in region")).count(), 2);
    assert!(rego_findings.iter().any(|finding| finding.contains("not supported with runtime 'python3.8'")));
    assert!(rego_findings.iter().any(|finding| finding.contains("|RegionLimitedJava|Properties.SnapStart.ApplyOn|")));
}
