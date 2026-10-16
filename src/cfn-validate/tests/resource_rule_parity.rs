use cel_engine::CelEngine;
use diagnostics::{Diagnostic, ReportStatus};
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

/// Each finding as `resource|property path|start line:start column`, sorted.
fn selected_finding_anchors(engine: &dyn ValidationEngine, template: &str, rule_ids: &[&str]) -> Vec<String> {
    let validator = SchemaValidator::default();
    let report = validate_bytes(engine, &validator, template.as_bytes(), ValidateConfig::default()).unwrap();
    let mut anchors: Vec<String> = report
        .diagnostics
        .iter()
        .filter(|diagnostic| rule_ids.contains(&diagnostic.rule_id.as_str()))
        .map(|diagnostic| {
            let location = diagnostic.location.as_ref().expect("every finding must carry a source location");
            format!(
                "{}|{}|{}:{}",
                diagnostic.resource_logical_id().unwrap_or(""),
                diagnostic.property_path.as_deref().unwrap_or(""),
                location.start_line,
                location.start_column
            )
        })
        .collect();
    anchors.sort();
    anchors
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
fn fargate_parameter_scenarios_are_not_treated_as_deployment_values() {
    let template = r#"
Parameters:
  Cpu:
    Type: Number
    Default: 16384
    AllowedValues: [256, 512, 1024, 2048, 4096, 8192, 16384]
  Memory:
    Type: Number
    Default: 49152
  CpuList:
    Type: CommaDelimitedList
    Default: "2048"
  Prefix:
    Type: String
    Default: "1"
  Suffix:
    Type: String
    Default: "024"
  Environment:
    Type: String
    Default: small
    AllowedValues: [small, large]
Mappings:
  TaskSizes:
    small: {Cpu: 256, Memory: 512}
    large: {Cpu: 8192, Memory: 49152}
Conditions:
  UseParameter: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  ParameterizedPair:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: !Ref Cpu
      Memory: !Ref Memory
      ContainerDefinitions: [{Name: app, Image: nginx}]
  ParameterizedCpu:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: !Ref Cpu
      Memory: 49152
      ContainerDefinitions: [{Name: app, Image: nginx}]
  ParameterizedMemory:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: 256
      Memory: !Ref Memory
      ContainerDefinitions: [{Name: app, Image: nginx}]
  MappedPair:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: !FindInMap [TaskSizes, !Ref Environment, Cpu]
      Memory: !FindInMap [TaskSizes, !Ref Environment, Memory]
      ContainerDefinitions: [{Name: app, Image: nginx}]
  JoinedCpu:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: !Join ["", [!Ref Cpu]]
      Memory: 49152
      ContainerDefinitions: [{Name: app, Image: nginx}]
  HoistedSelect:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu:
        Fn::Select:
          - 0
          - - Fn::If: [UseParameter, !Ref Cpu, 512]
      Memory: 512
      ContainerDefinitions: [{Name: app, Image: nginx}]
  HoistedJoin:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu:
        Fn::Join:
          - ""
          - Fn::If: [UseParameter, !Ref CpuList, ["512"]]
      Memory: 512
      ContainerDefinitions: [{Name: app, Image: nginx}]
  SubstitutedCpu:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: !Sub "${Prefix}${Suffix}"
      Memory: 512
      ContainerDefinitions: [{Name: app, Image: nginx}]
  ConditionalCpu:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: !If [UseParameter, !Ref Cpu, 512]
      Memory: 512
      ContainerDefinitions: [{Name: app, Image: nginx}]
  ConditionalMemory:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: 256
      Memory: !If [UseParameter, !Ref Memory, 4096]
      ContainerDefinitions: [{Name: app, Image: nginx}]
  LiteralInvalid:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: 256
      Memory: 4096
      ContainerDefinitions: [{Name: app, Image: nginx}]
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3047"]);
    let cel_findings = selected_findings(&cel, template, &["E3047"]);

    assert_eq!(rego_findings, cel_findings, "parameter handling must match across engines");
    assert_eq!(rego_findings.len(), 5, "only invalid literal scenarios should be reported: {rego_findings:?}");
    for (resource, message) in [
        ("ConditionalCpu", "Cpu 512 is not compatible with Memory 512 for Fargate"),
        ("ConditionalMemory", "Cpu 256 is not compatible with Memory 4096 for Fargate"),
        ("HoistedSelect", "Cpu 512 is not compatible with Memory 512 for Fargate"),
        ("HoistedJoin", "Cpu '512' is not compatible with Memory 512 for Fargate"),
        ("LiteralInvalid", "Cpu 256 is not compatible with Memory 4096 for Fargate"),
    ] {
        assert!(
            rego_findings.iter().any(|finding| finding.contains(resource) && finding.contains(message)),
            "missing literal-scenario finding for {resource}: {rego_findings:?}"
        );
    }
    for resource in
        ["ParameterizedPair", "ParameterizedCpu", "ParameterizedMemory", "MappedPair", "JoinedCpu", "SubstitutedCpu"]
    {
        assert!(
            rego_findings.iter().all(|finding| !finding.contains(resource)),
            "parameter-derived values must not be reported for {resource}: {rego_findings:?}"
        );
    }
}

#[test]
fn fargate_parameter_overrides_are_validated_as_deployment_values() {
    let template = r#"
Parameters:
  Cpu:
    Type: Number
    Default: 8192
    AllowedValues: [256, 8192]
  Memory:
    Type: Number
    Default: 49152
  Prefix:
    Type: String
    Default: "8"
  Suffix:
    Type: String
    Default: "192"
  RuntimeCpu:
    Type: AWS::SSM::Parameter::Value<String>
    Default: /ecs/task/cpu
Resources:
  DirectTask:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: !Ref Cpu
      Memory: !Ref Memory
      ContainerDefinitions: [{Name: app, Image: nginx}]
  SubstitutedTask:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: !Sub "${Prefix}${Suffix}"
      Memory: !Ref Memory
      ContainerDefinitions: [{Name: app, Image: nginx}]
  SsmTask:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: !Ref RuntimeCpu
      Memory: 512
      ContainerDefinitions: [{Name: app, Image: nginx}]
"#;
    let invalid_config = ValidateConfig {
        parameter_overrides: [
            ("Cpu".into(), "256".into()),
            ("Memory".into(), "4096".into()),
            ("Prefix".into(), "2".into()),
            ("Suffix".into(), "56".into()),
            ("RuntimeCpu".into(), "/ecs/task/cpu".into()),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    let partial_config = ValidateConfig {
        parameter_overrides: [
            ("Cpu".into(), "256".into()),
            ("Memory".into(), "4096".into()),
            ("Suffix".into(), "56".into()),
            ("RuntimeCpu".into(), "/ecs/task/cpu".into()),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    let valid_config = ValidateConfig {
        parameter_overrides: [
            ("Cpu".into(), "8192".into()),
            ("Memory".into(), "49152".into()),
            ("Prefix".into(), "8".into()),
            ("Suffix".into(), "192".into()),
            ("RuntimeCpu".into(), "/ecs/task/cpu".into()),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    let (rego, cel) = engines();
    let rego_invalid = selected_findings_with_config(&rego, template, &["E3047"], invalid_config.clone());
    let cel_invalid = selected_findings_with_config(&cel, template, &["E3047"], invalid_config);
    let rego_partial = selected_findings_with_config(&rego, template, &["E3047"], partial_config.clone());
    let cel_partial = selected_findings_with_config(&cel, template, &["E3047"], partial_config);
    let rego_valid = selected_findings_with_config(&rego, template, &["E3047"], valid_config.clone());
    let cel_valid = selected_findings_with_config(&cel, template, &["E3047"], valid_config);

    assert_eq!(rego_invalid, cel_invalid, "invalid overrides must match across engines");
    assert_eq!(rego_invalid.len(), 2, "each invalid supplied pair must be reported: {rego_invalid:?}");
    assert!(rego_invalid.iter().any(|finding| finding.contains("DirectTask")));
    assert!(rego_invalid.iter().any(|finding| finding.contains("SubstitutedTask")));
    assert_eq!(rego_partial, cel_partial, "partial overrides must match across engines");
    assert_eq!(rego_partial.len(), 1, "only the fully supplied pair may be reported: {rego_partial:?}");
    assert!(rego_partial[0].contains("DirectTask"));
    assert_eq!(rego_valid, cel_valid, "valid overrides must match across engines");
    assert!(rego_valid.is_empty(), "valid supplied pairs must not be reported: {rego_valid:?}");
    for findings in [&rego_invalid, &rego_partial, &rego_valid] {
        assert!(findings.iter().all(|finding| !finding.contains("SsmTask")));
    }
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
fn dynamic_properties_do_not_imply_missing_retention_period() {
    let template = r#"
Parameters:
  Stage:
    Type: String
  RetentionDays:
    Type: Number
Conditions:
  IsProduction: !Equals [!Ref Stage, production]
  IsNotProduction: !Not [!Condition IsProduction]
Resources:
  DynamicPropertiesQueue:
    Type: AWS::SQS::Queue
    Properties:
      Fn::Transform:
        Name: AWS::Include
        Parameters:
          Location: s3://example-bucket/queue-properties.yaml
  SiblingTransformQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: example-queue
      Fn::Transform:
        Name: AWS::Include
        Parameters:
          Location: s3://example-bucket/queue-properties.yaml
  ResourceTransformQueue:
    Type: AWS::SQS::Queue
    Fn::Transform:
      Name: AWS::Include
      Parameters:
        Location: s3://example-bucket/queue-resource.yaml
  NestedTransformQueue:
    Type: AWS::SQS::Queue
    Properties:
      Tags:
        Fn::Transform:
          Name: AWS::Include
          Parameters:
            Location: s3://example-bucket/queue-tags.yaml
  DynamicRetentionQueue:
    Type: AWS::SQS::Queue
    Properties:
      MessageRetentionPeriod: !Ref RetentionDays
  ConditionalSetQueue:
    Type: AWS::SQS::Queue
    Properties: !If
      - IsProduction
      - MessageRetentionPeriod: 1209600
      - MessageRetentionPeriod: 60
  ConditionalMacroOrSetQueue:
    Type: AWS::SQS::Queue
    Properties: !If
      - IsProduction
      - Fn::Transform:
          Name: AWS::Include
          Parameters:
            Location: s3://example-bucket/production-queue-properties.yaml
      - MessageRetentionPeriod: 60
  ConditionalMacroOnlyQueue:
    Type: AWS::SQS::Queue
    Properties: !If
      - IsProduction
      - Fn::Transform:
          Name: AWS::Include
          Parameters:
            Location: s3://example-bucket/production-queue-properties.yaml
      - Fn::Transform:
          Name: AWS::Include
          Parameters:
            Location: s3://example-bucket/development-queue-properties.yaml
  ConditionalRetentionQueue:
    Type: AWS::SQS::Queue
    Properties:
      MessageRetentionPeriod: !If [IsProduction, 1209600, !Ref AWS::NoValue]
  ResourceConditionAllowsAbsenceQueue:
    Type: AWS::SQS::Queue
    Condition: IsProduction
    Properties:
      MessageRetentionPeriod: !If [IsProduction, !Ref AWS::NoValue, 60]
  ResourceConditionExcludesAbsenceQueue:
    Type: AWS::SQS::Queue
    Condition: IsProduction
    Properties:
      MessageRetentionPeriod: !If [IsProduction, 60, !Ref AWS::NoValue]
  NegatedResourceConditionExcludesAbsenceQueue:
    Type: AWS::SQS::Queue
    Condition: IsNotProduction
    Properties:
      MessageRetentionPeriod: !If [IsProduction, !Ref AWS::NoValue, 60]
  CorrelatedConditionsExcludeAbsenceQueue:
    Type: AWS::SQS::Queue
    Properties:
      MessageRetentionPeriod: !If
        - IsProduction
        - 1209600
        - !If [IsNotProduction, 60, !Ref AWS::NoValue]
  ConditionalTransformQueue:
    Type: AWS::SQS::Queue
    Properties: !If
      - IsProduction
      - Fn::Transform:
          Name: AWS::Include
          Parameters:
            Location: s3://example-bucket/queue-properties.yaml
      - VisibilityTimeout: 900
  ConcreteQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: concrete-queue
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["I3013"]);
    let cel_findings = selected_findings(&cel, template, &["I3013"]);

    assert_eq!(rego_findings, cel_findings);
    assert_eq!(
        rego_findings.len(),
        5,
        "only known reachable missing retention periods are reported: {rego_findings:?}"
    );
    for resource in [
        "ConcreteQueue",
        "ConditionalRetentionQueue",
        "ConditionalTransformQueue",
        "NestedTransformQueue",
        "ResourceConditionAllowsAbsenceQueue",
    ] {
        assert!(rego_findings.iter().any(|finding| finding.contains(&format!("|{resource}|Properties|"))));
    }
    for resource in [
        "ConditionalMacroOnlyQueue",
        "ConditionalMacroOrSetQueue",
        "ConditionalSetQueue",
        "CorrelatedConditionsExcludeAbsenceQueue",
        "DynamicPropertiesQueue",
        "DynamicRetentionQueue",
        "NegatedResourceConditionExcludesAbsenceQueue",
        "ResourceConditionExcludesAbsenceQueue",
        "ResourceTransformQueue",
        "SiblingTransformQueue",
    ] {
        assert!(rego_findings.iter().all(|finding| !finding.contains(&format!("|{resource}|"))));
    }
}

#[test]
fn whole_properties_no_value_is_a_schema_type_error() {
    let template = r#"
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties: !Ref AWS::NoValue
  MacroOwnedQueue:
    Type: AWS::SQS::Queue
    Properties: !Ref AWS::NoValue
    Fn::Transform:
      Name: AWS::Include
      Parameters:
        Location: s3://example-bucket/queue-resource.yaml
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["F3012", "I3013"]);
    let cel_findings = selected_findings(&cel, template, &["F3012", "I3013"]);

    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 1, "the non-object Properties value must produce one finding: {rego_findings:?}");
    assert!(
        rego_findings[0].contains("F3012|Fatal|Queue|Properties|{'Ref': 'AWS::NoValue'} is not of type 'object'"),
        "the whole Properties value must be rejected without a missing-retention cascade: {rego_findings:?}"
    );

    let rego_anchors = selected_finding_anchors(&rego, template, &["F3012"]);
    let cel_anchors = selected_finding_anchors(&cel, template, &["F3012"]);
    assert_eq!(rego_anchors, cel_anchors);
    assert_eq!(rego_anchors, ["Queue|Properties|5:5"]);
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

#[test]
fn icmpv6_type_code_is_neither_ignored_nor_required() {
    let template = include_str!("../../resources/templates/good/sg_icmpv6_type_code.yaml");
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["W3687", "E3687"]);
    let cel_findings = selected_findings(&cel, template, &["W3687", "E3687"]);
    assert_eq!(rego_findings, cel_findings);
    assert!(rego_findings.is_empty(), "ICMPv6 type/code must not be reported as ignored or missing: {rego_findings:?}");
}

#[test]
fn ports_are_ignored_only_for_protocols_other_than_tcp_udp_icmp_icmpv6() {
    let template = include_str!("../../resources/templates/bad/W3687_ports_ignored_by_protocol.yaml");
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["W3687", "E3687"]);
    let cel_findings = selected_findings(&cel, template, &["W3687", "E3687"]);
    assert_eq!(rego_findings, cel_findings, "protocol/port diagnostics must be identical");
    let ignored: Vec<_> = rego_findings.iter().filter(|finding| finding.starts_with("W3687|")).collect();
    let required: Vec<_> = rego_findings.iter().filter(|finding| finding.starts_with("E3687|")).collect();
    assert_eq!(ignored.len(), 5, "esp, 50, -1, gre and the standalone esp rule ignore their ports: {ignored:?}");
    assert_eq!(required.len(), 3, "icmp, udp and the standalone tcp rule must state ports: {required:?}");
}

#[test]
fn application_load_balancer_subnet_minimum_covers_default_type_refs_and_mappings() {
    let template = include_str!("../../resources/templates/bad/E3680_alb_fewer_than_two_subnets.yaml");
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3680"]);
    let cel_findings = selected_findings(&cel, template, &["E3680"]);
    assert_eq!(rego_findings, cel_findings, "subnet minimum diagnostics must be identical");
    assert_eq!(rego_findings.len(), 3, "one finding per under-provisioned load balancer: {rego_findings:?}");
    assert!(rego_findings.iter().any(|finding| finding.contains("|AlbDefaultTypeOneSubnet|Properties.Subnets|")));
    assert!(rego_findings.iter().any(|finding| finding.contains("|AlbExplicitTypeOneSubnet|Properties.Subnets|")));
    assert!(rego_findings.iter().any(|finding| finding.contains("|AlbOneSubnetMapping|Properties.SubnetMappings|")));
}

#[test]
fn subnet_minimum_skips_other_types_unknown_types_and_parameter_lists() {
    let template = include_str!("../../resources/templates/good/E3680_alb_subnet_counts.yaml");
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3680"]);
    let cel_findings = selected_findings(&cel, template, &["E3680"]);
    assert_eq!(rego_findings, cel_findings);
    assert!(rego_findings.is_empty(), "no load balancer here is a provably under-provisioned ALB: {rego_findings:?}");
}

#[test]
fn inverted_port_range_is_reported_on_every_rule_form() {
    let template = include_str!("../../resources/templates/bad/E9002_inverted_port_range_egress_and_standalone.yaml");
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E9002"]);
    let cel_findings = selected_findings(&cel, template, &["E9002"]);
    assert_eq!(rego_findings, cel_findings, "inverted range diagnostics must be identical");
    assert_eq!(rego_findings.len(), 3, "inline egress plus both standalone resources: {rego_findings:?}");
    assert!(rego_findings.iter().any(|finding| finding.contains("|SecurityGroup|Properties.SecurityGroupEgress.0|")));
    assert!(rego_findings.iter().any(|finding| finding.contains("|StandaloneIngressInverted|Properties.FromPort|")));
    assert!(rego_findings.iter().any(|finding| finding.contains("|StandaloneEgressInverted|Properties.FromPort|")));
}

#[test]
fn icmp_type_code_pairs_and_ascending_ranges_are_not_inverted() {
    let template = include_str!("../../resources/templates/good/E9002_port_range_exemptions.yaml");
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E9002"]);
    let cel_findings = selected_findings(&cel, template, &["E9002"]);
    assert_eq!(rego_findings, cel_findings);
    assert!(rego_findings.is_empty(), "type/code pairs are not port ranges: {rego_findings:?}");
}

#[test]
fn conditional_value_constraints_report_under_their_owning_rules() {
    let template = include_str!("../../resources/templates/bad/E3717_E3718_E3719_E3723_conditional_constraints.yaml");
    let (rego, cel) = engines();
    let rule_ids = ["E3717", "E3718", "E3719", "E3723"];
    let rego_findings = selected_findings(&rego, template, &rule_ids);
    let cel_findings = selected_findings(&cel, template, &rule_ids);
    assert_eq!(rego_findings, cel_findings, "conditional constraint diagnostics must be identical");
    assert!(
        rego_findings.iter().any(|finding| {
            finding.starts_with("E3718|")
                && finding.contains("|TokenAuthorizerTtlTooLong|Properties.AuthorizerResultTtlInSeconds|")
                && finding.contains("4000 exceeds maximum 3600 for a TOKEN or REQUEST authorizer")
        }),
        "{rego_findings:?}"
    );
    assert!(
        rego_findings.iter().any(|finding| {
            finding.starts_with("E3719|")
                && finding.contains("|MysqlBackupRetentionTooLong|Properties.BackupRetentionPeriod|")
                && finding.contains("40 exceeds maximum 35 for a non-Aurora engine")
        }),
        "{rego_findings:?}"
    );
    assert!(
        rego_findings.iter().any(|finding| {
            finding.starts_with("E3723|")
                && finding.contains("|StageWithRelativeResourcePath|Properties.MethodSettings.0.ResourcePath|")
                && finding.contains("ResourcePath 'orders' must start with '/'")
        }),
        "{rego_findings:?}"
    );
    assert!(
        rego_findings.iter().all(|finding| !finding.contains("MethodSettings.1")),
        "an absolute path is valid: {rego_findings:?}"
    );
}

#[test]
fn conditional_value_constraints_stay_silent_within_limits_and_outside_their_condition() {
    let template = include_str!("../../resources/templates/good/conditional_constraints_within_limits.yaml");
    let (rego, cel) = engines();
    let rule_ids = ["E3717", "E3718", "E3719", "E3723", "E3031"];
    let rego_findings = selected_findings(&rego, template, &rule_ids);
    let cel_findings = selected_findings(&cel, template, &rule_ids);
    assert_eq!(rego_findings, cel_findings);
    assert!(rego_findings.is_empty(), "values within the conditional limits must not be reported: {rego_findings:?}");
}

#[test]
fn custom_cognito_domain_must_be_a_fully_qualified_lowercase_name() {
    let template = include_str!("../../resources/templates/bad/E3031_cognito_user_pool_domain_pattern.yaml");
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3031"]);
    let cel_findings = selected_findings(&cel, template, &["E3031"]);
    assert_eq!(rego_findings, cel_findings, "domain pattern diagnostics must be identical");
    assert!(rego_findings.iter().any(|finding| finding.contains("|CustomDomainWithoutDots|Properties.Domain|")));
    assert!(rego_findings.iter().any(|finding| finding.contains("|CustomDomainLeadingHyphen|Properties.Domain|")));
}

#[test]
fn valid_cognito_domains_of_either_kind_are_not_reported() {
    let template = include_str!("../../resources/templates/good/E3031_cognito_user_pool_domain_pattern.yaml");
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3031"]);
    let cel_findings = selected_findings(&cel, template, &["E3031"]);
    assert_eq!(rego_findings, cel_findings);
    assert!(rego_findings.is_empty(), "{rego_findings:?}");
}

#[test]
fn composite_key_reserved_username_and_monitoring_constraints_report_under_their_owners() {
    let template = include_str!("../../resources/templates/bad/E3032_E3002_E3689_conditional_constraints.yaml");
    let (rego, cel) = engines();
    let rule_ids = ["E3032", "E3002", "E3689"];
    let rego_findings = selected_findings(&rego, template, &rule_ids);
    let cel_findings = selected_findings(&cel, template, &rule_ids);
    assert_eq!(rego_findings, cel_findings, "conditional constraint diagnostics must be identical");
    let item_count: Vec<_> = rego_findings.iter().filter(|finding| finding.starts_with("E3032|")).collect();
    assert_eq!(item_count.len(), 4, "key schema and attribute definitions of both table kinds: {item_count:?}");
    assert!(item_count.iter().all(|finding| finding.contains("Array length 1 is below minimum 2")));
    assert!(
        rego_findings.iter().any(|finding| {
            finding.starts_with("E3002|")
                && finding.contains("|ClusterReservedMasterUsername|Properties.MasterUsername|")
                && finding.contains("'admin' must not be one of ['admin']")
        }),
        "{rego_findings:?}"
    );
    let monitoring: Vec<_> = rego_findings.iter().filter(|finding| finding.starts_with("E3689|")).collect();
    assert_eq!(monitoring.len(), 2, "a role without an interval and an interval without a role: {monitoring:?}");
    assert!(
        monitoring
            .iter()
            .any(|finding| finding.contains("|ClusterMonitoringRoleWithoutInterval|Properties.MonitoringInterval|"))
    );
    assert!(monitoring.iter().any(|finding| finding.contains("|ClusterIntervalWithoutMonitoringRole|Properties|")));
}

#[test]
fn composite_keys_other_engines_and_consistent_monitoring_are_not_reported() {
    let template =
        include_str!("../../resources/templates/good/conditional_constraints_composite_keys_and_monitoring.yaml");
    let (rego, cel) = engines();
    let rule_ids = ["E3032", "E3002", "E3689"];
    let rego_findings = selected_findings(&rego, template, &rule_ids);
    let cel_findings = selected_findings(&cel, template, &rule_ids);
    assert_eq!(rego_findings, cel_findings);
    assert!(rego_findings.is_empty(), "{rego_findings:?}");
}

#[test]
fn snapstart_without_version_is_reported_at_each_reachable_enabling_apply_on() {
    let template = include_str!("../../resources/templates/bad/W2530_snapstart_conditional_apply_on.yaml");
    let (rego, cel) = engines();
    assert_eq!(
        selected_findings_with_spans(&rego, template, &["W2530"]),
        selected_findings_with_spans(&cel, template, &["W2530"]),
        "SnapStart version findings must be identical, spans included"
    );

    let anchors = selected_finding_anchors(&rego, template, &["W2530"]);

    assert_eq!(
        anchors,
        [
            "ApplyOnBesideNoValue|Properties.SnapStart.ApplyOn|74:53",
            "ApplyOnFalseBranch|Properties.SnapStart.ApplyOn|63:40",
            "ApplyOnTrueBranch|Properties.SnapStart.ApplyOn|52:34",
            "EveryBranchEnables|Properties.SnapStart.ApplyOn|100:11",
            "EveryBranchEnables|Properties.SnapStart.ApplyOn|99:11",
            "PropertiesFalseBranch|Properties.SnapStart.ApplyOn|41:11",
            "PropertiesTrueBranch|Properties.SnapStart.ApplyOn|17:11",
            "SnapStartBesideNoValue|Properties.SnapStart.ApplyOn|87:11",
        ],
        "every reachable enabling value is reported once at its authored position"
    );
}

#[test]
fn snapstart_in_unreachable_or_published_scenarios_is_not_reported() {
    let template = include_str!("../../resources/templates/good/W2530_snapstart_unreachable_or_published.yaml");
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["W2530"]);
    let cel_findings = selected_findings(&cel, template, &["W2530"]);
    assert_eq!(rego_findings, cel_findings);
    assert!(
        rego_findings.is_empty(),
        "unreachable enabling branches and versions published alongside SnapStart must not be reported: {rego_findings:?}"
    );
}

#[test]
fn snapstart_requires_a_version_publishing_the_function_in_the_same_deployment() {
    let template = include_str!("../../resources/templates/bad/W2530_snapstart_version_not_coexisting.yaml");
    let (rego, cel) = engines();
    assert_eq!(
        selected_findings_with_spans(&rego, template, &["W2530"]),
        selected_findings_with_spans(&cel, template, &["W2530"]),
        "SnapStart version findings must be identical, spans included"
    );

    let anchors = selected_finding_anchors(&rego, template, &["W2530"]);

    assert_eq!(
        anchors,
        [
            "VersionInOtherEnvironment|Properties.SnapStart.ApplyOn|65:11",
            "VersionNamesOtherFunctionWhenEnabled|Properties.SnapStart.ApplyOn|82:34",
            "VersionOnlyDependsOnFunction|Properties.SnapStart.ApplyOn|32:9",
            "VersionOnlyDescribesFunction|Properties.SnapStart.ApplyOn|48:9",
        ],
        "a version publishes a function only through its FunctionName and only where it is created"
    );
}

#[test]
fn snapstart_version_published_from_conditional_version_properties_follows_the_branch() {
    let template = r#"
Conditions:
  IsUsEast1: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  Other:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Role: !Sub arn:${AWS::Partition}:iam::${AWS::AccountId}:role/lambda
      Code: {S3Bucket: bucket, S3Key: code.zip}
  PublishedInEnablingBranch:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: java21
      Handler: example.Handler
      Role: !Sub arn:${AWS::Partition}:iam::${AWS::AccountId}:role/lambda
      Code: {S3Bucket: bucket, S3Key: code.zip}
      SnapStart: !If [IsUsEast1, {ApplyOn: PublishedVersions}, !Ref AWS::NoValue]
  PublishedInEnablingBranchVersion:
    Type: AWS::Lambda::Version
    Properties: !If
      - IsUsEast1
      - FunctionName: !Ref PublishedInEnablingBranch
      - FunctionName: !Ref Other
  PublishedOutsideEnablingBranch:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: java21
      Handler: example.Handler
      Role: !Sub arn:${AWS::Partition}:iam::${AWS::AccountId}:role/lambda
      Code: {S3Bucket: bucket, S3Key: code.zip}
      SnapStart: !If [IsUsEast1, {ApplyOn: PublishedVersions}, !Ref AWS::NoValue]
  PublishedOutsideEnablingBranchVersion:
    Type: AWS::Lambda::Version
    Properties: !If
      - IsUsEast1
      - FunctionName: !Ref Other
      - FunctionName: !Ref PublishedOutsideEnablingBranch
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings_with_spans(&rego, template, &["W2530"]);
    let cel_findings = selected_findings_with_spans(&cel, template, &["W2530"]);
    assert_eq!(rego_findings, cel_findings);
    assert_eq!(
        rego_findings.len(),
        1,
        "only the branch-mismatched version leaves SnapStart unpublished: {rego_findings:?}"
    );
    assert!(rego_findings[0].contains("|PublishedOutsideEnablingBranch|Properties.SnapStart.ApplyOn|"));
}

#[test]
fn snapstart_version_with_matching_explicit_function_name_is_attached() {
    let template = r#"
Resources:
  Named:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: snap-named
      Runtime: java21
      Handler: example.Handler
      Role: !Sub arn:${AWS::Partition}:iam::${AWS::AccountId}:role/lambda
      Code: {S3Bucket: bucket, S3Key: code.zip}
      SnapStart: {ApplyOn: PublishedVersions}
  NamedVersion:
    Type: AWS::Lambda::Version
    DependsOn: Named
    Properties:
      FunctionName: snap-named
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings_with_spans(&rego, template, &["W2530"]);
    let cel_findings = selected_findings_with_spans(&cel, template, &["W2530"]);

    assert_eq!(rego_findings, cel_findings);
    assert!(rego_findings.is_empty(), "the matching explicit name publishes the function: {rego_findings:?}");
}

#[test]
fn route53_cname_identity_ignores_unrelated_record_scenarios() {
    let template = include_str!("../../resources/templates/bad/E3023_cname_projection_covering.yaml");
    let (rego, cel) = engines();
    let rego_findings = selected_findings_with_spans(&rego, template, &["E3023"]);
    let cel_findings = selected_findings_with_spans(&cel, template, &["E3023"]);

    assert_eq!(rego_findings, cel_findings, "Route53 diagnostics must be identical, spans included");
    assert_eq!(rego_findings.len(), 1, "the reachable CNAME at the zone apex must be reported: {rego_findings:?}");
    assert!(rego_findings[0].contains("|Record|Properties.Name|"));
    assert!(rego_findings[0].contains("must not match HostedZoneName"));
}

#[test]
fn fargate_missing_network_mode_ignores_ec2_only_placement_scenarios() {
    let template = include_str!("../../resources/templates/bad/E3048_fargate_projection_covering.yaml");
    let (rego, cel) = engines();
    let rego_findings = selected_findings_with_spans(&rego, template, &["E3048"]);
    let cel_findings = selected_findings_with_spans(&cel, template, &["E3048"]);

    assert_eq!(rego_findings, cel_findings, "Fargate diagnostics must be identical, spans included");
    assert_eq!(
        rego_findings.len(),
        1,
        "only the reachable Fargate deployment without NetworkMode must be reported: {rego_findings:?}"
    );
    assert!(rego_findings[0].contains("|Task|Properties|"));
    assert!(rego_findings[0].contains("NetworkMode to be specified as 'awsvpc'"));
}

#[test]
fn whole_properties_item_cardinality_preserves_nested_member_conditions() {
    let template = include_str!("../../resources/templates/bad/F3032_whole_properties_item_cardinality.yaml");
    let (rego, cel) = engines();
    let rego_findings = selected_findings_with_spans(&rego, template, &["F3032"]);
    let cel_findings = selected_findings_with_spans(&cel, template, &["F3032"]);

    assert_eq!(rego_findings, cel_findings, "schema diagnostics must be identical, spans included");
    assert_eq!(rego_findings.len(), 1, "the selected branch can contain seventeen subnets: {rego_findings:?}");
    assert!(rego_findings[0].contains("|Function|Properties.VpcConfig.SubnetIds|"));
    assert!(rego_findings[0].contains("expected maximum item count: 16, found: 17"));
    let anchors = selected_finding_anchors(&rego, template, &["F3032"]);
    assert_eq!(anchors, ["Function|Properties.VpcConfig.SubnetIds|89:13"]);
}

#[test]
fn route53_alias_checks_ignore_unrelated_property_scenarios() {
    let template = include_str!("../../resources/templates/bad/E3029_alias_projection_covering.yaml");
    let (rego, cel) = engines();
    let rego_findings = selected_findings_with_spans(&rego, template, &["E3029"]);
    let cel_findings = selected_findings_with_spans(&cel, template, &["E3029"]);

    assert_eq!(rego_findings, cel_findings, "Route53 alias diagnostics must be identical, spans included");
    assert_eq!(rego_findings.len(), 2, "both independent alias constraints must be reported: {rego_findings:?}");
    assert!(rego_findings.iter().any(|finding| finding.contains("TTL must not be set when AliasTarget is specified")));
    assert!(rego_findings.iter().any(|finding| finding.contains("record type 'NS'")));
}

#[test]
fn route53_record_checks_expand_members_independently() {
    let template = include_str!("../../resources/templates/bad/E3023_record_value_projection_covering.yaml");
    let (rego, cel) = engines();
    let rego_findings = selected_findings_with_spans(&rego, template, &["E3023"]);
    let cel_findings = selected_findings_with_spans(&cel, template, &["E3023"]);

    assert_eq!(rego_findings, cel_findings, "Route53 record diagnostics must be identical, spans included");
    assert_eq!(rego_findings.len(), 2, "both reachable record defects must be reported: {rego_findings:?}");
    assert!(rego_findings.iter().any(|finding| {
        finding.contains("|CnameCountRecord|Properties.ResourceRecords|")
            && finding.contains("at most 1 ResourceRecord")
    }));
    assert!(rego_findings.iter().any(|finding| {
        finding.contains("|AddressRecord|Properties.ResourceRecords.1|") && finding.contains("not a valid IPv4 address")
    }));
}

#[test]
fn route53_cname_record_count_reports_each_invalid_branch() {
    let template = include_str!("../../resources/templates/bad/E3023_cname_conditional_record_counts.yaml");
    let (rego, cel) = engines();
    let rego_findings = selected_findings_with_spans(&rego, template, &["E3023"]);
    let cel_findings = selected_findings_with_spans(&cel, template, &["E3023"]);

    assert_eq!(rego_findings, cel_findings, "conditional CNAME count diagnostics must match, spans included");
    assert_eq!(
        rego_findings.len(),
        3,
        "each invalid authored property location must be reported once: {rego_findings:?}"
    );
    assert_eq!(rego_findings.iter().filter(|finding| finding.contains("|ConditionalList|")).count(), 1);
    assert_eq!(rego_findings.iter().filter(|finding| finding.contains("|ConditionalProperties|")).count(), 2);
    assert!(rego_findings.iter().all(|finding| !finding.contains("|SingleRecordBranches|")));
}

#[test]
fn route53_recordset_group_checks_expand_members_independently() {
    let template = include_str!("../../resources/templates/bad/E3023_recordsetgroup_projection_covering.yaml");
    let (rego, cel) = engines();
    let rego_findings = selected_findings_with_spans(&rego, template, &["E3023"]);
    let cel_findings = selected_findings_with_spans(&cel, template, &["E3023"]);

    assert_eq!(rego_findings, cel_findings, "Route53 group diagnostics must be identical, spans included");
    assert_eq!(rego_findings.len(), 2, "both reachable group record defects must be reported: {rego_findings:?}");
    assert!(rego_findings.iter().any(|finding| {
        finding.contains("|CnameGroup|Properties.RecordSets.0.ResourceRecords|")
            && finding.contains("at most 1 ResourceRecord")
    }));
    assert!(rego_findings.iter().any(|finding| {
        finding.contains("|AddressGroup|Properties.RecordSets.0.ResourceRecords.1|")
            && finding.contains("not a valid IPv4 address")
    }));
}

#[test]
fn sqs_event_source_timeout_reports_every_reachable_defaulted_scenario() {
    let template = include_str!("../../resources/templates/bad/E3505_conditional_service_defaults.yaml");
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3505"]);
    let cel_findings = selected_findings(&cel, template, &["E3505"]);

    assert_eq!(rego_findings, cel_findings, "timeout diagnostics must be identical across engines");
    assert_eq!(rego_findings.len(), 8, "every distinct reachable violation must be reported: {rego_findings:?}");
    for (queue, visibility, timeout) in [
        ("QueueAtOneSecond", 1, 3),
        ("QueueAtOneSecond", 1, 60),
        ("QueueAtServiceDefault", 30, 60),
        ("QueueAtServiceDefault", 30, 90),
        ("QueueWithConditionalTimeout", 10, 60),
        ("QueueWithConditionalProperties", 30, 60),
        ("QueueWithConditionalTransform", 10, 60),
        ("QueueWithNoValue", 30, 60),
    ] {
        let message =
            format!("Queue visibility timeout ({visibility}) is less than Function timeout ({timeout}) seconds");
        assert!(
            rego_findings.iter().any(|finding| finding.contains(queue) && finding.contains(&message)),
            "missing {queue} scenario {visibility} < {timeout}: {rego_findings:?}"
        );
    }
}

#[test]
fn sqs_event_source_timeout_checks_parameters_only_after_override() {
    let template = include_str!("../../resources/templates/good/E3505_unresolved_dynamic_and_covering.yaml");
    let (rego, cel) = engines();
    let rego_unresolved = selected_findings(&rego, template, &["E3505"]);
    let cel_unresolved = selected_findings(&cel, template, &["E3505"]);
    assert_eq!(rego_unresolved, cel_unresolved, "unresolved timeout handling must match across engines");
    assert!(rego_unresolved.is_empty(), "deployment-time parameter values must be skipped: {rego_unresolved:?}");

    let config = ValidateConfig {
        parameter_overrides: [
            ("QueueTimeout".into(), "10".into()),
            ("FunctionTimeout".into(), "60".into()),
            ("FunctionTimeoutWithDefault".into(), "60".into()),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    let rego_overridden = selected_findings_with_config(&rego, template, &["E3505"], config.clone());
    let cel_overridden = selected_findings_with_config(&cel, template, &["E3505"], config);
    assert_eq!(rego_overridden, cel_overridden, "parameter override diagnostics must match across engines");
    assert_eq!(rego_overridden.len(), 3, "each invalid fixed deployment value must be reported: {rego_overridden:?}");
    for queue in ["UnresolvedQueue", "QueueAtOneSecond", "QueueAtTwentySeconds"] {
        assert!(
            rego_overridden.iter().any(|finding| finding.contains(queue)),
            "missing override finding for {queue}: {rego_overridden:?}"
        );
    }
}

#[test]
fn sqs_event_source_timeout_skips_mutually_exclusive_resources() {
    let template = r#"
Parameters:
  Stage:
    Type: String
    AllowedValues: [production, development]
Conditions:
  IsProduction: !Equals [!Ref Stage, production]
  IsDevelopment: !Equals [!Ref Stage, development]
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Condition: IsProduction
    Properties:
      VisibilityTimeout: 10
  Function:
    Type: AWS::Lambda::Function
    Condition: IsDevelopment
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Timeout: 60
      Role: !Sub arn:${AWS::Partition}:iam::${AWS::AccountId}:role/role
      Code: {ZipFile: "def handler(event, context): pass"}
  Mapping:
    Type: AWS::Lambda::EventSourceMapping
    Condition: IsProduction
    Properties:
      FunctionName: !Ref Function
      EventSourceArn: !GetAtt Queue.Arn
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3505"]);
    let cel_findings = selected_findings(&cel, template, &["E3505"]);

    assert_eq!(rego_findings, cel_findings, "resource-condition reachability must match across engines");
    assert!(
        rego_findings.is_empty(),
        "mutually exclusive resources cannot form a timeout violation: {rego_findings:?}"
    );
}

#[test]
fn sqs_event_source_timeout_reports_jointly_reachable_conditioned_resources() {
    let template = r#"
Conditions:
  IsProduction: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Condition: IsProduction
    Properties:
      VisibilityTimeout: 10
  Function:
    Type: AWS::Lambda::Function
    Condition: IsProduction
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Timeout: 60
      Role: !Sub arn:${AWS::Partition}:iam::${AWS::AccountId}:role/role
      Code: {ZipFile: "def handler(event, context): pass"}
  Mapping:
    Type: AWS::Lambda::EventSourceMapping
    Condition: IsProduction
    Properties:
      FunctionName: !Ref Function
      EventSourceArn: !GetAtt Queue.Arn
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3505"]);
    let cel_findings = selected_findings(&cel, template, &["E3505"]);

    assert_eq!(rego_findings, cel_findings, "resource-condition reachability must match across engines");
    assert_eq!(rego_findings.len(), 1, "the coexisting invalid resources must be reported: {rego_findings:?}");
    assert!(rego_findings[0].contains("|Queue|Properties.VisibilityTimeout|"));
}

#[test]
fn sqs_event_source_timeout_skips_only_macro_owned_scenarios() {
    let template = r#"
Parameters:
  Stage:
    Type: String
Conditions:
  IsProduction: !Equals [!Ref Stage, production]
Resources:
  CoveringQueue:
    Type: AWS::SQS::Queue
    Properties: !If
      - IsProduction
      - DelaySeconds: 0
        Fn::Transform:
          Name: AWS::Include
          Parameters: {Location: s3://example-bucket/queue-properties.yaml}
      - VisibilityTimeout: 900
  InvalidQueue:
    Type: AWS::SQS::Queue
    Properties: !If
      - IsProduction
      - DelaySeconds: 0
        Fn::Transform:
          Name: AWS::Include
          Parameters: {Location: s3://example-bucket/queue-properties.yaml}
      - VisibilityTimeout: 10
  ResourceMacroQueue:
    Type: AWS::SQS::Queue
    Fn::Transform:
      Name: AWS::Include
      Parameters: {Location: s3://example-bucket/queue-resource.yaml}
  SiblingMacroQueue:
    Type: AWS::SQS::Queue
    Properties:
      DelaySeconds: 0
      Fn::Transform:
        Name: AWS::Include
        Parameters: {Location: s3://example-bucket/queue-properties.yaml}
  MappingMacroQueue:
    Type: AWS::SQS::Queue
    Properties:
      VisibilityTimeout: 10
  QueueAtOneSecond:
    Type: AWS::SQS::Queue
    Properties:
      VisibilityTimeout: 1
  FunctionAtSixtySeconds:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Timeout: 60
      Role: !Sub arn:${AWS::Partition}:iam::${AWS::AccountId}:role/role
      Code: {ZipFile: "def handler(event, context): pass"}
  ResourceMacroFunction:
    Type: AWS::Lambda::Function
    Fn::Transform:
      Name: AWS::Include
      Parameters: {Location: s3://example-bucket/function-resource.yaml}
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Timeout: 60
      Role: !Sub arn:${AWS::Partition}:iam::${AWS::AccountId}:role/role
      Code: {ZipFile: "def handler(event, context): pass"}
  ConditionalMacroFunction:
    Type: AWS::Lambda::Function
    Properties: !If
      - IsProduction
      - Fn::Transform:
          Name: AWS::Include
          Parameters: {Location: s3://example-bucket/function-properties.yaml}
      - Runtime: python3.12
        Handler: index.handler
        Timeout: 1
        Role: !Sub arn:${AWS::Partition}:iam::${AWS::AccountId}:role/role
        Code: {ZipFile: "def handler(event, context): pass"}
  CoveringMapping:
    Type: AWS::Lambda::EventSourceMapping
    Properties:
      FunctionName: !Ref FunctionAtSixtySeconds
      EventSourceArn: !GetAtt CoveringQueue.Arn
  InvalidMapping:
    Type: AWS::Lambda::EventSourceMapping
    Properties:
      FunctionName: !Ref FunctionAtSixtySeconds
      EventSourceArn: !GetAtt InvalidQueue.Arn
  ResourceMacroMapping:
    Type: AWS::Lambda::EventSourceMapping
    Properties:
      FunctionName: !Ref FunctionAtSixtySeconds
      EventSourceArn: !GetAtt ResourceMacroQueue.Arn
  SiblingMacroQueueMapping:
    Type: AWS::Lambda::EventSourceMapping
    Properties:
      FunctionName: !Ref FunctionAtSixtySeconds
      EventSourceArn: !GetAtt SiblingMacroQueue.Arn
  FunctionMacroMapping:
    Type: AWS::Lambda::EventSourceMapping
    Properties:
      FunctionName: !Ref ConditionalMacroFunction
      EventSourceArn: !GetAtt QueueAtOneSecond.Arn
  ResourceMacroFunctionMapping:
    Type: AWS::Lambda::EventSourceMapping
    Properties:
      FunctionName: !Ref ResourceMacroFunction
      EventSourceArn: !GetAtt QueueAtOneSecond.Arn
  ResourceMacroOwnedMapping:
    Type: AWS::Lambda::EventSourceMapping
    Fn::Transform:
      Name: AWS::Include
      Parameters: {Location: s3://example-bucket/mapping-resource.yaml}
    Properties:
      FunctionName: !Ref FunctionAtSixtySeconds
      EventSourceArn: !GetAtt MappingMacroQueue.Arn
  PropertyMacroOwnedMapping:
    Type: AWS::Lambda::EventSourceMapping
    Properties:
      FunctionName: !Ref FunctionAtSixtySeconds
      EventSourceArn: !GetAtt MappingMacroQueue.Arn
      Fn::Transform:
        Name: AWS::Include
        Parameters: {Location: s3://example-bucket/mapping-properties.yaml}
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3505"]);
    let cel_findings = selected_findings(&cel, template, &["E3505"]);

    assert_eq!(rego_findings, cel_findings, "macro scenario handling must match across engines");
    assert_eq!(rego_findings.len(), 1, "only the known invalid sibling branch must be reported: {rego_findings:?}");
    assert!(rego_findings[0].contains("|InvalidQueue|Properties.VisibilityTimeout|"));
    assert!(rego_findings[0].contains("timeout (10) is less than Function timeout (60)"));
}

#[test]
fn sqs_event_source_timeout_deduplicates_identical_mappings() {
    let template = r#"
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      VisibilityTimeout: 10
  Function:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Timeout: 60
      Role: !Sub arn:${AWS::Partition}:iam::${AWS::AccountId}:role/role
      Code: {ZipFile: "def handler(event, context): pass"}
  FirstMapping:
    Type: AWS::Lambda::EventSourceMapping
    Properties:
      FunctionName: !Ref Function
      EventSourceArn: !GetAtt Queue.Arn
  DuplicateMapping:
    Type: AWS::Lambda::EventSourceMapping
    Properties:
      FunctionName: !GetAtt Function.Arn
      EventSourceArn: !GetAtt Queue.Arn
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3505"]);
    let cel_findings = selected_findings(&cel, template, &["E3505"]);

    assert_eq!(rego_findings, cel_findings, "duplicate handling must match across engines");
    assert_eq!(rego_findings.len(), 1, "identical mappings must produce one timeout finding: {rego_findings:?}");
    assert!(rego_findings[0].contains("|Queue|Properties.VisibilityTimeout|"));
}

#[test]
fn sqs_event_source_timeout_parameter_override_selects_reachable_branch() {
    let template = r#"
Parameters:
  Stage:
    Type: String
    AllowedValues: [production, development]
Conditions:
  IsProduction: !Equals [!Ref Stage, production]
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      VisibilityTimeout: !If [IsProduction, 10, 900]
  Function:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Timeout: 60
      Role: !Sub arn:${AWS::Partition}:iam::${AWS::AccountId}:role/role
      Code: {ZipFile: "def handler(event, context): pass"}
  Mapping:
    Type: AWS::Lambda::EventSourceMapping
    Properties:
      FunctionName: !Ref Function
      EventSourceArn: !GetAtt Queue.Arn
"#;
    let production_config = ValidateConfig {
        parameter_overrides: [("Stage".into(), "production".into())].into_iter().collect(),
        ..Default::default()
    };
    let development_config = ValidateConfig {
        parameter_overrides: [("Stage".into(), "development".into())].into_iter().collect(),
        ..Default::default()
    };
    let (rego, cel) = engines();
    let rego_production = selected_findings_with_config(&rego, template, &["E3505"], production_config.clone());
    let cel_production = selected_findings_with_config(&cel, template, &["E3505"], production_config);
    let rego_development = selected_findings_with_config(&rego, template, &["E3505"], development_config.clone());
    let cel_development = selected_findings_with_config(&cel, template, &["E3505"], development_config);

    assert_eq!(rego_production, cel_production, "production override diagnostics must match across engines");
    assert_eq!(rego_production.len(), 1, "the production branch violates the function timeout");
    assert_eq!(rego_development, cel_development, "development override diagnostics must match across engines");
    assert!(rego_development.is_empty(), "the development branch covers the function timeout");
}

#[test]
fn sqs_event_source_timeout_keeps_ssm_parameter_conditions_unresolved() {
    let template = r#"
Parameters:
  Stage:
    Type: AWS::SSM::Parameter::Value<String>
    Default: /application/stage
Conditions:
  IsProduction: !Equals [!Ref Stage, production]
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      VisibilityTimeout: !If [IsProduction, 10, 900]
  Function:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Timeout: 60
      Role: !Sub arn:${AWS::Partition}:iam::${AWS::AccountId}:role/role
      Code: {ZipFile: "def handler(event, context): pass"}
  Mapping:
    Type: AWS::Lambda::EventSourceMapping
    Properties:
      FunctionName: !Ref Function
      EventSourceArn: !GetAtt Queue.Arn
"#;
    let config = ValidateConfig {
        parameter_overrides: [("Stage".into(), "/application/stage".into())].into_iter().collect(),
        ..Default::default()
    };
    let (rego, cel) = engines();
    let rego_findings = selected_findings_with_config(&rego, template, &["E3505"], config.clone());
    let cel_findings = selected_findings_with_config(&cel, template, &["E3505"], config);

    assert_eq!(rego_findings, cel_findings, "SSM-backed condition handling must match across engines");
    assert_eq!(
        rego_findings.len(),
        1,
        "the override is a lookup name, so the production branch remains reachable: {rego_findings:?}"
    );
}
#[test]
fn conditional_nested_required_properties_are_checked_per_reachable_scenario() {
    let template = include_str!("../../resources/templates/bad/F3003_conditional_nested_required.yaml");
    let (rego, cel) = engines();
    let rego_findings = selected_finding_anchors(&rego, template, &["F3003"]);
    let cel_findings = selected_finding_anchors(&cel, template, &["F3003"]);

    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 4, "every missing nested child must be reported: {rego_findings:?}");
    assert!(rego_findings.iter().any(|finding| finding.starts_with("ConditionalObject|Properties.EphemeralStorage|")));
    assert!(rego_findings.iter().any(|finding| finding.starts_with("ConditionalChild|Properties.EphemeralStorage|")));
    assert!(
        rego_findings.iter().any(|finding| finding.starts_with("UnconditionalNoValue|Properties.EphemeralStorage|"))
    );
    assert!(
        rego_findings
            .iter()
            .any(|finding| { finding.starts_with("ConditionalChildNoValueTrue|Properties.EphemeralStorage|") })
    );
    assert!(rego_findings.iter().all(|finding| !finding.starts_with("OptionalObjectControl|")));
}

#[test]
fn ordinary_parameter_defaults_warn_without_fatal_schema_contradictions() {
    let template = include_str!("../../resources/templates/bad/W1030_parameter_default_constraints.yaml");
    let rule_ids = ["W1030", "W1032", "W1035", "W3030", "F3030", "F3031", "F3033", "F3034"];
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &rule_ids);
    let cel_findings = selected_findings(&cel, template, &rule_ids);

    assert_eq!(rego_findings, cel_findings);
    assert_eq!(
        rego_findings.len(),
        19,
        "each invalid candidate or composed output must be reported: {rego_findings:?}"
    );
    assert_eq!(rego_findings.iter().filter(|finding| finding.starts_with("W1030|")).count(), 16);
    assert_eq!(rego_findings.iter().filter(|finding| finding.starts_with("W1032|")).count(), 1);
    assert_eq!(rego_findings.iter().filter(|finding| finding.starts_with("W1035|")).count(), 2);
    assert_eq!(
        selected_finding_anchors(&rego, template, &["W1035"]),
        ["|Parameters/InvalidRetentionDays/Default|20:40", "|Parameters/Timeout/Default|12:27",]
    );
    for path in [
        "Parameters/BadPattern/Default",
        "Properties.FunctionName",
        "Properties.Description",
        "Parameters/BadPackageType/Default",
        "Parameters/Timeout/Default",
        "Parameters/SmallStorage/Default",
        "Properties.Tags.0.Key",
        "Parameters/AllowedPackage/AllowedValues/1",
        "Parameters/AllowedArchitecture/AllowedValues/1",
    ] {
        assert!(rego_findings.iter().any(|finding| finding.contains(path)));
    }
}

#[test]
fn parameter_override_replaces_an_invalid_default_for_destination_constraints() {
    let template = include_str!("../../resources/templates/bad/W1030_parameter_default_constraints.yaml");
    let config = ValidateConfig {
        parameter_overrides: [("BadPattern".to_string(), "valid-name".to_string())].into(),
        ..ValidateConfig::default()
    };
    let (rego, cel) = engines();
    let rule_ids = ["W1030", "W1032", "W1035"];
    let rego_findings = selected_findings_with_config(&rego, template, &rule_ids, config.clone());
    let cel_findings = selected_findings_with_config(&cel, template, &rule_ids, config);

    assert_eq!(rego_findings, cel_findings);
    assert!(rego_findings.iter().all(|finding| !finding.contains("BadPattern")));
    assert_eq!(
        rego_findings.len(),
        17,
        "only both overridden-default consumer warnings must disappear: {rego_findings:?}"
    );
}

#[test]
fn composed_parameter_values_use_their_intrinsic_rule_ids() {
    let template = r#"
Parameters:
  Name: {Type: String, Default: 'bad name'}
  Retention: {Type: Number, Default: 1024}
  OtherRetention: {Type: Number, Default: 7}
  Environment: {Type: String, AllowedValues: [development], Default: development}
Mappings:
  PackageTypes:
    development: {Value: Jar}
Resources:
  Substituted:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub '${Name}-bucket'
  Joined:
    Type: AWS::Lambda::Function
    Properties:
      PackageType: !Join ['', [!Ref Name]]
      Role: !Sub arn:${AWS::Partition}:iam::${AWS::AccountId}:role/example
      Runtime: python3.12
      Handler: index.handler
      Code: {ZipFile: x}
  NestedSubJoined:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Join ['', [!Sub '${Name}', '-bucket']]
  NestedSelectJoined:
    Type: AWS::Lambda::Function
    Properties:
      PackageType: !Join ['', [!Select [0, [!Ref Name]]]]
      Role: !Sub arn:${AWS::Partition}:iam::${AWS::AccountId}:role/example
      Runtime: python3.12
      Handler: index.handler
      Code: {ZipFile: x}
  Mapped:
    Type: AWS::Lambda::Function
    Properties:
      PackageType: !FindInMap [PackageTypes, !Ref Environment, Value]
      Role: !Sub arn:${AWS::Partition}:iam::${AWS::AccountId}:role/example
      Runtime: python3.12
      Handler: index.handler
      Code: {ZipFile: x}
  Selected:
    Type: AWS::Logs::LogGroup
    Properties:
      RetentionInDays: !Select [0, [!Select [0, [!Ref Retention]], 7]]
  SelectedSecondParameter:
    Type: AWS::Logs::LogGroup
    Properties:
      RetentionInDays: !Select [1, [!Ref OtherRetention, !Ref Retention]]
"#;
    let rule_ids = ["W1030", "W1031", "W1032", "W1034", "W1035"];
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &rule_ids);
    let cel_findings = selected_findings(&cel, template, &rule_ids);

    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 7, "each composed value must use its outer intrinsic rule: {rego_findings:?}");
    assert_eq!(rego_findings.iter().filter(|finding| finding.starts_with("W1031|")).count(), 1);
    assert_eq!(rego_findings.iter().filter(|finding| finding.starts_with("W1032|")).count(), 3);
    assert_eq!(rego_findings.iter().filter(|finding| finding.starts_with("W1034|")).count(), 1);
    assert_eq!(rego_findings.iter().filter(|finding| finding.starts_with("W1035|")).count(), 2);
    assert!(
        rego_findings
            .iter()
            .filter(|finding| finding.starts_with("W1035|"))
            .all(|finding| finding.contains("|Parameters/Retention/Default|"))
    );
    assert!(rego_findings.iter().all(|finding| !finding.starts_with("W1030|")));
}

#[test]
fn composed_parameter_checks_stay_with_their_conditional_branch() {
    let template = r#"
Parameters:
  Environment: {Type: String, AllowedValues: [development, production], Default: development}
  ValidPackage: {Type: String, Default: Zip}
  InvalidPackage: {Type: String, Default: Jar}
Conditions:
  Production: !Equals [!Ref Environment, production]
Resources:
  LiteralAndSub:
    Type: AWS::Lambda::Function
    Properties:
      PackageType: !If [Production, Jar, !Sub '${ValidPackage}']
      Role: !Sub arn:${AWS::Partition}:iam::${AWS::AccountId}:role/example
      Runtime: python3.12
      Handler: index.handler
      Code: {ZipFile: x}
  DifferentCompositions:
    Type: AWS::Lambda::Function
    Properties:
      PackageType: !If [Production, !Join ['', [!Ref InvalidPackage]], !Sub '${InvalidPackage}']
      Role: !Sub arn:${AWS::Partition}:iam::${AWS::AccountId}:role/example
      Runtime: python3.12
      Handler: index.handler
      Code: {ZipFile: x}
  RefAndComposition:
    Type: AWS::Lambda::Function
    Properties:
      PackageType: !If [Production, !Ref InvalidPackage, !Join ['', [!Ref InvalidPackage]]]
      Role: !Sub arn:${AWS::Partition}:iam::${AWS::AccountId}:role/example
      Runtime: python3.12
      Handler: index.handler
      Code: {ZipFile: x}
"#;
    let rule_ids = ["W1030", "W1031", "W1032"];
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &rule_ids);
    let cel_findings = selected_findings(&cel, template, &rule_ids);

    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 4, "only parameter-dependent invalid branches must warn: {rego_findings:?}");
    assert!(rego_findings.iter().all(|finding| !finding.contains("|LiteralAndSub|")));
    assert_eq!(rego_findings.iter().filter(|finding| finding.contains("|DifferentCompositions|")).count(), 2);
    assert!(rego_findings.iter().any(|finding| finding.starts_with("W1031|")));
    assert_eq!(rego_findings.iter().filter(|finding| finding.starts_with("W1032|")).count(), 2);
    assert!(rego_findings.iter().any(|finding| finding.starts_with("W1030|")));
}

#[test]
fn composed_ssm_parameter_paths_remain_deployment_time_values() {
    let template = r#"
Parameters:
  Prefix:
    Type: AWS::SSM::Parameter::Value<String>
    Default: /organization/application/bucket-prefix
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub '${Prefix}-data'
"#;
    let rule_ids = ["W1030", "W1031", "F3031"];
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &rule_ids);
    let cel_findings = selected_findings(&cel, template, &rule_ids);

    assert_eq!(rego_findings, cel_findings);
    assert!(rego_findings.is_empty(), "an SSM path is not the deployment-time parameter value: {rego_findings:?}");
}

#[test]
fn specialized_parameter_checks_preserve_independent_schema_constraints() {
    let template = r#"
Parameters:
  Value:
    Type: String
    Default: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Resources:
  LaunchConfiguration:
    Type: AWS::AutoScaling::LaunchConfiguration
    Properties:
      ImageId: !Ref Value
      InstanceType: t3.micro
  Endpoint:
    Type: AWS::S3Outposts::Endpoint
    Properties:
      OutpostId: op-01234567890123456
      SecurityGroupId: sg-01234567890123456
      SubnetId: subnet-01234567890123456
      CidrBlock: !Ref Value
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["W1030"]);
    let cel_findings = selected_findings(&cel, template, &["W1030"]);

    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 4, "format and maximum-length violations must both be reported: {rego_findings:?}");
    assert!(rego_findings.iter().any(|finding| finding.contains("above maximum 255")));
    assert!(rego_findings.iter().any(|finding| finding.contains("above maximum 20")));
    assert!(rego_findings.iter().any(|finding| finding.contains("AWS::EC2::Image.Id")));
    assert!(rego_findings.iter().any(|finding| finding.contains("ipv4-network")));
}

#[test]
fn duplicate_tag_keys_are_reported_independently_of_values() {
    let template = include_str!("../../resources/templates/bad/E3024_duplicate_tag_keys.yaml");
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["E3024"]);
    let cel_findings = selected_findings(&cel, template, &["E3024"]);

    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 9, "duplicate and conditionally missing keys must all be reported");
    for resource in [
        "DifferentValues",
        "EqualValues",
        "ConditionalValues",
        "ConditionalKey",
        "SameParameterKey",
        "ConditionalTagList",
        "SameGetAttKey",
    ] {
        assert!(rego_findings.iter().any(|finding| finding.contains(&format!("|{resource}|Properties.Tags|"))));
    }
    assert_eq!(
        rego_findings.iter().filter(|finding| finding.contains("|ConditionalMissingKeys|Properties.Tags.")).count(),
        2
    );
    for resource in [
        "DistinctKeys",
        "MutuallyExclusiveTags",
        "CustomResourceControl",
        "ParameterAndLiteralControl",
        "DifferentParametersControl",
        "PseudoAndLiteralControl",
        "DifferentGetAttTargetsControl",
    ] {
        assert!(rego_findings.iter().all(|finding| !finding.contains(&format!("|{resource}|"))));
    }
}

#[test]
fn whole_properties_nested_unreachable_branches_keep_authored_paths_and_spans() {
    let template = include_str!("../../resources/templates/bad/W1028_whole_properties_nested_branch.yaml");
    let (rego, cel) = engines();
    let expected = [
        "Bucket|Properties.Fn::If.1.BucketName.Fn::If.2|12:57".to_string(),
        "Bucket|Properties.Fn::If.2.BucketName.Fn::If.1|13:38".to_string(),
    ];
    let rego_findings = selected_finding_anchors(&rego, template, &["W1028"]);
    let cel_findings = selected_finding_anchors(&cel, template, &["W1028"]);

    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings, expected);
}

#[test]
fn scenario_product_covering_is_reported_as_incomplete_analysis() {
    let template = include_str!("../../resources/templates/bad/W9052_scenario_product_covering.yaml");
    let validator = SchemaValidator::default();
    let (rego, cel) = engines();
    let rego_report = validate_bytes(&rego, &validator, template.as_bytes(), ValidateConfig::default()).unwrap();
    let cel_report = validate_bytes(&cel, &validator, template.as_bytes(), ValidateConfig::default()).unwrap();

    assert_eq!(rego_report.status, ReportStatus::AnalysisIncomplete);
    assert_eq!(cel_report.status, ReportStatus::AnalysisIncomplete);
    let rego_warning = rego_report.diagnostics.iter().filter(|diagnostic| diagnostic.rule_id == "W9052").count();
    let cel_warning = cel_report.diagnostics.iter().filter(|diagnostic| diagnostic.rule_id == "W9052").count();
    assert_eq!(rego_warning, 1);
    assert_eq!(cel_warning, 1);
    let exhaustions = rego_report.metadata.budget_exhaustions.expect("covering metadata must be present");
    assert!(exhaustions.iter().any(|record| record.kind == "scenarioProductCovering" && record.analysis_incomplete));
}

#[test]
fn parameter_default_fragments_are_not_checked_as_whole_property_values() {
    let template = r#"
Parameters:
  Prefix: {Type: String, Default: ''}
  Suffix: {Type: String, Default: suffix}
Resources:
  Joined:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Join ['', [!Ref Prefix, function]]
      Runtime: python3.12
      Handler: index.handler
      Role: arn:aws:iam::123456789012:role/example
      Code: {ZipFile: x}
  Substituted:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub '${Prefix}function'
      Runtime: python3.12
      Handler: index.handler
      Role: arn:aws:iam::123456789012:role/example
      Code: {ZipFile: x}
  Selected:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Join ['-', [function, !Select [0, [!Ref Suffix]]]]
      Runtime: python3.12
      Handler: index.handler
      Role: arn:aws:iam::123456789012:role/example
      Code: {ZipFile: x}
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["W1030"]);
    let cel_findings = selected_findings(&cel, template, &["W1030"]);

    assert_eq!(rego_findings, cel_findings);
    assert!(rego_findings.is_empty(), "a parameter fragment is not the destination property value");
}

#[test]
fn whole_properties_mapping_branch_unreachable_span_uses_first_authored_key() {
    let template = include_str!("../../resources/templates/good/W2530_snapstart_unreachable_or_published.yaml");
    let (rego, cel) = engines();
    let rego_anchors = selected_finding_anchors(&rego, template, &["W1028"]);
    let cel_anchors = selected_finding_anchors(&cel, template, &["W1028"]);

    assert_eq!(rego_anchors, cel_anchors);
    assert!(
        rego_anchors
            .iter()
            .any(|anchor| { anchor == "PropertiesBranchExcludedByResourceCondition|Properties.Fn::If.2|19:9" }),
        "the unreachable mapping branch must anchor at its first authored property: {rego_anchors:?}"
    );
}

#[test]
fn aws_no_value_does_not_defer_a_container_type_violation() {
    let template = include_str!("../../resources/templates/bad/F3012_novalue_container_type.yaml");
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["F3012"]);
    let cel_findings = selected_findings(&cel, template, &["F3012"]);

    assert_eq!(rego_findings, cel_findings);
    assert_eq!(rego_findings.len(), 1, "the surviving list remains the wrong type: {rego_findings:?}");
    assert!(rego_findings[0].contains("|Function|Properties.MemorySize|"));
}

#[test]
fn non_object_intrinsic_items_do_not_emit_nested_required_findings() {
    let template = r#"
Resources:
  SplitIngress:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: example
      SecurityGroupIngress: !Split [',', 'first,second']
  AvailabilityZoneIngress:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: example
      SecurityGroupIngress: !GetAZs ''
"#;
    let (rego, cel) = engines();
    let rego_findings = selected_findings(&rego, template, &["F3003"]);
    let cel_findings = selected_findings(&cel, template, &["F3003"]);

    assert_eq!(rego_findings, cel_findings);
    assert!(rego_findings.is_empty(), "required object members do not apply to scalar list items");
}
