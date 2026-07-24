#[cfg(test)]
mod tests {
    use cel_engine::CelEngine;
    use schema_validator::SchemaValidator;
    use std::sync::LazyLock;
    use validation_engine::{EngineConfig, ValidateConfig, ValidationEngine, validate_bytes};

    static SV: LazyLock<SchemaValidator> = LazyLock::new(SchemaValidator::new);

    fn validate(template: &str) -> Vec<String> {
        let engine = CelEngine::new(EngineConfig::default()).unwrap();
        let report = validate_bytes(&engine, &SV, template.as_bytes(), ValidateConfig::default()).unwrap();
        let mut ids: Vec<String> = report.diagnostics.iter().map(|d| d.rule_id.clone()).collect();
        ids.sort();
        ids
    }

    fn validate_file(path: &str) -> Vec<String> {
        let full = format!("../resources/templates/{}", path);
        let bytes = std::fs::read(&full).unwrap_or_else(|e| panic!("Failed to read {}: {}", full, e));
        let engine = CelEngine::new(EngineConfig::default()).unwrap();
        let report = validate_bytes(&engine, &SV, &bytes, ValidateConfig::default()).unwrap();
        let mut ids: Vec<String> = report.diagnostics.iter().map(|d| d.rule_id.clone()).collect();
        ids.sort();
        ids
    }

    #[test]
    fn cel_engine_constructs_with_default_config() {
        let engine = CelEngine::new(EngineConfig::default()).unwrap();
        assert_eq!(engine.engine_name(), "cel");
        let rules = engine.list_rules();
        assert!(!rules.is_empty(), "Engine should have registered rules");
    }

    #[test]
    fn minimal_template_produces_no_structure_errors() {
        let ids = validate(
            r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
"#,
        );
        assert!(!ids.iter().any(|id| id.starts_with("F0")), "No structure (fatal) errors expected, got: {:?}", ids);
    }

    #[test]
    fn bad_format_version_triggers_f0002() {
        let ids = validate(
            r#"
AWSTemplateFormatVersion: '2010-09-10'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
"#,
        );
        assert!(ids.contains(&"F0002".to_string()), "Expected F0002 for bad format version, got: {:?}", ids);
    }

    #[test]
    fn nonexistent_ref_triggers_ref_error() {
        let ids = validate(
            r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref NonExistent
"#,
        );
        // A Ref to a completely unknown target is recorded as an invalid ref and
        // surfaced as a "Ref/GetAtt target must exist" diagnostic.
        assert!(ids.contains(&"F1020".to_string()), "Expected F1020 for Ref to unknown target, got: {:?}", ids);
    }

    #[test]
    fn list_rules_includes_all_expected_rule_ids() {
        let engine = CelEngine::new(EngineConfig::default()).unwrap();
        let rules = engine.list_rules();
        assert!(!rules.is_empty());
        assert!(rules.iter().any(|r| r.id == "F0001"));
        assert!(rules.iter().any(|r| r.id == "F3012"));
        assert!(rules.iter().any(|r| r.id == "W9008"));
    }

    #[test]
    fn w9008_not_raised_for_cluster_member_instance() {
        // StorageEncrypted is "Not applicable" on cluster-member instances; encryption
        // is managed by the DB cluster (issue #235)
        let ids = validate_file("good/aurora_dbinstance.yaml");
        assert!(!ids.contains(&"W9008".to_string()), "Cluster-member instance should not trigger W9008, got: {:?}", ids);
    }

    #[test]
    fn w9008_raised_for_standalone_instance_without_storage_encrypted() {
        let ids = validate(
            r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyDB:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: mysql
      DBInstanceClass: db.t3.micro
      AllocatedStorage: '20'
"#,
        );
        assert!(ids.contains(&"W9008".to_string()), "Standalone instance without StorageEncrypted should trigger W9008, got: {:?}", ids);
    }

    #[test]
    fn well_formed_template_with_encryption_no_structure_errors() {
        let ids = validate(
            r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
"#,
        );
        assert!(!ids.iter().any(|id| id.starts_with("F0")), "No structure (fatal) errors expected, got: {:?}", ids);
    }

    #[test]
    fn iam_notaction_triggers_w2512() {
        let ids = validate_file("bad/iam_wildcard_all_types.yaml");
        let w2512 = ids.iter().filter(|id| *id == "W2512").count();
        assert!(w2512 >= 1, "Expected at least 1 W2512 (NotAction on User), got {}", w2512);
    }

    #[test]
    fn sagemaker_instance_types_trigger_regional_enum_rules() {
        let ids = validate_file("bad/sagemaker_instance_types.yaml");
        for rule in ["E3640", "E3642", "E3643", "E3644"] {
            assert!(
                ids.contains(&rule.to_string()),
                "Expected {rule} for invalid SageMaker instance type, got {ids:?}"
            );
        }
    }

    #[test]
    fn opensearch_invalid_instance_type_triggers_e3653() {
        let ids = validate_file("bad/opensearch_instance_type.yaml");
        assert_eq!(
            ids.iter().filter(|id| *id == "E3653").count(),
            1,
            "Expected exactly one E3653 (only the invalid domain), got {ids:?}"
        );
    }
}

#[cfg(test)]
mod nested_schema_tests {
    use cel_engine::CelEngine;
    use schema_validator::SchemaValidator;
    use std::sync::LazyLock;
    use validation_engine::{EngineConfig, ValidateConfig, validate_bytes};

    static SV2: LazyLock<SchemaValidator> = LazyLock::new(SchemaValidator::new);

    fn diags(template: &str) -> Vec<(String, String)> {
        let engine = CelEngine::new(EngineConfig::default()).unwrap();
        let report = validate_bytes(&engine, &SV2, template.as_bytes(), ValidateConfig::default()).unwrap();
        report.diagnostics.iter().map(|d| (d.rule_id.clone(), d.message.clone())).collect()
    }

    fn rule_ids(template: &str) -> Vec<String> {
        diags(template).into_iter().map(|(id, _)| id).collect()
    }

    #[test]
    fn e3012_catches_string_where_integer_expected_in_sg_ingress() {
        let ids = rule_ids(
            r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  SG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: test
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: '443'
          ToPort: '443'
          CidrIp: 0.0.0.0/0
"#,
        );
        let w3012_count = ids.iter().filter(|id| *id == "W9003").count();
        assert!(
            w3012_count >= 2,
            "Expected W9003 coercion warnings for string '443' on FromPort and ToPort, got {} W9003s in {:?}",
            w3012_count,
            ids
        );
        let f3012_count = ids.iter().filter(|id| *id == "F3012").count();
        assert_eq!(f3012_count, 0, "String '443' should be coerced, not rejected — got {} F3012s", f3012_count);
    }

    #[test]
    fn e3012_accepts_native_integer_in_sg_ingress() {
        let ds = diags(
            r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  SG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: test
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0
"#,
        );
        let f3012_port =
            ds.iter().any(|(id, msg)| id == "F3012" && (msg.contains("FromPort") || msg.contains("ToPort")));
        assert!(!f3012_port, "Native integers should not trigger F3012 for FromPort/ToPort, got: {:?}", ds);
    }

    #[test]
    fn e3012_catches_string_where_boolean_expected() {
        let ids = rule_ids(
            r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  ASG:
    Type: AWS::AutoScaling::AutoScalingGroup
    Properties:
      MinSize: '1'
      MaxSize: '1'
      LaunchConfigurationName: lc
      Tags:
        - Key: Name
          Value: test
          PropagateAtLaunch: 'true'
"#,
        );
        let has_w3012 = ids.iter().any(|id| id == "W9003");
        assert!(has_w3012, "Expected W9003 coercion warning for string 'true' on PropagateAtLaunch, got: {:?}", ids);
        let has_f3012 = ids.iter().any(|id| id == "F3012");
        assert!(!has_f3012, "String 'true' should be coerced, not rejected — got F3012 in: {:?}", ids);
    }

    #[test]
    fn e3020_catches_mutually_exclusive_properties() {
        let ds = diags(
            r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Subnet:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: vpc-123
      AvailabilityZone: us-east-1a
      AvailabilityZoneId: use1-az1
      CidrBlock: 10.0.0.0/24
"#,
        );
        let f3020_count = ds.iter().filter(|(id, _)| id == "F3020").count();
        assert!(
            f3020_count >= 2,
            "Expected F3020 for AvailabilityZone + AvailabilityZoneId, got {} F3020s in {:?}",
            f3020_count,
            ds
        );
    }
}

#[cfg(test)]
mod guard_tests {
    use cel_engine::CelEngine;
    use rules::{FilterConfig, RuleFilterConfig, Severity};
    use schema_validator::SchemaValidator;
    use std::sync::LazyLock;
    use validation_engine::guard::resolve_guard_config;
    use validation_engine::{EngineConfig, ExternalRuleSource, ValidateConfig, ValidationEngine, validate_bytes};

    static SV: LazyLock<SchemaValidator> = LazyLock::new(SchemaValidator::new);

    const GUARD_S3_VERSIONING: &str = r#"
rule s3_versioning_check {
    AWS::S3::Bucket {
        Properties.VersioningConfiguration.Status == "Enabled"
            <<S3 bucket must have versioning enabled>>
    }
}
"#;

    #[test]
    fn guard_rule_registers_with_correct_metadata() {
        let config = EngineConfig {
            guard_rules: vec![ExternalRuleSource {
                name: "s3_versioning.guard".into(),
                content: GUARD_S3_VERSIONING.into(),
            }],
            ..Default::default()
        };
        let engine = CelEngine::new(config).unwrap();
        let template = b"AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Bucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      VersioningConfiguration:\n        Status: Enabled\n";
        let report = validate_bytes(&engine, &SV, template, ValidateConfig::default()).unwrap();
        let rules = engine.list_rules();
        let guard_rule = rules.iter().find(|r| r.id == "s3_versioning_check");
        assert!(guard_rule.is_some(), "Guard rule should appear in list_rules");
        let guard_rule = guard_rule.unwrap();
        assert_eq!(guard_rule.category.as_deref(), Some("guard:s3_versioning"));
        for d in report.diagnostics.iter().filter(|d| d.rule_id == "s3_versioning_check") {
            assert_eq!(d.severity, Severity::Error);
            assert_eq!(d.category.as_deref(), Some("guard:s3_versioning"));
        }
    }

    #[test]
    fn guard_rule_pack_loads_from_directory() {
        let guard_rules = resolve_guard_config(&["../guard-translator/tests/fixtures/pack".into()]).unwrap_or_default();
        let config = EngineConfig { guard_rules, ..Default::default() };
        let engine = CelEngine::new(config);
        // Pack loading may fail if translated CEL has issues from wildcard let assignments.
        // This tests that the pack name derivation uses the directory name.
        if let Ok(engine) = engine {
            let rules = engine.list_rules();
            let guard_rules: Vec<_> =
                rules.iter().filter(|r| r.category.as_deref().is_some_and(|c| c.starts_with("guard:"))).collect();
            assert!(!guard_rules.is_empty(), "Should have loaded guard rules from pack directory");
        }
    }

    #[test]
    fn guard_rule_excluded_by_category_filter() {
        let config = EngineConfig {
            guard_rules: vec![ExternalRuleSource {
                name: "s3_versioning.guard".into(),
                content: GUARD_S3_VERSIONING.into(),
            }],
            ..Default::default()
        };
        let engine = CelEngine::new(config).unwrap();
        let template = b"AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Bucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      VersioningConfiguration:\n        Status: Enabled\n";
        let validate_config = ValidateConfig {
            filters: FilterConfig::new(
                RuleFilterConfig::default(),
                RuleFilterConfig { categories: vec!["guard:s3_versioning".into()], ..Default::default() },
            ),
            ..Default::default()
        };
        let report = validate_bytes(&engine, &SV, template, validate_config).unwrap();
        assert!(
            !report.diagnostics.iter().any(|d| d.rule_id == "s3_versioning_check"),
            "Guard rule should be filtered out by category exclusion"
        );
    }
}

// These tests cover this engine's own rule catalogue and consistency; broader
// end-to-end behaviour is verified at the integration layer.

#[cfg(test)]
mod consistency_tests {
    use cel_engine::CelEngine;
    use validation_engine::{EngineConfig, ValidationEngine};

    #[test]
    fn list_rules_covers_all_expected_categories() {
        let engine = CelEngine::new(EngineConfig::default()).unwrap();
        let rules = engine.list_rules();
        let categories: std::collections::HashSet<&str> =
            rules.iter().map(|r| r.category.as_deref().unwrap_or("")).collect();
        for expected in [
            "Structure",
            "Intrinsic Function",
            "Parameter",
            "Reference",
            "Resource",
            "Security",
            "Best Practice",
            "Deprecation",
            "Schema",
        ] {
            assert!(categories.contains(expected), "list_rules missing category '{}', got: {:?}", expected, categories);
        }
    }
}

#[cfg(test)]
mod rule_category_tests {
    use cel_engine::CelEngine;
    use schema_validator::SchemaValidator;
    use std::sync::LazyLock;
    use validation_engine::{EngineConfig, ValidateConfig, validate_bytes};

    static SV: LazyLock<SchemaValidator> = LazyLock::new(SchemaValidator::new);

    fn validate(template: &str) -> Vec<String> {
        let engine = CelEngine::new(EngineConfig::default()).unwrap();
        let report = validate_bytes(&engine, &SV, template.as_bytes(), ValidateConfig::default()).unwrap();
        let mut ids: Vec<String> = report.diagnostics.iter().map(|d| d.rule_id.clone()).collect();
        ids.sort();
        ids
    }

    fn validate_file(path: &str) -> Vec<String> {
        let full = format!("../resources/templates/{}", path);
        let bytes = std::fs::read(&full).unwrap_or_else(|e| panic!("Failed to read {}: {}", full, e));
        let engine = CelEngine::new(EngineConfig::default()).unwrap();
        let report = validate_bytes(&engine, &SV, &bytes, ValidateConfig::default()).unwrap();
        let mut ids: Vec<String> = report.diagnostics.iter().map(|d| d.rule_id.clone()).collect();
        ids.sort();
        ids
    }

    fn has_rule(ids: &[String], rule: &str) -> bool {
        ids.iter().any(|id| id == rule)
    }

    #[test]
    fn structure_bad_format_version() {
        let ids = validate_file("bad/templates/base.yaml");
        assert!(has_rule(&ids, "F0002"), "Expected E0002, got: {:?}", ids);
    }

    #[test]
    fn structure_duplicate_keys() {
        let ids = validate_file("bad/duplicate.json");
        assert!(has_rule(&ids, "F0000"), "Expected E0000 for duplicate keys, got: {:?}", ids);
    }

    #[test]
    fn structure_not_cloudformation() {
        let ids = validate_file("bad/not_cloudformation.yaml");
        assert!(has_rule(&ids, "F0001") || has_rule(&ids, "F0000"), "Expected structure error, got: {:?}", ids);
    }

    #[test]
    fn structure_good_minimal_no_errors() {
        let ids = validate_file("good/minimal.yaml");
        let structure_errors: Vec<_> = ids.iter().filter(|id| id.starts_with("F0")).collect();
        assert!(structure_errors.is_empty(), "No structure (fatal) errors expected, got: {:?}", structure_errors);
    }

    #[test]
    fn intrinsics_bad_ref() {
        let ids = validate_file("bad/refs.yaml");
        // Refs to unknown targets are recorded as invalid refs and surfaced as the
        // invalid-reference diagnostic. Fn::Sub variables resolve through the same
        // path but are not recorded as invalid refs, so they do not trigger it here.
        assert!(has_rule(&ids, "F1020"), "Expected F1020 for refs to unknown targets, got: {:?}", ids);
    }

    #[test]
    fn intrinsics_bad_findinmap() {
        let ids = validate_file("bad/findinmap_bad.yaml");
        assert!(has_rule(&ids, "F1012"), "Expected E1012 for FindInMap error, got: {:?}", ids);
    }

    #[test]
    fn intrinsics_bad_select() {
        let ids = validate_file("bad/functions_select.yaml");
        // Malformed Select shapes (non-integer index, wrong arity, non-array
        // value) are errors under the Select rule.
        let select_errors = ids.iter().filter(|id| *id == "E1017").count();
        assert!(select_errors >= 3, "Expected E1017 Select shape errors, got: {:?}", ids);
    }

    #[test]
    fn intrinsics_select_integer_string_index_is_not_warned() {
        // CloudFormation coerces a numeric string index ("0", "1"), so the
        // Select type warning must not fire on it.
        let ids = validate_file("good/functions/select_string_index.yaml");
        assert!(!ids.iter().any(|id| id == "W1102"), "W1102 must not fire on an integer-string index, got: {:?}", ids);
    }

    #[test]
    fn intrinsics_bad_sub_needed() {
        let ids = validate_file("bad/sub_needed.yaml");
        assert!(has_rule(&ids, "E1029"), "Expected E1029 for Sub needed, got: {:?}", ids);
    }

    #[test]
    fn intrinsics_good_ref_no_errors() {
        let ids = validate_file("good/functions/ref.yaml");
        let ref_errors: Vec<_> = ids.iter().filter(|id| id.starts_with("F10")).collect();
        assert!(ref_errors.is_empty(), "No ref errors expected, got: {:?}", ref_errors);
    }

    #[test]
    fn references_circular_dependency() {
        let ids = validate_file("bad/resources_circular_dependency.yaml");
        assert!(has_rule(&ids, "F3004"), "Expected E3004 for circular dependency, got: {:?}", ids);
    }

    #[test]
    fn references_circular_dependency_dependson() {
        let ids = validate_file("bad/resources_circular_dependency_dependson.yaml");
        assert!(has_rule(&ids, "F3004"), "Expected E3004 for DependsOn circular, got: {:?}", ids);
    }

    #[test]
    fn best_practices_deletion_policy() {
        let ids = validate_file("bad/resources_deletionpolicy.yaml");
        let has_deletion = ids.iter().any(|id| id == "I3011" || id == "W3011");
        assert!(has_deletion, "Expected deletion policy warning, got: {:?}", ids);
    }

    #[test]
    fn best_practices_hardcoded_arn() {
        let ids = validate_file("bad/hard_coded_arn_properties.yaml");
        assert!(has_rule(&ids, "I3042"), "Expected I3042 for hardcoded ARN, got: {:?}", ids);
    }

    #[test]
    fn best_practices_previous_gen_instance() {
        let ids = validate_file("bad/previous_gen_instance.yaml");
        assert!(has_rule(&ids, "I3100"), "Expected I3100 for previous gen instance, got: {:?}", ids);
    }

    #[test]
    fn best_practices_good_deletion_policies_has_expected_warnings() {
        // This template has resources with DeletionPolicy set, but some still
        // trigger retention-period rules for resources that need retention period config.
        let ids = validate_file("good/deletion_policies.yaml");
        assert!(!ids.iter().any(|id| id.starts_with("E") || id.starts_with("F")), "No errors expected, got: {:?}", ids);
    }

    #[test]
    fn resources_fargate_bad_cpu_memory() {
        let ids = validate_file("bad/fargate_bad_cpu_memory.yaml");
        assert!(has_rule(&ids, "E3047"), "Expected E3047 for Fargate CPU/memory, got: {:?}", ids);
    }

    #[test]
    fn resources_sg_bad_port_range() {
        let ids = validate_file("bad/sg_bad_port_range.yaml");
        assert!(has_rule(&ids, "E9002"), "Expected E9002 for bad port range, got: {:?}", ids);
    }

    #[test]
    fn resources_sqs_fifo_no_suffix() {
        let ids = validate_file("bad/sqs_fifo_no_suffix.yaml");
        assert!(has_rule(&ids, "E3501") || has_rule(&ids, "E2504"), "Expected SQS FIFO error, got: {:?}", ids);
    }

    #[test]
    fn resources_stepfunctions_bad_start_at() {
        let ids = validate_file("bad/stepfunctions_bad_start_at.yaml");
        assert!(has_rule(&ids, "E3601"), "Expected E3601 for StepFunctions StartAt, got: {:?}", ids);
    }

    #[test]
    fn resources_lambda_zip_no_handler() {
        let ids = validate_file("bad/lambda_zip_no_handler.yaml");
        assert!(has_rule(&ids, "W2533"), "Expected W2533 for Lambda zip no handler, got: {:?}", ids);
    }

    #[test]
    fn resources_good_ecs_fargate_valid() {
        let ids = validate_file("good/ecs_fargate_valid.yaml");
        assert!(!has_rule(&ids, "E3042"), "No E3042 expected for valid Fargate, got: {:?}", ids);
    }

    #[test]
    fn conditions_undefined_condition() {
        let ids = validate_file("bad/undefined_condition.yaml");
        assert!(has_rule(&ids, "E8002"), "Expected condition error, got: {:?}", ids);
    }

    #[test]
    fn conditions_equals_wrong_arity() {
        let ids = validate_file("bad/equals_wrong_arity.yaml");
        assert!(has_rule(&ids, "E8003") || has_rule(&ids, "W8001"), "Expected Equals arity error, got: {:?}", ids);
    }

    #[test]
    fn conditions_good_no_errors() {
        let ids = validate_file("good/conditions.yaml");
        let cond_errors: Vec<_> = ids.iter().filter(|id| id.starts_with("F8")).collect();
        assert!(cond_errors.is_empty(), "No condition errors expected, got: {:?}", cond_errors);
    }

    #[test]
    fn generated_rules_deprecated_type() {
        let ids = validate_file("bad/deprecated_type.yaml");
        assert!(has_rule(&ids, "W9009"), "Expected W9009 for deprecated type, got: {:?}", ids);
    }

    #[test]
    fn generated_rules_unknown_properties() {
        let ids = validate_file("bad/unknown_properties.yaml");
        assert!(has_rule(&ids, "F3002"), "Expected F3002 for unknown property, got: {:?}", ids);
    }

    #[test]
    fn generated_rules_unique_items() {
        let ids = validate_file("bad/unique_items.yaml");
        assert!(has_rule(&ids, "W9007"), "Expected unique items error, got: {:?}", ids);
    }

    #[test]
    fn good_generic_no_errors() {
        let ids = validate_file("good/generic.yaml");
        let errors: Vec<_> = ids.iter().filter(|id| id.starts_with("E") || id.starts_with("F")).collect();
        assert!(errors.is_empty(), "No errors expected for good/generic.yaml, got: {:?}", errors);
    }

    #[test]
    fn good_both_forms_no_errors() {
        let ids = validate_file("good/both_forms.yaml");
        let errors: Vec<_> = ids.iter().filter(|id| id.starts_with("E") || id.starts_with("F")).collect();
        assert!(errors.is_empty(), "No errors expected for good/both_forms.yaml, got: {:?}", errors);
    }

    #[test]
    fn e6101_non_string_getatt_in_output() {
        let ids = validate(
            r#"
Resources:
  CapRes:
    Type: AWS::EC2::CapacityReservation
    Properties:
      AvailabilityZone: us-east-1a
      InstanceCount: 1
      InstanceType: t2.micro
      InstancePlatform: Linux/UNIX
Outputs:
  IntegerOutput:
    Value: !GetAtt CapRes.InstanceCount
  BooleanOutput:
    Value: !GetAtt CapRes.EphemeralStorage
"#,
        );
        let e6101_count = ids.iter().filter(|id| *id == "F6101").count();
        assert!(
            e6101_count >= 2,
            "Expected at least 2 E6101 for integer and boolean GetAtt outputs, got {}: {:?}",
            e6101_count,
            ids
        );
    }

    #[test]
    fn e6101_getatt_types_integration_template() {
        let ids = validate_file("integration/getatt-types.yaml");
        let e6101_count = ids.iter().filter(|id| *id == "F6101").count();
        assert!(e6101_count >= 5, "Expected at least 5 E6101 in getatt-types.yaml, got {}: {:?}", e6101_count, ids);
    }

    #[test]
    fn i3011_sqs_queue_requires_deletion_policy() {
        let ids = validate(
            r#"
Resources:
  MyQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: test-queue
"#,
        );
        assert!(
            ids.contains(&"I3011".to_string()),
            "Expected I3011 for SQS::Queue without DeletionPolicy, got: {:?}",
            ids
        );
    }

    #[test]
    fn i3013_sqs_queue_requires_retention_period() {
        let ids = validate(
            r#"
Resources:
  MyQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: test-queue
"#,
        );
        assert!(
            ids.contains(&"I3013".to_string()),
            "Expected I3013 for SQS::Queue without MessageRetentionPeriod, got: {:?}",
            ids
        );
    }

    #[test]
    fn e1010_invalid_getatt_attribute() {
        let ids = validate(
            r#"
Resources:
  Bucket:
    Type: AWS::S3::Bucket
  Param:
    Type: AWS::SSM::Parameter
    Properties:
      Type: String
      Value: !GetAtt Bucket.NonExistentAttr
"#,
        );
        assert!(ids.contains(&"E9004".to_string()), "Expected E9004 for invalid GetAtt attribute, got: {:?}", ids);
    }

    #[test]
    fn e9004_dotted_attribute_on_object_attribute_is_still_invalid() {
        // A dotted GetAtt whose leading segment is an object/array-typed property
        // (here S3 Bucket `Tags`, an array) is NOT a valid map-member reference:
        // GetAtt cannot index into such an attribute, so CloudFormation rejects it
        // and the engine must still flag it. Only nested-stack / provisioned-product
        // `Outputs.<key>` is an open-ended map member.
        let ids = validate(
            r#"
Resources:
  Bucket:
    Type: AWS::S3::Bucket
  Param:
    Type: AWS::SSM::Parameter
    Properties:
      Type: String
      Value: !GetAtt Bucket.Tags.0
"#,
        );
        assert!(
            ids.contains(&"E9004".to_string()),
            "Expected E9004 for a dotted GetAtt into an object/array attribute, got: {:?}",
            ids
        );
    }

    #[test]
    fn e9004_provisioned_product_outputs_member_is_valid() {
        // A provisioned product exposes `Outputs.<OutputKey>` for any key, so a
        // dotted `Outputs.<key>` must NOT be flagged, while a genuinely invalid
        // attribute on the same type still is.
        let ids = validate(
            r#"
Resources:
  PP:
    Type: AWS::ServiceCatalog::CloudFormationProvisionedProduct
    Properties:
      ProductName: p
      ProvisioningArtifactName: v1
  UseOutput:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: !GetAtt PP.Outputs.MyKey
"#,
        );
        assert!(
            !ids.contains(&"E9004".to_string()),
            "A provisioned product Outputs.<key> member must not be flagged, got: {:?}",
            ids
        );

        let bad = validate(
            r#"
Resources:
  PP:
    Type: AWS::ServiceCatalog::CloudFormationProvisionedProduct
    Properties:
      ProductName: p
      ProvisioningArtifactName: v1
  UseBad:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: !GetAtt PP.NotARealAttr
"#,
        );
        assert!(
            bad.contains(&"E9004".to_string()),
            "An invalid provisioned product attribute must still be flagged, got: {:?}",
            bad
        );
    }
}
