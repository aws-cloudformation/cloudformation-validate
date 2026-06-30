//! Regression tests for reported GitHub issues.
//!
//! Each test pins the CURRENT, observed behavior of both engines on a fixture
//! checked in under `resources/templates/gh-issues/`. Where an issue describes a
//! bug that has since been fixed, the test asserts the corrected behavior (the
//! focal rule no longer fires); where the bug still reproduces, the test asserts
//! that it does, so the report stays honest and any future change is caught. The
//! same fixtures are also covered by the golden-file tests (they live in a
//! `GOLDEN_DIRS` directory), so this file adds focused, rule-level assertions on
//! top of the full-report snapshots.
//!
//! Both engines must agree on every assertion here unless a test explicitly says
//! otherwise (see `issue_36_*`, which pins a known rego/cel divergence).

mod common;

use cel_engine::CelEngine;
use common::load_template;
use diagnostics::Diagnostic;
use rego_engine::RegoEngine;
use rules::Severity;
use schema_validator::SchemaValidator;
use std::sync::LazyLock;
use template_model::PseudoParameterOverrides;
use validation_engine::{EngineConfig, ValidateConfig, ValidationEngine, validate_bytes};

static REGO: LazyLock<RegoEngine> = LazyLock::new(|| RegoEngine::new(EngineConfig::default()).unwrap());
static CEL: LazyLock<CelEngine> = LazyLock::new(|| CelEngine::new(EngineConfig::default()).unwrap());

/// Validate a `gh-issues` fixture with one engine at the lowest severity gate
/// (so INFO/DEBUG findings are visible to assertions).
fn validate_with(engine: &dyn ValidationEngine, fixture: &str, config: ValidateConfig) -> Vec<Diagnostic> {
    let sv = SchemaValidator::new();
    let bytes = load_template(&format!("gh-issues/{fixture}"));
    validate_bytes(engine, &sv, &bytes, config).expect("validation should not error").diagnostics
}

fn debug_config() -> ValidateConfig {
    ValidateConfig { severity_level: Severity::Debug, ..Default::default() }
}

/// Run both engines with the default config and return their diagnostics tagged
/// by engine name. Every assertion helper checks both, so a test that passes is
/// asserting engine parity for that fact.
fn validate_both(fixture: &str) -> Vec<(&'static str, Vec<Diagnostic>)> {
    vec![
        ("rego", validate_with(&*REGO, fixture, debug_config())),
        ("cel", validate_with(&*CEL, fixture, debug_config())),
    ]
}

fn count(diags: &[Diagnostic], rule_id: &str) -> usize {
    diags.iter().filter(|d| d.rule_id == rule_id).count()
}

/// Assert `rule_id` fires at least once in every engine's output.
fn assert_fires(by_engine: &[(&str, Vec<Diagnostic>)], rule_id: &str) {
    for (engine, diags) in by_engine {
        assert!(count(diags, rule_id) > 0, "[{engine}] expected {rule_id} to fire, but it did not");
    }
}

/// Assert `rule_id` never fires in any engine's output.
fn assert_absent(by_engine: &[(&str, Vec<Diagnostic>)], rule_id: &str) {
    for (engine, diags) in by_engine {
        let hits: Vec<&str> = diags.iter().filter(|d| d.rule_id == rule_id).map(|d| d.message.as_str()).collect();
        assert!(hits.is_empty(), "[{engine}] expected {rule_id} to be absent, but it fired: {hits:?}");
    }
}

/// Assert `rule_id` fires with exactly `severity` in every engine's output.
fn assert_fires_with_severity(by_engine: &[(&str, Vec<Diagnostic>)], rule_id: &str, severity: Severity) {
    for (engine, diags) in by_engine {
        let matched = diags.iter().filter(|d| d.rule_id == rule_id).collect::<Vec<_>>();
        assert!(!matched.is_empty(), "[{engine}] expected {rule_id} to fire at {severity}, but it did not fire");
        for d in matched {
            assert_eq!(d.severity, severity, "[{engine}] {rule_id} fired at {} (expected {severity})", d.severity);
        }
    }
}

/// Assert `rule_id` fires on the resource with logical id `resource_id` in every engine.
fn assert_fires_on_resource(by_engine: &[(&str, Vec<Diagnostic>)], rule_id: &str, resource_id: &str) {
    for (engine, diags) in by_engine {
        let on_resource = diags
            .iter()
            .filter(|d| d.rule_id == rule_id)
            .any(|d| d.resource.as_ref().and_then(|r| r.id.as_deref()) == Some(resource_id));
        assert!(on_resource, "[{engine}] expected {rule_id} on resource {resource_id}, but it did not fire there");
    }
}

/// Assert `rule_id` fires exactly `expected` times in every engine's output.
fn assert_count(by_engine: &[(&str, Vec<Diagnostic>)], rule_id: &str, expected: usize) {
    for (engine, diags) in by_engine {
        assert_eq!(count(diags, rule_id), expected, "[{engine}] expected {expected} {rule_id} diagnostic(s)");
    }
}

// ---------------------------------------------------------------------------
// Per-issue regression tests
// ---------------------------------------------------------------------------

/// Issue #34: SSM-typed parameter Defaults (`AWS::SSM::Parameter::Value<...>`) no
/// longer trip the AMI-format false positive; the SSM-path Default is treated as
/// a deploy-time name, not a literal value. The remaining W2506 (a `<String>`-typed
/// param used as an ImageId) is correct.
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/34
#[test]
fn issue_34_no_false_positive_on_ssm_typed_parameter_default() {
    let diags = validate_both("issue-34.json");
    assert_absent(&diags, "E1152");
    assert_absent(&diags, "W1030");
    assert_fires_with_severity(&diags, "W2506", Severity::Warn);
    assert_count(&diags, "W2506", 1);
}

/// Issue #35: a dynamic reference embedded mid-string is not treated as a
/// deploy-time-opaque value, so the schedule-expression format check E3027 still
/// fires (false positive) in both engines. Pins the current buggy behavior.
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/35
#[test]
fn issue_35_e3027_fires_on_embedded_dynamic_reference() {
    let diags = validate_both("issue-35.yaml");
    assert_fires_with_severity(&diags, "E3027", Severity::Error);
    assert_fires_on_resource(&diags, "E3027", "ScheduledRule");
    assert_count(&diags, "E3027", 1);
}

// issue #36 is tested below in a dedicated test that also pins the rego/cel divergence.

/// Issue #37: the maintenance-mode warning W3697 fires on
/// `AWS::AutoScaling::LaunchConfiguration`. Per-service silencing is not yet a
/// dedicated CLI flag, but the rule itself fires correctly and identically in
/// both engines (and is suppressible via the existing exclude filters — see the
/// suppressibility tests at the bottom of this file).
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/37
#[test]
fn issue_37_w3697_fires_on_autoscaling_launchconfiguration() {
    let diags = validate_both("issue-37.yaml");
    assert_fires_with_severity(&diags, "W3697", Severity::Warn);
    assert_fires_on_resource(&diags, "W3697", "MyLaunchConfig");
    assert_count(&diags, "W3697", 1);
}

/// Issue #38: E3040 must not flag a top-level property when only deeply-nested
/// subproperties are read-only. The read-only check was removed, so E3040 never
/// fires; the resource still resolves (proven by the INFO findings).
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/38
#[test]
fn issue_38_no_false_positive_on_nested_readonly_subproperty() {
    let diags = validate_both("issue-38.json");
    assert_absent(&diags, "E3040");
    assert_count(&diags, "E3040", 0);
    assert_fires_on_resource(&diags, "I9001", "Memory");
    assert_fires_on_resource(&diags, "I9040", "Memory");
}

/// Issue #39: `Fn::GetAtt [VPC, CidrBlock]` is a valid documented attribute, so
/// the GetAtt-attribute checks must not fire (the stale data was regenerated).
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/39
#[test]
fn issue_39_no_false_positive_on_vpc_cidrblock_getatt() {
    let diags = validate_both("issue-39.json");
    assert_absent(&diags, "E9004");
    assert_absent(&diags, "E9003");
    assert_count(&diags, "E9004", 0);
    assert_fires_on_resource(&diags, "I9001", "VPCB9E5F0B4");
}

/// Issue #40: E1150 fires only on a concrete, inspectable value (`sg-1`), never
/// on a `Ref` to a deploy-time value — the two concerns are now separate rules.
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/40
#[test]
fn issue_40_e1150_only_on_concrete_value_not_on_ref() {
    let diags = validate_both("issue-40.yaml");
    assert_fires_with_severity(&diags, "E1150", Severity::Error);
    assert_count(&diags, "E1150", 1);
    assert_fires_on_resource(&diags, "E1150", "DaxConcrete");
}

/// Issue #41: W9013 still fires (false positive) on an ARN built via `Fn::Join`
/// with `Ref: AWS::AccountId`, because the resolver bakes the account placeholder
/// into a concrete string and loses the pseudo-parameter provenance.
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/41
#[test]
fn issue_41_w9013_false_positive_on_join_ref_accountid() {
    let diags = validate_both("issue-41.json");
    assert_fires_with_severity(&diags, "W9013", Severity::Warn);
    assert_fires_on_resource(&diags, "W9013", "MyFunction");
    assert_count(&diags, "W9013", 1);
}

/// Issue #42: E3049 still fires on an ECS dynamic-port (HostPort 0) TargetGroup
/// when HealthCheckPort is omitted — the absent value is treated as `""` rather
/// than the documented `traffic-port` default. Pins the current behavior, which
/// matches the reference linter baseline.
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/42
#[test]
fn issue_42_e3049_omitted_healthcheckport_with_hostport_zero() {
    let diags = validate_both("issue-42.yaml");
    assert_fires_with_severity(&diags, "E3049", Severity::Error);
    assert_fires_on_resource(&diags, "E3049", "TargetGroup");
    assert_count(&diags, "E3049", 1);
}

/// Issue #44: E3702 must NOT fire on an `AWS/Deploy/CloudFormation` action that
/// legitimately has 0 input artifacts (`CHANGE_SET_EXECUTE`). The artifact-count
/// table is keyed on the full Owner/Category/Provider tuple, so this action's
/// real bound (0–10 inputs) applies instead of a collapsed category-only bound.
/// cfn-lint reports nothing here.
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/44
#[test]
fn issue_44_no_e3702_false_positive_on_changeset_execute() {
    let diags = validate_both("issue-44.json");
    assert_absent(&diags, "E3702");
    assert_count(&diags, "E3702", 0);
}

/// Issue #45: F6101 must not fire when an array-returning `Fn::GetAtt` is wrapped
/// in `Fn::Join` (which yields a string) in an output value.
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/45
#[test]
fn issue_45_no_false_positive_on_array_getatt_wrapped_in_join() {
    let diags = validate_both("issue-45.json");
    assert_absent(&diags, "F6101");
    assert_count(&diags, "F6101", 0);
    assert_fires_on_resource(&diags, "I9040", "interfaceVpcEndpoint89C99945");
}

/// Issue #46: E1150 must not fire on `Fn::GetAtt` to an EKS cluster's
/// `ClusterSecurityGroupId` used as a SecurityGroupId — it is a deploy-time value.
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/46
#[test]
fn issue_46_no_false_positive_on_eks_securitygroupid_getatt() {
    let diags = validate_both("issue-46.json");
    assert_absent(&diags, "E1150");
    assert_absent(&diags, "E1041");
    assert_fires_on_resource(&diags, "W9002", "ClusterEB0386A7");
}

/// Issue #47: an open-world service-enum mismatch (Lambda Runtime `node99.x`) is
/// emitted as a FATAL F3030. Pins the current FATAL classification the issue
/// disputes; note the diagnostic is suppressible (see suppressibility tests).
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/47
#[test]
fn issue_47_f3030_enum_mismatch_is_fatal() {
    let diags = validate_both("issue-47.json");
    assert_fires_with_severity(&diags, "F3030", Severity::Fatal);
    assert_fires_on_resource(&diags, "F3030", "MyFunction");
    assert_count(&diags, "F3030", 1);
    assert_fires_with_severity(&diags, "E3677", Severity::Error);
}

/// Issue #48: a binding type-ergonomics request (`PseudoParameterOverrides`
/// fields rendered as required in the generated `.d.ts`). There is no rule
/// behavior to assert; this pins that a template referencing `AWS::AccountId` /
/// `AWS::Region` validates cleanly with no error/fatal diagnostics.
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/48
#[test]
fn issue_48_pseudo_parameter_template_validates_cleanly() {
    let diags = validate_both("issue-48.json");
    for (engine, ds) in &diags {
        let bad: Vec<&str> = ds
            .iter()
            .filter(|d| matches!(d.severity, Severity::Fatal | Severity::Error))
            .map(|d| d.rule_id.as_str())
            .collect();
        assert!(bad.is_empty(), "[{engine}] expected no error/fatal diagnostics, got {bad:?}");
    }
    assert_fires_on_resource(&diags, "I9001", "MyBucket");
    assert_count(&diags, "I9001", 1);
}

/// Issue #49: with no region supplied the engine assumes `us-east-1`, so the
/// region-scoped instance-type enum rules fire on values invalid there (E3652 on
/// the OpenSearch domain, E3620 on the DocDB instance) while a value valid in
/// `us-east-1` (EC2 `t2.nano`) does not trip E3628.
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/49
#[test]
fn issue_49_region_scoped_enums_assume_us_east_1() {
    let diags = validate_both("issue-49.yaml");
    assert_fires_with_severity(&diags, "E3652", Severity::Error);
    assert_fires_on_resource(&diags, "E3652", "EsDomain");
    assert_fires_on_resource(&diags, "E3620", "DocDbInstance");
    assert_absent(&diags, "E3628");
}

/// Issue #50: W1030 must not fire when an opaque String-param `Ref` is `Fn::Split`
/// into an IAM policy `Resource` (the CDK token scenario).
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/50
#[test]
fn issue_50_no_false_positive_on_fn_split_ref_iam_resource() {
    let diags = validate_both("issue-50.json");
    assert_absent(&diags, "W1030");
    assert_fires_on_resource(&diags, "I9040", "MyFunctionServiceRole");
    assert_count(&diags, "I9040", 1);
}

/// Issue #52: W9007 falsely flags two distinct `Fn::ImportValue` items in an array
/// as duplicates, because both collapse to one symbolic cross-stack-import value.
/// Pins the current false positive.
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/52
#[test]
fn issue_52_w9007_false_duplicate_on_distinct_importvalue() {
    let diags = validate_both("issue-52.json");
    assert_fires_with_severity(&diags, "W9007", Severity::Warn);
    assert_fires_on_resource(&diags, "W9007", "Nodegroup");
    assert_count(&diags, "W9007", 1);
}

/// Issue #53: F3004 correctly fires on a genuine bidirectional `DependsOn`
/// circular dependency (a cycle invisible to Ref/GetAtt-only graph tools).
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/53
#[test]
fn issue_53_f3004_fires_on_real_dependson_cycle() {
    let diags = validate_both("issue-53.json");
    assert_fires_with_severity(&diags, "F3004", Severity::Fatal);
    assert_count(&diags, "F3004", 9);
    assert_fires_on_resource(&diags, "F3004", "ClusterKubectlHandlerRole94549F93");
    assert_fires_on_resource(&diags, "F3004", "ClusterKubectlReadyBarrier200052AF");
}

/// Issue #54: F3003 falsely fires "OwnershipControls is a required property"
/// (FATAL) on an S3 bucket with non-Private AccessControl, duplicating the
/// suppressible E3045. Pins the current false positive.
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/54
#[test]
fn issue_54_f3003_false_required_ownershipcontrols() {
    let diags = validate_both("issue-54.json");
    assert_fires_with_severity(&diags, "F3003", Severity::Fatal);
    assert_fires_on_resource(&diags, "F3003", "Bucket");
    assert_fires(&diags, "E3045");
}

/// Issue #55: a `CommaDelimitedList` parameter Default referenced by an
/// array-typed property must not raise an F3012 "not of type array" false
/// positive.
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/55
#[test]
fn issue_55_no_false_positive_on_commadelimitedlist_default() {
    let diags = validate_both("issue-55.json");
    assert_absent(&diags, "F3012");
    assert_absent(&diags, "W9003");
    assert_count(&diags, "F3012", 0);
}

/// Issue #56: F3012 (FATAL type mismatch) must not fire on an unrecognized
/// `Fn::GetStackOutput` intrinsic used as a string property value.
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/56
#[test]
fn issue_56_no_fatal_on_unrecognized_getstackoutput_intrinsic() {
    let diags = validate_both("issue-56.json");
    assert_absent(&diags, "F3012");
    assert_absent(&diags, "W9003");
    assert_count(&diags, "F3012", 0);
    assert_fires_on_resource(&diags, "I9001", "WeakConsumer");
}

/// Issue #57: E3057 false positive — a `TargetOriginId` that references an
/// `OriginGroups.Items[].Id` is rejected because only `Origins[].Id` is treated
/// as a valid target. Pins the current buggy behavior.
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/57
#[test]
fn issue_57_e3057_rejects_valid_origin_group_id() {
    let diags = validate_both("issue-57.json");
    assert_fires_with_severity(&diags, "E3057", Severity::Error);
    assert_fires_on_resource(
        &diags,
        "E3057",
        "AReallyAwesomeDistributionWithAMemorableNameThatIWillNeverForget046C0FA9",
    );
    assert_count(&diags, "E3057", 1);
}

/// Issue #61: a bare `AWS::EC2::Volume` with no Properties fires FATAL F3017
/// (anyOf failure). Pins the current behavior; the issue is about the generic
/// message dropping the per-branch required-property detail (no companion F3003).
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/61
#[test]
fn issue_61_f3017_anyof_on_bare_ec2_volume() {
    let diags = validate_both("issue-61.json");
    assert_fires_with_severity(&diags, "F3017", Severity::Fatal);
    assert_fires_on_resource(&diags, "F3017", "Resource");
    assert_count(&diags, "F3017", 1);
    assert_absent(&diags, "F3003");
}

/// Issue #62: F3032 fires as a FATAL on an empty `ResourcesToReplicateTags` array
/// for `AWS::Synthetics::Canary` (a synced `minItems:1` bound). Pins the current
/// FATAL classification the issue disputes.
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/62
#[test]
fn issue_62_f3032_fatal_on_empty_unconstrained_array() {
    let diags = validate_both("issue-62.json");
    assert_fires_with_severity(&diags, "F3032", Severity::Fatal);
    assert_fires_on_resource(&diags, "F3032", "Canary");
    assert_count(&diags, "F3032", 1);
}

/// Issue #63: E2001 fires on an intrinsic (`Fn::GetStackOutput`) used in a
/// parameter Default, because CloudFormation never evaluates intrinsics in
/// `Parameters.*.Default`. Working as intended (matches the reference linter).
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/63
#[test]
fn issue_63_e2001_on_intrinsic_in_parameter_default() {
    let diags = validate_both("issue-63.json");
    assert_fires_with_severity(&diags, "E2001", Severity::Error);
    assert_count(&diags, "E2001", 1);
}

// issue #65 is tested below in a dedicated test (needs a non-12-digit account id override).

/// Issue #67: F3014 FATAL false positive on a deployable PromQL CloudWatch alarm
/// that uses `EvaluationCriteria` instead of `Metrics`/`MetricName` (a stale
/// `requiredXor` patch predating the PromQL feature). Pins the current behavior.
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/67
#[test]
fn issue_67_f3014_false_positive_on_promql_alarm() {
    let diags = validate_both("issue-67.json");
    assert_fires_with_severity(&diags, "F3014", Severity::Fatal);
    assert_fires_on_resource(&diags, "F3014", "PromAlarm");
    assert_count(&diags, "F3014", 1);
}

/// Issue #68: the Lambda ZipFile runtime rule (E3677) already uses a
/// forward-looking `nodejs`/`python` prefix — it fires on `node99.x` but not on
/// `nodejs99.x`. The genuinely non-future-proof check is the baked-in Runtime
/// enum (F3030), which FATAL-rejects both unknown runtimes.
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/68
#[test]
fn issue_68_zipfile_runtime_forward_looking_vs_enum_snapshot() {
    let diags = validate_both("issue-68.json");
    assert_fires_with_severity(&diags, "E3677", Severity::Error);
    assert_fires_on_resource(&diags, "E3677", "FutureNodeFunc");
    assert_count(&diags, "E3677", 1);
    assert_fires_with_severity(&diags, "F3030", Severity::Fatal);
    assert_count(&diags, "F3030", 2);
}

/// Issue #69: the FATAL-classification debate. Service-content schema constraints
/// F3037 (uniqueItems) and F3032 (maxItems) still fire as FATAL on an
/// `AWS::IAM::InstanceProfile` with duplicate Roles. Pins the current behavior;
/// note these FATALs are suppressible (see the suppressibility tests below).
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/69
#[test]
fn issue_69_f3037_f3032_content_constraints_are_fatal() {
    let diags = validate_both("issue-69.yaml");
    assert_fires_with_severity(&diags, "F3037", Severity::Fatal);
    assert_fires_on_resource(&diags, "F3037", "Profile");
    assert_fires_with_severity(&diags, "F3032", Severity::Fatal);
    assert_count(&diags, "F3037", 1);
}

// ---------------------------------------------------------------------------
// Issue #36 — pins both the shared E1156 false positive AND the rego/cel
// E3511 divergence. The committed fixture uses `arn:aws-iso:` (parity-clean, so
// it is golden-compatible); the divergence is reproduced here with inline bytes
// using `arn:aws-isob:`, which the CEL ARN regex rejects but the rego one accepts.
// ---------------------------------------------------------------------------

/// Issue #36: hardcoded partition enumerations in the IAM-role-ARN checks raise a
/// false positive on ADC-partition ARNs. The schema-validator's
/// `AWS::IAM::Role.Arn` format check (E1156) fires in BOTH engines on an
/// `arn:aws-iso:` ARN.
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/36
#[test]
fn issue_36_e1156_false_positive_on_iso_partition_arn() {
    let diags = validate_both("issue-36.yaml");
    assert_fires_with_severity(&diags, "E1156", Severity::Error);
    assert_fires_on_resource(&diags, "E1156", "TaskDef");
}

/// Issue #36 (continued): the CEL engine's ARN regex still hardcodes the partition
/// list, so it fires E3511 on an `arn:aws-isob:` ARN, while the rego rule (already
/// future-proofed) does not. Pins this known rego/cel divergence so a future fix
/// to either engine is forced to update this assertion.
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/36
#[test]
fn issue_36_e3511_diverges_between_engines_on_isob_partition() {
    const TEMPLATE: &[u8] = br#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  TaskDef:
    Type: AWS::ECS::TaskDefinition
    Properties:
      ExecutionRoleArn: arn:aws-isob:iam::123456789012:role/my-task-role
"#;
    let sv = SchemaValidator::new();
    let rego = validate_bytes(&*REGO, &sv, TEMPLATE, debug_config()).unwrap().diagnostics;
    let cel = validate_bytes(&*CEL, &sv, TEMPLATE, debug_config()).unwrap().diagnostics;

    // E1156 (schema-validator) fires in both — the shared partition false positive.
    assert!(rego.iter().any(|d| d.rule_id == "E1156"), "rego should fire E1156");
    assert!(cel.iter().any(|d| d.rule_id == "E1156"), "cel should fire E1156");

    // E3511 (engine rule) currently fires in CEL only — the divergence.
    assert!(!rego.iter().any(|d| d.rule_id == "E3511"), "rego should NOT fire E3511 (regex already future-proofed)");
    assert!(cel.iter().any(|d| d.rule_id == "E3511"), "cel still fires E3511 (regex hardcodes partitions)");
}

// ---------------------------------------------------------------------------
// Issue #65 — needs a non-12-digit AWS::AccountId override to surface the bug.
// ---------------------------------------------------------------------------

/// Issue #65: `Ref: AWS::AccountId` resolves to a bare literal that schema
/// validation checks against. With a non-12-digit account override the literal
/// trips F3031 (pattern) and F3033 (length) on the Lambda::Permission
/// SourceAccount — it should instead be a symbolic 12-digit value.
/// https://github.com/aws-cloudformation/cloudformation-validate/issues/65
#[test]
fn issue_65_accountid_ref_resolves_to_nonvalidating_literal() {
    let config = ValidateConfig {
        severity_level: Severity::Debug,
        pseudo_parameter_overrides: PseudoParameterOverrides {
            account_id: Some("unknown-account".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    let diags = vec![
        ("rego", validate_with(&*REGO, "issue-65.json", config.clone())),
        ("cel", validate_with(&*CEL, "issue-65.json", config)),
    ];
    assert_fires_with_severity(&diags, "F3031", Severity::Fatal);
    assert_fires_on_resource(&diags, "F3031", "S3Permission");
    assert_fires_on_resource(&diags, "F3033", "S3Permission");
    assert_count(&diags, "F3033", 1);
}

// ---------------------------------------------------------------------------
// FATAL rules are suppressible.
//
// FATAL diagnostics are filtered by the same include/exclude mechanism as every
// other severity — there is no severity gate that exempts them. These tests pin
// that contract across all three exclude dimensions (rule id, category, id range)
// in both engines, using a bare `AWS::EC2::Volume` that deterministically yields
// the FATAL schema rule F3017.
// ---------------------------------------------------------------------------

/// A bare `AWS::EC2::Volume` (no Properties) yields exactly one FATAL F3017 in
/// both engines — the fixture for the suppressibility tests.
fn fatal_baseline(engine: &dyn ValidationEngine) -> Vec<Diagnostic> {
    validate_with(engine, "issue-61.json", debug_config())
}

#[test]
fn fatal_rule_present_without_filter() {
    for (name, engine) in [("rego", &*REGO as &dyn ValidationEngine), ("cel", &*CEL as &dyn ValidationEngine)] {
        let diags = fatal_baseline(engine);
        assert_eq!(count(&diags, "F3017"), 1, "[{name}] F3017 should fire without a filter");
        assert!(diags.iter().any(|d| d.severity == Severity::Fatal), "[{name}] a FATAL diagnostic is expected");
    }
}

#[test]
fn fatal_rule_suppressed_by_exclude_id() {
    use rules::{FilterConfig, RuleFilterConfig};
    let config = ValidateConfig {
        severity_level: Severity::Debug,
        filters: FilterConfig::new(
            RuleFilterConfig::default(),
            RuleFilterConfig { ids: vec!["F3017".into()], ..Default::default() },
        ),
        ..Default::default()
    };
    for (name, engine) in [("rego", &*REGO as &dyn ValidationEngine), ("cel", &*CEL as &dyn ValidationEngine)] {
        let diags = validate_with(engine, "issue-61.json", config.clone());
        assert_eq!(count(&diags, "F3017"), 0, "[{name}] --exclude-ids F3017 must suppress the FATAL rule");
        assert!(!diags.iter().any(|d| d.severity == Severity::Fatal), "[{name}] no FATAL should remain after exclude");
    }
}

#[test]
fn fatal_rule_suppressed_by_exclude_category() {
    use rules::{FilterConfig, RuleFilterConfig};
    // F3017 is a schema rule; excluding the Schema category removes it.
    let config = ValidateConfig {
        severity_level: Severity::Debug,
        filters: FilterConfig::new(
            RuleFilterConfig::default(),
            RuleFilterConfig { categories: vec!["Schema".into()], ..Default::default() },
        ),
        ..Default::default()
    };
    for (name, engine) in [("rego", &*REGO as &dyn ValidationEngine), ("cel", &*CEL as &dyn ValidationEngine)] {
        let diags = validate_with(engine, "issue-61.json", config.clone());
        assert_eq!(count(&diags, "F3017"), 0, "[{name}] excluding the Schema category must suppress the FATAL rule");
    }
}

#[test]
fn fatal_rule_suppressed_by_exclude_range() {
    use rules::{FilterConfig, IdRange, RuleFilterConfig};
    let config = ValidateConfig {
        severity_level: Severity::Debug,
        filters: FilterConfig::new(
            RuleFilterConfig::default(),
            RuleFilterConfig {
                id_ranges: vec![IdRange { prefix: "F".into(), start: 3000, end: 3099 }],
                ..Default::default()
            },
        ),
        ..Default::default()
    };
    for (name, engine) in [("rego", &*REGO as &dyn ValidationEngine), ("cel", &*CEL as &dyn ValidationEngine)] {
        let diags = validate_with(engine, "issue-61.json", config.clone());
        assert_eq!(count(&diags, "F3017"), 0, "[{name}] excluding the F3000-F3099 range must suppress the FATAL rule");
    }
}
