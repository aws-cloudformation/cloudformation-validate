//! Integration tests for nested unreachable-branch traversal in the CEL engine.
//!
//! Verifies that `find_unreachable_branches` correctly recurses into nested
//! `Fn::If` branches with the right assumption propagation:
//! - Satisfiable outer branch: recurse with the outer condition assumption added.
//! - Unsatisfiable outer branch: report it, then recurse using the prior
//!   assumptions (not the impossible one) so nested unreachable branches are
//!   detected independently.

use cel_engine::CelEngine;
use diagnostics::Diagnostic;
use schema_validator::SchemaValidator;
use std::sync::LazyLock;
use validation_engine::{EngineConfig, ValidateConfig, validate_bytes};

static SV: LazyLock<SchemaValidator> = LazyLock::new(SchemaValidator::default);

fn w1028_diagnostics(template: &str) -> Vec<Diagnostic> {
    let engine = CelEngine::new(EngineConfig::default()).unwrap();
    let report = validate_bytes(&engine, &SV, template.as_bytes(), ValidateConfig::default()).unwrap();
    report.diagnostics.into_iter().filter(|d| d.rule_id == "W1028").collect()
}

fn w1028_paths(template: &str) -> Vec<String> {
    w1028_diagnostics(template).into_iter().map(|d| d.property_path.unwrap_or_default()).collect()
}

/// Nested unreachable branch under a reachable outer branch.
///
/// Setup: `IsProduction` and `IsNotProduction` are mutually exclusive (Not).
/// The outer `Fn::If` on `IsProduction` is reachable in both branches.
/// Inside the true-branch (where IsProduction=true), a nested `Fn::If` on
/// `IsNotProduction` has its true-branch unreachable (IsProduction=true AND
/// IsNotProduction=true is unsatisfiable).
#[test]
fn nested_unreachable_under_reachable_outer() {
    let template = r#"
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  Env:
    Type: String
Conditions:
  IsProduction: !Equals [!Ref Env, prod]
  IsNotProduction: !Not [Condition: IsProduction]
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName:
        Fn::If:
          - IsProduction
          - Fn::If:
              - IsNotProduction
              - unreachable-value
              - prod-value
          - non-prod-value
"#;

    let paths = w1028_paths(template);
    // The nested true-branch (IsNotProduction=true when IsProduction=true) is
    // unreachable. Exactly one finding is expected.
    assert_eq!(paths.len(), 1, "Expected exactly 1 W1028 for the nested unreachable branch, got: {:?}", paths);
    assert!(
        paths[0].contains("Fn::If.1.Fn::If.1"),
        "Expected path to contain nested 'Fn::If.1.Fn::If.1', got: {:?}",
        paths[0]
    );
}

/// Nested conditional inside an already-unreachable outer branch.
///
/// Setup: `CondA` and `CondB` are mutually exclusive (CondB = Not CondA).
/// A resource with `Condition: CondA` makes CondA=true the base assumption.
/// The outer `Fn::If` on `CondB` has its true-branch unreachable (CondA=true
/// AND CondB=true is unsatisfiable). Inside that unreachable branch, there is
/// a nested `Fn::If` on `CondA`. Since we recurse with PRIOR assumptions
/// (just [CondA=true]), the nested false-branch (CondA=false) is independently
/// unreachable because the resource condition forces CondA=true.
#[test]
fn nested_inside_unreachable_outer_uses_prior_assumptions() {
    let template = r#"
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  Env:
    Type: String
Conditions:
  CondA: !Equals [!Ref Env, a]
  CondB: !Not [Condition: CondA]
Resources:
  Thing:
    Type: AWS::CloudFormation::WaitConditionHandle
    Condition: CondA
    Properties:
      Metadata:
        Fn::If:
          - CondB
          - Fn::If:
              - CondA
              - nested-true
              - nested-false
          - outer-false-value
"#;

    let diags = w1028_diagnostics(template);
    let paths: Vec<&str> = diags.iter().map(|d| d.property_path.as_deref().unwrap_or("")).collect();

    // Expect two findings:
    // 1. The outer true-branch (CondB=true) is unreachable because CondA=true
    //    (resource condition) makes CondB=true impossible.
    // 2. Inside that unreachable branch, we recurse with prior assumptions
    //    [CondA=true]. The nested false-branch (CondA=false) is unreachable
    //    because CondA is forced true by the resource condition.
    assert_eq!(diags.len(), 2, "Expected 2 W1028 diagnostics, got {} : {:?}", diags.len(), paths);

    let has_outer = paths.iter().any(|p| p.ends_with("Fn::If.1") && !p.contains("Fn::If.1.Fn::If"));
    let has_nested = paths.iter().any(|p| p.contains("Fn::If.1.Fn::If.2"));
    assert!(has_outer, "Expected W1028 for outer CondB true-branch, paths: {:?}", paths);
    assert!(
        has_nested,
        "Expected W1028 for nested CondA false-branch (prior-assumption recursion), paths: {:?}",
        paths
    );
}

/// Reachable nested branches produce no findings.
///
/// Both conditions are independent (not mutually exclusive), so every
/// combination of branches is satisfiable.
#[test]
fn reachable_nested_branches_produce_no_w1028() {
    let template = r#"
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  Env:
    Type: String
  Region:
    Type: String
Conditions:
  IsProduction: !Equals [!Ref Env, prod]
  IsUsEast1: !Equals [!Ref Region, us-east-1]
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName:
        Fn::If:
          - IsProduction
          - Fn::If:
              - IsUsEast1
              - prod-east-bucket
              - prod-other-bucket
          - Fn::If:
              - IsUsEast1
              - dev-east-bucket
              - dev-other-bucket
"#;

    let paths = w1028_paths(template);
    assert_eq!(paths.len(), 0, "Expected no W1028 for fully reachable nested branches, got: {:?}", paths);
}
