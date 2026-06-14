use guard_translator::ir::*;
use guard_translator::*;
use std::env;
use std::fs;

const S3_GUARD: &str = r#"
let s3_buckets = Resources.*[ Type == 'AWS::S3::Bucket' ]

rule s3_bucket_encryption when %s3_buckets !empty {
    %s3_buckets.Properties.BucketEncryption exists
        <<S3 bucket must have encryption configured>>
}
"#;

const ELB_GUARD: &str = r#"
let allowed_protocols = [ "HTTPS", "TLS" ]
let elbs = Resources.*[ Type == 'AWS::ElasticLoadBalancingV2::Listener' ]

rule ensure_all_elbs_are_secure when %elbs !empty {
    %elbs.Properties {
        Protocol in %allowed_protocols
        Certificates !empty
    }
}

rule ensure_elbs_are_internal when %elbs !empty {
    ensure_all_elbs_are_secure
    %elbs.Properties.Scheme == 'internal'
}
"#;

#[test]
fn parse_guard_extracts_single_rule_with_assignment() {
    let file = parse_guard(S3_GUARD, "s3.guard").unwrap();
    assert_eq!(file.rules.len(), 1);
    assert_eq!(file.rules[0].name, "s3_bucket_encryption");
    assert_eq!(file.assignments.len(), 1);
    assert_eq!(file.assignments[0].var, "s3_buckets");
}

#[test]
fn parse_guard_extracts_multiple_rules_and_assignments() {
    let file = parse_guard(ELB_GUARD, "elb.guard").unwrap();
    assert_eq!(file.rules.len(), 2);
    assert_eq!(file.rules[0].name, "ensure_all_elbs_are_secure");
    assert_eq!(file.rules[1].name, "ensure_elbs_are_internal");
    assert_eq!(file.assignments.len(), 2);
    assert_eq!(file.assignments[0].var, "allowed_protocols");
    assert_eq!(file.assignments[1].var, "elbs");
}

#[test]
fn parse_guard_returns_empty_file_for_empty_source() {
    let file = parse_guard("", "empty.guard").unwrap();
    assert!(file.rules.is_empty());
    assert!(file.assignments.is_empty());
    assert!(file.parameterized_rules.is_empty());
}

#[test]
fn parse_guard_returns_error_with_filename_on_invalid_syntax() {
    let result = parse_guard("rule { invalid syntax !!!", "bad.guard");
    let err = result.unwrap_err();
    assert!(
        err.contains("bad.guard"),
        "error should mention filename, got: {err}"
    );
}

#[test]
fn pack_name_from_path_strips_directory_and_extension() {
    assert_eq!(
        pack_name_from_path("security-policies/elb-listener.guard"),
        "elb_listener"
    );
    assert_eq!(pack_name_from_path("/a/b/my-rule.ruleset"), "my_rule");
}

#[test]
fn load_pack_directory_returns_sorted_guard_files() {
    let sources = load_pack_directory("tests/fixtures/pack").unwrap();
    assert_eq!(sources.len(), 2);
    assert!(sources[0].0.contains("elb_https.guard"));
    assert!(sources[1].0.contains("s3_versioning.guard"));
    assert!(sources[0].1.contains("elb_https_only"));
    assert!(sources[1].1.contains("s3_versioning"));
}

#[test]
fn load_pack_directory_errors_on_nonexistent_path() {
    let err = load_pack_directory("tests/fixtures/nonexistent").unwrap_err();
    assert!(err.contains("not found"));
}

#[test]
fn load_pack_directory_errors_when_no_guard_files_found() {
    let dir = env::temp_dir().join("guard_test_empty_pack");
    let _ = fs::create_dir_all(&dir);
    let err = load_pack_directory(dir.to_str().unwrap()).unwrap_err();
    assert!(err.contains("No .guard files"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn load_guard_sources_recursive_finds_files_in_subdirectories() {
    let sources = load_guard_sources_recursive("tests/fixtures").unwrap();
    assert!(
        sources.len() >= 3,
        "expected at least 3 files, got {}",
        sources.len()
    );
}

#[test]
fn load_guard_sources_recursive_errors_on_nonexistent_path() {
    let result = load_guard_sources_recursive("tests/fixtures/nonexistent");
    result.unwrap_err();
}

#[test]
fn lower_type_block_extracts_type_name_operator_and_custom_message() {
    let source = r#"
AWS::S3::Bucket {
    Properties.BucketEncryption exists
        <<Encryption required>>
}
"#;
    let file = parse_guard(source, "test.guard").unwrap();
    let tb = match &file.rules[0].block.conjunctions[0][0] {
        RuleClauseIR::TypeBlock(tb) => tb,
        other => panic!("Expected TypeBlock, got {:?}", other),
    };
    assert_eq!(tb.type_name, "AWS::S3::Bucket");
    let ac = match &tb.block.conjunctions[0][0] {
        GuardClauseIR::Access(ac) => ac,
        other => panic!("Expected Access, got {:?}", other),
    };
    assert_eq!(ac.operator, Operator::Exists);
    assert!(!ac.negated, "EXISTS should not be negated");
    assert_eq!(ac.custom_message.as_deref(), Some("Encryption required"));
}

#[test]
fn lower_negated_eq_sets_negated_flag_on_access_clause() {
    let source = r#"
rule check {
    AWS::EC2::Instance {
        Properties.InstanceType != "t2.micro"
    }
}
"#;
    let file = parse_guard(source, "test.guard").unwrap();
    let tb = match &file.rules[0].block.conjunctions[0][0] {
        RuleClauseIR::TypeBlock(tb) => tb,
        other => panic!("Expected TypeBlock, got {:?}", other),
    };
    let ac = match &tb.block.conjunctions[0][0] {
        GuardClauseIR::Access(ac) => ac,
        other => panic!("Expected Access, got {:?}", other),
    };
    assert_eq!(ac.operator, Operator::Eq);
    assert!(ac.negated, "NOT_EQUALS should be negated");
}

#[test]
fn lower_negated_empty_sets_negated_flag_on_access_clause() {
    let source = r#"
rule check {
    AWS::EC2::Instance {
        Properties.Tags !empty
    }
}
"#;
    let file = parse_guard(source, "test.guard").unwrap();
    let tb = match &file.rules[0].block.conjunctions[0][0] {
        RuleClauseIR::TypeBlock(tb) => tb,
        other => panic!("Expected TypeBlock, got {:?}", other),
    };
    let ac = match &tb.block.conjunctions[0][0] {
        GuardClauseIR::Access(ac) => ac,
        other => panic!("Expected Access, got {:?}", other),
    };
    assert_eq!(ac.operator, Operator::Empty);
    assert!(ac.negated, "NOT_EMPTY should be negated");
}

#[test]
fn lower_in_operator_preserves_list_compare_value() {
    let source = r#"
rule check {
    AWS::EC2::Instance {
        Properties.SubnetId in ["subnet-1", "subnet-2"]
    }
}
"#;
    let file = parse_guard(source, "test.guard").unwrap();
    let tb = match &file.rules[0].block.conjunctions[0][0] {
        RuleClauseIR::TypeBlock(tb) => tb,
        other => panic!("Expected TypeBlock, got {:?}", other),
    };
    let ac = match &tb.block.conjunctions[0][0] {
        GuardClauseIR::Access(ac) => ac,
        other => panic!("Expected Access, got {:?}", other),
    };
    assert_eq!(ac.operator, Operator::In);
    assert!(!ac.negated, "IN operator should not be negated");
    assert!(
        ac.compare_with.is_some(),
        "IN clause should have compare_with"
    );
}

#[test]
fn lower_when_condition_produces_negated_empty_access() {
    let source = r#"
let buckets = Resources.*[ Type == 'AWS::S3::Bucket' ]
rule check when %buckets !empty {
    %buckets.Properties.BucketName exists
}
"#;
    let file = parse_guard(source, "test.guard").unwrap();
    let conds = file.rules[0].conditions.as_ref().unwrap();
    assert_eq!(conds.len(), 1);
    assert_eq!(conds[0].len(), 1);
    match &conds[0][0] {
        WhenClauseIR::Access(ac) => {
            assert_eq!(ac.operator, Operator::Empty);
            assert!(ac.negated, "when clause NOT_EMPTY should be negated");
        }
        other => panic!("Expected WhenClauseIR::Access, got {:?}", other),
    }
}

#[test]
fn lower_when_condition_with_named_rule_preserves_rule_name() {
    let source = r#"
rule base_check {
    AWS::S3::Bucket { Properties.BucketName exists }
}
rule derived when base_check {
    AWS::S3::Bucket { Properties.Tags !empty }
}
"#;
    let file = parse_guard(source, "test.guard").unwrap();
    let conds = file.rules[1].conditions.as_ref().unwrap();
    assert_eq!(conds.len(), 1);
    match &conds[0][0] {
        WhenClauseIR::NamedRule(nr) => {
            assert_eq!(nr.rule_name, "base_check");
            assert!(!nr.negated);
        }
        other => panic!("Expected WhenClauseIR::NamedRule, got {:?}", other),
    }
}

#[test]
fn lower_integer_comparison_preserves_operator_and_value() {
    let source = r#"
let s3 = Resources.*[ Type == 'AWS::S3::Bucket' ]
rule r { %s3.Properties.X == 42 }
"#;
    let file = parse_guard(source, "test.guard").unwrap();
    assert_eq!(file.assignments[0].var, "s3");
    let ac = match &file.rules[0].block.conjunctions[0][0] {
        RuleClauseIR::Guard(GuardClauseIR::Access(ac)) => ac,
        other => panic!("Expected Guard(Access), got {:?}", other),
    };
    assert_eq!(ac.operator, Operator::Eq);
    match &ac.compare_with {
        Some(LetValueIR::Value(ValueIR::Int(42))) => {}
        other => panic!("Expected Int(42), got {:?}", other),
    }
}

#[test]
fn lower_nested_block_preserves_multiple_checks_and_gt_operator() {
    let source = r#"
rule r {
    AWS::ECS::TaskDefinition {
        Properties.ContainerDefinitions.* {
            Image exists
            Memory > 128
        }
    }
}
"#;
    let file = parse_guard(source, "test.guard").unwrap();
    let tb = match &file.rules[0].block.conjunctions[0][0] {
        RuleClauseIR::TypeBlock(tb) => tb,
        other => panic!("Expected TypeBlock, got {:?}", other),
    };
    let bc = match &tb.block.conjunctions[0][0] {
        GuardClauseIR::Block(bc) => bc,
        other => panic!("Expected Block, got {:?}", other),
    };
    assert_eq!(bc.block.conjunctions.len(), 2);

    // Verify the Gt operator on Memory > 128
    let memory_check = match &bc.block.conjunctions[1][0] {
        GuardClauseIR::Access(ac) => ac,
        other => panic!("Expected Access, got {:?}", other),
    };
    assert_eq!(memory_check.operator, Operator::Gt);
    match &memory_check.compare_with {
        Some(LetValueIR::Value(ValueIR::Int(128))) => {}
        other => panic!("Expected Int(128), got {:?}", other),
    }
}

#[test]
fn lower_named_rule_reference_in_body_preserves_rule_name() {
    let file = parse_guard(ELB_GUARD, "elb.guard").unwrap();
    // ensure_elbs_are_internal references ensure_all_elbs_are_secure in its body
    let clause = &file.rules[1].block.conjunctions[0][0];
    match clause {
        RuleClauseIR::Guard(GuardClauseIR::NamedRule(nr)) => {
            assert_eq!(nr.rule_name, "ensure_all_elbs_are_secure");
            assert!(!nr.negated);
        }
        other => panic!("Expected Guard(NamedRule), got {:?}", other),
    }
}

#[test]
fn lower_parameterized_rule_preserves_parameter_names() {
    let source = r#"
rule check_prop(prop, expected) {
    %prop == %expected
}
"#;
    let file = parse_guard(source, "test.guard").unwrap();
    assert_eq!(file.parameterized_rules.len(), 1);
    let pr = &file.parameterized_rules[0];
    assert_eq!(pr.parameter_names, vec!["prop", "expected"]);
    assert_eq!(pr.rule.name, "check_prop");
}

#[test]
fn lower_list_literal_assignment_preserves_elements() {
    let source = r#"
let allowed = ["a", "b", "c"]
rule r { Properties.X in %allowed }
"#;
    let file = parse_guard(source, "test.guard").unwrap();
    match &file.assignments[0].value {
        LetValueIR::Value(ValueIR::List(items)) => {
            assert_eq!(items.len(), 3);
        }
        other => panic!("Expected Value(List), got {:?}", other),
    }
}
