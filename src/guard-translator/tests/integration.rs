use guard_translator::*;
use serde_json::{Value, json};
use std::env;
use std::fs;

/// Two buckets with no name, one named `bar`, and one whose name is a parameter
/// reference - the shapes a check on `Properties.BucketName` must distinguish.
fn bucket_template() -> Value {
    json!({
        "Parameters": {"NameParam": {"Type": "String"}},
        "Resources": {
            "NoProps": {"Type": "AWS::S3::Bucket"},
            "Missing": {"Type": "AWS::S3::Bucket", "Properties": {"Tags": [{"Key": "Team", "Value": "x"}]}},
            "Present": {
                "Type": "AWS::S3::Bucket",
                "Properties": {"BucketName": "bar", "Port": "abc", "Tags": [{"Key": "Owner", "Value": "y"}]}
            },
            "RefValue": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": {"Ref": "NameParam"}}}
        }
    })
}

fn evaluate(source: &str) -> Vec<GuardFinding> {
    GuardRuleFile::parse("checks.guard", source)
        .expect("rule file parses")
        .evaluate(&bucket_template())
        .expect("evaluates")
}

fn paths(findings: &[GuardFinding]) -> Vec<Option<&str>> {
    findings.iter().map(|finding| finding.path.as_deref()).collect()
}

#[test]
fn parse_records_rule_names_and_first_custom_message() {
    let file = GuardRuleFile::parse(
        "security-policies/elb-listener.guard",
        r#"
let elbs = Resources.*[ Type == 'AWS::ElasticLoadBalancingV2::Listener' ]

rule ensure_all_elbs_are_secure when %elbs !empty {
    %elbs.Properties {
        Protocol in ["HTTPS", "TLS"]
        <<listeners must use a secure protocol>>
        Certificates !empty
    }
}

rule ensure_elbs_are_internal when %elbs !empty {
    %elbs.Properties.Scheme == 'internal'
}
"#,
    )
    .unwrap();
    assert_eq!(file.name(), "security-policies/elb-listener.guard");
    assert_eq!(file.pack(), "elb_listener");
    assert_eq!(
        file.rules(),
        &[
            GuardRuleInfo {
                name: "ensure_all_elbs_are_secure".into(),
                custom_message: Some("listeners must use a secure protocol".into()),
            },
            GuardRuleInfo { name: "ensure_elbs_are_internal".into(), custom_message: None },
        ]
    );
}

#[test]
fn parse_records_the_custom_message_of_a_type_block_check() {
    let file = GuardRuleFile::parse(
        "s3.guard",
        r#"
rule check_bucket_name {
    AWS::S3::Bucket {
        Properties.BucketName EXISTS
        <<BucketName must be specified>>
    }
}
"#,
    )
    .unwrap();
    assert_eq!(file.rules()[0].custom_message.as_deref(), Some("BucketName must be specified"));
}

#[test]
fn parse_accepts_an_empty_file_with_no_rules() {
    let file = GuardRuleFile::parse("empty.guard", "").unwrap();
    assert!(file.rules().is_empty());
    assert!(file.evaluate(&bucket_template()).unwrap().is_empty());
}

#[test]
fn parse_reports_a_syntax_error_with_the_file_name() {
    let error = GuardRuleFile::parse("broken.guard", "rule { this is not guard").unwrap_err();
    assert!(error.contains("broken.guard"), "error must name the file, got: {error}");
    assert!(error.contains("Failed to parse"), "error must say parsing failed, got: {error}");
}

#[test]
fn pack_name_from_path_strips_directory_and_extension() {
    assert_eq!(pack_name_from_path("security-policies/elb-listener.guard"), "elb_listener");
    assert_eq!(pack_name_from_path("s3.guard"), "s3");
    assert_eq!(pack_name_from_path("rules/pack.ruleset"), "pack");
}

#[test]
fn load_guard_sources_recursive_finds_files_in_subdirectories_sorted_by_path() {
    let dir = env::temp_dir().join("guard_translator_recursive_test");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("nested")).unwrap();
    fs::write(dir.join("b.guard"), "rule b { true }").unwrap();
    fs::write(dir.join("nested/a.guard"), "rule a { true }").unwrap();
    fs::write(dir.join("ignored.txt"), "not a rule").unwrap();

    let sources = load_guard_sources_recursive(dir.to_str().unwrap()).unwrap();

    let names: Vec<&str> = sources.iter().map(|(path, _)| path.rsplit('/').next().unwrap()).collect();
    assert_eq!(names, vec!["b.guard", "a.guard"], "only .guard files, in path order");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn load_guard_sources_recursive_errors_on_nonexistent_path() {
    let error = load_guard_sources_recursive("/nonexistent/guard/rules").unwrap_err();
    assert!(error.contains("not found"), "got: {error}");
}

#[test]
fn exists_fails_only_where_the_property_is_missing() {
    let findings = evaluate(
        r#"
rule bucket_name {
    AWS::S3::Bucket {
        Properties.BucketName EXISTS
        <<BucketName must be specified>>
    }
}
"#,
    );
    assert_eq!(paths(&findings), vec![Some("Resources/NoProps"), Some("Resources/Missing/Properties")]);
    assert_eq!(findings[0].missing_query.as_deref(), Some("Properties.BucketName"));
    assert_eq!(findings[1].missing_query.as_deref(), Some("BucketName"));
    for finding in &findings {
        assert_eq!(finding.rule_name, "bucket_name");
        assert_eq!(finding.custom_message.as_deref(), Some("BucketName must be specified"));
        assert_eq!(finding.check, "Properties.BucketName EXISTS");
    }
}

#[test]
fn equality_fails_for_missing_mismatched_and_intrinsic_values_with_the_value_path() {
    let findings = evaluate(
        r#"
rule bucket_name_is_foo {
    AWS::S3::Bucket {
        Properties.BucketName == "foo"
    }
}
"#,
    );
    assert_eq!(
        paths(&findings),
        vec![
            Some("Resources/NoProps"),
            Some("Resources/Missing/Properties"),
            Some("Resources/Present/Properties/BucketName"),
            Some("Resources/RefValue/Properties/BucketName"),
        ]
    );
    assert_eq!(findings[2].missing_query, None, "a present value has no missing remainder");
    assert_eq!(findings[2].custom_message, None);
    assert_eq!(findings[2].check, r#"Properties.BucketName EQUALS "foo""#);
}

#[test]
fn negated_type_and_existence_checks_pass_for_missing_properties() {
    let findings = evaluate(
        r#"
rule absent_is_fine {
    AWS::S3::Bucket {
        Properties.BucketName !EXISTS
        Properties.BucketName EMPTY
        Properties.BucketName !IS_STRING
    }
}
"#,
    );
    let mut failing = paths(&findings);
    failing.sort();
    assert_eq!(
        failing,
        vec![
            Some("Resources/Present/Properties/BucketName"),
            Some("Resources/Present/Properties/BucketName"),
            Some("Resources/Present/Properties/BucketName"),
            Some("Resources/RefValue/Properties/BucketName"),
            Some("Resources/RefValue/Properties/BucketName"),
        ],
        "only buckets that have a name fail; the literal fails all three checks while the \
         parameter reference is a struct and so satisfies `!IS_STRING`"
    );
}

#[test]
fn list_wildcard_checks_every_element_and_the_some_keyword_needs_one() {
    let every = evaluate(
        r#"
rule tags_all_owner {
    AWS::S3::Bucket {
        Properties.Tags[*].Key == "Owner"
    }
}
"#,
    );
    assert_eq!(
        paths(&every),
        vec![
            Some("Resources/NoProps"),
            Some("Resources/Missing/Properties/Tags/0/Key"),
            Some("Resources/RefValue/Properties")
        ]
    );

    let some = evaluate(
        r#"
rule some_tag_is_owner {
    AWS::S3::Bucket {
        some Properties.Tags[*].Key == "Owner"
    }
}
"#,
    );
    assert_eq!(
        paths(&some),
        vec![
            Some("Resources/NoProps"),
            Some("Resources/Missing/Properties/Tags/0/Key"),
            Some("Resources/RefValue/Properties")
        ]
    );
}

#[test]
fn regex_and_type_mismatch_follow_guard_semantics() {
    let findings = evaluate(
        r#"
rule name_prefix {
    AWS::S3::Bucket {
        Properties.BucketName == /^ba/
    }
}
rule port_is_large {
    AWS::S3::Bucket {
        Properties.Port > 1024
    }
}
"#,
    );
    let prefix: Vec<_> = findings.iter().filter(|f| f.rule_name == "name_prefix").collect();
    assert_eq!(
        paths(&prefix.iter().map(|f| (*f).clone()).collect::<Vec<_>>()),
        vec![
            Some("Resources/NoProps"),
            Some("Resources/Missing/Properties"),
            Some("Resources/RefValue/Properties/BucketName")
        ],
        "the literal name `bar` matches the regex; missing and intrinsic values fail"
    );
    let port: Vec<_> = findings.iter().filter(|f| f.rule_name == "port_is_large").collect();
    assert!(
        port.iter().any(|f| f.path.as_deref() == Some("Resources/Present/Properties/Port")),
        "comparing the string `abc` with a number must fail rather than be skipped"
    );
}

#[test]
fn when_condition_that_does_not_match_skips_the_check() {
    let findings = evaluate(
        r#"
rule port_required_for_bar {
    AWS::S3::Bucket {
        when Properties.BucketName == "bar" {
            Properties.Port EXISTS
        }
    }
}
rule owner_required_for_bar {
    AWS::S3::Bucket {
        when Properties.BucketName == "bar" {
            Properties.Owner EXISTS
        }
    }
}
"#,
    );
    assert_eq!(
        paths(&findings),
        vec![Some("Resources/Present/Properties")],
        "only the bucket named `bar` is checked, and only for the property it lacks"
    );
    assert_eq!(findings[0].rule_name, "owner_required_for_bar");
    assert_eq!(findings[0].missing_query.as_deref(), Some("Owner"));
}

#[test]
fn or_alternatives_yield_one_finding_naming_every_alternative() {
    let findings = evaluate(
        r#"
rule foo_or_bar {
    AWS::S3::Bucket {
        Properties.BucketName == "foo" OR Properties.BucketName == "baz"
        <<name must be foo or baz>>
    }
}
"#,
    );
    assert_eq!(
        paths(&findings),
        vec![
            Some("Resources/NoProps"),
            Some("Resources/Missing/Properties"),
            Some("Resources/Present/Properties/BucketName"),
            Some("Resources/RefValue/Properties/BucketName"),
        ],
        "one finding per resource, not one per alternative"
    );
    assert_eq!(findings[2].check, r#"Properties.BucketName EQUALS "foo" OR Properties.BucketName EQUALS "baz""#);
    assert_eq!(findings[2].custom_message.as_deref(), Some("name must be foo or baz"));
}

#[test]
fn block_clause_reports_the_missing_block_query_and_failing_elements() {
    let findings = evaluate(
        r#"
rule tag_keys {
    AWS::S3::Bucket {
        Properties.Tags[*] {
            Key == "Owner"
            <<tag key must be Owner>>
        }
    }
}
"#,
    );
    assert_eq!(
        paths(&findings),
        vec![
            Some("Resources/NoProps"),
            Some("Resources/Missing/Properties/Tags/0/Key"),
            Some("Resources/RefValue/Properties")
        ]
    );
    assert_eq!(findings[0].missing_query.as_deref(), Some("Properties.Tags[*]"));
    assert_eq!(findings[0].check, "Properties.Tags[*]");
    assert_eq!(findings[1].custom_message.as_deref(), Some("tag key must be Owner"));
    assert_eq!(findings[1].check, r#"Key EQUALS "Owner""#);
}

#[test]
fn variable_scoped_rules_and_named_rule_dependencies_are_evaluated() {
    let findings = evaluate(
        r#"
let buckets = Resources.*[ Type == 'AWS::S3::Bucket' ]

rule named_buckets when %buckets !empty {
    %buckets.Properties.BucketName EXISTS
    <<via variable>>
}

rule depends_on_named_buckets {
    named_buckets <<depends on named_buckets>>
}
"#,
    );
    let via_variable: Vec<_> = findings.iter().filter(|f| f.rule_name == "named_buckets").collect();
    assert_eq!(via_variable.len(), 2, "the two unnamed buckets fail the variable-scoped rule");
    assert!(via_variable.iter().all(|f| f.custom_message.as_deref() == Some("via variable")));

    let dependent: Vec<_> = findings.iter().filter(|f| f.rule_name == "depends_on_named_buckets").collect();
    assert_eq!(dependent.len(), 1);
    assert_eq!(dependent[0].path, None, "a failed rule dependency has no template location");
    assert_eq!(dependent[0].custom_message.as_deref(), Some("depends on named_buckets"));
}

#[test]
fn guard_functions_and_let_bindings_inside_blocks_evaluate() {
    let findings = evaluate(
        r#"
rule at_least_two_tags {
    AWS::S3::Bucket {
        when Properties.Tags EXISTS {
            let tag_count = count(Properties.Tags[*])
            %tag_count >= 2
            <<buckets need at least two tags>>
        }
    }
}
"#,
    );
    assert_eq!(findings.len(), 2, "both tagged buckets have a single tag");
    assert!(findings.iter().all(|f| f.custom_message.as_deref() == Some("buckets need at least two tags")));
}

#[test]
fn compliant_template_produces_no_findings() {
    let findings = GuardRuleFile::parse(
        "checks.guard",
        r#"
rule bucket_name {
    AWS::S3::Bucket {
        Properties.BucketName EXISTS
    }
}
"#,
    )
    .unwrap()
    .evaluate(&json!({"Resources": {"B": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "x"}}}}))
    .unwrap();
    assert!(findings.is_empty(), "got: {findings:?}");
}

#[test]
fn template_without_matching_resources_produces_no_findings() {
    let findings = GuardRuleFile::parse(
        "checks.guard",
        r#"
rule bucket_name {
    AWS::S3::Bucket {
        Properties.BucketName EXISTS
    }
}
"#,
    )
    .unwrap()
    .evaluate(&json!({"Resources": {"Q": {"Type": "AWS::SQS::Queue"}}}))
    .unwrap();
    assert!(findings.is_empty(), "a type block over an absent type is skipped, got: {findings:?}");
}
