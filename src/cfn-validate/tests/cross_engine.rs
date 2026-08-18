mod common;

use cel_engine::CelEngine;
use common::{load_rule, load_template};
use diagnostics::Diagnostic;
use rego_engine::RegoEngine;
use rules::registry::RULE_REGISTRY;
use rules::{FilterConfig, RuleFilterConfig};
use rules::{RuleInfo, RuleMetadataEntry, RuleOrigin, Severity};
use schema_validator::SchemaValidator;
use std::sync::LazyLock;
use validation_engine::{EngineConfig, ExternalRuleSource, ValidateConfig, ValidationEngine, validate_bytes};

static REGO: LazyLock<RegoEngine> = LazyLock::new(|| RegoEngine::new(EngineConfig::default()).unwrap());
static CEL: LazyLock<CelEngine> = LazyLock::new(|| CelEngine::new(EngineConfig::default()).unwrap());

fn assert_list_rules_identical(cel_rules: &[RuleInfo], rego_rules: &[RuleInfo], label: &str) {
    let cel_json = serde_json::to_value(cel_rules).expect("serialize cel rules");
    let rego_json = serde_json::to_value(rego_rules).expect("serialize rego rules");
    assert_eq!(cel_json, rego_json, "{label}: listRules differ between engines");
}

fn find_rule<'a>(rules: &'a [RuleInfo], id: &str) -> &'a RuleInfo {
    rules.iter().find(|r| r.id == id).unwrap_or_else(|| panic!("rule {id} not found in listRules"))
}

fn validate_template(engine: &dyn ValidationEngine, template: &str) -> Vec<Diagnostic> {
    let sv = SchemaValidator::default();
    let bytes = load_template(template);
    validate_bytes(engine, &sv, &bytes, Default::default()).unwrap().diagnostics
}

fn validate_template_with_config(
    engine: &dyn ValidationEngine,
    template: &str,
    config: ValidateConfig,
) -> Vec<Diagnostic> {
    let sv = SchemaValidator::default();
    let bytes = load_template(template);
    validate_bytes(engine, &sv, &bytes, config).unwrap().diagnostics
}

/// A length constraint is only reported broken when it is broken whichever value
/// the deployment picks, and both engines must reach that conclusion from the same
/// evidence. Before both engines shared one estimate they disagreed here: one
/// reported a length taken from an internal placeholder while the other stayed
/// silent, and neither outcome came from what the template would actually deploy.
#[test]
fn string_length_findings_are_identical_between_engines() {
    for template in ["bad/W9006_every_allowed_value_too_long.json", "good/string_length_unknowable_values.json"] {
        let rego = validate_template(&*REGO, template);
        let cel = validate_template(&*CEL, template);
        let findings = |diags: &[Diagnostic]| -> Vec<String> {
            let mut messages: Vec<String> =
                diags.iter().filter(|d| d.rule_id == "W9006").map(|d| d.message.clone()).collect();
            messages.sort();
            messages
        };
        assert_eq!(findings(&rego), findings(&cel), "{template}: engines disagree on W9006");
    }
}

/// The estimate may only cite a length some deployment actually produces.
#[test]
fn string_length_is_reported_only_when_every_possible_value_breaks_it() {
    let expected = "String length 78 exceeds maximum 63 for property 'BucketName'";
    for (engine_name, diags) in [
        ("rego", validate_template(&*REGO, "bad/W9006_every_allowed_value_too_long.json")),
        ("cel", validate_template(&*CEL, "bad/W9006_every_allowed_value_too_long.json")),
    ] {
        let messages: Vec<&str> = diags.iter().filter(|d| d.rule_id == "W9006").map(|d| d.message.as_str()).collect();
        assert_eq!(messages, vec![expected], "[{engine_name}] every allowed value is too long, so W9006 stands");
    }

    for (engine_name, diags) in [
        ("rego", validate_template(&*REGO, "good/string_length_unknowable_values.json")),
        ("cel", validate_template(&*CEL, "good/string_length_unknowable_values.json")),
    ] {
        let messages: Vec<&str> = diags.iter().filter(|d| d.rule_id == "W9006").map(|d| d.message.as_str()).collect();
        assert!(
            messages.is_empty(),
            "[{engine_name}] no length is known for every possible value, so nothing may be reported: {messages:?}"
        );
    }
}

#[test]
fn duplicate_objects_are_compared_by_contents_in_both_engines() {
    let template = "bad/W9007_duplicate_objects_different_key_order.yaml";
    for (engine_name, diags) in
        [("rego", validate_template(&*REGO, template)), ("cel", validate_template(&*CEL, template))]
    {
        let findings: Vec<&Diagnostic> = diags.iter().filter(|d| d.rule_id == "W9007").collect();
        assert_eq!(findings.len(), 1, "[{engine_name}] equal object items must remain a duplicate");
        assert_eq!(findings[0].property_path.as_deref(), Some("Properties.PlacementConstraints"));
    }
}

fn custom_config(engine: &str) -> EngineConfig {
    let (name, content) = if engine == "rego" {
        ("rego_custom.rego", load_rule("rego_custom.rego"))
    } else {
        ("cel_custom.json", load_rule("cel_custom.json"))
    };
    EngineConfig {
        custom_rules: vec![ExternalRuleSource { name: name.into(), content }],
        guard_rules: vec![],
        ..Default::default()
    }
}

fn arbitrary_id_config(engine: &str) -> EngineConfig {
    let (name, content) = if engine == "rego" {
        ("rego_arbitrary_id.rego", load_rule("rego_arbitrary_id.rego"))
    } else {
        ("cel_arbitrary_id.json", load_rule("cel_arbitrary_id.json"))
    };
    EngineConfig {
        custom_rules: vec![ExternalRuleSource { name: name.into(), content }],
        guard_rules: vec![],
        ..Default::default()
    }
}

fn guard_config() -> EngineConfig {
    EngineConfig {
        custom_rules: vec![],
        guard_rules: vec![ExternalRuleSource {
            name: "guard_encryption.guard".into(),
            content: load_rule("guard_encryption.guard"),
        }],
        ..Default::default()
    }
}

fn single_combined_config(engine: &str) -> EngineConfig {
    let (name, content) = if engine == "rego" {
        ("rego_custom.rego", load_rule("rego_custom.rego"))
    } else {
        ("cel_custom.json", load_rule("cel_custom.json"))
    };
    EngineConfig {
        custom_rules: vec![ExternalRuleSource { name: name.into(), content }],
        guard_rules: vec![ExternalRuleSource {
            name: "guard_encryption.guard".into(),
            content: load_rule("guard_encryption.guard"),
        }],
        ..Default::default()
    }
}

fn multi_combined_config(engine: &str) -> EngineConfig {
    let (name, content) = if engine == "rego" {
        ("rego_multi_custom.rego", load_rule("rego_multi_custom.rego"))
    } else {
        ("cel_multi_custom.json", load_rule("cel_multi_custom.json"))
    };
    EngineConfig {
        custom_rules: vec![ExternalRuleSource { name: name.into(), content }],
        guard_rules: vec![
            ExternalRuleSource { name: "guard_encryption.guard".into(), content: load_rule("guard_encryption.guard") },
            ExternalRuleSource { name: "guard_multi.guard".into(), content: load_rule("guard_multi.guard") },
        ],
        ..Default::default()
    }
}

#[test]
fn default_list_rules_identical_between_engines() {
    let rules = CEL.list_rules();
    assert_list_rules_identical(&rules, &REGO.list_rules(), "default");

    let builtin_count = rules.len();
    assert!(builtin_count > 0, "must have built-in rules");
    assert_eq!(builtin_count, RULE_REGISTRY.len(), "engine rule count must match registry");
    assert!(rules.iter().any(|rule| rule.id == "E3510"), "active IAM policy rule must be advertised");
    for dead_id in ["E9005", "E3514", "W3515"] {
        assert!(!rules.iter().any(|rule| rule.id == dead_id), "dead IAM rule {dead_id} must not be advertised");
    }
}

#[test]
fn custom_rule_list_rules_and_validate_match_between_engines() {
    let cel = CelEngine::new(custom_config("cel")).unwrap();
    let rego = RegoEngine::new(custom_config("rego")).unwrap();
    validate_template(&rego, "bad/invalid_deletion_policy.yaml");

    let baseline_count = CEL.list_rules().len();
    for (name, rules) in [("cel", cel.list_rules()), ("rego", rego.list_rules())] {
        let c = find_rule(&rules, "CUSTOM001");
        assert_eq!(c.severity, Severity::Error, "{name}: CUSTOM001 severity");
        assert_eq!(c.origin, RuleOrigin::Custom, "{name}: CUSTOM001 origin");
        assert_eq!(c.description, "S3 bucket must have encryption configured", "{name}: CUSTOM001 description");

        let builtin_count = rules.iter().filter(|r| r.origin != RuleOrigin::Custom).count();
        assert_eq!(builtin_count, baseline_count, "{name}: custom must not pollute builtins");
    }

    assert_list_rules_identical(&cel.list_rules(), &rego.list_rules(), "custom");

    for (name, diags) in [
        ("cel", validate_template(&cel, "bad/invalid_deletion_policy.yaml")),
        ("rego", validate_template(&rego, "bad/invalid_deletion_policy.yaml")),
    ] {
        let d = diags
            .iter()
            .find(|d| d.rule_id == "CUSTOM001")
            .unwrap_or_else(|| panic!("{name}: CUSTOM001 diagnostic must fire"));
        assert_eq!(d.severity, Severity::Error, "{name}: diagnostic severity");
        assert_eq!(d.resource_logical_id(), Some("Bucket"), "{name}: resource_id");
        assert_eq!(
            d.entity.as_ref().and_then(|e| e.resource_type.as_deref()),
            Some("AWS::S3::Bucket"),
            "{name}: resource_type"
        );
    }
}

#[test]
fn arbitrary_f_prefixed_custom_id_keeps_declared_severity_in_both_engines() {
    // A custom rule ID is arbitrary (here: `Firewall.check-1`, WARN). The built-in
    // `F`-prefix→Fatal heuristic must NOT apply to it, and both engines must agree.
    let cel = CelEngine::new(arbitrary_id_config("cel")).unwrap();
    let rego = RegoEngine::new(arbitrary_id_config("rego")).unwrap();

    for (name, engine) in [("cel", &cel as &dyn ValidationEngine), ("rego", &rego as &dyn ValidationEngine)] {
        let diags = validate_template(engine, "bad/invalid_deletion_policy.yaml");
        let d = diags
            .iter()
            .find(|d| d.rule_id == "Firewall.check-1")
            .unwrap_or_else(|| panic!("{name}: Firewall.check-1 diagnostic must fire"));
        assert_eq!(d.severity, Severity::Warn, "{name}: declared WARN must survive an F-prefixed ID (not Fatal)");
        assert_eq!(d.source, RuleOrigin::Custom, "{name}: source");
    }
}

#[test]
fn custom_rule_with_arbitrary_id_is_suppressed_by_exclude_ids_in_both_engines() {
    // An arbitrary custom ID must be filterable by exact-ID include/exclude filters
    // identically across engines.
    let cel = CelEngine::new(arbitrary_id_config("cel")).unwrap();
    let rego = RegoEngine::new(arbitrary_id_config("rego")).unwrap();

    let exclude_config = || ValidateConfig {
        filters: FilterConfig::new(
            RuleFilterConfig::default(),
            RuleFilterConfig { ids: vec!["Firewall.check-1".into()], ..Default::default() },
        ),
        ..Default::default()
    };

    for (name, engine) in [("cel", &cel as &dyn ValidationEngine), ("rego", &rego as &dyn ValidationEngine)] {
        // Without a filter the rule fires.
        let unfiltered = validate_template(engine, "bad/invalid_deletion_policy.yaml");
        assert!(unfiltered.iter().any(|d| d.rule_id == "Firewall.check-1"), "{name}: rule must fire before filtering");
        // --exclude-ids on the arbitrary ID suppresses it.
        let filtered = validate_template_with_config(engine, "bad/invalid_deletion_policy.yaml", exclude_config());
        assert!(
            !filtered.iter().any(|d| d.rule_id == "Firewall.check-1"),
            "{name}: exclude-ids must suppress the arbitrary custom ID"
        );
    }
}

#[test]
fn guard_rule_list_rules_and_validate_match_between_engines() {
    let cel = CelEngine::new(guard_config()).unwrap();
    let rego = RegoEngine::new(guard_config()).unwrap();

    let baseline_count = CEL.list_rules().len();
    for (name, rules) in [("cel", cel.list_rules()), ("rego", rego.list_rules())] {
        let g = find_rule(&rules, "check_bucket_encryption");
        assert_eq!(g.severity, Severity::Error, "{name}: check_bucket_encryption severity");
        assert_eq!(g.origin, RuleOrigin::Guard, "{name}: check_bucket_encryption origin");
        assert_eq!(
            g.description, "S3 bucket must have encryption configured",
            "{name}: check_bucket_encryption description"
        );

        let builtin_count = rules.iter().filter(|r| r.origin != RuleOrigin::Guard).count();
        assert_eq!(builtin_count, baseline_count, "{name}: guard must not pollute builtins");
    }

    assert_list_rules_identical(&cel.list_rules(), &rego.list_rules(), "guard");

    for (name, diags) in [
        ("cel", validate_template(&cel, "bad/invalid_deletion_policy.yaml")),
        ("rego", validate_template(&rego, "bad/invalid_deletion_policy.yaml")),
    ] {
        let d = diags
            .iter()
            .find(|d| d.rule_id == "check_bucket_encryption")
            .unwrap_or_else(|| panic!("{name}: check_bucket_encryption diagnostic must fire"));
        assert_eq!(d.severity, Severity::Error, "{name}: diagnostic severity");
        assert_eq!(d.source, RuleOrigin::Guard, "{name}: diagnostic source");
        assert_eq!(d.resource_logical_id(), Some("Bucket"), "{name}: resource_id");
    }
}

#[test]
fn single_combined_list_rules_and_validate_match_between_engines() {
    let cel = CelEngine::new(single_combined_config("cel")).unwrap();
    let rego = RegoEngine::new(single_combined_config("rego")).unwrap();
    validate_template(&rego, "bad/invalid_deletion_policy.yaml");

    for (name, rules) in [("cel", cel.list_rules()), ("rego", rego.list_rules())] {
        let c = find_rule(&rules, "CUSTOM001");
        assert_eq!(c.origin, RuleOrigin::Custom, "{name}: CUSTOM001 origin");

        let g = find_rule(&rules, "check_bucket_encryption");
        assert_eq!(g.origin, RuleOrigin::Guard, "{name}: check_bucket_encryption origin");

        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "{name}: rules must be sorted");
    }

    assert_list_rules_identical(&cel.list_rules(), &rego.list_rules(), "single_combined");
}

#[test]
fn multi_combined_list_rules_and_validate_match_between_engines() {
    let cel = CelEngine::new(multi_combined_config("cel")).unwrap();
    let rego = RegoEngine::new(multi_combined_config("rego")).unwrap();
    validate_template(&rego, "bad/invalid_deletion_policy.yaml");

    for (name, rules) in [("cel", cel.list_rules()), ("rego", rego.list_rules())] {
        let c1 = find_rule(&rules, "CUSTOM010");
        assert_eq!(c1.severity, Severity::Error, "{name}: CUSTOM010 severity");
        assert_eq!(c1.origin, RuleOrigin::Custom, "{name}: CUSTOM010 origin");
        assert_eq!(c1.description, "S3 bucket must have versioning enabled", "{name}: CUSTOM010 description");

        let c2 = find_rule(&rules, "CUSTOM011");
        assert_eq!(c2.severity, Severity::Warn, "{name}: CUSTOM011 severity");
        assert_eq!(c2.origin, RuleOrigin::Custom, "{name}: CUSTOM011 origin");
        assert_eq!(c2.description, "S3 bucket should have lifecycle rules configured", "{name}: CUSTOM011 description");

        let enc = find_rule(&rules, "check_bucket_encryption");
        assert_eq!(enc.origin, RuleOrigin::Guard, "{name}: check_bucket_encryption origin");
        assert_eq!(
            enc.description, "S3 bucket must have encryption configured",
            "{name}: check_bucket_encryption description"
        );

        let ver = find_rule(&rules, "check_bucket_versioning");
        assert_eq!(ver.origin, RuleOrigin::Guard, "{name}: check_bucket_versioning origin");
        assert_eq!(
            ver.description, "S3 bucket must have versioning enabled",
            "{name}: check_bucket_versioning description"
        );

        let lc = find_rule(&rules, "check_bucket_lifecycle");
        assert_eq!(lc.origin, RuleOrigin::Guard, "{name}: check_bucket_lifecycle origin");
        assert_eq!(
            lc.description, "S3 bucket should have lifecycle rules configured",
            "{name}: check_bucket_lifecycle description"
        );

        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "{name}: rules must be sorted");
    }

    assert_list_rules_identical(&cel.list_rules(), &rego.list_rules(), "multi_combined");
}

fn assert_metadata_maps_identical(
    cel_meta: &std::collections::HashMap<String, RuleMetadataEntry>,
    rego_meta: &std::collections::HashMap<String, RuleMetadataEntry>,
    label: &str,
) {
    assert_eq!(
        cel_meta.len(),
        rego_meta.len(),
        "{label}: entry count differs - cel={} rego={}",
        cel_meta.len(),
        rego_meta.len()
    );
    for (id, cel_entry) in cel_meta {
        let rego_entry = rego_meta.get(id).unwrap_or_else(|| panic!("{label}: rule {id} in cel but not rego"));
        assert_eq!(
            cel_entry, rego_entry,
            "{label}: rule {id} metadata differs - cel={cel_entry:?} rego={rego_entry:?}"
        );
    }
    for id in rego_meta.keys() {
        assert!(cel_meta.contains_key(id), "{label}: rule {id} in rego but not cel");
    }
}

#[test]
fn default_rule_metadata_identical_between_engines() {
    let cel_meta = CEL.rule_metadata();
    let rego_meta = REGO.rule_metadata();

    // Assert expected shape: every entry has all fields populated
    for (id, entry) in cel_meta {
        assert!(entry.category.is_some(), "rule {id}: category must be present");
        assert!(!entry.description.is_empty(), "rule {id}: description must not be empty");
    }

    assert_metadata_maps_identical(cel_meta, rego_meta, "default rule_metadata");
}

#[test]
fn default_external_rule_metadata_identical_between_engines() {
    let cel_ext = CEL.external_rule_metadata();
    let rego_ext = REGO.external_rule_metadata();
    assert_metadata_maps_identical(&cel_ext, &rego_ext, "default external_rule_metadata");
}

#[test]
fn custom_external_rule_metadata_identical_between_engines() {
    let cel = CelEngine::new(single_combined_config("cel")).unwrap();
    let rego = RegoEngine::new(single_combined_config("rego")).unwrap();
    // Trigger rego metadata discovery by evaluating
    validate_template(&rego, "bad/invalid_deletion_policy.yaml");

    let cel_ext = cel.external_rule_metadata();
    let rego_ext = rego.external_rule_metadata();

    // Assert expected shape: custom and guard entries present with correct origins
    let custom_entry = cel_ext.get("CUSTOM001").expect("CUSTOM001 must be in external metadata");
    assert_eq!(custom_entry.severity, Severity::Error);
    assert_eq!(custom_entry.origin, RuleOrigin::Custom);
    assert_eq!(custom_entry.description, "S3 bucket must have encryption configured");

    let guard_entry =
        cel_ext.get("check_bucket_encryption").expect("check_bucket_encryption must be in external metadata");
    assert_eq!(guard_entry.severity, Severity::Error);
    assert_eq!(guard_entry.origin, RuleOrigin::Guard);
    assert_eq!(guard_entry.description, "S3 bucket must have encryption configured");

    assert_metadata_maps_identical(&cel_ext, &rego_ext, "custom external_rule_metadata");
}

#[test]
fn multi_combined_external_rule_metadata_identical_between_engines() {
    let cel = CelEngine::new(multi_combined_config("cel")).unwrap();
    let rego = RegoEngine::new(multi_combined_config("rego")).unwrap();
    validate_template(&rego, "bad/invalid_deletion_policy.yaml");

    let cel_ext = cel.external_rule_metadata();
    let rego_ext = rego.external_rule_metadata();

    // Assert expected shape: all custom and guard rules present
    for id in
        &["CUSTOM010", "CUSTOM011", "check_bucket_encryption", "check_bucket_versioning", "check_bucket_lifecycle"]
    {
        assert!(cel_ext.contains_key(*id), "cel external metadata missing {id}");
    }

    assert_metadata_maps_identical(&cel_ext, &rego_ext, "multi_combined external_rule_metadata");
}

#[test]
fn iam_action_resource_findings_target_authored_fields_in_both_engines() {
    let template = "bad/functions/sub_needed.yaml";
    for (engine_name, diagnostics) in
        [("rego", validate_template(&*REGO, template)), ("cel", validate_template(&*CEL, template))]
    {
        let findings: Vec<&Diagnostic> = diagnostics.iter().filter(|d| d.rule_id == "I3510").collect();
        assert_eq!(findings.len(), 2, "[{engine_name}] expected both incompatible IAM statements");
        assert!(
            findings.iter().any(|d| {
                d.property_path.as_deref() == Some("Properties.PolicyDocument.Statement.0.Resource")
                    && d.location.as_ref().is_some_and(|span| span.start_line == 25)
            }),
            "[{engine_name}] Resource finding should target line 25: {findings:?}"
        );
        assert!(
            findings.iter().any(|d| {
                d.property_path.as_deref() == Some("Properties.PolicyDocument.Statement.1.NotResource")
                    && d.location.as_ref().is_some_and(|span| span.start_line == 29)
            }),
            "[{engine_name}] NotResource finding should target line 29: {findings:?}"
        );
    }
}

const GOOD_FIXTURES_WITH_EXPECTED_ERRORS: &[&str] = &[
    "core/conditions.yaml",
    "core/config_cfn_lint.json",
    "core/config_cfn_lint.yaml",
    "core/config_only_i1002.yaml",
    "core/config_only_i1003.yaml",
    "core/config_parameters.yaml",
    "custom/is-defined.yaml",
    "custom/numeric-inequalities-large.yaml",
    "custom/numeric-inequalities-small.yaml",
    "decode/parsing.json",
    "functions/relationship_conditions.yaml",
    "functions/sub.yaml",
    "functions/sub_needed.yaml",
    "functions/sub_needed_custom_excludes.yaml",
    "functions_findinmap_enhanced.yaml",
    "mappings/name.yaml",
    "mappings/used.yaml",
    "parameters/default.yaml",
    "parameters/not_used_parameters.yaml",
    "parameters/used_transforms.yaml",
    "properties_ec2_vpc.yaml",
    "resources/cloudformation/stack_nested.yaml",
    "resources/dynamodb/attributes_transform.yaml",
    "resources/elasticache/cache_cluster_failover.yaml",
    "resources/iam/policy.yaml",
    "resources/name.yaml",
    "resources/properties/az_cdk.yaml",
    "resources/properties/exclusive.yaml",
    "resources/properties/list_duplicates.yaml",
    "some_logs_stream_lambda.yaml",
    "transform_serverless_globals.yaml",
    "transform_serverless_ignore_globals.yaml",
];

/// Fixtures in the exception list have exact Fatal/Error diagnostics protected
/// by golden tests; this complementary guard covers templates expected clean.
#[test]
fn good_templates_without_expected_errors_are_clean() {
    let sv = SchemaValidator::default();
    let root = common::templates_dir().join("good");
    let mut failures = Vec::new();
    for (engine_name, engine) in [("cel", &*CEL as &dyn ValidationEngine), ("rego", &*REGO as &dyn ValidationEngine)] {
        for entry in walkdir(&root) {
            let bytes = std::fs::read(&entry).unwrap();
            let name = entry.strip_prefix(&root).unwrap_or(&entry);
            let relative_name = name.to_string_lossy().replace('\\', "/");
            if GOOD_FIXTURES_WITH_EXPECTED_ERRORS.contains(&relative_name.as_str()) {
                continue;
            }
            let report = match validate_bytes(engine, &sv, &bytes, Default::default()) {
                Ok(r) => r,
                Err(e) => {
                    failures.push(format!("[{engine_name}] {}: validation error: {e}", name.display()));
                    continue;
                }
            };
            let bad: Vec<_> = report
                .diagnostics
                .iter()
                .filter(|d| matches!(d.severity, Severity::Fatal | Severity::Error))
                .map(|d| format!("  {} {}: {}", d.rule_id, d.severity, d.message))
                .collect();
            if !bad.is_empty() {
                failures.push(format!("[{engine_name}] {}:\n{}", name.display(), bad.join("\n")));
            }
        }
    }
    assert!(failures.is_empty(), "Good templates produced Fatal/Error diagnostics:\n{}", failures.join("\n\n"));
}

/// Every `good/sam` template must be clean of Fatal/Error diagnostics on both
/// engines: these are the counter-examples proving the SAM transform-error and
/// implicit-resource handling does not false-positive on valid templates.
#[test]
fn good_sam_templates_are_clean_on_both_engines() {
    let sv = SchemaValidator::default();
    let root = common::templates_dir().join("good").join("sam");
    let mut failures = Vec::new();
    for (engine_name, engine) in [("cel", &*CEL as &dyn ValidationEngine), ("rego", &*REGO as &dyn ValidationEngine)] {
        for entry in walkdir(&root) {
            let bytes = std::fs::read(&entry).unwrap();
            let report = validate_bytes(engine, &sv, &bytes, Default::default()).unwrap();
            let bad: Vec<_> = report
                .diagnostics
                .iter()
                .filter(|d| matches!(d.severity, Severity::Fatal | Severity::Error))
                .map(|d| format!("  {} {}: {}", d.rule_id, d.severity, d.message))
                .collect();
            if !bad.is_empty() {
                let name = entry.strip_prefix(&root).unwrap_or(&entry);
                failures.push(format!("[{engine_name}] {}:\n{}", name.display(), bad.join("\n")));
            }
        }
    }
    assert!(failures.is_empty(), "good/sam templates produced Fatal/Error diagnostics:\n{}", failures.join("\n\n"));
}

/// Every `bad/sam` template must produce identical diagnostics on both engines,
/// and each must fire the SAM transform-error rule (E0001) or the
/// missing-transform rule (E3038) - the engines stay at parity on SAM handling.
#[test]
fn bad_sam_templates_fire_identically_on_both_engines() {
    let sv = SchemaValidator::default();
    let root = common::templates_dir().join("bad").join("sam");
    for entry in walkdir(&root) {
        let bytes = std::fs::read(&entry).unwrap();
        let name = entry.strip_prefix(&root).unwrap_or(&entry).display().to_string();
        let ids = |engine: &dyn ValidationEngine| -> Vec<String> {
            let report = validate_bytes(engine, &sv, &bytes, Default::default()).unwrap();
            let mut out: Vec<String> = report
                .diagnostics
                .iter()
                .filter(|d| matches!(d.severity, Severity::Fatal | Severity::Error))
                .map(|d| format!("{}|{}", d.rule_id, d.message))
                .collect();
            out.sort();
            out
        };
        let cel_ids = ids(&*CEL);
        let rego_ids = ids(&*REGO);
        assert_eq!(cel_ids, rego_ids, "{name}: engines diverge");
        assert!(
            cel_ids.iter().any(|d| d.starts_with("E0001|") || d.starts_with("E3038|")),
            "{name}: expected a SAM transform error (E0001/E3038), got {cel_ids:?}"
        );
    }
}

#[test]
fn intrinsic_and_condition_fixtures_fire_identically_on_both_engines() {
    // The intrinsic/condition rules reworked to emit from the shared model must
    // produce byte-identical diagnostics on both engines. Assert full parity
    // (all severities) on the fixtures that exercise them.
    let sv = SchemaValidator::default();
    let fixtures = [
        "bad/E1050_dynamic_ref_malformed.yaml",
        "bad/W1051_secretsmanager_at_arn.yaml",
        "bad/W1054_raw_pseudo_param.yaml",
        "bad/E8007_condition_undefined_in_expr.yaml",
        "bad/E9106_condition_cycle.yaml",
        "bad/W9053_equivalent_conditions.yaml",
        "bad/W1019_sub_unused_key.yaml",
        "bad/W1053_dynref_spaces.yaml",
        "good/good_conditions_valid_refs.yaml",
    ];
    for name in fixtures {
        let bytes = load_template(name);
        let ids = |engine: &dyn ValidationEngine| -> Vec<String> {
            let report = validate_bytes(engine, &sv, &bytes, Default::default()).unwrap();
            let mut out: Vec<String> =
                report.diagnostics.iter().map(|d| format!("{}|{:?}|{}", d.rule_id, d.severity, d.message)).collect();
            out.sort();
            out
        };
        assert_eq!(ids(&*CEL), ids(&*REGO), "{name}: engines diverge");
    }
}

fn walkdir(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    walk_recursive(dir, &mut out);
    out.sort();
    out
}

fn walk_recursive(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_recursive(&path, out);
        } else if matches!(path.extension().and_then(|s| s.to_str()), Some("yaml" | "yml" | "json")) {
            out.push(path);
        }
    }
}

#[test]
fn standard_queue_names_respect_the_fifo_suffix_boundary() {
    let invalid = "bad/resources/sqs/standard_queue_fifo_suffix.yaml";
    let valid = "good/resources/sqs/standard_queue_name.yaml";
    let findings = |engine: &dyn ValidationEngine, template: &str| {
        validate_template(engine, template)
            .into_iter()
            .filter(|diagnostic| diagnostic.rule_id == "E3501")
            .collect::<Vec<_>>()
    };

    let rego_invalid = findings(&*REGO, invalid);
    let cel_invalid = findings(&*CEL, invalid);
    assert_eq!(rego_invalid.len(), 1);
    assert_eq!(rego_invalid[0].property_path.as_deref(), Some("Properties.QueueName"));
    assert_eq!(serde_json::to_value(&rego_invalid).unwrap(), serde_json::to_value(&cel_invalid).unwrap());

    assert!(findings(&*REGO, valid).is_empty());
    assert!(findings(&*CEL, valid).is_empty());
}

#[test]
fn obsolete_dependencies_anchor_each_array_entry() {
    let template = br#"
Resources:
  FirstTopic:
    Type: AWS::SNS::Topic
  SecondTopic:
    Type: AWS::SNS::Topic
  ConsumerTopic:
    Type: AWS::SNS::Topic
    DependsOn:
      - FirstTopic
      - SecondTopic
    Properties:
      DisplayName: !Sub "${FirstTopic}-${SecondTopic}"
"#;
    let schema_validator = SchemaValidator::default();
    let findings = |engine: &dyn ValidationEngine| {
        let report = validate_bytes(engine, &schema_validator, template, ValidateConfig::default()).unwrap();
        let mut diagnostics: Vec<Diagnostic> =
            report.diagnostics.into_iter().filter(|diagnostic| diagnostic.rule_id == "W3005").collect();
        diagnostics.sort_by(|left, right| left.property_path.cmp(&right.property_path));
        diagnostics
    };

    let rego = findings(&*REGO);
    let cel = findings(&*CEL);
    assert_eq!(
        rego.iter().filter_map(|diagnostic| diagnostic.property_path.as_deref()).collect::<Vec<_>>(),
        ["DependsOn.0", "DependsOn.1"]
    );
    assert_eq!(serde_json::to_value(&rego).unwrap(), serde_json::to_value(&cel).unwrap());
}

#[test]
fn nested_metadata_intrinsics_use_authored_source_locations() {
    let template = br#"Resources:
  R:
    Type: AWS::EC2::Instance
    Metadata:
      AWS::CloudFormation::Init:
        config:
          files:
            /etc/cfn/cfn-hup.conf:
              content: !Sub constant
            /etc/cfn/cfn-auto-reloader.conf:
              content: !Join ["", ["a", "b"]]
"#;
    let schema_validator = SchemaValidator::default();
    let findings = |engine: &dyn ValidationEngine| {
        let report = validate_bytes(engine, &schema_validator, template, ValidateConfig::default()).unwrap();
        let mut diagnostics: Vec<Diagnostic> = report
            .diagnostics
            .into_iter()
            .filter(|diagnostic| matches!(diagnostic.rule_id.as_str(), "W1020" | "I1022"))
            .collect();
        diagnostics.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
        diagnostics
    };

    let rego = findings(&*REGO);
    let cel = findings(&*CEL);
    assert_eq!(serde_json::to_value(&rego).unwrap(), serde_json::to_value(&cel).unwrap());
    assert_eq!(rego.len(), 2, "expected one finding for each redundant intrinsic: {rego:?}");
    assert_eq!(rego[0].rule_id, "I1022");
    assert_eq!(rego[0].location.as_ref().map(|location| location.start_line), Some(11));
    assert_eq!(rego[1].rule_id, "W1020");
    assert_eq!(rego[1].location.as_ref().map(|location| location.start_line), Some(9));
}

#[test]
fn dependency_diagnostics_preserve_authored_scalar_and_array_paths() {
    let template = br#"Resources:
  Existing:
    Type: AWS::SNS::Topic
  MissingArray:
    Type: AWS::SNS::Topic
    DependsOn:
      - NotPresentArray
  MissingScalar:
    Type: AWS::SNS::Topic
    DependsOn: NotPresentScalar
  RedundantArray:
    Type: AWS::SNS::Topic
    DependsOn:
      - Existing
    Properties:
      DisplayName: !Ref Existing
  RedundantScalar:
    Type: AWS::SNS::Topic
    DependsOn: Existing
    Properties:
      DisplayName: !Ref Existing
"#;
    let schema_validator = SchemaValidator::default();
    let findings = |engine: &dyn ValidationEngine| {
        let report = validate_bytes(engine, &schema_validator, template, ValidateConfig::default()).unwrap();
        let mut diagnostics: Vec<Diagnostic> = report
            .diagnostics
            .into_iter()
            .filter(|diagnostic| matches!(diagnostic.rule_id.as_str(), "E3005" | "W3005"))
            .collect();
        diagnostics.sort_by(|left, right| {
            left.entity
                .as_ref()
                .map(|entity| entity.logical_id.as_str())
                .cmp(&right.entity.as_ref().map(|entity| entity.logical_id.as_str()))
        });
        diagnostics
    };

    let rego = findings(&*REGO);
    let cel = findings(&*CEL);
    assert_eq!(serde_json::to_value(&rego).unwrap(), serde_json::to_value(&cel).unwrap());
    let identities: Vec<(&str, &str, &str)> = rego
        .iter()
        .map(|diagnostic| {
            (
                diagnostic.entity.as_ref().map(|entity| entity.logical_id.as_str()).unwrap_or_default(),
                diagnostic.rule_id.as_str(),
                diagnostic.property_path.as_deref().unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(
        identities,
        [
            ("MissingArray", "E3005", "DependsOn.0"),
            ("MissingScalar", "E3005", "DependsOn"),
            ("RedundantArray", "W3005", "DependsOn.0"),
            ("RedundantScalar", "W3005", "DependsOn"),
        ]
    );
}

#[test]
fn diagnostics_retain_precise_authored_member_paths() {
    let cases = [
        ("bad/E9001_unknown_resource_type.yaml", "F3006", "Mystery", "Type"),
        ("bad/sam/transform_bogus_name.yaml", "E3038", "MyFn", "Type"),
        ("bad/lambda_zipfile_java.yaml", "E3677", "LambdaFn", "Properties.Runtime"),
        ("bad/fargate_daemon.yaml", "E3052", "FargateDaemon", "Properties"),
        ("bad/findinmap_bad.yaml", "F1012", "Bucket", "Properties.Tags.0.Value.Fn::FindInMap.0"),
        (
            "bad/functions_getaz.yaml",
            "E9004",
            "mySubnet3",
            "Properties.AvailabilityZone.Fn::Select.1.Fn::GetAZs.Fn::GetAtt.1",
        ),
        (
            "bad/codepipeline_bad_artifacts.yaml",
            "E3701",
            "Pipeline",
            "Properties.Stages.1.Actions.0.InputArtifacts.0.Name",
        ),
        ("bad/codepipeline_bad_artifact_counts.yaml", "E3702", "Pipeline", "Properties.Stages.1.Actions.0"),
        ("bad/stepfunctions_bad_start_at.yaml", "E3601", "SM", "Properties.DefinitionString.StartAt"),
        ("bad/core/E3001_resource_shape.yaml", "E3001", "NumericType", "Type"),
        ("bad/undefined_condition.yaml", "E8002", "R", "Condition"),
        ("bad/lambda_snapstart_no_version.yaml", "W2530", "Func", "Properties.SnapStart.ApplyOn"),
        ("bad/cross_resource_task10.yaml", "E3663", "BadEnvLambda", "Properties.Environment.Variables.AWS_REGION"),
        (
            "bad/sagemaker_instance_types.yaml",
            "E3642",
            "InferenceExperiment",
            "Properties.ModelVariants.0.InfrastructureConfig.RealTimeInferenceConfig.InstanceType",
        ),
        (
            "bad/sagemaker_instance_types.yaml",
            "E3643",
            "ModelPackage",
            "Properties.ValidationSpecification.ValidationProfiles.0.TransformJobDefinition.TransformResources.InstanceType",
        ),
        ("bad/sagemaker_instance_types.yaml", "E3644", "Cluster", "Properties.InstanceGroups.0.InstanceType"),
    ];

    for (template, rule_id, resource_id, expected_path) in cases {
        let selected = |engine: &dyn ValidationEngine| {
            validate_template(engine, template)
                .into_iter()
                .filter(|diagnostic| {
                    diagnostic.rule_id == rule_id
                        && diagnostic.entity.as_ref().map(|entity| entity.logical_id.as_str()) == Some(resource_id)
                })
                .collect::<Vec<_>>()
        };
        let rego = selected(&*REGO);
        let cel = selected(&*CEL);
        assert_eq!(serde_json::to_value(&rego).unwrap(), serde_json::to_value(&cel).unwrap(), "{template}");
        assert!(
            rego.iter().any(|diagnostic| diagnostic.property_path.as_deref() == Some(expected_path)),
            "{template}: expected {rule_id} on {resource_id} at {expected_path}, got {rego:?}"
        );
    }
}

#[test]
fn output_intrinsics_use_authored_value_spans() {
    let findings = |engine: &dyn ValidationEngine, template: &str, rule_id: &str| {
        let mut diagnostics: Vec<Diagnostic> = validate_template(engine, template)
            .into_iter()
            .filter(|diagnostic| diagnostic.rule_id == rule_id)
            .collect();
        diagnostics.sort_by_key(|diagnostic| diagnostic.location.as_ref().map(|location| location.start_line));
        diagnostics
    };

    let rego_invalid = findings(&*REGO, "bad/output_invalid_references.yaml", "F6101");
    let cel_invalid = findings(&*CEL, "bad/output_invalid_references.yaml", "F6101");
    assert_eq!(serde_json::to_value(&rego_invalid).unwrap(), serde_json::to_value(&cel_invalid).unwrap());
    assert_eq!(
        rego_invalid
            .iter()
            .filter_map(|diagnostic| diagnostic.location.as_ref().map(|location| location.start_line))
            .collect::<Vec<_>>(),
        [7, 9]
    );

    let rego_joins = findings(&*REGO, "integration/getatt-types.yaml", "I1022");
    let cel_joins = findings(&*CEL, "integration/getatt-types.yaml", "I1022");
    assert_eq!(serde_json::to_value(&rego_joins).unwrap(), serde_json::to_value(&cel_joins).unwrap());
    assert_eq!(
        rego_joins
            .iter()
            .filter_map(|diagnostic| diagnostic.location.as_ref().map(|location| location.start_line))
            .collect::<Vec<_>>(),
        [91, 93]
    );
}
