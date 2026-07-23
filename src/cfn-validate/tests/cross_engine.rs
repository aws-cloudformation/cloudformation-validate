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
    let sv = SchemaValidator::new();
    let bytes = load_template(template);
    validate_bytes(engine, &sv, &bytes, Default::default()).unwrap().diagnostics
}

fn validate_template_with_config(
    engine: &dyn ValidationEngine,
    template: &str,
    config: ValidateConfig,
) -> Vec<Diagnostic> {
    let sv = SchemaValidator::new();
    let bytes = load_template(template);
    validate_bytes(engine, &sv, &bytes, config).unwrap().diagnostics
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
    assert_list_rules_identical(&CEL.list_rules(), &REGO.list_rules(), "default");

    let builtin_count = CEL.list_rules().len();
    assert!(builtin_count > 0, "must have built-in rules");
    assert_eq!(builtin_count, RULE_REGISTRY.len(), "engine rule count must match registry");
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
        "{label}: entry count differs — cel={} rego={}",
        cel_meta.len(),
        rego_meta.len()
    );
    for (id, cel_entry) in cel_meta {
        let rego_entry = rego_meta.get(id).unwrap_or_else(|| panic!("{label}: rule {id} in cel but not rego"));
        assert_eq!(
            cel_entry, rego_entry,
            "{label}: rule {id} metadata differs — cel={cel_entry:?} rego={rego_entry:?}"
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
fn good_templates_produce_no_fatal_or_error_diagnostics() {
    let new_rule_ids: std::collections::HashSet<&str> = [
        "E1002", "E1005", "E1015", "E1016", "E1027", "F1030", "F1031", "F1032", "E1033", "E1051", "E1052", "E3011",
        "E3023", "E3026", "E3027", "E3029", "E3062", "E3617", "E3620", "E3621", "E3647", "E3672", "E3694", "E3640",
        "E3642", "E3643", "E3644", "E3652", "E3653", "I2003", "W3002", "W3037", "W3660", "W3664", "W3671", "W3688",
        "W3689", "W3693", "W3694", "W3698",
    ]
    .into_iter()
    .collect();

    let sv = SchemaValidator::new();
    let root = common::templates_dir().join("good");
    let mut failures = Vec::new();
    for (engine_name, engine) in [("cel", &*CEL as &dyn ValidationEngine), ("rego", &*REGO as &dyn ValidationEngine)] {
        for entry in walkdir(&root) {
            let bytes = std::fs::read(&entry).unwrap();
            let report = match validate_bytes(engine, &sv, &bytes, Default::default()) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let bad: Vec<_> = report
                .diagnostics
                .iter()
                .filter(|d| new_rule_ids.contains(d.rule_id.as_str()))
                .filter(|d| matches!(d.severity, Severity::Fatal | Severity::Error))
                .map(|d| format!("  {} {}: {}", d.rule_id, d.severity, d.message))
                .collect();
            if !bad.is_empty() {
                let name = entry.strip_prefix(&root).unwrap_or(&entry);
                failures.push(format!("[{engine_name}] {}:\n{}", name.display(), bad.join("\n")));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "Good templates produced Fatal/Error diagnostics from new rules:\n{}",
        failures.join("\n\n")
    );
}

/// Every `good/sam` template must be clean of Fatal/Error diagnostics on both
/// engines: these are the counter-examples proving the SAM transform-error and
/// implicit-resource handling does not false-positive on valid templates.
#[test]
fn good_sam_templates_are_clean_on_both_engines() {
    let sv = SchemaValidator::new();
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
/// missing-transform rule (E3038) — the engines stay at parity on SAM handling.
#[test]
fn bad_sam_templates_fire_identically_on_both_engines() {
    let sv = SchemaValidator::new();
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
    let sv = SchemaValidator::new();
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
