mod common;

use cel_engine::CelEngine;
use common::{
    DETAILED_ONLY_DIAGNOSTIC_FIELDS, deep_diff, discover_all_templates, load_combined_golden,
    load_template, zero_durations,
};
use diagnostics::DetailLevel;
use rego_engine::RegoEngine;
use rules::Severity;
use schema_validator::SchemaValidator;
use validation_engine::{EngineConfig, ValidateConfig, validate_bytes_with_path};

fn validate_to_json(
    engine: &dyn validation_engine::ValidationEngine,
    bytes: &[u8],
    relative_path: &str,
    detail_level: DetailLevel,
) -> serde_json::Value {
    let sv = SchemaValidator::new();
    let mut config = ValidateConfig::default();
    config.detail_level = detail_level.clone();
    config.severity_level = Severity::Debug;
    let report = validate_bytes_with_path(engine, &sv, bytes, config, relative_path.to_string())
        .expect("validate");
    match detail_level {
        DetailLevel::Detailed => serde_json::to_value(report.to_detailed()).expect("serialize"),
        DetailLevel::Standard => serde_json::to_value(report.to_standard()).expect("serialize"),
    }
}

fn strip_detailed_only_fields(val: &mut serde_json::Value) {
    if let Some(diags) = val
        .as_object_mut()
        .and_then(|o| o.get_mut("diagnostics"))
        .and_then(|d| d.as_array_mut())
    {
        for diag in diags {
            if let Some(obj) = diag.as_object_mut() {
                for field in DETAILED_ONLY_DIAGNOSTIC_FIELDS {
                    obj.remove(*field);
                }
            }
        }
    }
}

fn check_detailed(engine_name: &str, engine: &dyn validation_engine::ValidationEngine) {
    let combined = load_combined_golden();
    let all_templates = discover_all_templates();
    let mut failures = Vec::new();
    let mut missing_goldens = Vec::new();

    for relative_path in &all_templates {
        let Some(golden) = combined.get(relative_path.as_str()) else {
            missing_goldens.push(relative_path.clone());
            continue;
        };
        let bytes = load_template(relative_path);
        let mut actual = validate_to_json(engine, &bytes, relative_path, DetailLevel::Detailed);
        zero_durations(&mut actual);

        let mut expected = golden.clone();
        zero_durations(&mut expected);

        let diffs = deep_diff(&expected, &actual, "");
        if !diffs.is_empty() {
            failures.push(format!(
                "{relative_path}:\n{}",
                diffs.iter().take(5).cloned().collect::<Vec<_>>().join("\n")
            ));
        }
    }

    assert!(
        missing_goldens.is_empty(),
        "{engine_name} detailed: {} template(s) missing from all_templates.json — run generate.py:\n{}",
        missing_goldens.len(),
        missing_goldens
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        failures.is_empty(),
        "{engine_name} detailed: {} template(s) differ from golden:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

fn check_standard(engine_name: &str, engine: &dyn validation_engine::ValidationEngine) {
    let combined = load_combined_golden();
    let all_templates = discover_all_templates();
    let mut failures = Vec::new();
    let mut missing_goldens = Vec::new();

    for relative_path in &all_templates {
        let Some(golden) = combined.get(relative_path.as_str()) else {
            missing_goldens.push(relative_path.clone());
            continue;
        };
        let bytes = load_template(relative_path);
        let mut actual = validate_to_json(engine, &bytes, relative_path, DetailLevel::Standard);
        zero_durations(&mut actual);

        let mut expected = golden.clone();
        zero_durations(&mut expected);
        strip_detailed_only_fields(&mut expected);

        let diffs = deep_diff(&expected, &actual, "");
        if !diffs.is_empty() {
            failures.push(format!(
                "{relative_path}:\n{}",
                diffs.iter().take(5).cloned().collect::<Vec<_>>().join("\n")
            ));
        }
    }

    assert!(
        missing_goldens.is_empty(),
        "{engine_name} standard: {} template(s) missing from all_templates.json — run generate.py:\n{}",
        missing_goldens.len(),
        missing_goldens
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        failures.is_empty(),
        "{engine_name} standard: {} template(s) differ from golden:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

#[test]
fn rego_detailed_matches_golden() {
    let engine = RegoEngine::new(EngineConfig::default()).expect("rego engine");
    check_detailed("rego", &engine);
}

#[test]
fn rego_standard_matches_golden() {
    let engine = RegoEngine::new(EngineConfig::default()).expect("rego engine");
    check_standard("rego", &engine);
}

#[test]
fn cel_detailed_matches_golden() {
    let engine = CelEngine::new(EngineConfig::default()).expect("cel engine");
    check_detailed("cel", &engine);
}

#[test]
fn cel_standard_matches_golden() {
    let engine = CelEngine::new(EngineConfig::default()).expect("cel engine");
    check_standard("cel", &engine);
}
