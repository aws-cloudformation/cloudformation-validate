mod common;

use cel_engine::CelEngine;
use common::{DETAILED_ONLY_DIAGNOSTIC_FIELDS, deep_diff, discover_all_templates, load_combined_golden, load_template};
use diagnostics::DetailLevel;
use rego_engine::RegoEngine;
use rules::Severity;
use schema_validator::SchemaValidator;
use validation_engine::{EngineConfig, ValidateConfig, ValidationEngine, validate_bytes_with_path};

fn validate_to_json(
    engine: &dyn ValidationEngine,
    bytes: &[u8],
    relative_path: &str,
    detail_level: DetailLevel,
) -> serde_json::Value {
    let sv = SchemaValidator::new();
    let config =
        ValidateConfig { detail_level: detail_level.clone(), severity_level: Severity::Debug, ..Default::default() };
    let report = validate_bytes_with_path(engine, &sv, bytes, config, relative_path.to_string()).expect("validate");
    match detail_level {
        DetailLevel::Detailed => serde_json::to_value(report.to_detailed()).expect("serialize"),
        DetailLevel::Standard => serde_json::to_value(report.to_standard()).expect("serialize"),
    }
}

fn strip_detailed_only_fields(val: &mut serde_json::Value) {
    if let Some(diags) = val.as_object_mut().and_then(|o| o.get_mut("diagnostics")).and_then(|d| d.as_array_mut()) {
        for diag in diags {
            if let Some(obj) = diag.as_object_mut() {
                for field in DETAILED_ONLY_DIAGNOSTIC_FIELDS {
                    obj.remove(*field);
                }
            }
        }
    }
}

fn check_detailed(engine_name: &str, engine: &dyn ValidationEngine) {
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
        let actual = validate_to_json(engine, &bytes, relative_path, DetailLevel::Detailed);

        let expected = golden.clone();

        let diffs = deep_diff(&expected, &actual, "");
        if !diffs.is_empty() {
            failures
                .push(format!("{relative_path}:\n{}", diffs.iter().take(5).cloned().collect::<Vec<_>>().join("\n")));
        }
    }

    assert!(
        missing_goldens.is_empty(),
        "{engine_name} detailed: {} template(s) missing from all_templates.json — run `cargo run --release -p resources --example generate_golden`:\n{}",
        missing_goldens.len(),
        missing_goldens.iter().take(20).cloned().collect::<Vec<_>>().join("\n")
    );
    assert!(
        failures.is_empty(),
        "{engine_name} detailed: {} template(s) differ from golden:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

fn check_standard(engine_name: &str, engine: &dyn ValidationEngine) {
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
        let actual = validate_to_json(engine, &bytes, relative_path, DetailLevel::Standard);

        let mut expected = golden.clone();
        strip_detailed_only_fields(&mut expected);

        let diffs = deep_diff(&expected, &actual, "");
        if !diffs.is_empty() {
            failures
                .push(format!("{relative_path}:\n{}", diffs.iter().take(5).cloned().collect::<Vec<_>>().join("\n")));
        }
    }

    assert!(
        missing_goldens.is_empty(),
        "{engine_name} standard: {} template(s) missing from all_templates.json — run `cargo run --release -p resources --example generate_golden`:\n{}",
        missing_goldens.len(),
        missing_goldens.iter().take(20).cloned().collect::<Vec<_>>().join("\n")
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

const EXPECTED_RULES_EVALUATED: u64 = 300;

#[test]
fn rules_evaluated_is_full_rule_count() {
    let rego = RegoEngine::new(EngineConfig::default()).expect("rego engine");
    let cel = CelEngine::new(EngineConfig::default()).expect("cel engine");
    let bytes = load_template("good/generic.yaml");

    for (name, report) in [
        ("rego", validate_to_json(&rego, &bytes, "good/generic.yaml", DetailLevel::Detailed)),
        ("cel", validate_to_json(&cel, &bytes, "good/generic.yaml", DetailLevel::Detailed)),
    ] {
        assert_eq!(
            report["metadata"]["rulesEvaluated"].as_u64(),
            Some(EXPECTED_RULES_EVALUATED),
            "{name}: rulesEvaluated must be the full built-in rule count"
        );
    }
}

const EXPECTED_ENGINE_VERSION: &str = "1.6.0";

#[test]
fn engine_version_matches_workspace_version() {
    let rego = RegoEngine::new(EngineConfig::default()).expect("rego engine");
    let cel = CelEngine::new(EngineConfig::default()).expect("cel engine");
    let bytes = load_template("good/generic.yaml");

    for (name, report) in [
        ("rego", validate_to_json(&rego, &bytes, "good/generic.yaml", DetailLevel::Detailed)),
        ("cel", validate_to_json(&cel, &bytes, "good/generic.yaml", DetailLevel::Detailed)),
    ] {
        assert_eq!(
            report["version"].as_str(),
            Some(EXPECTED_ENGINE_VERSION),
            "{name}: version must be the workspace crate version"
        );
    }
}

fn message_defect(text: &str) -> Option<String> {
    for (idx, ch) in text.char_indices() {
        if !ch.is_ascii() {
            return Some(format!("non-ASCII U+{:04X} '{ch}' at byte {idx}", ch as u32));
        }
        if ch.is_ascii_control() {
            return Some(format!("control char U+{:04X} at byte {idx}", ch as u32));
        }
    }
    if text.contains("\\u") {
        return Some("literal unicode escape".to_string());
    }
    None
}

#[test]
fn message_defect_flags_bad_text_and_accepts_clean_text() {
    // Each of these must be reported as a defect.
    let bad = [
        ("em dash", "Hardcoded AMI ID \u{2014} use a parameter"),
        ("arrow", "coerced (number \u{2192} string)"),
        ("literal unicode escape", "trailing \\u2014 escape"),
        ("tab control char", "value\tinjected"),
    ];
    for (label, text) in bad {
        assert!(message_defect(text).is_some(), "message_defect must flag {label}: {text:?}");
    }

    let clean = [
        "Hardcoded AMI ID - use a parameter or mapping for portability",
        "'X' is not of type 'string' - automatically coerced (number to string)",
        "'X' is not one of ['TOKEN', 'REQUEST']",
        "TXT record value '\"aaaa\"' must be enclosed in double quotes",
    ];
    for text in clean {
        assert_eq!(message_defect(text), None, "message_defect must accept clean text: {text:?}");
    }
}

#[test]
fn golden_messages_are_clean_ascii_text() {
    let combined = load_combined_golden();

    let mut violations = Vec::new();
    let mut messages_checked = 0usize;

    for (template, report) in &combined {
        let Some(diagnostics) = report.get("diagnostics").and_then(|d| d.as_array()) else {
            continue;
        };
        for diag in diagnostics {
            let rule_id = diag.get("ruleId").and_then(|r| r.as_str()).expect("every diagnostic must have a ruleId");
            for field in ["message", "ruleDescription", "suggestedFix"] {
                let Some(text) = diag.get(field).and_then(|m| m.as_str()) else {
                    continue;
                };
                messages_checked += 1;
                if let Some(defect) = message_defect(text) {
                    violations.push(format!("{template} [{rule_id}/{field}] {defect}: {text}"));
                }
            }
        }
    }

    assert!(messages_checked > 0, "no diagnostic messages were scanned across {} templates", combined.len());

    assert!(
        violations.is_empty(),
        "{} golden message(s) contain non-ASCII, control chars, or unicode escapes:\n{}",
        violations.len(),
        violations.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}

#[test]
fn performance_is_present_in_report() {
    let rego = RegoEngine::new(EngineConfig::default()).expect("rego engine");
    let bytes = load_template("good/generic.yaml");
    let report = validate_to_json(&rego, &bytes, "good/generic.yaml", DetailLevel::Detailed);

    let performance = report["performance"].as_object().expect("performance must be present");
    for phase in [
        "schemaInit",
        "engineInit",
        "modelBuild",
        "schemaValidate",
        "ruleEvaluation",
        "diagnosticFinalize",
        "validateTotal",
    ] {
        assert!(
            performance.get(phase).and_then(|p| p.get("durationMs")).and_then(|d| d.as_f64()).is_some(),
            "performance.{phase}.durationMs must be present"
        );
    }
}
