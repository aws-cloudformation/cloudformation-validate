mod common;

use cel_engine::CelEngine;
use common::load_template;
use diagnostics::Diagnostic;
use rego_engine::RegoEngine;
use rules::Severity;
use schema_validator::SchemaValidator;
use std::sync::LazyLock;
use validation_engine::{EngineConfig, ValidateConfig, ValidationEngine, validate_bytes};

const RULE_ID: &str = "W9100";

static REGO: LazyLock<RegoEngine> = LazyLock::new(|| RegoEngine::new(EngineConfig::default()).unwrap());
static CEL: LazyLock<CelEngine> = LazyLock::new(|| CelEngine::new(EngineConfig::default()).unwrap());

fn validate_context(engine: &dyn ValidationEngine, template: &str, config: ValidateConfig) -> Vec<Diagnostic> {
    let report = validate_bytes(engine, &SchemaValidator::default(), &load_template(template), config)
        .expect("context fixture should validate");
    report.diagnostics.into_iter().filter(|diagnostic| diagnostic.rule_id == RULE_ID).collect()
}

fn assert_engine_parity(rego: &[Diagnostic], cel: &[Diagnostic], template: &str) {
    let rego_json = serde_json::to_value(rego).expect("serialize rego context diagnostics");
    let cel_json = serde_json::to_value(cel).expect("serialize cel context diagnostics");
    assert_eq!(rego_json, cel_json, "{template}: context diagnostics differ between engines");
}

#[test]
fn canonical_context_is_accepted_by_both_engines() {
    let template = "good/W9100_context_valid.yaml";
    let rego = validate_context(&*REGO, template, ValidateConfig::default());
    let cel = validate_context(&*CEL, template, ValidateConfig::default());

    assert_engine_parity(&rego, &cel, template);
    assert!(rego.is_empty(), "canonical context and incidental resources must not be flagged: {rego:?}");
}

#[test]
fn missing_context_is_aggregated_to_two_located_warnings() {
    let template = "bad/W9100_context_missing.yaml";
    let rego = validate_context(&*REGO, template, ValidateConfig::default());
    let cel = validate_context(&*CEL, template, ValidateConfig::default());

    assert_engine_parity(&rego, &cel, template);
    assert_eq!(rego.len(), 2, "one template and one primary-resource aggregate are expected");
    assert!(rego.iter().all(|diagnostic| diagnostic.severity == Severity::Warn));
    assert!(rego.iter().all(|diagnostic| diagnostic.location.is_some()));
    assert!(rego.iter().all(|diagnostic| diagnostic.suggested_fix.is_some()));
    let combined = rego.iter().map(|diagnostic| diagnostic.message.as_str()).collect::<Vec<_>>().join(" ");
    assert!(combined.contains("No top-level Metadata.com.aws.cloudformation.Context block found"));
    assert!(combined.contains("Bucket"));
    assert!(combined.contains("Queue"));
    assert!(!combined.contains("CDKMetadata: No Metadata"), "incidental CDK metadata must be excluded");
}

#[test]
fn malformed_context_reports_all_schema_failures_within_two_diagnostics() {
    let template = "bad/W9100_context_malformed.yaml";
    let rego = validate_context(&*REGO, template, ValidateConfig::default());
    let cel = validate_context(&*CEL, template, ValidateConfig::default());

    assert_engine_parity(&rego, &cel, template);
    assert_eq!(rego.len(), 2, "schema findings must remain aggregated by placement");
    let combined = rego.iter().map(|diagnostic| diagnostic.message.as_str()).collect::<Vec<_>>().join(" ");
    for expected in [
        "arch",
        "why' belongs at resource level",
        "ref[0].at",
        "Bucket",
        "must",
        "mutable",
        "mutability.QueueName",
        "trust.src",
        "trust.conf",
        "trust.extra",
        "ref' belongs at template level",
        "unknown",
    ] {
        assert!(combined.contains(expected), "missing {expected:?} from {combined}");
    }
}

#[test]
fn strict_mode_promotes_context_warnings_identically() {
    let template = "bad/W9100_context_missing.yaml";
    let config = || ValidateConfig { strict: true, ..Default::default() };
    let rego = validate_context(&*REGO, template, config());
    let cel = validate_context(&*CEL, template, config());

    assert_engine_parity(&rego, &cel, template);
    assert_eq!(rego.len(), 2);
    assert!(rego.iter().all(|diagnostic| diagnostic.severity == Severity::Error));
}
