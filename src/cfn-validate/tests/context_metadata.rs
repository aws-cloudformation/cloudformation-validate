mod common;

use cel_engine::CelEngine;
use common::load_template;
use composite_engine::CompositeEngine;
use diagnostics::Diagnostic;
use rego_engine::RegoEngine;
use rules::Severity;
use schema_validator::SchemaValidator;
use std::sync::LazyLock;
use template_model::EntityType;
use validation_engine::{CompositeEngineConfig, EngineConfig, ValidateConfig, ValidationEngine, validate_bytes};

const CONTEXT_RULE_IDS: [&str; 3] = ["I4010", "W4011", "W4012"];

static REGO: LazyLock<RegoEngine> = LazyLock::new(|| RegoEngine::new(EngineConfig::default()).unwrap());
static CEL: LazyLock<CelEngine> = LazyLock::new(|| CelEngine::new(EngineConfig::default()).unwrap());
static COMPOSITE: LazyLock<CompositeEngine> =
    LazyLock::new(|| CompositeEngine::new(CompositeEngineConfig::default()).unwrap());

fn engines() -> [(&'static str, &'static dyn ValidationEngine); 3] {
    [("rego", &*REGO), ("cel", &*CEL), ("composite", &*COMPOSITE)]
}

fn context_diagnostics(engine: &dyn ValidationEngine, template: &str, config: ValidateConfig) -> Vec<Diagnostic> {
    let report = validate_bytes(engine, &SchemaValidator::default(), &load_template(template), config)
        .expect("context fixture should validate");
    report.diagnostics.into_iter().filter(|d| CONTEXT_RULE_IDS.contains(&d.rule_id.as_str())).collect()
}

/// Runs every engine selector on `template` and asserts they agree before
/// returning one engine's diagnostics for behavioral assertions.
fn context_diagnostics_on_every_engine(template: &str, config: ValidateConfig) -> Vec<Diagnostic> {
    let mut agreed: Option<(serde_json::Value, Vec<Diagnostic>)> = None;
    for (name, engine) in engines() {
        let diagnostics = context_diagnostics(engine, template, config.clone());
        let json = serde_json::to_value(&diagnostics).expect("serialize context diagnostics");
        match &agreed {
            Some((expected, _)) => assert_eq!(expected, &json, "{template}: {name} differs from the other engines"),
            None => agreed = Some((json, diagnostics)),
        }
    }
    agreed.expect("at least one engine ran").1
}

fn summary(diagnostics: &[Diagnostic]) -> Vec<(String, Option<String>, Option<String>, String)> {
    diagnostics
        .iter()
        .map(|d| {
            (d.rule_id.clone(), d.resource_logical_id().map(str::to_string), d.property_path.clone(), d.message.clone())
        })
        .collect()
}

#[test]
fn complete_context_is_clean_on_every_engine() {
    let diagnostics =
        context_diagnostics_on_every_engine("good/metadata_context_complete.yaml", ValidateConfig::default());

    assert!(diagnostics.is_empty(), "complete context and exempt resources must not be flagged: {diagnostics:?}");
}

/// Context describes the deployed resources whatever produced the template, so a
/// synthesized template is checked like any other; only the CDK analytics
/// record is exempt from the requirement.
#[test]
fn cdk_synthesized_template_is_checked_except_for_its_analytics_record() {
    let diagnostics = context_diagnostics_on_every_engine(
        "bad/I4010_cdk_synthesized_missing_context.json",
        ValidateConfig::default(),
    );

    let rule_ids: Vec<&str> = diagnostics.iter().map(|d| d.rule_id.as_str()).collect();
    assert_eq!(rule_ids, ["W4011", "I4010", "I4010"], "{diagnostics:?}");
    assert_eq!(diagnostics[0].resource_logical_id(), Some("OrderTopic"));
    assert_eq!(
        diagnostics[2].message,
        "Resources without a Metadata.com.aws.cloudformation.Context block: OrderQueue (AWS::SQS::Queue), OrderHandler (AWS::Lambda::Function)."
    );
    assert!(diagnostics.iter().all(|d| !d.message.contains("CDKMetadata")));
}

#[test]
fn missing_context_yields_a_template_finding_and_one_aggregate_in_yaml_and_json() {
    let from_yaml = context_diagnostics_on_every_engine("bad/I4010_context_missing.yaml", ValidateConfig::default());
    let from_json = context_diagnostics_on_every_engine("bad/I4010_context_missing.json", ValidateConfig::default());

    assert_eq!(summary(&from_yaml), summary(&from_json), "JSON and YAML templates must produce the same findings");
    assert_eq!(from_yaml.len(), 2, "one template finding and one resource aggregate: {from_yaml:?}");
    assert!(from_yaml.iter().all(|d| d.severity == Severity::Info && d.suggested_fix.is_some()));
    let template_finding = &from_yaml[0];
    assert!(template_finding.entity.is_none());
    assert_eq!(template_finding.property_path.as_deref(), Some("Metadata"));
    let aggregate = &from_yaml[1];
    assert_eq!(aggregate.resource_logical_id(), Some("OrderQueue"));
    assert_eq!(
        aggregate.message,
        "Resources without a Metadata.com.aws.cloudformation.Context block: OrderQueue (AWS::SQS::Queue), OrdersTable (AWS::DynamoDB::Table)."
    );
    assert!(aggregate.location.is_some());
    let related = aggregate.related_resources.as_ref().expect("the second resource is attached as related");
    assert_eq!(related.len(), 1);
    assert_eq!(related[0].resource.as_ref().and_then(|r| r.id.as_deref()), Some("OrdersTable"));
    for diagnostics in [&from_yaml, &from_json] {
        assert!(diagnostics.iter().all(|d| d.rule_id == "I4010"));
        assert!(diagnostics[1].location.is_some(), "the aggregate is anchored at the first resource");
    }
}

#[test]
fn missing_why_is_excused_only_by_low_confidence_trust() {
    let diagnostics =
        context_diagnostics_on_every_engine("bad/W4011_context_missing_why.yaml", ValidateConfig::default());

    let flagged: Vec<Option<&str>> = diagnostics.iter().map(Diagnostic::resource_logical_id).collect();
    assert!(diagnostics.iter().all(|d| d.rule_id == "W4011"), "{diagnostics:?}");
    assert_eq!(flagged, [Some("OrderQueue"), Some("Notifier"), Some("ServiceLogGroup")]);
    assert!(diagnostics.iter().all(|d| {
        d.severity == Severity::Warn
            && d.property_path.as_deref() == Some("Metadata.com.aws.cloudformation.Context")
            && d.location.is_some()
    }));
}

#[test]
fn schema_violations_are_reported_once_per_field_at_both_placements() {
    let diagnostics =
        context_diagnostics_on_every_engine("bad/W4012_context_schema_violation.yaml", ValidateConfig::default());

    let violations: Vec<&Diagnostic> = diagnostics.iter().filter(|d| d.rule_id == "W4012").collect();
    assert_eq!(violations.len(), 15, "{diagnostics:?}");
    assert_eq!(violations.iter().filter(|d| d.resource_logical_id() == Some("Bucket")).count(), 1);
    assert_eq!(violations.iter().filter(|d| d.resource_logical_id() == Some("Queue")).count(), 9);
    let template_level: Vec<&&Diagnostic> = violations.iter().filter(|d| d.resource_logical_id().is_none()).collect();
    assert_eq!(template_level.len(), 5);
    assert!(
        template_level.iter().all(|d| {
            d.entity.as_ref().is_some_and(|entity| {
                entity.entity_type == EntityType::Metadata && entity.logical_id == "com.aws.cloudformation.Context"
            })
        }),
        "template-level findings identify the Metadata key they validate: {template_level:?}"
    );
    assert!(violations.iter().all(|d| d.location.is_some() && d.property_path.is_some()));
    let paths: Vec<&str> = violations.iter().filter_map(|d| d.property_path.as_deref()).collect();
    for expected in [
        "Metadata.com.aws.cloudformation.Context",
        "Metadata.com.aws.cloudformation.Context.mutability.QueueName",
        "Metadata.com.aws.cloudformation.Context.trust.extra",
        "Metadata/com.aws.cloudformation.Context/ref/0",
        "Metadata/com.aws.cloudformation.Context/gaps",
    ] {
        assert!(paths.contains(&expected), "missing {expected} in {paths:?}");
    }
    let rationale_findings: Vec<Option<&str>> =
        diagnostics.iter().filter(|d| d.rule_id == "W4011").map(Diagnostic::resource_logical_id).collect();
    assert_eq!(
        rationale_findings,
        [Some("Queue")],
        "a numeric 'why' is no rationale; a non-mapping block is shape only"
    );
    assert!(diagnostics.iter().all(|d| d.rule_id != "I4010"), "every resource and the template supply a block");
}

#[test]
fn strict_mode_promotes_context_warnings_but_not_the_informational_rule() {
    let strict = ValidateConfig { strict: true, ..Default::default() };

    let missing = context_diagnostics_on_every_engine("bad/I4010_context_missing.yaml", strict.clone());
    let malformed = context_diagnostics_on_every_engine("bad/W4012_context_schema_violation.yaml", strict);

    assert!(missing.iter().all(|d| d.severity == Severity::Info), "{missing:?}");
    assert!(!malformed.is_empty() && malformed.iter().all(|d| d.severity == Severity::Error), "{malformed:?}");
}
