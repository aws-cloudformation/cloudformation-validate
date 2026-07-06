//! Security and robustness regression tests.
//!
//! These tests confirm the validator stays bounded and structured on adversarial
//! input: oversized templates are rejected, deep nesting does not overflow the
//! stack, pathological condition counts and closures resolve within a bounded
//! budget, internal panics surface as structured errors, custom rules cannot
//! reach host resources, and large templates validate without runaway cost.
//!
//! The large/pathological fixtures live in `resources/security/` and are produced
//! by `resources/security/generate.py`.

mod common;

use std::time::Duration;

use cel_engine::CelEngine;
use rego_engine::RegoEngine;
use schema_validator::SchemaValidator;
use template_model::SemanticModel;
use validation_engine::{
    EngineConfig, ExternalRuleSource, ValidateConfig, ValidationEngine, validate_bytes_with_path,
    validate_catching_panics,
};

/// Generous wall-clock ceiling. These tests guard against unbounded/exponential
/// blow-up (a denial-of-service regression), not a precise latency SLA. The real
/// safeguard is deterministic and machine-independent — a cumulative
/// satisfiability-iteration budget and a per-query parameter cap in
/// `template-model` — so this ceiling only has to be loose enough to never flake
/// on debug builds or loaded CI hosts while still failing fast on a true hang.
const COMPLETION_BUDGET: Duration = Duration::from_secs(120);

const SMALL_TEMPLATE: &[u8] = b"Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n";

fn build_engine(engine_name: &str) -> Result<Box<dyn ValidationEngine>, String> {
    match engine_name {
        "rego" => RegoEngine::new(EngineConfig::default())
            .map(|e| Box::new(e) as Box<dyn ValidationEngine>)
            .map_err(|e| e.to_string()),
        "cel" => CelEngine::new(EngineConfig::default())
            .map(|e| Box::new(e) as Box<dyn ValidationEngine>)
            .map_err(|e| e.to_string()),
        other => Err(format!("unknown engine '{other}'")),
    }
}

/// Validates `bytes` on a freshly built engine in a worker thread. Returns
/// `Some(Ok(rule_ids))` with the rule ID of every diagnostic produced if it
/// finishes within `budget`, `Some(Err(_))` if validation errored, or `None` if
/// it did not finish in time. Running on a worker thread means a hang fails the
/// test instead of blocking the whole suite.
fn validate_within(budget: Duration, engine_name: &'static str, bytes: Vec<u8>) -> Option<Result<Vec<String>, String>> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let outcome = match build_engine(engine_name) {
            Ok(engine) => {
                let schema_validator = SchemaValidator::new();
                validate_bytes_with_path(
                    engine.as_ref(),
                    &schema_validator,
                    &bytes,
                    ValidateConfig::default(),
                    "security-fixture".to_string(),
                )
                .map(|report| report.diagnostics.iter().map(|d| d.rule_id.clone()).collect::<Vec<String>>())
                .map_err(|e| e.to_string())
            }
            Err(e) => Err(e),
        };
        let _ = sender.send(outcome);
    });
    receiver.recv_timeout(budget).ok()
}

#[test]
fn oversized_template_is_rejected_before_processing() {
    // Built in-memory rather than committed as a multi-megabyte fixture.
    let oversized = vec![b' '; 11 * 1024 * 1024];
    let error = match SemanticModel::from_bytes(&oversized) {
        Ok(_) => panic!("a template larger than the size limit must be rejected"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("exceeds maximum size"), "expected a size-limit error, got: {error}");
}

#[test]
fn deeply_nested_template_does_not_overflow_the_stack() {
    let bytes = common::load_security("deep_nesting.json");
    // A stack overflow aborts the process, so simply returning here proves the
    // parser stayed bounded; catch_unwind additionally turns any panic into a
    // failed assertion rather than a process abort.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| SemanticModel::from_bytes(&bytes)));
    let parse_result = outcome.expect("parsing a deeply nested template must not panic or overflow the stack");
    if let Err(error) = parse_result {
        let message = error.to_string().to_lowercase();
        assert!(
            message.contains("recursion")
                || message.contains("limit")
                || message.contains("depth")
                || message.contains("nest"),
            "deep nesting should fail gracefully with a structured parse error, got: {error}"
        );
    }
}

#[test]
fn pathological_conditions_resolve_within_budget() {
    for engine_name in ["rego", "cel"] {
        let bytes = common::load_security("many_conditions.yaml");
        let finished = validate_within(COMPLETION_BUDGET, engine_name, bytes);
        assert!(
            finished.is_some(),
            "{engine_name}: a template with many interdependent conditions must resolve within \
             {COMPLETION_BUDGET:?}; the scenario budget must bound the work"
        );
        finished.unwrap().expect("validation should return a structured report");
    }
}

#[test]
fn pathological_condition_closures_resolve_within_budget() {
    // Conditions with large dependency closures over many shared parameters are
    // the worst case for the satisfiability consistency check: the pairwise
    // condition-compatibility pass on the validate hot path would otherwise
    // enumerate an exponential parameter space and run for minutes. The
    // per-query parameter cap and cumulative iteration budget in template-model
    // make the solver fall back to its conservative "assume satisfiable" answer
    // and stay bounded. This guards that such a template still validates to a
    // structured report — on both engines — instead of hanging.
    for engine_name in ["rego", "cel"] {
        let bytes = common::load_security("pathological_conditions.yaml");
        let finished = validate_within(COMPLETION_BUDGET, engine_name, bytes);
        assert!(
            finished.is_some(),
            "{engine_name}: a template with large condition closures must stay bounded and \
             resolve within {COMPLETION_BUDGET:?}; the satisfiability budget must cap the work"
        );
        finished.unwrap().expect("validation should return a structured report");
    }
}

#[test]
fn internal_panic_becomes_a_structured_error() {
    // The deliberate panic prints a message to stderr via the default hook; the
    // wrapper still converts it into a recoverable error instead of aborting.
    let result = validate_catching_panics(|| {
        panic!("simulated internal assertion failure");
    });
    let error = result.expect_err("a panic must be converted into an error, not propagated");
    assert!(
        error.to_string().contains("Internal validation error"),
        "expected a structured internal-error message, got: {error}"
    );
}

#[test]
fn successful_validation_passes_through_the_panic_guard() {
    let schema_validator = SchemaValidator::new();
    let engine = RegoEngine::new(EngineConfig::default()).expect("engine must build");
    let report = validate_catching_panics(|| {
        validate_bytes_with_path(
            &engine,
            &schema_validator,
            SMALL_TEMPLATE,
            ValidateConfig::default(),
            "inline".to_string(),
        )
    });
    let report = report.expect("a normal validation must pass through the guard unchanged");
    assert!(
        report.diagnostics.iter().all(|d| !d.rule_id.starts_with('F')),
        "a minimal valid template must produce no fatal (F-prefixed) diagnostics through the guard; got {:?}",
        report.diagnostics.iter().map(|d| d.rule_id.as_str()).collect::<Vec<_>>()
    );
}

#[test]
fn custom_rule_reaching_a_host_builtin_is_a_hard_error_not_a_diagnostic() {
    // The escape rule reaches for host builtins the sandbox does not provide:
    // network egress (http.send), DNS (net.lookup_ip_addr), and host
    // runtime/environment (opa.runtime). The interpreter registers none of
    // them, so evaluating the rule fails with an unknown-function error. That
    // failure must surface as a hard validation error (an exception) — never be
    // silently swallowed, and never be reported as a diagnostic. A failed
    // escape attempt must not be able to masquerade as a finding.
    let escape_rule = common::load_security_rule("rego_sandbox_escape.rego");
    let config = EngineConfig {
        custom_rules: vec![ExternalRuleSource { name: "sandbox_escape.rego".into(), content: escape_rule }],
        guard_rules: vec![],
    };
    let engine = RegoEngine::new(config).expect("engine must build even with a host-builtin-reaching custom rule");
    let schema_validator = SchemaValidator::new();
    let error = validate_bytes_with_path(
        &engine,
        &schema_validator,
        SMALL_TEMPLATE,
        ValidateConfig::default(),
        "inline".to_string(),
    )
    .expect_err(
        "a custom rule that reaches for a host builtin must fail validation with an error, not \
         return a (possibly empty) set of diagnostics",
    );
    let message = error.to_string();
    assert!(
        message.contains("failed to evaluate") && message.contains("could not find function"),
        "the error must identify the failed custom rule and the unknown host builtin (network, \
         DNS, or host runtime); got: {message}"
    );
}

#[test]
fn benign_custom_rule_runs_and_fires() {
    // Control: a custom rule of the same shape but WITHOUT a host-builtin call
    // must evaluate cleanly and fire. This proves custom rules are actually run,
    // so the hard error above is caused by the absent host builtin — not by
    // custom rules being skipped or by a misconfiguration.
    let control_rule = "package sandbox_control\n\
import rego.v1\n\
violation contains make_diag(\"CTRL001\", \"WARN\", name, \"control rule fired\") if {\n\
    some name, _ in input.resources\n\
}\n"
    .to_string();
    let config = EngineConfig {
        custom_rules: vec![ExternalRuleSource { name: "sandbox_control.rego".into(), content: control_rule }],
        guard_rules: vec![],
    };
    let engine = RegoEngine::new(config).expect("engine must build");
    let schema_validator = SchemaValidator::new();
    let report = validate_bytes_with_path(
        &engine,
        &schema_validator,
        SMALL_TEMPLATE,
        ValidateConfig::default(),
        "inline".to_string(),
    )
    .expect("a benign custom rule must validate successfully");
    let fired: Vec<&str> = report.diagnostics.iter().map(|d| d.rule_id.as_str()).collect();
    assert!(fired.contains(&"CTRL001"), "the benign control rule should fire, proving custom rules run; got {fired:?}");
}

#[test]
fn custom_cel_rule_that_fails_to_evaluate_is_a_hard_error_not_a_diagnostic() {
    // The CEL counterpart to the Rego sandbox-escape test: a custom CEL rule
    // whose expression calls a function the interpreter does not provide
    // compiles, but fails at execution. That failure must surface as a hard
    // validation error (an exception) — never silently dropped, never reported
    // as a diagnostic — matching the Rego engine's custom-rule semantics
    // (no silent failures).
    let escape_rule = r#"{"rules": [
        {
            "rule_id": "SBXCEL001",
            "severity": "WARN",
            "expression": "host_network_access(resources)",
            "message": "custom CEL rule reached a host resource"
        }
    ]}"#
    .to_string();
    let config = EngineConfig {
        custom_rules: vec![ExternalRuleSource { name: "sandbox_escape.celrules.json".into(), content: escape_rule }],
        guard_rules: vec![],
    };
    let engine =
        CelEngine::new(config).expect("engine must build: the expression compiles; it only fails at execution");
    let schema_validator = SchemaValidator::new();
    let error = validate_bytes_with_path(
        &engine,
        &schema_validator,
        SMALL_TEMPLATE,
        ValidateConfig::default(),
        "inline".to_string(),
    )
    .expect_err(
        "a custom CEL rule that fails to execute must fail validation with an error, not be \
         silently dropped or reported as a diagnostic",
    );
    assert!(
        error.to_string().contains("failed to evaluate"),
        "the error must identify the failed custom rule; got: {error}"
    );
}

#[test]
fn benign_custom_cel_rule_runs_and_fires() {
    // Control: a custom CEL rule whose expression executes cleanly and is true
    // must fire, proving custom CEL rules are actually evaluated — so the hard
    // error above is caused by the failed execution, not by rules being skipped.
    let control_rule = r#"{"rules": [
        {
            "rule_id": "CTRLCEL001",
            "severity": "WARN",
            "expression": "true",
            "message": "control rule fired"
        }
    ]}"#
    .to_string();
    let config = EngineConfig {
        custom_rules: vec![ExternalRuleSource { name: "sandbox_control.celrules.json".into(), content: control_rule }],
        guard_rules: vec![],
    };
    let engine = CelEngine::new(config).expect("engine must build");
    let schema_validator = SchemaValidator::new();
    let report = validate_bytes_with_path(
        &engine,
        &schema_validator,
        SMALL_TEMPLATE,
        ValidateConfig::default(),
        "inline".to_string(),
    )
    .expect("a benign custom CEL rule must validate successfully");
    let fired: Vec<&str> = report.diagnostics.iter().map(|d| d.rule_id.as_str()).collect();
    assert!(
        fired.contains(&"CTRLCEL001"),
        "the benign control CEL rule should fire, proving custom CEL rules run; got {fired:?}"
    );
}

#[test]
fn large_resource_count_validates_to_a_bounded_result_on_both_engines() {
    // The bound under test is the resource count itself — a fixed,
    // machine-independent quantity — not wall-clock time. A template at the
    // 500-resource scale must parse to exactly that many resources and validate
    // to a structured report (never hang, panic, or error) on both engines.
    const SCALE_RESOURCES: usize = 500;
    let bytes = common::load_security("many_resources.yaml");

    let model = SemanticModel::from_bytes(&bytes).expect("the large-resource fixture must parse to a semantic model");
    assert_eq!(
        model.resources.len(),
        SCALE_RESOURCES,
        "the fixture must hold exactly {SCALE_RESOURCES} resources so the scale under test is fixed"
    );

    for engine_name in ["rego", "cel"] {
        let engine = build_engine(engine_name).expect("engine must build");
        let schema_validator = SchemaValidator::new();
        let _ = validate_bytes_with_path(
            engine.as_ref(),
            &schema_validator,
            &bytes,
            ValidateConfig::default(),
            "security-fixture".to_string(),
        )
        .unwrap_or_else(|e| {
            panic!(
                "{engine_name}: validating {SCALE_RESOURCES} resources must return a structured \
                 report, not an error: {e}"
            )
        });
    }
}

#[test]
fn cross_resource_pair_comparison_produces_a_deterministic_bounded_count() {
    // 500 resources that all share one primary-identifier value put every pair
    // in a single group — the worst case for the cross-resource uniqueness
    // rule. The deterministic, machine-independent signature that the quadratic
    // pair comparison ran to completion and stayed bounded is the exact
    // diagnostic count: exactly one uniqueness diagnostic per resource in the
    // duplicate group, and identical on both engines. This replaces the former
    // wall-clock ceiling.
    const PRIMARY_IDENTIFIER_UNIQUENESS_RULE: &str = "E3019";
    const SHARED_IDENTIFIER_RESOURCES: usize = 500;
    for engine_name in ["rego", "cel"] {
        let bytes = common::load_security("cross_resource_scale.yaml");
        let engine = build_engine(engine_name).expect("engine must build");
        let schema_validator = SchemaValidator::new();
        let report = validate_bytes_with_path(
            engine.as_ref(),
            &schema_validator,
            &bytes,
            ValidateConfig::default(),
            "security-fixture".to_string(),
        )
        .unwrap_or_else(|e| {
            panic!("{engine_name}: cross-resource scale validation must return a structured report: {e}")
        });
        let uniqueness_diagnostics =
            report.diagnostics.iter().filter(|d| d.rule_id == PRIMARY_IDENTIFIER_UNIQUENESS_RULE).count();
        assert_eq!(
            uniqueness_diagnostics, SHARED_IDENTIFIER_RESOURCES,
            "{engine_name}: every resource sharing the identifier must get exactly one uniqueness \
             diagnostic — proving the quadratic pair-comparison ran to completion and produced a \
             bounded, deterministic result; got {uniqueness_diagnostics}"
        );
    }
}
