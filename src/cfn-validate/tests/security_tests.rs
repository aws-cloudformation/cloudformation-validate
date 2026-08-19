//! Security and robustness regression tests.
//!
//! These tests confirm the validator stays bounded and structured on adversarial
//! input: oversized templates are rejected, deep nesting does not overflow the
//! stack, pathological condition counts and closures resolve within a bounded
//! budget, conditions layered over shared inputs are still analyzed in full,
//! internal panics surface as structured errors, custom rules cannot reach host
//! resources, and large templates validate without runaway cost.
//!
//! The large/pathological fixtures live in `resources/security/` and are produced
//! by `resources/security/generate.py`.

mod common;

use std::time::Duration;

use cel_engine::CelEngine;
use diagnostics::{DetailLevel, ReportStatus, ValidationReport};
use rego_engine::RegoEngine;
use rules::Severity;
use schema_validator::SchemaValidator;
use template_model::SemanticModel;
use validation_engine::{
    EngineConfig, ExternalRuleSource, ValidateConfig, ValidationEngine, validate_bytes_with_path,
    validate_catching_panics,
};

/// Generous wall-clock ceiling. These tests guard against unbounded/exponential
/// blow-up (a denial-of-service regression), not a precise latency SLA. The real
/// safeguard is deterministic and machine-independent - a cumulative
/// satisfiability-iteration budget and a per-query parameter cap in
/// `template-model`. A one-minute ceiling retains substantial headroom on debug
/// builds and loaded CI hosts while rejecting the prior cross-resource scale
/// regression, which required more than 90 seconds.
const COMPLETION_BUDGET: Duration = Duration::from_secs(60);

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

/// Validates `bytes` on a freshly built engine in a worker thread. Returns a
/// completed report, a structured error, or `None` when the test-only deadline
/// expires.
fn validate_report_within(
    budget: Duration,
    engine_name: &'static str,
    bytes: Vec<u8>,
) -> Option<Result<ValidationReport, String>> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let outcome = match build_engine(engine_name) {
            Ok(engine) => {
                let schema_validator = SchemaValidator::default();
                let config = ValidateConfig {
                    detail_level: DetailLevel::Detailed,
                    severity_level: Severity::Debug,
                    ..ValidateConfig::default()
                };
                validate_bytes_with_path(
                    engine.as_ref(),
                    &schema_validator,
                    &bytes,
                    config,
                    "security-fixture".to_string(),
                )
                .map_err(|error| error.to_string())
            }
            Err(error) => Err(error),
        };
        let _ = sender.send(outcome);
    });
    receiver.recv_timeout(budget).ok()
}

fn validate_within(budget: Duration, engine_name: &'static str, bytes: Vec<u8>) -> Option<Result<Vec<String>, String>> {
    validate_report_within(budget, engine_name, bytes).map(|outcome| {
        outcome.map(|report| report.diagnostics.into_iter().map(|diagnostic| diagnostic.rule_id).collect())
    })
}

fn budget_metadata(report: &ValidationReport) -> Vec<(String, String, u64, bool)> {
    report
        .metadata
        .budget_exhaustions
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|record| (record.kind.clone(), record.description.clone(), record.limit, record.analysis_incomplete))
        .collect()
}

fn collect_security_templates(directory: &std::path::Path, templates: &mut Vec<std::path::PathBuf>) {
    let entries = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("failed to read security fixture directory {}: {error}", directory.display()));
    for entry in entries {
        let path = entry.expect("security fixture directory entry must be readable").path();
        if path.is_dir() {
            collect_security_templates(&path, templates);
        } else if matches!(path.extension().and_then(|extension| extension.to_str()), Some("json" | "yaml" | "yml")) {
            templates.push(path);
        }
    }
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
fn every_security_template_is_exercised_by_both_engines() {
    let mut templates = Vec::new();
    collect_security_templates(&common::security_dir(), &mut templates);
    templates.sort();
    assert!(!templates.is_empty(), "security fixture directory must contain templates");

    for engine_name in ["rego", "cel"] {
        for template in &templates {
            let bytes = std::fs::read(template)
                .unwrap_or_else(|error| panic!("failed to read security fixture {}: {error}", template.display()));
            let finished = validate_within(COMPLETION_BUDGET, engine_name, bytes).unwrap_or_else(|| {
                panic!(
                    "{engine_name}: security fixture {} must validate within {COMPLETION_BUDGET:?}",
                    template.display()
                )
            });
            if let Err(error) = finished {
                let filename = template.file_name().and_then(|name| name.to_str()).unwrap_or("");
                assert!(
                    filename == "deep_nesting.json" || filename == "deep_yaml_nesting.yaml",
                    "{engine_name}: security fixture {} returned an unexpected error: {error}",
                    template.display()
                );
            }
        }
    }
}

#[test]
fn schema_scenario_assignment_boundary_is_explicit_and_bounded() {
    const CURTAILED_ANALYSIS_ADVISORY: &str = "W9052";
    let mut engine_reports = Vec::new();
    for engine_name in ["rego", "cel"] {
        let report = validate_report_within(
            COMPLETION_BUDGET,
            engine_name,
            common::load_security("scenario_assignment_budget.yaml"),
        )
        .unwrap_or_else(|| {
            panic!("{engine_name}: schema scenario assignment boundary must complete within {COMPLETION_BUDGET:?}")
        })
        .expect("schema assignment boundary validation must return a structured report");
        let curtailed_count =
            report.diagnostics.iter().filter(|diagnostic| diagnostic.rule_id == CURTAILED_ANALYSIS_ADVISORY).count();
        assert_eq!(curtailed_count, 1, "{engine_name}: budget exhaustion must produce one aggregate warning");
        assert_eq!(
            report.status,
            ReportStatus::AnalysisIncomplete,
            "{engine_name}: assignment truncation must mark analysis incomplete"
        );
        assert!(report.metadata.budget_exhaustions.is_some());
        engine_reports.push(report);
    }

    assert_eq!(budget_metadata(&engine_reports[0]), budget_metadata(&engine_reports[1]));
    assert_eq!(engine_reports[0].status, engine_reports[1].status);
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
    // structured report - on both engines - instead of hanging.
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
fn conditions_layered_over_shared_inputs_are_analyzed_without_curtailing() {
    const CURTAILED_ANALYSIS_ADVISORY: &str = "W9052";
    let mut engine_reports = Vec::new();
    for engine_name in ["rego", "cel"] {
        let report =
            validate_report_within(COMPLETION_BUDGET, engine_name, common::load_security("condition_fusion.yaml"))
                .unwrap_or_else(|| {
                    panic!(
                        "{engine_name}: conditions layered over shared inputs must validate within \
                 {COMPLETION_BUDGET:?}"
                    )
                })
                .expect("validation must return a structured report");
        assert!(
            report.diagnostics.iter().all(|diagnostic| diagnostic.rule_id != CURTAILED_ANALYSIS_ADVISORY),
            "{engine_name}: the fully decided condition fixture must not report curtailment"
        );
        assert_eq!(
            report.status,
            ReportStatus::Ok,
            "{engine_name}: complete condition analysis must keep the report status ok"
        );
        assert!(report.metadata.budget_exhaustions.is_none(), "{engine_name}: no budget may be exhausted");
        engine_reports.push(report);
    }

    assert_eq!(budget_metadata(&engine_reports[0]), budget_metadata(&engine_reports[1]));
    assert_eq!(engine_reports[0].status, engine_reports[1].status);
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
    let schema_validator = SchemaValidator::default();
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
    // failure must surface as a hard validation error (an exception) - never be
    // silently swallowed, and never be reported as a diagnostic. A failed
    // escape attempt must not be able to masquerade as a finding.
    let escape_rule = common::load_security_rule("rego_sandbox_escape.rego");
    let config = EngineConfig {
        custom_rules: vec![ExternalRuleSource { name: "sandbox_escape.rego".into(), content: escape_rule }],
        guard_rules: vec![],
        ..Default::default()
    };
    let engine = RegoEngine::new(config).expect("engine must build even with a host-builtin-reaching custom rule");
    let schema_validator = SchemaValidator::default();
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
    // so the hard error above is caused by the absent host builtin - not by
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
        ..Default::default()
    };
    let engine = RegoEngine::new(config).expect("engine must build");
    let schema_validator = SchemaValidator::default();
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
fn custom_cel_rule_reaching_an_unknown_function_is_a_hard_error_not_a_diagnostic() {
    // The CEL counterpart to the Rego sandbox-escape test: a custom CEL rule
    // whose expression calls a function the interpreter does not provide is a
    // hard error - never silently dropped, never reported as a diagnostic. A
    // failed escape attempt must not be able to masquerade as a finding.
    //
    // Unlike Rego (whose missing builtins only surface at evaluation), CEL can
    // enumerate an expression's function references at compile time, so the
    // unknown function is rejected when the engine loads the rule rather than
    // when it runs. That is strictly safer: a rule scoped to an absent resource
    // type cannot load clean and then silently never run.
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
        ..Default::default()
    };
    let error = CelEngine::new(config).err().expect(
        "a custom CEL rule referencing an unknown function must fail the engine build with an error, \
         not load clean and then be silently dropped or reported as a diagnostic",
    );
    let message = error.to_string();
    assert!(
        message.contains("SBXCEL001")
            && message.contains("unknown function")
            && message.contains("host_network_access"),
        "the error must identify the failed custom rule and the unresolved function; got: {message}"
    );
}

#[test]
fn benign_custom_cel_rule_runs_and_fires() {
    // Control: a custom CEL rule whose expression executes cleanly and is true
    // must fire, proving custom CEL rules are actually evaluated - so the hard
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
        ..Default::default()
    };
    let engine = CelEngine::new(config).expect("engine must build");
    let schema_validator = SchemaValidator::default();
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
    // The bound under test is the resource count itself - a fixed,
    // machine-independent quantity - not wall-clock time. A template at the
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
        let schema_validator = SchemaValidator::default();
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
fn condition_chain_boundary_resolves_within_budget() {
    // 20 parameters, 40 acyclic chained conditions matching the public CDK repro
    // shape, 10 gated resources, and nested Fn::If depth 2 in properties. This
    // exercises the condition-resolution hot path on a real-world shape without
    // triggering pathological exponential blowup.
    for engine_name in ["rego", "cel"] {
        let bytes = common::load_security("condition_chain_boundary.yaml");
        let finished = validate_within(COMPLETION_BUDGET, engine_name, bytes);
        assert!(
            finished.is_some(),
            "{engine_name}: condition chain boundary fixture (20 params, 40 conditions) must \
             resolve within {COMPLETION_BUDGET:?}"
        );
        finished.unwrap().expect("validation should return a structured report");
    }
}

#[test]
fn condition_chain_wide_resolves_within_budget() {
    // 73 parameters with 40 chained conditions - the reported 73-parameter case.
    // The parameter space (>2^20 paths) exercises the per-query parameter cap and
    // cumulative iteration budget.
    for engine_name in ["rego", "cel"] {
        let bytes = common::load_security("condition_chain_wide.yaml");
        let finished = validate_within(COMPLETION_BUDGET, engine_name, bytes);
        assert!(
            finished.is_some(),
            "{engine_name}: condition chain wide fixture (73 params, 40 chained conditions) must \
             resolve within {COMPLETION_BUDGET:?}"
        );
        finished.unwrap().expect("validation should return a structured report");
    }
}

#[test]
fn cross_resource_pair_comparison_produces_a_deterministic_bounded_count() {
    // 500 resources that all share one primary-identifier value put every pair
    // in a single group - the worst case for the cross-resource uniqueness
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
        let schema_validator = SchemaValidator::default();
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
             diagnostic - proving the quadratic pair-comparison ran to completion and produced a \
             bounded, deterministic result; got {uniqueness_diagnostics}"
        );
    }
}

#[test]
fn foreach_branch_explosion_is_bounded_within_budget() {
    // A triple-nested Fn::ForEach with combinatorial output and a wide body must
    // produce one transform diagnostic and leave the original section in
    // place—never apply a partially expanded set of resources.
    let bytes = common::load_security("foreach_branch_explosion.yaml");
    let start = std::time::Instant::now();
    let model = SemanticModel::from_bytes(&bytes).expect("model must build even when budget is exhausted");
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(30),
        "model construction must complete quickly once the budget caps expansion; took {:?}",
        elapsed
    );
    let budget_diags: Vec<_> = model.diagnostics.iter().filter(|d| d.message.contains("expansion budget")).collect();
    assert_eq!(
        budget_diags.len(),
        1,
        "exactly one budget-exhaustion diagnostic (E0001) must be emitted; got: {:?}",
        model.diagnostics.iter().map(|d| &d.rule_id).collect::<Vec<_>>()
    );
    assert_eq!(budget_diags[0].rule_id, "E0001");
    assert!(
        model.resources.len() <= 1,
        "a failed transform must not apply a partial generated section; got {} modeled resources",
        model.resources.len()
    );
    // The universal sweep above validates that both engines return within the
    // test-only wall-clock deadline on this same fixture.
}

#[test]
fn deep_yaml_nesting_is_rejected_with_structured_error() {
    let bytes = common::load_security("deep_yaml_nesting.yaml");
    let result = SemanticModel::from_bytes(&bytes);
    let error = match result {
        Err(e) => e,
        Ok(_) => panic!("a deeply nested YAML template must fail with a parse error"),
    };
    let msg = error.to_string().to_lowercase();
    assert!(msg.contains("nesting depth"), "error must reference nesting depth, got: {}", error);
}

#[test]
fn deep_intrinsic_resolution_completes_within_budget() {
    // A valid template with deeply nested block-style Fn::If chains (64 levels,
    // one condition) must parse to a SemanticModel, produce the expected resource,
    // and resolve within the timeout on both engines without error.
    let bytes = common::load_security("deep_intrinsic_resolution.yaml");

    // Phase 1: Assert the SemanticModel builds and has the expected shape.
    let model =
        SemanticModel::from_bytes(&bytes).expect("deeply nested Fn::If must parse successfully into a SemanticModel");
    assert_eq!(model.resources.len(), 1, "fixture has exactly one resource (DeepIfResource)");
    assert!(model.resources.contains_key("DeepIfResource"), "resource logical ID must be DeepIfResource");
    assert!(model.conditions.conditions.contains_key("IsUsEast1"), "fixture declares a single condition IsUsEast1");

    // Phase 2: Both engines complete validation without error.
    for engine_name in ["rego", "cel"] {
        let engine_bytes = common::load_security("deep_intrinsic_resolution.yaml");
        let finished = validate_within(COMPLETION_BUDGET, engine_name, engine_bytes);
        assert!(
            finished.is_some(),
            "{engine_name}: deep intrinsic resolution must complete within {COMPLETION_BUDGET:?}"
        );
        finished.unwrap().unwrap_or_else(|e| panic!("{engine_name}: deep intrinsic resolution must not error: {e}"));
    }
}
