use std::fmt::Write as FmtWrite;
use std::io::Write;
use std::path::Path;
use std::{env, fs, panic, path::PathBuf, process, time::Instant};

use cel_engine::CelEngine;
use diagnostics::{DetailLevel, ValidationReport};
use log::{error, info, warn};
use rego_engine::RegoEngine;
use rules::Severity;
use schema_validator::SchemaValidator;
use sha2::{Digest, Sha256};
use template_model::SemanticModel;
use validation_engine::{EngineConfig, EngineType, ValidateConfig, ValidationEngine, validate_bytes_with_path};

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        eprintln!("Usage: cfn-benchmark [TEMPLATE|DIR] [--engine rego|cel] [--iterations N]");
        process::exit(2);
    }

    let default_template_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("resources");
    let template_dir_arg = args.get(1).filter(|a| !a.starts_with('-')).map(|s| s.to_string());
    let template_dir = template_dir_arg.as_deref().unwrap_or_else(|| default_template_dir.to_str().unwrap());

    let engine_type = args
        .iter()
        .position(|a| a == "--engine")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| EngineType::parse(s).ok())
        .unwrap_or_default();

    let iterations: usize = args
        .iter()
        .position(|a| a == "--iterations")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(20)
        .max(1);

    // Hardcoded: benchmarks always use DETAILED format and DEBUG severity to capture
    // all diagnostics, so the native/wasm/jvm harnesses all measure the same work.
    let detail_level = DetailLevel::Detailed;
    let severity_level = Severity::Debug;
    let format_str = "detailed";

    // First sample is cold (no JIT/codegen cache); rest are warm.
    let config = EngineConfig::default();
    let mut schema_init_samples_ms: Vec<f64> = Vec::with_capacity(iterations);
    let mut engine_init_samples_ms: Vec<f64> = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let t0 = Instant::now();
        let sv = SchemaValidator::new();
        schema_init_samples_ms.push(t0.elapsed().as_secs_f64() * 1000.0);

        let t1 = Instant::now();
        let e: Box<dyn ValidationEngine> = match engine_type {
            EngineType::Cel => Box::new(CelEngine::new(config.clone()).expect("cel engine init failed")),
            EngineType::Rego => Box::new(RegoEngine::new(config.clone()).expect("rego engine init failed")),
        };
        engine_init_samples_ms.push(t1.elapsed().as_secs_f64() * 1000.0);
        drop(e);
        drop(sv);
    }
    let init_samples_ms: Vec<f64> =
        schema_init_samples_ms.iter().zip(engine_init_samples_ms.iter()).map(|(s, e)| s + e).collect();
    let cold_init_ms = init_samples_ms[0];
    let warm_init_samples_ms: Vec<f64> =
        if init_samples_ms.len() > 1 { init_samples_ms[1..].to_vec() } else { init_samples_ms.clone() };

    let schema_validator = SchemaValidator::new();
    let engine: Box<dyn ValidationEngine> = match engine_type {
        EngineType::Cel => Box::new(CelEngine::new(config.clone()).expect("cel engine init failed")),
        EngineType::Rego => Box::new(RegoEngine::new(config.clone()).expect("rego engine init failed")),
    };

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let engine_name = engine.engine_name();
    let output_dir = manifest.join("reports").join(engine_name);

    let input_path = Path::new(template_dir);
    let mut templates = cfn_validate::collect_files(input_path);
    // Sort by string representation (not PathBuf component-wise) for consistency
    // with TS and Kotlin harnesses.
    templates.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
    info!("Found {} templates in {}", templates.len(), template_dir);

    if templates.is_empty() {
        error!("No templates found in {}", template_dir);
        process::exit(1);
    }

    let json_dir = output_dir.join(format!("json_{}", format_str));
    fs::create_dir_all(&json_dir).expect("failed to create json dir");

    let mut results: Vec<TemplateResult> = Vec::new();
    // Deferred until after the timed loop so disk I/O does not contaminate throughput.
    let mut deferred_writes: Vec<(PathBuf, String, (ValidationReport, serde_json::Value))> = Vec::new();

    // Amortize first-call costs so throughput numbers are comparable across harnesses.
    let benchmark_config = ValidateConfig { detail_level: detail_level.clone(), severity_level, ..Default::default() };
    if let Some(first) = templates.first()
        && let Ok(bytes) = fs::read(first)
    {
        let _ = SemanticModel::parse(&bytes, Default::default());
        let _ = validate_bytes_with_path(
            engine.as_ref(),
            &schema_validator,
            &bytes,
            benchmark_config.clone(),
            first.display().to_string(),
        );
    }

    let bench_start = Instant::now();

    for template_path in &templates {
        let stripped = template_path.strip_prefix(template_dir).unwrap_or(template_path).display().to_string();
        let relative_path = stripped.trim_start_matches('/');
        let relative_path = if relative_path.is_empty() {
            template_path.file_name().unwrap_or_default().to_string_lossy().to_string()
        } else {
            relative_path.to_string()
        };
        eprint!("  {}", relative_path);

        let bytes = match fs::read(template_path) {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to read {}: {}", relative_path, e);
                results.push(TemplateResult::error(&relative_path, "read_error", &e.to_string()));
                continue;
            }
        };

        let size_bytes = bytes.len();

        let mut iter_model_build_ms: Vec<f64> = Vec::with_capacity(iterations);
        let mut iter_schema_validate_ms: Vec<f64> = Vec::with_capacity(iterations);
        let mut iter_rule_eval_ms: Vec<f64> = Vec::with_capacity(iterations);
        let mut iter_finalize_ms: Vec<f64> = Vec::with_capacity(iterations);
        // Measures parse cost independently from validate_bytes (which re-parses internally),
        // so parse latency can be compared across bindings on host-language clocks.
        let mut iter_host_model_ms: Vec<f64> = Vec::with_capacity(iterations);
        let mut iter_engine_internal_ms: Vec<f64> = Vec::with_capacity(iterations);
        let mut iter_host_validate_ms: Vec<f64> = Vec::with_capacity(iterations);
        let mut last_report = None;
        let mut failed = false;

        for i in 0..iterations {
            let tm0 = Instant::now();
            let _parsed = match SemanticModel::parse(&bytes, Default::default()) {
                Ok(m) => m,
                Err(e) => {
                    warn!("{} parse failed: {}", relative_path, e);
                    results.push(TemplateResult::error(&relative_path, "parse_error", &e.to_string()));
                    failed = true;
                    break;
                }
            };
            iter_host_model_ms.push(tm0.elapsed().as_secs_f64() * 1000.0);

            let t0 = Instant::now();
            let report = match panic::catch_unwind(panic::AssertUnwindSafe(|| {
                validate_bytes_with_path(
                    engine.as_ref(),
                    &schema_validator,
                    &bytes,
                    benchmark_config.clone(),
                    relative_path.clone(),
                )
            })) {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    warn!("{} failed: {}", relative_path, e);
                    results.push(TemplateResult::error(&relative_path, "error", &e.to_string()));
                    failed = true;
                    break;
                }
                Err(_) => {
                    error!("{} panicked during validation", relative_path);
                    results.push(TemplateResult::error(&relative_path, "panic", "panic during validate"));
                    failed = true;
                    break;
                }
            };
            let host_validate_ms = t0.elapsed().as_secs_f64() * 1000.0;
            let perf = &report.performance;
            iter_model_build_ms.push(perf.model_build.duration_ms);
            iter_schema_validate_ms.push(perf.schema_validate.duration_ms);
            iter_rule_eval_ms.push(perf.rule_evaluation.duration_ms);
            iter_finalize_ms.push(perf.diagnostic_finalize.duration_ms);
            iter_engine_internal_ms.push(perf.validate_total.duration_ms);
            iter_host_validate_ms.push(host_validate_ms);

            if i == iterations - 1 {
                last_report = Some(report);
            }
        }
        if failed {
            continue;
        }
        let report = last_report.unwrap();

        let cold_engine_internal_ms = iter_engine_internal_ms[0];
        let warm_engine_internal_ms =
            if iterations > 1 { median_f64(&iter_engine_internal_ms[1..]) } else { cold_engine_internal_ms };
        let median_engine_internal_ms = median_f64(&iter_engine_internal_ms);
        let cold_wall_clock_ms = iter_host_validate_ms[0];
        let warm_wall_clock_ms =
            if iterations > 1 { median_f64(&iter_host_validate_ms[1..]) } else { cold_wall_clock_ms };
        let median_wall_clock_ms = median_f64(&iter_host_validate_ms);
        let cold_host_model_ms = iter_host_model_ms[0];
        let warm_host_model_ms = if iterations > 1 { median_f64(&iter_host_model_ms[1..]) } else { cold_host_model_ms };
        let median_host_model_ms = median_f64(&iter_host_model_ms);
        // On wasm/jvm this captures ABI cost (bytes copy, serialization, FFI dispatch).
        let binding_overhead_ms = round4(median_wall_clock_ms - median_engine_internal_ms);

        let report_resources = report.metadata.resources_scanned as usize;
        let report_fatal = report.metadata.counts.fatal;
        let report_errors = report.metadata.counts.errors;
        let report_warnings = report.metadata.counts.warnings;
        let report_informational = report.metadata.counts.informational;
        let report_diag_count = report.diagnostics.len();

        // Deferred until after the timed loop so disk I/O is not measured.
        // Keep the file extension as part of the key (".yaml" -> "_yaml") so a
        // template authored in both JSON and YAML (e.g. format round-trip tests)
        // produces two distinct reports instead of one overwriting the other.
        let json_stem =
            relative_path.replace('/', "_").replace(".yaml", "_yaml").replace(".yml", "_yml").replace(".json", "_json");
        let dump_report = report;
        let benchmark_metrics = serde_json::json!({
            "iterations": iterations,
            "firstIteration": {
                "hostModelMs": round4(iter_host_model_ms[0]),
                "modelBuildMs": round4(iter_model_build_ms[0]),
                "schemaValidateMs": round4(iter_schema_validate_ms[0]),
                "ruleEvaluationMs": round4(iter_rule_eval_ms[0]),
                "diagnosticFinalizeMs": round4(iter_finalize_ms[0]),
                "engineInternalMs": round4(cold_engine_internal_ms),
                "wallClockMs": round4(cold_wall_clock_ms),
            },
            "steadyState": {
                "hostModelMs": round4(warm_host_model_ms),
                "modelBuildMs": round4(if iterations > 1 { median_f64(&iter_model_build_ms[1..]) } else { iter_model_build_ms[0] }),
                "schemaValidateMs": round4(if iterations > 1 { median_f64(&iter_schema_validate_ms[1..]) } else { iter_schema_validate_ms[0] }),
                "ruleEvaluationMs": round4(if iterations > 1 { median_f64(&iter_rule_eval_ms[1..]) } else { iter_rule_eval_ms[0] }),
                "diagnosticFinalizeMs": round4(if iterations > 1 { median_f64(&iter_finalize_ms[1..]) } else { iter_finalize_ms[0] }),
                "engineInternalMs": round4(warm_engine_internal_ms),
                "wallClockMs": round4(warm_wall_clock_ms),
            },
            "bindingOverheadMs": binding_overhead_ms,
        });
        let json_path = json_dir.join(format!("{}.json", json_stem));
        deferred_writes.push((json_path, relative_path.clone(), (dump_report, benchmark_metrics)));

        let template_result = TemplateResult {
            file: relative_path.to_string(),
            status: "ok".into(),
            size_bytes,
            resources: report_resources,
            fatal: report_fatal,
            errors: report_errors,
            warnings: report_warnings,
            informational: report_informational,
            diag_count: report_diag_count,
            host_model_ms: median_host_model_ms,
            cold_host_model_ms,
            warm_host_model_ms,
            model_build_ms: median_f64(&iter_model_build_ms),
            schema_validate_ms: median_f64(&iter_schema_validate_ms),
            rule_eval_ms: median_f64(&iter_rule_eval_ms),
            diagnostic_finalize_ms: median_f64(&iter_finalize_ms),
            engine_internal_ms: median_engine_internal_ms,
            cold_engine_internal_ms,
            warm_engine_internal_ms,
            wall_clock_ms: median_wall_clock_ms,
            cold_wall_clock_ms,
            warm_wall_clock_ms,
            binding_overhead_ms,
            error_msg: None,
        };
        eprintln!(
            "  model={:.4}ms  engine={:.4}ms  wall={:.4}ms  {}E {}W {}I",
            template_result.host_model_ms,
            template_result.engine_internal_ms,
            template_result.wall_clock_ms,
            template_result.errors,
            template_result.warnings,
            template_result.informational
        );
        results.push(template_result);
    }

    let total_wall_ms = bench_start.elapsed().as_secs_f64() * 1000.0;

    for (json_path, _relative_path, (report, benchmark_metrics)) in deferred_writes.drain(..) {
        let detailed = report.to_detailed();
        let mut template_json = serde_json::to_value(&detailed).unwrap();
        template_json["engine"] = serde_json::json!(engine_name);
        template_json["binding"] = serde_json::json!("native");
        template_json["detailLevel"] = serde_json::json!("DETAILED");
        template_json["benchmarkMetrics"] = benchmark_metrics;
        if let Ok(mut f) = fs::File::create(&json_path) {
            let _ = f.write_all(serde_json::to_string_pretty(&template_json).unwrap().as_bytes());
        }
    }

    let successful_results: Vec<&TemplateResult> = results.iter().filter(|r| r.status == "ok").collect();
    let failed_results: Vec<&TemplateResult> = results.iter().filter(|r| r.status != "ok").collect();

    let model_build_vec: Vec<f64> = successful_results.iter().map(|r| r.model_build_ms).collect();
    let schema_validate_vec: Vec<f64> = successful_results.iter().map(|r| r.schema_validate_ms).collect();
    let rule_eval_vec: Vec<f64> = successful_results.iter().map(|r| r.rule_eval_ms).collect();
    let finalize_vec: Vec<f64> = successful_results.iter().map(|r| r.diagnostic_finalize_ms).collect();
    let engine_internal_vec: Vec<f64> = successful_results.iter().map(|r| r.engine_internal_ms).collect();
    let cold_engine_internal_vec: Vec<f64> = successful_results.iter().map(|r| r.cold_engine_internal_ms).collect();
    let warm_engine_internal_vec: Vec<f64> = successful_results.iter().map(|r| r.warm_engine_internal_ms).collect();
    let wall_clock_vec: Vec<f64> = successful_results.iter().map(|r| r.wall_clock_ms).collect();
    let cold_wall_clock_vec: Vec<f64> = successful_results.iter().map(|r| r.cold_wall_clock_ms).collect();
    let warm_wall_clock_vec: Vec<f64> = successful_results.iter().map(|r| r.warm_wall_clock_ms).collect();
    let host_model_vec: Vec<f64> = successful_results.iter().map(|r| r.host_model_ms).collect();
    let cold_host_model_vec: Vec<f64> = successful_results.iter().map(|r| r.cold_host_model_ms).collect();
    let warm_host_model_vec: Vec<f64> = successful_results.iter().map(|r| r.warm_host_model_ms).collect();
    let binding_overhead_vec: Vec<f64> = successful_results.iter().map(|r| r.binding_overhead_ms).collect();

    let throughput_per_sec = if total_wall_ms > 0.0 {
        (successful_results.len() * iterations) as f64 / (total_wall_ms / 1000.0)
    } else {
        0.0
    };

    let (corpus_fingerprint, fingerprint_file_count) = compute_corpus_fingerprint(input_path);
    let run_fingerprint = run_fingerprint(&corpus_fingerprint, engine_name, "DETAILED", iterations);

    let aggregate_stats = serde_json::json!({
        "timestamp": chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        "engine": engine_name,
        "binding": "native",
        "detail_level": "DETAILED",
        "template_dir": template_dir,
        "templates_total": results.len(),
        "templates_ok": successful_results.len(),
        "templates_failed": failed_results.len(),
        "iterations_per_template": iterations,
        "corpus_fingerprint": corpus_fingerprint,
        "corpus_file_count": fingerprint_file_count,
        "run_fingerprint": run_fingerprint,
        "performance": {
            "module_load_ms": 0.0,
            "init_ms": stats_json(&init_samples_ms),
            "cold_init_ms": round4(cold_init_ms),
            "warm_init_ms": stats_json(&warm_init_samples_ms),
            "schema_init_ms": stats_json(&schema_init_samples_ms),
            "engine_init_ms": stats_json(&engine_init_samples_ms),
            "total_wall_ms": round4(total_wall_ms),
            "throughput_per_sec": round4(throughput_per_sec),
            "model_build_ms": stats_json(&model_build_vec),
            "schema_validate_ms": stats_json(&schema_validate_vec),
            "rule_evaluation_ms": stats_json(&rule_eval_vec),
            "diagnostic_finalize_ms": stats_json(&finalize_vec),
            "engine_internal_ms": stats_json(&engine_internal_vec),
            "cold_engine_internal_ms": stats_json(&cold_engine_internal_vec),
            "warm_engine_internal_ms": stats_json(&warm_engine_internal_vec),
            "wall_clock_ms": stats_json(&wall_clock_vec),
            "cold_wall_clock_ms": stats_json(&cold_wall_clock_vec),
            "warm_wall_clock_ms": stats_json(&warm_wall_clock_vec),
            "host_model_ms": stats_json(&host_model_vec),
            "cold_host_model_ms": stats_json(&cold_host_model_vec),
            "warm_host_model_ms": stats_json(&warm_host_model_vec),
            "binding_overhead_ms": stats_json(&binding_overhead_vec),
        },
        "diagnostics": {
            "total_fatal": successful_results.iter().map(|r| r.fatal as u64).sum::<u64>(),
            "total_errors": successful_results.iter().map(|r| r.errors as u64).sum::<u64>(),
            "total_warnings": successful_results.iter().map(|r| r.warnings as u64).sum::<u64>(),
            "total_informational": successful_results.iter().map(|r| r.informational as u64).sum::<u64>(),
        },
        "failures": failed_results.iter().map(|r| serde_json::json!({"file": r.file, "status": r.status, "error": r.error_msg})).collect::<Vec<_>>(),
    });
    let aggregate_path = output_dir.join(format!("aggregate_{}.json", format_str));
    fs::write(&aggregate_path, serde_json::to_string_pretty(&aggregate_stats).unwrap()).expect("write aggregate json");

    let report_markdown = generate_markdown(
        &results,
        &successful_results,
        &failed_results,
        &init_samples_ms,
        &schema_init_samples_ms,
        &engine_init_samples_ms,
        &cold_engine_internal_vec,
        &warm_engine_internal_vec,
        &cold_wall_clock_vec,
        &warm_wall_clock_vec,
        &cold_host_model_vec,
        &warm_host_model_vec,
        &host_model_vec,
        &model_build_vec,
        &schema_validate_vec,
        &rule_eval_vec,
        &finalize_vec,
        &engine_internal_vec,
        &wall_clock_vec,
        &binding_overhead_vec,
        total_wall_ms,
        throughput_per_sec,
        engine_name,
        iterations,
        &corpus_fingerprint,
        fingerprint_file_count,
    );
    let report_path = output_dir.join(format!("report_{}.md", format_str));
    fs::write(&report_path, &report_markdown).expect("write report md");

    eprintln!();
    info!(
        "Benchmark complete: {} ok, {} failed ({} iterations/template)",
        successful_results.len(),
        failed_results.len(),
        iterations
    );
    info!(
        "engine_internal (median): median={:.4}ms p99={:.4}ms max={:.4}ms",
        median_f64(&engine_internal_vec),
        percentile_f64(&engine_internal_vec, 99),
        max_f64(&engine_internal_vec)
    );
    info!(
        "wall_clock     (median): median={:.4}ms p99={:.4}ms max={:.4}ms",
        median_f64(&wall_clock_vec),
        percentile_f64(&wall_clock_vec, 99),
        max_f64(&wall_clock_vec)
    );
    info!("Throughput: {:.2} validations/sec", throughput_per_sec);
    info!("Corpus fingerprint: {} ({} files)", corpus_fingerprint, fingerprint_file_count);
    info!("Reports written to {}", output_dir.display());
}

struct TemplateResult {
    file: String,
    status: String,
    size_bytes: usize,
    resources: usize,
    fatal: u32,
    errors: u32,
    warnings: u32,
    informational: u32,
    diag_count: usize,
    host_model_ms: f64,
    cold_host_model_ms: f64,
    warm_host_model_ms: f64,
    model_build_ms: f64,
    schema_validate_ms: f64,
    rule_eval_ms: f64,
    diagnostic_finalize_ms: f64,
    engine_internal_ms: f64,
    cold_engine_internal_ms: f64,
    warm_engine_internal_ms: f64,
    wall_clock_ms: f64,
    cold_wall_clock_ms: f64,
    warm_wall_clock_ms: f64,
    binding_overhead_ms: f64,
    error_msg: Option<String>,
}

impl TemplateResult {
    fn error(file: &str, status: &str, msg: &str) -> Self {
        Self {
            file: file.into(),
            status: status.into(),
            size_bytes: 0,
            resources: 0,
            fatal: 0,
            errors: 0,
            warnings: 0,
            informational: 0,
            diag_count: 0,
            host_model_ms: 0.0,
            cold_host_model_ms: 0.0,
            warm_host_model_ms: 0.0,
            model_build_ms: 0.0,
            schema_validate_ms: 0.0,
            rule_eval_ms: 0.0,
            diagnostic_finalize_ms: 0.0,
            engine_internal_ms: 0.0,
            cold_engine_internal_ms: 0.0,
            warm_engine_internal_ms: 0.0,
            wall_clock_ms: 0.0,
            cold_wall_clock_ms: 0.0,
            warm_wall_clock_ms: 0.0,
            binding_overhead_ms: 0.0,
            error_msg: Some(msg.into()),
        }
    }
}

fn generate_markdown(
    results: &[TemplateResult],
    successful_results: &[&TemplateResult],
    failed_results: &[&TemplateResult],
    init_ms: &[f64],
    schema_init_ms: &[f64],
    engine_init_ms: &[f64],
    cold_engine_internal: &[f64],
    warm_engine_internal: &[f64],
    cold_wall_clock: &[f64],
    warm_wall_clock: &[f64],
    cold_host_model: &[f64],
    warm_host_model: &[f64],
    host_model_ms: &[f64],
    model_build_ms: &[f64],
    schema_validate_ms: &[f64],
    rule_eval_ms: &[f64],
    diagnostic_finalize_ms: &[f64],
    engine_internal_ms: &[f64],
    wall_clock_ms: &[f64],
    binding_overhead_ms: &[f64],
    total_wall_ms: f64,
    throughput_per_sec: f64,
    engine_name: &str,
    iterations: usize,
    corpus_fingerprint: &str,
    corpus_file_count: usize,
) -> String {
    let mut report_markdown = String::new();
    report_markdown
        .push_str(&format!("# cloudformation-validate Benchmark Report — {} engine (DETAILED)\n\n", engine_name));
    report_markdown.push_str(&format!("Generated: {}\n\n", chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ")));
    report_markdown
        .push_str(&format!("Corpus fingerprint: `{}` ({} files)\n\n", corpus_fingerprint, corpus_file_count));

    report_markdown.push_str("## Summary\n\n");
    report_markdown.push_str("| Metric | Value |\n|---|---|\n");
    report_markdown.push_str(&format!(
        "| Templates | {} ok, {} failed, {} total |\n",
        successful_results.len(),
        failed_results.len(),
        results.len()
    ));
    report_markdown.push_str(&format!("| Iterations per template | {} |\n", iterations));
    report_markdown.push_str(&format!(
        "| Total resources | {} |\n",
        successful_results.iter().map(|r| r.resources).sum::<usize>()
    ));
    report_markdown.push_str(&format!("| Total wall time | {:.4} ms |\n", total_wall_ms));
    report_markdown.push_str(&format!("| Throughput | {:.2} validations/sec |\n", throughput_per_sec));
    report_markdown.push_str("| Detail level | DETAILED |\n");

    report_markdown.push_str("\n## Initialization (ms)\n\n");
    report_markdown.push_str("| Stat | Schema Init | Engine Init | Combined |\n|---|---|---|---|\n");
    report_markdown.push_str(&format!(
        "| Median | {:.4} | {:.4} | {:.4} |\n",
        median_f64(schema_init_ms),
        median_f64(engine_init_ms),
        median_f64(init_ms)
    ));
    report_markdown.push_str(&format!(
        "| P99 | {:.4} | {:.4} | {:.4} |\n",
        percentile_f64(schema_init_ms, 99),
        percentile_f64(engine_init_ms, 99),
        percentile_f64(init_ms, 99)
    ));
    report_markdown.push_str(&format!(
        "| Max | {:.4} | {:.4} | {:.4} |\n",
        max_f64(schema_init_ms),
        max_f64(engine_init_ms),
        max_f64(init_ms)
    ));

    report_markdown.push_str("\n## Validation Latency (ms, median / p99 / max per template)\n\n");
    report_markdown
        .push_str("host_model = host timer around SemanticModel::parse (bytes → model). Includes FFI on wasm/jvm.\n");
    report_markdown
        .push_str("wall_clock = host timer around validate_bytes (full validate call, re-parses internally).\n");
    report_markdown.push_str("engine_internal = Rust-internal `report.performance.total` (engine work only).\n\n");
    report_markdown.push_str("| Metric | Median | P99 | Max |\n|---|---|---|---|\n");
    for (label, vals) in [
        ("Cold host_model (first iter)", cold_host_model),
        ("Warm host_model (steady)", warm_host_model),
        ("Cold engine_internal (first iter)", cold_engine_internal),
        ("Warm engine_internal (steady)", warm_engine_internal),
        ("Cold wall_clock (first iter)", cold_wall_clock),
        ("Warm wall_clock (steady)", warm_wall_clock),
        ("host_model (per-template median)", host_model_ms),
        ("engine_internal (per-template median)", engine_internal_ms),
        ("wall_clock (per-template median)", wall_clock_ms),
        ("Model build (rust-internal)", model_build_ms),
        ("Schema validate (rust-internal)", schema_validate_ms),
        ("Rule evaluation (rust-internal)", rule_eval_ms),
        ("Diagnostic finalize (rust-internal)", diagnostic_finalize_ms),
        ("Binding overhead (wall − internal)", binding_overhead_ms),
    ] {
        report_markdown.push_str(&format!(
            "| {} | {:.4} | {:.4} | {:.4} |\n",
            label,
            median_f64(vals),
            percentile_f64(vals, 99),
            max_f64(vals),
        ));
    }

    report_markdown.push_str("\n## Diagnostics\n\n");
    report_markdown.push_str("| Level | Count |\n|---|---|\n");
    report_markdown
        .push_str(&format!("| Fatal | {} |\n", successful_results.iter().map(|r| r.fatal as u64).sum::<u64>()));
    report_markdown
        .push_str(&format!("| Errors | {} |\n", successful_results.iter().map(|r| r.errors as u64).sum::<u64>()));
    report_markdown
        .push_str(&format!("| Warnings | {} |\n", successful_results.iter().map(|r| r.warnings as u64).sum::<u64>()));
    report_markdown.push_str(&format!(
        "| Informational | {} |\n",
        successful_results.iter().map(|r| r.informational as u64).sum::<u64>()
    ));

    report_markdown.push_str("\n## All Results\n\n");
    let mut all_sorted: Vec<&TemplateResult> = results.iter().collect();
    all_sorted.sort_by(|a, b| b.wall_clock_ms.partial_cmp(&a.wall_clock_ms).unwrap());
    report_markdown.push_str("| # | Template | Status | Size | Resources | Model (ms) | Schema (ms) | Rules (ms) | Finalize (ms) | Engine (ms) | Wall (ms) | Overhead (ms) | F | E | W | I | Diags |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
    for (i, r) in all_sorted.iter().enumerate() {
        if r.status == "ok" {
            report_markdown.push_str(&format!(
                "| {} | {} | ✅ | {} | {} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} | {} | {} | {} | {} | {} |\n",
                i + 1, r.file, fmt_bytes(r.size_bytes), r.resources,
                r.model_build_ms, r.schema_validate_ms, r.rule_eval_ms, r.diagnostic_finalize_ms,
                r.engine_internal_ms, r.wall_clock_ms, r.binding_overhead_ms,
                r.fatal, r.errors, r.warnings, r.informational, r.diag_count
            ));
        } else {
            report_markdown.push_str(&format!(
                "| {} | {} | ❌ {} | - | - | - | - | - | - | - | - | - | 0 | 0 | 0 | 0 | 0 |\n",
                i + 1,
                r.file,
                r.status
            ));
        }
    }

    if !failed_results.is_empty() {
        report_markdown.push_str("\n## Failures\n\n");
        for r in failed_results {
            report_markdown.push_str(&format!(
                "- **{}**: {} — {}\n",
                r.file,
                r.status,
                r.error_msg.as_deref().unwrap_or("unknown")
            ));
        }
    }

    report_markdown
}

fn min_f64(vals: &[f64]) -> f64 {
    if vals.is_empty() {
        return 0.0;
    }
    vals.iter().cloned().fold(f64::INFINITY, f64::min)
}
fn max_f64(vals: &[f64]) -> f64 {
    if vals.is_empty() {
        return 0.0;
    }
    vals.iter().cloned().fold(f64::NEG_INFINITY, f64::max)
}
fn avg_f64(vals: &[f64]) -> f64 {
    if vals.is_empty() { 0.0 } else { vals.iter().sum::<f64>() / vals.len() as f64 }
}
fn median_f64(vals: &[f64]) -> f64 {
    if vals.is_empty() {
        return 0.0;
    }
    let mut sorted = vals.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = sorted.len();
    if n.is_multiple_of(2) { (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0 } else { sorted[n / 2] }
}
fn percentile_f64(vals: &[f64], pct: u64) -> f64 {
    if vals.is_empty() {
        return 0.0;
    }
    let mut sorted = vals.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let rank = (pct as f64 / 100.0) * (sorted.len() - 1) as f64;
    let lo = rank.floor() as usize;
    let hi = rank.ceil().min((sorted.len() - 1) as f64) as usize;
    let frac = rank - lo as f64;
    sorted[lo] + frac * (sorted[hi] - sorted[lo])
}

fn stddev_f64(vals: &[f64]) -> f64 {
    if vals.len() < 2 {
        return 0.0;
    }
    let mean = avg_f64(vals);
    let variance = vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (vals.len() - 1) as f64;
    variance.sqrt()
}

fn stats_json(vals: &[f64]) -> serde_json::Value {
    serde_json::json!({
        "min": round4(min_f64(vals)),
        "avg": round4(avg_f64(vals)),
        "stddev": round4(stddev_f64(vals)),
        "median": round4(median_f64(vals)),
        "p90": round4(percentile_f64(vals, 90)),
        "p95": round4(percentile_f64(vals, 95)),
        "p99": round4(percentile_f64(vals, 99)),
        "max": round4(max_f64(vals)),
        "total": round4(vals.iter().sum::<f64>()),
    })
}

fn round4(v: f64) -> f64 {
    (v * 10000.0).round() / 10000.0
}

fn fmt_bytes(n: usize) -> String {
    if n >= 1_048_576 {
        format!("{:.1} MB", n as f64 / 1_048_576.0)
    } else if n >= 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{} B", n)
    }
}

/// Lowercase, zero-padded hex of a SHA-256 digest — the standard encoding every
/// harness (native/TS/JVM) shares, so fingerprints compare byte-for-byte.
fn to_hex(digest: impl AsRef<[u8]>) -> String {
    let mut hex = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        write!(hex, "{byte:02x}").expect("writing to a String never fails");
    }
    hex
}

/// Relative paths are sorted as raw strings (not `PathBuf` component-wise) so the
/// fingerprint matches byte-for-byte across native/TS/JVM harnesses.
fn compute_corpus_fingerprint(root: &Path) -> (String, usize) {
    let files = cfn_validate::collect_files(root);
    let mut relative_and_absolute: Vec<(String, PathBuf)> = files
        .into_iter()
        .map(|f| {
            let rel = f.strip_prefix(root).unwrap_or(&f).display().to_string().trim_start_matches('/').to_string();
            let rel =
                if rel.is_empty() { f.file_name().unwrap_or_default().to_string_lossy().to_string() } else { rel };
            (rel, f)
        })
        .collect();
    relative_and_absolute.sort_by(|a, b| a.0.cmp(&b.0));

    let mut outer = Sha256::new();
    for (rel, abs) in &relative_and_absolute {
        let content = fs::read(abs).unwrap_or_default();
        let mut inner = Sha256::new();
        inner.update(&content);
        let file_hash = to_hex(inner.finalize());
        outer.update(format!("{}\t{}\n", rel, file_hash).as_bytes());
    }
    (to_hex(outer.finalize()), relative_and_absolute.len())
}

/// Deterministic across bindings for the same (corpus, engine, format, iterations) tuple.
fn run_fingerprint(corpus_fp: &str, engine: &str, format: &str, iterations: usize) -> String {
    let mut h = Sha256::new();
    h.update(format!("{}|{}|{}|{}", corpus_fp, engine, format, iterations).as_bytes());
    to_hex(h.finalize())
}
