use std::io::Write;
use std::path::{Path, PathBuf};
use std::{env, fs, panic, process, time::Instant};

use cel_engine::CelEngine;
use diagnostics::{DetailLevel, ValidationReport};
use log::{error, info, warn};
use rego_engine::RegoEngine;
use rules::Severity;
use schema_validator::SchemaValidator;
use sha2::{Digest, Sha256};
use template_model::SemanticModel;
use validation_engine::{EngineConfig, EngineType, ValidateConfig, ValidationEngine, validate_bytes_with_path};

/// Replaces the file-extension suffix of a path string, leaving interior occurrences untouched.
/// Only the trailing `suffix` is replaced; if the string does not end with `suffix`, it is
/// returned unchanged.
fn replace_extension_suffix(s: &str, suffix: &str, replacement: &str) -> String {
    match s.strip_suffix(suffix) {
        Some(stripped) => format!("{stripped}{replacement}"),
        None => s.to_string(),
    }
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    if let Err(e) = run() {
        eprintln!("cfn-benchmark: error: {e}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        eprintln!("Usage: cfn-benchmark [TEMPLATE|DIR] [--engine rego|cel] [--iterations N]");
        process::exit(2);
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let default_template_dir = manifest_dir
        .parent()
        .ok_or_else(|| format!("manifest directory '{}' has no parent", manifest_dir.display()))?
        .join("resources")
        .join("templates");
    let template_dir_arg = args.get(1).filter(|a| !a.starts_with('-')).map(|s| s.to_string());
    let template_dir = match template_dir_arg.as_deref() {
        Some(path) => path,
        None => default_template_dir
            .to_str()
            .ok_or_else(|| format!("template path '{}' is not valid UTF-8", default_template_dir.display()))?,
    };

    let engine_type = match args.iter().position(|a| a == "--engine") {
        Some(i) => match args.get(i + 1) {
            Some(s) => match EngineType::parse(s) {
                Ok(e) => e,
                Err(_) => {
                    eprintln!("Error: --engine must be 'rego' or 'cel', got '{}'", s);
                    process::exit(2);
                }
            },
            None => {
                eprintln!("Error: --engine requires a value");
                process::exit(2);
            }
        },
        None => EngineType::default(),
    };

    let iterations: usize = match args.iter().position(|a| a == "--iterations") {
        Some(i) => match args.get(i + 1) {
            Some(s) => match s.parse::<usize>() {
                Ok(n) if n > 0 => n,
                _ => {
                    eprintln!("Error: --iterations must be a positive integer, got '{}'", s);
                    process::exit(2);
                }
            },
            None => {
                eprintln!("Error: --iterations requires a value");
                process::exit(2);
            }
        },
        None => 20,
    };

    // Hardcoded: benchmarks always use DETAILED format and DEBUG severity to capture
    // all diagnostics, so all five binding harnesses (native/wasm/jvm/python/go) measure the same work.
    let detail_level = DetailLevel::Detailed;
    let severity_level = Severity::Debug;
    let format_str = "detailed";

    // First sample is cold (no JIT/codegen cache); rest are warm.
    let config = EngineConfig::default();
    let mut schema_init_samples_ms: Vec<f64> = Vec::with_capacity(iterations);
    let mut engine_init_samples_ms: Vec<f64> = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let t0 = Instant::now();
        let sv = SchemaValidator::default();
        schema_init_samples_ms.push(t0.elapsed().as_secs_f64() * 1000.0);

        let t1 = Instant::now();
        let e: Box<dyn ValidationEngine> = match engine_type {
            EngineType::Cel => {
                Box::new(CelEngine::new(config.clone()).map_err(|e| format!("CEL engine initialization failed: {e}"))?)
            }
            EngineType::Rego => Box::new(
                RegoEngine::new(config.clone()).map_err(|e| format!("Rego engine initialization failed: {e}"))?,
            ),
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

    let schema_validator = SchemaValidator::default();
    let engine: Box<dyn ValidationEngine> = match engine_type {
        EngineType::Cel => {
            Box::new(CelEngine::new(config.clone()).map_err(|e| format!("CEL engine initialization failed: {e}"))?)
        }
        EngineType::Rego => {
            Box::new(RegoEngine::new(config.clone()).map_err(|e| format!("Rego engine initialization failed: {e}"))?)
        }
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
    // Clean previous output so stale reports from dropped/renamed templates are not left behind.
    if json_dir.exists() {
        fs::remove_dir_all(&json_dir)
            .map_err(|e| format!("failed to remove previous output directory '{}': {e}", json_dir.display()))?;
    }
    fs::create_dir_all(&json_dir)
        .map_err(|e| format!("failed to create output directory '{}': {e}", json_dir.display()))?;

    let mut results: Vec<TemplateResult> = Vec::new();
    // Deferred until after the timed loop so disk I/O does not contaminate throughput.
    let mut deferred_writes: Vec<(PathBuf, String, (ValidationReport, serde_json::Value))> = Vec::new();

    // Amortize first-call costs so throughput numbers are comparable across harnesses.
    let benchmark_config = ValidateConfig { detail_level: detail_level.clone(), severity_level, ..Default::default() };
    if let Some(first) = templates.first()
        && let Ok(bytes) = fs::read(first)
        && SemanticModel::parse(&bytes, Default::default()).is_ok()
    {
        drop(
            validate_bytes_with_path(
                engine.as_ref(),
                &schema_validator,
                &bytes,
                benchmark_config.clone(),
                first.display().to_string(),
            )
            .map_err(|e| format!("warmup validation failed on '{}': {e}", first.display()))?,
        );
    }

    let bench_start = Instant::now();

    for template_path in &templates {
        let stripped = template_path.strip_prefix(template_dir).unwrap_or(template_path).display().to_string();
        let relative_path = stripped.trim_start_matches('/').trim_start_matches('\\');
        let relative_path = if relative_path.is_empty() {
            template_path
                .file_name()
                .ok_or_else(|| format!("template path '{}' has no file name component", template_path.display()))?
                .to_string_lossy()
                .to_string()
        } else {
            // Normalize to forward slashes for cross-platform fingerprint consistency.
            relative_path.replace('\\', "/")
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
        // Keep the file extension as part of the key (".yaml" -> "_yaml") so a
        // template authored in both JSON and YAML (e.g. format round-trip tests)
        // produces two distinct reports instead of one overwriting the other.
        let json_stem = relative_path.replace('/', "_");
        let json_stem = replace_extension_suffix(&json_stem, ".yaml", "_yaml");
        let json_stem = replace_extension_suffix(&json_stem, ".yml", "_yml");
        let json_stem = replace_extension_suffix(&json_stem, ".json", "_json");
        let json_path = json_dir.join(format!("{}.json", json_stem));

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
                    let mut report = validate_bytes_with_path(
                        engine.as_ref(),
                        &schema_validator,
                        &bytes,
                        benchmark_config.clone(),
                        relative_path.clone(),
                    )
                    .map_err(|report_error| {
                        format!("failed to create parse-failure report for '{relative_path}': {report_error}")
                    })?;
                    report.diagnostics.clear();
                    report.metadata.counts.fatal = 0;
                    report.metadata.counts.errors = 0;
                    report.metadata.counts.warnings = 0;
                    report.metadata.counts.informational = 0;
                    report.metadata.counts.debug = 0;
                    report.performance.schema_init.duration_ms = 0.0;
                    report.performance.engine_init.duration_ms = 0.0;
                    report.performance.model_build.duration_ms = 0.0;
                    report.performance.schema_validate.duration_ms = 0.0;
                    report.performance.rule_evaluation.duration_ms = 0.0;
                    report.performance.diagnostic_finalize.duration_ms = 0.0;
                    report.performance.validate_total.duration_ms = 0.0;
                    let benchmark_metrics = serde_json::json!({
                        "iterations": 0,
                        "firstIteration": {
                            "hostModelMs": 0.0,
                            "modelBuildMs": 0.0,
                            "schemaValidateMs": 0.0,
                            "ruleEvaluationMs": 0.0,
                            "diagnosticFinalizeMs": 0.0,
                            "engineInternalMs": 0.0,
                            "wallClockMs": 0.0,
                        },
                        "steadyState": {
                            "hostModelMs": 0.0,
                            "modelBuildMs": 0.0,
                            "schemaValidateMs": 0.0,
                            "ruleEvaluationMs": 0.0,
                            "diagnosticFinalizeMs": 0.0,
                            "engineInternalMs": 0.0,
                            "wallClockMs": 0.0,
                        },
                        "bindingOverheadMs": 0.0,
                    });
                    deferred_writes.push((json_path.clone(), relative_path.clone(), (report, benchmark_metrics)));
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
        let report = last_report.ok_or_else(|| {
            format!("no validation report produced for '{relative_path}' after {iterations} iterations")
        })?;

        let first_engine_internal_ms = iter_engine_internal_ms[0];
        let steady_engine_internal_ms =
            if iterations > 1 { median_f64(&iter_engine_internal_ms[1..]) } else { first_engine_internal_ms };
        let median_engine_internal_ms = median_f64(&iter_engine_internal_ms);
        let first_wall_clock_ms = iter_host_validate_ms[0];
        let steady_wall_clock_ms =
            if iterations > 1 { median_f64(&iter_host_validate_ms[1..]) } else { first_wall_clock_ms };
        let median_wall_clock_ms = median_f64(&iter_host_validate_ms);
        let first_host_model_ms = iter_host_model_ms[0];
        let steady_host_model_ms =
            if iterations > 1 { median_f64(&iter_host_model_ms[1..]) } else { first_host_model_ms };
        let median_host_model_ms = median_f64(&iter_host_model_ms);

        // Binding overhead: median of per-iteration (host wall_clock − engine internal).
        // On wasm/jvm/python/go this captures ABI cost (bytes copy, serialization, FFI dispatch).
        let per_iter_overhead: Vec<f64> = iter_host_validate_ms
            .iter()
            .zip(iter_engine_internal_ms.iter())
            .map(|(wall, internal)| wall - internal)
            .collect();
        let binding_overhead_ms = round4(median_f64(&per_iter_overhead));

        let report_resources = report.metadata.resources_scanned as usize;
        let report_fatal = report.metadata.counts.fatal;
        let report_errors = report.metadata.counts.errors;
        let report_warnings = report.metadata.counts.warnings;
        let report_informational = report.metadata.counts.informational;
        let report_diag_count = report.diagnostics.len();

        // Deferred until after the timed loop so disk I/O is not measured.
        let dump_report = report;
        let benchmark_metrics = serde_json::json!({
            "iterations": iterations,
            "firstIteration": {
                "hostModelMs": round4(iter_host_model_ms[0]),
                "modelBuildMs": round4(iter_model_build_ms[0]),
                "schemaValidateMs": round4(iter_schema_validate_ms[0]),
                "ruleEvaluationMs": round4(iter_rule_eval_ms[0]),
                "diagnosticFinalizeMs": round4(iter_finalize_ms[0]),
                "engineInternalMs": round4(first_engine_internal_ms),
                "wallClockMs": round4(first_wall_clock_ms),
            },
            "steadyState": {
                "hostModelMs": round4(steady_host_model_ms),
                "modelBuildMs": round4(if iterations > 1 { median_f64(&iter_model_build_ms[1..]) } else { iter_model_build_ms[0] }),
                "schemaValidateMs": round4(if iterations > 1 { median_f64(&iter_schema_validate_ms[1..]) } else { iter_schema_validate_ms[0] }),
                "ruleEvaluationMs": round4(if iterations > 1 { median_f64(&iter_rule_eval_ms[1..]) } else { iter_rule_eval_ms[0] }),
                "diagnosticFinalizeMs": round4(if iterations > 1 { median_f64(&iter_finalize_ms[1..]) } else { iter_finalize_ms[0] }),
                "engineInternalMs": round4(steady_engine_internal_ms),
                "wallClockMs": round4(steady_wall_clock_ms),
            },
            "bindingOverheadMs": binding_overhead_ms,
        });
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
            first_host_model_ms,
            steady_host_model_ms,
            model_build_ms: median_f64(&iter_model_build_ms),
            schema_validate_ms: median_f64(&iter_schema_validate_ms),
            rule_eval_ms: median_f64(&iter_rule_eval_ms),
            diagnostic_finalize_ms: median_f64(&iter_finalize_ms),
            engine_internal_ms: median_engine_internal_ms,
            first_engine_internal_ms,
            steady_engine_internal_ms,
            wall_clock_ms: median_wall_clock_ms,
            first_wall_clock_ms,
            steady_wall_clock_ms,
            wall_clock_total_ms: iter_host_validate_ms.iter().sum(),
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

    for (json_path, relative_path, (report, benchmark_metrics)) in deferred_writes.drain(..) {
        let detailed = report.to_detailed();
        let mut template_json = serde_json::to_value(&detailed)
            .map_err(|e| format!("failed to serialize report for '{}': {e}", relative_path))?;
        template_json["engine"] = serde_json::json!(engine_name);
        template_json["binding"] = serde_json::json!("native");
        template_json["detailLevel"] = serde_json::json!("DETAILED");
        template_json["benchmarkMetrics"] = benchmark_metrics;
        let mut f = fs::File::create(&json_path)
            .map_err(|e| format!("failed to create report file '{}': {e}", json_path.display()))?;
        let json_bytes = serde_json::to_string_pretty(&template_json)
            .map_err(|e| format!("failed to serialize JSON for '{}': {e}", relative_path))?;
        f.write_all(json_bytes.as_bytes())
            .map_err(|e| format!("failed to write report file '{}': {e}", json_path.display()))?;
    }

    let successful_results: Vec<&TemplateResult> = results.iter().filter(|r| r.status == "ok").collect();
    let failed_results: Vec<&TemplateResult> = results.iter().filter(|r| r.status != "ok").collect();

    let model_build_vec: Vec<f64> = successful_results.iter().map(|r| r.model_build_ms).collect();
    let schema_validate_vec: Vec<f64> = successful_results.iter().map(|r| r.schema_validate_ms).collect();
    let rule_eval_vec: Vec<f64> = successful_results.iter().map(|r| r.rule_eval_ms).collect();
    let finalize_vec: Vec<f64> = successful_results.iter().map(|r| r.diagnostic_finalize_ms).collect();
    let engine_internal_vec: Vec<f64> = successful_results.iter().map(|r| r.engine_internal_ms).collect();
    let first_engine_internal_vec: Vec<f64> = successful_results.iter().map(|r| r.first_engine_internal_ms).collect();
    let steady_engine_internal_vec: Vec<f64> = successful_results.iter().map(|r| r.steady_engine_internal_ms).collect();
    let wall_clock_vec: Vec<f64> = successful_results.iter().map(|r| r.wall_clock_ms).collect();
    let first_wall_clock_vec: Vec<f64> = successful_results.iter().map(|r| r.first_wall_clock_ms).collect();
    let steady_wall_clock_vec: Vec<f64> = successful_results.iter().map(|r| r.steady_wall_clock_ms).collect();
    let host_model_vec: Vec<f64> = successful_results.iter().map(|r| r.host_model_ms).collect();
    let first_host_model_vec: Vec<f64> = successful_results.iter().map(|r| r.first_host_model_ms).collect();
    let steady_host_model_vec: Vec<f64> = successful_results.iter().map(|r| r.steady_host_model_ms).collect();
    let binding_overhead_vec: Vec<f64> = successful_results.iter().map(|r| r.binding_overhead_ms).collect();

    // Throughput denominator: sum of host-timed validate calls for successful templates only.
    // This excludes file I/O, standalone model benchmarks, logging overhead, and failures.
    let measured_validation_wall_ms: f64 = successful_results.iter().map(|r| r.wall_clock_total_ms).sum();
    let throughput_per_sec = if measured_validation_wall_ms > 0.0 {
        (successful_results.len() * iterations) as f64 / (measured_validation_wall_ms / 1000.0)
    } else {
        0.0
    };

    let (corpus_fingerprint, fingerprint_file_count) = compute_corpus_fingerprint(input_path)?;
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
            "measured_validation_wall_ms": round4(measured_validation_wall_ms),
            "throughput_per_sec": round4(throughput_per_sec),
            "model_build_ms": stats_json(&model_build_vec),
            "schema_validate_ms": stats_json(&schema_validate_vec),
            "rule_evaluation_ms": stats_json(&rule_eval_vec),
            "diagnostic_finalize_ms": stats_json(&finalize_vec),
            "engine_internal_ms": stats_json(&engine_internal_vec),
            "cold_engine_internal_ms": stats_json(&first_engine_internal_vec),
            "warm_engine_internal_ms": stats_json(&steady_engine_internal_vec),
            "wall_clock_ms": stats_json(&wall_clock_vec),
            "cold_wall_clock_ms": stats_json(&first_wall_clock_vec),
            "warm_wall_clock_ms": stats_json(&steady_wall_clock_vec),
            "host_model_ms": stats_json(&host_model_vec),
            "cold_host_model_ms": stats_json(&first_host_model_vec),
            "warm_host_model_ms": stats_json(&steady_host_model_vec),
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
    let aggregate_json = serde_json::to_string_pretty(&aggregate_stats)
        .map_err(|e| format!("failed to serialize aggregate stats: {e}"))?;
    let aggregate_path = output_dir.join(format!("aggregate_{}.json", format_str));
    fs::write(&aggregate_path, aggregate_json)
        .map_err(|e| format!("failed to write aggregate report '{}': {e}", aggregate_path.display()))?;

    let report_markdown = generate_markdown(
        &results,
        &successful_results,
        &failed_results,
        &init_samples_ms,
        &schema_init_samples_ms,
        &engine_init_samples_ms,
        &first_engine_internal_vec,
        &steady_engine_internal_vec,
        &first_wall_clock_vec,
        &steady_wall_clock_vec,
        &first_host_model_vec,
        &steady_host_model_vec,
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
    fs::write(&report_path, &report_markdown)
        .map_err(|e| format!("failed to write markdown report '{}': {e}", report_path.display()))?;

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

    Ok(())
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
    first_host_model_ms: f64,
    steady_host_model_ms: f64,
    model_build_ms: f64,
    schema_validate_ms: f64,
    rule_eval_ms: f64,
    diagnostic_finalize_ms: f64,
    engine_internal_ms: f64,
    first_engine_internal_ms: f64,
    steady_engine_internal_ms: f64,
    wall_clock_ms: f64,
    first_wall_clock_ms: f64,
    steady_wall_clock_ms: f64,
    /// Sum of all host-timed validate calls (all iterations) for this template.
    wall_clock_total_ms: f64,
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
            first_host_model_ms: 0.0,
            steady_host_model_ms: 0.0,
            model_build_ms: 0.0,
            schema_validate_ms: 0.0,
            rule_eval_ms: 0.0,
            diagnostic_finalize_ms: 0.0,
            engine_internal_ms: 0.0,
            first_engine_internal_ms: 0.0,
            steady_engine_internal_ms: 0.0,
            wall_clock_ms: 0.0,
            first_wall_clock_ms: 0.0,
            steady_wall_clock_ms: 0.0,
            wall_clock_total_ms: 0.0,
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
    first_engine_internal: &[f64],
    steady_engine_internal: &[f64],
    first_wall_clock: &[f64],
    steady_wall_clock: &[f64],
    first_host_model: &[f64],
    steady_host_model: &[f64],
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
        .push_str(&format!("# cloudformation-validate Benchmark Report - {} engine (DETAILED)\n\n", engine_name));
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
        ("First measured host_model (after harness warmup)", first_host_model),
        ("Steady state host_model", steady_host_model),
        ("First measured engine_internal (after harness warmup)", first_engine_internal),
        ("Steady state engine_internal", steady_engine_internal),
        ("First measured wall_clock (after harness warmup)", first_wall_clock),
        ("Steady state wall_clock", steady_wall_clock),
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
    all_sorted.sort_by(|a, b| b.wall_clock_ms.total_cmp(&a.wall_clock_ms));
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
                "- **{}**: {} - {}\n",
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
    sorted.sort_by(|a, b| a.total_cmp(b));
    let n = sorted.len();
    if n.is_multiple_of(2) { (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0 } else { sorted[n / 2] }
}
fn percentile_f64(vals: &[f64], pct: u64) -> f64 {
    if vals.is_empty() {
        return 0.0;
    }
    let mut sorted = vals.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
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

/// Lowercase, zero-padded hex of a SHA-256 digest - the standard encoding every
/// harness (native/TS/JVM/Python/Go) shares, so fingerprints compare byte-for-byte.
fn to_hex(digest: impl AsRef<[u8]>) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let bytes = digest.as_ref();
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        hex.push(HEX_CHARS[(byte >> 4) as usize] as char);
        hex.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    hex
}

/// Relative paths are sorted as raw strings (not `PathBuf` component-wise) so the
/// fingerprint matches byte-for-byte across all five binding harnesses.
fn compute_corpus_fingerprint(root: &Path) -> Result<(String, usize), String> {
    let files = cfn_validate::collect_files(root);
    let mut relative_and_absolute: Vec<(String, PathBuf)> = Vec::with_capacity(files.len());
    for f in files {
        let rel = f.strip_prefix(root).unwrap_or(&f).display().to_string().trim_start_matches('/').to_string();
        let rel = if rel.is_empty() {
            f.file_name()
                .ok_or_else(|| format!("corpus file '{}' has no file name component", f.display()))?
                .to_string_lossy()
                .to_string()
        } else {
            rel
        };
        // Normalize to forward slashes for cross-platform fingerprint consistency.
        let rel = rel.replace('\\', "/");
        relative_and_absolute.push((rel, f));
    }
    relative_and_absolute.sort_by(|a, b| a.0.cmp(&b.0));

    let mut outer = Sha256::new();
    for (rel, abs) in &relative_and_absolute {
        let content = fs::read(abs)
            .map_err(|e| format!("failed to read corpus file '{}' for fingerprint: {e}", abs.display()))?;
        let mut inner = Sha256::new();
        inner.update(&content);
        let file_hash = to_hex(inner.finalize());
        outer.update(format!("{}\t{}\n", rel, file_hash).as_bytes());
    }
    let count = relative_and_absolute.len();
    Ok((to_hex(outer.finalize()), count))
}

/// Deterministic across bindings for the same (corpus, engine, format, iterations) tuple.
fn run_fingerprint(corpus_fp: &str, engine: &str, format: &str, iterations: usize) -> String {
    let mut h = Sha256::new();
    h.update(format!("{}|{}|{}|{}", corpus_fp, engine, format, iterations).as_bytes());
    to_hex(h.finalize())
}
