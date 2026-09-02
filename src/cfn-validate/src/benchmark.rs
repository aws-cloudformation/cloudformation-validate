// The large `serde_json::json!` aggregate report literal exceeds the default macro recursion limit.
#![recursion_limit = "256"]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::{env, fs, panic, process, time::Instant};

use cel_engine::CelEngine;
use diagnostics::{DetailLevel, ValidationReport};
use log::{error, info};
use rego_engine::RegoEngine;
use rules::Severity;
use schema_validator::SchemaValidator;
use sha2::{Digest, Sha256};
use template_model::SemanticModel;
use validation_engine::{EngineConfig, EngineType, ValidateConfig, ValidationEngine, validate_bytes_with_path};

const DEFAULT_STARTUP_TEMPLATE: &str = "good/minimal.yaml";

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

fn build_engine(engine_type: EngineType, config: &EngineConfig) -> Result<Box<dyn ValidationEngine>, String> {
    match engine_type {
        EngineType::Cel => {
            Ok(Box::new(CelEngine::new(config.clone()).map_err(|e| format!("CEL engine initialization failed: {e}"))?))
        }
        EngineType::Rego => Ok(Box::new(
            RegoEngine::new(config.clone()).map_err(|e| format!("Rego engine initialization failed: {e}"))?,
        )),
    }
}

struct FirstValidation {
    host_ms: f64,
    internal_ms: f64,
    model_build_ms: f64,
    schema_validate_ms: f64,
    rule_evaluation_ms: f64,
    diagnostic_finalize_ms: f64,
}

struct StartupMeasurement {
    startup_template: String,
    module_load_ms: f64,
    consumer_init_scope: &'static str,
    consumer_init_ms: f64,
    schema_init_ms: Option<f64>,
    engine_init_ms: f64,
    first: FirstValidation,
    internal_time_to_first_result_ms: f64,
}

fn measure_startup(
    engine_type: EngineType,
    config: &EngineConfig,
    startup_bytes: &[u8],
    startup_label: &str,
    benchmark_config: &ValidateConfig,
) -> Result<(SchemaValidator, Box<dyn ValidationEngine>, StartupMeasurement), String> {
    let module_load_ms = 0.0;

    let schema_start = Instant::now();
    let schema_validator = SchemaValidator::default();
    let schema_init_ms = schema_start.elapsed().as_secs_f64() * 1000.0;

    let engine_start = Instant::now();
    let engine = build_engine(engine_type, config)?;
    let engine_init_ms = engine_start.elapsed().as_secs_f64() * 1000.0;

    let consumer_init_ms = schema_init_ms + engine_init_ms;

    let validate_start = Instant::now();
    let report = validate_bytes_with_path(
        engine.as_ref(),
        &schema_validator,
        startup_bytes,
        benchmark_config.clone(),
        startup_label.to_string(),
    )
    .map_err(|e| format!("startup first validation failed on '{startup_label}': {e}"))?;
    let host_ms = validate_start.elapsed().as_secs_f64() * 1000.0;

    let perf = &report.performance;
    let first = FirstValidation {
        host_ms,
        internal_ms: perf.validate_total.duration_ms,
        model_build_ms: perf.model_build.duration_ms,
        schema_validate_ms: perf.schema_validate.duration_ms,
        rule_evaluation_ms: perf.rule_evaluation.duration_ms,
        diagnostic_finalize_ms: perf.diagnostic_finalize.duration_ms,
    };

    let startup = StartupMeasurement {
        startup_template: startup_label.to_string(),
        module_load_ms,
        consumer_init_scope: "schema_validator+engine",
        consumer_init_ms,
        schema_init_ms: Some(schema_init_ms),
        engine_init_ms,
        internal_time_to_first_result_ms: module_load_ms + consumer_init_ms + host_ms,
        first,
    };
    Ok((schema_validator, engine, startup))
}

fn query_tool_version(tool: &str) -> String {
    match process::Command::new(tool).arg("--version").output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).lines().next().unwrap_or("").trim().to_string()
        }
        _ => "unknown".to_string(),
    }
}

fn env_or_query(var: &str, tool: &str) -> String {
    match env::var(var) {
        Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => query_tool_version(tool),
    }
}

fn provenance_json() -> serde_json::Value {
    let core_version = env!("CARGO_PKG_VERSION");
    serde_json::json!({
        "cloudformation_validate": core_version,
        "binding_artifact": {
            "kind": "cargo",
            "version": core_version,
            "source": "cfn-validate (workspace crate)",
        },
        "cargo": env_or_query("BENCHMARK_CARGO_VERSION", "cargo"),
        "rustc": env_or_query("BENCHMARK_RUSTC_VERSION", "rustc"),
        "runtime": format!("native {}-{}", env::consts::OS, env::consts::ARCH),
    })
}

fn first_validation_json(first: &FirstValidation) -> serde_json::Value {
    serde_json::json!({
        "host_ms": round4(first.host_ms),
        "internal_ms": round4(first.internal_ms),
        "model_build_ms": round4(first.model_build_ms),
        "schema_validate_ms": round4(first.schema_validate_ms),
        "rule_evaluation_ms": round4(first.rule_evaluation_ms),
        "diagnostic_finalize_ms": round4(first.diagnostic_finalize_ms),
    })
}

fn startup_section_json(startup: &StartupMeasurement) -> serde_json::Value {
    serde_json::json!({
        "startup_template": startup.startup_template,
        "module_load_ms": round4(startup.module_load_ms),
        "consumer_init": {
            "scope": startup.consumer_init_scope,
            "duration_ms": round4(startup.consumer_init_ms),
        },
        "schema_init_ms": startup.schema_init_ms.map(round4),
        "engine_init_ms": round4(startup.engine_init_ms),
        "first_validation": first_validation_json(&startup.first),
        "internal_time_to_first_result_ms": round4(startup.internal_time_to_first_result_ms),
    })
}

fn resolve_default_template_dir() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest_dir
        .parent()
        .ok_or_else(|| format!("manifest directory '{}' has no parent", manifest_dir.display()))?
        .join("resources")
        .join("templates"))
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        eprintln!("Usage: cfn-benchmark [TEMPLATE|DIR] [--engine rego|cel] [--iterations N] [--startup-probe]");
        process::exit(2);
    }

    let startup_probe = args.iter().any(|a| a == "--startup-probe");

    let default_template_dir = resolve_default_template_dir()?;
    let positional = args.get(1).filter(|a| !a.starts_with('-')).map(|s| s.to_string());

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
    let benchmark_config = ValidateConfig { detail_level: detail_level.clone(), severity_level, ..Default::default() };
    let config = EngineConfig::default();

    if startup_probe {
        return run_startup_probe(engine_type, &config, &benchmark_config, &default_template_dir);
    }

    let template_dir = match positional.as_deref() {
        Some(path) => path.to_string(),
        None => default_template_dir
            .to_str()
            .ok_or_else(|| format!("template path '{}' is not valid UTF-8", default_template_dir.display()))?
            .to_string(),
    };

    let input_path = Path::new(&template_dir);
    let mut templates = cfn_validate::collect_files(input_path);
    // Sort by string representation (not PathBuf component-wise) for consistency
    // with TS and Kotlin harnesses.
    templates.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
    info!("Found {} templates in {}", templates.len(), template_dir);

    if templates.is_empty() {
        error!("No templates found in {}", template_dir);
        process::exit(1);
    }

    let startup_template_path = &templates[0];
    let startup_bytes = fs::read(startup_template_path)
        .map_err(|e| format!("failed to read startup template '{}': {e}", startup_template_path.display()))?;
    let startup_label = relative_template_key(&template_dir, startup_template_path)?;

    let (schema_validator, engine, startup) =
        measure_startup(engine_type, &config, &startup_bytes, &startup_label, &benchmark_config)?;
    let engine_name = engine.engine_name();

    let schema_init_samples_ms: Vec<f64> = vec![startup.schema_init_ms.unwrap_or(0.0)];
    let engine_init_samples_ms: Vec<f64> = vec![startup.engine_init_ms];
    let init_samples_ms: Vec<f64> =
        schema_init_samples_ms.iter().zip(engine_init_samples_ms.iter()).map(|(s, e)| s + e).collect();
    let cold_init_ms = startup.module_load_ms + init_samples_ms[0];
    let subsequent_init_samples_ms: Vec<f64> = Vec::new();

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let output_dir = manifest.join("reports").join(engine_name);

    let json_dir = output_dir.join(format!("json_{}", format_str));
    // Clean previous output so stale reports from dropped/renamed templates are not left behind.
    if json_dir.exists() {
        fs::remove_dir_all(&json_dir)
            .map_err(|e| format!("failed to remove previous output directory '{}': {e}", json_dir.display()))?;
    }
    fs::create_dir_all(&json_dir)
        .map_err(|e| format!("failed to create output directory '{}': {e}", json_dir.display()))?;

    let mut results: Vec<TemplateResult> = Vec::new();

    let bench_start = Instant::now();

    for template_path in &templates {
        let relative_path = relative_template_key(&template_dir, template_path)?;
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
        let mut parse_failure_report: Option<ValidationReport> = None;
        let mut failed = false;

        for i in 0..iterations {
            let tm0 = Instant::now();
            let parse_result = SemanticModel::parse(&bytes, Default::default());
            match parse_result {
                Ok(_) => {}
                Err(e) => {
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
                    parse_failure_report = Some(report);
                    results.push(TemplateResult::error(&relative_path, "parse_error", &e.to_string()));
                    failed = true;
                    break;
                }
            }
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
            if let Some(report) = parse_failure_report {
                write_template_report(&json_path, &relative_path, &report, zero_benchmark_metrics(), engine_name)?;
            }
            continue;
        }
        let report = last_report.ok_or_else(|| {
            format!("no validation report produced for '{relative_path}' after {iterations} iterations")
        })?;

        let sample =
            SampleSummary::from_iterations(&iter_host_model_ms, &iter_engine_internal_ms, &iter_host_validate_ms);

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

        let benchmark_metrics = per_template_metrics_json(
            iterations,
            &iter_host_model_ms,
            &iter_model_build_ms,
            &iter_schema_validate_ms,
            &iter_rule_eval_ms,
            &iter_finalize_ms,
            &iter_engine_internal_ms,
            &iter_host_validate_ms,
            binding_overhead_ms,
        );
        write_template_report(&json_path, &relative_path, &report, benchmark_metrics, engine_name)?;
        drop(report);

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
            host_model_ms: median_f64(&iter_host_model_ms),
            first_measured_host_model_ms: sample.first_host_model_ms,
            subsequent_host_model_ms: sample.subsequent_host_model_ms,
            model_build_ms: median_f64(&iter_model_build_ms),
            schema_validate_ms: median_f64(&iter_schema_validate_ms),
            rule_eval_ms: median_f64(&iter_rule_eval_ms),
            diagnostic_finalize_ms: median_f64(&iter_finalize_ms),
            engine_internal_ms: median_f64(&iter_engine_internal_ms),
            first_measured_engine_internal_ms: sample.first_engine_internal_ms,
            subsequent_engine_internal_ms: sample.subsequent_engine_internal_ms,
            wall_clock_ms: median_f64(&iter_host_validate_ms),
            first_measured_wall_clock_ms: sample.first_wall_clock_ms,
            subsequent_wall_clock_ms: sample.subsequent_wall_clock_ms,
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

    let successful_results: Vec<&TemplateResult> = results.iter().filter(|r| r.status == "ok").collect();
    let failed_results: Vec<&TemplateResult> = results.iter().filter(|r| r.status != "ok").collect();

    let aggregate = AggregateVectors::from_results(&successful_results);

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
    let provenance = provenance_json();

    let aggregate_stats = serde_json::json!({
        "timestamp": chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        "engine": engine_name,
        "binding": "native",
        "detail_level": "DETAILED",
        "template_dir": template_dir,
        "provenance": provenance,
        "templates_total": results.len(),
        "templates_ok": successful_results.len(),
        "templates_failed": failed_results.len(),
        "iterations_per_template": iterations,
        "corpus_fingerprint": corpus_fingerprint,
        "corpus_file_count": fingerprint_file_count,
        "run_fingerprint": run_fingerprint,
        "performance": {
            "module_load_ms": round4(startup.module_load_ms),
            "startup": startup_section_json(&startup),
            "init_ms": stats_json(&init_samples_ms),
            "cold_init_ms": round4(cold_init_ms),
            "warm_init_ms": stats_json(&subsequent_init_samples_ms),
            "subsequent_init_ms": stats_json(&subsequent_init_samples_ms),
            "schema_init_ms": stats_json(&schema_init_samples_ms),
            "engine_init_ms": stats_json(&engine_init_samples_ms),
            "total_wall_ms": round4(total_wall_ms),
            "measured_validation_wall_ms": round4(measured_validation_wall_ms),
            "throughput_per_sec": round4(throughput_per_sec),
            "model_build_ms": stats_json(&aggregate.model_build),
            "schema_validate_ms": stats_json(&aggregate.schema_validate),
            "rule_evaluation_ms": stats_json(&aggregate.rule_eval),
            "diagnostic_finalize_ms": stats_json(&aggregate.finalize),
            "engine_internal_ms": stats_json(&aggregate.engine_internal),
            "first_measured_engine_internal_ms": stats_json(&aggregate.first_engine_internal),
            "subsequent_engine_internal_ms": stats_json(&aggregate.subsequent_engine_internal),
            "cold_engine_internal_ms": stats_json(&aggregate.first_engine_internal),
            "warm_engine_internal_ms": stats_json(&aggregate.subsequent_engine_internal),
            "wall_clock_ms": stats_json(&aggregate.wall_clock),
            "first_measured_wall_clock_ms": stats_json(&aggregate.first_wall_clock),
            "subsequent_wall_clock_ms": stats_json(&aggregate.subsequent_wall_clock),
            "cold_wall_clock_ms": stats_json(&aggregate.first_wall_clock),
            "warm_wall_clock_ms": stats_json(&aggregate.subsequent_wall_clock),
            "host_model_ms": stats_json(&aggregate.host_model),
            "first_measured_host_model_ms": stats_json(&aggregate.first_host_model),
            "subsequent_host_model_ms": stats_json(&aggregate.subsequent_host_model),
            "cold_host_model_ms": stats_json(&aggregate.first_host_model),
            "warm_host_model_ms": stats_json(&aggregate.subsequent_host_model),
            "binding_overhead_ms": stats_json(&aggregate.binding_overhead),
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

    let report_markdown = generate_markdown(&MarkdownInput {
        results: &results,
        successful_results: &successful_results,
        failed_results: &failed_results,
        startup: &startup,
        provenance: &provenance,
        init_samples: &init_samples_ms,
        schema_init_samples: &schema_init_samples_ms,
        engine_init_samples: &engine_init_samples_ms,
        aggregate: &aggregate,
        total_wall_ms,
        throughput_per_sec,
        engine_name,
        iterations,
        corpus_fingerprint: &corpus_fingerprint,
        corpus_file_count: fingerprint_file_count,
    });
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
        median_f64(&aggregate.engine_internal),
        percentile_f64(&aggregate.engine_internal, 99),
        max_f64(&aggregate.engine_internal)
    );
    info!(
        "wall_clock     (median): median={:.4}ms p99={:.4}ms max={:.4}ms",
        median_f64(&aggregate.wall_clock),
        percentile_f64(&aggregate.wall_clock, 99),
        max_f64(&aggregate.wall_clock)
    );
    info!("Throughput: {:.2} validations/sec", throughput_per_sec);
    info!("Corpus fingerprint: {} ({} files)", corpus_fingerprint, fingerprint_file_count);
    info!("Reports written to {}", output_dir.display());

    Ok(())
}

fn run_startup_probe(
    engine_type: EngineType,
    config: &EngineConfig,
    benchmark_config: &ValidateConfig,
    default_template_dir: &Path,
) -> Result<(), String> {
    let startup_path = default_template_dir.join(DEFAULT_STARTUP_TEMPLATE);
    let startup_bytes = fs::read(&startup_path)
        .map_err(|e| format!("failed to read startup template '{}': {e}", startup_path.display()))?;
    let startup_label = startup_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| startup_path.display().to_string());

    let (_schema_validator, engine, startup) =
        measure_startup(engine_type, config, &startup_bytes, &startup_label, benchmark_config)?;
    let engine_name = engine.engine_name();

    let mut probe = startup_section_json(&startup);
    probe["binding"] = serde_json::json!("native");
    probe["engine"] = serde_json::json!(engine_name);
    probe["versions"] = provenance_json();
    let serialized = serde_json::to_string(&probe).map_err(|e| format!("failed to serialize startup probe: {e}"))?;
    println!("{serialized}");
    Ok(())
}

fn relative_template_key(template_dir: &str, template_path: &Path) -> Result<String, String> {
    let stripped = template_path.strip_prefix(template_dir).unwrap_or(template_path).display().to_string();
    let relative_path = stripped.trim_start_matches('/').trim_start_matches('\\');
    if relative_path.is_empty() {
        Ok(template_path
            .file_name()
            .ok_or_else(|| format!("template path '{}' has no file name component", template_path.display()))?
            .to_string_lossy()
            .to_string())
    } else {
        // Normalize to forward slashes for cross-platform fingerprint consistency.
        Ok(relative_path.replace('\\', "/"))
    }
}

struct SampleSummary {
    first_host_model_ms: f64,
    subsequent_host_model_ms: Option<f64>,
    first_engine_internal_ms: f64,
    subsequent_engine_internal_ms: Option<f64>,
    first_wall_clock_ms: f64,
    subsequent_wall_clock_ms: Option<f64>,
}

impl SampleSummary {
    fn from_iterations(host_model: &[f64], engine_internal: &[f64], wall_clock: &[f64]) -> Self {
        let subsequent_median =
            |vals: &[f64]| -> Option<f64> { if vals.len() > 1 { Some(median_f64(&vals[1..])) } else { None } };
        Self {
            first_host_model_ms: host_model[0],
            subsequent_host_model_ms: subsequent_median(host_model),
            first_engine_internal_ms: engine_internal[0],
            subsequent_engine_internal_ms: subsequent_median(engine_internal),
            first_wall_clock_ms: wall_clock[0],
            subsequent_wall_clock_ms: subsequent_median(wall_clock),
        }
    }
}

fn iteration_metrics_json(
    host_model: f64,
    model_build: f64,
    schema_validate: f64,
    rule_eval: f64,
    finalize: f64,
    engine_internal: f64,
    wall_clock: f64,
) -> serde_json::Value {
    serde_json::json!({
        "hostModelMs": round4(host_model),
        "modelBuildMs": round4(model_build),
        "schemaValidateMs": round4(schema_validate),
        "ruleEvaluationMs": round4(rule_eval),
        "diagnosticFinalizeMs": round4(finalize),
        "engineInternalMs": round4(engine_internal),
        "wallClockMs": round4(wall_clock),
    })
}

fn subsequent_metric(vals: &[f64]) -> serde_json::Value {
    if vals.len() > 1 { serde_json::json!(round4(median_f64(&vals[1..]))) } else { serde_json::Value::Null }
}

fn per_template_metrics_json(
    iterations: usize,
    host_model: &[f64],
    model_build: &[f64],
    schema_validate: &[f64],
    rule_eval: &[f64],
    finalize: &[f64],
    engine_internal: &[f64],
    wall_clock: &[f64],
    binding_overhead_ms: f64,
) -> serde_json::Value {
    let first_measured = iteration_metrics_json(
        host_model[0],
        model_build[0],
        schema_validate[0],
        rule_eval[0],
        finalize[0],
        engine_internal[0],
        wall_clock[0],
    );
    let subsequent = serde_json::json!({
        "sampleCount": wall_clock.len().saturating_sub(1),
        "hostModelMs": subsequent_metric(host_model),
        "modelBuildMs": subsequent_metric(model_build),
        "schemaValidateMs": subsequent_metric(schema_validate),
        "ruleEvaluationMs": subsequent_metric(rule_eval),
        "diagnosticFinalizeMs": subsequent_metric(finalize),
        "engineInternalMs": subsequent_metric(engine_internal),
        "wallClockMs": subsequent_metric(wall_clock),
    });
    // Legacy steadyState keeps a numeric value for older consumers, falling back to the first sample.
    let steady_or_first = |vals: &[f64]| -> f64 { if vals.len() > 1 { median_f64(&vals[1..]) } else { vals[0] } };
    let steady_state = iteration_metrics_json(
        steady_or_first(host_model),
        steady_or_first(model_build),
        steady_or_first(schema_validate),
        steady_or_first(rule_eval),
        steady_or_first(finalize),
        steady_or_first(engine_internal),
        steady_or_first(wall_clock),
    );
    serde_json::json!({
        "iterations": iterations,
        "firstMeasured": first_measured.clone(),
        "subsequent": subsequent,
        "firstIteration": first_measured,
        "steadyState": steady_state,
        "bindingOverheadMs": binding_overhead_ms,
    })
}

fn write_template_report(
    json_path: &Path,
    relative_path: &str,
    report: &ValidationReport,
    benchmark_metrics: serde_json::Value,
    engine_name: &str,
) -> Result<(), String> {
    let detailed = report.to_detailed();
    let mut template_json = serde_json::to_value(&detailed)
        .map_err(|e| format!("failed to serialize report for '{}': {e}", relative_path))?;
    template_json["engine"] = serde_json::json!(engine_name);
    template_json["binding"] = serde_json::json!("native");
    template_json["detailLevel"] = serde_json::json!("DETAILED");
    template_json["benchmarkMetrics"] = benchmark_metrics;
    let mut f = fs::File::create(json_path)
        .map_err(|e| format!("failed to create report file '{}': {e}", json_path.display()))?;
    let json_bytes = serde_json::to_string_pretty(&template_json)
        .map_err(|e| format!("failed to serialize JSON for '{}': {e}", relative_path))?;
    f.write_all(json_bytes.as_bytes())
        .map_err(|e| format!("failed to write report file '{}': {e}", json_path.display()))?;
    Ok(())
}

fn zero_benchmark_metrics() -> serde_json::Value {
    let zero_iteration = serde_json::json!({
        "hostModelMs": 0.0,
        "modelBuildMs": 0.0,
        "schemaValidateMs": 0.0,
        "ruleEvaluationMs": 0.0,
        "diagnosticFinalizeMs": 0.0,
        "engineInternalMs": 0.0,
        "wallClockMs": 0.0,
    });
    serde_json::json!({
        "iterations": 0,
        "firstMeasured": zero_iteration.clone(),
        "subsequent": {
            "sampleCount": 0,
            "hostModelMs": serde_json::Value::Null,
            "modelBuildMs": serde_json::Value::Null,
            "schemaValidateMs": serde_json::Value::Null,
            "ruleEvaluationMs": serde_json::Value::Null,
            "diagnosticFinalizeMs": serde_json::Value::Null,
            "engineInternalMs": serde_json::Value::Null,
            "wallClockMs": serde_json::Value::Null,
        },
        "firstIteration": zero_iteration.clone(),
        "steadyState": zero_iteration,
        "bindingOverheadMs": 0.0,
    })
}

struct AggregateVectors {
    model_build: Vec<f64>,
    schema_validate: Vec<f64>,
    rule_eval: Vec<f64>,
    finalize: Vec<f64>,
    engine_internal: Vec<f64>,
    first_engine_internal: Vec<f64>,
    subsequent_engine_internal: Vec<f64>,
    wall_clock: Vec<f64>,
    first_wall_clock: Vec<f64>,
    subsequent_wall_clock: Vec<f64>,
    host_model: Vec<f64>,
    first_host_model: Vec<f64>,
    subsequent_host_model: Vec<f64>,
    binding_overhead: Vec<f64>,
}

impl AggregateVectors {
    fn from_results(successful: &[&TemplateResult]) -> Self {
        Self {
            model_build: successful.iter().map(|r| r.model_build_ms).collect(),
            schema_validate: successful.iter().map(|r| r.schema_validate_ms).collect(),
            rule_eval: successful.iter().map(|r| r.rule_eval_ms).collect(),
            finalize: successful.iter().map(|r| r.diagnostic_finalize_ms).collect(),
            engine_internal: successful.iter().map(|r| r.engine_internal_ms).collect(),
            first_engine_internal: successful.iter().map(|r| r.first_measured_engine_internal_ms).collect(),
            subsequent_engine_internal: successful.iter().filter_map(|r| r.subsequent_engine_internal_ms).collect(),
            wall_clock: successful.iter().map(|r| r.wall_clock_ms).collect(),
            first_wall_clock: successful.iter().map(|r| r.first_measured_wall_clock_ms).collect(),
            subsequent_wall_clock: successful.iter().filter_map(|r| r.subsequent_wall_clock_ms).collect(),
            host_model: successful.iter().map(|r| r.host_model_ms).collect(),
            first_host_model: successful.iter().map(|r| r.first_measured_host_model_ms).collect(),
            subsequent_host_model: successful.iter().filter_map(|r| r.subsequent_host_model_ms).collect(),
            binding_overhead: successful.iter().map(|r| r.binding_overhead_ms).collect(),
        }
    }
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
    first_measured_host_model_ms: f64,
    subsequent_host_model_ms: Option<f64>,
    model_build_ms: f64,
    schema_validate_ms: f64,
    rule_eval_ms: f64,
    diagnostic_finalize_ms: f64,
    engine_internal_ms: f64,
    first_measured_engine_internal_ms: f64,
    subsequent_engine_internal_ms: Option<f64>,
    wall_clock_ms: f64,
    first_measured_wall_clock_ms: f64,
    subsequent_wall_clock_ms: Option<f64>,
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
            first_measured_host_model_ms: 0.0,
            subsequent_host_model_ms: None,
            model_build_ms: 0.0,
            schema_validate_ms: 0.0,
            rule_eval_ms: 0.0,
            diagnostic_finalize_ms: 0.0,
            engine_internal_ms: 0.0,
            first_measured_engine_internal_ms: 0.0,
            subsequent_engine_internal_ms: None,
            wall_clock_ms: 0.0,
            first_measured_wall_clock_ms: 0.0,
            subsequent_wall_clock_ms: None,
            wall_clock_total_ms: 0.0,
            binding_overhead_ms: 0.0,
            error_msg: Some(msg.into()),
        }
    }
}

struct MarkdownInput<'a> {
    results: &'a [TemplateResult],
    successful_results: &'a [&'a TemplateResult],
    failed_results: &'a [&'a TemplateResult],
    startup: &'a StartupMeasurement,
    provenance: &'a serde_json::Value,
    init_samples: &'a [f64],
    schema_init_samples: &'a [f64],
    engine_init_samples: &'a [f64],
    aggregate: &'a AggregateVectors,
    total_wall_ms: f64,
    throughput_per_sec: f64,
    engine_name: &'a str,
    iterations: usize,
    corpus_fingerprint: &'a str,
    corpus_file_count: usize,
}

fn provenance_str<'a>(provenance: &'a serde_json::Value, key: &str) -> &'a str {
    provenance.get(key).and_then(|v| v.as_str()).unwrap_or("unknown")
}

fn generate_markdown(input: &MarkdownInput) -> String {
    let mut report_markdown = String::new();
    report_markdown
        .push_str(&format!("# cloudformation-validate Benchmark Report - {} engine (DETAILED)\n\n", input.engine_name));
    report_markdown.push_str(&format!("Generated: {}\n\n", chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ")));
    report_markdown.push_str(&format!(
        "Corpus fingerprint: `{}` ({} files)\n\n",
        input.corpus_fingerprint, input.corpus_file_count
    ));

    report_markdown.push_str("## Provenance\n\n");
    report_markdown.push_str("| Field | Value |\n|---|---|\n");
    let binding_artifact = input
        .provenance
        .get("binding_artifact")
        .and_then(|v| v.get("version"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    report_markdown.push_str(&format!(
        "| cloudformation-validate | {} |\n",
        provenance_str(input.provenance, "cloudformation_validate")
    ));
    report_markdown.push_str(&format!("| Binding artifact (cargo) | {} |\n", binding_artifact));
    report_markdown.push_str(&format!("| Cargo | {} |\n", provenance_str(input.provenance, "cargo")));
    report_markdown.push_str(&format!("| rustc | {} |\n", provenance_str(input.provenance, "rustc")));
    report_markdown.push_str(&format!("| Runtime | {} |\n", provenance_str(input.provenance, "runtime")));

    report_markdown.push_str("\n## Summary\n\n");
    report_markdown.push_str("| Metric | Value |\n|---|---|\n");
    report_markdown.push_str(&format!(
        "| Templates | {} ok, {} failed, {} total |\n",
        input.successful_results.len(),
        input.failed_results.len(),
        input.results.len()
    ));
    report_markdown.push_str(&format!("| Iterations per template | {} |\n", input.iterations));
    report_markdown.push_str(&format!(
        "| Total resources | {} |\n",
        input.successful_results.iter().map(|r| r.resources).sum::<usize>()
    ));
    report_markdown.push_str(&format!("| Total wall time | {:.4} ms |\n", input.total_wall_ms));
    report_markdown.push_str(&format!("| Throughput | {:.2} validations/sec |\n", input.throughput_per_sec));
    report_markdown.push_str("| Detail level | DETAILED |\n");

    report_markdown.push_str("\n## Process Startup (single cold sequence)\n\n");
    report_markdown.push_str(
        "The consumer validation setup constructed once, then the first validate call on that same engine - the process-cold path a consumer pays before any warmup.\n\n",
    );
    report_markdown.push_str("| Metric | Value (ms) |\n|---|---|\n");
    report_markdown.push_str(&format!("| Startup template | {} |\n", input.startup.startup_template));
    report_markdown.push_str(&format!("| Module load | {:.4} |\n", input.startup.module_load_ms));
    report_markdown.push_str(&format!(
        "| Consumer init ({}) | {:.4} |\n",
        input.startup.consumer_init_scope, input.startup.consumer_init_ms
    ));
    report_markdown.push_str(&format!("| First validation (host) | {:.4} |\n", input.startup.first.host_ms));
    report_markdown.push_str(&format!("| First validation (internal) | {:.4} |\n", input.startup.first.internal_ms));
    report_markdown.push_str(&format!(
        "| Internal time-to-first-result | {:.4} |\n",
        input.startup.internal_time_to_first_result_ms
    ));

    report_markdown.push_str("\n## Initialization (ms)\n\n");
    report_markdown.push_str("| Stat | Schema Init | Engine Init | Combined |\n|---|---|---|---|\n");
    report_markdown.push_str(&format!(
        "| Median | {:.4} | {:.4} | {:.4} |\n",
        median_f64(input.schema_init_samples),
        median_f64(input.engine_init_samples),
        median_f64(input.init_samples)
    ));
    report_markdown.push_str(&format!(
        "| P99 | {:.4} | {:.4} | {:.4} |\n",
        percentile_f64(input.schema_init_samples, 99),
        percentile_f64(input.engine_init_samples, 99),
        percentile_f64(input.init_samples, 99)
    ));
    report_markdown.push_str("| Subsequent median | - | - | - |\n");

    report_markdown.push_str("\n## Validation Latency (ms, median / p99 / max per template)\n\n");
    report_markdown
        .push_str("host_model = host timer around SemanticModel::parse (bytes → model). Includes FFI on wasm/jvm.\n");
    report_markdown
        .push_str("wall_clock = host timer around validate_bytes (full validate call, re-parses internally).\n");
    report_markdown
        .push_str("engine_internal = Rust-internal `report.performance.validate_total` (engine work only).\n");
    report_markdown.push_str(
        "First measured = iteration 1 per template (warm at process level). Subsequent = median of iterations 2..N (empty when N=1).\n\n",
    );
    report_markdown.push_str("| Metric | Median | P99 | Max |\n|---|---|---|---|\n");
    for (label, vals) in [
        ("First measured host_model", &input.aggregate.first_host_model),
        ("Subsequent host_model", &input.aggregate.subsequent_host_model),
        ("First measured engine_internal", &input.aggregate.first_engine_internal),
        ("Subsequent engine_internal", &input.aggregate.subsequent_engine_internal),
        ("First measured wall_clock", &input.aggregate.first_wall_clock),
        ("Subsequent wall_clock", &input.aggregate.subsequent_wall_clock),
        ("host_model (per-template median)", &input.aggregate.host_model),
        ("engine_internal (per-template median)", &input.aggregate.engine_internal),
        ("wall_clock (per-template median)", &input.aggregate.wall_clock),
        ("Model build (rust-internal)", &input.aggregate.model_build),
        ("Schema validate (rust-internal)", &input.aggregate.schema_validate),
        ("Rule evaluation (rust-internal)", &input.aggregate.rule_eval),
        ("Diagnostic finalize (rust-internal)", &input.aggregate.finalize),
        ("Binding overhead (wall − internal)", &input.aggregate.binding_overhead),
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
        .push_str(&format!("| Fatal | {} |\n", input.successful_results.iter().map(|r| r.fatal as u64).sum::<u64>()));
    report_markdown
        .push_str(&format!("| Errors | {} |\n", input.successful_results.iter().map(|r| r.errors as u64).sum::<u64>()));
    report_markdown.push_str(&format!(
        "| Warnings | {} |\n",
        input.successful_results.iter().map(|r| r.warnings as u64).sum::<u64>()
    ));
    report_markdown.push_str(&format!(
        "| Informational | {} |\n",
        input.successful_results.iter().map(|r| r.informational as u64).sum::<u64>()
    ));

    report_markdown.push_str("\n## All Results\n\n");
    let mut all_sorted: Vec<&TemplateResult> = input.results.iter().collect();
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

    if !input.failed_results.is_empty() {
        report_markdown.push_str("\n## Failures\n\n");
        for r in input.failed_results {
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
        "count": vals.len(),
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
