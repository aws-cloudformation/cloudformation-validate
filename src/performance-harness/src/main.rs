use cel_engine::CelEngine;
use diagnostics::{DetailLevel, ValidationReport};
use rego_engine::RegoEngine;
use rules::Severity;
use schema_validator::SchemaValidator;
use std::env;
use std::fs;
use std::hint::black_box;
use std::time::Instant;
use validation_engine::{EngineConfig, ValidateConfig, ValidationEngine, validate_bytes_with_path};

fn percentile(samples: &[f64], fraction: f64) -> f64 {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    sorted[((sorted.len() - 1) as f64 * fraction).round() as usize]
}

fn fingerprint_bytes(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325_u64, |hash, byte| (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3))
}

fn fingerprint(report: &ValidationReport) -> u64 {
    let value = serde_json::json!({
        "status": &report.status,
        "diagnostics": &report.diagnostics,
        "counts": &report.metadata.counts,
        "budgetExhaustions": &report.metadata.budget_exhaustions,
    });
    let bytes = serde_json::to_vec(&value).expect("report fingerprint input must serialize");
    fingerprint_bytes(&bytes)
}

fn error_fingerprint(error: &impl std::fmt::Display) -> u64 {
    fingerprint_bytes(format!("validation-error:{error}").as_bytes())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 6 {
        eprintln!("usage: performance-harness <rego|cel> <iterations> <warmups> <label> <template>...");
        std::process::exit(2);
    }
    let engine_name = &args[1];
    let iterations: usize = args[2].parse().expect("iterations must be a positive integer");
    let warmups: usize = args[3].parse().expect("warmups must be a positive integer");
    let label = &args[4];
    let templates: Vec<(String, Vec<u8>)> =
        args[5..].iter().map(|path| (path.clone(), fs::read(path).expect("template must be readable"))).collect();
    assert!(iterations > 0 && warmups > 0 && !templates.is_empty());

    let schema_start = Instant::now();
    let schema_validator = SchemaValidator::default();
    let schema_init_ms = schema_start.elapsed().as_secs_f64() * 1000.0;

    let engine_start = Instant::now();
    let config = EngineConfig::default();
    let engine: Box<dyn ValidationEngine> = match engine_name.as_str() {
        "rego" => Box::new(
            RegoEngine::new_with_schema_validator(config, &schema_validator).expect("Rego engine initialization"),
        ),
        "cel" => Box::new(
            CelEngine::new_with_schema_validator(config, &schema_validator).expect("CEL engine initialization"),
        ),
        _ => panic!("engine must be 'rego' or 'cel'"),
    };
    let engine_init_ms = engine_start.elapsed().as_secs_f64() * 1000.0;

    let validate_config =
        ValidateConfig { detail_level: DetailLevel::Detailed, severity_level: Severity::Debug, ..Default::default() };

    let (first_path, first_bytes) = &templates[0];
    let first_start = Instant::now();
    let first_outcome = validate_bytes_with_path(
        engine.as_ref(),
        &schema_validator,
        first_bytes,
        validate_config.clone(),
        first_path.clone(),
    );
    let first_wall_ms = first_start.elapsed().as_secs_f64() * 1000.0;
    let (first_internal_ms, first_fingerprint, first_status) = match &first_outcome {
        Ok(report) => (
            report.performance.validate_total.duration_ms,
            fingerprint(report),
            serde_json::to_value(report.status).expect("report status must serialize"),
        ),
        Err(error) => (0.0, error_fingerprint(error), serde_json::Value::String("VALIDATION_ERROR".to_string())),
    };
    let _ = black_box(first_outcome);

    let mut fingerprints = Vec::with_capacity(templates.len());
    for _ in 0..warmups {
        for (path, bytes) in &templates {
            let outcome = validate_bytes_with_path(
                engine.as_ref(),
                &schema_validator,
                bytes,
                validate_config.clone(),
                path.clone(),
            );
            let _ = black_box(outcome);
        }
    }
    for (path, bytes) in &templates {
        match validate_bytes_with_path(engine.as_ref(), &schema_validator, bytes, validate_config.clone(), path.clone())
        {
            Ok(report) => {
                fingerprints.push(serde_json::json!({
                    "path": path,
                    "fingerprint": format!("{:016x}", fingerprint(&report)),
                    "diagnostics": report.diagnostics.len(),
                    "status": report.status,
                }));
                let _ = black_box(report);
            }
            Err(error) => {
                fingerprints.push(serde_json::json!({
                    "path": path,
                    "fingerprint": format!("{:016x}", error_fingerprint(&error)),
                    "diagnostics": 0,
                    "status": "VALIDATION_ERROR",
                    "error": error.to_string(),
                }));
                let _ = black_box(error);
            }
        }
    }

    let sample_count = iterations * templates.len();
    let mut wall_ms = Vec::with_capacity(sample_count);
    let mut internal_ms = Vec::with_capacity(sample_count);
    let mut model_ms = Vec::with_capacity(sample_count);
    let mut schema_ms = Vec::with_capacity(sample_count);
    let mut rule_ms = Vec::with_capacity(sample_count);
    let mut finalize_ms = Vec::with_capacity(sample_count);
    let timed_start = Instant::now();
    for _ in 0..iterations {
        for (path, bytes) in &templates {
            let call_start = Instant::now();
            let outcome = validate_bytes_with_path(
                engine.as_ref(),
                &schema_validator,
                bytes,
                validate_config.clone(),
                path.clone(),
            );
            wall_ms.push(call_start.elapsed().as_secs_f64() * 1000.0);
            match outcome {
                Ok(report) => {
                    internal_ms.push(report.performance.validate_total.duration_ms);
                    model_ms.push(report.performance.model_build.duration_ms);
                    schema_ms.push(report.performance.schema_validate.duration_ms);
                    rule_ms.push(report.performance.rule_evaluation.duration_ms);
                    finalize_ms.push(report.performance.diagnostic_finalize.duration_ms);
                    let _ = black_box(report);
                }
                Err(error) => {
                    internal_ms.push(0.0);
                    model_ms.push(0.0);
                    schema_ms.push(0.0);
                    rule_ms.push(0.0);
                    finalize_ms.push(0.0);
                    let _ = black_box(error);
                }
            }
        }
    }
    let timed_total_ms = timed_start.elapsed().as_secs_f64() * 1000.0;

    let output = serde_json::json!({
        "label": label,
        "engine": engine_name,
        "templateCount": templates.len(),
        "iterations": iterations,
        "samples": sample_count,
        "schemaInitMs": schema_init_ms,
        "engineInitMs": engine_init_ms,
        "initTotalMs": schema_init_ms + engine_init_ms,
        "firstValidation": {
            "wallMs": first_wall_ms,
            "internalMs": first_internal_ms,
            "fingerprint": format!("{first_fingerprint:016x}"),
            "status": first_status,
        },
        "warm": {
            "totalMs": timed_total_ms,
            "perCallTotalMs": timed_total_ms / sample_count as f64,
            "wallMedianMs": percentile(&wall_ms, 0.5),
            "wallP95Ms": percentile(&wall_ms, 0.95),
            "internalMedianMs": percentile(&internal_ms, 0.5),
            "modelMedianMs": percentile(&model_ms, 0.5),
            "schemaMedianMs": percentile(&schema_ms, 0.5),
            "ruleMedianMs": percentile(&rule_ms, 0.5),
            "finalizeMedianMs": percentile(&finalize_ms, 0.5),
        },
        "fingerprints": fingerprints,
    });
    println!("{}", serde_json::to_string(&output).expect("benchmark result must serialize"));
}
