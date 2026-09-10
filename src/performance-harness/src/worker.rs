use cel_engine::CelEngine;
use diagnostics::{DetailLevel, ValidationReport};
use rego_engine::RegoEngine;
use rules::Severity;
use schema_validator::SchemaValidator;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::hint::black_box;
use std::time::Instant;
use validation_engine::{EngineConfig, ValidateConfig, ValidationEngine, validate_bytes_with_path};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FirstValidation {
    pub wall_ms: f64,
    pub internal_ms: f64,
    pub fingerprint: String,
    pub status: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WarmMeasurement {
    pub total_ms: f64,
    pub per_call_total_ms: f64,
    pub wall_median_ms: f64,
    pub wall_p95_ms: f64,
    pub internal_median_ms: f64,
    pub model_median_ms: f64,
    pub schema_median_ms: f64,
    pub rule_median_ms: f64,
    pub finalize_median_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Fingerprint {
    pub path: String,
    pub fingerprint: String,
    pub diagnostics: usize,
    pub status: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Measurement {
    pub label: String,
    pub engine: String,
    pub template_count: usize,
    pub iterations: usize,
    pub samples: usize,
    pub schema_init_ms: f64,
    pub engine_init_ms: f64,
    pub init_total_ms: f64,
    pub first_validation: FirstValidation,
    pub warm: WarmMeasurement,
    pub fingerprints: Vec<Fingerprint>,
    #[serde(default)]
    pub peak_rss_bytes: u64,
    #[serde(default)]
    pub sample: i32,
    #[serde(default = "default_true")]
    pub gate_process_lifecycle: bool,
}

fn default_true() -> bool {
    true
}

fn percentile(samples: &[f64], fraction: f64) -> Result<f64, String> {
    if samples.is_empty() || samples.iter().any(|sample| !sample.is_finite()) {
        return Err("percentile requires finite samples".into());
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    Ok(sorted[((sorted.len() - 1) as f64 * fraction).round() as usize])
}

fn fingerprint_bytes(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325_u64, |hash, byte| (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3))
}

fn fingerprint(report: &ValidationReport) -> Result<u64, String> {
    let value = serde_json::json!({
        "status": &report.status,
        "diagnostics": &report.diagnostics,
        "counts": &report.metadata.counts,
        "budgetExhaustions": &report.metadata.budget_exhaustions,
    });
    serde_json::to_vec(&value)
        .map(|bytes| fingerprint_bytes(&bytes))
        .map_err(|error| format!("report fingerprint input could not be serialized: {error}"))
}

fn error_fingerprint(error: &impl std::fmt::Display) -> u64 {
    fingerprint_bytes(format!("validation-error:{error}").as_bytes())
}

fn parse_positive(value: &str, name: &str) -> Result<usize, String> {
    let parsed = value.parse::<usize>().map_err(|error| format!("{name} must be a positive integer: {error}"))?;
    if parsed == 0 {
        return Err(format!("{name} must be a positive integer"));
    }
    Ok(parsed)
}

pub fn run(arguments: &[String]) -> Result<(), String> {
    if arguments.len() < 5 {
        return Err("usage: performance-harness measure <rego|cel> <iterations> <warmups> <label> <template>...".into());
    }
    let engine_name = &arguments[0];
    let iterations = parse_positive(&arguments[1], "iterations")?;
    let warmups = parse_positive(&arguments[2], "warmups")?;
    let label = &arguments[3];
    let templates: Vec<(String, Vec<u8>)> = arguments[4..]
        .iter()
        .map(|path| {
            fs::read(path)
                .map(|bytes| (path.clone(), bytes))
                .map_err(|error| format!("template {path} could not be read: {error}"))
        })
        .collect::<Result<_, _>>()?;
    if templates.is_empty() {
        return Err("at least one template is required".into());
    }

    let schema_start = Instant::now();
    let schema_validator = SchemaValidator::default();
    let schema_init_ms = schema_start.elapsed().as_secs_f64() * 1000.0;

    let engine_start = Instant::now();
    let config = EngineConfig::default();
    let engine: Box<dyn ValidationEngine> = match engine_name.as_str() {
        "rego" => Box::new(
            RegoEngine::new_with_schema_validator(config, &schema_validator)
                .map_err(|error| format!("Rego engine initialization failed: {error}"))?,
        ),
        "cel" => Box::new(
            CelEngine::new_with_schema_validator(config, &schema_validator)
                .map_err(|error| format!("CEL engine initialization failed: {error}"))?,
        ),
        _ => return Err("engine must be 'rego' or 'cel'".into()),
    };
    let engine_init_ms = engine_start.elapsed().as_secs_f64() * 1000.0;

    let validate_config =
        ValidateConfig { detail_level: DetailLevel::Detailed, severity_level: Severity::Debug, ..Default::default() };

    let (first_path, first_bytes) = templates.first().ok_or_else(|| "at least one template is required".to_string())?;
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
            fingerprint(report)?,
            serde_json::to_value(report.status)
                .map_err(|error| format!("report status could not be serialized: {error}"))?,
        ),
        Err(error) => (0.0, error_fingerprint(error), Value::String("VALIDATION_ERROR".to_string())),
    };
    let _ = black_box(first_outcome);

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

    let mut fingerprints = Vec::with_capacity(templates.len());
    for (path, bytes) in &templates {
        match validate_bytes_with_path(engine.as_ref(), &schema_validator, bytes, validate_config.clone(), path.clone())
        {
            Ok(report) => {
                fingerprints.push(Fingerprint {
                    path: path.clone(),
                    fingerprint: format!("{:016x}", fingerprint(&report)?),
                    diagnostics: report.diagnostics.len(),
                    status: serde_json::to_value(report.status)
                        .map_err(|error| format!("report status could not be serialized: {error}"))?,
                    error: None,
                });
                let _ = black_box(report);
            }
            Err(error) => {
                fingerprints.push(Fingerprint {
                    path: path.clone(),
                    fingerprint: format!("{:016x}", error_fingerprint(&error)),
                    diagnostics: 0,
                    status: Value::String("VALIDATION_ERROR".to_string()),
                    error: Some(error.to_string()),
                });
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

    let output = Measurement {
        label: label.clone(),
        engine: engine_name.clone(),
        template_count: templates.len(),
        iterations,
        samples: sample_count,
        schema_init_ms,
        engine_init_ms,
        init_total_ms: schema_init_ms + engine_init_ms,
        first_validation: FirstValidation {
            wall_ms: first_wall_ms,
            internal_ms: first_internal_ms,
            fingerprint: format!("{first_fingerprint:016x}"),
            status: first_status,
        },
        warm: WarmMeasurement {
            total_ms: timed_total_ms,
            per_call_total_ms: timed_total_ms / sample_count as f64,
            wall_median_ms: percentile(&wall_ms, 0.5)?,
            wall_p95_ms: percentile(&wall_ms, 0.95)?,
            internal_median_ms: percentile(&internal_ms, 0.5)?,
            model_median_ms: percentile(&model_ms, 0.5)?,
            schema_median_ms: percentile(&schema_ms, 0.5)?,
            rule_median_ms: percentile(&rule_ms, 0.5)?,
            finalize_median_ms: percentile(&finalize_ms, 0.5)?,
        },
        fingerprints,
        peak_rss_bytes: 0,
        sample: 0,
        gate_process_lifecycle: true,
    };
    println!(
        "{}",
        serde_json::to_string(&output).map_err(|error| format!("benchmark result could not be serialized: {error}"))?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::percentile;

    #[test]
    fn percentile_rejects_empty_samples_and_selects_rank() {
        assert!(percentile(&[], 0.5).is_err());
        assert_eq!(percentile(&[1.0, 2.0, 3.0], 0.5).expect("median percentile"), 2.0);
    }
}
