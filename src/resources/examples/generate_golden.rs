//! Regenerate the golden `expected/all_templates.json` from `cfn-validate`
//! `--format detailed` output - a Rust port of the former `generate.py`, run in
//! parallel across CPU cores because serial Python (≈1000 engine-initializing
//! subprocess launches) is too slow.
//!
//! Runs BOTH engines (rego and cel) on every template and verifies they produce
//! identical diagnostics. Fails loudly on any divergence or missing output.
//!
//! Run from the workspace root, in release (the generator itself is CPU-bound):
//!     cargo run --release -p resources --example generate_golden
//!
//! The example first builds the release `cfn-validate` binary it drives, so no
//! separate build step is required.

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use resources::{discover_templates, golden_file, templates_dir, workspace_root};
use serde_json::{Map, Value};

/// Engines that must agree on every template. Rego is the reference persisted to
/// the golden file; cel is validated against it for parity.
const ENGINES: &[&str] = &["rego", "cel"];

/// Fields stripped before the rego-vs-cel parity comparison
const PARITY_IGNORED_FIELDS: &[&str] = &["performance", "benchmarkMetrics", "suppressed"];

/// Top-level fields compared across engines but not persisted to the golden file.
const OUTPUT_ONLY_TOP_LEVEL_FIELDS: &[&str] = &["performance"];

/// `metadata` fields compared across engines but not persisted to the golden file.
const OUTPUT_ONLY_METADATA_FIELDS: &[&str] = &["rulesEvaluated"];

/// Identity of a single diagnostic, used only to describe parity divergences.
type DiagnosticKey = (String, String, String, String, String);

/// The result of validating one template with both engines.
enum Outcome {
    /// Both engines agreed; carries the report to persist (rego, output-trimmed).
    Persist(Value),
    /// Engines diverged; carries the diagnostics unique to each.
    Parity { only_rego: Vec<DiagnosticKey>, only_cel: Vec<DiagnosticKey> },
    /// A binary invocation produced no output or unparseable JSON.
    Fatal(String),
}

fn main() {
    let cfn_validate = match build_release_binary() {
        Ok(path) => path,
        Err(message) => fail(&message),
    };

    let templates = discover_templates();
    println!("Output file: {}", golden_file().display());
    println!("Discovered {} templates", templates.len());
    println!("Running both engines ({}) on each template...\n", ENGINES.join(" + "));

    let outcomes = run_all(&cfn_validate, &templates);

    let mut parity_failures = Vec::new();
    let mut fatals = Vec::new();
    let mut persisted = Map::new();
    for (template, outcome) in templates.iter().zip(outcomes) {
        match outcome {
            Outcome::Persist(report) => {
                persisted.insert(template.clone(), report);
            }
            Outcome::Parity { only_rego, only_cel } => parity_failures.push((template.clone(), only_rego, only_cel)),
            Outcome::Fatal(message) => fatals.push((template.clone(), message)),
        }
    }

    if !fatals.is_empty() {
        for (template, message) in &fatals {
            eprintln!("  FATAL: {template}: {message}");
        }
        fail(&format!("{} template(s) failed to validate", fatals.len()));
    }

    if !parity_failures.is_empty() {
        eprintln!("\nFATAL: {} template(s) have engine parity failures:\n", parity_failures.len());
        for (template, only_rego, only_cel) in &parity_failures {
            eprintln!("  {template}");
            for (rule_id, severity, message, resource, path) in only_rego {
                eprintln!("    rego-only: [{severity}] {rule_id} | {resource} {path} | {message}");
            }
            for (rule_id, severity, message, resource, path) in only_cel {
                eprintln!("    cel-only:  [{severity}] {rule_id} | {resource} {path} | {message}");
            }
        }
        fail(&format!("{} template(s) have engine parity failures", parity_failures.len()));
    }

    let count = persisted.len();
    let rendered = serde_json::to_string_pretty(&Value::Object(persisted))
        .unwrap_or_else(|e| fail(&format!("serialize golden: {e}")));
    if let Err(e) = std::fs::write(golden_file(), rendered + "\n") {
        fail(&format!("write {}: {e}", golden_file().display()));
    }

    println!("\nWrote {count} template results to {}", golden_file().display());
    println!("Engine parity verified: rego == cel on all {count} templates");
}

/// Build the release `cfn-validate` binary this generator drives, and return its path.
fn build_release_binary() -> Result<PathBuf, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    println!("Building cfn-validate (release)...");
    let status = Command::new(&cargo)
        .args(["build", "--release", "-p", "cfn-validate", "--bin", "cfn-validate"])
        .status()
        .map_err(|e| format!("failed to invoke `{cargo} build`: {e}"))?;
    if !status.success() {
        return Err("cargo build --release -p cfn-validate failed".to_string());
    }

    let target_dir =
        std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from).unwrap_or_else(|| workspace_root().join("target"));
    let binary = target_dir.join("release").join(format!("cfn-validate{}", std::env::consts::EXE_SUFFIX));
    if !binary.exists() {
        return Err(format!("built binary not found at {}", binary.display()));
    }
    Ok(binary)
}

/// Validate every template with both engines, fanning out across CPU cores.
/// Returns one [`Outcome`] per template, in the input order.
fn run_all(cfn_validate: &PathBuf, templates: &[String]) -> Vec<Outcome> {
    let total = templates.len();
    let worker_count = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).min(total.max(1));

    let next = AtomicUsize::new(0);
    let completed = AtomicUsize::new(0);
    let results: Mutex<Vec<(usize, Outcome)>> = Mutex::new(Vec::with_capacity(total));

    std::thread::scope(|scope| {
        for _ in 0..worker_count {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    if index >= total {
                        break;
                    }
                    let outcome = validate_template(cfn_validate, &templates[index]);
                    let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                    println!("[{done}/{total}] {}", templates[index]);
                    results.lock().expect("results mutex").push((index, outcome));
                }
            });
        }
    });

    let mut ordered = results.into_inner().expect("results mutex");
    ordered.sort_by_key(|(index, _)| *index);
    ordered.into_iter().map(|(_, outcome)| outcome).collect()
}

/// Run both engines on one template and decide its [`Outcome`].
fn validate_template(cfn_validate: &PathBuf, template: &str) -> Outcome {
    let rego = match run_cfn_validate(cfn_validate, template, "rego") {
        Ok(report) => report,
        Err(message) => return Outcome::Fatal(message),
    };
    let cel = match run_cfn_validate(cfn_validate, template, "cel") {
        Ok(report) => report,
        Err(message) => return Outcome::Fatal(message),
    };

    let rego_comparable = strip_fields(&rego, PARITY_IGNORED_FIELDS);
    let cel_comparable = strip_fields(&cel, PARITY_IGNORED_FIELDS);

    if rego_comparable != cel_comparable {
        let rego_diagnostics = diagnostic_keys(&rego_comparable);
        let cel_diagnostics = diagnostic_keys(&cel_comparable);
        let only_rego = sorted_difference(&rego_diagnostics, &cel_diagnostics);
        let only_cel = sorted_difference(&cel_diagnostics, &rego_diagnostics);
        return Outcome::Parity { only_rego, only_cel };
    }

    Outcome::Persist(strip_output_only_fields(&rego))
}

/// Invoke `cfn-validate <template> --format detailed --level debug --engine <engine>`
/// from the templates directory and parse its stdout, zeroing durations.
fn run_cfn_validate(cfn_validate: &PathBuf, template: &str, engine: &str) -> Result<Value, String> {
    let output = Command::new(cfn_validate)
        .args([template, "--format", "detailed", "--level", "debug", "--engine", engine])
        .current_dir(templates_dir())
        .output()
        .map_err(|e| format!("{engine} invocation failed: {e}"))?;

    if output.stdout.iter().all(u8::is_ascii_whitespace) {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("{engine} produced no output\n  stderr: {}", stderr.chars().take(500).collect::<String>()));
    }

    let mut report: Value =
        serde_json::from_slice(&output.stdout).map_err(|e| format!("{engine} produced invalid JSON: {e}"))?;
    zero_durations(&mut report);
    Ok(report)
}

/// Set every `durationMs` value (at any depth) to zero, so timing noise never
/// reaches the golden file or the parity comparison.
fn zero_durations(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if key == "durationMs" {
                    *child = Value::from(0.0);
                } else {
                    zero_durations(child);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(zero_durations),
        _ => {}
    }
}

/// Return a deep copy of `value` with every object key in `drop` removed at any depth.
fn strip_fields(value: &Value, drop: &[&str]) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(key, _)| !drop.contains(&key.as_str()))
                .map(|(key, child)| (key.clone(), strip_fields(child, drop)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(|item| strip_fields(item, drop)).collect()),
        other => other.clone(),
    }
}

/// Remove the fields that are compared across engines but not persisted: the
/// top-level output-only fields and `metadata.rulesEvaluated`.
fn strip_output_only_fields(report: &Value) -> Value {
    let Value::Object(map) = report else {
        return report.clone();
    };
    let mut trimmed: Map<String, Value> = map
        .iter()
        .filter(|(key, _)| !OUTPUT_ONLY_TOP_LEVEL_FIELDS.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    if let Some(Value::Object(metadata)) = trimmed.get("metadata") {
        let trimmed_metadata: Map<String, Value> = metadata
            .iter()
            .filter(|(key, _)| !OUTPUT_ONLY_METADATA_FIELDS.contains(&key.as_str()))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        // Re-inserting an existing key preserves its position (IndexMap semantics).
        trimmed.insert("metadata".to_string(), Value::Object(trimmed_metadata));
    }
    Value::Object(trimmed)
}

/// Extract identifying keys for every diagnostic in a report.
fn diagnostic_keys(report: &Value) -> HashSet<DiagnosticKey> {
    let field =
        |diagnostic: &Value, name: &str| diagnostic.get(name).and_then(Value::as_str).unwrap_or_default().to_string();
    report
        .get("diagnostics")
        .and_then(Value::as_array)
        .map(|diagnostics| {
            diagnostics
                .iter()
                .map(|d| {
                    (
                        field(d, "ruleId"),
                        field(d, "severity"),
                        field(d, "message"),
                        field(d, "resourceId"),
                        field(d, "propertyPath"),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The members of `left` absent from `right`, sorted for stable reporting.
fn sorted_difference(left: &HashSet<DiagnosticKey>, right: &HashSet<DiagnosticKey>) -> Vec<DiagnosticKey> {
    let mut only: Vec<DiagnosticKey> = left.difference(right).cloned().collect();
    only.sort();
    only
}

fn fail(message: &str) -> ! {
    eprintln!("ERROR: {message}");
    std::process::exit(1);
}
