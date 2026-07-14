//! Conformance tests proving the JSON and YAML front-ends are interchangeable.
//!
//! Every JSON template under `resources/templates` is validated directly, then
//! losslessly re-serialized to YAML and validated again. For each engine, the two
//! runs must produce the same diagnostics. Source locations legitimately differ
//! between the two formats (byte offsets in JSON vs YAML markers), so they are
//! excluded from the comparison; everything else — rule id, severity, message,
//! resource, property path, context — must match exactly. A divergence is a
//! parser bug.

mod common;

use cel_engine::CelEngine;
use common::{load_template, templates_dir};
use diagnostics::DetailLevel;
use rego_engine::RegoEngine;
use rules::Severity;
use schema_validator::SchemaValidator;
use serde_json::Value;
use std::collections::BTreeMap;
use validation_engine::{EngineConfig, ValidateConfig, ValidationEngine, validate_bytes_with_path};

/// JSON templates that cannot survive a structural round-trip through YAML, and
/// therefore cannot be compared this way. The first two are intentionally
/// malformed JSON (they exercise the parse-error path and never yield a model to
/// convert); the third relies on a duplicate object key, which any structural
/// re-serialization collapses — erasing the very condition it tests.
const NON_ROUNDTRIPPABLE: &[&str] = &["bad/json_parse.json", "bad/core/config_invalid_json.json", "bad/duplicate.json"];

/// Guards against the discovery walk silently finding nothing and the test
/// passing vacuously. There are ~150 convertible JSON templates today.
const MIN_JSON_TEMPLATES: usize = 100;

/// Location fields that legitimately differ between the two formats and are
/// dropped before comparing diagnostics.
const LOCATION_FIELDS: &[&str] = &["startLine", "startColumn", "endLine", "endColumn"];

fn discover_json_templates() -> Vec<String> {
    let root = templates_dir();
    let mut templates = Vec::new();
    collect_json(&root, &root, &mut templates);
    templates.retain(|rel| !NON_ROUNDTRIPPABLE.contains(&rel.as_str()));
    templates.sort();
    templates
}

fn collect_json(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_json(&path, root, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("json")
            && let Ok(rel) = path.strip_prefix(root)
        {
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
}

/// Re-serializes a parsed JSON template as block-style YAML that re-parses to the
/// identical logical content. Every string and key is double-quoted so the YAML
/// front-end never re-infers a scalar's type — a bare `1` is an integer, but the
/// JSON string `"1"` must stay a string. Numbers use their canonical `serde_json`
/// spelling so float text cannot drift between the two front-ends. The escape set
/// `serde_json` emits for a string is a subset of YAML's double-quoted escapes, so
/// the exact same characters come back out.
fn json_to_yaml(value: &Value) -> String {
    let mut out = String::new();
    match scalar_repr(value) {
        Some(scalar) => {
            out.push_str(&scalar);
            out.push('\n');
        }
        None => emit_block(value, 0, &mut out),
    }
    out
}

/// The single-line YAML rendering of a scalar or empty collection, or `None` for a
/// non-empty object/array that must be emitted as an indented block.
fn scalar_repr(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some("null".to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        Value::String(_) => Some(quote(value)),
        Value::Object(map) if map.is_empty() => Some("{}".to_string()),
        Value::Array(items) if items.is_empty() => Some("[]".to_string()),
        _ => None,
    }
}

/// Renders `s` as a double-quoted YAML scalar by borrowing `serde_json`'s string
/// escaping, whose output is always a valid YAML double-quoted scalar.
fn quote(string_value: &Value) -> String {
    serde_json::to_string(string_value).expect("string value serializes")
}

fn emit_block(value: &Value, indent: usize, out: &mut String) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                push_indent(out, indent);
                out.push_str(&quote(&Value::String(key.clone())));
                out.push(':');
                match scalar_repr(child) {
                    Some(scalar) => {
                        out.push(' ');
                        out.push_str(&scalar);
                        out.push('\n');
                    }
                    None => {
                        out.push('\n');
                        emit_block(child, indent + 1, out);
                    }
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                push_indent(out, indent);
                match scalar_repr(item) {
                    Some(scalar) => {
                        out.push_str("- ");
                        out.push_str(&scalar);
                        out.push('\n');
                    }
                    None => {
                        // A nested collection under a sequence entry goes on the
                        // lines after the dash, indented one level deeper.
                        out.push_str("-\n");
                        emit_block(item, indent + 1, out);
                    }
                }
            }
        }
        _ => unreachable!("scalars are rendered by scalar_repr before recursion"),
    }
}

fn push_indent(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push_str("  ");
    }
}

/// Validates `bytes` at detailed level and returns the diagnostics as a
/// location-independent, order-independent multiset: each diagnostic is a JSON
/// object with its source-location fields removed, and the collection is sorted so
/// two runs can be compared directly.
fn diagnostic_multiset(engine: &dyn ValidationEngine, bytes: &[u8], path: &str) -> Vec<Value> {
    let sv = SchemaValidator::new();
    let config =
        ValidateConfig { detail_level: DetailLevel::Detailed, severity_level: Severity::Debug, ..Default::default() };
    let report = validate_bytes_with_path(engine, &sv, bytes, config, path.to_string()).expect("validate");
    let detailed = serde_json::to_value(report.to_detailed()).expect("serialize detailed report");

    let mut diagnostics: Vec<Value> = detailed
        .get("diagnostics")
        .and_then(|d| d.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|mut diag| {
            strip_locations(&mut diag);
            diag
        })
        .collect();
    diagnostics.sort_by_cached_key(|d| serde_json::to_string(d).unwrap_or_default());
    diagnostics
}

fn strip_locations(diag: &mut Value) {
    let Some(obj) = diag.as_object_mut() else {
        return;
    };
    for field in LOCATION_FIELDS {
        obj.remove(*field);
    }
    if let Some(related) = obj.get_mut("relatedResources").and_then(|r| r.as_array_mut()) {
        for entry in related {
            if let Some(entry_obj) = entry.as_object_mut() {
                entry_obj.remove("location");
            }
        }
    }
}

/// A one-line human-readable summary of a diagnostic, for failure messages.
fn summarize(diag: &Value) -> String {
    let field = |name: &str| diag.get(name).and_then(|v| v.as_str()).unwrap_or("");
    format!(
        "{} [{}] resource={:?} path={:?} msg={:?}",
        field("ruleId"),
        field("severity"),
        field("resourceId"),
        field("propertyPath"),
        field("message"),
    )
}

/// Describes how two diagnostic multisets differ, as a multiset difference in both
/// directions.
fn describe_difference(from_json: &[Value], from_yaml: &[Value]) -> String {
    let mut counts: BTreeMap<String, (i32, Value)> = BTreeMap::new();
    for diag in from_json {
        let entry = counts.entry(serde_json::to_string(diag).unwrap_or_default()).or_insert((0, diag.clone()));
        entry.0 += 1;
    }
    for diag in from_yaml {
        let entry = counts.entry(serde_json::to_string(diag).unwrap_or_default()).or_insert((0, diag.clone()));
        entry.0 -= 1;
    }

    let mut only_json = Vec::new();
    let mut only_yaml = Vec::new();
    for (_, (delta, diag)) in counts {
        if delta > 0 {
            only_json.push(format!("    JSON-only (x{}): {}", delta, summarize(&diag)));
        } else if delta < 0 {
            only_yaml.push(format!("    YAML-only (x{}): {}", -delta, summarize(&diag)));
        }
    }

    let mut lines = Vec::new();
    lines.extend(only_json);
    lines.extend(only_yaml);
    lines.join("\n")
}

fn check_engine(engine_name: &str, engine: &dyn ValidationEngine) {
    let templates = discover_json_templates();
    assert!(
        templates.len() >= MIN_JSON_TEMPLATES,
        "discovered only {} JSON templates under {} — expected at least {MIN_JSON_TEMPLATES}",
        templates.len(),
        templates_dir().display()
    );

    let mut failures = Vec::new();
    for relative_path in &templates {
        let json_bytes = load_template(relative_path);
        let value: Value = match serde_json::from_slice(&json_bytes) {
            Ok(v) => v,
            Err(e) => {
                failures.push(format!("{relative_path}: not parseable as JSON for conversion: {e}"));
                continue;
            }
        };
        let yaml_source = json_to_yaml(&value);
        let yaml_path = format!("{relative_path}.converted.yaml");

        let from_json = diagnostic_multiset(engine, &json_bytes, relative_path);
        let from_yaml = diagnostic_multiset(engine, yaml_source.as_bytes(), &yaml_path);

        if from_json != from_yaml {
            failures.push(format!("{relative_path}:\n{}", describe_difference(&from_json, &from_yaml)));
        }
    }

    assert!(
        failures.is_empty(),
        "{engine_name}: {} template(s) produced different diagnostics from JSON vs converted YAML:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

#[test]
fn rego_json_and_yaml_diagnostics_match() {
    let engine = RegoEngine::new(EngineConfig::default()).expect("rego engine");
    check_engine("rego", &engine);
}

#[test]
fn cel_json_and_yaml_diagnostics_match() {
    let engine = CelEngine::new(EngineConfig::default()).expect("cel engine");
    check_engine("cel", &engine);
}

/// The converter must produce YAML — not accidentally re-emit something the format
/// dispatcher routes back to the JSON front-end (only a leading `{` selects JSON).
#[test]
fn converter_emits_yaml_not_json() {
    let value: Value = serde_json::json!({ "Resources": { "B": { "Type": "AWS::S3::Bucket" } } });
    let yaml = json_to_yaml(&value);
    let first = yaml.trim_start().as_bytes().first().copied();
    assert_ne!(first, Some(b'{'), "converted output must not lead with '{{' or it dispatches to the JSON parser");
    assert!(yaml.contains("\"Resources\":"), "expected a quoted block-style key, got:\n{yaml}");
}
