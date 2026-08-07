#![allow(dead_code)]

use serde_json::Value;
use std::path::PathBuf;

pub fn resources_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().expect("workspace root").join("resources")
}

pub fn rules_dir() -> PathBuf {
    resources_root().join("rules")
}
pub fn templates_dir() -> PathBuf {
    resources_root().join("templates")
}

pub fn load_template(relative_path: &str) -> Vec<u8> {
    let path = templates_dir().join(relative_path);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read template {}: {e}", path.display()))
}

pub fn load_rule(filename: &str) -> String {
    let path = rules_dir().join(filename);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read rule {}: {e}", path.display()))
}

pub fn security_dir() -> PathBuf {
    resources_root().join("security")
}

pub fn load_security(filename: &str) -> Vec<u8> {
    let path = security_dir().join(filename);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read security fixture {}: {e}", path.display()))
}

pub fn load_security_rule(filename: &str) -> String {
    let path = security_dir().join(filename);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read security rule {}: {e}", path.display()))
}

/// All template directories covered by golden-file tests.
const GOLDEN_DIRS: &[&str] =
    &["bad", "cdk", "good", "gh-issues", "integration", "issues", "lsp", "public", "quickstart"];

/// Discover all templates under the given subdirectories of templates_dir().
pub fn discover_all_templates() -> Vec<String> {
    let root = templates_dir();
    let mut templates = Vec::new();
    for subdir in GOLDEN_DIRS {
        let dir = root.join(subdir);
        if dir.is_dir() {
            walk_collect(&dir, &root, &mut templates);
        }
    }
    templates.sort();
    templates
}

fn walk_collect(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_collect(&path, root, out);
        } else if matches!(path.extension().and_then(|s| s.to_str()), Some("yaml" | "yml" | "json"))
            && let Ok(rel) = path.strip_prefix(root)
        {
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
}

pub const MIN_GOLDEN_TEMPLATES: usize = 400;

pub fn load_combined_golden() -> serde_json::Map<String, Value> {
    let path = resources_root().join("expected").join("validation_reports.json");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read golden {}: {e}", path.display()));
    let val: Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse golden {}: {e}", path.display()));
    let map = val.as_object().cloned().unwrap_or_default();
    assert!(
        map.len() > MIN_GOLDEN_TEMPLATES,
        "golden {} must contain more than {MIN_GOLDEN_TEMPLATES} templates, found {} - the file is missing, empty, or truncated",
        path.display(),
        map.len()
    );
    map
}

/// Deep-compares `actual` against `expected`, collecting every path where they
/// differ. Returns the list of mismatch descriptions (empty = identical).
pub fn deep_diff(expected: &Value, actual: &Value, path: &str) -> Vec<String> {
    let mut diffs = Vec::new();
    match (expected, actual) {
        (Value::Object(exp), Value::Object(act)) => {
            for key in exp.keys() {
                if GOLDEN_EXCLUDED_FIELDS.contains(&key.as_str()) {
                    continue;
                }
                let child_path = if path.is_empty() { key.clone() } else { format!("{path}.{key}") };
                match act.get(key) {
                    Some(act_val) => diffs.extend(deep_diff(&exp[key], act_val, &child_path)),
                    None => diffs.push(format!("{child_path}: missing in actual")),
                }
            }
            for key in act.keys() {
                if !exp.contains_key(key) && !GOLDEN_EXCLUDED_FIELDS.contains(&key.as_str()) {
                    let child_path = if path.is_empty() { key.clone() } else { format!("{path}.{key}") };
                    diffs.push(format!("{child_path}: unexpected in actual"));
                }
            }
        }
        (Value::Array(exp), Value::Array(act)) => {
            if exp.len() != act.len() {
                diffs.push(format!("{path}: array length expected={} actual={}", exp.len(), act.len()));
            }
            for (i, (e, a)) in exp.iter().zip(act.iter()).enumerate() {
                diffs.extend(deep_diff(e, a, &format!("{path}[{i}]")));
            }
        }
        _ => {
            if expected != actual {
                diffs.push(format!(
                    "{path}: expected={} actual={}",
                    serde_json::to_string(expected).unwrap_or_default(),
                    serde_json::to_string(actual).unwrap_or_default(),
                ));
            }
        }
    }
    diffs
}

pub const DETAILED_ONLY_DIAGNOSTIC_FIELDS: &[&str] = &["documentationUrl", "context", "ruleDescription", "phase"];

pub const GOLDEN_EXCLUDED_FIELDS: &[&str] = &["performance", "version", "rulesEvaluated", "suppressed"];
