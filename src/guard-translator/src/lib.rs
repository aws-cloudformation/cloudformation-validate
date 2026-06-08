//! Parses Guard DSL files into an engine-agnostic IR.
//!
//! Engine-specific translation (IR → Rego, IR → CEL) lives in each engine crate.

pub mod ir;
pub(crate) mod lower;

use std::fs;
use std::path::Path;

use ir::GuardFile;

pub fn parse_guard(source: &str, file_name: &str) -> Result<GuardFile, String> {
    let span = guard_lang::parser::Span::new_extra(source, file_name);
    match guard_lang::parser::rules_file(span) {
        Ok(Some(rules_file)) => Ok(lower::lower_rules_file(&rules_file)),
        Ok(None) => Ok(GuardFile {
            assignments: Vec::new(),
            rules: Vec::new(),
            parameterized_rules: Vec::new(),
        }),
        Err(e) => Err(format!("Failed to parse Guard file '{}': {}", file_name, e)),
    }
}

/// Load all `.guard` files from a single directory (non-recursive).
pub fn load_pack_directory(dir: &str) -> Result<Vec<(String, String)>, String> {
    let path = Path::new(dir);
    if !path.is_dir() {
        return Err(format!("Guard rule pack directory not found: {}", dir));
    }
    let mut sources = Vec::new();
    let entries = fs::read_dir(path)
        .map_err(|e| format!("Failed to read pack directory '{}': {}", dir, e))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read entry in '{}': {}", dir, e))?;
        let file_path = entry.path();
        if file_path.extension().and_then(|e| e.to_str()) == Some("guard") {
            let path_str = file_path.display().to_string();
            let content = fs::read_to_string(&file_path)
                .map_err(|e| format!("Failed to read '{}': {}", path_str, e))?;
            sources.push((path_str, content));
        }
    }
    if sources.is_empty() {
        return Err(format!("No .guard files found in pack directory: {}", dir));
    }
    sources.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(sources)
}

/// Load all `.guard` files from a directory tree (recursive).
pub fn load_guard_sources_recursive(dir: &str) -> Result<Vec<(String, String)>, String> {
    let path = Path::new(dir);
    if !path.is_dir() {
        return Err(format!("Guard rule directory not found: {}", dir));
    }
    let mut sources = Vec::new();
    collect_guard_files_recursive(path, &mut sources)?;
    if sources.is_empty() {
        return Err(format!(
            "No .guard files found in directory (recursive): {}",
            dir
        ));
    }
    sources.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(sources)
}

fn collect_guard_files_recursive(
    dir: &Path,
    out: &mut Vec<(String, String)>,
) -> Result<(), String> {
    let entries = fs::read_dir(dir)
        .map_err(|e| format!("Failed to read directory '{}': {}", dir.display(), e))?;
    for entry in entries {
        let entry =
            entry.map_err(|e| format!("Failed to read entry in '{}': {}", dir.display(), e))?;
        let path = entry.path();
        if path.is_dir() {
            collect_guard_files_recursive(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("guard") {
            let path_str = path.display().to_string();
            let content = fs::read_to_string(&path)
                .map_err(|e| format!("Failed to read '{}': {}", path_str, e))?;
            out.push((path_str, content));
        }
    }
    Ok(())
}

/// Derive a pack name from a file path by taking the file stem and replacing
/// non-alphanumeric characters with `_`.
///
/// e.g. `"security-policies/elb-listener.guard"` → `"elb_listener"`
pub fn pack_name_from_path(path: &str) -> String {
    let stem = path
        .rsplit('/')
        .next()
        .unwrap_or(path)
        .trim_end_matches(".guard")
        .trim_end_matches(".ruleset");
    stem.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}
