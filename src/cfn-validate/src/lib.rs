use std::fs;
use std::path::{Path, PathBuf};

use data_source::AdditionalSchemaSource;
use rules::IdRange;
use validation_engine::ValidationError;

/// Loads overlay schemas from files and directories.
///
/// A path may be a single `.json` schema or a directory, which is scanned
/// (non-recursively) for `.json` files. The resource type name comes from each
/// schema's own `typeName`, so a directory of registry schemas can be pointed
/// at directly.
///
/// Returns contextual errors for directory read failures and individual file
/// read failures (naming the failing path), and rejects an empty directory as
/// likely user error.
pub fn load_additional_schema_sources(paths: &[String]) -> Result<Vec<AdditionalSchemaSource>, ValidationError> {
    let mut sources = Vec::new();
    for path in paths {
        let candidate = Path::new(path);
        if candidate.is_dir() {
            let entries = fs::read_dir(candidate).map_err(|e| {
                ValidationError::Engine(format!("Failed to read additional schema directory '{path}': {e}"))
            })?;
            let mut files: Vec<PathBuf> = Vec::new();
            for entry in entries {
                let entry = entry
                    .map_err(|e| ValidationError::Engine(format!("Failed to read directory entry in '{path}': {e}")))?;
                let file_path = entry.path();
                if file_path.extension().is_some_and(|ext| ext == "json") {
                    files.push(file_path);
                }
            }
            files.sort();
            if files.is_empty() {
                return Err(ValidationError::Engine(format!("No .json schema files found in '{path}'")));
            }
            for file in files {
                sources.push(read_schema_file(&file)?);
            }
        } else if candidate.is_file() {
            sources.push(read_schema_file(candidate)?);
        } else {
            return Err(ValidationError::Engine(format!("Additional schema not found: {path}")));
        }
    }
    Ok(sources)
}

fn read_schema_file(path: &Path) -> Result<AdditionalSchemaSource, ValidationError> {
    let schema = fs::read_to_string(path)
        .map_err(|e| ValidationError::Engine(format!("Failed to read additional schema '{}': {e}", path.display())))?;
    let source = AdditionalSchemaSource { type_name: None, schema };
    source.resolve().map_err(|e| {
        ValidationError::Engine(format!("Failed to resolve additional schema '{}': {e}", path.display()))
    })?;
    Ok(source)
}

pub fn collect_files(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }
    let mut files = Vec::new();
    collect_files_recursive(path, &mut files);
    files.sort();
    files
}

fn is_template_file(path: &Path) -> bool {
    matches!(path.extension().and_then(|s| s.to_str()), Some("yaml" | "yml" | "json"))
}

fn collect_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files_recursive(&path, files);
        } else if path.is_file() && is_template_file(&path) {
            files.push(path);
        }
    }
}

/// Parses a resource-scoped filter argument of the form `TARGET` or
/// `TARGET=RULE_ID`, returning the target and the optional rule scope.
///
/// The target is a logical resource ID, a resource type, or a service name
/// depending on the flag; it is taken verbatim. The bare `TARGET` form (or a
/// trailing `=` with nothing after it) scopes the filter to every rule on that
/// target; `TARGET=RULE_ID` scopes it to a single rule.
/// `=` is used as the separator because it never appears in a rule ID, a service
/// name, or a resource type (which uses `::`), so the split is unambiguous.
/// Returns `None` only when the target is empty.
pub fn parse_scoped_target(s: &str) -> Option<(String, Option<String>)> {
    let (target, rule_id) = match s.split_once('=') {
        Some((target, rule_id)) => (target, Some(rule_id)),
        None => (s, None),
    };
    if target.is_empty() {
        return None;
    }
    Some((target.to_string(), rule_id.filter(|r| !r.is_empty()).map(String::from)))
}

/// Parses a rule ID range of the form `"<start>-<end>"` (a shared letter prefix
/// followed by an inclusive numeric span) into an `IdRange`. Returns `None` if
/// the format is invalid.
pub fn parse_range(s: &str) -> Option<IdRange> {
    let halves: Vec<&str> = s.split('-').collect();
    if halves.len() != 2 {
        return None;
    }
    let start_half = halves[0];
    let end_half = halves[1];
    let prefix_len = start_half.chars().take_while(|c| !c.is_ascii_digit()).count();
    let prefix = &start_half[..prefix_len];
    let start: u32 = start_half[prefix_len..].parse().ok()?;
    let end_prefix_len = end_half.chars().take_while(|c| !c.is_ascii_digit()).count();
    let end: u32 = end_half[end_prefix_len..].parse().ok()?;
    Some(IdRange { prefix: prefix.to_string(), start, end })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_scoped_target_bare_target_scopes_all_rules() {
        let (target, rule_id) = parse_scoped_target("AWS::AutoScaling").unwrap();
        assert_eq!(target, "AWS::AutoScaling");
        assert_eq!(rule_id, None, "a bare target scopes the filter to every rule");
    }

    #[test]
    fn parse_scoped_target_with_rule_id_splits_on_equals_not_double_colon() {
        // A service prefix contains `::`; the split must be on `=` so the whole
        // `AWS::AutoScaling` prefix stays intact as the target.
        let (target, rule_id) = parse_scoped_target("AWS::AutoScaling=W3697").unwrap();
        assert_eq!(target, "AWS::AutoScaling");
        assert_eq!(rule_id.as_deref(), Some("W3697"));
    }

    #[test]
    fn parse_scoped_target_handles_resource_type_with_double_colons() {
        let (target, rule_id) = parse_scoped_target("AWS::AutoScaling::LaunchConfiguration=W3697").unwrap();
        assert_eq!(target, "AWS::AutoScaling::LaunchConfiguration");
        assert_eq!(rule_id.as_deref(), Some("W3697"));
    }

    #[test]
    fn parse_scoped_target_trailing_equals_scopes_all_rules() {
        let (target, rule_id) = parse_scoped_target("MyBucket=").unwrap();
        assert_eq!(target, "MyBucket");
        assert_eq!(rule_id, None, "an empty rule id after '=' scopes the filter to every rule");
    }

    #[test]
    fn parse_scoped_target_returns_none_for_empty_target() {
        assert!(parse_scoped_target("").is_none(), "an empty target is rejected");
        assert!(parse_scoped_target("=W3697").is_none(), "a missing target before '=' is rejected");
    }

    #[test]
    fn parse_range_returns_prefix_start_end() {
        let range = parse_range("E3000-E3099").unwrap();
        assert_eq!(range.prefix, "E");
        assert_eq!(range.start, 3000);
        assert_eq!(range.end, 3099);
    }

    #[test]
    fn parse_range_end_half_without_prefix() {
        let range = parse_range("W1000-1099").unwrap();
        assert_eq!(range.prefix, "W");
        assert_eq!(range.start, 1000);
        assert_eq!(range.end, 1099);
    }

    #[test]
    fn parse_range_returns_none_for_missing_dash() {
        assert!(parse_range("E3000").is_none(), "single rule ID without dash should return None");
    }

    #[test]
    fn parse_range_returns_none_for_too_many_dashes() {
        assert!(parse_range("E3000-E3099-E3199").is_none(), "triple-segment range should return None");
    }

    #[test]
    fn parse_range_returns_none_for_non_numeric() {
        assert!(parse_range("abc-def").is_none(), "non-numeric range should return None");
    }

    #[test]
    fn parse_range_returns_none_for_empty_string() {
        assert!(parse_range("").is_none(), "empty string should return None");
    }

    #[test]
    fn load_additional_schema_sources_names_file_when_type_name_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let schema_file = dir.path().join("missing-type-name.json");
        fs::write(&schema_file, r#"{"properties":{"Name":{"type":"string"}}}"#).unwrap();

        let error = load_additional_schema_sources(&[schema_file.to_string_lossy().into_owned()])
            .expect_err("a schema without a type name must fail");
        let message = error.to_string();
        assert!(
            message.contains(schema_file.to_string_lossy().as_ref()),
            "the error must identify the failing schema file: {message}"
        );
        assert!(
            message.contains("missing a resource type name"),
            "the error must retain the resolution failure: {message}"
        );
    }

    #[test]
    fn collect_files_returns_single_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("template.yaml");
        fs::write(&file, "content").unwrap();

        let result = collect_files(&file);
        assert_eq!(result, vec![file]);
    }

    #[test]
    fn collect_files_returns_sorted_directory_contents() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("b.yaml"), "b").unwrap();
        fs::write(dir.path().join("a.yaml"), "a").unwrap();

        let result = collect_files(dir.path());
        let names: Vec<_> = result.iter().map(|p| p.file_name().unwrap()).collect();
        assert_eq!(names, vec!["a.yaml", "b.yaml"]);
    }

    #[test]
    fn collect_files_recurses_into_subdirectories() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(dir.path().join("root.yaml"), "r").unwrap();
        fs::write(sub.join("nested.yaml"), "n").unwrap();

        let result = collect_files(dir.path());
        assert_eq!(result.len(), 2);
        assert!(result.iter().any(|p| p.ends_with("root.yaml")));
        assert!(result.iter().any(|p| p.ends_with("nested.yaml")));
    }

    #[test]
    fn collect_files_returns_empty_for_nonexistent_directory() {
        let result = collect_files(Path::new("/nonexistent/path/that/does/not/exist"));
        assert!(result.is_empty());
    }

    #[test]
    fn collect_files_returns_empty_for_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let result = collect_files(dir.path());
        assert!(result.is_empty());
    }

    #[test]
    fn collect_files_includes_yaml_yml_json_only() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.yaml"), "a").unwrap();
        fs::write(dir.path().join("b.yml"), "b").unwrap();
        fs::write(dir.path().join("c.json"), "c").unwrap();
        fs::write(dir.path().join("d.txt"), "d").unwrap();
        fs::write(dir.path().join("e.md"), "e").unwrap();

        let result = collect_files(dir.path());
        let names: Vec<_> = result.iter().map(|p| p.file_name().unwrap().to_str().unwrap()).collect();
        assert_eq!(names, vec!["a.yaml", "b.yml", "c.json"], "only .yaml, .yml, .json files should be collected");
    }
}
