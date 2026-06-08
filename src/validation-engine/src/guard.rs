use crate::engine::ExternalRuleSource;
use std::fs;
use std::path::Path;

pub fn resolve_guard_config(
    rule_source_paths: &[String],
) -> Result<Vec<ExternalRuleSource>, String> {
    let mut entries = Vec::new();

    for path in rule_source_paths {
        let p = Path::new(path);
        if p.is_dir() {
            let sources = guard_translator::load_guard_sources_recursive(path)?;
            for (file_path, file_content) in sources {
                entries.push(ExternalRuleSource {
                    name: file_path,
                    content: file_content,
                });
            }
        } else if p.is_file() {
            let file_content = fs::read_to_string(p)
                .map_err(|e| format!("Failed to read guard file '{}': {}", path, e))?;
            entries.push(ExternalRuleSource {
                name: path.clone(),
                content: file_content,
            });
        } else {
            return Err(format!("Guard rule source not found: {}", path));
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;

    #[test]
    fn resolve_guard_config_single_file() {
        let dir = env::temp_dir().join("guard_test_single");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("test.guard");
        fs::write(&file, "rule example { true }").unwrap();

        let result = resolve_guard_config(&[file.to_string_lossy().to_string()]);
        let entries = result.expect("resolve_guard_config should succeed for single file");
        assert_eq!(entries.len(), 1);
        assert!(entries[0].content.contains("rule example"));
        assert!(entries[0].name.contains("test.guard"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_guard_config_directory_recursive() {
        let dir = env::temp_dir().join("guard_test_dir");
        let _ = fs::remove_dir_all(&dir);
        let sub = dir.join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(dir.join("a.guard"), "rule a { true }").unwrap();
        fs::write(sub.join("b.guard"), "rule b { true }").unwrap();

        let result = resolve_guard_config(&[dir.to_string_lossy().to_string()]);
        let entries = result.expect("resolve_guard_config should succeed for directory");
        assert_eq!(entries.len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_guard_config_nonexistent_path_returns_error() {
        let result = resolve_guard_config(&["/nonexistent/path/to/guard.guard".into()]);
        let err = result.unwrap_err();
        assert!(
            err.contains("not found"),
            "error should mention 'not found', got: {err}"
        );
    }

    #[test]
    fn resolve_guard_config_empty_paths_returns_empty() {
        let result = resolve_guard_config(&[]);
        let entries = result.expect("empty paths should succeed");
        assert_eq!(entries.len(), 0, "empty paths should return empty vec");
    }

    #[test]
    fn resolve_guard_config_mixed_file_and_dir() {
        let dir = env::temp_dir().join("guard_test_mixed");
        let _ = fs::remove_dir_all(&dir);
        let sub = dir.join("rules");
        fs::create_dir_all(&sub).unwrap();
        let standalone = dir.join("standalone.guard");
        fs::write(&standalone, "rule standalone { true }").unwrap();
        fs::write(sub.join("packed.guard"), "rule packed { true }").unwrap();

        let result = resolve_guard_config(&[
            standalone.to_string_lossy().to_string(),
            sub.to_string_lossy().to_string(),
        ]);
        let entries = result.expect("mixed file and dir should succeed");
        assert_eq!(entries.len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_guard_config_preserves_file_content() {
        let dir = env::temp_dir().join("guard_test_content");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("content.guard");
        let guard_source =
            "rule check_bucket {\n  AWS::S3::Bucket {\n    Properties.BucketName exists\n  }\n}";
        fs::write(&file, guard_source).unwrap();

        let entries = resolve_guard_config(&[file.to_string_lossy().to_string()]).unwrap();
        assert_eq!(entries[0].content, guard_source);

        let _ = fs::remove_dir_all(&dir);
    }
}
