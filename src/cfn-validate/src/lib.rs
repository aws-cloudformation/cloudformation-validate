use std::fs;
use std::path::{Path, PathBuf};

use rules::IdRange;

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
    matches!(
        path.extension().and_then(|s| s.to_str()),
        Some("yaml" | "yml" | "json")
    )
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

/// Parses a rule ID range like `"E3000-E3099"` into an `IdRange`.
/// Returns `None` if the format is invalid.
pub fn parse_range(s: &str) -> Option<IdRange> {
    let halves: Vec<&str> = s.split('-').collect();
    if halves.len() != 2 {
        return None;
    }
    let start_half = halves[0];
    let end_half = halves[1];
    let prefix_len = start_half
        .chars()
        .take_while(|c| !c.is_ascii_digit())
        .count();
    let prefix = &start_half[..prefix_len];
    let start: u32 = start_half[prefix_len..].parse().ok()?;
    let end_prefix_len = end_half.chars().take_while(|c| !c.is_ascii_digit()).count();
    let end: u32 = end_half[end_prefix_len..].parse().ok()?;
    Some(IdRange {
        prefix: prefix.to_string(),
        start,
        end,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
        assert!(
            parse_range("E3000").is_none(),
            "single rule ID without dash should return None"
        );
    }

    #[test]
    fn parse_range_returns_none_for_too_many_dashes() {
        assert!(
            parse_range("E3000-E3099-E3199").is_none(),
            "triple-segment range should return None"
        );
    }

    #[test]
    fn parse_range_returns_none_for_non_numeric() {
        assert!(
            parse_range("abc-def").is_none(),
            "non-numeric range should return None"
        );
    }

    #[test]
    fn parse_range_returns_none_for_empty_string() {
        assert!(parse_range("").is_none(), "empty string should return None");
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
        let names: Vec<_> = result
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec!["a.yaml", "b.yml", "c.json"],
            "only .yaml, .yml, .json files should be collected"
        );
    }
}
