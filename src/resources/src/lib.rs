//! Test-fixture crate for `cloudformation-validate`.
//!
//! The template corpus, rule fixtures, security fixtures, and the
//! `expected/validation_reports*.json` snapshot chunks all live on disk under
//! this crate's root. This library exposes their locations and separate discovery
//! APIs for the regular template corpus, complete snapshot generation, and
//! snapshot loading.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// Maximum number of template reports stored in a single snapshot chunk file.
pub const TEMPLATES_PER_CHUNK: usize = 100;

/// Prefix for snapshot chunk filenames (before the 1-based index).
const CHUNK_FILENAME_PREFIX: &str = "validation_reports";

/// Extension for snapshot chunk filenames.
const CHUNK_FILENAME_EXTENSION: &str = ".json";

/// Root of this crate — the directory holding `templates/`, `rules/`, `security/`,
/// and `expected/`.
pub fn resources_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The Cargo workspace root (parent of this crate), under which `target/` lives.
pub fn workspace_root() -> PathBuf {
    resources_root().parent().expect("resources crate has a parent workspace directory").to_path_buf()
}

pub fn templates_dir() -> PathBuf {
    resources_root().join("templates")
}

pub fn security_dir() -> PathBuf {
    resources_root().join("security")
}

pub fn expected_dir() -> PathBuf {
    resources_root().join("expected")
}

/// Path to the legacy single snapshot file (used only for cleanup during regeneration).
pub fn legacy_validation_reports_file() -> PathBuf {
    expected_dir().join("validation_reports.json")
}

/// Build the filename for a 1-based chunk index: `validation_reports1.json`, etc.
pub fn snapshot_chunk_filename(one_based_index: usize) -> String {
    format!("{CHUNK_FILENAME_PREFIX}{one_based_index}{CHUNK_FILENAME_EXTENSION}")
}

/// Discover all numbered snapshot chunk files in `expected/` in numeric order.
///
/// Returns tuples of (1-based index, path). Fails if no chunks are found or if
/// the chunk sequence has gaps or duplicates.
pub fn discover_snapshot_chunks() -> Result<Vec<(usize, PathBuf)>, String> {
    let dir = expected_dir();
    let entries = std::fs::read_dir(&dir).map_err(|e| format!("read expected directory {}: {e}", dir.display()))?;

    let mut chunks: Vec<(usize, PathBuf)> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry in {}: {e}", dir.display()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Some(index) = parse_chunk_index(&path) {
            chunks.push((index, path));
        }
    }

    if chunks.is_empty() {
        return Err(format!(
            "no snapshot chunk files ({}N{}) found in {}",
            CHUNK_FILENAME_PREFIX,
            CHUNK_FILENAME_EXTENSION,
            dir.display()
        ));
    }

    chunks.sort_by_key(|(index, _)| *index);

    // Reject duplicate chunk numbers.
    for window in chunks.windows(2) {
        if window[0].0 == window[1].0 {
            return Err(format!("duplicate snapshot chunk number {} in {}", window[0].0, dir.display()));
        }
    }

    // Reject non-contiguous indices (must be 1..=N with no gaps).
    for (expected_pos, (actual_index, path)) in chunks.iter().enumerate() {
        let expected_index = expected_pos + 1;
        if *actual_index != expected_index {
            return Err(format!(
                "non-contiguous snapshot chunk sequence: expected index {} but found {} ({})",
                expected_index,
                actual_index,
                path.display()
            ));
        }
    }

    Ok(chunks)
}

/// Load and merge all snapshot chunk files into a single map.
///
/// Fails on: no chunks found, non-object JSON, or duplicate template keys across chunks.
pub fn load_merged_snapshots() -> Result<serde_json::Map<String, Value>, String> {
    let chunks = discover_snapshot_chunks()?;
    let mut merged = serde_json::Map::new();

    for (index, path) in &chunks {
        let bytes = std::fs::read(path).map_err(|e| format!("read snapshot chunk {}: {e}", path.display()))?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|e| {
            format!("parse snapshot chunk {} ({}): {e}", path.display(), snapshot_chunk_filename(*index))
        })?;
        let map = value
            .as_object()
            .ok_or_else(|| format!("snapshot chunk {} is not a JSON object", snapshot_chunk_filename(*index)))?;

        for (key, report) in map {
            if merged.contains_key(key) {
                return Err(format!(
                    "duplicate template key {key:?} in chunk {} — already present in an earlier chunk",
                    snapshot_chunk_filename(*index)
                ));
            }
            merged.insert(key.clone(), report.clone());
        }
    }

    Ok(merged)
}

/// Extract the 1-based numeric index from a chunk filename, or `None` if the
/// path does not match the canonical `validation_reports[1-9][0-9]*.json` pattern.
fn parse_chunk_index(path: &Path) -> Option<usize> {
    let filename = path.file_name()?.to_str()?;
    let without_ext = filename.strip_suffix(CHUNK_FILENAME_EXTENSION)?;
    let index_str = without_ext.strip_prefix(CHUNK_FILENAME_PREFIX)?;
    if index_str.is_empty() {
        return None;
    }
    // Reject leading zeros (e.g. "01") and zero itself.
    let first_char = index_str.as_bytes().first()?;
    if *first_char == b'0' {
        return None;
    }
    // All characters must be ASCII digits.
    if !index_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    index_str.parse::<usize>().ok()
}

/// Discover every template recursively under [`templates_dir`], returned as
/// sorted, forward-slash paths relative to that directory.
pub fn discover_templates() -> Vec<String> {
    let root = templates_dir();
    let mut templates = Vec::new();
    if root.is_dir() {
        collect_templates(&root, &root, &mut templates);
    }
    templates.sort();
    templates
}

/// Discover every fixture persisted by snapshot generation.
///
/// Regular template keys remain relative to [`templates_dir`]. Security fixture
/// keys retain their `security/` prefix so the two roots remain distinguishable.
pub fn discover_snapshot_templates() -> Vec<String> {
    let mut templates = discover_templates();
    let root = resources_root();
    let security = security_dir();
    if security.is_dir() {
        collect_templates(&security, &root, &mut templates);
    }
    templates.sort();
    templates
}

fn collect_templates(dir: &Path, root: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_templates(&path, root, out);
        } else if matches!(path.extension().and_then(|s| s.to_str()), Some("yaml" | "yml" | "json"))
            && let Ok(rel) = path.strip_prefix(root)
        {
            out.push(rel.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_chunk_filename_produces_expected_names() {
        assert_eq!(snapshot_chunk_filename(1), "validation_reports1.json");
        assert_eq!(snapshot_chunk_filename(10), "validation_reports10.json");
        assert_eq!(snapshot_chunk_filename(100), "validation_reports100.json");
    }

    #[test]
    fn parse_chunk_index_extracts_valid_indices() {
        assert_eq!(parse_chunk_index(Path::new("validation_reports1.json")), Some(1));
        assert_eq!(parse_chunk_index(Path::new("validation_reports10.json")), Some(10));
        assert_eq!(parse_chunk_index(Path::new("validation_reports99.json")), Some(99));
        assert_eq!(parse_chunk_index(Path::new("/some/dir/validation_reports3.json")), Some(3));
    }

    #[test]
    fn parse_chunk_index_rejects_invalid_names() {
        // Legacy single file (empty index).
        assert_eq!(parse_chunk_index(Path::new("validation_reports.json")), None);
        // Zero index.
        assert_eq!(parse_chunk_index(Path::new("validation_reports0.json")), None);
        // Leading zero.
        assert_eq!(parse_chunk_index(Path::new("validation_reports01.json")), None);
        // Non-numeric suffix.
        assert_eq!(parse_chunk_index(Path::new("validation_reportsX.json")), None);
        // Wrong extension.
        assert_eq!(parse_chunk_index(Path::new("validation_reports1.txt")), None);
        // Wrong prefix.
        assert_eq!(parse_chunk_index(Path::new("other_reports1.json")), None);
    }

    #[test]
    fn discover_snapshot_chunks_finds_real_chunks() {
        let chunks = discover_snapshot_chunks().expect("discover real snapshot chunks");
        assert!(!chunks.is_empty());
        for (i, (index, _)) in chunks.iter().enumerate() {
            assert_eq!(*index, i + 1, "chunk indices must be 1-based and contiguous");
        }
    }

    #[test]
    fn load_merged_snapshots_loads_real_chunks() {
        let merged = load_merged_snapshots().expect("load real snapshot chunks");
        assert!(merged.len() > 400, "snapshot chunks must contain more than 400 templates, found {}", merged.len());
    }

    #[test]
    fn snapshot_chunks_satisfy_artifact_contract() {
        let chunks = discover_snapshot_chunks().expect("discover snapshot chunks");
        assert!(!chunks.is_empty(), "at least one snapshot chunk must exist");

        let mut previous_last_key: Option<String> = None;

        for (pos, (index, path)) in chunks.iter().enumerate() {
            assert_eq!(*index, pos + 1, "chunk numbering must be contiguous from 1");

            let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read chunk {}: {e}", path.display()));
            let value: Value =
                serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse chunk {}: {e}", path.display()));
            let map = value
                .as_object()
                .unwrap_or_else(|| panic!("chunk {} must be a JSON object", snapshot_chunk_filename(*index)));

            assert!(!map.is_empty(), "chunk {} must be nonempty", snapshot_chunk_filename(*index));
            assert!(
                map.len() <= TEMPLATES_PER_CHUNK,
                "chunk {} has {} entries, exceeds TEMPLATES_PER_CHUNK ({})",
                snapshot_chunk_filename(*index),
                map.len(),
                TEMPLATES_PER_CHUNK
            );

            let is_final = pos == chunks.len() - 1;
            if !is_final {
                assert_eq!(
                    map.len(),
                    TEMPLATES_PER_CHUNK,
                    "non-final chunk {} must have exactly TEMPLATES_PER_CHUNK entries, found {}",
                    snapshot_chunk_filename(*index),
                    map.len()
                );
            }

            let keys: Vec<&String> = map.keys().collect();
            let mut sorted_keys = keys.clone();
            sorted_keys.sort();
            assert_eq!(keys, sorted_keys, "keys in chunk {} must be sorted", snapshot_chunk_filename(*index));

            let first_key = keys.first().expect("nonempty").to_string();
            if let Some(ref prev) = previous_last_key {
                assert!(
                    first_key > *prev,
                    "key ranges must be globally increasing: last key of previous chunk ({prev:?}) >= first key of chunk {} ({first_key:?})",
                    snapshot_chunk_filename(*index)
                );
            }
            previous_last_key = Some(keys.last().expect("nonempty").to_string());
        }
    }
}
