//! Test-fixture crate for `cloudformation-validate`.
//!
//! The template corpus, rule fixtures, security fixtures, and the golden
//! `expected/validation_reports.json` all live on disk under this crate's root. This
//! library exposes their locations and separate discovery APIs for the regular
//! template corpus and snapshot generation.

use std::path::{Path, PathBuf};

/// Template subdirectories (relative to [`templates_dir`]) included in the regular
/// snapshot corpus, in the order they are scanned. The discovered set is sorted
/// afterwards, so this order only bounds *which* directories are walked.
pub const GOLDEN_DIRS: &[&str] =
    &["bad", "cdk", "good", "gh-issues", "integration", "issues", "lsp", "public", "quickstart"];

/// Root of this crate - the directory holding `templates/`, `rules/`, `security/`,
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

/// Path to the golden report file produced by the `generate_validation_reports` example.
pub fn validation_reports_file() -> PathBuf {
    expected_dir().join("validation_reports.json")
}

/// Discover every regular template under [`GOLDEN_DIRS`], returned as sorted,
/// forward-slash paths relative to [`templates_dir`].
pub fn discover_templates() -> Vec<String> {
    let root = templates_dir();
    let mut templates = Vec::new();
    for subdir in GOLDEN_DIRS {
        let dir = root.join(subdir);
        if dir.is_dir() {
            collect_templates(&dir, &root, &mut templates);
        }
    }
    templates.sort();
    templates
}

/// Discover every fixture persisted by snapshot generation.
///
/// Regular template keys remain relative to [`templates_dir`]. Security fixture
/// keys retain their `security/` prefix so all snapshot keys are unambiguous.
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
