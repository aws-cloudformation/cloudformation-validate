use crate::SyncStats;
use crate::source_versions::CFN_LINT_SOURCE;
use log::info;
use std::path::Path;
use std::process::Command;

/// Data files emitted by the cfn-lint table extractor. These originate as Python
/// dicts inside cfn-lint rule code, so a Python helper imports cfn-lint and
/// writes them as JSON rather than us re-parsing Python or hand-copying values.
const EXTRACTED_FILES: &[&str] =
    &["getatt_additions.json", "retention_period_requirements.json", "codepipeline_action_artifact_counts.json"];

/// Read the version exported by the exact cfn-lint checkout used for extraction.
fn extract_cfn_lint_version(rule_source_dir: &Path) -> anyhow::Result<String> {
    let source_dir = rule_source_dir.join("src");
    anyhow::ensure!(source_dir.is_dir(), "cfn-lint source directory not found at {}", source_dir.display());

    let output = Command::new("python3")
        .arg("-c")
        .arg("import sys; sys.path.insert(0, sys.argv[1]); from cfnlint.version import __version__; print(__version__)")
        .arg(&source_dir)
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "failed to read cfn-lint version ({}):\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    parse_cfn_lint_version(&output.stdout)
}

fn parse_cfn_lint_version(stdout: &[u8]) -> anyhow::Result<String> {
    let output = std::str::from_utf8(stdout)?;
    let version = output.trim();
    anyhow::ensure!(!version.is_empty(), "cfn-lint version output was blank");
    anyhow::ensure!(version.split_whitespace().count() == 1, "cfn-lint version output contained multiple values");
    Ok(format!("{CFN_LINT_SOURCE}@{version}"))
}

/// Run `scripts/sync_cfnlint_data.py` to extract data tables embedded in
/// cfn-lint's Python rule code into `data_output_dir`.
pub fn sync_cfnlint_tables(rule_source_dir: &Path, data_output_dir: &Path) -> anyhow::Result<(SyncStats, String)> {
    let mut stats = SyncStats::default();
    let cfn_lint_version = extract_cfn_lint_version(rule_source_dir)?;

    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = manifest.join("scripts").join("sync_cfnlint_data.py");
    anyhow::ensure!(script.exists(), "cfn-lint table extractor not found at {}", script.display());

    info!("Extracting cfn-lint data tables via {}", script.display());
    let output = Command::new("python3")
        .arg(&script)
        .arg("--cfn-lint-root")
        .arg(rule_source_dir)
        .arg("--out")
        .arg(data_output_dir)
        .output()?;

    if !output.status.success() {
        anyhow::bail!(
            "cfn-lint table extractor failed ({}):\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    // The extractor logs per-type skips to stderr; surface them at info level.
    let stderr = String::from_utf8_lossy(&output.stderr);
    for line in stderr.lines().filter(|l| !l.trim().is_empty()) {
        info!("  cfnlint-tables: {}", line.trim());
    }

    for file in EXTRACTED_FILES {
        let path = data_output_dir.join(file);
        anyhow::ensure!(path.exists(), "extractor did not produce expected file: {}", path.display());
        stats.files_written += 1;
    }

    info!("Extracted {} cfn-lint data tables", stats.files_written);
    Ok((stats, cfn_lint_version))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cfn_lint_version_parses_single_value() {
        assert_eq!(
            parse_cfn_lint_version(b"1.54.0\n").expect("version should parse"),
            "https://github.com/aws-cloudformation/cfn-lint@1.54.0"
        );
    }

    #[test]
    fn cfn_lint_version_rejects_blank_output() {
        assert!(parse_cfn_lint_version(b" \n").is_err());
    }

    #[test]
    fn cfn_lint_version_rejects_multiple_values() {
        let error = parse_cfn_lint_version(b"1.54.0\nunexpected\n").expect_err("multiple values must fail");
        assert!(error.to_string().contains("multiple values"));
    }

    #[test]
    fn cfn_lint_version_rejects_non_utf8_output() {
        assert!(parse_cfn_lint_version(&[0xff]).is_err());
    }
}
