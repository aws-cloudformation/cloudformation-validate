use crate::SyncStats;
use log::info;
use std::path::Path;
use std::process::Command;

/// Data files emitted by the cfn-lint table extractor. These originate as Python
/// dicts inside cfn-lint rule code, so a Python helper imports cfn-lint and
/// writes them as JSON rather than us re-parsing Python or hand-copying values.
const EXTRACTED_FILES: &[&str] =
    &["getatt_additions.json", "retention_period_requirements.json", "codepipeline_action_artifact_counts.json"];

/// Run `scripts/sync_cfnlint_data.py` to extract data tables embedded in
/// cfn-lint's Python rule code into `data_output_dir`.
pub fn sync_cfnlint_tables(rule_source_dir: &Path, data_output_dir: &Path) -> anyhow::Result<SyncStats> {
    let mut stats = SyncStats::default();

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
    Ok(stats)
}
