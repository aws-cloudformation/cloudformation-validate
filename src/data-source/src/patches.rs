use crate::{SyncStats, rule_source_dir_to_name};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Each resource type maps to a Vec of file-groups.
/// Each file-group is a Vec<Value> (one source file's patch ops).
type PatchGroups = HashMap<String, Vec<Vec<serde_json::Value>>>;

pub fn sync_patches(rule_source_dir: &Path, output_dir: &Path) -> anyhow::Result<SyncStats> {
    let mut stats = SyncStats::default();

    let providers_src = rule_source_dir.join("src/cfnlint/data/schemas/patches/providers/all");
    let extensions_src = rule_source_dir.join("src/cfnlint/data/schemas/patches/extensions/all");

    if !providers_src.exists() {
        anyhow::bail!(
            "Rule-source patches not found at: {}\nExpected: <rule-source-root>/src/cfnlint/data/schemas/patches/providers/all/",
            providers_src.display()
        );
    }

    info!(
        "Syncing patches: providers={} extensions={} output={}",
        providers_src.display(),
        extensions_src.display(),
        output_dir.display()
    );
    fs::create_dir_all(output_dir)?;

    let mut removed = 0;
    if let Ok(entries) = fs::read_dir(output_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            if entry.file_name().to_string_lossy().ends_with(".patch.json") {
                let _ = fs::remove_file(entry.path());
                removed += 1;
            }
        }
    }
    if removed > 0 {
        debug!("Cleaned {} existing patch files", removed);
    }

    let mut all_patches: PatchGroups = HashMap::new();

    let provider_count = collect_patches_from_dir(&providers_src, &mut all_patches)?;
    info!("Found {} provider patch directories", provider_count);

    let ext_count = if extensions_src.exists() {
        collect_patches_from_dir(&extensions_src, &mut all_patches)?
    } else {
        warn!("Extension patches directory not found at {}, skipping", extensions_src.display());
        0
    };
    info!("Found {} extension patch directories", ext_count);

    let mut names: Vec<_> = all_patches.keys().cloned().collect();
    names.sort();
    for name in names {
        let groups = all_patches.remove(&name).unwrap();
        if groups.is_empty() {
            stats.files_skipped += 1;
            continue;
        }
        let serialized: Vec<serde_json::Value> =
            groups.into_iter().filter(|g| !g.is_empty()).map(serde_json::Value::Array).collect();
        if serialized.is_empty() {
            stats.files_skipped += 1;
            continue;
        }
        let out_file = output_dir.join(format!("{}.patch.json", name));
        fs::write(&out_file, serde_json::to_string_pretty(&serialized)?)?;
        stats.files_written += 1;
    }

    info!("Wrote {} merged patch files", stats.files_written);
    Ok(stats)
}

fn collect_patches_from_dir(src_dir: &Path, out: &mut PatchGroups) -> anyhow::Result<usize> {
    let mut type_dirs: Vec<_> = fs::read_dir(src_dir)?.filter_map(|e| e.ok()).filter(|e| e.path().is_dir()).collect();
    type_dirs.sort_by_key(|e| e.file_name());
    let count = type_dirs.len();

    for entry in type_dirs {
        let dir_name = entry.file_name().to_string_lossy().to_string();
        let out_name = rule_source_dir_to_name(&dir_name);
        match collect_patch_files(&entry.path()) {
            Ok(file_groups) => {
                out.entry(out_name).or_default().extend(file_groups);
            }
            Err(e) => {
                error!("Failed to merge patches for {}: {}", dir_name, e);
            }
        }
    }
    Ok(count)
}

/// Collect patches from a directory, keeping each file as a separate group.
/// Manual files are collected last so they override smithy/format patches.
fn collect_patch_files(dir: &Path) -> anyhow::Result<Vec<Vec<serde_json::Value>>> {
    let mut regular_groups = Vec::new();
    let mut manual_groups = Vec::new();
    let mut files: Vec<_> = fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
        .collect();
    files.sort_by_key(|e| e.file_name());

    for entry in files {
        let is_manual = entry.file_name().to_string_lossy().starts_with("manual");
        let content = fs::read_to_string(entry.path())?;
        let val: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                warn!("Skipping malformed patch file {}: {}", entry.path().file_name().unwrap().to_string_lossy(), e);
                continue;
            }
        };
        let ops = match val {
            serde_json::Value::Array(arr) => arr,
            obj @ serde_json::Value::Object(_) => vec![obj],
            _ => continue,
        };
        if ops.is_empty() {
            continue;
        }
        if is_manual {
            manual_groups.push(ops);
        } else {
            regular_groups.push(ops);
        }
    }
    regular_groups.extend(manual_groups);
    Ok(regular_groups)
}
