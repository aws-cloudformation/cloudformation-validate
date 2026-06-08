use crate::SyncStats;
use log::{debug, error, info};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub fn sync_regions(rule_source_dir: &Path, data_output_dir: &Path) -> anyhow::Result<SyncStats> {
    let mut stats = SyncStats::default();
    let providers_dir = rule_source_dir.join("src/cfnlint/data/schemas/providers");

    if !providers_dir.exists() {
        anyhow::bail!(
            "Rule-source providers not found at: {}\nExpected: <rule-source-root>/src/cfnlint/data/schemas/providers/",
            providers_dir.display()
        );
    }

    info!(
        "Syncing regions: source={} output={}",
        providers_dir.display(),
        data_output_dir.display()
    );
    fs::create_dir_all(data_output_dir)?;

    let mut region_map: HashMap<String, serde_json::Map<String, serde_json::Value>> =
        HashMap::new();

    let mut files: Vec<_> = fs::read_dir(&providers_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let p = e.path();
            if !p.is_file() {
                return false;
            }
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if name == "__init__.py" {
                return false;
            }
            let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
            ext == "py" || ext == "json"
        })
        .collect();
    files.sort_by_key(|e| e.file_name());
    info!("Found {} provider files", files.len());

    for entry in files {
        let path = entry.path();
        let file_stem = path.file_stem().unwrap().to_string_lossy().to_string();
        let region = file_stem.replace('_', "-");
        let ext = path.extension().and_then(|x| x.to_str()).unwrap_or("");

        let types = match ext {
            "py" => match parse_provider_py(&path) {
                Ok(t) => t,
                Err(e) => {
                    error!("Failed to parse provider file {}: {}", file_stem, e);
                    stats.errors.push(format!("{}: {}", file_stem, e));
                    continue;
                }
            },
            "json" => match parse_provider_json(&path) {
                Ok(t) => t,
                Err(e) => {
                    error!("Failed to parse provider file {}: {}", file_stem, e);
                    stats.errors.push(format!("{}: {}", file_stem, e));
                    continue;
                }
            },
            _ => continue,
        };

        if types.is_empty() {
            debug!("Skipping region {}: no resource types found", region);
            stats.files_skipped += 1;
            continue;
        }

        debug!("Parsed region {} -> {} resource types", region, types.len());
        let mut type_set = serde_json::Map::new();
        for t in types {
            type_set.insert(t, serde_json::Value::Bool(true));
        }
        region_map.insert(region, type_set);
        stats.files_written += 1;
    }

    let out_file = data_output_dir.join("region_resource_types.json");
    let mut sorted_map = serde_json::Map::new();
    let mut regions: Vec<_> = region_map.keys().cloned().collect();
    regions.sort();
    for region in regions {
        sorted_map.insert(
            region.clone(),
            serde_json::Value::Object(region_map.remove(&region).unwrap()),
        );
    }
    let output = serde_json::json!({ "region_resource_types": sorted_map });
    fs::write(&out_file, serde_json::to_string_pretty(&output)?)?;
    info!("Wrote {}", out_file.display());

    Ok(stats)
}

fn parse_provider_py(path: &Path) -> anyhow::Result<Vec<String>> {
    let content = fs::read_to_string(path)?;
    let mut types = Vec::new();
    let mut in_dict = false;
    for line in content.lines() {
        if line.contains("types: dict[str, str] = {") || line.contains("types: dict[str, str]= {") {
            in_dict = true;
            continue;
        }
        if in_dict {
            let trimmed = line.trim();
            if trimmed == "}" {
                break;
            }
            if let Some(start) = trimmed.find('"') {
                if let Some(end) = trimmed[start + 1..].find('"') {
                    let type_name = &trimmed[start + 1..start + 1 + end];
                    if type_name.starts_with("AWS::") || type_name.starts_with("Alexa::") {
                        types.push(type_name.to_string());
                    }
                }
            }
        }
    }
    types.sort();
    Ok(types)
}

fn parse_provider_json(path: &Path) -> anyhow::Result<Vec<String>> {
    let content = fs::read_to_string(path)?;
    let val: serde_json::Value = serde_json::from_str(&content)?;
    let mut types = Vec::new();
    if let Some(obj) = val.as_object() {
        for key in obj.keys() {
            if key.starts_with("AWS::") || key.starts_with("Alexa::") {
                types.push(key.clone());
            }
        }
    }
    types.sort();
    Ok(types)
}
