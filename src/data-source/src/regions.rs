use crate::SyncStats;
use log::{debug, error, info};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Build `region_resource_types.json` from the per-region provider maps written
/// by the schema download (`upstream/providers/{region}.json`). Each provider
/// map is `{ resource_type: content_hash }`; we only need the set of type names
/// valid in each region, so the hashes are discarded here.
pub fn sync_regions(providers_dir: &Path, data_output_dir: &Path) -> anyhow::Result<SyncStats> {
    let mut stats = SyncStats::default();

    if !providers_dir.exists() {
        anyhow::bail!("Provider maps not found at: {}\nRun the schema download first.", providers_dir.display());
    }

    info!("Syncing regions: source={} output={}", providers_dir.display(), data_output_dir.display());
    fs::create_dir_all(data_output_dir)?;

    let mut region_map: HashMap<String, serde_json::Map<String, serde_json::Value>> = HashMap::new();

    let mut files: Vec<_> = fs::read_dir(providers_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let p = e.path();
            if !p.is_file() || p.extension().and_then(|x| x.to_str()) != Some("json") {
                return false;
            }
            // `sam.json` is the region-independent SAM type→hash pointer, not a
            // region. SAM types are added globally elsewhere, so skip it here to
            // avoid inventing a bogus "sam" region.
            p.file_stem().and_then(|s| s.to_str()) != Some("sam")
        })
        .collect();
    files.sort_by_key(|e| e.file_name());
    info!("Found {} provider files", files.len());

    for entry in files {
        let path = entry.path();
        let region = path.file_stem().unwrap().to_string_lossy().to_string();

        let types = match parse_provider_map(&path) {
            Ok(t) => t,
            Err(e) => {
                error!("Failed to parse provider file {}: {}", region, e);
                stats.errors.push(format!("{}: {}", region, e));
                continue;
            }
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
        sorted_map.insert(region.clone(), serde_json::Value::Object(region_map.remove(&region).unwrap()));
    }
    let output = serde_json::json!({ "region_resource_types": sorted_map });
    fs::write(&out_file, serde_json::to_string_pretty(&output)?)?;
    info!("Wrote {}", out_file.display());

    Ok(stats)
}

/// Parse a `{ resource_type: content_hash }` provider map, returning the sorted
/// list of CloudFormation/Alexa resource type names it contains.
fn parse_provider_map(path: &Path) -> anyhow::Result<Vec<String>> {
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
