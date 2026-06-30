use crate::SyncStats;
use log::{debug, info};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

/// Enhanced CloudFormation provider schemas, the same artifact cfn-lint consumes.
/// The archive is fully assembled: every provider/extension patch is already
/// applied to each resource schema, so no separate patch pass is needed. It is
/// laid out as `providers/{region}.json` (resource-type → content hash) plus
/// `resources/{hash}.json` (the schema bodies).
const CFN_SCHEMA_ZIP_URL: &str = "https://github.com/aws-cloudformation/resource-provider-enhanced-schemas/releases/download/latest/schemas-cfn-lint.zip";
const SAM_SCHEMA_URL: &str = "https://raw.githubusercontent.com/aws/serverless-application-model/refs/heads/develop/samtranslator/schema/schema.json";

/// Download and assemble CloudFormation schemas into `upstream_dir`.
///
/// Writes one schema file per resource type to `upstream/schemas/` (keyed by
/// type name, preferring the us-east-1 variant when a type appears in multiple
/// regions) and the per-region type→hash maps to `upstream/providers/`, then
/// appends the region-independent SAM resource schemas.
pub fn download_schemas(upstream_dir: &Path) -> anyhow::Result<SyncStats> {
    let mut stats = SyncStats::default();
    let schemas_out = schema_dir(upstream_dir);
    let providers_out = providers_dir(upstream_dir);
    fs::create_dir_all(&schemas_out)?;
    fs::create_dir_all(&providers_out)?;

    info!("Downloading enhanced schemas from {}", CFN_SCHEMA_ZIP_URL);
    let resp = ureq::get(CFN_SCHEMA_ZIP_URL).call()?;
    let bytes = resp.into_body().read_to_vec()?;
    info!("Downloaded {} bytes, reading archive", bytes.len());

    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;

    // Pass 1: read every provider map (region → {type_name: content_hash}) and
    // persist it for the region-resource-type sync. Build a single type→hash map,
    // preferring us-east-1 so multi-region types resolve deterministically.
    // `providers/sam.json` is the region-independent SAM type→hash pointer, not a
    // region map. SAM resource schemas are sourced from the SAM model below
    // (download_sam_schemas), so exclude it from both the region maps and the
    // type→hash set the resource schemas are written from.
    let mut region_files: Vec<String> = archive
        .file_names()
        .filter(|n| n.starts_with("providers/") && n.ends_with(".json") && *n != "providers/sam.json")
        .map(String::from)
        .collect();
    // Read us-east-1 first so its hash wins for any type present in several regions.
    region_files.sort_by_key(|n| (!n.ends_with("/us-east-1.json"), n.clone()));

    let mut type_to_hash: BTreeMap<String, String> = BTreeMap::new();
    for name in &region_files {
        let mut entry = archive.by_name(name)?;
        let map: BTreeMap<String, String> = serde_json::from_reader(&mut entry)?;
        drop(entry);
        for (type_name, hash) in &map {
            type_to_hash.entry(type_name.clone()).or_insert_with(|| hash.clone());
        }
        let region = Path::new(name).file_name().and_then(|f| f.to_str()).unwrap_or(name);
        fs::write(providers_out.join(region), serde_json::to_string_pretty(&map)?)?;
    }
    info!("Read {} region provider maps, {} distinct resource types", region_files.len(), type_to_hash.len());

    // Pass 2: write one schema file per resource type, looked up by content hash.
    // A provider map that references a hash absent from the archive is a corrupt
    // or truncated download — fail rather than silently dropping the type.
    for (type_name, hash) in &type_to_hash {
        let resource_path = format!("resources/{hash}.json");
        let mut entry = archive.by_name(&resource_path).map_err(|e| {
            anyhow::anyhow!("provider maps reference {} but {} is absent: {}", type_name, resource_path, e)
        })?;
        let schema: Value = serde_json::from_reader(&mut entry)
            .map_err(|e| anyhow::anyhow!("failed to parse {} for {}: {}", resource_path, type_name, e))?;
        drop(entry);
        let filename = type_name.replace("::", "-").to_lowercase();
        fs::write(schemas_out.join(format!("{filename}.json")), serde_json::to_string_pretty(&schema)?)?;
        stats.files_written += 1;
    }
    info!("Wrote {} resource type schemas to {}", stats.files_written, schemas_out.display());

    let sam_count = download_sam_schemas(&schemas_out)?;
    stats.files_written += sam_count;
    info!("Wrote {} SAM resource type schemas", sam_count);

    Ok(stats)
}

fn download_sam_schemas(output_dir: &Path) -> anyhow::Result<usize> {
    info!("Downloading SAM schema from {}", SAM_SCHEMA_URL);
    let resp = ureq::get(SAM_SCHEMA_URL).call()?;
    let body = resp.into_body().read_to_vec()?;
    let schema: Value = serde_json::from_slice(&body)?;
    let defs = schema
        .get("definitions")
        .and_then(|d| d.as_object())
        .ok_or_else(|| anyhow::anyhow!("SAM schema missing 'definitions'"))?;

    let mut count = 0;
    for (def_name, def_val) in defs {
        if !def_name.ends_with("__Resource") {
            continue;
        }
        let Some(props) = def_val.get("properties") else {
            continue;
        };
        let type_name = props.get("Type").and_then(|t| {
            t.get("enum")
                .and_then(|e| e.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .or_else(|| t.get("const").and_then(|c| c.as_str()))
        });
        let Some(type_name) = type_name else { continue };
        if !type_name.starts_with("AWS::Serverless::") {
            continue;
        }

        let props_schema = props
            .get("Properties")
            .and_then(|p| p.get("$ref"))
            .and_then(|r| r.as_str())
            .and_then(|r| r.strip_prefix("#/definitions/"))
            .and_then(|name| defs.get(name));
        let Some(props_schema) = props_schema else {
            continue;
        };

        let mut local_defs = Map::new();
        let resolved_props = props_schema.get("properties").cloned().unwrap_or(Value::Object(Map::new()));
        collect_referenced_defs(&resolved_props, defs, &mut local_defs, &mut HashSet::new());

        let mut cfn_schema = serde_json::json!({
            "typeName": type_name,
            "properties": resolved_props,
            "additionalProperties": props_schema.get("additionalProperties").cloned()
                .unwrap_or(Value::Bool(true)),
        });
        if let Some(req) = props_schema.get("required") {
            cfn_schema["required"] = req.clone();
        }
        if !local_defs.is_empty() {
            cfn_schema["definitions"] = Value::Object(local_defs);
        }

        let filename = type_name.replace("::", "-").to_lowercase();
        let out_path = output_dir.join(format!("{}.json", filename));
        fs::write(&out_path, serde_json::to_string_pretty(&cfn_schema)?)?;
        debug!("SAM: {} -> {}", type_name, out_path.file_name().unwrap().to_string_lossy());
        count += 1;
    }
    Ok(count)
}

fn collect_referenced_defs(
    val: &Value,
    all_defs: &Map<String, Value>,
    local_defs: &mut Map<String, Value>,
    visited: &mut HashSet<String>,
) {
    match val {
        Value::Object(map) => {
            if let Some(ref_str) = map.get("$ref").and_then(|r| r.as_str()) {
                if let Some(name) = ref_str.strip_prefix("#/definitions/") {
                    if !visited.contains(name) {
                        visited.insert(name.to_string());
                        if let Some(def) = all_defs.get(name) {
                            local_defs.insert(name.to_string(), def.clone());
                            collect_referenced_defs(def, all_defs, local_defs, visited);
                        }
                    }
                }
            }
            for (_, v) in map {
                collect_referenced_defs(v, all_defs, local_defs, visited);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                collect_referenced_defs(v, all_defs, local_defs, visited);
            }
        }
        _ => {}
    }
}

/// Schema directory path within the upstream output.
pub(crate) fn schema_dir(upstream_dir: &Path) -> PathBuf {
    upstream_dir.join("schemas")
}

/// Per-region provider-map directory within the upstream output.
pub(crate) fn providers_dir(upstream_dir: &Path) -> PathBuf {
    upstream_dir.join("providers")
}
