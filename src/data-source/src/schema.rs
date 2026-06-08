use crate::SyncStats;
use log::{debug, info};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

const CFN_SCHEMA_ZIP_URL: &str =
    "https://schema.cloudformation.us-east-1.amazonaws.com/CloudformationSchema.zip";
const SAM_SCHEMA_URL: &str = "https://raw.githubusercontent.com/aws/serverless-application-model/refs/heads/develop/samtranslator/schema/schema.json";

/// Download CloudFormation schemas into `output_dir`.
pub fn download_schemas(output_dir: &Path) -> anyhow::Result<SyncStats> {
    let mut stats = SyncStats::default();
    fs::create_dir_all(output_dir)?;

    info!(
        "Downloading schemas from {} to {}",
        CFN_SCHEMA_ZIP_URL,
        output_dir.display()
    );
    let resp = ureq::get(CFN_SCHEMA_ZIP_URL).call()?;
    let bytes = resp.into_body().read_to_vec()?;
    info!("Downloaded {} bytes, extracting", bytes.len());

    let cursor = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor)?;
    let file_count = archive.len();
    archive.extract(output_dir)?;
    stats.files_written = file_count;
    info!("Extracted {} schema files", file_count);

    let sam_count = download_sam_schemas(output_dir)?;
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
        let resolved_props = props_schema
            .get("properties")
            .cloned()
            .unwrap_or(Value::Object(Map::new()));
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
        debug!(
            "SAM: {} -> {}",
            type_name,
            out_path.file_name().unwrap().to_string_lossy()
        );
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
