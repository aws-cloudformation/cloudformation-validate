use crate::{SyncStats, rule_source_dir_to_name};
use log::{debug, error, info};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Extension files that must be extracted as data documents for engine rules
/// (CEL/Rego) to query at runtime. These contain per-region enum data or
/// per-engine/version compatibility data that the engines use for resolved-value
/// checks beyond what the schema-validator handles for literal values.
///
/// All other extension files flow into extensions.json as schema patches.
const DATA_DOC_STEMS: &[&str] = &[
    // Per-region instance type / node type / instance class enums
    "cachenodetype_enum",
    "dbclusterinstanceclass_enum",
    "dbinstanceclass_enum",
    "ec2instancetype_enum",
    "instancetype_enum",
    "instancetypeconfig_instancetype_enum",
    "nodeconfiguration_instancetype_enum",
    "nodetype_enum",
    // Per-engine/version compatibility data
    "db_instance_class",
];

fn is_data_document(file_stem: &str) -> bool {
    DATA_DOC_STEMS.iter().any(|s| file_stem.ends_with(s))
}

pub fn sync_extensions(
    rule_source_dir: &Path,
    ext_output_dir: &Path,
    data_output_dir: &Path,
) -> anyhow::Result<SyncStats> {
    let mut stats = SyncStats::default();
    let ext_src = rule_source_dir.join("src/cfnlint/data/schemas/extensions");

    if !ext_src.exists() {
        anyhow::bail!(
            "Rule-source extensions not found at: {}\nExpected: <rule-source-root>/src/cfnlint/data/schemas/extensions/",
            ext_src.display()
        );
    }

    info!(
        "Syncing extensions: source={} extensions={} data={}",
        ext_src.display(),
        ext_output_dir.display(),
        data_output_dir.display(),
    );

    fs::create_dir_all(ext_output_dir)?;
    fs::create_dir_all(data_output_dir)?;

    let mut removed = 0;
    if let Ok(entries) = fs::read_dir(ext_output_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            if entry.file_name().to_string_lossy().ends_with(".ext.json") {
                let _ = fs::remove_file(entry.path());
                removed += 1;
            }
        }
    }
    if removed > 0 {
        debug!("Cleaned {} existing extension files", removed);
    }

    let mut type_dirs: Vec<_> = fs::read_dir(&ext_src)?.filter_map(|e| e.ok()).filter(|e| e.path().is_dir()).collect();
    type_dirs.sort_by_key(|e| e.file_name());
    info!("Found {} resource type directories", type_dirs.len());

    let mut codegen_fragments: HashMap<String, Vec<serde_json::Value>> = HashMap::new();
    let mut data_doc_count = 0;

    for entry in type_dirs {
        let dir_name = entry.file_name().to_string_lossy().to_string();
        let out_name = rule_source_dir_to_name(&dir_name);

        let mut json_files: Vec<_> = fs::read_dir(entry.path())?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
            .collect();
        json_files.sort_by_key(|e| e.file_name());

        for file_entry in json_files {
            let path = file_entry.path();
            let file_stem = path.file_stem().unwrap().to_string_lossy().to_string();

            if is_data_document(&file_stem) {
                debug!("Extracting enum extension {}/{} as data document", dir_name, file_stem);
                match extract_and_write_data_doc(&path, &out_name, &file_stem, data_output_dir) {
                    Ok(()) => {
                        stats.files_written += 1;
                        data_doc_count += 1;
                    }
                    Err(e) => {
                        error!("Failed to extract data doc {}/{}: {}", dir_name, file_stem, e);
                        stats.errors.push(format!("{}:{}: {}", dir_name, file_stem, e));
                    }
                }
            } else {
                match fs::read_to_string(&path) {
                    Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
                        Ok(fragment) => {
                            codegen_fragments.entry(out_name.clone()).or_default().push(fragment);
                        }
                        Err(e) => {
                            error!("Failed to parse extension {}/{}: {}", dir_name, file_stem, e);
                            stats.errors.push(format!("{}:{}: parse error: {}", dir_name, file_stem, e));
                        }
                    },
                    Err(e) => {
                        error!("Failed to read extension {}/{}: {}", dir_name, file_stem, e);
                        stats.errors.push(format!("{}:{}: read error: {}", dir_name, file_stem, e));
                    }
                }
            }
        }
    }

    let mut names: Vec<_> = codegen_fragments.keys().cloned().collect();
    names.sort();
    for name in names {
        let fragments = codegen_fragments.remove(&name).unwrap();
        if fragments.is_empty() {
            continue;
        }
        let out_file = ext_output_dir.join(format!("{}.ext.json", name));
        debug!(
            "Writing codegen extension {} ({} fragments) -> {}",
            name,
            fragments.len(),
            out_file.file_name().unwrap().to_string_lossy()
        );
        fs::write(&out_file, serde_json::to_string_pretty(&fragments)?)?;
        stats.files_written += 1;
    }

    info!("Extensions complete: {} codegen, {} data documents", stats.files_written - data_doc_count, data_doc_count);
    Ok(stats)
}

fn extract_and_write_data_doc(
    path: &Path,
    out_name: &str,
    file_stem: &str,
    data_output_dir: &Path,
) -> anyhow::Result<()> {
    let content = fs::read_to_string(path)?;
    let val: serde_json::Value = serde_json::from_str(&content)?;
    let data = extract_enum_data(&val)?;

    let data_key = format!("{}_{}", out_name.replace('-', "_"), file_stem);
    let data_file = data_output_dir.join(format!("{}.json", data_key));
    let wrapped = serde_json::json!({ &data_key: data });
    fs::write(&data_file, serde_json::to_string_pretty(&wrapped)?)?;
    debug!("Wrote data document: {}", data_file.file_name().unwrap().to_string_lossy());
    Ok(())
}

fn extract_enum_data(val: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let mut region_data: HashMap<String, Vec<String>> = HashMap::new();
    extract_if_then_enums(val, &mut region_data);
    if region_data.is_empty() {
        return Ok(val.clone());
    }
    let mut result = serde_json::Map::new();
    let mut regions: Vec<_> = region_data.keys().cloned().collect();
    regions.sort();
    for region in regions {
        let mut vals = region_data.remove(&region).unwrap();
        vals.sort();
        vals.dedup();
        result.insert(region, serde_json::json!(vals));
    }
    Ok(serde_json::Value::Object(result))
}

fn extract_if_then_enums(val: &serde_json::Value, out: &mut HashMap<String, Vec<String>>) {
    if let Some(all_of) = val.get("allOf").and_then(|v| v.as_array()) {
        for item in all_of {
            extract_if_then_enums(item, out);
        }
    }
    if let (Some(if_clause), Some(then_clause)) = (val.get("if"), val.get("then")) {
        if let Some(region) = extract_region_from_if(if_clause) {
            let enums = extract_enums_from_value(then_clause);
            if !enums.is_empty() {
                out.entry(region).or_default().extend(enums);
            }
        }
        if let Some(else_clause) = val.get("else") {
            extract_if_then_enums(else_clause, out);
        }
    }
}

fn extract_region_from_if(if_clause: &serde_json::Value) -> Option<String> {
    // The "cfn-lint" key is part of the upstream JSON schema format for region conditions
    if let Some(region_condition) = if_clause.get("cfn-lint") {
        if let Some(regions) = region_condition.get("region").and_then(|v| v.as_array()) {
            if regions.len() == 1 {
                return regions[0].as_str().map(|s| s.to_string());
            }
        }
    }
    if let Some(funcs) = if_clause.get("functions") {
        if let Some(eq) = funcs.get("equals").and_then(|v| v.as_array()) {
            if eq.len() == 2 {
                let has_ref = eq.iter().any(|v| {
                    v.get("ref").and_then(|r| r.as_str()) == Some("AWS::Region")
                        || v.get("Ref").and_then(|r| r.as_str()) == Some("AWS::Region")
                });
                if has_ref {
                    for item in eq {
                        if let Some(s) = item.as_str() {
                            return Some(s.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

fn extract_enums_from_value(val: &serde_json::Value) -> Vec<String> {
    let mut result = Vec::new();
    collect_enum_values(val, &mut result);
    result
}

fn collect_enum_values(val: &serde_json::Value, out: &mut Vec<String>) {
    match val {
        serde_json::Value::Object(map) => {
            if let Some(arr) = map.get("enum").and_then(|v| v.as_array()) {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        out.push(s.to_string());
                    }
                }
            }
            for v in map.values() {
                collect_enum_values(v, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_enum_values(item, out);
            }
        }
        _ => {}
    }
}
