use crate::process::SchemaTop;
use log::{info, warn};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub fn generate(generated_dir: &Path, handwritten_dir: &Path) -> anyhow::Result<()> {
    let schema_source = generated_dir.join("patched_schemas");
    if !schema_source.exists() {
        anyhow::bail!(
            "Patched schema directory not found: {}\nRun process step first.",
            schema_source.display()
        );
    }

    let rules_dir = generated_dir.join("cel-rules");
    fs::create_dir_all(&rules_dir)?;
    info!(
        "CEL codegen: schemas={} rules={}",
        schema_source.display(),
        rules_dir.display()
    );

    let mut raw_schemas: HashMap<String, serde_json::Value> = HashMap::new();
    for entry in fs::read_dir(&schema_source)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let content = fs::read_to_string(&path)?;
        let json: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(type_name) = json.get("typeName").and_then(|v| v.as_str()) else {
            continue;
        };
        raw_schemas.insert(type_name.to_string(), json);
    }
    info!("Loaded {} patched schemas", raw_schemas.len());

    let mut schemas: HashMap<String, SchemaTop> = HashMap::new();
    let mut skipped = 0;
    for (tn, json) in &raw_schemas {
        let schema: SchemaTop = serde_json::from_value(json.clone()).unwrap_or_default();
        if schema.type_name.is_none() {
            skipped += 1;
            continue;
        }
        schemas.insert(tn.clone(), schema);
    }
    if skipped > 0 {
        warn!("Skipped {} schemas with no typeName", skipped);
    }
    info!("Parsed {} schemas for CEL codegen", schemas.len());

    let ds_data = generated_dir.join("data");
    let all_rules = generate_data_driven_rules(&ds_data, handwritten_dir);

    let rules_json = json!({ "rules": all_rules });
    fs::write(
        rules_dir.join("generated_rules.json"),
        serde_json::to_string_pretty(&rules_json)?,
    )?;
    info!("Generated {} CEL rules total", all_rules.len());

    Ok(())
}

fn generate_data_driven_rules(
    _generated_dir: &Path,
    _handwritten_dir: &Path,
) -> Vec<serde_json::Value> {
    // Deprecated resource types are handled by the native Rust rule
    // eval_deprecated_resource_types() in cel-engine/src/rules/best_practices.rs.
    // No data-driven CEL rules are currently needed.
    let rules = Vec::new();
    info!("Generated {} data-driven best practice rules", rules.len());
    rules
}
