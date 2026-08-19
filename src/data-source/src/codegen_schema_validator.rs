use crate::compiled_schema::{CompiledSchema, RefSiblings, compile_schema_with};
use crate::types::GetattData;
use log::info;
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Generate compiled schemas from data-source/generated/ into generated/schema-validator/.
pub fn generate(generated_dir: &Path, upstream_dir: &Path) -> anyhow::Result<()> {
    let schema_dir = generated_dir.join("patched_schemas");
    let output_dir = generated_dir.join("schema-validator");

    anyhow::ensure!(
        schema_dir.exists(),
        "Patched schema directory not found: {}\nRun data-source generate first.",
        schema_dir.display()
    );
    fs::create_dir_all(&output_dir)?;

    let mut raw: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for entry in fs::read_dir(&schema_dir)?.flatten() {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        // These are schemas this pipeline just wrote to patched_schemas/, so a
        // read/parse failure or missing typeName is corruption - fail loudly.
        let content = fs::read_to_string(&p).map_err(|e| anyhow::anyhow!("failed to read {}: {}", p.display(), e))?;
        let json: serde_json::Value =
            serde_json::from_str(&content).map_err(|e| anyhow::anyhow!("failed to parse {}: {}", p.display(), e))?;
        let Some(tn) = json.get("typeName").and_then(|v| v.as_str()) else {
            anyhow::bail!("patched schema {} has no 'typeName'", p.display());
        };
        raw.insert(tn.to_string(), json);
    }
    anyhow::ensure!(!raw.is_empty(), "no patched schemas found in {}", schema_dir.display());

    let mut compiled: BTreeMap<String, CompiledSchema> = BTreeMap::new();
    for (tn, schema) in &raw {
        // Bundled schemas compile with `$ref` evaluation - keywords
        // beside a reference are ignored, matching what the CloudFormation
        // registry itself enforces. Overlay schemas opt into enforcing them.
        compiled.insert(tn.clone(), compile_schema_with(tn, schema, RefSiblings::Ignore));
    }

    let json_bytes = serde_json::to_string_pretty(&compiled)?;
    fs::write(output_dir.join("compiled_schemas.json"), json_bytes.as_bytes())?;
    info!("Compiled {} schemas ({} bytes) -> compiled_schemas.json", compiled.len(), json_bytes.len());

    generate_ref_types(generated_dir, &raw, &output_dir)?;
    generate_region_enums(generated_dir, &output_dir)?;
    generate_extension_data(upstream_dir, &output_dir)?;

    Ok(())
}

/// Compile Ref return types and GetAtt attribute types into ref_types.json.
/// Uses primaryIdentifier → property type resolution and getatt_attribute_types data.
fn generate_ref_types(
    generated_dir: &Path,
    raw_schemas: &BTreeMap<String, serde_json::Value>,
    output_dir: &Path,
) -> anyhow::Result<()> {
    let mut ref_returns: BTreeMap<String, String> = BTreeMap::new();
    let mut getatt_returns: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();

    for (type_name, schema) in raw_schemas {
        let primary_ids = schema.get("primaryIdentifier").and_then(|v| v.as_array()).unwrap_or(&Vec::new()).clone();
        let read_only: HashSet<String> = schema
            .get("readOnlyProperties")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        if primary_ids.len() != 1
            || primary_ids.iter().any(|p| p.as_str().map(|s| read_only.contains(s)).unwrap_or(false))
        {
            if !primary_ids.is_empty() {
                ref_returns.insert(type_name.clone(), "string".into());
            }
            continue;
        }

        if let Some(path) = primary_ids[0].as_str().and_then(|s| s.strip_prefix("/properties/")) {
            let prop_type = resolve_property_type(schema, path);
            ref_returns.insert(type_name.clone(), prop_type);
        }
    }

    let getatt_path = generated_dir.join("data").join("getatt_attributes.json");
    let content = fs::read_to_string(&getatt_path)
        .map_err(|source| anyhow::anyhow!("failed to read required {}: {}", getatt_path.display(), source))?;
    let getatt_data: GetattData = serde_json::from_str(&content)
        .map_err(|source| anyhow::anyhow!("failed to parse required {}: {}", getatt_path.display(), source))?;
    anyhow::ensure!(
        !getatt_data.getatt_attribute_types.is_empty(),
        "{}: getatt_attribute_types must not be empty",
        getatt_path.display()
    );
    for (type_name, attrs) in getatt_data.getatt_attribute_types {
        anyhow::ensure!(
            !attrs.is_empty(),
            "{}: GetAtt types for '{}' must not be empty",
            getatt_path.display(),
            type_name
        );
        getatt_returns.insert(type_name, attrs.into_iter().collect());
    }

    let format_compatible: BTreeMap<String, Vec<String>> = [
        ("AWS::EC2::VPC.Id", vec!["AWS::EC2::VPC"]),
        ("AWS::EC2::Subnet.Id", vec!["AWS::EC2::Subnet"]),
        ("AWS::EC2::SecurityGroup.Id", vec!["AWS::EC2::SecurityGroup"]),
        ("AWS::EC2::Image.Id", vec![]),
        ("AWS::EC2::KeyPair.KeyName", vec!["AWS::EC2::KeyPair"]),
        ("AWS::EC2::Volume.Id", vec!["AWS::EC2::Volume"]),
        ("AWS::EC2::NetworkInterface.Id", vec!["AWS::EC2::NetworkInterface"]),
        ("AWS::Route53::HostedZone.Id", vec!["AWS::Route53::HostedZone"]),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.into_iter().map(String::from).collect()))
    .collect();

    let ref_types = serde_json::json!({
        "ref_returns": ref_returns,
        "getatt_returns": getatt_returns,
        "format_compatible_types": format_compatible,
    });
    let bytes = serde_json::to_string_pretty(&ref_types)?;
    fs::write(output_dir.join("ref_types.json"), bytes.as_bytes())?;
    info!(
        "Compiled ref types: {} Ref returns, {} GetAtt types -> ref_types.json",
        ref_returns.len(),
        getatt_returns.len()
    );
    Ok(())
}

/// Resolve a property's type from the raw schema by following JSON pointer paths and $ref chains.
fn resolve_property_type(schema: &serde_json::Value, prop_path: &str) -> String {
    let segments: Vec<&str> = prop_path.split('/').collect();
    let mut current = schema.get("properties");
    for seg in &segments {
        current = current.and_then(|v| v.get(*seg));
    }
    let Some(prop) = current else {
        return "string".into();
    };

    if let Some(ref_str) = prop.get("$ref").and_then(|v| v.as_str()) {
        if let Some(def_name) = ref_str.strip_prefix("#/definitions/") {
            if let Some(def) = schema.get("definitions").and_then(|d| d.get(def_name)) {
                return extract_type_string(def);
            }
        }
    }
    extract_type_string(prop)
}

fn extract_type_string(prop: &serde_json::Value) -> String {
    match prop.get("type") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Array(arr)) => {
            arr.iter().filter_map(|v| v.as_str()).find(|s| *s != "null").unwrap_or("string").to_string()
        }
        _ => "string".into(),
    }
}

/// Build region_enums.json from per-region enum data files.
fn generate_region_enums(generated_dir: &Path, output_dir: &Path) -> anyhow::Result<()> {
    let enum_file_mappings: &[(&str, &str, &str)] = &[
        ("aws_ec2_instance_instancetype_enum", "AWS::EC2::Instance", "InstanceType"),
        ("aws_emr_cluster_instancetypeconfig_instancetype_enum", "AWS::EMR::Cluster", "Instances.MasterInstanceType"),
        ("aws_gamelift_fleet_ec2instancetype_enum", "AWS::GameLift::Fleet", "EC2InstanceType"),
    ];

    let mut region_enums: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
    let data_dir = generated_dir.join("data");

    for (file_key, resource_type, prop_name) in enum_file_mappings {
        let path = data_dir.join(format!("{}.json", file_key));
        let content = fs::read_to_string(&path)
            .map_err(|source| anyhow::anyhow!("failed to read required {}: {}", path.display(), source))?;
        let json: serde_json::Value = serde_json::from_str(&content)
            .map_err(|source| anyhow::anyhow!("failed to parse required {}: {}", path.display(), source))?;
        let data = json
            .get(*file_key)
            .and_then(|value| value.as_object())
            .ok_or_else(|| anyhow::anyhow!("{} is missing required '{}' object", path.display(), file_key))?;
        anyhow::ensure!(!data.is_empty(), "{}: '{}' must not be empty", path.display(), file_key);

        let map_key = format!("{}::{}", resource_type, prop_name);
        let mut per_region: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (region, region_data) in data {
            if let Some(enum_vals) = region_data.get("enum").and_then(|v| v.as_array()) {
                let vals: Vec<String> = enum_vals.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                if !vals.is_empty() {
                    per_region.insert(region.clone(), vals);
                }
            }
        }
        if !per_region.is_empty() {
            region_enums.insert(map_key, per_region);
        }
    }

    let bytes = serde_json::to_string_pretty(&region_enums)?;
    fs::write(output_dir.join("region_enums.json"), bytes.as_bytes())?;
    info!("Compiled {} regional enum overrides -> region_enums.json", region_enums.len());
    Ok(())
}

/// Merge all extension files into a single extensions.json keyed by resource type.
fn generate_extension_data(upstream_dir: &Path, output_dir: &Path) -> anyhow::Result<()> {
    let ext_dir = upstream_dir.join("extensions");
    anyhow::ensure!(ext_dir.is_dir(), "Required extensions directory not found: {}", ext_dir.display());
    let mut extensions: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for entry in fs::read_dir(&ext_dir)? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with(".ext.json") {
            continue;
        }
        // Convert filename aws-s3-bucket.ext.json → AWS::S3::Bucket
        let type_name = name
            .trim_end_matches(".ext.json")
            .split('-')
            .map(|seg| {
                let mut c = seg.chars();
                match c.next() {
                    Some(first) => first.to_uppercase().to_string() + c.as_str(),
                    None => String::new(),
                }
            })
            .collect::<Vec<_>>()
            .join("::");
        // Fix: AWS::Ec2::Instance → need proper casing from the actual type names
        // The extension JSON itself doesn't contain the type name, so we use the filename convention.
        let content = fs::read_to_string(&path)
            .map_err(|source| anyhow::anyhow!("failed to read required {}: {}", path.display(), source))?;
        let json = serde_json::from_str::<serde_json::Value>(&content)
            .map_err(|source| anyhow::anyhow!("failed to parse required {}: {}", path.display(), source))?;
        extensions.insert(type_name, json);
    }
    anyhow::ensure!(!extensions.is_empty(), "No extension files found in {}", ext_dir.display());
    let bytes = serde_json::to_string_pretty(&extensions)?;
    fs::write(output_dir.join("extensions.json"), bytes.as_bytes())?;
    info!("Compiled {} resource type extensions -> extensions.json", extensions.len());
    Ok(())
}

/// Read the raw step functions state machine schema from upstream, flatten nested
/// definitions and composition `$ref`s so `compile_schema` can handle it, compile,
/// and write the result to the schema-validator output directory.
pub fn compile_step_functions_schema(upstream_dir: &Path, output_dir: &Path) -> anyhow::Result<()> {
    let raw_path = upstream_dir.join("step_functions_statemachine.json");
    let content = fs::read_to_string(&raw_path)
        .map_err(|source| anyhow::anyhow!("failed to read required {}: {}", raw_path.display(), source))?;
    let mut schema: serde_json::Value = serde_json::from_str(&content)?;

    flatten_sf_schema(&mut schema);

    schema.as_object_mut().unwrap().insert(
        "typeName".into(),
        serde_json::Value::String("AWS::StepFunctions::StateMachine::DefinitionBody".into()),
    );

    let compiled =
        compile_schema_with("AWS::StepFunctions::StateMachine::DefinitionBody", &schema, RefSiblings::Ignore);
    let json = serde_json::to_string_pretty(&compiled)?;
    fs::write(output_dir.join("step_functions_definition_schema.json"), json.as_bytes())?;
    info!("Compiled Step Functions definition schema -> step_functions_definition_schema.json");
    Ok(())
}

/// Flatten the step functions JSON schema in-place so it only uses top-level
/// `#/definitions/<name>` refs that `compile_schema`/`compile_prop` can resolve.
///
/// 1. Hoist nested definitions (e.g. `choice.definitions.X`) to top-level as `choice__X`
/// 2. Create a synthetic `__root` definition for `#/` self-references
/// 3. Merge composition `$ref`s (where a definition has `$ref` + its own properties/allOf)
/// 4. Rewrite all `$ref` pointers to use the flattened names
fn flatten_sf_schema(schema: &mut serde_json::Value) {
    let mut hoisted: Vec<(String, serde_json::Value)> = Vec::new();
    if let Some(defs) = schema.get_mut("definitions").and_then(|v| v.as_object_mut()) {
        for (parent_name, def_val) in defs.iter_mut() {
            if let Some(nested) = def_val.get("definitions").cloned() {
                if let Some(nested_obj) = nested.as_object() {
                    for (child_name, child_val) in nested_obj {
                        hoisted.push((format!("{}__{}", parent_name, child_name), child_val.clone()));
                    }
                }
                def_val.as_object_mut().unwrap().remove("definitions");
            }
        }
        for (name, val) in hoisted {
            defs.insert(name, val);
        }
    }

    let mut root_def = serde_json::Map::new();
    for key in &["properties", "required", "additionalProperties", "type"] {
        if let Some(v) = schema.get(*key) {
            root_def.insert((*key).to_string(), v.clone());
        }
    }
    if let Some(defs) = schema.get_mut("definitions").and_then(|v| v.as_object_mut()) {
        defs.insert("__root".into(), serde_json::Value::Object(root_def));
    }

    let defs_snapshot = schema.get("definitions").cloned().unwrap_or_default();
    if let Some(defs_obj) = defs_snapshot.as_object() {
        if let Some(defs_mut) = schema.get_mut("definitions").and_then(|v| v.as_object_mut()) {
            for (_name, def_val) in defs_mut.iter_mut() {
                let def_obj = match def_val.as_object_mut() {
                    Some(o) => o,
                    None => continue,
                };
                let ref_target = match def_obj.get("$ref").and_then(|v| v.as_str()) {
                    Some(r) => r.to_string(),
                    None => continue,
                };
                // Only merge if this definition has its own content beyond just `$ref`
                if def_obj.len() <= 1 {
                    continue;
                }
                let target_name = match ref_target.strip_prefix("#/definitions/") {
                    Some(n) => n,
                    None => continue,
                };
                let target = match defs_obj.get(target_name) {
                    Some(t) => t.clone(),
                    None => continue,
                };
                def_obj.remove("$ref");
                if let Some(target_all_of) = target.get("allOf").and_then(|v| v.as_array()) {
                    let all_of = def_obj
                        .entry("allOf")
                        .or_insert_with(|| serde_json::Value::Array(Vec::new()))
                        .as_array_mut()
                        .unwrap();
                    for item in target_all_of {
                        all_of.push(item.clone());
                    }
                }
                // Merge properties from the referenced definition (don't overwrite existing)
                if let Some(target_props) = target.get("properties").and_then(|v| v.as_object()) {
                    let props = def_obj
                        .entry("properties")
                        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
                        .as_object_mut()
                        .unwrap();
                    for (k, v) in target_props {
                        if !props.contains_key(k) {
                            props.insert(k.clone(), v.clone());
                        }
                    }
                }
                if let Some(target_req) = target.get("required").and_then(|v| v.as_array()) {
                    let req = def_obj
                        .entry("required")
                        .or_insert_with(|| serde_json::Value::Array(Vec::new()))
                        .as_array_mut()
                        .unwrap();
                    for item in target_req {
                        if !req.contains(item) {
                            req.push(item.clone());
                        }
                    }
                }
            }
        }
    }

    rewrite_refs(schema);
}

/// Recursively rewrite `$ref` values:
/// - `#/definitions/X/definitions/Y` → `#/definitions/X__Y`
/// - `#/` → `#/definitions/__root`
fn rewrite_refs(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(ref_val) = map.get_mut("$ref") {
                if let Some(s) = ref_val.as_str().map(String::from) {
                    if s == "#/" {
                        *ref_val = serde_json::Value::String("#/definitions/__root".into());
                    } else if let Some(rest) = s.strip_prefix("#/definitions/") {
                        if rest.contains("/definitions/") {
                            // e.g. "choice/definitions/Operator" → "choice__Operator"
                            let mangled = rest.replace("/definitions/", "__");
                            *ref_val = serde_json::Value::String(format!("#/definitions/{}", mangled));
                        }
                    }
                }
            }
            for (_, v) in map.iter_mut() {
                rewrite_refs(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                rewrite_refs(v);
            }
        }
        _ => {}
    }
}
