use log::info;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

// Mirror types — must match src/compiled.rs
#[derive(Serialize, Deserialize)]
struct CompiledSchema {
    type_name: String,
    #[serde(default)]
    properties: BTreeMap<String, PropSchema>,
    #[serde(default)]
    definitions: BTreeMap<String, PropSchema>,
    #[serde(default)]
    required: Vec<String>,
    #[serde(default)]
    additional_properties: Option<bool>,
    #[serde(default)]
    read_only_properties: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    write_only_properties: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    create_only_properties: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    deprecated_properties: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    conditional_create_only_properties: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    primary_identifier: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replacement_strategy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    documentation_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    all_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    any_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    one_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    if_then_else: Vec<IfThenElse>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    dependent_required: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    dependent_excluded: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    required_or: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    required_xor: Vec<String>,
}

#[derive(Serialize, Deserialize, Default)]
struct IfThenElse {
    condition: ConditionSchema,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    then_schema: Option<SubSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    else_schema: Option<SubSchema>,
}

#[derive(Serialize, Deserialize, Default)]
struct ConditionSchema {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    properties: BTreeMap<String, PropSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    required: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    any_of: Vec<ConditionSchema>,
}

#[derive(Serialize, Deserialize, Default)]
struct PropSchema {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ref_name: Option<String>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    prop_type: Option<PropType>,
    #[serde(default, rename = "enum", skip_serializing_if = "Vec::is_empty")]
    enum_values: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    enum_case_insensitive: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    not_enum: Vec<serde_json::Value>,
    #[serde(default, rename = "const", skip_serializing_if = "Option::is_none")]
    const_value: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    minimum: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    maximum: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exclusive_minimum: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exclusive_maximum: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    min_length: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_length: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    min_items: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_items: Option<u64>,
    #[serde(default, skip_serializing_if = "skip_false")]
    unique_items: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    min_properties: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_properties: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    properties: BTreeMap<String, PropSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    required: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    additional_properties: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pattern_properties: BTreeMap<String, PropSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    items: Option<Box<PropSchema>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    all_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    any_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    one_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    dependent_required: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    dependent_excluded: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    required_or: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    required_xor: Vec<String>,
}
fn skip_false(b: &bool) -> bool {
    !b
}

#[derive(Serialize, Deserialize, Default)]
struct SubSchema {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    required: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    properties: BTreeMap<String, PropSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    additional_properties: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    dependent_required: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    dependent_excluded: BTreeMap<String, Vec<String>>,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum PropType {
    Single(String),
    Multi(Vec<String>),
}

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
        // read/parse failure or missing typeName is corruption — fail loudly.
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
        compiled.insert(tn.clone(), compile_schema(tn, schema));
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
    if getatt_path.exists() {
        if let Ok(content) = fs::read_to_string(&getatt_path) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(types) = json.get("getatt_attribute_types").and_then(|v| v.as_object()) {
                    for (type_name, attrs) in types {
                        if let Some(attr_obj) = attrs.as_object() {
                            let mut attr_map = BTreeMap::new();
                            for (attr, type_val) in attr_obj {
                                if let Some(t) = type_val.as_str() {
                                    attr_map.insert(attr.clone(), t.to_string());
                                }
                            }
                            if !attr_map.is_empty() {
                                getatt_returns.insert(type_name.clone(), attr_map);
                            }
                        }
                    }
                }
            }
        }
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
        if !path.exists() {
            continue;
        }
        let content = fs::read_to_string(&path)?;
        let json: serde_json::Value = serde_json::from_str(&content)?;
        let Some(data) = json.get(*file_key).and_then(|v| v.as_object()) else {
            continue;
        };

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
    if !ext_dir.exists() {
        return Ok(());
    }
    let mut extensions: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for entry in fs::read_dir(&ext_dir)?.flatten() {
        let path = entry.path();
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
        // The extension JSON itself doesn't contain the type name, so we use the filename convention
        if let Ok(content) = fs::read_to_string(&path) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                extensions.insert(type_name, json);
            }
        }
    }
    let bytes = serde_json::to_string_pretty(&extensions)?;
    fs::write(output_dir.join("extensions.json"), bytes.as_bytes())?;
    info!("Compiled {} resource type extensions -> extensions.json", extensions.len());
    Ok(())
}

/// Convert `/properties/X/Y/Z` paths to `X.Y.Z` dot notation.
fn convert_property_paths(raw: &serde_json::Value) -> Vec<String> {
    raw.as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().and_then(|s| s.strip_prefix("/properties/")).map(|s| s.replace('/', ".")))
                .collect()
        })
        .unwrap_or_default()
}

fn compile_schema(type_name: &str, raw: &serde_json::Value) -> CompiledSchema {
    let mut defs = BTreeMap::new();
    if let Some(d) = raw.get("definitions").and_then(|v| v.as_object()) {
        for (k, v) in d {
            defs.insert(k.clone(), compile_prop(v));
        }
    }
    let mut props = BTreeMap::new();
    if let Some(p) = raw.get("properties").and_then(|v| v.as_object()) {
        for (k, v) in p {
            props.insert(k.clone(), compile_prop(v));
        }
    }

    let mut all_of = Vec::new();
    let mut if_then_else = Vec::new();
    if let Some(arr) = raw.get("allOf").and_then(|v| v.as_array()) {
        for item in arr {
            if item.get("if").is_some() {
                if let Some(ite) = compile_if_then_else(item) {
                    if_then_else.push(ite);
                }
            } else {
                all_of.push(compile_sub(item));
            }
        }
    }

    CompiledSchema {
        type_name: type_name.to_string(),
        properties: props,
        definitions: defs,
        required: str_arr(raw.get("required")),
        additional_properties: raw.get("additionalProperties").and_then(|v| v.as_bool()),
        read_only_properties: convert_property_paths(raw.get("readOnlyProperties").unwrap_or(&serde_json::Value::Null)),
        write_only_properties: convert_property_paths(
            raw.get("writeOnlyProperties").unwrap_or(&serde_json::Value::Null),
        ),
        create_only_properties: convert_property_paths(
            raw.get("createOnlyProperties").unwrap_or(&serde_json::Value::Null),
        ),
        deprecated_properties: convert_property_paths(
            raw.get("deprecatedProperties").unwrap_or(&serde_json::Value::Null),
        ),
        conditional_create_only_properties: convert_property_paths(
            raw.get("conditionalCreateOnlyProperties").unwrap_or(&serde_json::Value::Null),
        ),
        primary_identifier: convert_property_paths(raw.get("primaryIdentifier").unwrap_or(&serde_json::Value::Null)),
        replacement_strategy: raw
            .get("replacementStrategy")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from),
        documentation_url: raw
            .get("documentationUrl")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from),
        source_url: raw.get("sourceUrl").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(String::from),
        description: raw.get("description").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(String::from),
        all_of,
        any_of: compile_subs(raw.get("anyOf")),
        one_of: compile_subs(raw.get("oneOf")),
        if_then_else,
        dependent_required: str_map(raw.get("dependentRequired")),
        dependent_excluded: str_map(raw.get("dependentExcluded")),
        required_or: str_arr(raw.get("requiredOr")),
        required_xor: str_arr(raw.get("requiredXor")),
    }
}

fn compile_if_then_else(raw: &serde_json::Value) -> Option<IfThenElse> {
    let if_val = raw.get("if")?;
    let condition = compile_condition_schema(if_val);
    let then_schema = raw.get("then").map(compile_sub);
    let else_schema = raw.get("else").map(compile_sub);
    if then_schema.is_none() && else_schema.is_none() {
        return None;
    }
    Some(IfThenElse { condition, then_schema, else_schema })
}

fn compile_condition_schema(raw: &serde_json::Value) -> ConditionSchema {
    let obj = match raw.as_object() {
        Some(o) => o,
        None => return ConditionSchema::default(),
    };
    let mut props = BTreeMap::new();
    if let Some(p) = obj.get("properties").and_then(|v| v.as_object()) {
        for (k, v) in p {
            props.insert(k.clone(), compile_prop(v));
        }
    }
    let any_of = obj
        .get("anyOf")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(compile_condition_schema).collect())
        .unwrap_or_default();
    ConditionSchema { properties: props, required: str_arr(obj.get("required")), any_of }
}

fn compile_prop(raw: &serde_json::Value) -> PropSchema {
    let obj = match raw.as_object() {
        Some(o) => o,
        None => return PropSchema::default(),
    };
    if let Some(ref_str) = obj.get("$ref").and_then(|v| v.as_str()) {
        if let Some(def_name) = ref_str.strip_prefix("#/definitions/") {
            return PropSchema { ref_name: Some(def_name.to_string()), ..Default::default() };
        }
        return PropSchema::default();
    }

    let prop_type = obj.get("type").map(|v| match v {
        serde_json::Value::String(s) => PropType::Single(s.clone()),
        serde_json::Value::Array(a) => PropType::Multi(a.iter().filter_map(|v| v.as_str().map(String::from)).collect()),
        _ => PropType::Single("string".into()),
    });
    let mut sub_props = BTreeMap::new();
    if let Some(p) = obj.get("properties").and_then(|v| v.as_object()) {
        for (k, v) in p {
            sub_props.insert(k.clone(), compile_prop(v));
        }
    }
    let mut pat_props = BTreeMap::new();
    if let Some(p) = obj.get("patternProperties").and_then(|v| v.as_object()) {
        for (k, v) in p {
            pat_props.insert(k.clone(), compile_prop(v));
        }
    }
    let items = obj.get("items").map(|v| Box::new(compile_prop(v)));

    PropSchema {
        ref_name: None,
        prop_type,
        enum_values: obj.get("enum").and_then(|v| v.as_array()).cloned().unwrap_or_default(),
        enum_case_insensitive: obj.get("enumCaseInsensitive").and_then(|v| v.as_array()).cloned().unwrap_or_default(),
        not_enum: obj.get("not").and_then(|v| v.get("enum")).and_then(|v| v.as_array()).cloned().unwrap_or_default(),
        const_value: obj.get("const").cloned(),
        pattern: obj.get("pattern").and_then(|v| v.as_str()).map(String::from),
        minimum: obj.get("minimum").and_then(|v| v.as_f64()),
        maximum: obj.get("maximum").and_then(|v| v.as_f64()),
        exclusive_minimum: obj.get("exclusiveMinimum").and_then(|v| v.as_f64()),
        exclusive_maximum: obj.get("exclusiveMaximum").and_then(|v| v.as_f64()),
        min_length: obj.get("minLength").and_then(|v| v.as_u64()),
        max_length: obj.get("maxLength").and_then(|v| v.as_u64()),
        min_items: obj.get("minItems").and_then(|v| v.as_u64()),
        max_items: obj.get("maxItems").and_then(|v| v.as_u64()),
        unique_items: obj.get("uniqueItems").and_then(|v| v.as_bool()).unwrap_or(false),
        min_properties: obj.get("minProperties").and_then(|v| v.as_u64()),
        max_properties: obj.get("maxProperties").and_then(|v| v.as_u64()),
        format: obj.get("format").and_then(|v| v.as_str()).map(String::from),
        description: obj.get("description").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(String::from),
        properties: sub_props,
        required: str_arr(obj.get("required").cloned().as_ref()),
        additional_properties: obj.get("additionalProperties").and_then(|v| v.as_bool()),
        pattern_properties: pat_props,
        items,
        all_of: compile_subs(obj.get("allOf").cloned().as_ref()),
        any_of: compile_subs(obj.get("anyOf").cloned().as_ref()),
        one_of: compile_subs(obj.get("oneOf").cloned().as_ref()),
        dependent_required: str_map(obj.get("dependentRequired").cloned().as_ref()),
        dependent_excluded: str_map(obj.get("dependentExcluded").cloned().as_ref()),
        required_or: str_arr(obj.get("requiredOr").cloned().as_ref()),
        required_xor: str_arr(obj.get("requiredXor").cloned().as_ref()),
    }
}

fn compile_sub(raw: &serde_json::Value) -> SubSchema {
    let obj = raw.as_object();
    let mut props = BTreeMap::new();
    if let Some(p) = obj.and_then(|o| o.get("properties")).and_then(|v| v.as_object()) {
        for (k, v) in p {
            props.insert(k.clone(), compile_prop(v));
        }
    }
    SubSchema {
        required: str_arr(obj.and_then(|o| o.get("required"))),
        properties: props,
        additional_properties: obj.and_then(|o| o.get("additionalProperties")).and_then(|v| v.as_bool()),
        dependent_required: str_map(obj.and_then(|o| o.get("dependentRequired"))),
        dependent_excluded: str_map(obj.and_then(|o| o.get("dependentExcluded"))),
    }
}

fn compile_subs(val: Option<&serde_json::Value>) -> Vec<SubSchema> {
    let Some(arr) = val.and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    arr.iter().map(|s| compile_sub(s)).collect()
}

fn str_arr(val: Option<&serde_json::Value>) -> Vec<String> {
    val.and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default()
}
fn str_map(val: Option<&serde_json::Value>) -> BTreeMap<String, Vec<String>> {
    val.and_then(|v| v.as_object())
        .map(|m| m.iter().map(|(k, v)| (k.clone(), str_arr(Some(v)))).collect())
        .unwrap_or_default()
}

/// Read the raw step functions state machine schema from upstream, flatten nested
/// definitions and composition `$ref`s so `compile_schema` can handle it, compile,
/// and write the result to the schema-validator output directory.
pub fn compile_step_functions_schema(upstream_dir: &Path, output_dir: &Path) -> anyhow::Result<()> {
    let raw_path = upstream_dir.join("step_functions_statemachine.json");
    if !raw_path.exists() {
        info!("Step Functions schema not found at {}, skipping", raw_path.display());
        return Ok(());
    }
    let content = fs::read_to_string(&raw_path)?;
    let mut schema: serde_json::Value = serde_json::from_str(&content)?;

    flatten_sf_schema(&mut schema);

    schema.as_object_mut().unwrap().insert(
        "typeName".into(),
        serde_json::Value::String("AWS::StepFunctions::StateMachine::DefinitionBody".into()),
    );

    let compiled = compile_schema("AWS::StepFunctions::StateMachine::DefinitionBody", &schema);
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
