//! Shared CloudFormation resource-provider schema model and the raw-JSON →
//! compiled-schema transform.
//!
//! This is the single source of truth for turning a raw CloudFormation registry
//! schema (`$ref`, `type`, `enum`, `/properties/...` paths, `allOf`+`if`, …) into
//! the compiled representation that the schema validator consumes.
//!
//! - At **build time**, `codegen_schema_validator` compiles every bundled schema
//!   with [`compile_schema`] and serializes the results to `compiled_schemas.json`
//!   (embedded into the binary). `BTreeMap` fields make that output deterministic.
//! - At **run time**, the `schema-validator` crate applies additional/overlay
//!   schemas by calling [`compile_schema`] and round-tripping the result through
//!   serde into its own runtime schema type. Routing overlays through this exact
//!   function guarantees they are compiled identically to bundled schemas.
//!
//! This module is intentionally dependency-free (only `serde`/`serde_json` +
//! `std`) and is **not** behind the `full` feature, so the runtime can use the
//! transform without pulling in the build pipeline's heavy dependencies.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize)]
pub struct CompiledSchema {
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

pub fn compile_schema(type_name: &str, raw: &serde_json::Value) -> CompiledSchema {
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
    arr.iter().map(compile_sub).collect()
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
