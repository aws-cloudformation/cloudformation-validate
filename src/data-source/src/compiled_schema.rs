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
//!   schemas by calling [`compile_schema`] and converting the result into its own
//!   runtime schema type. Routing overlays through this exact function guarantees
//!   the *transform* is the same one bundled schemas go through.
//!
//! The transform is shared; the **input** is not. Bundled schemas are compiled
//! from the build pipeline's patched archive, which adds keywords the raw registry
//! does not carry (case-insensitive enums, `requiredOr`/`requiredXor`,
//! `dependentExcluded`, injected conditional `allOf` fragments). A caller-supplied
//! overlay is compiled straight from the JSON it provides, so anything the
//! pipeline would have contributed is absent unless the caller states it
//! explicitly. Callers must not assume an overlay for a bundled type reproduces
//! that type's enriched schema.
//!
//! This module is intentionally dependency-free (only `serde`/`serde_json` +
//! `std`) and is **not** behind the `full` feature, so the runtime can use the
//! transform without pulling in the build pipeline's heavy dependencies.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize)]
pub struct CompiledSchema {
    pub type_name: String,
    #[serde(default)]
    pub properties: BTreeMap<String, PropSchema>,
    #[serde(default)]
    pub definitions: BTreeMap<String, PropSchema>,
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub additional_properties: Option<bool>,
    #[serde(default)]
    pub read_only_properties: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub write_only_properties: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub create_only_properties: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deprecated_properties: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditional_create_only_properties: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub primary_identifier: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_strategy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub all_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub any_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub one_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub if_then_else: Vec<IfThenElse>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependent_required: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependent_excluded: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_or: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_xor: Vec<String>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct IfThenElse {
    pub condition: ConditionSchema,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub then_schema: Option<SubSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub else_schema: Option<SubSchema>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct ConditionSchema {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, PropSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub any_of: Vec<ConditionSchema>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct PropSchema {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_name: Option<String>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub prop_type: Option<PropType>,
    #[serde(default, rename = "enum", skip_serializing_if = "Vec::is_empty")]
    pub enum_values: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enum_case_insensitive: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_enum: Vec<serde_json::Value>,
    #[serde(default, rename = "const", skip_serializing_if = "Option::is_none")]
    pub const_value: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclusive_minimum: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclusive_maximum: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_items: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_items: Option<u64>,
    /// `None` when the source schema omits `uniqueItems`, so an overlay that
    /// explicitly sets it to `false` can relax a bundled `true`. Serialization
    /// only emits the field when it is `true`, keeping the encoding identical to
    /// the plain-boolean form this replaced.
    #[serde(default, skip_serializing_if = "skip_unless_true")]
    pub unique_items: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_properties: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_properties: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, PropSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_properties: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pattern_properties: BTreeMap<String, PropSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<PropSchema>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub all_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub any_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub one_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependent_required: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependent_excluded: BTreeMap<String, Vec<String>>,
}
fn skip_unless_true(value: &Option<bool>) -> bool {
    *value != Some(true)
}

#[derive(Serialize, Deserialize, Default)]
pub struct SubSchema {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, PropSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_properties: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependent_required: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependent_excluded: BTreeMap<String, Vec<String>>,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum PropType {
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
        unique_items: obj.get("uniqueItems").and_then(|v| v.as_bool()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compiles_properties_definitions_and_refs() {
        let compiled = compile_schema(
            "AWS::Test::T",
            &json!({
                "properties": {
                    "Name": { "type": "string", "pattern": "^a", "minLength": 1 },
                    "Cfg": { "$ref": "#/definitions/Config" },
                    "Kinds": { "type": ["string", "null"] }
                },
                "definitions": { "Config": { "type": "object", "required": ["Inner"] } },
                "required": ["Name"],
                "additionalProperties": false
            }),
        );
        assert_eq!(compiled.type_name, "AWS::Test::T");
        assert_eq!(compiled.required, vec!["Name".to_string()]);
        assert_eq!(compiled.additional_properties, Some(false));
        assert_eq!(compiled.properties["Cfg"].ref_name.as_deref(), Some("Config"));
        assert_eq!(compiled.definitions["Config"].required, vec!["Inner".to_string()]);
        assert_eq!(compiled.properties["Name"].pattern.as_deref(), Some("^a"));
        assert_eq!(compiled.properties["Name"].min_length, Some(1));
        match compiled.properties["Kinds"].prop_type.as_ref().expect("a multi type is compiled") {
            PropType::Multi(names) => assert_eq!(names, &vec!["string".to_string(), "null".to_string()]),
            PropType::Single(name) => panic!("expected a multi type, got {name}"),
        }
    }

    #[test]
    fn converts_property_pointer_paths_to_dot_notation() {
        let compiled = compile_schema(
            "AWS::Test::T",
            &json!({
                "readOnlyProperties": ["/properties/Arn", "/properties/Nested/Id"],
                "writeOnlyProperties": ["/properties/Secret"],
                "createOnlyProperties": ["/properties/Name"],
                "deprecatedProperties": ["/properties/Old"],
                "conditionalCreateOnlyProperties": ["/properties/Maybe"],
                "primaryIdentifier": ["/properties/Name"]
            }),
        );
        assert_eq!(compiled.read_only_properties, vec!["Arn".to_string(), "Nested.Id".to_string()]);
        assert_eq!(compiled.write_only_properties, vec!["Secret".to_string()]);
        assert_eq!(compiled.create_only_properties, vec!["Name".to_string()]);
        assert_eq!(compiled.deprecated_properties, vec!["Old".to_string()]);
        assert_eq!(compiled.conditional_create_only_properties, vec!["Maybe".to_string()]);
        assert_eq!(compiled.primary_identifier, vec!["Name".to_string()]);
    }

    #[test]
    fn splits_all_of_into_plain_and_conditional_entries() {
        let compiled = compile_schema(
            "AWS::Test::T",
            &json!({
                "allOf": [
                    { "required": ["Plain"] },
                    { "if": { "properties": { "A": { "enum": ["x"] } } }, "then": { "required": ["B"] } },
                    { "if": { "properties": { "A": { "enum": ["y"] } } } }
                ]
            }),
        );
        assert_eq!(compiled.all_of.len(), 1, "plain entries stay in all_of");
        assert_eq!(compiled.all_of[0].required, vec!["Plain".to_string()]);
        assert_eq!(compiled.if_then_else.len(), 1, "an if with neither then nor else is dropped");
        assert_eq!(compiled.if_then_else[0].then_schema.as_ref().expect("then branch").required, vec!["B".to_string()]);
    }

    #[test]
    fn preserves_unique_items_presence() {
        let compiled = compile_schema(
            "AWS::Test::T",
            &json!({
                "properties": {
                    "Strict": { "type": "array", "uniqueItems": true },
                    "Relaxed": { "type": "array", "uniqueItems": false },
                    "Silent": { "type": "array" }
                }
            }),
        );
        assert_eq!(compiled.properties["Strict"].unique_items, Some(true));
        assert_eq!(
            compiled.properties["Relaxed"].unique_items,
            Some(false),
            "an explicit false must be distinguishable from an omitted keyword"
        );
        assert_eq!(compiled.properties["Silent"].unique_items, None);
    }

    #[test]
    fn unique_items_serialization_only_emits_true() {
        // The committed `compiled_schemas.json` was produced when this field was a
        // plain bool that was skipped unless true; the encoding must not change.
        let compiled = compile_schema(
            "AWS::Test::T",
            &json!({
                "properties": {
                    "Strict": { "uniqueItems": true },
                    "Relaxed": { "uniqueItems": false },
                    "Silent": {}
                }
            }),
        );
        let json = serde_json::to_value(&compiled).expect("a compiled schema serializes");
        let properties = json.get("properties").and_then(|v| v.as_object()).expect("properties are serialized");
        assert_eq!(properties["Strict"].get("unique_items"), Some(&json!(true)));
        assert!(properties["Relaxed"].get("unique_items").is_none(), "explicit false must be omitted");
        assert!(properties["Silent"].get("unique_items").is_none(), "an absent keyword must be omitted");
    }

    #[test]
    fn compiles_both_enum_representations_and_constraint_keywords() {
        let compiled = compile_schema(
            "AWS::Test::T",
            &json!({
                "properties": {
                    "Exact": { "enum": ["a", "b"] },
                    "Insensitive": { "enumCaseInsensitive": ["a", "b"] },
                    "Excluded": { "not": { "enum": ["bad"] } },
                    "Fixed": { "const": 7 }
                },
                "dependentRequired": { "A": ["B"] },
                "dependentExcluded": { "C": ["D"] },
                "requiredOr": ["A", "B"],
                "requiredXor": ["C", "D"]
            }),
        );
        assert_eq!(compiled.properties["Exact"].enum_values, vec![json!("a"), json!("b")]);
        assert_eq!(compiled.properties["Insensitive"].enum_case_insensitive, vec![json!("a"), json!("b")]);
        assert_eq!(compiled.properties["Excluded"].not_enum, vec![json!("bad")]);
        assert_eq!(compiled.properties["Fixed"].const_value, Some(json!(7)));
        assert_eq!(compiled.dependent_required.get("A"), Some(&vec!["B".to_string()]));
        assert_eq!(compiled.dependent_excluded.get("C"), Some(&vec!["D".to_string()]));
        assert_eq!(compiled.required_or, vec!["A".to_string(), "B".to_string()]);
        assert_eq!(compiled.required_xor, vec!["C".to_string(), "D".to_string()]);
    }

    #[test]
    fn compiles_nested_properties_items_and_pattern_properties() {
        let compiled = compile_schema(
            "AWS::Test::T",
            &json!({
                "properties": {
                    "Cfg": { "type": "object", "properties": { "Inner": { "type": "string" } } },
                    "Arr": { "type": "array", "items": { "type": "string", "maxLength": 3 } },
                    "Map": { "type": "object", "patternProperties": { "^k$": { "type": "integer" } } }
                }
            }),
        );
        assert!(compiled.properties["Cfg"].properties["Inner"].prop_type.is_some(), "nested type is compiled");
        assert_eq!(compiled.properties["Arr"].items.as_ref().expect("items").max_length, Some(3));
        assert!(compiled.properties["Map"].pattern_properties.contains_key("^k$"));
    }
}
