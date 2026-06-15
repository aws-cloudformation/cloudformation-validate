use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Definitions are stored separately and referenced by name to avoid exponential blowup.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CompiledSchema {
    #[serde(default)]
    pub type_name: String,
    #[serde(default)]
    pub properties: HashMap<String, PropSchema>,
    #[serde(default)]
    pub definitions: HashMap<String, PropSchema>,
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub additional_properties: Option<bool>,
    #[serde(default)]
    pub read_only_properties: Vec<String>,
    #[serde(default)]
    pub write_only_properties: Vec<String>,
    #[serde(default)]
    pub create_only_properties: Vec<String>,
    #[serde(default)]
    pub deprecated_properties: Vec<String>,
    #[serde(default)]
    pub conditional_create_only_properties: Vec<String>,
    #[serde(default)]
    pub primary_identifier: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_strategy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub all_of: Vec<SubSchema>,
    #[serde(default)]
    pub any_of: Vec<SubSchema>,
    #[serde(default)]
    pub one_of: Vec<SubSchema>,
    #[serde(default)]
    pub if_then_else: Vec<IfThenElse>,
    #[serde(default)]
    pub dependent_required: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub dependent_excluded: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub required_or: Vec<String>,
    #[serde(default)]
    pub required_xor: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IfThenElse {
    pub condition: ConditionSchema,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub then_schema: Option<SubSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub else_schema: Option<SubSchema>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConditionSchema {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub properties: HashMap<String, PropSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
    /// When set, the condition matches if ANY of these sub-conditions match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub any_of: Vec<ConditionSchema>,
}

/// `$ref` is stored as `ref_name` and resolved at validation time against the parent schema's `definitions`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PropSchema {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_name: Option<String>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub prop_type: Option<PropType>,
    #[serde(default, rename = "enum", skip_serializing_if = "Vec::is_empty")]
    pub enum_values: Vec<serde_json::Value>,
    /// JSON Schema `not: { enum: [...] }` — value must NOT match any of these.
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
    #[serde(default, skip_serializing_if = "is_false")]
    pub unique_items: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_properties: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_properties: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub properties: HashMap<String, PropSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_properties: Option<bool>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub pattern_properties: HashMap<String, PropSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<PropSchema>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub all_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub any_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub one_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub dependent_required: HashMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub dependent_excluded: HashMap<String, Vec<String>>,
}

fn is_false(b: &bool) -> bool {
    !b
}

impl PropSchema {
    pub fn resolve<'a>(&'a self, defs: &'a HashMap<String, PropSchema>) -> &'a PropSchema {
        if let Some(ref name) = self.ref_name { defs.get(name).map(|d| d.resolve(defs)).unwrap_or(self) } else { self }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SubSchema {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub properties: HashMap<String, PropSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_properties: Option<bool>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub dependent_required: HashMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub dependent_excluded: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PropType {
    Single(String),
    Multi(Vec<String>),
}

impl PropType {
    pub fn primary(&self) -> Option<&str> {
        match self {
            PropType::Single(s) => Some(s),
            PropType::Multi(v) => v.iter().find(|s| s.as_str() != "null").map(|s| s.as_str()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::ptr;

    #[test]
    fn primary_single_returns_the_type() {
        let pt = PropType::Single("string".into());
        assert_eq!(pt.primary(), Some("string"));
    }

    #[test]
    fn primary_multi_skips_null() {
        let pt = PropType::Multi(vec!["null".into(), "integer".into()]);
        assert_eq!(pt.primary(), Some("integer"));
    }

    #[test]
    fn primary_multi_all_null_returns_none() {
        let pt = PropType::Multi(vec!["null".into()]);
        assert_eq!(pt.primary(), None);
    }

    #[test]
    fn primary_multi_empty_returns_none() {
        let pt = PropType::Multi(vec![]);
        assert_eq!(pt.primary(), None);
    }

    #[test]
    fn primary_multi_first_non_null() {
        let pt = PropType::Multi(vec!["string".into(), "null".into(), "integer".into()]);
        assert_eq!(pt.primary(), Some("string"));
    }

    #[test]
    fn resolve_no_ref_returns_self() {
        let schema = PropSchema { prop_type: Some(PropType::Single("string".into())), ..Default::default() };
        let defs = HashMap::new();
        let resolved = schema.resolve(&defs);
        assert!(ptr::eq(resolved, &schema));
    }

    #[test]
    fn resolve_follows_ref_to_definition() {
        let target = PropSchema { prop_type: Some(PropType::Single("integer".into())), ..Default::default() };
        let mut defs = HashMap::new();
        defs.insert("MyDef".into(), target);

        let schema = PropSchema { ref_name: Some("MyDef".into()), ..Default::default() };
        let resolved = schema.resolve(&defs);
        assert_eq!(resolved.prop_type.as_ref().unwrap().primary(), Some("integer"));
    }

    #[test]
    fn resolve_chained_refs() {
        let final_target = PropSchema { prop_type: Some(PropType::Single("boolean".into())), ..Default::default() };
        let intermediate = PropSchema { ref_name: Some("Final".into()), ..Default::default() };
        let mut defs = HashMap::new();
        defs.insert("Final".into(), final_target);
        defs.insert("Intermediate".into(), intermediate);

        let schema = PropSchema { ref_name: Some("Intermediate".into()), ..Default::default() };
        let resolved = schema.resolve(&defs);
        assert_eq!(resolved.prop_type.as_ref().unwrap().primary(), Some("boolean"));
    }

    #[test]
    fn resolve_missing_ref_returns_self() {
        let schema = PropSchema { ref_name: Some("NonExistent".into()), ..Default::default() };
        let defs = HashMap::new();
        let resolved = schema.resolve(&defs);
        assert!(ptr::eq(resolved, &schema));
    }

    #[test]
    fn prop_schema_roundtrip_json() {
        let schema = PropSchema {
            prop_type: Some(PropType::Single("string".into())),
            enum_values: vec![json!("a"), json!("b")],
            pattern: Some("^[a-z]+$".into()),
            minimum: Some(0.0),
            maximum: Some(100.0),
            min_length: Some(1),
            max_length: Some(256),
            unique_items: true,
            ..Default::default()
        };
        let json_str = serde_json::to_string(&schema).unwrap();
        let deserialized: PropSchema = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.prop_type.as_ref().unwrap().primary(), Some("string"));
        assert_eq!(deserialized.enum_values.len(), 2);
        assert_eq!(deserialized.pattern.as_deref(), Some("^[a-z]+$"));
        assert_eq!(deserialized.minimum, Some(0.0));
        assert_eq!(deserialized.maximum, Some(100.0));
        assert_eq!(deserialized.min_length, Some(1));
        assert_eq!(deserialized.max_length, Some(256));
        assert!(deserialized.unique_items, "unique_items should be true");
    }

    #[test]
    fn prop_type_single_deserializes_from_string() {
        let pt: PropType = serde_json::from_str(r#""string""#).unwrap();
        assert_eq!(pt.primary(), Some("string"));
    }

    #[test]
    fn prop_type_multi_deserializes_from_array() {
        let pt: PropType = serde_json::from_str(r#"["string", "null"]"#).unwrap();
        assert_eq!(pt.primary(), Some("string"));
    }

    #[test]
    fn compiled_schema_defaults_are_empty() {
        let json_str = r#"{"type_name": "AWS::Test::Resource"}"#;
        let schema: CompiledSchema = serde_json::from_str(json_str).unwrap();
        assert_eq!(schema.type_name, "AWS::Test::Resource");
        assert_eq!(schema.properties.len(), 0, "properties should be empty");
        assert_eq!(schema.definitions.len(), 0, "definitions should be empty");
        assert_eq!(schema.required.len(), 0, "required should be empty");
        assert_eq!(schema.additional_properties, None, "additional_properties should be None");
        assert_eq!(schema.read_only_properties.len(), 0, "read_only_properties should be empty");
        assert_eq!(schema.if_then_else.len(), 0, "if_then_else should be empty");
    }

    #[test]
    fn if_then_else_roundtrip() {
        let ite = IfThenElse {
            condition: ConditionSchema {
                properties: {
                    let mut m = HashMap::new();
                    m.insert("Engine".into(), PropSchema { enum_values: vec![json!("aurora")], ..Default::default() });
                    m
                },
                ..Default::default()
            },
            then_schema: Some(SubSchema { required: vec!["Port".into()], ..Default::default() }),
            else_schema: None,
        };
        let json_str = serde_json::to_string(&ite).unwrap();
        let deserialized: IfThenElse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.condition.properties.len(), 1);
        assert!(deserialized.then_schema.is_some(), "then_schema should be present");
        assert!(deserialized.else_schema.is_none(), "else_schema should be None");
    }

    #[test]
    fn prop_schema_skip_serializing_defaults() {
        let schema = PropSchema::default();
        let json_str = serde_json::to_string(&schema).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let obj = val.as_object().unwrap();
        // Default PropSchema should serialize to empty object (all fields skipped)
        assert!(obj.is_empty(), "expected empty JSON for default PropSchema, got: {}", json_str);
    }

    #[test]
    fn sub_schema_with_dependent_required() {
        let sub = SubSchema {
            dependent_required: {
                let mut m = HashMap::new();
                m.insert("A".into(), vec!["B".into(), "C".into()]);
                m
            },
            ..Default::default()
        };
        let json_str = serde_json::to_string(&sub).unwrap();
        let deserialized: SubSchema = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.dependent_required.get("A").unwrap(), &vec!["B".to_string(), "C".to_string()]);
    }
}
