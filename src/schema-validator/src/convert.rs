//! Explicit conversion from the build-time compiled-schema types in
//! [`data_source::compiled_schema`] to this crate's runtime types.
//!
//! Both families describe the same model but differ in map type: the build types
//! use `BTreeMap` so `compiled_schemas.json` is deterministic, the runtime types
//! use `HashMap` for lookup speed. The conversion is written out field by field
//! and destructures the source exhaustively, so adding a field to *either* side
//! is a compile error rather than a value silently dropped at run time. It
//! replaces an earlier serialize/deserialize round trip that both hid drift and
//! required panicking on a `pub` path.

use crate::compiled::{CompiledSchema, ConditionSchema, IfThenElse, PropSchema, PropType};
use data_source::compiled_schema as build;
use std::collections::HashMap;

fn props(source: std::collections::BTreeMap<String, build::PropSchema>) -> HashMap<String, PropSchema> {
    source.into_iter().map(|(name, prop)| (name, prop.into())).collect()
}

fn map(source: std::collections::BTreeMap<String, Vec<String>>) -> HashMap<String, Vec<String>> {
    source.into_iter().collect()
}

impl From<build::PropType> for PropType {
    fn from(source: build::PropType) -> Self {
        match source {
            build::PropType::Single(name) => PropType::Single(name),
            build::PropType::Multi(names) => PropType::Multi(names),
        }
    }
}

impl From<build::ConditionSchema> for ConditionSchema {
    fn from(source: build::ConditionSchema) -> Self {
        let build::ConditionSchema { properties, required, any_of } = source;
        ConditionSchema {
            properties: props(properties),
            required,
            any_of: any_of.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<build::IfThenElse> for IfThenElse {
    fn from(source: build::IfThenElse) -> Self {
        let build::IfThenElse { condition, then_schema, else_schema } = source;
        IfThenElse {
            condition: condition.into(),
            then_schema: then_schema.map(Into::into),
            else_schema: else_schema.map(Into::into),
        }
    }
}

impl From<build::PropSchema> for PropSchema {
    fn from(source: build::PropSchema) -> Self {
        let build::PropSchema {
            ref_name,
            prop_type,
            enum_values,
            enum_case_insensitive,
            not_enum,
            const_value,
            pattern,
            minimum,
            maximum,
            exclusive_minimum,
            exclusive_maximum,
            multiple_of,
            min_length,
            max_length,
            min_items,
            max_items,
            unique_items,
            min_properties,
            max_properties,
            format,
            description,
            properties,
            required,
            additional_properties,
            pattern_properties,
            items,
            all_of,
            any_of,
            one_of,
            if_then_else,
            dependent_required,
            dependent_excluded,
        } = source;
        PropSchema {
            ref_name,
            prop_type: prop_type.map(Into::into),
            enum_values,
            enum_case_insensitive,
            not_enum,
            const_value,
            pattern,
            minimum,
            maximum,
            exclusive_minimum,
            exclusive_maximum,
            multiple_of,
            min_length,
            max_length,
            min_items,
            max_items,
            unique_items,
            min_properties,
            max_properties,
            format,
            description,
            properties: props(properties),
            required,
            required_present: false,
            additional_properties,
            pattern_properties: props(pattern_properties),
            items: items.map(|boxed| Box::new((*boxed).into())),
            all_of: all_of.into_iter().map(Into::into).collect(),
            any_of: any_of.into_iter().map(Into::into).collect(),
            one_of: one_of.into_iter().map(Into::into).collect(),
            if_then_else: if_then_else.into_iter().map(Into::into).collect(),
            dependent_required: map(dependent_required),
            dependent_excluded: map(dependent_excluded),
        }
    }
}

impl From<build::CompiledSchema> for CompiledSchema {
    fn from(source: build::CompiledSchema) -> Self {
        let build::CompiledSchema {
            type_name,
            properties,
            definitions,
            required,
            additional_properties,
            read_only_properties,
            write_only_properties,
            create_only_properties,
            deprecated_properties,
            conditional_create_only_properties,
            primary_identifier,
            replacement_strategy,
            documentation_url,
            source_url,
            description,
            all_of,
            any_of,
            one_of,
            if_then_else,
            dependent_required,
            dependent_excluded,
            required_or,
            required_xor,
        } = source;
        CompiledSchema {
            type_name,
            properties: props(properties),
            definitions: props(definitions),
            required,
            required_present: false,
            additional_properties,
            read_only_properties,
            write_only_properties,
            create_only_properties,
            deprecated_properties,
            conditional_create_only_properties,
            primary_identifier,
            replacement_strategy,
            documentation_url,
            source_url,
            description,
            all_of: all_of.into_iter().map(Into::into).collect(),
            any_of: any_of.into_iter().map(Into::into).collect(),
            one_of: one_of.into_iter().map(Into::into).collect(),
            if_then_else: if_then_else.into_iter().map(Into::into).collect(),
            dependent_required: map(dependent_required),
            dependent_excluded: map(dependent_excluded),
            required_or,
            required_xor,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn conversion_carries_every_populated_field() {
        let raw = json!({
            "typeName": "AWS::Test::Convert",
            "properties": {
                "Name": {
                    "type": "string",
                    "enum": ["a", "b"],
                    "pattern": "^a",
                    "minLength": 1,
                    "maxLength": 4,
                    "description": "d"
                },
                "Items": { "type": "array", "uniqueItems": true, "items": { "type": "string" } },
                "Relaxed": { "type": "array", "uniqueItems": false },
                "Cfg": { "$ref": "#/definitions/Config" }
            },
            "definitions": { "Config": { "type": "object", "required": ["Inner"] } },
            "required": ["Name"],
            "additionalProperties": false,
            "readOnlyProperties": ["/properties/Arn"],
            "deprecatedProperties": ["/properties/Old"],
            "primaryIdentifier": ["/properties/Name"],
            "dependentRequired": { "Name": ["Items"] },
            "requiredXor": ["Name", "Items"],
            "oneOf": [{ "required": ["Name"] }],
            "allOf": [{ "if": { "properties": { "Name": { "enum": ["a"] } } }, "then": { "required": ["Items"] } }]
        });
        let compiled: CompiledSchema = build::compile_schema("AWS::Test::Convert", &raw).into();

        assert_eq!(compiled.type_name, "AWS::Test::Convert");
        assert_eq!(compiled.required, vec!["Name".to_string()]);
        assert_eq!(compiled.additional_properties, Some(false));
        assert_eq!(compiled.read_only_properties, vec!["Arn".to_string()]);
        assert_eq!(compiled.deprecated_properties, vec!["Old".to_string()]);
        assert_eq!(compiled.primary_identifier, vec!["Name".to_string()]);
        assert_eq!(compiled.dependent_required.get("Name"), Some(&vec!["Items".to_string()]));
        assert_eq!(compiled.required_xor, vec!["Name".to_string(), "Items".to_string()]);
        assert_eq!(compiled.one_of.len(), 1);
        assert_eq!(compiled.if_then_else.len(), 1);
        assert_eq!(compiled.definitions["Config"].required, vec!["Inner".to_string()]);
        assert_eq!(compiled.properties["Cfg"].ref_name.as_deref(), Some("Config"));

        let name = &compiled.properties["Name"];
        assert_eq!(name.prop_type.as_ref().and_then(PropType::primary), Some("string"));
        assert_eq!(name.enum_values.len(), 2);
        assert_eq!(name.pattern.as_deref(), Some("^a"));
        assert_eq!(name.min_length, Some(1));
        assert_eq!(name.max_length, Some(4));
        assert_eq!(name.description.as_deref(), Some("d"));

        assert_eq!(compiled.properties["Items"].unique_items, Some(true));
        assert!(compiled.properties["Items"].items.is_some(), "items must survive the conversion");
        assert_eq!(
            compiled.properties["Relaxed"].unique_items,
            Some(false),
            "an explicit uniqueItems:false must be preserved as Some(false), not collapsed to absent"
        );
    }

    #[test]
    fn unique_items_encoding_is_unchanged_by_the_option_representation() {
        // The generated `compiled_schemas.json` predates `Option<bool>`; the
        // encoding must stay identical so the committed artifact keeps matching a
        // fresh build: emitted only when true, omitted otherwise.
        let encode = |value: Option<bool>| {
            serde_json::to_string(&PropSchema { unique_items: value, ..Default::default() })
                .expect("PropSchema serializes")
        };
        assert_eq!(encode(Some(true)), r#"{"unique_items":true}"#);
        assert_eq!(encode(Some(false)), "{}", "explicit false must not be written to the artifact");
        assert_eq!(encode(None), "{}");
    }
}
