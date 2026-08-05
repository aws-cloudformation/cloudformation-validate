//! A pre-read CloudFormation resource provider schema to overlay on bundled
//! schemas. This module provides the shared type used by both `EngineConfig`
//! (in `validation-engine`) and `SchemaValidatorConfig` (in
//! `schema-validator`) so that overlays are specified once and applied
//! identically everywhere.
//!
//! The struct contains only pre-read data and pure resolution logic — no
//! filesystem access. Host layers (CLI, language bindings) read files and
//! populate the struct before passing it in. Feature-gated derives expose the
//! same record shape through WASM and UniFFI bindings. `type_name` is optional:
//! leaving it unset (`None`) requests the schema's own `typeName`, so the field
//! maps to a naturally nullable, omittable value in every binding.

use crate::compiled_schema::keywords;
use serde::{Deserialize, Serialize};

/// Error type for schema source resolution failures. Deliberately cheap to
/// construct (just a message string) and convertible from the caller's own
/// error type via `From<String>`.
#[derive(Debug, Clone)]
pub struct SchemaSourceError(pub String);

impl std::fmt::Display for SchemaSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SchemaSourceError {}

impl From<String> for SchemaSourceError {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// A single additional CloudFormation resource provider schema to overlay on top
/// of the bundled schemas.
///
/// `type_name` identifies the resource type (e.g., `"AWS::Lambda::Function"`).
/// When absent (`None`), the `typeName` field inside the schema JSON is used
/// instead. When both are present they must agree.
///
/// `schema` is the complete resource provider schema as a JSON string, in the
/// standard CloudFormation registry format.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm-bindings", tsify(from_wasm_abi))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct AdditionalSchemaSource {
    /// The resource type name (e.g., `"AWS::Lambda::Function"`). When absent, the
    /// `typeName` field of the schema JSON is used instead. When both are
    /// present they must agree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm-bindings", tsify(optional))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub type_name: Option<String>,
    /// The complete resource provider schema as a JSON string, in the standard
    /// CloudFormation registry format.
    pub schema: String,
}

impl AdditionalSchemaSource {
    /// Parse the schema JSON and resolve the effective resource type name into the
    /// `(type_name, schema)` pair the schema validator consumes.
    ///
    /// Returns an error when the schema is not valid JSON, is not a JSON object,
    /// provides no resource type name at all, or names one type explicitly and a
    /// different one in the schema body — a contradiction that is far more likely
    /// to be a copy/paste mistake than an intentional rename.
    pub fn resolve(&self) -> Result<(String, serde_json::Value), SchemaSourceError> {
        // An absent (`None`) or empty explicit name both mean "take the type name
        // from the schema body"; collapse them to a single `&str` view so the
        // resolution logic below is agnostic to which one the caller supplied.
        let explicit = self.type_name.as_deref().unwrap_or("");
        let label = if explicit.is_empty() { "<unnamed>" } else { explicit };
        let schema: serde_json::Value = serde_json::from_str(&self.schema)
            .map_err(|e| SchemaSourceError(format!("Invalid additional schema for '{label}': {e}")))?;
        if !schema.is_object() {
            return Err(SchemaSourceError(format!(
                "Invalid additional schema for '{label}': expected a JSON object describing a CloudFormation \
                 resource provider schema"
            )));
        }
        if !explicit.is_empty() && explicit != explicit.trim() {
            return Err(SchemaSourceError(format!(
                "Invalid additional schema for '{label}': type name has leading or trailing whitespace"
            )));
        }
        let in_schema = match schema.get(keywords::TYPE_NAME) {
            Some(value) => {
                let declared = value.as_str().ok_or_else(|| {
                    SchemaSourceError(format!("Invalid additional schema for '{label}': 'typeName' must be a string"))
                })?;
                if declared != declared.trim() {
                    return Err(SchemaSourceError(format!(
                        "Invalid additional schema for '{label}': type name has leading or trailing whitespace"
                    )));
                }
                (!declared.is_empty()).then_some(declared)
            }
            None => None,
        };
        let type_name = match (explicit, in_schema) {
            ("", None) => {
                return Err(SchemaSourceError(
                    "Additional schema is missing a resource type name (no explicit type name and no typeName in \
                     the schema)"
                        .to_string(),
                ));
            }
            ("", Some(from_schema)) => from_schema.to_string(),
            (explicit, None) => explicit.to_string(),
            (explicit, Some(from_schema)) if explicit == from_schema => explicit.to_string(),
            (explicit, Some(from_schema)) => {
                return Err(SchemaSourceError(format!(
                    "Invalid additional schema for '{explicit}': the schema declares typeName '{from_schema}'; \
                     remove one of them or make them match"
                )));
            }
        };
        // Reject leading/trailing whitespace in the resolved type name.
        if type_name != type_name.trim() {
            return Err(SchemaSourceError(format!(
                "Invalid additional schema for '{label}': type name has leading or trailing whitespace"
            )));
        }
        Ok((type_name, schema))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error_msg(result: Result<(String, serde_json::Value), SchemaSourceError>) -> String {
        result.expect_err("expected error").0
    }

    #[test]
    fn resolve_uses_explicit_type_name() {
        let src = AdditionalSchemaSource {
            type_name: Some("AWS::Lambda::Function".into()),
            schema: r#"{"properties":{"P":{"type":"string"}}}"#.into(),
        };
        let (type_name, schema) = src.resolve().expect("valid schema resolves");
        assert_eq!(type_name, "AWS::Lambda::Function");
        assert!(schema.is_object());
    }

    #[test]
    fn resolve_accepts_matching_type_names() {
        let src = AdditionalSchemaSource {
            type_name: Some("AWS::Lambda::Function".into()),
            schema: r#"{"typeName":"AWS::Lambda::Function","properties":{"P":{"type":"string"}}}"#.into(),
        };
        let (type_name, _) = src.resolve().expect("agreeing type names resolve");
        assert_eq!(type_name, "AWS::Lambda::Function");
    }

    #[test]
    fn resolve_rejects_contradictory_type_names() {
        let src = AdditionalSchemaSource {
            type_name: Some("AWS::Lambda::Function".into()),
            schema: r#"{"typeName":"AWS::Other::Type","properties":{}}"#.into(),
        };
        let message = error_msg(src.resolve());
        assert!(message.contains("AWS::Lambda::Function") && message.contains("AWS::Other::Type"));
    }

    #[test]
    fn resolve_falls_back_to_schema_type_name() {
        let src = AdditionalSchemaSource {
            type_name: None,
            schema: r#"{"typeName":"AWS::Lambda::Function","properties":{}}"#.into(),
        };
        let (type_name, _) = src.resolve().expect("valid schema resolves");
        assert_eq!(type_name, "AWS::Lambda::Function");
    }

    #[test]
    fn resolve_rejects_invalid_json() {
        let src =
            AdditionalSchemaSource { type_name: Some("AWS::Lambda::Function".into()), schema: "{ not json ".into() };
        let message = error_msg(src.resolve());
        assert!(message.contains("Invalid additional schema"));
    }

    #[test]
    fn resolve_rejects_json_beyond_the_default_parser_depth_limit() {
        const SERDE_JSON_DEFAULT_DEPTH_LIMIT: usize = 128;
        let nesting = SERDE_JSON_DEFAULT_DEPTH_LIMIT + 1;
        let schema = format!("{}null{}", "[".repeat(nesting), "]".repeat(nesting));
        let src = AdditionalSchemaSource { type_name: Some("AWS::Test::Deep".into()), schema };

        let message = error_msg(src.resolve());

        assert!(message.contains("recursion limit exceeded"), "unexpected error: {message}");
    }

    #[test]
    fn resolve_rejects_non_object() {
        let src = AdditionalSchemaSource { type_name: Some("AWS::Lambda::Function".into()), schema: "42".into() };
        let message = error_msg(src.resolve());
        assert!(message.contains("expected a JSON object"));
    }

    #[test]
    fn resolve_rejects_missing_type_name() {
        let src = AdditionalSchemaSource { type_name: None, schema: r#"{"properties":{}}"#.into() };
        let message = error_msg(src.resolve());
        assert!(message.contains("missing a resource type name"));
    }

    #[test]
    fn resolve_error_names_an_unnamed_source() {
        let src = AdditionalSchemaSource { type_name: None, schema: "{ not json ".into() };
        let message = error_msg(src.resolve());
        assert!(message.contains("<unnamed>"));
    }

    #[test]
    fn serializes_without_the_type_name_key_when_absent() {
        let src = AdditionalSchemaSource { type_name: None, schema: "{}".into() };
        let json = serde_json::to_value(&src).expect("serializes");
        assert_eq!(json, serde_json::json!({ "schema": "{}" }), "an absent type name is omitted from the wire form");
    }

    #[test]
    fn serializes_the_type_name_key_under_its_camel_case_name_when_present() {
        let src = AdditionalSchemaSource { type_name: Some("AWS::Lambda::Function".into()), schema: "{}".into() };
        let json = serde_json::to_value(&src).expect("serializes");
        assert_eq!(json, serde_json::json!({ "typeName": "AWS::Lambda::Function", "schema": "{}" }));
    }

    #[test]
    fn deserializes_a_missing_type_name_to_none() {
        let src: AdditionalSchemaSource = serde_json::from_str(r#"{"schema":"{}"}"#).expect("deserializes");
        assert_eq!(src.type_name, None, "a wire form without typeName yields an absent type name");
        assert_eq!(src.schema, "{}");
    }

    #[test]
    fn deserializes_a_present_type_name_from_its_camel_case_key() {
        let src: AdditionalSchemaSource =
            serde_json::from_str(r#"{"typeName":"AWS::Lambda::Function","schema":"{}"}"#).expect("deserializes");
        assert_eq!(src.type_name.as_deref(), Some("AWS::Lambda::Function"));
    }

    #[test]
    fn round_trips_through_json_in_both_states() {
        for original in [
            AdditionalSchemaSource { type_name: None, schema: r#"{"typeName":"AWS::S3::Bucket"}"#.into() },
            AdditionalSchemaSource { type_name: Some("AWS::S3::Bucket".into()), schema: "{}".into() },
        ] {
            let json = serde_json::to_string(&original).expect("serializes");
            let restored: AdditionalSchemaSource = serde_json::from_str(&json).expect("deserializes");
            assert_eq!(restored.type_name, original.type_name);
            assert_eq!(restored.schema, original.schema);
        }
    }
}
