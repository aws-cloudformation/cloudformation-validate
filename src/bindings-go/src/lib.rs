//! Go bindings for cloudformation-validate.
//!
//! Unlike the JVM and Python bindings, which export the full typed surface
//! through uniffi records, this crate exposes a compact JSON-over-FFI surface:
//! engine objects are native, and configs and reports cross the boundary as
//! JSON strings in the same serde shapes the CLI emits. This keeps the crate
//! on the released uniffi version that `uniffi-bindgen-go` supports, while the
//! hand-maintained Go package decodes the JSON into typed Go structs.

uniffi::setup_scaffolding!();

use std::collections::HashMap;
use std::sync::Arc;

use data_source::AdditionalSchemaSource;
use diagnostics::DetailLevel;
use rules::{FilterConfig, RuleFilterConfig, Severity};
use schema_validator::SchemaValidatorConfig;
use template_model::PseudoParameterOverrides;
use validation_engine::{EngineConfig, ExternalRuleSource, ValidationEngine, catch_panics, validate_bytes_with_path};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ValidationError {
    #[error("{msg}")]
    Engine { msg: String },
}

impl ValidationError {
    fn new(msg: impl std::fmt::Display) -> Self {
        Self::Engine { msg: msg.to_string() }
    }
}

/// Maps a caught panic message to the Go error type, so an internal panic
/// surfaces to Go as a returned `ValidationError` instead of unwinding across
/// the FFI boundary. Pair with [`catch_panics`] at the fallible entry points.
fn panic_to_error(message: String) -> ValidationError {
    ValidationError::Engine { msg: format!("Internal validation error: {message}") }
}

/// Per-call validation options, deserialized from the JSON produced by the Go
/// wrapper. Field names and defaults mirror the core `ValidateConfig`.
///
/// Unknown keys are rejected: the Go structs and this struct are two
/// hand-maintained halves of one wire contract, so a field that drifts on
/// either side must surface as an error instead of being silently dropped and
/// leaving the option with no effect.
#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
struct ValidateOptions {
    include: RuleFilterConfig,
    exclude: RuleFilterConfig,
    severity_level: Option<Severity>,
    parameter_overrides: HashMap<String, String>,
    pseudo_parameter_overrides: PseudoParameterOverrides,
    strict: Option<bool>,
    disable_builtin_rules: Option<bool>,
}

impl ValidateOptions {
    fn parse(options_json: &str) -> Result<Self, ValidationError> {
        serde_json::from_str(options_json).map_err(|e| ValidationError::new(format!("invalid options JSON: {e}")))
    }

    fn to_core(&self, detail_level: DetailLevel) -> validation_engine::ValidateConfig {
        let defaults = validation_engine::ValidateConfig::default();
        validation_engine::ValidateConfig {
            filters: FilterConfig::new(self.include.clone(), self.exclude.clone()),
            detail_level,
            severity_level: self.severity_level.unwrap_or(defaults.severity_level),
            parameter_overrides: self.parameter_overrides.clone(),
            pseudo_parameter_overrides: self.pseudo_parameter_overrides.clone(),
            strict: self.strict.unwrap_or(defaults.strict),
            disable_builtin_rules: self.disable_builtin_rules.unwrap_or(defaults.disable_builtin_rules),
        }
    }
}

#[cfg(test)]
fn parse_engine_config(config_json: &str) -> Result<EngineConfig, ValidationError> {
    EngineOptions::parse(config_json).map(EngineOptions::into_core)
}

/// Engine construction options, deserialized from the JSON produced by the Go
/// wrapper. A strict mirror of the core `EngineConfig`: rejecting unknown keys
/// turns a drifted field name into an error rather than an engine that silently
/// loads none of the caller's rules.
#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
struct EngineOptions {
    custom_rules: Vec<RuleSourceOptions>,
    guard_rules: Vec<RuleSourceOptions>,
    schema_validator_config: Option<SchemaValidatorOptionsInline>,
}

/// One external rule source, mirroring the core `ExternalRuleSource`.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSourceOptions {
    name: String,
    content: String,
}

/// One additional overlay schema, mirroring the core `AdditionalSchemaSource`.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SchemaSourceOptions {
    #[serde(default)]
    type_name: Option<String>,
    schema: String,
}

/// Inline schema validator config nested inside engine options.
#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
struct SchemaValidatorOptionsInline {
    additional_schemas: Vec<SchemaSourceOptions>,
}

impl EngineOptions {
    fn parse(config_json: &str) -> Result<Self, ValidationError> {
        serde_json::from_str(config_json).map_err(|e| ValidationError::new(format!("invalid engine config JSON: {e}")))
    }

    #[cfg(test)]
    fn into_core(self) -> EngineConfig {
        EngineConfig {
            custom_rules: self.custom_rules.into_iter().map(ExternalRuleSource::from).collect(),
            guard_rules: self.guard_rules.into_iter().map(ExternalRuleSource::from).collect(),
            schema_validator_config: self.schema_validator_config.map(|sv| SchemaValidatorConfig {
                additional_schemas: sv.additional_schemas.into_iter().map(AdditionalSchemaSource::from).collect(),
            }),
        }
    }
}

impl From<RuleSourceOptions> for ExternalRuleSource {
    fn from(options: RuleSourceOptions) -> Self {
        Self { name: options.name, content: options.content }
    }
}

impl From<SchemaSourceOptions> for AdditionalSchemaSource {
    fn from(options: SchemaSourceOptions) -> Self {
        Self { type_name: options.type_name, schema: options.schema }
    }
}

/// Per-engine schema validator configuration, deserialized from the JSON produced
/// by the Go wrapper. Strict mirror of the shared [`SchemaValidatorConfig`]:
/// rejecting unknown keys turns a drifted field name into an error rather than
/// silently ignoring additional schemas.
#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
struct SchemaValidatorOptions {
    additional_schemas: Vec<SchemaSourceOptions>,
}

impl SchemaValidatorOptions {
    fn parse(config_json: &str) -> Result<Self, ValidationError> {
        serde_json::from_str(config_json)
            .map_err(|e| ValidationError::new(format!("invalid schema validator config JSON: {e}")))
    }

    fn into_core(self) -> SchemaValidatorConfig {
        SchemaValidatorConfig {
            additional_schemas: self.additional_schemas.into_iter().map(AdditionalSchemaSource::from).collect(),
        }
    }
}

fn parse_schema_config(config_json: &str) -> Result<SchemaValidatorConfig, ValidationError> {
    SchemaValidatorOptions::parse(config_json).map(SchemaValidatorOptions::into_core)
}

fn to_json<T: serde::Serialize>(value: &T) -> Result<String, ValidationError> {
    serde_json::to_string(value).map_err(|e| ValidationError::new(format!("failed to serialize result: {e}")))
}

#[derive(uniffi::Object)]
pub struct GoSchemaValidator {
    inner: schema_validator::SchemaValidator,
}

#[uniffi::export]
impl GoSchemaValidator {
    #[uniffi::constructor]
    pub fn new(schema_config_json: String) -> Result<Arc<Self>, ValidationError> {
        catch_panics(
            || {
                let schema_config = parse_schema_config(&schema_config_json)?;
                let inner = schema_validator::SchemaValidator::new(schema_config).map_err(ValidationError::new)?;
                Ok(Arc::new(Self { inner }))
            },
            panic_to_error,
        )
    }

    /// Returns the schema validator's rules as a JSON array of rule infos.
    pub fn list_rules_json(&self) -> Result<String, ValidationError> {
        catch_panics(|| to_json(&self.inner.list_rules()), panic_to_error)
    }

    pub fn schema_count(&self) -> u32 {
        self.inner.schema_count() as u32
    }

    /// Validates a parsed model against the provider schemas and returns the
    /// diagnostics as a JSON array of standard diagnostics.
    pub fn validate_json(&self, model: &GoSemanticModel, region: Option<String>) -> Result<String, ValidationError> {
        catch_panics(
            || {
                let result = self.inner.validate(&model.model, region.as_deref());
                let diagnostics: Vec<_> = result.diagnostics.iter().map(|d| d.to_standard()).collect();
                to_json(&diagnostics)
            },
            panic_to_error,
        )
    }
}

macro_rules! impl_go_engine {
    ($GoType:ident, $InnerEngine:ty, $constructor:path) => {
        #[derive(uniffi::Object)]
        pub struct $GoType {
            engine: $InnerEngine,
            schema_validator: schema_validator::SchemaValidator,
        }

        #[uniffi::export]
        impl $GoType {
            /// Builds an engine from a JSON engine config (`{}` for defaults;
            /// `customRules` / `guardRules` load external rule sources).
            #[uniffi::constructor]
            pub fn new(config_json: String) -> Result<Arc<Self>, ValidationError> {
                catch_panics(
                    || {
                        let engine_options = EngineOptions::parse(&config_json)?;
                        let schema_config = engine_options
                            .schema_validator_config
                            .map(|sv| SchemaValidatorConfig {
                                additional_schemas: sv
                                    .additional_schemas
                                    .into_iter()
                                    .map(AdditionalSchemaSource::from)
                                    .collect(),
                            })
                            .unwrap_or_default();
                        let config = EngineConfig {
                            custom_rules: engine_options
                                .custom_rules
                                .into_iter()
                                .map(ExternalRuleSource::from)
                                .collect(),
                            guard_rules: engine_options.guard_rules.into_iter().map(ExternalRuleSource::from).collect(),
                            schema_validator_config: None,
                        };
                        let schema_validator =
                            schema_validator::SchemaValidator::new(schema_config).map_err(ValidationError::new)?;
                        let engine = $constructor(config, &schema_validator).map_err(ValidationError::new)?;
                        Ok(Arc::new(Self { engine, schema_validator }))
                    },
                    panic_to_error,
                )
            }

            /// Validates a template and returns the standard report as JSON.
            pub fn validate_standard_json(
                &self,
                template: Vec<u8>,
                options_json: String,
                file_path: String,
            ) -> Result<String, ValidationError> {
                catch_panics(
                    || {
                        let config = ValidateOptions::parse(&options_json)?.to_core(DetailLevel::Standard);
                        let report = validate_bytes_with_path(
                            &self.engine,
                            &self.schema_validator,
                            &template,
                            config,
                            file_path,
                        )
                        .map_err(ValidationError::new)?;
                        to_json(&report.to_standard())
                    },
                    panic_to_error,
                )
            }

            /// Validates a template and returns the detailed report as JSON.
            pub fn validate_detailed_json(
                &self,
                template: Vec<u8>,
                options_json: String,
                file_path: String,
            ) -> Result<String, ValidationError> {
                catch_panics(
                    || {
                        let config = ValidateOptions::parse(&options_json)?.to_core(DetailLevel::Detailed);
                        let report = validate_bytes_with_path(
                            &self.engine,
                            &self.schema_validator,
                            &template,
                            config,
                            file_path,
                        )
                        .map_err(ValidationError::new)?;
                        to_json(&report.to_detailed())
                    },
                    panic_to_error,
                )
            }

            /// Returns the engine's rules as a JSON array of rule infos.
            pub fn list_rules_json(&self) -> Result<String, ValidationError> {
                catch_panics(|| to_json(&self.engine.list_rules()), panic_to_error)
            }

            pub fn engine_name(&self) -> String {
                self.engine.engine_name().to_string()
            }
        }
    };
}

impl_go_engine!(GoRegoEngine, rego_engine::RegoEngine, rego_engine::RegoEngine::new_with_schema_validator);
impl_go_engine!(GoCelEngine, cel_engine::CelEngine, cel_engine::CelEngine::new_with_schema_validator);

#[derive(uniffi::Object)]
pub struct GoSemanticModel {
    model: Arc<template_model::SemanticModel>,
}

#[uniffi::export]
impl GoSemanticModel {
    #[uniffi::constructor]
    pub fn parse(template: Vec<u8>) -> Result<Arc<Self>, ValidationError> {
        catch_panics(
            || {
                let result = template_model::SemanticModel::parse(&template, Default::default())
                    .map_err(ValidationError::new)?;
                Ok(Arc::new(Self { model: Arc::new(result.model) }))
            },
            panic_to_error,
        )
    }

    /// Returns the resolved resources as a JSON object keyed by logical ID.
    pub fn resources_json(&self) -> Result<String, ValidationError> {
        catch_panics(|| to_json(&self.model.resources), panic_to_error)
    }

    /// Returns the template parameters as a JSON object keyed by name.
    pub fn parameters_json(&self) -> Result<String, ValidationError> {
        catch_panics(|| to_json(&self.model.parameters), panic_to_error)
    }

    /// Returns the template outputs as a JSON object keyed by name.
    pub fn outputs_json(&self) -> Result<String, ValidationError> {
        catch_panics(|| to_json(&self.model.outputs), panic_to_error)
    }

    pub fn conditions(&self) -> Result<Vec<String>, ValidationError> {
        catch_panics(|| Ok(self.model.conditions.names().map(String::from).collect()), panic_to_error)
    }

    pub fn transforms(&self) -> Result<Vec<String>, ValidationError> {
        catch_panics(|| Ok(self.model.transforms.clone()), panic_to_error)
    }

    pub fn format_version(&self) -> Option<String> {
        self.model.format_version.clone()
    }

    pub fn description(&self) -> Option<String> {
        self.model.description.clone()
    }

    /// Returns the full diagnostic model as JSON.
    pub fn to_diagnostic_model_json(&self) -> Result<String, ValidationError> {
        catch_panics(|| to_json(&self.model.to_diagnostic_json()), panic_to_error)
    }

    /// Returns the source span for a template path as JSON, or None when the
    /// path has no recorded location.
    pub fn source_location_json(&self, path: String) -> Result<Option<String>, ValidationError> {
        catch_panics(
            || match self.model.source_location(&path) {
                Some(span) => Ok(Some(to_json(span)?)),
                None => Ok(None),
            },
            panic_to_error,
        )
    }
}

#[uniffi::export]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use template_model::EntityType;

    /// Neither options struct nor `EngineConfig` implements `Debug`, so failure
    /// paths are asserted through these helpers instead of `expect_err`.
    fn expect_validate_options_error(options_json: &str) -> ValidationError {
        match ValidateOptions::parse(options_json) {
            Err(error) => error,
            Ok(_) => panic!("expected {options_json} to be rejected"),
        }
    }

    fn expect_engine_config_error(config_json: &str) -> ValidationError {
        match parse_engine_config(config_json) {
            Err(error) => error,
            Ok(_) => panic!("expected {config_json} to be rejected"),
        }
    }

    /// The JSON a fully populated Go `ValidateConfig` marshals to. Kept in sync
    /// with `FULL_VALIDATE_CONFIG_JSON` in `go/config_test.go`, which asserts
    /// the Go structs produce exactly this document — together the two tests pin
    /// the wire contract from both sides.
    const FULL_VALIDATE_OPTIONS_JSON: &str = r#"{
        "include": {
            "ids": ["E3012"],
            "categories": ["Security"],
            "idRanges": [{"prefix": "E", "start": 3000, "end": 3099}],
            "idPatterns": ["^W30.*$"],
            "resourceIds": [{"ruleId": "W3010", "resourceId": "MyBucket"}],
            "logicalIds": [{"ruleId": "W2501", "logicalId": "MyPassword", "entityType": "Parameter"}],
            "resourceTypes": [{"ruleId": "I9040", "resourceType": "AWS::S3::Bucket"}],
            "services": [{"ruleId": "I3011", "service": "AWS::RDS"}]
        },
        "exclude": {
            "ids": ["I9003"],
            "categories": ["Best Practice"],
            "idRanges": [{"prefix": "I", "start": 9000, "end": 9099}],
            "idPatterns": ["^I90.*$"],
            "resourceIds": [{"resourceId": "MyQueue"}],
            "logicalIds": [{"logicalId": "MyOutput"}],
            "resourceTypes": [{"resourceType": "AWS::SQS::Queue"}],
            "services": [{"service": "AWS::SQS"}]
        },
        "severityLevel": "WARN",
        "parameterOverrides": {"Environment": "prod"},
        "pseudoParameterOverrides": {
            "accountId": "123456789012",
            "notificationArns": "arn:aws:sns:us-west-2:123456789012:topic",
            "partition": "aws",
            "region": "us-west-2",
            "stackId": "arn:aws:cloudformation:us-west-2:123456789012:stack/my-stack/id",
            "stackName": "my-stack",
            "urlSuffix": "amazonaws.com"
        },
        "strict": true,
        "disableBuiltinRules": false
    }"#;

    #[test]
    fn validate_options_parses_every_field_the_go_wrapper_sends() {
        let options = ValidateOptions::parse(FULL_VALIDATE_OPTIONS_JSON).expect("full config must parse");

        assert_eq!(vec!["E3012"], options.include.ids);
        assert_eq!(vec!["Security"], options.include.categories);
        assert_eq!("E", options.include.id_ranges[0].prefix);
        assert_eq!(3000, options.include.id_ranges[0].start);
        assert_eq!(3099, options.include.id_ranges[0].end);
        assert_eq!(vec!["^W30.*$"], options.include.id_patterns);
        assert_eq!("MyBucket", options.include.resource_ids[0].resource_id);
        assert_eq!(Some("W3010"), options.include.resource_ids[0].rule_id.as_deref());
        assert_eq!("MyPassword", options.include.logical_ids[0].logical_id);
        assert_eq!(Some(EntityType::Parameter), options.include.logical_ids[0].entity_type);
        assert_eq!("AWS::S3::Bucket", options.include.resource_types[0].resource_type);
        assert_eq!("AWS::RDS", options.include.services[0].service);

        assert_eq!(vec!["I9003"], options.exclude.ids);
        assert_eq!("MyQueue", options.exclude.resource_ids[0].resource_id);
        assert_eq!(None, options.exclude.logical_ids[0].rule_id);
        assert_eq!("AWS::SQS::Queue", options.exclude.resource_types[0].resource_type);
        assert_eq!("AWS::SQS", options.exclude.services[0].service);

        assert_eq!(Some(Severity::Warn), options.severity_level);
        assert_eq!(Some(&"prod".to_string()), options.parameter_overrides.get("Environment"));
        assert_eq!(Some("us-west-2"), options.pseudo_parameter_overrides.region.as_deref());
        assert_eq!(Some("123456789012"), options.pseudo_parameter_overrides.account_id.as_deref());
        assert_eq!(Some("amazonaws.com"), options.pseudo_parameter_overrides.url_suffix.as_deref());
        assert_eq!(Some(true), options.strict);
        assert_eq!(Some(false), options.disable_builtin_rules);
    }

    #[test]
    fn empty_object_yields_core_defaults() {
        let defaults = validation_engine::ValidateConfig::default();
        let config = ValidateOptions::parse("{}").expect("an empty object must parse").to_core(DetailLevel::Detailed);

        assert_eq!(defaults.severity_level, config.severity_level);
        assert_eq!(defaults.strict, config.strict);
        assert_eq!(defaults.disable_builtin_rules, config.disable_builtin_rules);
        assert!(config.parameter_overrides.is_empty());
        assert_eq!(DetailLevel::Detailed, config.detail_level);
    }

    #[test]
    fn unknown_validate_option_is_rejected() {
        let error = expect_validate_options_error(r#"{"severityLevl": "WARN"}"#);

        assert!(error.to_string().contains("severityLevl"), "error must name the offending key: {error}");
    }

    #[test]
    fn engine_options_parse_rule_sources() {
        let config = parse_engine_config(
            r#"{
                "customRules": [{"name": "s3.json", "content": "{}"}],
                "guardRules": [{"name": "compliance.guard", "content": "let x = 1"}]
            }"#,
        )
        .expect("engine config must parse");

        assert_eq!(1, config.custom_rules.len());
        assert_eq!("s3.json", config.custom_rules[0].name);
        assert_eq!("compliance.guard", config.guard_rules[0].name);
        assert_eq!("let x = 1", config.guard_rules[0].content);
    }

    #[test]
    fn empty_engine_config_loads_no_external_rules() {
        let config = parse_engine_config("{}").expect("an empty object must parse");

        assert!(config.custom_rules.is_empty());
        assert!(config.guard_rules.is_empty());
    }

    #[test]
    fn unknown_engine_option_is_rejected() {
        let error = expect_engine_config_error(r#"{"guardRule": []}"#);

        assert!(error.to_string().contains("guardRule"), "error must name the offending key: {error}");
    }

    #[test]
    fn unknown_rule_source_field_is_rejected() {
        let error = expect_engine_config_error(r#"{"guardRules": [{"name": "a.guard", "text": "let x = 1"}]}"#);

        assert!(error.to_string().contains("text"), "error must name the offending key: {error}");
    }

    #[test]
    fn malformed_json_reports_an_engine_error() {
        let error = expect_engine_config_error("not json");

        assert!(
            error.to_string().contains("invalid engine config JSON"),
            "error must identify the failing input: {error}"
        );
    }

    #[test]
    fn schema_validator_options_parse_additional_schemas() {
        let config = parse_schema_config(
            r#"{
                "additionalSchemas": [{"typeName": "AWS::Test::Type", "schema": "{}"}]
            }"#,
        )
        .expect("schema config must parse");

        assert_eq!(1, config.additional_schemas.len());
        assert_eq!(Some("AWS::Test::Type"), config.additional_schemas[0].type_name.as_deref());
    }

    #[test]
    fn schema_validator_options_default_the_type_name_when_the_key_is_omitted() {
        let config = parse_schema_config(
            r#"{
                "additionalSchemas": [{"schema": "{\"typeName\":\"AWS::Test::Type\"}"}]
            }"#,
        )
        .expect("a schema source without an explicit typeName must parse");

        assert_eq!(1, config.additional_schemas.len());
        assert_eq!(
            None,
            config.additional_schemas[0].type_name.as_deref(),
            "an omitted typeName key deserializes to an absent type name, not an empty string"
        );
    }

    #[test]
    fn empty_schema_config_yields_no_overlays() {
        let config = parse_schema_config("{}").expect("an empty object must parse");
        assert!(config.additional_schemas.is_empty());
    }

    #[test]
    fn unknown_schema_config_field_is_rejected() {
        let error = match parse_schema_config(r#"{"additonalSchemas": []}"#) {
            Err(e) => e,
            Ok(_) => panic!("misspelled field must be rejected"),
        };
        assert!(error.to_string().contains("additonalSchemas"), "error must name the offending key: {error}");
    }

    #[test]
    fn malformed_schema_config_json_reports_error() {
        let error = match parse_schema_config("not json") {
            Err(e) => e,
            Ok(_) => panic!("invalid JSON must fail"),
        };
        assert!(
            error.to_string().contains("invalid schema validator config JSON"),
            "error must identify the failing input: {error}"
        );
    }
}
