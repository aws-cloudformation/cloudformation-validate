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

use diagnostics::DetailLevel;
use rules::{FilterConfig, RuleFilterConfig, Severity};
use template_model::PseudoParameterOverrides;
use validation_engine::{EngineConfig, ValidationEngine, catch_panics, validate_bytes_with_path};

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
#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
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

fn parse_engine_config(config_json: &str) -> Result<EngineConfig, ValidationError> {
    serde_json::from_str(config_json).map_err(|e| ValidationError::new(format!("invalid engine config JSON: {e}")))
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
    pub fn new() -> Arc<Self> {
        Arc::new(Self { inner: schema_validator::SchemaValidator::new() })
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
                        let config = parse_engine_config(&config_json)?;
                        let engine = $constructor(config).map_err(ValidationError::new)?;
                        Ok(Arc::new(Self { engine, schema_validator: schema_validator::SchemaValidator::new() }))
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

impl_go_engine!(GoRegoEngine, rego_engine::RegoEngine, rego_engine::RegoEngine::new);
impl_go_engine!(GoCelEngine, cel_engine::CelEngine, cel_engine::CelEngine::new);

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
