uniffi::setup_scaffolding!();

use std::collections::HashMap;
use std::sync::Arc;
use validation_engine::ValidationEngine;

pub use diagnostics::{
    DetailLevel, DetailedDiagnostic, DetailedReport, JsonValue, PerformanceMetrics, PhaseMetric, RelatedResource,
    ReportMetadata, ReportStatus, ResourceRef, SourceSpan, StandardDiagnostic, StandardReport, Summary,
    ViolationContext,
};
pub use rules::{IdRange, ResourceIdFilter, ResourceTypeFilter, RuleFilterConfig, RuleInfo, RuleOrigin, Severity};
pub use template_model::PseudoParameterOverrides;
pub use template_model::diagnostic::{
    ConditionalNull, DiagnosticCondition, DiagnosticForEachExpansion, DiagnosticImplication, DiagnosticModel,
    DiagnosticMutexGroup, DiagnosticOutput, DiagnosticResource, DiagnosticRule, DiagnosticRuleAssertion,
    DiagnosticTemplate, GetAttRef, IncomingRef, OutgoingRef, PathTarget, PathVariable, ReferenceEdge, ResolutionSource,
};
pub use template_model::model::{
    ConditionalNullEntry, ForEachExpansion, PathValuePair, ResolvedOutput, ResolvedResource, ResourceDiagnostics,
};
pub use template_model::resolver::{MapEntry, ParameterInfo, RefKind, ResolvedValue};
pub use validation_engine::{EngineConfig, EngineType, ExternalRuleSource};

#[derive(Debug, Clone, uniffi::Record)]
pub struct ValidateConfig {
    #[uniffi(default)]
    pub include: RuleFilterConfig,
    #[uniffi(default)]
    pub exclude: RuleFilterConfig,
    #[uniffi(default)]
    pub severity_level: Option<Severity>,
    #[uniffi(default)]
    pub parameter_overrides: HashMap<String, String>,
    #[uniffi(default)]
    pub pseudo_parameter_overrides: PseudoParameterOverrides,
    #[uniffi(default)]
    pub strict: Option<bool>,
    #[uniffi(default)]
    pub disable_builtin_rules: Option<bool>,
}

impl ValidateConfig {
    fn to_core(&self, detail_level: DetailLevel) -> validation_engine::ValidateConfig {
        let defaults = validation_engine::ValidateConfig::default();
        validation_engine::ValidateConfig {
            filters: rules::FilterConfig::new(self.include.clone(), self.exclude.clone()),
            detail_level,
            severity_level: self.severity_level.unwrap_or(defaults.severity_level),
            parameter_overrides: self.parameter_overrides.clone(),
            pseudo_parameter_overrides: self.pseudo_parameter_overrides.clone(),
            strict: self.strict.unwrap_or(defaults.strict),
            disable_builtin_rules: self.disable_builtin_rules.unwrap_or(defaults.disable_builtin_rules),
        }
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ValidationError {
    #[error("{msg}")]
    Engine { msg: String },
}

/// Maps a caught panic message to the JVM error type, so an internal panic
/// surfaces to Kotlin/Java as a catchable `ValidationError` instead of unwinding
/// across the FFI boundary. Pair with [`validation_engine::catch_panics`] at the
/// fallible entry points. (uniffi already converts uncaught panics on every
/// exported method into an `InternalException`; this upgrades the result to the
/// typed `ValidationError` callers handle.)
fn panic_to_error(message: String) -> ValidationError {
    ValidationError::Engine { msg: format!("Internal validation error: {message}") }
}

#[derive(uniffi::Record)]
pub struct JvmSchemaValidationResult {
    pub diagnostics: Vec<StandardDiagnostic>,
    pub metric: PhaseMetric,
}

#[derive(uniffi::Object)]
pub struct JvmSchemaValidator {
    inner: schema_validator::SchemaValidator,
}

#[uniffi::export]
impl JvmSchemaValidator {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self { inner: schema_validator::SchemaValidator::new() })
    }

    pub fn list_rules(&self) -> Result<Vec<RuleInfo>, ValidationError> {
        validation_engine::catch_panics(|| Ok(self.inner.list_rules()), panic_to_error)
    }

    pub fn schema_count(&self) -> u32 {
        self.inner.schema_count() as u32
    }

    pub fn validate(
        &self,
        model: &JvmSemanticModel,
        region: String,
    ) -> Result<JvmSchemaValidationResult, ValidationError> {
        validation_engine::catch_panics(
            || {
                let result = self.inner.validate(&model.model, &region);
                Ok(JvmSchemaValidationResult {
                    diagnostics: result.diagnostics.iter().map(|d| d.to_standard()).collect(),
                    metric: result.metric,
                })
            },
            panic_to_error,
        )
    }
}

macro_rules! impl_jvm_engine {
    ($JvmType:ident, $InnerEngine:ty, $constructor:path) => {
        #[derive(uniffi::Object)]
        pub struct $JvmType {
            engine: $InnerEngine,
            schema_validator: schema_validator::SchemaValidator,
        }

        #[uniffi::export]
        impl $JvmType {
            #[uniffi::constructor]
            pub fn new(config: EngineConfig) -> Result<Arc<Self>, ValidationError> {
                validation_engine::catch_panics(
                    || {
                        let engine =
                            $constructor(config).map_err(|e| ValidationError::Engine { msg: e.to_string() })?;
                        Ok(Arc::new(Self { engine, schema_validator: schema_validator::SchemaValidator::new() }))
                    },
                    panic_to_error,
                )
            }

            pub fn validate_standard(
                &self,
                template: Vec<u8>,
                config: ValidateConfig,
                file_path: String,
            ) -> Result<StandardReport, ValidationError> {
                validation_engine::catch_panics(
                    || {
                        let core_config = config.to_core(DetailLevel::Standard);
                        let report = validation_engine::validate_bytes_with_path(
                            &self.engine,
                            &self.schema_validator,
                            &template,
                            core_config,
                            file_path,
                        )
                        .map_err(|e| ValidationError::Engine { msg: e.to_string() })?;
                        Ok(report.to_standard())
                    },
                    panic_to_error,
                )
            }

            pub fn validate_detailed(
                &self,
                template: Vec<u8>,
                config: ValidateConfig,
                file_path: String,
            ) -> Result<DetailedReport, ValidationError> {
                validation_engine::catch_panics(
                    || {
                        let core_config = config.to_core(DetailLevel::Detailed);
                        let report = validation_engine::validate_bytes_with_path(
                            &self.engine,
                            &self.schema_validator,
                            &template,
                            core_config,
                            file_path,
                        )
                        .map_err(|e| ValidationError::Engine { msg: e.to_string() })?;
                        Ok(report.to_detailed())
                    },
                    panic_to_error,
                )
            }

            pub fn list_rules(&self) -> Result<Vec<RuleInfo>, ValidationError> {
                validation_engine::catch_panics(|| Ok(self.engine.list_rules()), panic_to_error)
            }

            pub fn engine_name(&self) -> String {
                self.engine.engine_name().to_string()
            }
        }
    };
}

impl_jvm_engine!(JvmRegoEngine, rego_engine::RegoEngine, rego_engine::RegoEngine::new);
impl_jvm_engine!(JvmCelEngine, cel_engine::CelEngine, cel_engine::CelEngine::new);

#[derive(uniffi::Object)]
pub struct JvmSemanticModel {
    model: Arc<template_model::SemanticModel>,
}

#[uniffi::export]
impl JvmSemanticModel {
    #[uniffi::constructor]
    pub fn parse(template: Vec<u8>) -> Result<Arc<Self>, ValidationError> {
        validation_engine::catch_panics(
            || {
                let result = template_model::SemanticModel::parse(&template, Default::default())
                    .map_err(|e| ValidationError::Engine { msg: e.to_string() })?;
                Ok(Arc::new(Self { model: Arc::new(result.model) }))
            },
            panic_to_error,
        )
    }

    pub fn resources(&self) -> Result<HashMap<String, template_model::model::ResolvedResource>, ValidationError> {
        validation_engine::catch_panics(|| Ok(self.model.resources.clone()), panic_to_error)
    }

    pub fn parameters(&self) -> Result<HashMap<String, template_model::resolver::ParameterInfo>, ValidationError> {
        validation_engine::catch_panics(|| Ok(self.model.parameters.clone()), panic_to_error)
    }

    pub fn outputs(&self) -> Result<HashMap<String, template_model::model::ResolvedOutput>, ValidationError> {
        validation_engine::catch_panics(|| Ok(self.model.outputs.clone()), panic_to_error)
    }

    pub fn conditions(&self) -> Result<Vec<String>, ValidationError> {
        validation_engine::catch_panics(
            || Ok(self.model.conditions.names().map(String::from).collect()),
            panic_to_error,
        )
    }

    pub fn transforms(&self) -> Result<Vec<String>, ValidationError> {
        validation_engine::catch_panics(|| Ok(self.model.transforms.clone()), panic_to_error)
    }

    pub fn format_version(&self) -> Option<String> {
        self.model.format_version.clone()
    }
    pub fn description(&self) -> Option<String> {
        self.model.description.clone()
    }

    pub fn to_diagnostic_model(&self) -> Result<template_model::diagnostic::DiagnosticModel, ValidationError> {
        validation_engine::catch_panics(|| Ok(self.model.to_diagnostic_json()), panic_to_error)
    }

    pub fn source_location(&self, path: String) -> Result<Option<SourceSpan>, ValidationError> {
        validation_engine::catch_panics(|| Ok(self.model.source_location(&path).copied()), panic_to_error)
    }
}

#[uniffi::export]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
