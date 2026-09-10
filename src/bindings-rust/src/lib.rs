#![doc = include_str!("../README.md")]

pub use cel_engine;
pub use data_source;
pub use diagnostics;
pub use rego_engine;
pub use rules;
pub use schema_validator;
pub use template_model;
pub use validation_engine;

pub use cel_engine::CelEngine;
pub use data_source::{AdditionalSchemaSource, SchemaSourceError};
pub use diagnostics::{DetailLevel, Diagnostic, ReportStatus, ValidationReport};
pub use rego_engine::RegoEngine;
pub use rules::{
    Category, FilterConfig, IdRange, LogicalIdFilter, ResourceIdFilter, ResourceTypeFilter, RuleFilterConfig,
    RuleOrigin, ServiceFilter, Severity,
};
pub use schema_validator::{
    OverlayCatalog, SchemaValidator, SchemaValidatorConfig, SchemaValidatorConfigError, prewarm_embedded_data,
};
pub use template_model::{ParseConfig, PseudoParameterOverrides, SemanticModel, SourceSpan};
pub use validation_engine::{
    EngineConfig, EngineType, ExternalRuleSource, ValidateConfig, ValidationEngine, ValidationError,
    validate_bytes_with_path, validate_catching_panics,
};

/// Returns the version of the published Rust facade.
#[must_use]
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
