#[cfg(feature = "uniffi-bindings")]
uniffi::setup_scaffolding!();

pub mod engine;
pub mod guard;
pub(crate) mod step_functions;

#[doc(hidden)]
pub use schema_validator::OverlayCatalog;
#[doc(hidden)]
pub use schema_validator::SchemaValidator;

pub use engine::{
    AdditionalSchemaSource, EngineConfig, EngineType, ExternalRuleSource, SchemaValidatorConfig,
    SchemaValidatorConfigError, ValidateConfig, ValidationEngine, ValidationError, build_rule_list, catch_panics,
    extract_diagnostics, make_resource_diagnostic, semantic_model_to_input_json, validate_bytes_with_path,
    validate_catching_panics,
};

#[doc(hidden)]
pub use engine::build_overlay_catalog;

#[cfg(any(test, feature = "test"))]
pub use engine::validate_bytes;
