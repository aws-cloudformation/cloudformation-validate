#[cfg(feature = "uniffi-bindings")]
uniffi::setup_scaffolding!();

pub mod engine;
pub mod guard;
pub(crate) mod step_functions;

pub use engine::{
    AdditionalSchemaSource, EngineConfig, EngineType, ExternalRuleSource, ValidateConfig, ValidationEngine,
    ValidationError, build_rule_list, catch_panics, extract_diagnostics, make_resource_diagnostic,
    schema_validator_from_config, semantic_model_to_input_json, validate_bytes_with_path, validate_catching_panics,
};

#[cfg(any(test, feature = "test"))]
pub use engine::validate_bytes;
