#[cfg(feature = "uniffi-bindings")]
uniffi::setup_scaffolding!();

pub mod aws_cli;
pub mod engine;
pub mod guard;
pub(crate) mod step_functions;

pub use aws_cli::{
    AwsCliCommand, AwsCliCommandContext, AwsCliCommandValidation, AwsCliCommandValidationStatus, AwsCliOperationKind,
    AwsCliTemplateSource, AwsCliValue, validate_aws_cli_command, validate_aws_cli_command_with_path,
};
pub use engine::{
    CompositeEngineConfig, DIAGNOSTIC_SOURCE_PATH_FIELD, EngineConfig, EngineType, ExternalRuleSource, ValidateConfig,
    ValidationEngine, ValidationError, build_rule_list, catch_panics, extract_diagnostics,
    extract_diagnostics_from_value, make_resource_diagnostic, make_resource_diagnostic_at_source,
    semantic_model_to_input_json, validate_bytes_with_path, validate_catching_panics,
};

#[cfg(any(test, feature = "test"))]
pub use engine::validate_bytes;
