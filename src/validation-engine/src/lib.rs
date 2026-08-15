#[cfg(feature = "uniffi-bindings")]
uniffi::setup_scaffolding!();

pub mod aws_api;
pub mod engine;
pub mod guard;
pub(crate) mod step_functions;

pub use aws_api::{
    AwsApiOperationKind, AwsApiRequest, AwsApiRequestContext, AwsApiRequestValidation, AwsApiRequestValidationStatus,
    AwsApiTemplateSource, AwsApiValue, DetailedAwsApiRequestValidation, StandardAwsApiRequestValidation,
    validate_aws_api_request, validate_aws_api_request_with_path,
};
pub use engine::{
    EngineConfig, EngineType, ExternalRuleSource, ValidateConfig, ValidationEngine, ValidationError, build_rule_list,
    catch_panics, extract_diagnostics, make_resource_diagnostic, make_resource_diagnostic_at_source,
    semantic_model_to_input_json, validate_bytes_with_path, validate_catching_panics,
};

#[cfg(any(test, feature = "test"))]
pub use engine::validate_bytes;
