#[cfg(feature = "uniffi-bindings")]
uniffi::setup_scaffolding!();

pub mod category;
pub mod filter;
pub mod helpers;
pub mod pattern;
pub mod registry;
pub mod schedule;
pub mod severity;

pub use category::Category;
pub use filter::{FilterConfig, IdRange, ResourceIdFilter, ResourceTypeFilter, RuleFilterConfig};
pub use helpers::{
    AMI_ID_PATTERN, AVAILABILITY_ZONE_PATTERN, CAA_RECORD_PATTERN, IAM_ROLE_ARN_PATTERN, IAM_ROLE_ARN_RULE_PATTERN,
    MX_RECORD_PATTERN, SECURITY_GROUP_NAME_PATTERN, category_for_rule_id, format_rule_for_format, is_fatal_rule,
    section_for_rule_id,
};
pub use pattern::{
    CompiledPattern, anchor_allowed_pattern, compile as compile_pattern, default_matches_pattern, is_service_valid,
};
pub use registry::{
    RULE_REGISTRY, RuleDefinition, RuleInfo, RuleMetadataEntry, RuleOrigin, build_rule_metadata_map, lookup_rule,
};
pub use schedule::schedule_expression_errors;
pub use severity::Severity;
