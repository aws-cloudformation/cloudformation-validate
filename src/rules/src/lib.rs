#[cfg(feature = "uniffi-bindings")]
uniffi::setup_scaffolding!();

pub mod category;
pub mod filter;
pub mod helpers;
pub mod registry;
pub mod severity;

pub use category::Category;
pub use filter::{
    FilterConfig, IdRange, LogicalIdFilter, ResourceIdFilter, ResourceTypeFilter, RuleFilterConfig, ServiceFilter,
};
pub use helpers::{
    CUSTOM_RULE_ID_SEPARATORS, category_for_rule_id, format_rule_for_format, is_fatal_rule, is_valid_custom_rule_id,
    rule_number, section_for_rule_id,
};
pub use registry::{
    RULE_REGISTRY, RuleDefinition, RuleInfo, RuleMetadataEntry, RuleOrigin, build_rule_metadata_map, lookup_rule,
};
pub use severity::Severity;
