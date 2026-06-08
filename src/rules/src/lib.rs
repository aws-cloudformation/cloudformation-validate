#[cfg(feature = "uniffi-bindings")]
uniffi::setup_scaffolding!();

pub mod category;
pub mod filter;
pub mod helpers;
pub mod registry;
pub mod severity;

pub use category::Category;
pub use filter::{FilterConfig, IdRange, ResourceIdFilter, ResourceTypeFilter, RuleFilterConfig};
pub use helpers::{
    category_for_rule_id, format_rule_for_format, is_fatal_rule, section_for_rule_id,
};
pub use registry::{
    RULE_REGISTRY, RuleDefinition, RuleInfo, RuleMetadataEntry, RuleOrigin,
    build_rule_metadata_map, lookup_rule,
};
pub use severity::Severity;
