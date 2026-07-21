#[cfg(feature = "uniffi-bindings")]
uniffi::setup_scaffolding!();

pub mod builder;
pub mod detail_level;
pub mod diagnostic;
pub mod filter;
pub mod helpers;
pub mod json_value;
pub mod message;
pub mod metrics;
pub mod phase;
pub mod span;

pub use builder::RegisteredDiagnostic;
pub use detail_level::DetailLevel;
pub use diagnostic::{
    DetailedDiagnostic, DetailedReport, Diagnostic, Entity, PerformanceMetrics, RelatedResource, ReportMetadata,
    ReportStatus, ResourceRef, StandardDiagnostic, StandardReport, Summary, ValidationReport, ViolationContext,
};
pub use filter::{Filterable, apply_filters};
pub use helpers::{
    SAM_TRANSFORM_ERROR_PREFIX, SAM_TRANSFORM_ERROR_RULE_ID, entity_identity, is_sam_transform_error_message,
    resolve_section_span, source_for_rule,
};
pub use json_value::JsonValue;
pub use message::{quote, render_str_list, render_value, render_value_list};
pub use metrics::{PhaseMetric, phase_metric};
pub use phase::Phase;
pub use rules::{EntityType, TopLevelSection};
pub use span::{SourceSpan, SpanProvider, UNKNOWN_SPAN, span_to_option};
