#[cfg(feature = "uniffi-bindings")]
uniffi::setup_scaffolding!();

pub mod detail_level;
pub mod diagnostic;
pub mod filter;
pub mod helpers;
pub mod json_value;
pub mod metrics;
pub mod phase;
pub mod span;

pub use detail_level::DetailLevel;
pub use diagnostic::{
    DetailedDiagnostic, DetailedReport, Diagnostic, PerformanceMetrics, RelatedResource,
    ReportMetadata, ReportStatus, ResourceRef, StandardDiagnostic, StandardReport, Summary,
    ValidationReport, ViolationContext,
};
pub use filter::{Filterable, apply_filters};
pub use helpers::{
    SAM_TRANSFORM_ERROR_PREFIX, is_sam_transform_error_message, resolve_section_span,
    source_for_rule,
};
pub use json_value::JsonValue;
pub use metrics::{PhaseMetric, phase_metric};
pub use phase::Phase;
pub use span::{SourceSpan, SpanProvider, UNKNOWN_SPAN};
