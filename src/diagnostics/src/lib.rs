#[cfg(feature = "uniffi-bindings")]
uniffi::setup_scaffolding!();

pub mod builder;
pub mod detail_level;
pub mod diagnostic;
pub mod filter;
pub mod helpers;
pub mod metrics;
pub mod phase;

pub use builder::{RegisteredDiagnostic, diagnostic_from_parse_defect};
pub use detail_level::DetailLevel;
pub use diagnostic::{
    BudgetExhaustionRecord, DetailedDiagnostic, DetailedReport, Diagnostic, Entity, PerformanceMetrics,
    RelatedResource, ReportMetadata, ReportStatus, ResourceRef, StandardDiagnostic, StandardReport, Summary,
    ValidationReport, ViolationContext,
};
pub use filter::{Filterable, apply_filters};
pub use helpers::{resolve_section_span, source_for_rule};
pub use metrics::{PhaseMetric, phase_metric};
pub use phase::Phase;
