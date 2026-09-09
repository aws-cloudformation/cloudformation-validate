use crate::diagnostic::{
    Entity, PerformanceMetrics, RelatedResource, ReportMetadata, ReportStatus, ViolationContext,
    serialize_sorted_optional_map,
};
use crate::phase::Phase;
use rules::{RuleOrigin, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single validation finding in the public report shape: the targeted entity is
/// carried as a nested `entity` struct and the source location is flattened into
/// individual line/column fields. The enrichment fields - `documentation_url`,
/// `rule_description`, `phase`, and `context` - are carried only when a report is
/// projected at the detailed level; the standard level leaves them `None`, so they
/// are omitted from serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct Diagnostic {
    /// Identifier of the rule that produced this finding; its leading letter encodes the severity.
    pub rule_id: String,
    pub severity: Severity,
    pub message: String,
    /// Where the rule came from, such as a provider schema, the built-in engine, or a user-supplied rule.
    pub source: RuleOrigin,
    /// The named template entity this finding targets - a resource, parameter, output, mapping, condition, or template rule - if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub entity: Option<Entity>,
    /// Path to the offending property within the resource, such as 'Properties.Name'.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub property_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub suggested_fix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub category: Option<String>,
    /// Line in the source template where the finding begins (1-based).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub start_line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub start_column: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub end_line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub end_column: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub related_resources: Option<Vec<RelatedResource>>,
    /// Condition name to boolean assignment under which this finding applies, when it depends on template conditions.
    #[serde(default, skip_serializing_if = "Option::is_none", serialize_with = "serialize_sorted_optional_map")]
    #[cfg_attr(feature = "wasm-bindings", tsify(type = "Record<string, boolean>"))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub condition_scenario: Option<HashMap<String, bool>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub documentation_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub rule_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub phase: Option<Phase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub context: Option<ViolationContext>,
}

/// The serializable validation result: report metadata, performance metrics, and
/// the flattened diagnostics. Detailed-only per-diagnostic context and enrichment
/// are present only when the report was projected at the detailed level.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct ValidationReport {
    pub file_path: String,
    pub status: ReportStatus,
    pub version: String,
    pub metadata: ReportMetadata,
    pub performance: PerformanceMetrics,
    pub diagnostics: Vec<Diagnostic>,
}
