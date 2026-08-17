//! Deterministic, thread-safe, deduplicating tracker for validation budget
//! exhaustions. Budget kinds form a finite enum — no unbounded per-path or
//! per-query detail is stored. The tracker is designed to be shared across
//! model construction (resolver, condition model) and downstream consumers
//! (schema validator, rule engines) through the `SemanticModel`.

use crate::consts::{
    MAX_ENUM_EXPANSION, MAX_FINGERPRINT_DEPTH, MAX_PARAM_COMBINATIONS, MAX_REQUIRED_PROPERTY_COMBINATIONS,
    MAX_RESOLVE_DEPTH, MAX_SAT_ITERATIONS, MAX_SCENARIO_COMBINATIONS, MAX_SCHEMA_MATCH_DEPTH,
    MAX_SCHEMA_SCENARIO_ASSIGNMENTS, MAX_SCHEMA_SCENARIO_MERGE_ATTEMPTS, MAX_TOTAL_SAT_ITERATIONS,
    MAX_TOTAL_SCENARIO_COMBINATIONS,
};
use std::collections::BTreeSet;
use std::sync::Mutex;

/// A finite set of deterministic validation budgets. Each variant names the
/// budget that was exhausted; no occurrence count, path, or query detail is
/// stored so the tracker remains bounded and order-insensitive.
///
/// Serialized as lower camelCase strings for report metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BudgetKind {
    /// Intrinsic-resolution recursion depth.
    ResolverDepth,
    /// Per-value variant expansion during intrinsic resolution.
    EnumExpansion,
    /// Per-value scenario-combination expansion.
    ScenarioCombinationsPerValue,
    /// Cumulative scenario-combination work across all values.
    ScenarioCombinationsTotal,
    /// Condition parameter-space pre-filter.
    ConditionParameterCombinations,
    /// Per-query satisfiability search steps.
    ConditionSatIterationsPerQuery,
    /// Cumulative satisfiability search steps across all queries.
    ConditionSatIterationsTotal,
    /// Schema scenario-assignment expansion per property group.
    SchemaScenarioAssignments,
    /// Schema scenario merge attempts per property group.
    SchemaScenarioMergeAttempts,
    /// Schema recursive match depth.
    SchemaMatchDepth,
    /// Required-property combination expansion. Context-only: reaching this cap
    /// truncates the diagnostic explanation without omitting the finding.
    RequiredPropertyCombinations,
    /// Expression fingerprint depth.
    ExpressionFingerprintDepth,
}

impl BudgetKind {
    /// The numeric limit for this budget kind.
    pub const fn limit(self) -> u64 {
        match self {
            Self::ResolverDepth => MAX_RESOLVE_DEPTH as u64,
            Self::EnumExpansion => MAX_ENUM_EXPANSION as u64,
            Self::ScenarioCombinationsPerValue => MAX_SCENARIO_COMBINATIONS as u64,
            Self::ScenarioCombinationsTotal => MAX_TOTAL_SCENARIO_COMBINATIONS,
            Self::ConditionParameterCombinations => MAX_PARAM_COMBINATIONS,
            Self::ConditionSatIterationsPerQuery => MAX_SAT_ITERATIONS,
            Self::ConditionSatIterationsTotal => MAX_TOTAL_SAT_ITERATIONS,
            Self::SchemaScenarioAssignments => MAX_SCHEMA_SCENARIO_ASSIGNMENTS as u64,
            Self::SchemaScenarioMergeAttempts => MAX_SCHEMA_SCENARIO_MERGE_ATTEMPTS as u64,
            Self::SchemaMatchDepth => MAX_SCHEMA_MATCH_DEPTH as u64,
            Self::RequiredPropertyCombinations => MAX_REQUIRED_PROPERTY_COMBINATIONS as u64,
            Self::ExpressionFingerprintDepth => MAX_FINGERPRINT_DEPTH as u64,
        }
    }

    /// Whether exhausting this budget makes the overall analysis incomplete.
    /// Required-property combination exhaustion only truncates a diagnostic's
    /// explanation; it does not affect whether the finding is emitted.
    pub const fn analysis_incomplete(self) -> bool {
        !matches!(self, Self::RequiredPropertyCombinations)
    }

    /// Lower camelCase string representation for serialization.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResolverDepth => "resolverDepth",
            Self::EnumExpansion => "enumExpansion",
            Self::ScenarioCombinationsPerValue => "scenarioCombinationsPerValue",
            Self::ScenarioCombinationsTotal => "scenarioCombinationsTotal",
            Self::ConditionParameterCombinations => "conditionParameterCombinations",
            Self::ConditionSatIterationsPerQuery => "conditionSatIterationsPerQuery",
            Self::ConditionSatIterationsTotal => "conditionSatIterationsTotal",
            Self::SchemaScenarioAssignments => "schemaScenarioAssignments",
            Self::SchemaScenarioMergeAttempts => "schemaScenarioMergeAttempts",
            Self::SchemaMatchDepth => "schemaMatchDepth",
            Self::RequiredPropertyCombinations => "requiredPropertyCombinations",
            Self::ExpressionFingerprintDepth => "expressionFingerprintDepth",
        }
    }
}

/// Thread-safe, deduplicating budget-exhaustion tracker. Keyed only by
/// `BudgetKind` — no per-path or per-query detail is stored. Uses a `BTreeSet`
/// for deterministic iteration order.
#[derive(Debug, Default)]
pub(crate) struct BudgetTracker {
    exhausted: Mutex<BTreeSet<BudgetKind>>,
}

impl BudgetTracker {
    pub(crate) fn new() -> Self {
        Self { exhausted: Mutex::new(BTreeSet::new()) }
    }

    /// Record that a budget kind was exhausted. Duplicate insertions are no-ops.
    pub(crate) fn record(&self, kind: BudgetKind) {
        self.exhausted.lock().unwrap_or_else(|p| p.into_inner()).insert(kind);
    }

    /// Returns the set of exhausted budget kinds in deterministic order.
    pub(crate) fn exhausted_kinds(&self) -> BTreeSet<BudgetKind> {
        self.exhausted.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Whether any exhausted budget makes the analysis incomplete.
    pub(crate) fn analysis_incomplete(&self) -> bool {
        self.exhausted.lock().unwrap_or_else(|p| p.into_inner()).iter().any(|kind| kind.analysis_incomplete())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_deduplicates() {
        let tracker = BudgetTracker::new();
        tracker.record(BudgetKind::ResolverDepth);
        tracker.record(BudgetKind::ResolverDepth);
        assert_eq!(tracker.exhausted_kinds().len(), 1);
    }

    #[test]
    fn exhausted_kinds_deterministic_order() {
        let tracker = BudgetTracker::new();
        tracker.record(BudgetKind::ExpressionFingerprintDepth);
        tracker.record(BudgetKind::ResolverDepth);
        tracker.record(BudgetKind::EnumExpansion);
        let kinds: Vec<_> = tracker.exhausted_kinds().into_iter().collect();
        assert_eq!(kinds[0], BudgetKind::ResolverDepth);
        assert_eq!(kinds[1], BudgetKind::EnumExpansion);
        assert_eq!(kinds[2], BudgetKind::ExpressionFingerprintDepth);
    }

    #[test]
    fn analysis_incomplete_reflects_kind() {
        let tracker = BudgetTracker::new();
        tracker.record(BudgetKind::RequiredPropertyCombinations);
        assert!(!tracker.analysis_incomplete());

        tracker.record(BudgetKind::ResolverDepth);
        assert!(tracker.analysis_incomplete());
    }

    #[test]
    fn limit_values_match_canonical_constants() {
        use crate::consts::*;
        assert_eq!(BudgetKind::ResolverDepth.limit(), MAX_RESOLVE_DEPTH as u64);
        assert_eq!(BudgetKind::EnumExpansion.limit(), MAX_ENUM_EXPANSION as u64);
        assert_eq!(BudgetKind::ScenarioCombinationsPerValue.limit(), MAX_SCENARIO_COMBINATIONS as u64);
        assert_eq!(BudgetKind::ScenarioCombinationsTotal.limit(), MAX_TOTAL_SCENARIO_COMBINATIONS);
        assert_eq!(BudgetKind::ConditionParameterCombinations.limit(), MAX_PARAM_COMBINATIONS);
        assert_eq!(BudgetKind::ConditionSatIterationsPerQuery.limit(), MAX_SAT_ITERATIONS);
        assert_eq!(BudgetKind::ConditionSatIterationsTotal.limit(), MAX_TOTAL_SAT_ITERATIONS);
        assert_eq!(BudgetKind::SchemaScenarioAssignments.limit(), MAX_SCHEMA_SCENARIO_ASSIGNMENTS as u64);
        assert_eq!(BudgetKind::SchemaScenarioMergeAttempts.limit(), MAX_SCHEMA_SCENARIO_MERGE_ATTEMPTS as u64);
        assert_eq!(BudgetKind::SchemaMatchDepth.limit(), MAX_SCHEMA_MATCH_DEPTH as u64);
        assert_eq!(BudgetKind::RequiredPropertyCombinations.limit(), MAX_REQUIRED_PROPERTY_COMBINATIONS as u64);
        assert_eq!(BudgetKind::ExpressionFingerprintDepth.limit(), MAX_FINGERPRINT_DEPTH as u64);
    }

    #[test]
    fn as_str_lower_camel_case() {
        assert_eq!(BudgetKind::ResolverDepth.as_str(), "resolverDepth");
        assert_eq!(BudgetKind::EnumExpansion.as_str(), "enumExpansion");
        assert_eq!(BudgetKind::ScenarioCombinationsPerValue.as_str(), "scenarioCombinationsPerValue");
        assert_eq!(BudgetKind::ConditionSatIterationsPerQuery.as_str(), "conditionSatIterationsPerQuery");
        assert_eq!(BudgetKind::SchemaMatchDepth.as_str(), "schemaMatchDepth");
        assert_eq!(BudgetKind::RequiredPropertyCombinations.as_str(), "requiredPropertyCombinations");
        assert_eq!(BudgetKind::ExpressionFingerprintDepth.as_str(), "expressionFingerprintDepth");
    }
}
