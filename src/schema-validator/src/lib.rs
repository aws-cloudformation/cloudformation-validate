pub(crate) mod compiled;
pub(crate) mod overlay;
pub mod store;
pub mod validate;

pub use store::CompiledSchemaStore;

/// Eagerly decompress all embedded data LazyLocks. Intended to be called once at
/// process/module start in environments that benefit from front-loading cost
pub fn prewarm_embedded_data() {
    data_source::embedded::warm_all();
}

use diagnostics::{Diagnostic, PhaseMetric, phase_metric};
use log::info;
use rules::{RuleInfo, lookup_rule};
use std::sync::Arc;
use template_model::SemanticModel;

pub struct SchemaValidationResult {
    pub diagnostics: Vec<Diagnostic>,
    pub metric: PhaseMetric,
}

pub struct SchemaValidator {
    store: CompiledSchemaStore,
    init_metric: PhaseMetric,
}

impl Default for SchemaValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl SchemaValidator {
    pub fn new() -> Self {
        let start = web_time::Instant::now();
        let store = CompiledSchemaStore::new();
        let init_metric = phase_metric(start);
        info!("SchemaValidator initialized: {} schemas loaded", store.len());
        SchemaValidator { store, init_metric }
    }

    /// Construct a validator whose schema store has `additional_schemas` merged on
    /// top of the bundled schemas.
    ///
    /// Each item is a `(type_name, schema)` pair where `schema` is an
    /// already-parsed CloudFormation resource provider schema (registry JSON, the
    /// same shape consumed by the build-time schema compiler) and `type_name` is
    /// the resolved, non-empty resource type name. Overlays are applied in order;
    /// see [`crate::overlay`] for the merge semantics.
    ///
    /// This constructor is infallible: parsing the JSON and resolving the type
    /// name are the caller's responsibility, so only well-formed input reaches
    /// here. Bindings use [`validation_engine::AdditionalSchemaSource::resolve`]
    /// to turn raw config into the pairs this method expects.
    pub fn with_additional_schemas<I, S>(additional_schemas: I) -> Self
    where
        I: IntoIterator<Item = (S, serde_json::Value)>,
        S: AsRef<str>,
    {
        let start = web_time::Instant::now();
        let mut store = CompiledSchemaStore::new();
        let mut applied = 0usize;
        for (type_name, schema) in additional_schemas {
            store.apply_overlay(type_name.as_ref(), &schema);
            applied += 1;
        }
        let init_metric = phase_metric(start);
        if applied > 0 {
            info!("SchemaValidator initialized: {} schemas loaded, {applied} overlay schema(s) applied", store.len());
        } else {
            info!("SchemaValidator initialized: {} schemas loaded", store.len());
        }
        SchemaValidator { store, init_metric }
    }

    pub fn init_metric(&self) -> &PhaseMetric {
        &self.init_metric
    }

    /// Validates every resource. `region` is the configured AWS region, or `None`
    /// when the caller supplied none — in which case region-scoped checks widen to
    /// the union of all regions (a resource type or enum value is flagged only when
    /// it is unavailable in every region) rather than assuming a default region.
    pub fn validate(&self, model: &Arc<SemanticModel>, region: Option<&str>) -> SchemaValidationResult {
        let start = web_time::Instant::now();
        let diagnostics = validate::validate_all_resources(&self.store, model, region);
        let metric = phase_metric(start);
        SchemaValidationResult { diagnostics, metric }
    }

    pub fn enrich_context(&self, diagnostics: &mut [Diagnostic], model: &Arc<SemanticModel>) {
        validate::enrich_schema_context(diagnostics, &self.store, model);
    }

    pub fn schema_count(&self) -> usize {
        self.store.len()
    }

    pub fn list_rules(&self) -> Vec<RuleInfo> {
        // Every rule ID the schema-validator can emit (see src/validate.rs).
        const SCHEMA_RULE_IDS: &[&str] = &[
            "F3002", "F3003", "F3012", "F3014", "F3017", "F3018", "F3020", "F3021", "F3030", "W3030", "F3031", "F3032",
            "F3033", "F3034", "F3037", "E3040", "W9054", "F3058", "E3030", "F3006", "E9006", "E2531", "E2533", "E3710",
            "E1103", "W9003", "W2531", "W3696", "W3697", "W9009", "I9001", "I9002",
        ];
        SCHEMA_RULE_IDS.iter().filter_map(|id| lookup_rule(id).map(|r| r.to_rule_info())).collect()
    }
}
