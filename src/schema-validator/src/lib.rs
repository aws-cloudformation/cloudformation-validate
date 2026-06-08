pub(crate) mod compiled;
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

impl SchemaValidator {
    pub fn new() -> Self {
        let start = web_time::Instant::now();
        let store = CompiledSchemaStore::new();
        let init_metric = phase_metric(start);
        info!(
            "SchemaValidator initialized: {} schemas loaded",
            store.len()
        );
        SchemaValidator { store, init_metric }
    }

    pub fn init_metric(&self) -> &PhaseMetric {
        &self.init_metric
    }

    pub fn validate(&self, model: &Arc<SemanticModel>, region: &str) -> SchemaValidationResult {
        let start = web_time::Instant::now();
        let diagnostics = validate::validate_all_resources(&self.store, model, region);
        let metric = phase_metric(start);
        SchemaValidationResult {
            diagnostics,
            metric,
        }
    }

    pub fn enrich_context(&self, diagnostics: &mut Vec<Diagnostic>, model: &Arc<SemanticModel>) {
        validate::enrich_schema_context(diagnostics, &self.store, model);
    }

    pub fn schema_count(&self) -> usize {
        self.store.len()
    }

    pub fn list_rules(&self) -> Vec<RuleInfo> {
        // Every rule ID the schema-validator can emit (see src/validate.rs).
        const SCHEMA_RULE_IDS: &[&str] = &[
            "F3002", "F3003", "F3012", "F3014", "F3017", "F3018", "F3020", "F3021", "F3030",
            "F3031", "F3032", "F3033", "F3034", "F3037", "E3040", "W3041", "F3058", "E3030",
            "E9001", "E9006", "E2531", "E2533", "E3710", "E1103", "W9003", "W2531", "W3696",
            "W3697", "W9009", "I9001", "I9002",
        ];
        SCHEMA_RULE_IDS
            .iter()
            .filter_map(|id| lookup_rule(id).map(|r| r.to_rule_info()))
            .collect()
    }
}
