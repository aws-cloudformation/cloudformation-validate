pub mod catalog;
pub(crate) mod compiled;
pub(crate) mod convert;
pub mod overlay;
pub mod store;
pub mod validate;

#[cfg(feature = "uniffi-bindings")]
uniffi::setup_scaffolding!();

pub use catalog::OverlayCatalog;
pub use data_source::{AdditionalSchemaSource, SchemaSourceError};
pub use overlay::{MAX_OVERLAY_DEPTH, SchemaOverlayError};
pub use store::{CompiledSchemaStore, OverlayOutcome};

/// Eagerly decompress all embedded data LazyLocks. Intended to be called once at
/// process/module start in environments that benefit from front-loading cost
pub fn prewarm_embedded_data() {
    data_source::embedded::warm_all();
}

use diagnostics::{Diagnostic, PhaseMetric, phase_metric};
use log::{info, warn};
use rules::{RuleInfo, lookup_rule};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use template_model::SemanticModel;

pub struct SchemaValidationResult {
    pub diagnostics: Vec<Diagnostic>,
    pub metric: PhaseMetric,
}

/// Configuration for constructing a [`SchemaValidator`] with optional overlay
/// schemas. Bindings and the CLI use this to build the validator separately from
/// the rule engine.
#[derive(Default, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm-bindings", tsify(from_wasm_abi))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct SchemaValidatorConfig {
    /// Additional CloudFormation resource provider schemas to merge on top of the
    /// bundled schemas before schema validation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub additional_schemas: Vec<AdditionalSchemaSource>,
}

impl SchemaValidatorConfig {
    /// Starts from the default configuration (no overlays).
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds resource provider schemas to overlay on the bundled ones.
    pub fn with_additional_schemas(mut self, schemas: impl IntoIterator<Item = AdditionalSchemaSource>) -> Self {
        self.additional_schemas.extend(schemas);
        self
    }
}

/// Error reported when schema-validator construction from config fails.
#[derive(Debug)]
pub enum SchemaValidatorConfigError {
    /// An overlay schema source failed to resolve (bad JSON, missing type name, etc.).
    Source(SchemaSourceError),
    /// An overlay schema failed to apply (cycle, depth limit, etc.).
    Overlay(SchemaOverlayError),
}

impl std::fmt::Display for SchemaValidatorConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchemaValidatorConfigError::Source(e) => write!(f, "{e}"),
            SchemaValidatorConfigError::Overlay(e) => {
                write!(f, "Failed to apply an additional schema: {e}")
            }
        }
    }
}

impl std::error::Error for SchemaValidatorConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SchemaValidatorConfigError::Source(e) => Some(e),
            SchemaValidatorConfigError::Overlay(e) => Some(e),
        }
    }
}

impl From<SchemaSourceError> for SchemaValidatorConfigError {
    fn from(e: SchemaSourceError) -> Self {
        SchemaValidatorConfigError::Source(e)
    }
}

impl From<SchemaOverlayError> for SchemaValidatorConfigError {
    fn from(e: SchemaOverlayError) -> Self {
        SchemaValidatorConfigError::Overlay(e)
    }
}

/// Builds an [`OverlayCatalog`] from resolved schema overlay pairs. This is the
/// internal helper that engines use for standalone construction when they need to
/// derive a catalog from additional schemas without constructing a full
/// [`SchemaValidator`].
///
/// Returns `Ok(catalog)` where `catalog.is_empty()` when `overlays` is empty.
#[doc(hidden)]
pub fn build_overlay_catalog<I, S>(overlays: I) -> Result<OverlayCatalog, SchemaOverlayError>
where
    I: IntoIterator<Item = (S, serde_json::Value)>,
    S: AsRef<str>,
{
    let mut store = CompiledSchemaStore::new();
    let mut type_names: Vec<String> = Vec::new();
    let mut any = false;
    for (type_name, schema) in overlays {
        let type_name = type_name.as_ref();
        store.apply_overlay(type_name, &schema)?;
        if !type_names.contains(&type_name.to_string()) {
            type_names.push(type_name.to_string());
        }
        any = true;
    }
    if !any {
        return Ok(OverlayCatalog::default());
    }
    Ok(OverlayCatalog::from_store(&store, &type_names))
}

pub struct SchemaValidator {
    store: CompiledSchemaStore,
    catalog: OverlayCatalog,
    init_metric: PhaseMetric,
}

impl Default for SchemaValidator {
    fn default() -> Self {
        Self::new_default()
    }
}

impl SchemaValidator {
    /// Constructs a [`SchemaValidator`] from a [`SchemaValidatorConfig`],
    /// resolving and applying each additional schema once. The resulting
    /// [`OverlayCatalog`] is stored and accessible via [`Self::overlay_catalog`].
    ///
    /// This is the canonical construction path: bindings, the CLI, and library
    /// embedders all go through this method. A configured overlay behaves
    /// identically no matter which front end supplied it.
    ///
    /// For call sites that need no overlay schemas, [`SchemaValidator::default()`]
    /// provides an infallible, zero-config constructor.
    ///
    /// Returns an error when an overlay is malformed.
    pub fn new(config: SchemaValidatorConfig) -> Result<Self, SchemaValidatorConfigError> {
        if config.additional_schemas.is_empty() {
            return Ok(Self::new_default());
        }
        let overlays: Vec<(String, serde_json::Value)> =
            config.additional_schemas.iter().map(|s| s.resolve()).collect::<Result<Vec<_>, _>>()?;
        Ok(Self::try_with_additional_schemas(overlays)?)
    }

    /// Infallible constructor with no overlay schemas — used by `Default`.
    fn new_default() -> Self {
        let start = web_time::Instant::now();
        let store = CompiledSchemaStore::new();
        Self::finish(store, OverlayCatalog::default(), 0, start)
    }

    /// Construct a validator whose schema store has `additional_schemas` merged
    /// on top of the bundled schemas.
    ///
    /// Each item is a `(type_name, schema)` pair where `schema` is an
    /// already-parsed CloudFormation resource provider schema (registry JSON, the
    /// same shape the build-time schema compiler consumes) and `type_name` is the
    /// resource type it applies to. Overlays are applied in order, so a later
    /// overlay sees the result of the earlier ones. The
    /// [`crate::overlay`] module documents the merge model and its scope
    /// limits.
    ///
    /// Fails, without building a validator, when an overlay is not a JSON object,
    /// carries no type name, nests too deeply, defines a cyclic `$ref` graph, or
    /// would change nothing. An overlay for a type the bundled schemas do not
    /// contain is registered as a new type and logged, since that is also what a
    /// misspelled type name looks like.
    pub fn try_with_additional_schemas<I, S>(additional_schemas: I) -> Result<Self, SchemaOverlayError>
    where
        I: IntoIterator<Item = (S, serde_json::Value)>,
        S: AsRef<str>,
    {
        let start = web_time::Instant::now();
        let mut store = CompiledSchemaStore::new();
        let mut applied = 0usize;
        let mut type_names: Vec<String> = Vec::new();
        for (type_name, schema) in additional_schemas {
            let type_name = type_name.as_ref();
            if store.apply_overlay(type_name, &schema)? == OverlayOutcome::Inserted {
                if should_warn_for_inserted_type(type_name) {
                    warn!(
                        "Additional schema for '{type_name}' matches no bundled resource type; registering it as a \
                         new type. Check the type name if this was meant to extend an existing type."
                    );
                } else {
                    info!("Additional schema for '{type_name}' registered as a new type (private/custom provider).");
                }
            }
            if !type_names.contains(&type_name.to_string()) {
                type_names.push(type_name.to_string());
            }
            applied += 1;
        }
        let catalog = OverlayCatalog::from_store(&store, &type_names);
        Ok(Self::finish(store, catalog, applied, start))
    }

    /// The overlay catalog derived from the final merged schema store. Empty
    /// when no additional schemas were applied. Rule engines use this to access
    /// overlay-aware metadata without rebuilding the store.
    #[doc(hidden)]
    pub fn overlay_catalog(&self) -> &OverlayCatalog {
        &self.catalog
    }

    fn finish(
        store: CompiledSchemaStore,
        catalog: OverlayCatalog,
        overlays_applied: usize,
        start: web_time::Instant,
    ) -> Self {
        let init_metric = phase_metric(start);
        if overlays_applied > 0 {
            info!(
                "SchemaValidator initialized: {} schemas loaded, {overlays_applied} overlay schema(s) applied",
                store.len()
            );
        } else {
            info!("SchemaValidator initialized: {} schemas loaded", store.len());
        }
        SchemaValidator { store, catalog, init_metric }
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

/// Whether inserting a previously unknown type should be logged at `warn` level.
///
/// Unknown AWS::* types are likely a misspelled type name — warn so the caller
/// notices. Private/custom provider types (e.g. `MyOrg::Network::Firewall`) are
/// intentionally new and insertion is the expected outcome — info is sufficient.
pub(crate) fn should_warn_for_inserted_type(type_name: &str) -> bool {
    type_name.starts_with("AWS::")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_without_overlays_matches_default_construction() {
        let config = SchemaValidatorConfig::default();
        let validator = SchemaValidator::new(config).expect("an empty config builds");
        assert_eq!(validator.schema_count(), SchemaValidator::default().schema_count());
    }

    #[test]
    fn new_applies_configured_overlays() {
        let config = SchemaValidatorConfig {
            additional_schemas: vec![AdditionalSchemaSource {
                type_name: String::new(),
                schema: r#"{"typeName":"AWS::Lambda::Function","properties":{"TestForOverride":{"type":"string"}}}"#
                    .into(),
            }],
        };
        let validator = SchemaValidator::new(config).expect("a valid overlay builds");
        let template = br#"
Resources:
  Fn:
    Type: AWS::Lambda::Function
    Properties:
      Code:
        ZipFile: "exports.handler = async () => {};"
      Role: arn:aws:iam::123456789012:role/lambda-role
      Runtime: nodejs18.x
      Handler: index.handler
      TestForOverride: enabled
"#;
        let model = Arc::new(SemanticModel::from_bytes(template).expect("template parses"));
        let diagnostics = validator.validate(&model, Some("us-east-1")).diagnostics;
        assert!(
            !diagnostics.iter().any(|d| d.rule_id == "F3002"),
            "the configured overlay must reach schema validation, got: {:?}",
            diagnostics.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn new_reports_a_malformed_overlay() {
        let config = SchemaValidatorConfig {
            additional_schemas: vec![AdditionalSchemaSource {
                type_name: "AWS::Test::Cycle".into(),
                schema: r##"{"properties":{"P":{"$ref":"#/definitions/D"}},"definitions":{"D":{"$ref":"#/definitions/D"}}}"##
                    .into(),
            }],
        };
        let message = match SchemaValidator::new(config) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a cyclic overlay must fail construction"),
        };
        assert!(message.contains("cycle"), "the error must describe the cycle, got: {message}");
    }

    #[test]
    fn config_builds_validator_with_overlays() {
        let config = SchemaValidatorConfig {
            additional_schemas: vec![AdditionalSchemaSource {
                type_name: String::new(),
                schema: r#"{"typeName":"AWS::Lambda::Function","properties":{"TestForOverride":{"type":"string"}}}"#
                    .into(),
            }],
        };
        let validator = SchemaValidator::new(config).expect("valid config builds");
        assert!(
            !validator.overlay_catalog().is_empty(),
            "validator built from SchemaValidatorConfig must expose a populated catalog"
        );
        assert!(
            validator.overlay_catalog().type_names.contains(&"AWS::Lambda::Function".to_string()),
            "catalog must include the overlaid type"
        );
    }

    #[test]
    fn config_empty_builds_default_validator() {
        let config = SchemaValidatorConfig::default();
        let validator = SchemaValidator::new(config).expect("empty config builds");
        assert_eq!(validator.schema_count(), SchemaValidator::default().schema_count());
        assert!(validator.overlay_catalog().is_empty());
    }

    #[test]
    fn should_warn_for_aws_types_but_not_private_providers() {
        assert!(
            should_warn_for_inserted_type("AWS::S3::NewBucket"),
            "unknown AWS::* types should warn — likely typo or unpublished"
        );
        assert!(
            should_warn_for_inserted_type("AWS::EC2::Instance"),
            "AWS namespace insertion warns regardless of whether the type exists"
        );
        assert!(
            !should_warn_for_inserted_type("MyOrg::Network::Firewall"),
            "private/custom provider types are supported and should not warn"
        );
        assert!(
            !should_warn_for_inserted_type("Acme::Storage::ObjectStore"),
            "third-party provider types are supported and should not warn"
        );
    }
}
