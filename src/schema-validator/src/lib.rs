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

pub use data_source::types::SchemaMetadataCatalog;
use data_source::types::SchemaMetadataDocument;
use diagnostics::{Diagnostic, PhaseMetric, phase_metric};
use log::{info, warn};
use rules::{RuleInfo, lookup_rule};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock};
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
    for (type_name, schema) in overlays {
        let type_name = type_name.as_ref();
        store.apply_overlay(type_name, &schema)?;
        if !type_names.contains(&type_name.to_string()) {
            type_names.push(type_name.to_string());
        }
    }
    build_validated_overlay_catalog(&store, &type_names)
}

/// Builds metadata only after validating references against the final merged
/// store. Per-overlay application permits forward references because a later
/// overlay may supply the target; anything still dangling here cannot resolve.
fn build_validated_overlay_catalog(
    store: &CompiledSchemaStore,
    type_names: &[String],
) -> Result<OverlayCatalog, SchemaOverlayError> {
    for type_name in type_names {
        if let Some(schema) = store.get(type_name)
            && let Some((path, target)) = overlay::find_dangling_refs(schema).into_iter().next()
        {
            return Err(SchemaOverlayError::DanglingRef { type_name: type_name.clone(), path, target });
        }
    }
    Ok(OverlayCatalog::from_store(store, type_names))
}

/// Error reported when the shared schema-metadata catalog cannot be produced.
#[derive(Debug)]
pub enum SchemaMetadataError {
    /// The embedded `schema_metadata` artifact is not valid JSON for the model.
    Parse(serde_json::Error),
    /// The embedded `schema_metadata` artifact is present but empty.
    Empty,
}

impl std::fmt::Display for SchemaMetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchemaMetadataError::Parse(e) => write!(f, "Failed to parse embedded schema_metadata: {e}"),
            SchemaMetadataError::Empty => write!(f, "Embedded schema_metadata must not be empty"),
        }
    }
}

impl std::error::Error for SchemaMetadataError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SchemaMetadataError::Parse(e) => Some(e),
            SchemaMetadataError::Empty => None,
        }
    }
}

/// The process-wide base schema-metadata catalog: the bundled artifact parsed
/// once into the shared typed model and handed out by reference.
///
/// Parsing is lazy and fallible - schema-only construction never triggers it, a
/// caller that needs the catalog gets the same [`Arc`] every other default
/// caller shares, and a corrupt embedded artifact surfaces as an error rather
/// than a panic or a plausible-looking empty catalog.
pub fn shared_base_schema_metadata() -> Result<Arc<SchemaMetadataCatalog>, SchemaMetadataError> {
    static BASE: OnceLock<Arc<SchemaMetadataCatalog>> = OnceLock::new();
    if let Some(existing) = BASE.get() {
        return Ok(existing.clone());
    }
    let document: SchemaMetadataDocument =
        serde_json::from_slice(&data_source::embedded::SCHEMA_METADATA_BYTES).map_err(SchemaMetadataError::Parse)?;
    if document.schema_metadata.is_empty() {
        return Err(SchemaMetadataError::Empty);
    }
    // On a construction race the redundant parse is discarded and every caller
    // still observes the single shared value the winner installed.
    Ok(BASE.get_or_init(|| Arc::new(document.schema_metadata)).clone())
}

/// Produce the schema-metadata catalog an engine should use for a given overlay.
///
/// With no overlaid metadata this returns the shared global base [`Arc`] itself,
/// so every default engine and validator in the process shares one parsed
/// catalog. With overlays it clones the base once and replaces the entry for
/// each overlaid type, preserving the base for every untouched type.
#[doc(hidden)]
pub fn schema_metadata_catalog_with_overlays(
    overlay: &OverlayCatalog,
) -> Result<Arc<SchemaMetadataCatalog>, SchemaMetadataError> {
    let base = shared_base_schema_metadata()?;
    if overlay.schema_metadata.is_empty() {
        return Ok(base);
    }
    let mut merged = (*base).clone();
    for (type_name, entry) in &overlay.schema_metadata {
        merged.insert(type_name.clone(), entry.clone());
    }
    Ok(Arc::new(merged))
}

pub struct SchemaValidator {
    store: CompiledSchemaStore,
    catalog: OverlayCatalog,
    init_metric: PhaseMetric,
    /// The shared schema-metadata catalog for this validator, resolved lazily on
    /// first request. A default validator resolves to the global base [`Arc`]; an
    /// overlay validator clones the base and replaces its overlaid entries once,
    /// then hands the same [`Arc`] to every engine built from it.
    metadata_catalog: OnceLock<Arc<SchemaMetadataCatalog>>,
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

    /// Infallible constructor with no overlay schemas - used by `Default`.
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
        let catalog = build_validated_overlay_catalog(&store, &type_names)?;
        Ok(Self::finish(store, catalog, applied, start))
    }

    /// The overlay catalog derived from the final merged schema store. Empty
    /// when no additional schemas were applied. Rule engines use this to access
    /// overlay-aware metadata without rebuilding the store.
    #[doc(hidden)]
    pub fn overlay_catalog(&self) -> &OverlayCatalog {
        &self.catalog
    }

    /// The shared schema-metadata catalog for this validator, resolved on first
    /// call and cached thereafter.
    ///
    /// A default validator hands back the process-wide base [`Arc`], so every
    /// default consumer shares one parsed catalog. An overlay validator clones
    /// the base once, replaces its overlaid entries, and returns the same [`Arc`]
    /// to every later caller - so a Rego and a CEL engine built from one
    /// validator share the identical catalog rather than each rebuilding it.
    ///
    /// Fallible: a corrupt embedded artifact surfaces as an error instead of a
    /// panic. Construction never calls this, so a validator that is only used for
    /// schema validation never parses the metadata.
    #[doc(hidden)]
    pub fn schema_metadata_catalog(&self) -> Result<Arc<SchemaMetadataCatalog>, SchemaMetadataError> {
        if let Some(existing) = self.metadata_catalog.get() {
            return Ok(existing.clone());
        }
        let catalog = schema_metadata_catalog_with_overlays(&self.catalog)?;
        Ok(self.metadata_catalog.get_or_init(|| catalog).clone())
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
        SchemaValidator { store, catalog, init_metric, metadata_catalog: OnceLock::new() }
    }

    pub fn init_metric(&self) -> &PhaseMetric {
        &self.init_metric
    }

    /// Validates every resource. `region` is the configured AWS region, or `None`
    /// when the caller supplied none - in which case region-scoped checks widen to
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
/// Unknown AWS::* types are likely a misspelled type name - warn so the caller
/// notices. Private/custom provider types (e.g. `MyOrg::Network::Firewall`) are
/// intentionally new and insertion is the expected outcome - info is sufficient.
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
                type_name: None,
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
                type_name: Some("AWS::Test::Cycle".into()),
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
                type_name: None,
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
    fn schema_metadata_is_lazy_and_shared_by_default_validators() {
        let first = SchemaValidator::default();
        let second = SchemaValidator::default();
        assert!(first.metadata_catalog.get().is_none(), "construction must not parse rule metadata");
        assert!(second.metadata_catalog.get().is_none(), "construction must not parse rule metadata");

        let first_catalog = first.schema_metadata_catalog().expect("embedded metadata parses");
        let first_again = first.schema_metadata_catalog().expect("cached metadata remains available");
        let second_catalog = second.schema_metadata_catalog().expect("embedded metadata is shared");

        assert!(Arc::ptr_eq(&first_catalog, &first_again), "one validator must reuse its cached Arc");
        assert!(Arc::ptr_eq(&first_catalog, &second_catalog), "default validators must share the process-wide Arc");
    }

    #[test]
    fn overlay_schema_metadata_is_merged_once_per_validator() {
        let validator = SchemaValidator::try_with_additional_schemas([(
            "AWS::S3::Bucket",
            serde_json::json!({"properties": {"OverlayProperty": {"type": "string"}}}),
        )])
        .expect("overlay applies");
        assert!(validator.metadata_catalog.get().is_none(), "overlay construction must leave rule metadata lazy");

        let base = shared_base_schema_metadata().expect("base metadata parses");
        let merged = validator.schema_metadata_catalog().expect("overlay metadata merges");
        let merged_again = validator.schema_metadata_catalog().expect("merged metadata remains available");

        assert!(!Arc::ptr_eq(&base, &merged), "an overlay must not mutate the shared base catalog");
        assert!(Arc::ptr_eq(&merged, &merged_again), "an overlay validator must cache one merged Arc");
        assert!(
            merged["AWS::S3::Bucket"].properties.contains(&"OverlayProperty".to_string()),
            "the shared engine catalog must contain the overlay-derived property"
        );
        assert!(
            !base["AWS::S3::Bucket"].properties.contains(&"OverlayProperty".to_string()),
            "the process-wide base catalog must remain unchanged"
        );
    }

    #[test]
    fn should_warn_for_aws_types_but_not_private_providers() {
        assert!(
            should_warn_for_inserted_type("AWS::S3::NewBucket"),
            "unknown AWS::* types should warn - likely typo or unpublished"
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
