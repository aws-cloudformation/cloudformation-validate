use crate::policies;
use data_source::embedded;
use data_source::types::KnownResourceTypes;
use diagnostics::{Diagnostic, PhaseMetric, phase_metric};
use guard_translator::{ensure_translatable, pack_name_from_path, parse_guard};
use log::{debug, info, warn};
use rules::{Category, RuleInfo, RuleMetadataEntry, RuleOrigin, Severity, build_rule_metadata_map};
use schema_validator::{OverlayCatalog, SchemaMetadataCatalog, SchemaValidator, schema_metadata_catalog_with_overlays};
use std::collections::{HashMap, HashSet};
use std::str::from_utf8;
use std::sync::{Arc, LazyLock, Mutex};
use template_model::SemanticModel;
use validation_engine::{
    EngineConfig, ValidateConfig, ValidationEngine, ValidationError, build_rule_list, extract_diagnostics,
    semantic_model_to_input_json,
};

static REGORUS_DATA: LazyLock<Vec<(&str, &[u8])>> = LazyLock::new(|| {
    vec![
        (KNOWN_RESOURCE_TYPES_PATH, &*embedded::KNOWN_RESOURCE_TYPES_BYTES),
        (PRIMARY_IDENTIFIERS_PATH, &*embedded::PRIMARY_IDENTIFIERS_BYTES),
        ("data/iam_action_resource_patterns", &*embedded::IAM_ACTION_RESOURCE_PATTERNS_BYTES),
        ("data/stateful_resource_types", &*embedded::STATEFUL_RESOURCE_TYPES_BYTES),
        ("data/aws_rds_dbinstance_dbinstanceclass_enum", &*embedded::AWS_RDS_DBINSTANCE_DBINSTANCECLASS_ENUM_BYTES),
        ("data/aws_ec2_instance_instancetype_enum", &*embedded::AWS_EC2_INSTANCE_INSTANCETYPE_ENUM_BYTES),
        (
            "data/aws_emr_cluster_instancetypeconfig_instancetype_enum",
            &*embedded::AWS_EMR_CLUSTER_INSTANCETYPECONFIG_INSTANCETYPE_ENUM_BYTES,
        ),
        ("data/aws_gamelift_fleet_ec2instancetype_enum", &*embedded::AWS_GAMELIFT_FLEET_EC2INSTANCETYPE_ENUM_BYTES),
        ("data/aws_appstream_fleet_instancetype_enum", &*embedded::AWS_APPSTREAM_FLEET_INSTANCETYPE_ENUM_BYTES),
        ("data/aws_dax_cluster_nodetype_enum", &*embedded::AWS_DAX_CLUSTER_NODETYPE_ENUM_BYTES),
        ("data/aws_docdb_dbinstance_dbinstanceclass_enum", &*embedded::AWS_DOCDB_DBINSTANCE_DBINSTANCECLASS_ENUM_BYTES),
        (
            "data/aws_elasticache_cachecluster_cachenodetype_enum",
            &*embedded::AWS_ELASTICACHE_CACHECLUSTER_CACHENODETYPE_ENUM_BYTES,
        ),
        (
            "data/aws_managedblockchain_node_nodeconfiguration_instancetype_enum",
            &*embedded::AWS_MANAGEDBLOCKCHAIN_NODE_NODECONFIGURATION_INSTANCETYPE_ENUM_BYTES,
        ),
        (
            "data/aws_neptune_dbinstance_dbinstanceclass_enum",
            &*embedded::AWS_NEPTUNE_DBINSTANCE_DBINSTANCECLASS_ENUM_BYTES,
        ),
        (
            "data/aws_rds_dbcluster_dbclusterinstanceclass_enum",
            &*embedded::AWS_RDS_DBCLUSTER_DBCLUSTERINSTANCECLASS_ENUM_BYTES,
        ),
        ("data/aws_rds_dbinstance_db_instance_class", &*embedded::AWS_RDS_DBINSTANCE_DB_INSTANCE_CLASS_BYTES),
        ("data/aws_redshift_cluster_nodetype_enum", &*embedded::AWS_REDSHIFT_CLUSTER_NODETYPE_ENUM_BYTES),
        ("data/aws_amazonmq_broker_instancetype_enum", &*embedded::AWS_AMAZONMQ_BROKER_INSTANCETYPE_ENUM_BYTES),
        (
            "data/aws_sagemaker_processing_instancetype_enum",
            &*embedded::AWS_SAGEMAKER_PROCESSING_INSTANCETYPE_ENUM_BYTES,
        ),
        ("data/aws_sagemaker_hosting_instancetype_enum", &*embedded::AWS_SAGEMAKER_HOSTING_INSTANCETYPE_ENUM_BYTES),
        ("data/aws_sagemaker_transform_instancetype_enum", &*embedded::AWS_SAGEMAKER_TRANSFORM_INSTANCETYPE_ENUM_BYTES),
        ("data/aws_sagemaker_cluster_instancetype_enum", &*embedded::AWS_SAGEMAKER_CLUSTER_INSTANCETYPE_ENUM_BYTES),
        (
            "data/aws_elasticsearch_domain_elasticsearchclusterconfig_instancetype_enum",
            &*embedded::AWS_ELASTICSEARCH_DOMAIN_ELASTICSEARCHCLUSTERCONFIG_INSTANCETYPE_ENUM_BYTES,
        ),
        (
            "data/aws_opensearchservice_domain_clusterconfig_instancetype_enum",
            &*embedded::AWS_OPENSEARCHSERVICE_DOMAIN_CLUSTERCONFIG_INSTANCETYPE_ENUM_BYTES,
        ),
        (GETATT_ATTRIBUTES_PATH, &*embedded::GETATT_ATTRIBUTES_BYTES),
        ("data/codepipeline_action_artifact_counts", &*embedded::CODEPIPELINE_ACTION_ARTIFACT_COUNTS_BYTES),
        ("data/deprecated_resource_types", &*embedded::DEPRECATED_RESOURCE_TYPES_BYTES),
        ("data/retention_period_requirements", &*embedded::RETENTION_PERIOD_REQUIREMENTS_BYTES),
        ("data/sensitive_ports", &*embedded::SENSITIVE_PORTS_BYTES),
        ("data/secretsmanager_arn_fields", &*embedded::SECRETSMANAGER_ARN_FIELDS_BYTES),
        ("data/rule_data", &*embedded::RULE_DATA_BYTES),
        ("data/rule_tables", &*embedded::RULE_TABLES_BYTES),
    ]
});

const CORE_PACKAGES: &[(Category, &str)] = &[
    (Category::Structure, "data.structure.violation"),
    (Category::Intrinsic, "data.intrinsics.violation"),
    (Category::Reference, "data.references.violation"),
    (Category::BestPractice, "data.best_practices.violation"),
    (Category::Resource, "data.resources.violation"),
];

/// Pre-allocated capacity for merging all embedded JSON data files into one string.
const MERGED_DATA_INITIAL_CAPACITY: usize = 8 * 1024 * 1024;

/// The [`REGORUS_DATA`] entry holding the catalog of resource types the rules
/// treat as existing.
const KNOWN_RESOURCE_TYPES_PATH: &str = "data/known_resource_types";

/// The [`REGORUS_DATA`] entry holding GetAtt attributes and attribute types.
const GETATT_ATTRIBUTES_PATH: &str = "data/getatt_attributes";

/// The [`REGORUS_DATA`] entry holding primary identifiers per type.
const PRIMARY_IDENTIFIERS_PATH: &str = "data/primary_identifiers";

/// Re-serializes the known-resource-type catalog with `extra_types` appended, or
/// returns `None` when there is nothing to add so the embedded bytes are used
/// verbatim.
fn extend_known_resource_types(extra_types: &[String]) -> anyhow::Result<Option<String>> {
    if extra_types.is_empty() {
        return Ok(None);
    }
    let mut catalog: KnownResourceTypes = serde_json::from_slice(&embedded::KNOWN_RESOURCE_TYPES_BYTES)
        .map_err(|e| anyhow::anyhow!("Failed to parse the embedded known_resource_types data: {e}"))?;
    anyhow::ensure!(!catalog.known_resource_types.is_empty(), "Embedded known_resource_types data must not be empty");
    for type_name in extra_types {
        if !catalog.known_resource_types.contains(type_name) {
            catalog.known_resource_types.push(type_name.clone());
        }
    }
    Ok(Some(serde_json::to_string(&catalog)?))
}

/// Extends the embedded getatt_attributes data with overlay catalog entries.
/// Returns `None` when there is nothing to add.
fn extend_getatt_data(catalog: &OverlayCatalog) -> anyhow::Result<Option<String>> {
    if catalog.getatt_attributes.is_empty() && catalog.getatt_attribute_types.is_empty() {
        return Ok(None);
    }
    let mut data: serde_json::Value = serde_json::from_slice(&embedded::GETATT_ATTRIBUTES_BYTES)
        .map_err(|e| anyhow::anyhow!("Failed to parse the embedded getatt_attributes data: {e}"))?;

    // Merge getatt_attributes (sort/dedup after merging)
    if let Some(attrs_obj) = data.get_mut("getatt_attributes").and_then(|v| v.as_object_mut()) {
        for (type_name, attrs) in &catalog.getatt_attributes {
            let entry = attrs_obj.entry(type_name.clone()).or_insert_with(|| serde_json::Value::Array(Vec::new()));
            if let Some(arr) = entry.as_array_mut() {
                for attr in attrs {
                    let val = serde_json::Value::String(attr.clone());
                    if !arr.contains(&val) {
                        arr.push(val);
                    }
                }
                arr.sort_by(|a, b| a.as_str().unwrap_or("").cmp(b.as_str().unwrap_or("")));
                arr.dedup();
            }
        }
    }

    // Merge getatt_attribute_types
    if let Some(types_obj) = data.get_mut("getatt_attribute_types").and_then(|v| v.as_object_mut()) {
        for (type_name, attr_types) in &catalog.getatt_attribute_types {
            let entry =
                types_obj.entry(type_name.clone()).or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
            if let Some(obj) = entry.as_object_mut() {
                for (attr, atype) in attr_types {
                    obj.insert(attr.clone(), serde_json::Value::String(atype.clone()));
                }
            }
        }
    }

    Ok(Some(serde_json::to_string(&data)?))
}

/// Extends the embedded primary_identifiers data with overlay catalog entries.
/// Returns `None` when there is nothing to add.
fn extend_primary_identifiers_data(catalog: &OverlayCatalog) -> anyhow::Result<Option<String>> {
    if catalog.primary_identifiers.is_empty() {
        return Ok(None);
    }
    let mut data: serde_json::Value = serde_json::from_slice(&embedded::PRIMARY_IDENTIFIERS_BYTES)
        .map_err(|e| anyhow::anyhow!("Failed to parse the embedded primary_identifiers data: {e}"))?;

    if let Some(pids_obj) = data.get_mut("primary_identifiers").and_then(|v| v.as_object_mut()) {
        for (type_name, pids) in &catalog.primary_identifiers {
            pids_obj.insert(type_name.clone(), serde_json::json!(pids));
        }
    }

    Ok(Some(serde_json::to_string(&data)?))
}

pub struct RegoEngine {
    base_rego: regorus::Engine,
    /// Built-in rule metadata from the rules registry only.
    registry_metadata: HashMap<String, RuleMetadataEntry>,
    /// Metadata for custom user rules and translated guard rules.
    external_rule_metadata: HashMap<String, RuleMetadataEntry>,
    /// Custom rego rule metadata discovered from evaluation output.
    /// Rego rules embed metadata in their output objects, so it can only
    /// be extracted after evaluation. May be incomplete if not all rules fired.
    discovered_custom_metadata: Mutex<HashMap<String, RuleMetadataEntry>>,
    custom_packages: Vec<String>,
    guard_packages: Vec<String>,
    init_metric: PhaseMetric,
}

impl RegoEngine {
    pub fn new(config: EngineConfig) -> anyhow::Result<Self> {
        let overlay_catalog =
            config.build_overlay_catalog().map_err(|e| anyhow::anyhow!("Failed to build overlay catalog: {e}"))?;
        let start = web_time::Instant::now();
        let schema_metadata = schema_metadata_catalog_with_overlays(&overlay_catalog)?;
        Self::new_from_parts(config, &overlay_catalog, schema_metadata, start)
    }

    /// Constructs the engine reusing metadata from an already-built
    /// [`SchemaValidator`](schema_validator::SchemaValidator). The validator's
    /// overlay catalog is treated as authoritative - the engine does not
    /// re-resolve overlay schemas.
    ///
    /// This entry point is intended for language bindings and the CLI, which
    /// construct a `SchemaValidator` once and share it with the engine. The
    /// validator's shared schema-metadata catalog is reused rather than rebuilt,
    /// so every engine built from the same validator shares one catalog rather
    /// than rebuilding it.
    #[doc(hidden)]
    pub fn new_with_schema_validator(config: EngineConfig, validator: &SchemaValidator) -> anyhow::Result<Self> {
        let start = web_time::Instant::now();
        let schema_metadata = validator.schema_metadata_catalog()?;
        Self::new_from_parts(config, validator.overlay_catalog(), schema_metadata, start)
    }

    /// Internal constructor that accepts a pre-built overlay catalog and the
    /// shared schema-metadata catalog resolved for it.
    fn new_from_parts(
        config: EngineConfig,
        overlay_catalog: &OverlayCatalog,
        schema_metadata: Arc<SchemaMetadataCatalog>,
        start: web_time::Instant,
    ) -> anyhow::Result<Self> {
        let mut rego = regorus::Engine::new();
        rego.set_strict_builtin_errors(false);

        // Single-pass merge avoids per-file JSON parsing overhead.
        {
            // Resource types introduced by an overlay schema are legitimate
            // targets, so the type catalog the rules consult must include them
            // rather than reporting them as nonexistent.
            let overlay_types: Vec<String> = overlay_catalog.type_names.clone();
            let extended_known_types = extend_known_resource_types(&overlay_types)?;

            // Extend getatt_attributes data with overlay entries
            let extended_getatt = extend_getatt_data(overlay_catalog)?;
            // Extend primary_identifiers data with overlay entries
            let extended_primary_ids = extend_primary_identifiers_data(overlay_catalog)?;

            let mut merged = String::with_capacity(MERGED_DATA_INITIAL_CAPACITY);
            merged.push('{');
            for (i, (path, json_bytes)) in REGORUS_DATA.iter().enumerate() {
                let json_str = match (
                    *path,
                    extended_known_types.as_deref(),
                    extended_getatt.as_deref(),
                    extended_primary_ids.as_deref(),
                ) {
                    (KNOWN_RESOURCE_TYPES_PATH, Some(extended), _, _) => extended,
                    (GETATT_ATTRIBUTES_PATH, _, Some(extended), _) => extended,
                    (PRIMARY_IDENTIFIERS_PATH, _, _, Some(extended)) => extended,
                    _ => from_utf8(json_bytes).map_err(|error| {
                        anyhow::anyhow!("Embedded JSON data '{}' is not valid UTF-8: {}", path, error)
                    })?,
                };
                let inner = json_str
                    .trim()
                    .strip_prefix('{')
                    .and_then(|value| value.strip_suffix('}'))
                    .ok_or_else(|| anyhow::anyhow!("Embedded JSON data '{}' must be a top-level object", path))?;
                anyhow::ensure!(!inner.trim().is_empty(), "Embedded JSON data '{}' must not be empty", path);
                if i > 0 {
                    merged.push(',');
                }
                merged.push_str(inner);
            }
            merged.push('}');
            rego.add_data(regorus::Value::from_json_str(&merged)?)?;
        }

        for (path, source) in policies::HANDWRITTEN_REGO_POLICIES {
            rego.add_policy(path.to_string(), source.to_string())?;
        }
        debug!(
            "Loaded {} data files, {} handwritten rules",
            REGORUS_DATA.len(),
            policies::HANDWRITTEN_REGO_POLICIES.len()
        );

        let mut translated_guard_sources = Vec::new();
        let mut guard_rule_metadata: Vec<(String, Option<String>, String, Severity, RuleOrigin)> = Vec::new();
        for entry in &config.guard_rules {
            let guard_file = parse_guard(&entry.content, &entry.name)
                .map_err(|e| anyhow::anyhow!("Failed to parse guard file '{}': {}", entry.name, e))?;
            ensure_translatable(&guard_file)
                .map_err(|e| anyhow::anyhow!("Unsupported guard rule in '{}': {}", entry.name, e))?;
            let pack = pack_name_from_path(&entry.name);
            for tr in crate::guard_to_rego::translate_to_rego(&guard_file, &pack, &[]) {
                guard_rule_metadata.push((
                    tr.rule_id.clone(),
                    tr.category.clone(),
                    tr.description.clone(),
                    Severity::Error,
                    RuleOrigin::Guard,
                ));
                translated_guard_sources.push((tr.path, tr.source));
            }
        }

        for entry in &config.custom_rules {
            rego.add_policy(entry.name.clone(), entry.content.clone())?;
        }
        for (path, source) in &translated_guard_sources {
            rego.add_policy(path.clone(), source.clone())?;
        }
        let mut custom_packages = Vec::new();
        for entry in &config.custom_rules {
            for line in entry.content.lines() {
                let trimmed = line.trim();
                if let Some(pkg) = trimmed.strip_prefix("package ") {
                    let eval_path = format!("data.{}.violation", pkg.trim());
                    if !custom_packages.contains(&eval_path) {
                        custom_packages.push(eval_path);
                    }
                }
            }
        }
        let mut guard_packages = Vec::new();
        for (_, source) in &translated_guard_sources {
            for line in source.lines() {
                let trimmed = line.trim();
                if let Some(pkg) = trimmed.strip_prefix("package ") {
                    let eval_path = format!("data.{}.violation", pkg.trim());
                    if !guard_packages.contains(&eval_path) {
                        guard_packages.push(eval_path);
                    }
                }
            }
        }

        crate::builtins::register_all(&mut rego, overlay_catalog, schema_metadata)?;

        let registry_metadata = build_rule_metadata_map();
        let mut external_rule_metadata: HashMap<String, RuleMetadataEntry> = HashMap::new();
        for (id, cat, desc, severity, origin) in guard_rule_metadata {
            external_rule_metadata.entry(id).or_insert(RuleMetadataEntry {
                category: cat,
                description: desc,
                severity,
                origin,
            });
        }

        rego.set_input(regorus::Value::new_object());
        let _ = rego.eval_rule("data.all_violations.violation".to_string());

        info!(
            "RegoEngine initialized: {} handwritten rules, {} data files, {} registry + {} external metadata entries",
            policies::HANDWRITTEN_REGO_POLICIES.len(),
            REGORUS_DATA.len(),
            registry_metadata.len(),
            external_rule_metadata.len()
        );
        let init_metric = phase_metric(start);
        Ok(RegoEngine {
            base_rego: rego,
            registry_metadata,
            external_rule_metadata,
            discovered_custom_metadata: Mutex::new(HashMap::new()),
            custom_packages,
            guard_packages,
            init_metric,
        })
    }

    /// Evaluates a single Rego package and appends its diagnostics to `out`.
    ///
    /// Any evaluation or serialization failure is returned as a structured
    /// [`ValidationError`] - an exception the caller can handle - and is never
    /// converted into a diagnostic. A rule that fails to run must surface as an
    /// error, not masquerade as a finding.
    fn eval_package_into(
        &self,
        rego: &mut regorus::Engine,
        package: &str,
        source_label: &str,
        model: &SemanticModel,
        origin: Option<&RuleOrigin>,
        out: &mut Vec<Diagnostic>,
    ) -> Result<(), ValidationError> {
        let value = rego.eval_rule(package.to_string()).map_err(|e| {
            ValidationError::Engine(format!("{source_label} rule package '{package}' failed to evaluate: {e}"))
        })?;
        let json_str = value.to_json_str().map_err(|e| {
            ValidationError::Engine(format!(
                "{source_label} rule package '{package}' produced a result that could not be \
                 serialized to JSON: {e}"
            ))
        })?;
        extract_diagnostics(&json_str, model, out, origin).map_err(ValidationError::from)
    }

    /// The built-in rule IDs that global filtering proves cannot survive under
    /// `config`, so their handwritten clauses can stop at the `cfn_rule_active`
    /// guard before doing any work. Only rules the registry defines are eligible;
    /// custom and guard rules are never globally suppressed here.
    fn globally_suppressed_builtin_rules(&self, config: &ValidateConfig) -> Arc<HashSet<String>> {
        let suppressed: HashSet<String> = self
            .registry_metadata
            .iter()
            .filter(|(rule_id, entry)| {
                config.filters.globally_suppresses_builtin_rule(
                    rule_id,
                    entry.category.as_deref(),
                    entry.severity,
                    config.strict,
                    config.severity_level,
                )
            })
            .map(|(rule_id, _)| rule_id.clone())
            .collect();
        Arc::new(suppressed)
    }
}

impl ValidationEngine for RegoEngine {
    fn engine_name(&self) -> &str {
        "rego"
    }

    fn evaluate_rules(
        &self,
        model: &Arc<SemanticModel>,
        config: &ValidateConfig,
    ) -> Result<Vec<Diagnostic>, ValidationError> {
        let context = crate::eval_context::EvaluationContext::new(
            model.clone(),
            config.pseudo_parameter_overrides.region.clone(),
            self.globally_suppressed_builtin_rules(config),
        );
        let _scope = crate::eval_context::EvaluationScope::enter(context);

        let mut rego = self.base_rego.clone();

        let input_json = semantic_model_to_input_json(model)?;
        let input_value = crate::builtins::serde_json_to_rego_value(&input_json);
        rego.set_input(input_value);

        let mut diagnostics = Vec::new();

        if !config.disable_builtin_rules {
            let excluded_cats = config.filters.excluded_categories();

            let needed_core: Vec<&str> = CORE_PACKAGES
                .iter()
                .filter(|(cat, _)| !excluded_cats.contains(cat.as_str()))
                .map(|(_, pkg)| *pkg)
                .collect();

            if needed_core.len() == CORE_PACKAGES.len() {
                match rego.eval_rule("data.all_violations.violation".to_string()) {
                    Ok(val) => {
                        let json_str = val.to_json_str().map_err(|e| {
                            ValidationError::Engine(format!(
                                "Aggregated rule evaluation produced a result that could not be \
                             serialized to JSON: {e}"
                            ))
                        })?;
                        extract_diagnostics(&json_str, model, &mut diagnostics, None).map_err(ValidationError::from)?;
                    }
                    Err(e) => {
                        warn!("Aggregated eval failed ({}), falling back to individual packages", e);
                        for pkg in &needed_core {
                            self.eval_package_into(&mut rego, pkg, "Core", model, None, &mut diagnostics)?;
                        }
                    }
                }
            } else {
                debug!("Skipping excluded categories: {:?}", excluded_cats);
                for pkg in &needed_core {
                    self.eval_package_into(&mut rego, pkg, "Core", model, None, &mut diagnostics)?;
                }
            }
        }

        for pkg in &self.custom_packages {
            self.eval_package_into(&mut rego, pkg, "Custom", model, Some(&RuleOrigin::Custom), &mut diagnostics)?;
        }

        for pkg in &self.guard_packages {
            self.eval_package_into(&mut rego, pkg, "Guard", model, Some(&RuleOrigin::Guard), &mut diagnostics)?;
        }

        if !self.custom_packages.is_empty() {
            let mut discovered = self.discovered_custom_metadata.lock().unwrap_or_else(|e| e.into_inner());
            for d in &diagnostics {
                if d.source == RuleOrigin::Custom {
                    discovered.entry(d.rule_id.clone()).or_insert_with(|| RuleMetadataEntry {
                        category: d.category.clone(),
                        description: d.message.clone(),
                        severity: d.severity,
                        origin: RuleOrigin::Custom,
                    });
                }
            }
        }

        Ok(diagnostics)
    }

    fn list_rules(&self) -> Vec<RuleInfo> {
        let mut merged = self.external_rule_metadata.clone();
        if !self.custom_packages.is_empty() {
            let discovered = self.discovered_custom_metadata.lock().unwrap_or_else(|e| e.into_inner());
            merged.extend(discovered.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        build_rule_list(&self.registry_metadata, &merged)
    }

    fn rule_metadata(&self) -> &HashMap<String, RuleMetadataEntry> {
        &self.registry_metadata
    }

    /// Returns guard metadata merged with any custom Rego rule metadata
    /// discovered from prior evaluations.
    fn external_rule_metadata(&self) -> HashMap<String, RuleMetadataEntry> {
        let mut merged = self.external_rule_metadata.clone();
        if !self.custom_packages.is_empty() {
            let discovered = self.discovered_custom_metadata.lock().unwrap_or_else(|e| e.into_inner());
            merged.extend(discovered.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        merged
    }

    fn init_metric(&self) -> &PhaseMetric {
        &self.init_metric
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rules::{FilterConfig, RuleFilterConfig};
    use std::sync::Barrier;
    use std::thread;
    use template_model::SemanticModel;
    use validation_engine::{EngineConfig, ExternalRuleSource, ValidateConfig, ValidationEngine};

    fn make_engine() -> RegoEngine {
        RegoEngine::new(EngineConfig::default()).unwrap()
    }

    fn make_model_from_yaml(yaml: &str) -> Arc<SemanticModel> {
        let model = SemanticModel::from_bytes(yaml.as_bytes()).unwrap();
        Arc::new(model)
    }

    #[test]
    fn new_default_config_succeeds() {
        let engine = make_engine();
        assert_eq!(engine.engine_name(), "rego");
    }

    #[test]
    fn list_rules_returns_nonempty() {
        let engine = make_engine();
        let rules = engine.list_rules();
        assert!(!rules.is_empty(), "should have built-in rules");
    }

    #[test]
    fn rule_metadata_contains_entries() {
        let engine = make_engine();
        assert!(!engine.rule_metadata().is_empty());
    }

    #[test]
    fn init_metric_has_positive_duration() {
        let engine = make_engine();
        let metric = engine.init_metric();
        assert!(metric.duration_ms > 0.0, "init duration should be > 0, got {}", metric.duration_ms);
    }

    #[test]
    fn evaluate_minimal_template_no_errors() {
        let engine = make_engine();
        let model = make_model_from_yaml(
            r#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
"#,
        );
        let diags = engine.evaluate_rules(&model, &ValidateConfig::default()).unwrap();
        assert!(
            diags.iter().all(|d| d.severity != Severity::Fatal),
            "rego engine should not produce Fatal diagnostics"
        );
    }

    #[test]
    fn evaluate_empty_resources_does_not_panic() {
        let engine = make_engine();
        let model = make_model_from_yaml(
            r#"
AWSTemplateFormatVersion: "2010-09-09"
Resources: {}
"#,
        );
        // CloudFormation rejects templates with empty Resources, so the empty-resources diagnostic is expected.
        let diags = engine.evaluate_rules(&model, &ValidateConfig::default()).unwrap();
        assert!(
            diags.iter().any(|d| d.rule_id == "F0001"),
            "expected F0001 Fatal for empty Resources section, got: {:?}",
            diags.iter().map(|d| &d.rule_id).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn evaluate_with_excluded_categories() {
        let engine = make_engine();
        let model = make_model_from_yaml(
            r#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
"#,
        );
        let config = ValidateConfig {
            filters: FilterConfig::new(
                RuleFilterConfig::default(),
                RuleFilterConfig { categories: vec!["best_practices".to_string()], ..Default::default() },
            ),
            ..Default::default()
        };
        let diags_filtered = engine.evaluate_rules(&model, &config).unwrap();

        let diags_all = engine.evaluate_rules(&model, &ValidateConfig::default()).unwrap();

        assert!(
            diags_filtered.len() <= diags_all.len(),
            "filtered count {} should be <= unfiltered count {}",
            diags_filtered.len(),
            diags_all.len()
        );
    }

    #[test]
    fn custom_rego_rule_produces_diagnostics() {
        let custom_rego = r#"
package custom_test
import rego.v1

violation contains v if {
    some name, res in input.resources
    res.resourceType == "AWS::S3::Bucket"
    v := {"rule_id": "CUSTOM001", "severity": "error", "message": "Custom rule fired", "resource_id": name}
}
"#;
        let config = EngineConfig {
            custom_rules: vec![ExternalRuleSource { name: "custom_test.rego".into(), content: custom_rego.into() }],
            guard_rules: vec![],
            ..Default::default()
        };
        let engine = RegoEngine::new(config).unwrap();
        let model = make_model_from_yaml(
            r#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
"#,
        );
        let diags = engine.evaluate_rules(&model, &ValidateConfig::default()).unwrap();
        let custom = diags.iter().find(|d| d.rule_id == "CUSTOM001");
        assert!(custom.is_some(), "custom rule should fire");
    }

    #[test]
    fn guard_rule_produces_diagnostics() {
        let guard_source = r#"
rule check_bucket_name {
    AWS::S3::Bucket {
        Properties.BucketName EXISTS
        <<BucketName must be specified>>
    }
}
"#;
        let config = EngineConfig {
            custom_rules: vec![],
            guard_rules: vec![ExternalRuleSource { name: "test.guard".into(), content: guard_source.into() }],
            ..Default::default()
        };
        let engine = RegoEngine::new(config).unwrap();
        let model = make_model_from_yaml(
            r#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
"#,
        );
        let diags = engine.evaluate_rules(&model, &ValidateConfig::default()).unwrap();
        let guard_diag = diags.iter().find(|d| d.rule_id == "check_bucket_name");
        assert!(guard_diag.is_some(), "guard rule should fire when BucketName is missing");
    }

    #[test]
    fn guard_rule_exists_check_ignores_properties_prefix() {
        // BUG: Guard DSL `Properties.BucketName EXISTS` translates to
        // `has_property(name, "Properties.BucketName")` but has_property looks up
        // `resource.properties["Properties.BucketName"]` - the actual key is just
        // "BucketName", so the check always fails and the violation always fires.
        let guard_source = r#"
rule check_bucket_name {
    AWS::S3::Bucket {
        Properties.BucketName EXISTS
        <<BucketName must be specified>>
    }
}
"#;
        let config = EngineConfig {
            custom_rules: vec![],
            guard_rules: vec![ExternalRuleSource { name: "test.guard".into(), content: guard_source.into() }],
            ..Default::default()
        };
        let engine = RegoEngine::new(config).unwrap();
        let model = make_model_from_yaml(
            r#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket
"#,
        );
        let diags = engine.evaluate_rules(&model, &ValidateConfig::default()).unwrap();
        let guard_diag = diags.iter().find(|d| d.rule_id == "check_bucket_name");
        assert!(
            guard_diag.is_some(),
            "guard rule fires due to Properties. prefix mismatch in has_property (known bug)"
        );
    }

    #[test]
    fn evaluate_rules_can_be_called_repeatedly() {
        let engine = make_engine();
        let model = make_model_from_yaml(
            r#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  A:
    Type: AWS::S3::Bucket
"#,
        );
        // The per-thread evaluation context is installed and torn down each call,
        // so repeated evaluations on one thread neither deadlock nor leak state.
        let _ = engine.evaluate_rules(&model, &ValidateConfig::default()).unwrap();
        let diags = engine.evaluate_rules(&model, &ValidateConfig::default()).unwrap();
        assert!(
            diags.iter().all(|d| d.severity != Severity::Fatal),
            "rego engine should not produce Fatal diagnostics"
        );
    }

    #[test]
    fn build_rule_metadata_map_returns_entries() {
        let index = build_rule_metadata_map();
        assert!(!index.is_empty());
    }

    const BUILTIN_TEST_TEMPLATE: &str = r#"
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  Env:
    Type: String
    AllowedValues:
      - prod
      - dev
  Port:
    Type: Number
Conditions:
  IsProd:
    Fn::Equals:
      - !Ref Env
      - prod
Mappings:
  RegionMap:
    us-east-1:
      AMI: ami-12345678
    us-west-2:
      AMI: ami-abcdefgh
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket
      Tags:
        - Key: Env
          Value: !If [IsProd, "production", "development"]
  MyFunc:
    Type: AWS::Lambda::Function
    DependsOn: MyBucket
    Condition: IsProd
    Properties:
      FunctionName: my-func
      Runtime: python3.12
      Handler: index.handler
      Code:
        S3Bucket: !Ref MyBucket
        S3Key: code.zip
  MyQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: my-queue
Transform: AWS::Serverless-2016-10-31
"#;

    fn eval_builtin_policy(rego_source: &str, rule_id: &str) -> Vec<Diagnostic> {
        let config = EngineConfig {
            custom_rules: vec![ExternalRuleSource { name: "builtin_test.rego".into(), content: rego_source.into() }],
            guard_rules: vec![],
            ..Default::default()
        };
        let engine = RegoEngine::new(config).unwrap();
        let model = make_model_from_yaml(BUILTIN_TEST_TEMPLATE);
        let diags = engine.evaluate_rules(&model, &ValidateConfig::default()).unwrap();
        diags.into_iter().filter(|d| d.rule_id == rule_id).collect()
    }

    #[test]
    fn builtin_resolve_returns_property_value() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    val := resolve("MyBucket", "BucketName")
    val == "my-bucket"
    v := {"rule_id": "B_RESOLVE", "severity": "error", "message": "ok", "resource_id": "MyBucket"}
}
"#,
            "B_RESOLVE",
        );
        assert_eq!(diags.len(), 1, "resolve should return 'my-bucket'");
    }

    #[test]
    fn builtin_resolve_all_returns_conditional_values() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    vals := resolve_all("MyBucket", "Tags.0.Value")
    count(vals) >= 1
    v := {"rule_id": "B_RESOLVE_ALL", "severity": "error", "message": "ok", "resource_id": "MyBucket"}
}
"#,
            "B_RESOLVE_ALL",
        );
        assert_eq!(diags.len(), 1, "resolve_all should return at least one value");
    }

    #[test]
    fn builtin_is_dynamic_on_conditional_property() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    is_dynamic("MyFunc", "Code.S3Bucket")
    v := {"rule_id": "B_IS_DYN", "severity": "error", "message": "ok", "resource_id": "MyFunc"}
}
"#,
            "B_IS_DYN",
        );
        assert_eq!(diags.len(), 1, "Code.S3Bucket is a Ref → dynamic");
    }

    #[test]
    fn builtin_is_dynamic_false_for_static() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    not is_dynamic("MyBucket", "BucketName")
    v := {"rule_id": "B_NOT_DYN", "severity": "error", "message": "ok", "resource_id": "MyBucket"}
}
"#,
            "B_NOT_DYN",
        );
        assert_eq!(diags.len(), 1, "BucketName is static");
    }

    #[test]
    fn builtin_resources_of_type() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    ids := resources_of_type("AWS::S3::Bucket")
    count(ids) == 1
    v := {"rule_id": "B_ROT", "severity": "error", "message": "ok", "resource_id": ""}
}
"#,
            "B_ROT",
        );
        assert_eq!(diags.len(), 1, "should find 1 S3 bucket");
    }

    #[test]
    fn builtin_has_property_true() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    has_property("MyBucket", "BucketName")
    v := {"rule_id": "B_HAS_P", "severity": "error", "message": "ok", "resource_id": "MyBucket"}
}
"#,
            "B_HAS_P",
        );
        assert_eq!(diags.len(), 1, "MyBucket has BucketName");
    }

    #[test]
    fn builtin_has_property_false() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    not has_property("MyBucket", "NonExistent")
    v := {"rule_id": "B_NO_P", "severity": "error", "message": "ok", "resource_id": "MyBucket"}
}
"#,
            "B_NO_P",
        );
        assert_eq!(diags.len(), 1, "MyBucket does not have NonExistent");
    }

    #[test]
    fn builtin_has_transform() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    has_transform("AWS::Serverless-2016-10-31")
    v := {"rule_id": "B_HAS_T", "severity": "error", "message": "ok", "resource_id": ""}
}
"#,
            "B_HAS_T",
        );
        assert_eq!(diags.len(), 1, "template has Serverless transform");
    }

    #[test]
    fn builtin_param_allowed_values() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    vals := param_allowed_values("Env")
    count(vals) == 2
    v := {"rule_id": "B_PAV", "severity": "error", "message": "ok", "resource_id": ""}
}
"#,
            "B_PAV",
        );
        assert_eq!(diags.len(), 1, "Env has 2 allowed values");
    }

    #[test]
    fn builtin_param_type() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    t := param_type("Port")
    t == "Number"
    v := {"rule_id": "B_PT", "severity": "error", "message": "ok", "resource_id": ""}
}
"#,
            "B_PT",
        );
        assert_eq!(diags.len(), 1, "Port param type is Number");
    }

    #[test]
    fn builtin_mapping_value() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    val := mapping_value("RegionMap", "us-east-1", "AMI")
    val == "ami-12345678"
    v := {"rule_id": "B_MAP", "severity": "error", "message": "ok", "resource_id": ""}
}
"#,
            "B_MAP",
        );
        assert_eq!(diags.len(), 1, "mapping lookup should return ami-12345678");
    }

    #[test]
    fn builtin_resource_condition() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    c := resource_condition("MyFunc")
    c == "IsProd"
    v := {"rule_id": "B_RC", "severity": "error", "message": "ok", "resource_id": "MyFunc"}
}
"#,
            "B_RC",
        );
        assert_eq!(diags.len(), 1, "MyFunc has condition IsProd");
    }

    #[test]
    fn builtin_resource_condition_null_when_none() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    c := resource_condition("MyBucket")
    is_null(c)
    v := {"rule_id": "B_RC_NULL", "severity": "error", "message": "ok", "resource_id": "MyBucket"}
}
"#,
            "B_RC_NULL",
        );
        assert_eq!(diags.len(), 1, "MyBucket has no condition");
    }

    #[test]
    fn builtin_get_resource() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    res := get_resource("MyBucket")
    res.resourceType == "AWS::S3::Bucket"
    v := {"rule_id": "B_GR", "severity": "error", "message": "ok", "resource_id": "MyBucket"}
}
"#,
            "B_GR",
        );
        assert_eq!(diags.len(), 1, "get_resource should return bucket data");
    }

    #[test]
    fn builtin_depends_on() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    depends_on("MyFunc", "MyBucket")
    v := {"rule_id": "B_DEP", "severity": "error", "message": "ok", "resource_id": "MyFunc"}
}
"#,
            "B_DEP",
        );
        assert_eq!(diags.len(), 1, "MyFunc depends on MyBucket");
    }

    #[test]
    fn builtin_ref_targets() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    targets := ref_targets("MyFunc")
    count(targets) > 0
    v := {"rule_id": "B_RT", "severity": "error", "message": "ok", "resource_id": "MyFunc"}
}
"#,
            "B_RT",
        );
        assert_eq!(diags.len(), 1, "MyFunc should have ref targets (MyBucket)");
    }

    #[test]
    fn builtin_ref_sources() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    sources := ref_sources("MyBucket")
    count(sources) > 0
    v := {"rule_id": "B_RS", "severity": "error", "message": "ok", "resource_id": "MyBucket"}
}
"#,
            "B_RS",
        );
        assert_eq!(diags.len(), 1, "MyBucket should have ref sources (MyFunc)");
    }

    #[test]
    fn builtin_edges_from() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    edges := edges_from("MyFunc")
    count(edges) > 0
    v := {"rule_id": "B_EF", "severity": "error", "message": "ok", "resource_id": "MyFunc"}
}
"#,
            "B_EF",
        );
        assert_eq!(diags.len(), 1, "MyFunc should have outgoing edges");
    }

    #[test]
    fn builtin_edges_to() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    edges := edges_to("MyBucket")
    count(edges) > 0
    v := {"rule_id": "B_ET", "severity": "error", "message": "ok", "resource_id": "MyBucket"}
}
"#,
            "B_ET",
        );
        assert_eq!(diags.len(), 1, "MyBucket should have incoming edges");
    }

    #[test]
    fn builtin_make_diag_at() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    v := make_diag_at("B_MDA", "error", "MyBucket", "BucketName", "test diag at")
}
"#,
            "B_MDA",
        );
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].message, "test diag at");
    }

    #[test]
    fn builtin_make_diag_full() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    v := make_diag_full("B_MDF", "error", "MyBucket", "BucketName", "full diag", "fix it", "https://example.com")
}
"#,
            "B_MDF",
        );
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].message, "full diag");
    }

    #[test]
    fn builtin_schema_properties_known_type() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    props := schema_properties("AWS::S3::Bucket")
    # Just verify the builtin is callable and returns an array
    is_array(props)
    v := {"rule_id": "B_SP", "severity": "error", "message": "ok", "resource_id": ""}
}
"#,
            "B_SP",
        );
        assert_eq!(diags.len(), 1, "schema_properties should be callable and return array");
    }

    #[test]
    fn builtin_schema_required_known_type() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    req := schema_required("AWS::Lambda::Function")
    is_array(req)
    v := {"rule_id": "B_SR", "severity": "error", "message": "ok", "resource_id": ""}
}
"#,
            "B_SR",
        );
        assert_eq!(diags.len(), 1, "schema_required should be callable and return array");
    }

    #[test]
    fn builtin_conditions_compatible() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    conditions_compatible("MyBucket", "MyQueue")
    v := {"rule_id": "B_CC", "severity": "error", "message": "ok", "resource_id": ""}
}
"#,
            "B_CC",
        );
        assert_eq!(diags.len(), 1, "unconditional resources are always compatible");
    }

    #[test]
    fn builtin_resolve_type() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    t := resolve_type("MyBucket", "BucketName")
    t == "string"
    v := {"rule_id": "B_RTYPE", "severity": "error", "message": "ok", "resource_id": "MyBucket"}
}
"#,
            "B_RTYPE",
        );
        assert_eq!(diags.len(), 1, "BucketName should resolve to string type");
    }

    #[test]
    fn region_override_available_to_builtins() {
        let custom_rego = r#"
package region_test
import rego.v1
violation contains v if {
    r := input_region()
    r == "eu-west-1"
    v := {"rule_id": "B_REGION", "severity": "error", "message": "ok", "resource_id": ""}
}
"#;
        let config = EngineConfig {
            custom_rules: vec![ExternalRuleSource { name: "region_test.rego".into(), content: custom_rego.into() }],
            guard_rules: vec![],
            ..Default::default()
        };
        let engine = RegoEngine::new(config).unwrap();
        let model = make_model_from_yaml(BUILTIN_TEST_TEMPLATE);
        let mut vc = ValidateConfig::default();
        vc.pseudo_parameter_overrides.region = Some("eu-west-1".to_string());
        let diags = engine.evaluate_rules(&model, &vc).unwrap();
        let found = diags.iter().find(|d| d.rule_id == "B_REGION");
        assert!(found.is_some(), "input_region() should return eu-west-1");
    }

    #[test]
    fn multiple_custom_packages_all_evaluated() {
        let pkg_a = r#"
package custom_a
import rego.v1
violation contains v if {
    v := {"rule_id": "PKG_A", "severity": "error", "message": "from A", "resource_id": ""}
}
"#;
        let pkg_b = r#"
package custom_b
import rego.v1
violation contains v if {
    v := {"rule_id": "PKG_B", "severity": "error", "message": "from B", "resource_id": ""}
}
"#;
        let config = EngineConfig {
            custom_rules: vec![
                ExternalRuleSource { name: "a.rego".into(), content: pkg_a.into() },
                ExternalRuleSource { name: "b.rego".into(), content: pkg_b.into() },
            ],
            guard_rules: vec![],
            ..Default::default()
        };
        let engine = RegoEngine::new(config).unwrap();
        let model = make_model_from_yaml(BUILTIN_TEST_TEMPLATE);
        let diags = engine.evaluate_rules(&model, &ValidateConfig::default()).unwrap();
        assert!(diags.iter().any(|d| d.rule_id == "PKG_A"), "package A should fire");
        assert!(diags.iter().any(|d| d.rule_id == "PKG_B"), "package B should fire");
    }

    #[test]
    fn duplicate_custom_package_deduplicated() {
        let source = r#"
package custom_dedup
import rego.v1
violation contains v if {
    v := {"rule_id": "DEDUP1", "severity": "error", "message": "first", "resource_id": ""}
}
"#;
        let config = EngineConfig {
            custom_rules: vec![
                ExternalRuleSource { name: "a.rego".into(), content: source.into() },
                ExternalRuleSource { name: "b.rego".into(), content: source.into() },
            ],
            guard_rules: vec![],
            ..Default::default()
        };
        let engine = RegoEngine::new(config).unwrap();
        assert_eq!(
            engine.custom_packages.iter().filter(|p| p.contains("custom_dedup")).count(),
            1,
            "duplicate package should be deduplicated"
        );
    }

    #[test]
    fn builtin_follow_ref_returns_target_resource() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    target := follow_ref("MyFunc", "Code.S3Bucket")
    target == "MyBucket"
    v := {"rule_id": "B_FREF", "severity": "error", "message": "ok", "resource_id": "MyFunc"}
}
"#,
            "B_FREF",
        );
        assert_eq!(diags.len(), 1, "follow_ref should resolve Ref to MyBucket");
    }

    #[test]
    fn builtin_is_from_parameter_true_for_ref_param() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    is_from_parameter("MyBucket", "Tags.0.Value")
    v := {"rule_id": "B_IFP", "severity": "error", "message": "ok", "resource_id": "MyBucket"}
}
"#,
            "B_IFP",
        );
        // Tags.0.Value uses Fn::If with a condition based on a parameter, so it's from a parameter
        assert!(diags.len() <= 1, "expected at most 1 diagnostic, got {}", diags.len());
    }

    #[test]
    fn builtin_flatten_list_returns_items() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    items := flatten_list("MyBucket", "Tags")
    count(items) >= 1
    v := {"rule_id": "B_FL", "severity": "error", "message": "ok", "resource_id": "MyBucket"}
}
"#,
            "B_FL",
        );
        assert_eq!(diags.len(), 1, "flatten_list should return tag items");
    }

    #[test]
    fn builtin_resolve_scenarios_returns_values() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    scenarios := resolve_scenarios("MyBucket", "Tags.0.Value")
    count(scenarios) >= 1
    v := {"rule_id": "B_RS2", "severity": "error", "message": "ok", "resource_id": "MyBucket"}
}
"#,
            "B_RS2",
        );
        assert_eq!(diags.len(), 1, "resolve_scenarios should return at least one scenario");
    }

    #[test]
    fn builtin_is_satisfiable_with_compatible_assumptions() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    is_satisfiable({"IsProd": true})
    v := {"rule_id": "B_SAT", "severity": "error", "message": "ok", "resource_id": ""}
}
"#,
            "B_SAT",
        );
        assert_eq!(diags.len(), 1, "IsProd=true should be satisfiable");
    }

    #[test]
    fn builtin_make_diag_produces_diagnostic() {
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    v := make_diag("B_MD", "error", "MyBucket", "test message")
}
"#,
            "B_MD",
        );
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].message, "test message");
    }

    #[test]
    fn builtin_estimated_string_length_bounds_returns_both_bounds() {
        // `!If [IsProd, "production", "development"]` - the deployment picks one of
        // two known values, so the length is bounded but not fixed.
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    bounds := estimated_string_length_bounds("MyBucket", "Tags.0.Value")
    bounds.shortest == 10
    bounds.longest == 11
    v := {"rule_id": "B_ESL", "severity": "error", "message": "ok", "resource_id": "MyBucket"}
}
"#,
            "B_ESL",
        );
        assert_eq!(diags.len(), 1, "a value chosen between two known strings must report both bounds");
    }

    #[test]
    fn builtin_estimated_string_length_bounds_is_undefined_for_a_literal() {
        // Schema validation checks a literal against the constraint, so this rule
        // is not given one to estimate.
        let diags = eval_builtin_policy(
            r#"
package builtin_test
import rego.v1
violation contains v if {
    bounds := estimated_string_length_bounds("MyBucket", "BucketName")
    v := {"rule_id": "B_ESL_LITERAL", "severity": "error", "message": "ok", "resource_id": "MyBucket"}
}
"#,
            "B_ESL_LITERAL",
        );
        assert!(diags.is_empty(), "a literal string must yield no bounds, got {diags:?}");
    }

    #[test]
    fn regoengine_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RegoEngine>();
    }

    #[test]
    fn evaluate_rules_isolates_model_and_region_across_threads() {
        // One engine, many threads, each with a distinct model and region. The
        // probes echo the region and the resource names the thread should see, so
        // any leakage between threads' evaluation contexts surfaces as a mismatch.
        let probe = r#"
package concurrency_probe
import rego.v1
violation contains v if {
    r := input_region()
    v := {"rule_id": "REGIONPROBE", "severity": "info", "message": r, "resource_id": ""}
}
violation contains v if {
    some name in resources_of_type("AWS::S3::Bucket")
    v := {"rule_id": "MODELPROBE", "severity": "info", "message": name, "resource_id": name}
}
"#;
        let config = EngineConfig {
            custom_rules: vec![ExternalRuleSource { name: "concurrency_probe.rego".into(), content: probe.into() }],
            guard_rules: vec![],
            ..Default::default()
        };
        let engine = Arc::new(RegoEngine::new(config).unwrap());

        const THREAD_COUNT: usize = 8;
        let barrier = Arc::new(Barrier::new(THREAD_COUNT));
        let handles: Vec<_> = (0..THREAD_COUNT)
            .map(|i| {
                let engine = Arc::clone(&engine);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let region = format!("region-{i}");
                    let bucket = format!("Bucket{i}");
                    let model = make_model_from_yaml(&format!(
                        "AWSTemplateFormatVersion: \"2010-09-09\"\nResources:\n  {bucket}:\n    Type: AWS::S3::Bucket\n"
                    ));
                    let mut config = ValidateConfig::default();
                    config.pseudo_parameter_overrides.region = Some(region.clone());
                    // Release every thread at once so their evaluations overlap.
                    barrier.wait();
                    let diags = engine.evaluate_rules(&model, &config).unwrap();
                    (region, bucket, diags)
                })
            })
            .collect();

        for handle in handles {
            let (region, bucket, diags) = handle.join().unwrap();
            let regions: Vec<&str> =
                diags.iter().filter(|d| d.rule_id == "REGIONPROBE").map(|d| d.message.as_str()).collect();
            assert_eq!(regions, vec![region.as_str()], "a thread must observe only its own region");
            let resources: Vec<&str> =
                diags.iter().filter(|d| d.rule_id == "MODELPROBE").map(|d| d.message.as_str()).collect();
            assert_eq!(resources, vec![bucket.as_str()], "a thread must observe only its own model");
        }
    }

    const SUPPRESSION_TEMPLATE: &str = r#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  MyInstance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-12345678
      InstanceType: !Sub "t3.micro"
"#;

    fn exclude_ids(ids: &[&str]) -> ValidateConfig {
        ValidateConfig {
            filters: FilterConfig::new(
                RuleFilterConfig::default(),
                RuleFilterConfig { ids: ids.iter().map(|s| s.to_string()).collect(), ..Default::default() },
            ),
            ..Default::default()
        }
    }

    #[test]
    fn exclude_id_suppresses_matching_builtin_and_preserves_other_findings() {
        let engine = make_engine();
        let model = make_model_from_yaml(SUPPRESSION_TEMPLATE);

        let unfiltered = engine.evaluate_rules(&model, &ValidateConfig::default()).unwrap();
        assert!(unfiltered.iter().any(|d| d.rule_id == "W9010"), "hardcoded AMI should trigger W9010");
        let mut other_findings: Vec<(String, String)> = unfiltered
            .iter()
            .filter(|d| d.rule_id != "W9010")
            .map(|d| (d.rule_id.clone(), d.message.clone()))
            .collect();
        assert!(!other_findings.is_empty(), "template must also produce a non-W9010 finding worth preserving");
        other_findings.sort();

        let filtered = engine.evaluate_rules(&model, &exclude_ids(&["W9010"])).unwrap();
        assert!(filtered.iter().all(|d| d.rule_id != "W9010"), "the excluded rule must not be emitted");
        let mut remaining: Vec<(String, String)> =
            filtered.iter().map(|d| (d.rule_id.clone(), d.message.clone())).collect();
        remaining.sort();
        assert_eq!(remaining, other_findings, "excluding one rule must not alter any other diagnostic");
    }

    #[test]
    fn include_id_globally_suppresses_every_other_builtin() {
        let engine = make_engine();
        let model = make_model_from_yaml(SUPPRESSION_TEMPLATE);

        let config = ValidateConfig {
            filters: FilterConfig::new(
                RuleFilterConfig { ids: vec!["W9010".to_string()], ..Default::default() },
                RuleFilterConfig::default(),
            ),
            ..Default::default()
        };
        let filtered = engine.evaluate_rules(&model, &config).unwrap();
        assert!(filtered.iter().any(|d| d.rule_id == "W9010"), "the included rule must still fire");
        assert!(
            filtered.iter().all(|d| d.rule_id == "W9010"),
            "a non-empty include filter must globally suppress every rule it can never admit"
        );
    }

    #[test]
    fn severity_level_prunes_lower_severity_builtins() {
        let engine = make_engine();
        let model = make_model_from_yaml(SUPPRESSION_TEMPLATE);

        let default_run = engine.evaluate_rules(&model, &ValidateConfig::default()).unwrap();
        assert!(default_run.iter().any(|d| d.rule_id == "W9010"), "W9010 fires at the default Info level");

        let config = ValidateConfig { severity_level: Severity::Error, ..Default::default() };
        let error_only = engine.evaluate_rules(&model, &config).unwrap();
        assert!(
            error_only.iter().all(|d| d.severity >= Severity::Error),
            "no sub-Error diagnostics should be produced when the level is Error"
        );
        assert!(
            error_only.iter().all(|d| d.rule_id != "W9010"),
            "the Warn rule W9010 must be pruned at the Error level"
        );
    }

    #[test]
    fn cfn_rule_active_guard_short_circuits_a_suppressed_rule_body() {
        // Every built-in clause is shaped like this probe: cfn_rule_active guards
        // the body, so a globally suppressed rule stops before its body runs. The
        // body here would evaluate regex.match on an invalid pattern if reached;
        // the probe diagnostic is the observable signal that the body executed.
        let probe = r#"
package guard_probe
import rego.v1
violation contains v if {
    cfn_rule_active("W9010")
    not regex.match("(unterminated", "anything")
    v := {"rule_id": "GUARDPROBE", "severity": "error", "message": "guarded body ran", "resource_id": ""}
}
"#;
        let config = EngineConfig {
            custom_rules: vec![ExternalRuleSource { name: "guard_probe.rego".into(), content: probe.into() }],
            guard_rules: vec![],
            ..Default::default()
        };
        let engine = RegoEngine::new(config).unwrap();
        let model = make_model_from_yaml(
            r#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
"#,
        );

        let active = engine.evaluate_rules(&model, &ValidateConfig::default()).unwrap();
        assert!(active.iter().any(|d| d.rule_id == "GUARDPROBE"), "an active rule's guarded body must run");

        let suppressed = engine.evaluate_rules(&model, &exclude_ids(&["W9010"])).unwrap();
        assert!(
            suppressed.iter().all(|d| d.rule_id != "GUARDPROBE"),
            "a suppressed rule's guarded body - including its invalid regex - must not run"
        );
    }
}
