use data_source::embedded;
use data_source::rule_data::{NormalizedRuleTablesDocument, RuleData, RuleTables};
use data_source::types::{
    ArtifactCountEntry, CodepipelineArtifactCounts, DeprecatedResourceTypes, GetattData, IamActionResourcePatterns,
    KnownResourceTypes, PrimaryIdentifiers, RetentionPeriodRequirements, SchemaMetadataCatalog,
    SecretsManagerArnFields, SensitivePorts, StatefulResourceTypes,
};
use diagnostics::Diagnostic;
use rules::Category;
use schema_validator::OverlayCatalog;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};
use template_model::SemanticModel;

pub mod best_practices;
pub mod conditions;
pub mod intrinsics;
mod patterns;
pub mod references;
pub mod resources;
pub mod resources_extra;
pub mod structure;

/// Pre-loaded data from embedded JSON constants, shared across all rule evaluations.
pub struct CachedData {
    pub known_types: HashSet<String>,
    pub getatt_attrs: HashMap<String, Vec<String>>,
    pub getatt_attr_types: HashMap<String, HashMap<String, String>>,
    schema_metadata: Arc<SchemaMetadataCatalog>,
    pub iam_action_resource_patterns: HashMap<String, Vec<String>>,
    pub enum_data: HashMap<String, serde_json::Value>,
    pub stateful_resource_types: HashSet<String>,
    /// Maps resource type → list of required retention properties
    pub retention_period_requirements: HashMap<String, Vec<String>>,
    /// Maps resource type → list of primary identifier property names
    pub primary_identifiers: HashMap<String, Vec<String>>,
    /// Maps action category → artifact count constraints
    pub codepipeline_artifact_counts: HashMap<String, ArtifactCountEntry>,
    /// Deprecated resource type names
    pub deprecated_resource_types: HashSet<String>,
    /// Ports that should not be open to 0.0.0.0/0
    pub sensitive_ports: Vec<u16>,
    /// Property names that expect a Secrets Manager ARN rather than a resolved secret value
    pub secretsmanager_arn_fields: Vec<String>,
    pub classic_load_balancer_certificate_protocols: HashSet<String>,
    pub fargate_supported_log_drivers: Vec<String>,
    pub fargate_supported_log_driver_fix: String,
    pub lambda_image_excluded_properties: Vec<String>,
    pub lambda_reserved_environment_keys: HashSet<String>,
    pub load_balancer_v2_certificate_protocols: HashSet<String>,
    /// Parsed and validated rule tables data.
    pub rule_tables: RuleTables,
    /// Compiled regex for matching previous-generation instance types (e.g. `m1.large`).
    pub previous_generation_instance_regex: regex::Regex,
}

/// Enum data files and their embedded byte constants.
static ENUM_DATA: LazyLock<Vec<(&str, &[u8])>> = LazyLock::new(|| {
    vec![
        ("data/aws_ec2_instance_instancetype_enum", &*embedded::AWS_EC2_INSTANCE_INSTANCETYPE_ENUM_BYTES),
        (
            "data/aws_emr_cluster_instancetypeconfig_instancetype_enum",
            &*embedded::AWS_EMR_CLUSTER_INSTANCETYPECONFIG_INSTANCETYPE_ENUM_BYTES,
        ),
        ("data/aws_gamelift_fleet_ec2instancetype_enum", &*embedded::AWS_GAMELIFT_FLEET_EC2INSTANCETYPE_ENUM_BYTES),
        ("data/aws_rds_dbinstance_dbinstanceclass_enum", &*embedded::AWS_RDS_DBINSTANCE_DBINSTANCECLASS_ENUM_BYTES),
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
    ]
});

fn render_supported_choice_fix(choices: &[String]) -> anyhow::Result<String> {
    let (last, preceding) = choices
        .split_last()
        .ok_or_else(|| anyhow::anyhow!("Embedded Fargate supported log drivers must not be empty"))?;
    Ok(match preceding {
        [] => format!("Use '{last}'"),
        [first] => format!("Use '{first}' or '{last}'"),
        values => format!("Use '{}', or '{last}'", values.join("', '")),
    })
}

impl CachedData {
    pub fn load() -> anyhow::Result<Self> {
        let known_resource_types: KnownResourceTypes = serde_json::from_slice(&embedded::KNOWN_RESOURCE_TYPES_BYTES)
            .map_err(|e| anyhow::anyhow!("Failed to parse embedded known_resource_types data: {}", e))?;
        let known_types: HashSet<String> = known_resource_types.known_resource_types.into_iter().collect();
        anyhow::ensure!(!known_types.is_empty(), "Embedded known_resource_types data must not be empty");

        let getatt_data: GetattData = serde_json::from_slice(&embedded::GETATT_ATTRIBUTES_BYTES)
            .map_err(|e| anyhow::anyhow!("Failed to parse embedded getatt_attributes data: {}", e))?;
        let getatt_attrs = getatt_data.getatt_attributes;
        let getatt_attr_types = getatt_data.getatt_attribute_types;
        anyhow::ensure!(!getatt_attrs.is_empty(), "Embedded getatt_attributes data must not be empty");
        anyhow::ensure!(!getatt_attr_types.is_empty(), "Embedded getatt_attribute_types data must not be empty");

        let stateful_data: StatefulResourceTypes = serde_json::from_slice(&embedded::STATEFUL_RESOURCE_TYPES_BYTES)
            .map_err(|e| anyhow::anyhow!("Failed to parse embedded stateful_resource_types data: {}", e))?;
        let stateful_resource_types = stateful_data.stateful_resource_types;
        anyhow::ensure!(!stateful_resource_types.is_empty(), "Embedded stateful_resource_types data must not be empty");

        let retention_data: RetentionPeriodRequirements =
            serde_json::from_slice(&embedded::RETENTION_PERIOD_REQUIREMENTS_BYTES)
                .map_err(|e| anyhow::anyhow!("Failed to parse embedded retention_period_requirements data: {}", e))?;
        let retention_period_requirements = retention_data.retention_period_requirements;
        anyhow::ensure!(
            !retention_period_requirements.is_empty(),
            "Embedded retention_period_requirements data must not be empty"
        );

        let primary_id_data: PrimaryIdentifiers = serde_json::from_slice(&embedded::PRIMARY_IDENTIFIERS_BYTES)
            .map_err(|e| anyhow::anyhow!("Failed to parse embedded primary_identifiers data: {}", e))?;
        let primary_identifiers = primary_id_data.primary_identifiers;
        anyhow::ensure!(!primary_identifiers.is_empty(), "Embedded primary_identifiers data must not be empty");

        let pipeline_data: CodepipelineArtifactCounts =
            serde_json::from_slice(&embedded::CODEPIPELINE_ACTION_ARTIFACT_COUNTS_BYTES).map_err(|e| {
                anyhow::anyhow!("Failed to parse embedded codepipeline_action_artifact_counts data: {}", e)
            })?;
        let codepipeline_artifact_counts = pipeline_data.codepipeline_action_artifact_counts;
        anyhow::ensure!(
            !codepipeline_artifact_counts.is_empty(),
            "Embedded codepipeline_action_artifact_counts data must not be empty"
        );

        let deprecated_data: DeprecatedResourceTypes =
            serde_json::from_slice(&embedded::DEPRECATED_RESOURCE_TYPES_BYTES)
                .map_err(|e| anyhow::anyhow!("Failed to parse embedded deprecated_resource_types data: {}", e))?;
        let deprecated_resource_types: HashSet<String> =
            deprecated_data.deprecated_resource_types.into_iter().collect();
        anyhow::ensure!(
            !deprecated_resource_types.is_empty(),
            "Embedded deprecated_resource_types data must not be empty"
        );

        let sensitive_data: SensitivePorts = serde_json::from_slice(&embedded::SENSITIVE_PORTS_BYTES)
            .map_err(|e| anyhow::anyhow!("Failed to parse embedded sensitive_ports data: {}", e))?;
        let sensitive_ports = sensitive_data.sensitive_ports;
        anyhow::ensure!(!sensitive_ports.is_empty(), "Embedded sensitive_ports data must not be empty");

        let sm_arn_data: SecretsManagerArnFields =
            serde_json::from_slice(&embedded::SECRETSMANAGER_ARN_FIELDS_BYTES)
                .map_err(|e| anyhow::anyhow!("Failed to parse embedded secretsmanager_arn_fields data: {}", e))?;
        let secretsmanager_arn_fields = sm_arn_data.secretsmanager_arn_fields;
        anyhow::ensure!(
            !secretsmanager_arn_fields.is_empty(),
            "Embedded secretsmanager_arn_fields data must not be empty"
        );

        let rule_data: RuleData = serde_json::from_slice(&embedded::RULE_DATA_BYTES)
            .map_err(|e| anyhow::anyhow!("Failed to parse embedded rule data: {}", e))?;
        let classic_load_balancer_certificate_protocols: HashSet<String> =
            rule_data.classic_load_balancer_certificate_protocols.into_iter().collect();
        let fargate_supported_log_drivers = rule_data.fargate_supported_log_drivers;
        let fargate_supported_log_driver_fix = render_supported_choice_fix(&fargate_supported_log_drivers)?;
        let lambda_image_excluded_properties = rule_data.lambda_image_excluded_properties;
        anyhow::ensure!(
            !lambda_image_excluded_properties.is_empty(),
            "Embedded Lambda image excluded properties must not be empty"
        );
        let lambda_reserved_environment_keys: HashSet<String> =
            rule_data.lambda_reserved_environment_keys.into_iter().collect();
        anyhow::ensure!(
            !lambda_reserved_environment_keys.is_empty(),
            "Embedded Lambda reserved environment keys must not be empty"
        );
        let load_balancer_v2_certificate_protocols: HashSet<String> =
            rule_data.load_balancer_v2_certificate_protocols.into_iter().collect();
        anyhow::ensure!(
            !classic_load_balancer_certificate_protocols.is_empty(),
            "Embedded classic load balancer certificate protocols must not be empty"
        );
        anyhow::ensure!(
            !load_balancer_v2_certificate_protocols.is_empty(),
            "Embedded load balancer v2 certificate protocols must not be empty"
        );

        let rule_tables_doc: NormalizedRuleTablesDocument = serde_json::from_slice(&embedded::RULE_TABLES_BYTES)
            .map_err(|e| anyhow::anyhow!("Failed to parse embedded rule tables: {}", e))?;
        let rule_tables = RuleTables::validate(rule_tables_doc.rule_tables)
            .map_err(|e| anyhow::anyhow!("Embedded rule tables validation failed: {}", e))?;

        let previous_generation_instance_regex = regex::Regex::new(&rule_tables.previous_generation_instance_pattern)
            .map_err(|e| {
            anyhow::anyhow!(
                "Invalid previous_generation_instance_pattern '{}': {}",
                rule_tables.previous_generation_instance_pattern,
                e
            )
        })?;

        let mut enum_data = HashMap::new();
        for (name, bytes) in ENUM_DATA.iter() {
            let value: serde_json::Value = serde_json::from_slice(bytes)
                .map_err(|e| anyhow::anyhow!("Failed to parse embedded enum data '{}': {}", name, e))?;
            let document =
                value.as_object().ok_or_else(|| anyhow::anyhow!("Embedded enum data '{}' must be an object", name))?;
            anyhow::ensure!(!document.is_empty(), "Embedded enum data '{}' must not be empty", name);
            anyhow::ensure!(
                document.values().all(|entry| entry.as_object().is_some_and(|object| !object.is_empty())),
                "Embedded enum data '{}' must contain a nonempty data object",
                name
            );
            enum_data.insert(name.to_string(), value);
        }
        let iam_data: IamActionResourcePatterns = serde_json::from_slice(&embedded::IAM_ACTION_RESOURCE_PATTERNS_BYTES)
            .map_err(|e| anyhow::anyhow!("Failed to parse embedded iam_action_resource_patterns data: {}", e))?;
        let iam_action_resource_patterns = iam_data.iam_action_resource_patterns;
        anyhow::ensure!(
            !iam_action_resource_patterns.is_empty(),
            "Embedded iam_action_resource_patterns data must not be empty"
        );
        for (action, patterns) in &iam_action_resource_patterns {
            anyhow::ensure!(!action.is_empty(), "Embedded IAM action name must not be empty");
            anyhow::ensure!(
                !patterns.is_empty(),
                "Embedded IAM action '{}' must have at least one resource pattern",
                action
            );
            anyhow::ensure!(
                patterns.iter().all(|pattern| !pattern.is_empty()),
                "Embedded IAM action '{}' contains an empty resource pattern",
                action
            );
        }

        Ok(CachedData {
            known_types,
            getatt_attrs,
            getatt_attr_types,
            schema_metadata: Arc::new(SchemaMetadataCatalog::new()),
            iam_action_resource_patterns,
            enum_data,
            stateful_resource_types,
            retention_period_requirements,
            primary_identifiers,
            codepipeline_artifact_counts,
            deprecated_resource_types,
            sensitive_ports,
            secretsmanager_arn_fields,
            classic_load_balancer_certificate_protocols,
            fargate_supported_log_drivers,
            fargate_supported_log_driver_fix,
            lambda_image_excluded_properties,
            lambda_reserved_environment_keys,
            load_balancer_v2_certificate_protocols,
            rule_tables,
            previous_generation_instance_regex,
        })
    }

    /// Merges overlay catalog data into this cached data instance.
    ///
    /// Called when overlays are non-empty so their resource types, GetAtt
    /// attributes, attribute types, and primary identifiers are visible to rules.
    /// Overlay-aware schema metadata is installed separately through
    /// [`Self::set_schema_metadata`].
    pub fn merge_overlay_catalog(&mut self, catalog: &OverlayCatalog) -> anyhow::Result<()> {
        if catalog.is_empty() {
            return Ok(());
        }
        // Merge known types
        self.known_types.extend(catalog.type_names.iter().cloned());

        // Merge GetAtt attributes (sort/dedup after merging)
        for (type_name, attrs) in &catalog.getatt_attributes {
            let entry = self.getatt_attrs.entry(type_name.clone()).or_default();
            for attr in attrs {
                if !entry.contains(attr) {
                    entry.push(attr.clone());
                }
            }
            entry.sort();
            entry.dedup();
        }

        // Merge GetAtt attribute types
        for (type_name, attr_types) in &catalog.getatt_attribute_types {
            let entry = self.getatt_attr_types.entry(type_name.clone()).or_default();
            for (attr, atype) in attr_types {
                entry.insert(attr.clone(), atype.clone());
            }
        }

        // Merge primary identifiers
        for (type_name, pids) in &catalog.primary_identifiers {
            self.primary_identifiers.insert(type_name.clone(), pids.clone());
        }

        Ok(())
    }

    /// Installs the shared, overlay-aware schema-metadata catalog the engine
    /// resolved. The same [`Arc`] is shared across engines and validators, so no
    /// catalog is parsed or copied per engine.
    pub fn set_schema_metadata(&mut self, catalog: Arc<SchemaMetadataCatalog>) {
        self.schema_metadata = catalog;
    }

    /// The shared, overlay-aware schema-metadata catalog: resource type name to
    /// its typed metadata entry.
    pub fn schema_metadata_catalog(&self) -> &SchemaMetadataCatalog {
        &self.schema_metadata
    }
}

pub struct EvalContext<'a> {
    pub model: &'a Arc<SemanticModel>,
    pub input: &'a serde_json::Value,
    pub region: &'a Option<String>,
    pub cached_data: &'a CachedData,
}

pub type NativeRuleFn = fn(&EvalContext) -> Vec<Diagnostic>;

pub struct NativeRuleRegistry {
    pub rules: Vec<(Category, NativeRuleFn)>,
}

impl NativeRuleRegistry {
    pub fn new() -> Self {
        let mut reg = NativeRuleRegistry { rules: Vec::new() };
        structure::register(&mut reg);
        intrinsics::register(&mut reg);
        references::register(&mut reg);
        best_practices::register(&mut reg);
        resources::register(&mut reg);
        conditions::register(&mut reg);
        reg
    }

    pub fn add(&mut self, category: Category, f: NativeRuleFn) {
        self.rules.push((category, f));
    }

    pub fn evaluate(&self, ctx: &EvalContext, excluded_cats: &HashSet<&str>) -> Vec<Diagnostic> {
        let mut all = Vec::new();
        for (cat, f) in &self.rules {
            if excluded_cats.contains(cat.as_str()) {
                continue;
            }
            all.extend(f(ctx));
        }
        all
    }
}
