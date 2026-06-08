use data_source::embedded;
use data_source::types::{
    ArtifactCountEntry, CodepipelineArtifactCounts, DeprecatedResourceTypes, GetattData,
    KnownResourceTypes, PrimaryIdentifiers, RetentionPeriodRequirements, SensitivePorts,
    StatefulResourceTypes,
};
use diagnostics::Diagnostic;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock, OnceLock};
use template_model::SemanticModel;

pub mod best_practices;
pub mod conditions;
pub mod intrinsics;
pub mod references;
pub mod resources;
pub mod resources_extra;
pub mod structure;

/// Pre-loaded data from embedded JSON constants, shared across all rule evaluations.
pub struct CachedData {
    pub known_types: HashSet<String>,
    pub getatt_attrs: HashMap<String, Vec<String>>,
    pub getatt_attr_types: HashMap<String, HashMap<String, String>>,
    schema_metadata_lazy: OnceLock<serde_json::Value>,
    pub iam_action_resource_patterns: serde_json::Value,
    pub region_resource_types: serde_json::Value,
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
}

/// Enum data files and their embedded byte constants.
static ENUM_DATA: LazyLock<Vec<(&str, &[u8])>> = LazyLock::new(|| {
    vec![
        (
            "data/aws_ec2_instance_instancetype_enum",
            &*embedded::AWS_EC2_INSTANCE_INSTANCETYPE_ENUM_BYTES,
        ),
        (
            "data/aws_emr_cluster_instancetypeconfig_instancetype_enum",
            &*embedded::AWS_EMR_CLUSTER_INSTANCETYPECONFIG_INSTANCETYPE_ENUM_BYTES,
        ),
        (
            "data/aws_gamelift_fleet_ec2instancetype_enum",
            &*embedded::AWS_GAMELIFT_FLEET_EC2INSTANCETYPE_ENUM_BYTES,
        ),
        (
            "data/aws_rds_dbinstance_dbinstanceclass_enum",
            &*embedded::AWS_RDS_DBINSTANCE_DBINSTANCECLASS_ENUM_BYTES,
        ),
        (
            "data/aws_appstream_fleet_instancetype_enum",
            &*embedded::AWS_APPSTREAM_FLEET_INSTANCETYPE_ENUM_BYTES,
        ),
        (
            "data/aws_dax_cluster_nodetype_enum",
            &*embedded::AWS_DAX_CLUSTER_NODETYPE_ENUM_BYTES,
        ),
        (
            "data/aws_docdb_dbinstance_dbinstanceclass_enum",
            &*embedded::AWS_DOCDB_DBINSTANCE_DBINSTANCECLASS_ENUM_BYTES,
        ),
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
        (
            "data/aws_rds_dbinstance_db_instance_class",
            &*embedded::AWS_RDS_DBINSTANCE_DB_INSTANCE_CLASS_BYTES,
        ),
        (
            "data/aws_redshift_cluster_nodetype_enum",
            &*embedded::AWS_REDSHIFT_CLUSTER_NODETYPE_ENUM_BYTES,
        ),
        (
            "data/aws_amazonmq_broker_instancetype_enum",
            &*embedded::AWS_AMAZONMQ_BROKER_INSTANCETYPE_ENUM_BYTES,
        ),
    ]
});

impl CachedData {
    pub fn load() -> anyhow::Result<Self> {
        let known_resource_types: KnownResourceTypes =
            serde_json::from_slice(&embedded::KNOWN_RESOURCE_TYPES_BYTES)
                .map_err(|e| anyhow::anyhow!("known_resource_types: {}", e))?;
        let known_types: HashSet<String> = known_resource_types
            .known_resource_types
            .into_iter()
            .collect();

        let getatt_data: GetattData = serde_json::from_slice(&embedded::GETATT_ATTRIBUTES_BYTES)
            .map_err(|e| anyhow::anyhow!("getatt_attributes: {}", e))?;
        let getatt_attrs = getatt_data.getatt_attributes;
        let getatt_attr_types = getatt_data.getatt_attribute_types;

        let stateful_data: StatefulResourceTypes =
            serde_json::from_slice(&embedded::STATEFUL_RESOURCE_TYPES_BYTES)
                .map_err(|e| anyhow::anyhow!("stateful_resource_types: {}", e))?;
        let stateful_resource_types = stateful_data.stateful_resource_types;

        let retention_data: RetentionPeriodRequirements =
            serde_json::from_slice(&embedded::RETENTION_PERIOD_REQUIREMENTS_BYTES)
                .map_err(|e| anyhow::anyhow!("retention_period_requirements: {}", e))?;
        let retention_period_requirements = retention_data.retention_period_requirements;

        let primary_id_data: PrimaryIdentifiers =
            serde_json::from_slice(&embedded::PRIMARY_IDENTIFIERS_BYTES)
                .map_err(|e| anyhow::anyhow!("primary_identifiers: {}", e))?;
        let primary_identifiers = primary_id_data.primary_identifiers;

        let pipeline_data: CodepipelineArtifactCounts =
            serde_json::from_slice(&embedded::CODEPIPELINE_ACTION_ARTIFACT_COUNTS_BYTES)
                .map_err(|e| anyhow::anyhow!("codepipeline_action_artifact_counts: {}", e))?;
        let codepipeline_artifact_counts = pipeline_data.codepipeline_action_artifact_counts;

        let deprecated_data: DeprecatedResourceTypes =
            serde_json::from_slice(&embedded::DEPRECATED_RESOURCE_TYPES_BYTES)
                .map_err(|e| anyhow::anyhow!("deprecated_resource_types: {}", e))?;
        let deprecated_resource_types: HashSet<String> = deprecated_data
            .deprecated_resource_types
            .into_iter()
            .collect();

        let sensitive_data: SensitivePorts =
            serde_json::from_slice(&embedded::SENSITIVE_PORTS_BYTES)
                .map_err(|e| anyhow::anyhow!("sensitive_ports: {}", e))?;
        let sensitive_ports = sensitive_data.sensitive_ports;

        let mut enum_data = HashMap::new();
        for (name, bytes) in ENUM_DATA.iter() {
            let v: serde_json::Value = serde_json::from_slice(bytes)
                .map_err(|e| anyhow::anyhow!("enum data '{}': {}", name, e))?;
            enum_data.insert(name.to_string(), v);
        }
        let iam_action_resource_patterns: serde_json::Value =
            serde_json::from_slice(&embedded::IAM_ACTION_RESOURCE_PATTERNS_BYTES)
                .map_err(|e| anyhow::anyhow!("iam_action_resource_patterns: {}", e))?;
        let region_resource_types: serde_json::Value =
            serde_json::from_slice(&embedded::REGION_RESOURCE_TYPES_BYTES)
                .map_err(|e| anyhow::anyhow!("region_resource_types: {}", e))?;

        Ok(CachedData {
            known_types,
            getatt_attrs,
            getatt_attr_types,
            schema_metadata_lazy: OnceLock::new(),
            iam_action_resource_patterns,
            region_resource_types,
            enum_data,
            stateful_resource_types,
            retention_period_requirements,
            primary_identifiers,
            codepipeline_artifact_counts,
            deprecated_resource_types,
            sensitive_ports,
        })
    }

    /// Lazy accessor — parses the 14MB `schema_metadata` JSON on first call.
    pub fn schema_metadata(&self) -> &serde_json::Value {
        self.schema_metadata_lazy.get_or_init(|| {
            serde_json::from_slice(&embedded::SCHEMA_METADATA_BYTES)
                .expect("Failed to parse schema_metadata JSON")
        })
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
    pub rules: Vec<(rules::Category, NativeRuleFn)>, // (category, fn)
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

    pub fn add(&mut self, category: rules::Category, f: NativeRuleFn) {
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
