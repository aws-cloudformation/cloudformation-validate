pub mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_data.rs"));
}

#[cfg(feature = "uniffi-bindings")]
uniffi::setup_scaffolding!();

pub mod additional_schema_source;
#[cfg(feature = "maintenance")]
pub mod additional_specs;
#[cfg(feature = "maintenance")]
pub mod cfnlint_tables;
#[cfg(feature = "maintenance")]
pub mod codegen_cel;
#[cfg(feature = "maintenance")]
pub mod codegen_schema_validator;
pub mod compiled_schema;
#[cfg(feature = "maintenance")]
pub mod extensions;
#[cfg(feature = "maintenance")]
pub mod process;
#[cfg(feature = "maintenance")]
pub mod regions;
pub mod rule_data;
#[cfg(feature = "maintenance")]
pub mod schema;
#[cfg(feature = "maintenance")]
mod source_versions;
pub mod types;

pub use additional_schema_source::{AdditionalSchemaSource, SchemaSourceError};

#[cfg(feature = "maintenance")]
use log::{error, info};
#[cfg(feature = "maintenance")]
use std::fs;
#[cfg(feature = "maintenance")]
use std::path::{Path, PathBuf};

/// Convert a rule-source resource type directory name (e.g., "aws_rds_dbinstance")
/// to the normalized form used by this project (e.g., "aws-rds-dbinstance").
#[cfg(feature = "maintenance")]
pub fn rule_source_dir_to_name(dir_name: &str) -> String {
    dir_name.to_lowercase().replace('_', "-")
}

/// Resolve the rule-source root directory, returning an error if not provided or missing.
#[cfg(feature = "maintenance")]
pub fn resolve_rule_source_dir(path: Option<&str>) -> anyhow::Result<PathBuf> {
    let p = path.ok_or_else(|| anyhow::anyhow!("Pass --cfn-lint-root to the cfn-lint repo root"))?;
    let pb = PathBuf::from(p);
    anyhow::ensure!(pb.exists(), "Rule-source directory not found: {}", pb.display());
    Ok(pb)
}

#[cfg(feature = "maintenance")]
#[derive(Debug, Default)]
pub struct SyncStats {
    pub files_written: usize,
    pub files_skipped: usize,
    pub errors: Vec<String>,
}

#[cfg(feature = "maintenance")]
impl SyncStats {
    pub fn log(&self, label: &str) {
        info!(
            "{}: {} written, {} skipped, {} errors",
            label,
            self.files_written,
            self.files_skipped,
            self.errors.len()
        );
        for e in &self.errors {
            error!("{}: {}", label, e);
        }
    }

    pub fn fail_on_errors(&self, label: &str) -> anyhow::Result<()> {
        self.log(label);
        if !self.errors.is_empty() {
            anyhow::bail!("{} completed with {} error(s):\n  {}", label, self.errors.len(), self.errors.join("\n  "));
        }
        Ok(())
    }
}

#[cfg(feature = "maintenance")]
fn write_source_versions(path: &Path, versions: source_versions::SourceVersions) -> anyhow::Result<()> {
    let versions = source_versions::SourceVersions::new(versions.cfn_lint_version, versions.resource_schema_version)
        .map_err(anyhow::Error::msg)?;
    let mut contents = serde_json::to_string_pretty(&versions)?;
    contents.push('\n');
    fs::write(path, contents)?;
    Ok(())
}

#[cfg(feature = "maintenance")]
pub fn sync_upstream(upstream_dir: &Path, rule_source_root: &str) -> anyhow::Result<()> {
    info!("=== Sync phase ===");

    let generated_root = upstream_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("upstream directory must have a parent: {}", upstream_dir.display()))?;
    let generated_data = generated_root.join("generated").join("data");
    fs::create_dir_all(&generated_data)?;
    let source_versions_path = generated_data.join(source_versions::SOURCE_VERSIONS_FILE);
    let rule_source_dir = resolve_rule_source_dir(Some(rule_source_root))?;

    info!("Step 1: Downloading enhanced CloudFormation schemas (fully patched, with region maps)");
    let (schema_stats, resource_schema_version) = schema::download_schemas(upstream_dir)?;
    schema_stats.fail_on_errors("Download")?;

    info!("Step 2: Building region resource types from downloaded provider maps");
    regions::sync_regions(&schema::providers_dir(upstream_dir), &generated_data)?.fail_on_errors("Regions")?;

    info!("Step 3: Syncing extensions from {}", rule_source_dir.display());
    extensions::sync_extensions(&rule_source_dir, &upstream_dir.join("extensions"), &generated_data)?
        .fail_on_errors("Extensions")?;

    info!("Step 4: Syncing additional specs from {}", rule_source_dir.display());
    additional_specs::sync_additional_specs(&rule_source_dir, &generated_data, upstream_dir)?
        .fail_on_errors("AdditionalSpecs")?;

    info!("Step 5: Extracting data tables embedded in cfn-lint rule code");
    let (table_stats, cfn_lint_version) = cfnlint_tables::sync_cfnlint_tables(&rule_source_dir, &generated_data)?;
    table_stats.fail_on_errors("CfnLintTables")?;

    verify_files_exist_and_populated(REQUIRED_SYNC_FILES, &generated_data, "Sync")?;
    let source_versions =
        source_versions::SourceVersions::new(cfn_lint_version, resource_schema_version).map_err(anyhow::Error::msg)?;
    write_source_versions(&source_versions_path, source_versions)?;
    info!("Recorded complete data source provenance in {}", source_versions_path.display());

    Ok(())
}

#[cfg(feature = "maintenance")]
pub fn generate_all(upstream_dir: &Path, generated_dir: &Path, handwritten_dir: &Path) -> anyhow::Result<()> {
    info!("=== Generate phase ===");

    info!("Step 1: Processing schemas (extensions, metadata)");
    process::process_schemas(upstream_dir, generated_dir, handwritten_dir)?.fail_on_errors("Process")?;

    info!("Step 2: Generating CEL rules");
    codegen_cel::generate(generated_dir, handwritten_dir)?;

    info!("Step 3: Generating compiled schemas for schema-validator");
    codegen_schema_validator::generate(generated_dir, upstream_dir)?;

    info!("Step 4: Verifying all expected output files");
    verify_outputs(generated_dir, handwritten_dir)?;

    Ok(())
}

/// Expected data files that must exist and contain real data after a
/// successful sync+generate.

/// Files produced by sync_upstream (extensions, regions, additional specs).
#[cfg(feature = "maintenance")]
const REQUIRED_SYNC_FILES: &[&str] = &[
    // Enum data documents (from the upstream rule-source extensions)
    "aws_amazonmq_broker_instancetype_enum",
    "aws_appstream_fleet_instancetype_enum",
    "aws_dax_cluster_nodetype_enum",
    "aws_docdb_dbinstance_dbinstanceclass_enum",
    "aws_ec2_instance_instancetype_enum",
    "aws_elasticache_cachecluster_cachenodetype_enum",
    "aws_emr_cluster_instancetypeconfig_instancetype_enum",
    "aws_gamelift_fleet_ec2instancetype_enum",
    "aws_managedblockchain_node_nodeconfiguration_instancetype_enum",
    "aws_neptune_dbinstance_dbinstanceclass_enum",
    "aws_rds_dbcluster_dbclusterinstanceclass_enum",
    "aws_rds_dbinstance_db_instance_class",
    "aws_rds_dbinstance_dbinstanceclass_enum",
    "aws_redshift_cluster_nodetype_enum",
    "aws_sagemaker_processing_instancetype_enum",
    "aws_sagemaker_hosting_instancetype_enum",
    "aws_sagemaker_transform_instancetype_enum",
    "aws_sagemaker_cluster_instancetype_enum",
    "aws_elasticsearch_domain_elasticsearchclusterconfig_instancetype_enum",
    "aws_opensearchservice_domain_clusterconfig_instancetype_enum",
    // Additional specs
    "iam_action_resource_patterns",
    "lambda_runtimes",
    "region_resource_types",
    "stateful_resource_types",
    // Tables extracted from cfn-lint rule code
    "getatt_additions",
    "retention_period_requirements",
    "codepipeline_action_artifact_counts",
    "cfnlint_rule_tables",
];

/// Data files produced by generate_all schema processing.
#[cfg(feature = "maintenance")]
const REQUIRED_GENERATE_DATA_FILES: &[&str] =
    &["resource_lifecycle", "schema_metadata", "primary_identifiers", "getatt_attributes", "known_resource_types"];

/// Schema-validator files produced by generate_all.
#[cfg(feature = "maintenance")]
const REQUIRED_SCHEMA_VALIDATOR_FILES: &[&str] = &["compiled_schemas", "ref_types", "extensions", "region_enums"];

#[cfg(feature = "maintenance")]
const REQUIRED_CEL_RULE_FILES: &[&str] = &["generated_rules"];

#[cfg(feature = "maintenance")]
const REQUIRED_HANDWRITTEN_FILES: &[&str] = &[
    "deprecated_resource_types",
    "getatt_return_type_overrides",
    "schema_dependent_excluded_overrides",
    "secretsmanager_arn_fields",
    "sensitive_ports",
];

#[cfg(feature = "maintenance")]
fn verify_sync_outputs(data_dir: &Path) -> anyhow::Result<()> {
    source_versions::SourceVersions::read(&data_dir.join(source_versions::SOURCE_VERSIONS_FILE))
        .map_err(anyhow::Error::msg)?;
    verify_files_exist_and_populated(REQUIRED_SYNC_FILES, data_dir, "Sync")
}

#[cfg(feature = "maintenance")]
fn verify_outputs(generated_dir: &Path, handwritten_dir: &Path) -> anyhow::Result<()> {
    let data_dir = generated_dir.join("data");
    let schema_validator_dir = generated_dir.join("schema-validator");
    let cel_rules_dir = generated_dir.join("cel-rules");

    verify_sync_outputs(&data_dir)?;
    verify_files_exist_and_populated(REQUIRED_GENERATE_DATA_FILES, &data_dir, "Generate data")?;
    verify_files_exist_and_populated(REQUIRED_SCHEMA_VALIDATOR_FILES, &schema_validator_dir, "Schema validator")?;
    verify_files_exist_and_populated(REQUIRED_CEL_RULE_FILES, &cel_rules_dir, "Generated CEL rules")?;
    verify_files_exist_and_populated(REQUIRED_HANDWRITTEN_FILES, handwritten_dir, "Handwritten")?;

    let total = REQUIRED_SYNC_FILES.len()
        + REQUIRED_GENERATE_DATA_FILES.len()
        + REQUIRED_SCHEMA_VALIDATOR_FILES.len()
        + REQUIRED_CEL_RULE_FILES.len()
        + REQUIRED_HANDWRITTEN_FILES.len()
        + 1;
    info!("Verified {total} required data files");
    Ok(())
}

#[cfg(feature = "maintenance")]
fn verify_files_exist_and_populated(names: &[&str], directory: &Path, label: &str) -> anyhow::Result<()> {
    let mut missing = Vec::new();
    let mut stubs = Vec::new();

    for name in names {
        let path = directory.join(format!("{name}.json"));
        if !path.is_file() {
            missing.push(name.to_string());
            continue;
        }

        if is_stub(&path) {
            stubs.push(name.to_string());
        }
    }

    if !missing.is_empty() || !stubs.is_empty() {
        let mut msg = String::new();
        if !missing.is_empty() {
            msg.push_str(&format!("  Missing: {}\n", missing.join(", ")));
        }
        if !stubs.is_empty() {
            msg.push_str(&format!("  Empty stubs: {}\n", stubs.join(", ")));
        }
        anyhow::bail!(
            "{label} verification failed - {}/{} files not populated:\n{msg}",
            missing.len() + stubs.len(),
            names.len()
        );
    }
    Ok(())
}

/// A file is an invalid empty stub if it contains only `{}` or `[]`.
#[cfg(feature = "maintenance")]
fn is_stub(path: &Path) -> bool {
    match fs::read_to_string(path) {
        Ok(content) => {
            let trimmed = content.trim();
            trimmed == "{}" || trimmed == "[]"
        }
        Err(_) => true,
    }
}
