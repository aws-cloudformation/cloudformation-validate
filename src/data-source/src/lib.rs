pub mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_data.rs"));
}

#[cfg(feature = "full")]
pub mod additional_specs;
#[cfg(feature = "full")]
pub mod codegen_cel;
#[cfg(feature = "full")]
pub mod codegen_schema_validator;
#[cfg(feature = "full")]
pub mod extensions;
#[cfg(feature = "full")]
pub mod patches;
#[cfg(feature = "full")]
pub mod process;
#[cfg(feature = "full")]
pub mod regions;
#[cfg(feature = "full")]
pub mod schema;
pub mod types;

#[cfg(feature = "full")]
use log::{error, info};
#[cfg(feature = "full")]
use std::fs;
#[cfg(feature = "full")]
use std::path::{Path, PathBuf};

/// Convert a rule-source resource type directory name (e.g., "aws_rds_dbinstance")
/// to the normalized form used by this project (e.g., "aws-rds-dbinstance").
#[cfg(feature = "full")]
pub fn rule_source_dir_to_name(dir_name: &str) -> String {
    dir_name.to_lowercase().replace('_', "-")
}

/// Resolve the rule-source root directory, returning an error if not provided or missing.
#[cfg(feature = "full")]
pub fn resolve_rule_source_dir(path: Option<&str>) -> anyhow::Result<PathBuf> {
    let p =
        path.ok_or_else(|| anyhow::anyhow!("Pass --cfn-lint-root to the cfn-lint repo root"))?;
    let pb = PathBuf::from(p);
    anyhow::ensure!(
        pb.exists(),
        "Rule-source directory not found: {}",
        pb.display()
    );
    Ok(pb)
}

#[cfg(feature = "full")]
#[derive(Debug, Default)]
pub struct SyncStats {
    pub files_written: usize,
    pub files_skipped: usize,
    pub errors: Vec<String>,
}

#[cfg(feature = "full")]
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
            anyhow::bail!(
                "{} completed with {} error(s):\n  {}",
                label,
                self.errors.len(),
                self.errors.join("\n  ")
            );
        }
        Ok(())
    }
}

#[cfg(feature = "full")]
pub fn sync_upstream(upstream_dir: &Path, rule_source_root: Option<&str>) -> anyhow::Result<()> {
    info!("=== Sync phase ===");

    info!("Step 1: Downloading CloudFormation schemas");
    schema::download_schemas(&schema::schema_dir(upstream_dir))?.fail_on_errors("Download")?;

    if let Some(root) = rule_source_root {
        let rule_source_dir = resolve_rule_source_dir(Some(root))?;

        info!("Step 2: Syncing patches from {}", rule_source_dir.display());
        patches::sync_patches(&rule_source_dir, &upstream_dir.join("patches"))?
            .fail_on_errors("Patches")?;

        info!(
            "Step 3: Syncing extensions from {}",
            rule_source_dir.display()
        );
        let generated_data = upstream_dir
            .parent()
            .unwrap()
            .join("generated")
            .join("data");
        fs::create_dir_all(&generated_data)?;
        extensions::sync_extensions(
            &rule_source_dir,
            &upstream_dir.join("extensions"),
            &generated_data,
        )?
        .fail_on_errors("Extensions")?;

        info!("Step 4: Syncing regions from {}", rule_source_dir.display());
        regions::sync_regions(&rule_source_dir, &generated_data)?.fail_on_errors("Regions")?;

        info!(
            "Step 5: Syncing additional specs from {}",
            rule_source_dir.display()
        );
        additional_specs::sync_additional_specs(&rule_source_dir, &generated_data, upstream_dir)?
            .fail_on_errors("AdditionalSpecs")?;

        info!("Step 6: Verifying sync produced expected data files");
        verify_sync_outputs(&generated_data)?;
    } else {
        info!("Skipping rule-source sync (no --cfn-lint-root provided)");
    }

    Ok(())
}

#[cfg(feature = "full")]
pub fn generate_all(
    upstream_dir: &Path,
    generated_dir: &Path,
    handwritten_dir: &Path,
) -> anyhow::Result<()> {
    info!("=== Generate phase ===");

    info!("Step 1: Processing schemas (patches, extensions, metadata)");
    process::process_schemas(upstream_dir, generated_dir)?.fail_on_errors("Process")?;

    info!("Step 2: Generating CEL rules");
    codegen_cel::generate(generated_dir, handwritten_dir)?;

    info!("Step 3: Generating compiled schemas for schema-validator");
    codegen_schema_validator::generate(generated_dir, upstream_dir)?;

    info!("Step 4: Verifying all expected output files");
    verify_outputs(generated_dir, handwritten_dir)?;

    Ok(())
}

/// Expected data files that must exist and contain real data (not empty stubs)
/// after a successful sync+generate. build.rs creates `{}` stubs for these so
/// the crate compiles from a clean workspace, but the pipeline must populate
/// them with real content.

/// Files produced by sync_upstream (extensions, regions, additional specs).
#[cfg(feature = "full")]
const REQUIRED_SYNC_FILES: &[&str] = &[
    // Enum data documents (from cfn-lint extensions)
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
    // Additional specs
    "iam_action_resource_patterns",
    "lambda_runtimes",
    "region_resource_types",
    "stateful_resource_types",
];

/// Files produced by generate_all (schema processing, codegen).
#[cfg(feature = "full")]
const REQUIRED_GENERATE_FILES: &[&str] = &[
    "compiled_schemas",
    "ref_types",
    "extensions",
    "region_enums",
    "resource_lifecycle",
    "schema_metadata",
    "primary_identifiers",
    "getatt_attributes",
    "known_resource_types",
];

#[cfg(feature = "full")]
const REQUIRED_HANDWRITTEN_FILES: &[&str] = &[
    "codepipeline_action_artifact_counts",
    "deprecated_resource_types",
    "retention_period_requirements",
    "sensitive_ports",
];

#[cfg(feature = "full")]
fn verify_sync_outputs(data_dir: &Path) -> anyhow::Result<()> {
    verify_files_exist_and_populated(REQUIRED_SYNC_FILES, data_dir, None, "Sync")
}

#[cfg(feature = "full")]
fn verify_outputs(generated_dir: &Path, handwritten_dir: &Path) -> anyhow::Result<()> {
    let data_dir = generated_dir.join("data");
    let sv_dir = generated_dir.join("schema-validator");

    // Check sync-produced files are still present and populated
    verify_files_exist_and_populated(REQUIRED_SYNC_FILES, &data_dir, None, "Sync")?;
    // Check generate-produced files
    verify_files_exist_and_populated(
        REQUIRED_GENERATE_FILES,
        &data_dir,
        Some(&sv_dir),
        "Generate",
    )?;
    // Check handwritten files
    verify_files_exist_and_populated(
        REQUIRED_HANDWRITTEN_FILES,
        handwritten_dir,
        None,
        "Handwritten",
    )?;

    let total = REQUIRED_SYNC_FILES.len()
        + REQUIRED_GENERATE_FILES.len()
        + REQUIRED_HANDWRITTEN_FILES.len();
    info!("Verified {total} required data files");
    Ok(())
}

#[cfg(feature = "full")]
fn verify_files_exist_and_populated(
    names: &[&str],
    primary_dir: &Path,
    fallback_dir: Option<&Path>,
    label: &str,
) -> anyhow::Result<()> {
    let mut missing = Vec::new();
    let mut stubs = Vec::new();

    for name in names {
        let primary = primary_dir.join(format!("{name}.json"));
        let fallback = fallback_dir.map(|d| d.join(format!("{name}.json")));

        let path = if primary.exists() {
            primary
        } else if let Some(ref fb) = fallback {
            if fb.exists() {
                fb.clone()
            } else {
                missing.push(name.to_string());
                continue;
            }
        } else {
            missing.push(name.to_string());
            continue;
        };

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
            "{label} verification failed — {}/{} files not populated:\n{msg}",
            missing.len() + stubs.len(),
            names.len()
        );
    }
    Ok(())
}

/// A file is a stub if it's just `{}` or `[]` (created by build.rs for clean-workspace builds).
#[cfg(feature = "full")]
fn is_stub(path: &Path) -> bool {
    match fs::read_to_string(path) {
        Ok(content) => {
            let trimmed = content.trim();
            trimmed == "{}" || trimmed == "[]"
        }
        Err(_) => true,
    }
}
