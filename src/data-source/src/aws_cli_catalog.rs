//! Standalone AWS CLI operation catalog generation.
//!
//! This is intentionally decoupled from the [`crate::sync_upstream`] /
//! [`crate::generate_all`] maintenance pipeline: the catalog derives from AWS
//! CLI botocore service models plus CloudFormation provider handler metadata,
//! sources that the rest of the build does not touch, and it runs on its own
//! cadence. The `generate_aws_cli_catalog` example is the command-line entry
//! point; this module owns the logic it calls.

use crate::schema;
use anyhow::Context;
use log::info;
use std::fs;
use std::path::{Path, PathBuf};

/// Format version the generator emits and the runtime loader accepts.
const AWS_CLI_OPERATION_CATALOG_FORMAT_VERSION: u64 = 1;

#[derive(serde::Deserialize)]
struct AwsCliOperationCatalog {
    format_version: u64,
    adapters: Vec<serde_json::Value>,
}

/// Inputs for a standalone catalog generation run.
pub struct CatalogInputs {
    /// Path to a local AWS CLI (`aws-cli`) checkout. Its `awscli/` directory
    /// supplies the bundled botocore service models.
    pub aws_cli_root: PathBuf,
    /// Optional pre-downloaded provider-schema source (a directory of per-type
    /// JSON files or a `schemas-cfn-lint.zip` archive). When `None`, the current
    /// enhanced provider schemas are downloaded to a temporary directory.
    pub provider_schemas: Option<PathBuf>,
}

/// Generate the AWS CLI operation catalog into `generated_dir/data`.
///
/// Provider schemas are downloaded on demand when `inputs.provider_schemas` is
/// `None`, so this command does not depend on the maintenance `sync` having run.
/// The compiled CloudFormation schemas the generator verifies against are read
/// from the committed `generated_dir/schema-validator/compiled_schemas.json`.
pub fn generate_aws_cli_catalog(generated_dir: &Path, inputs: &CatalogInputs) -> anyhow::Result<()> {
    let botocore_root = inputs.aws_cli_root.join("awscli");
    let botocore_package = botocore_root.join("botocore").join("__init__.py");
    let compiled_schemas = generated_dir.join("schema-validator").join("compiled_schemas.json");
    let catalog_path = generated_dir.join("data").join("aws_cli_operation_catalog.json");
    let script_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts").join("generate_aws_cli_catalog.py");

    anyhow::ensure!(script_path.is_file(), "AWS CLI catalog generator not found at {}", script_path.display());
    anyhow::ensure!(inputs.aws_cli_root.is_dir(), "AWS CLI checkout not found at {}", inputs.aws_cli_root.display());
    anyhow::ensure!(
        botocore_package.is_file(),
        "AWS CLI checkout does not contain botocore at {}",
        botocore_package.display()
    );
    anyhow::ensure!(compiled_schemas.is_file(), "compiled schemas not found at {}", compiled_schemas.display());

    // Resolve provider schemas: use a caller-supplied path, or download the
    // current enhanced schemas into a scratch directory owned by this run.
    let downloaded_schemas;
    let provider_schemas = match &inputs.provider_schemas {
        Some(path) => {
            anyhow::ensure!(path.exists(), "provider schemas source not found at {}", path.display());
            path.clone()
        }
        None => {
            downloaded_schemas = download_provider_schemas()?;
            downloaded_schemas
        }
    };

    info!("Generating AWS CLI operation catalog via {}", script_path.display());
    let status = std::process::Command::new("python3")
        .arg(&script_path)
        .arg("--botocore-root")
        .arg(&botocore_root)
        .arg("--provider-schemas")
        .arg(&provider_schemas)
        .arg("--compiled-schemas")
        .arg(&compiled_schemas)
        .arg("--output")
        .arg(&catalog_path)
        .status()
        .map_err(|error| anyhow::anyhow!("failed to start AWS CLI catalog generator: {error}"))?;
    anyhow::ensure!(status.success(), "AWS CLI catalog generator failed with {status}");

    let catalog_bytes = fs::read(&catalog_path)
        .map_err(|error| anyhow::anyhow!("failed to read generated catalog {}: {error}", catalog_path.display()))?;
    let adapter_count = validate_catalog(&catalog_bytes)?;
    info!("Generated AWS CLI operation catalog with {adapter_count} adapters at {}", catalog_path.display());
    Ok(())
}

/// Download the current enhanced provider schemas into a scratch directory under
/// `upstream/` and return the per-type schema directory. Each schema body carries
/// the handler metadata the generator reads, matching the layout its directory
/// reader expects.
fn download_provider_schemas() -> anyhow::Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let scratch = manifest.join("upstream").join("aws_cli_catalog_schemas");
    info!("Downloading enhanced provider schemas for the AWS CLI catalog into {}", scratch.display());
    if scratch.exists() {
        fs::remove_dir_all(&scratch)
            .with_context(|| format!("failed to clear schema scratch directory {}", scratch.display()))?;
    }
    // `download_schemas` writes the per-region provider maps and the per-type
    // schema bodies (which carry handler metadata) under `<dir>/schemas`.
    let (stats, version) = schema::download_schemas(&scratch)?;
    stats.fail_on_errors("AWS CLI catalog schema download")?;
    info!("Downloaded {} provider schemas (version {})", stats.files_written, version);
    Ok(schema::schema_dir(&scratch))
}

fn validate_catalog(catalog_bytes: &[u8]) -> anyhow::Result<usize> {
    let catalog: AwsCliOperationCatalog = serde_json::from_slice(catalog_bytes)
        .map_err(|error| anyhow::anyhow!("generated AWS CLI operation catalog is invalid JSON: {error}"))?;
    anyhow::ensure!(
        catalog.format_version == AWS_CLI_OPERATION_CATALOG_FORMAT_VERSION,
        "generated AWS CLI operation catalog has format version {}, expected {}",
        catalog.format_version,
        AWS_CLI_OPERATION_CATALOG_FORMAT_VERSION
    );
    anyhow::ensure!(!catalog.adapters.is_empty(), "generated AWS CLI operation catalog contains no adapters");
    Ok(catalog.adapters.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_catalog_format_with_adapters_is_valid() {
        let catalog = br#"{"format_version":1,"adapters":[{}]}"#;
        let adapter_count = validate_catalog(catalog).expect("catalog should be valid");
        assert_eq!(1, adapter_count);
    }

    #[test]
    fn unsupported_catalog_format_is_rejected() {
        let catalog = br#"{"format_version":2,"adapters":[{}]}"#;
        let error = validate_catalog(catalog).expect_err("unsupported format must fail");
        assert!(error.to_string().contains("format version 2, expected 1"));
    }

    #[test]
    fn catalog_without_adapters_is_rejected() {
        let catalog = br#"{"format_version":1,"adapters":[]}"#;
        let error = validate_catalog(catalog).expect_err("empty adapters must fail");
        assert!(error.to_string().contains("contains no adapters"));
    }
}
