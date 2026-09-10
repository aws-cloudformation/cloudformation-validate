//! Standalone AWS CLI operation catalog generation.
//!
//! This is intentionally decoupled from the [`crate::sync_upstream`] /
//! [`crate::generate_all`] maintenance pipeline: the catalog derives from AWS
//! CLI botocore service models plus CloudFormation provider handler metadata,
//! and it runs on its own cadence. It only generates the catalog - it never
//! downloads or processes schemas. The resource data it reads must already be
//! present: the provider schemas under `upstream/schemas` (written by `sync`)
//! and the committed compiled schemas under `generated/schema-validator`.
//! The `generate_aws_cli_catalog` example is the command-line entry point; this
//! module owns the logic it calls.

use log::info;
use std::fs;
use std::path::Path;

/// Format version the generator emits and the runtime loader accepts.
const AWS_CLI_OPERATION_CATALOG_FORMAT_VERSION: u64 = 1;

#[derive(serde::Deserialize)]
struct AwsCliOperationCatalog {
    format_version: u64,
    adapters: Vec<serde_json::Value>,
}

/// Generate the AWS CLI operation catalog into `generated_dir/data`.
///
/// `aws_cli_root` is a local AWS CLI (`aws-cli`) checkout; its `awscli/`
/// directory supplies the bundled botocore service models. Provider schemas are
/// read from `upstream_dir/schemas` and compiled schemas from
/// `generated_dir/schema-validator/compiled_schemas.json`; both must already
/// exist - this command does not download or process schemas.
pub fn generate_aws_cli_catalog(upstream_dir: &Path, generated_dir: &Path, aws_cli_root: &Path) -> anyhow::Result<()> {
    let botocore_root = aws_cli_root.join("awscli");
    let botocore_package = botocore_root.join("botocore").join("__init__.py");
    let provider_schemas = upstream_dir.join("schemas");
    let compiled_schemas = generated_dir.join("schema-validator").join("compiled_schemas.json");
    let catalog_path = generated_dir.join("data").join("aws_cli_operation_catalog.json");
    let script_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts").join("generate_aws_cli_catalog.py");

    anyhow::ensure!(script_path.is_file(), "AWS CLI catalog generator not found at {}", script_path.display());
    anyhow::ensure!(aws_cli_root.is_dir(), "AWS CLI checkout not found at {}", aws_cli_root.display());
    anyhow::ensure!(
        botocore_package.is_file(),
        "AWS CLI checkout does not contain botocore at {}",
        botocore_package.display()
    );
    anyhow::ensure!(
        provider_schemas.is_dir(),
        "provider schemas not found at {}; run the sync example first to populate the resource data",
        provider_schemas.display()
    );
    anyhow::ensure!(compiled_schemas.is_file(), "compiled schemas not found at {}", compiled_schemas.display());

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
