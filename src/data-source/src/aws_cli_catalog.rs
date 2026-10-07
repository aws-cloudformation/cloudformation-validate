//! AWS CLI operation catalog generation for the `sync` maintenance workflow.
//!
//! The catalog derives from AWS CLI botocore service models plus CloudFormation
//! provider handler metadata, and it is structurally verified against the
//! compiled schemas. `sync` clears `generated/data/` before refreshing every
//! upstream source, so the catalog is either regenerated as the final `sync`
//! step (when an AWS CLI checkout is supplied) or carried across the sync
//! unchanged and re-verified against the freshly compiled schemas (when it is
//! not). Either way `generated/data/` ends the sync with a catalog the build
//! script can embed and a manifest that records the AWS CLI release it derives
//! from.

use crate::source_versions::{AWS_CLI_SOURCE, SOURCE_VERSIONS_FILE, SourceVersions};
use crate::write_source_versions;
use log::{info, warn};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

/// Format version the generator emits and the runtime loader accepts.
const AWS_CLI_OPERATION_CATALOG_FORMAT_VERSION: u64 = 1;

/// Catalog file name under `generated/data/`.
pub const AWS_CLI_OPERATION_CATALOG_FILE: &str = "aws_cli_operation_catalog.json";

#[derive(Debug, serde::Deserialize)]
struct AwsCliOperationCatalog {
    format_version: u64,
    adapters: Vec<CatalogAdapter>,
    source: AwsCliOperationCatalogSource,
}

#[derive(Debug, serde::Deserialize)]
struct AwsCliOperationCatalogSource {
    /// Release version of the AWS CLI checkout whose bundled botocore models the catalog derives from.
    aws_cli_version: String,
}

/// The part of a catalog adapter that must agree with the compiled schemas.
#[derive(Debug, serde::Deserialize)]
struct CatalogAdapter {
    service: String,
    operation: String,
    cfn_type: String,
    #[serde(default)]
    mappings: Vec<CatalogMapping>,
}

#[derive(Debug, serde::Deserialize)]
struct CatalogMapping {
    target: String,
}

/// The part of a compiled resource schema the catalog's mappings depend on.
#[derive(Debug, serde::Deserialize)]
struct CompiledPropertySurface {
    #[serde(default)]
    properties: HashMap<String, serde_json::Value>,
    #[serde(default)]
    read_only_properties: BTreeSet<String>,
}

/// A committed catalog carried across a sync that does not regenerate it.
#[derive(Debug)]
pub struct PreservedAwsCliCatalog {
    catalog: Vec<u8>,
    aws_cli_version: String,
}

fn catalog_path(generated_dir: &Path) -> PathBuf {
    generated_dir.join("data").join(AWS_CLI_OPERATION_CATALOG_FILE)
}

fn compiled_schemas_path(generated_dir: &Path) -> PathBuf {
    generated_dir.join("schema-validator").join("compiled_schemas.json")
}

/// Read the committed catalog and its recorded AWS CLI release before `sync`
/// clears `generated/data/`, so a sync run without an AWS CLI checkout can
/// restore it afterwards. Returns `None` when no catalog has been generated yet.
pub fn preserve_aws_cli_catalog(generated_dir: &Path) -> anyhow::Result<Option<PreservedAwsCliCatalog>> {
    let path = catalog_path(generated_dir);
    if !path.is_file() {
        return Ok(None);
    }
    let catalog_bytes = fs::read(&path)
        .map_err(|error| anyhow::anyhow!("failed to read committed catalog {}: {error}", path.display()))?;
    let catalog = validate_catalog(&catalog_bytes)
        .map_err(|error| anyhow::anyhow!("committed catalog {} cannot be preserved: {error}", path.display()))?;
    Ok(Some(PreservedAwsCliCatalog {
        catalog: catalog_bytes,
        aws_cli_version: format!("{AWS_CLI_SOURCE}@{}", catalog.source.aws_cli_version),
    }))
}

/// Write a preserved catalog back into `generated_dir/data` after a sync,
/// verify it against the freshly compiled schemas, and record its AWS CLI
/// release in the sync-written manifest.
///
/// A preserved catalog was derived from the compiled schemas of an earlier
/// sync. Every property it maps must still exist and still be writable in the
/// new compiled schemas; otherwise the runtime would report an engine error for
/// the affected command, so the restore fails and asks for regeneration instead.
pub fn restore_aws_cli_catalog(generated_dir: &Path, preserved: PreservedAwsCliCatalog) -> anyhow::Result<()> {
    let path = catalog_path(generated_dir);
    let stale = stale_mappings(&preserved.catalog, &compiled_schemas_path(generated_dir))?;
    anyhow::ensure!(
        stale.is_empty(),
        "the preserved AWS CLI operation catalog no longer agrees with the refreshed compiled schemas \
         ({} mapping(s), e.g. {}); rerun sync with --aws-cli-root <DIR> to regenerate it",
        stale.len(),
        stale.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
    );
    fs::create_dir_all(generated_dir.join("data"))?;
    fs::write(&path, &preserved.catalog)
        .map_err(|error| anyhow::anyhow!("failed to restore catalog {}: {error}", path.display()))?;
    record_aws_cli_version(generated_dir, preserved.aws_cli_version.clone())?;
    warn!(
        "Restored the previous AWS CLI operation catalog ({}) without regenerating it; pass --aws-cli-root <DIR> \
         to derive it from the refreshed schemas",
        preserved.aws_cli_version
    );
    Ok(())
}

/// Generate the AWS CLI operation catalog into `generated_dir/data`.
///
/// `aws_cli_root` is a local AWS CLI (`aws-cli`) checkout; its `awscli/`
/// directory supplies the bundled botocore service models. Provider schemas are
/// read from `upstream_dir/schemas` and compiled schemas from
/// `generated_dir/schema-validator/compiled_schemas.json`; both must already
/// exist, so this runs as the final `sync` step after `generate_all`.
pub fn generate_aws_cli_catalog(upstream_dir: &Path, generated_dir: &Path, aws_cli_root: &Path) -> anyhow::Result<()> {
    let botocore_root = aws_cli_root.join("awscli");
    let botocore_package = botocore_root.join("botocore").join("__init__.py");
    let provider_schemas = upstream_dir.join("schemas");
    let compiled_schemas = compiled_schemas_path(generated_dir);
    let catalog_path = catalog_path(generated_dir);
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
        "provider schemas not found at {}; sync must download them before generating the catalog",
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
    let catalog = validate_catalog(&catalog_bytes)?;
    let stale = stale_mappings(&catalog_bytes, &compiled_schemas)?;
    anyhow::ensure!(
        stale.is_empty(),
        "generated AWS CLI operation catalog maps properties absent from the compiled schemas: {}",
        stale.join(", ")
    );
    info!("Generated AWS CLI operation catalog with {} adapters at {}", catalog.adapters.len(), catalog_path.display());

    record_aws_cli_version(generated_dir, format!("{AWS_CLI_SOURCE}@{}", catalog.source.aws_cli_version))
}

fn record_aws_cli_version(generated_dir: &Path, aws_cli_version: String) -> anyhow::Result<()> {
    let source_versions_path = generated_dir.join("data").join(SOURCE_VERSIONS_FILE);
    let source_versions = SourceVersions::read(&source_versions_path)
        .and_then(|versions| versions.with_aws_cli_version(aws_cli_version.clone()))
        .map_err(anyhow::Error::msg)?;
    write_source_versions(&source_versions_path, source_versions)?;
    info!("Recorded {aws_cli_version} in {}", source_versions_path.display());
    Ok(())
}

fn validate_catalog(catalog_bytes: &[u8]) -> anyhow::Result<AwsCliOperationCatalog> {
    let catalog: AwsCliOperationCatalog = serde_json::from_slice(catalog_bytes)
        .map_err(|error| anyhow::anyhow!("AWS CLI operation catalog is invalid JSON: {error}"))?;
    anyhow::ensure!(
        catalog.format_version == AWS_CLI_OPERATION_CATALOG_FORMAT_VERSION,
        "AWS CLI operation catalog has format version {}, expected {}",
        catalog.format_version,
        AWS_CLI_OPERATION_CATALOG_FORMAT_VERSION
    );
    anyhow::ensure!(!catalog.adapters.is_empty(), "AWS CLI operation catalog contains no adapters");
    anyhow::ensure!(
        !catalog.source.aws_cli_version.trim().is_empty(),
        "AWS CLI operation catalog does not record the AWS CLI version"
    );
    Ok(catalog)
}

/// Mappings whose CloudFormation type or target property is missing from, or
/// read-only in, the compiled schemas at `compiled_schemas_path`, rendered as
/// `service:Operation -> Type.Property`.
fn stale_mappings(catalog_bytes: &[u8], compiled_schemas_path: &Path) -> anyhow::Result<Vec<String>> {
    let catalog = validate_catalog(catalog_bytes)?;
    let compiled: HashMap<String, CompiledPropertySurface> =
        serde_json::from_slice(&fs::read(compiled_schemas_path).map_err(|error| {
            anyhow::anyhow!("failed to read compiled schemas {}: {error}", compiled_schemas_path.display())
        })?)
        .map_err(|error| {
            anyhow::anyhow!("failed to parse compiled schemas {}: {error}", compiled_schemas_path.display())
        })?;
    Ok(stale_mappings_against(&catalog, &compiled))
}

fn stale_mappings_against(
    catalog: &AwsCliOperationCatalog,
    compiled: &HashMap<String, CompiledPropertySurface>,
) -> Vec<String> {
    let mut stale = Vec::new();
    for adapter in &catalog.adapters {
        let Some(schema) = compiled.get(&adapter.cfn_type) else {
            stale.push(format!("{}:{} -> {}", adapter.service, adapter.operation, adapter.cfn_type));
            continue;
        };
        for mapping in &adapter.mappings {
            if !schema.properties.contains_key(&mapping.target) || schema.read_only_properties.contains(&mapping.target)
            {
                stale.push(format!(
                    "{}:{} -> {}.{}",
                    adapter.service, adapter.operation, adapter.cfn_type, mapping.target
                ));
            }
        }
    }
    stale
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_CATALOG: &[u8] = br#"{
        "format_version": 1,
        "adapters": [{
            "service": "s3", "operation": "CreateBucket", "cfn_type": "AWS::S3::Bucket", "phase": "create",
            "mappings": [{"source": "Bucket", "target": "BucketName"}]
        }],
        "source": {"aws_cli_version": "2.36.43"}
    }"#;

    fn compiled(properties: &[&str], read_only: &[&str]) -> HashMap<String, CompiledPropertySurface> {
        HashMap::from([(
            "AWS::S3::Bucket".to_string(),
            CompiledPropertySurface {
                properties: properties.iter().map(|name| (name.to_string(), serde_json::json!({}))).collect(),
                read_only_properties: read_only.iter().map(|name| name.to_string()).collect(),
            },
        )])
    }

    #[test]
    fn current_catalog_format_with_adapters_is_valid() {
        let catalog = validate_catalog(VALID_CATALOG).expect("catalog should be valid");
        assert_eq!(1, catalog.adapters.len());
        assert_eq!("2.36.43", catalog.source.aws_cli_version);
    }

    #[test]
    fn unsupported_catalog_format_is_rejected() {
        let catalog = br#"{"format_version":2,"adapters":[{"service":"s3","operation":"CreateBucket","cfn_type":"AWS::S3::Bucket"}],"source":{"aws_cli_version":"2.36.43"}}"#;
        let error = validate_catalog(catalog).expect_err("unsupported format must fail");
        assert!(error.to_string().contains("format version 2, expected 1"));
    }

    #[test]
    fn catalog_without_adapters_is_rejected() {
        let catalog = br#"{"format_version":1,"adapters":[],"source":{"aws_cli_version":"2.36.43"}}"#;
        let error = validate_catalog(catalog).expect_err("empty adapters must fail");
        assert!(error.to_string().contains("contains no adapters"));
    }

    #[test]
    fn catalog_without_aws_cli_version_is_rejected() {
        let catalog = br#"{"format_version":1,"adapters":[{"service":"s3","operation":"CreateBucket","cfn_type":"AWS::S3::Bucket"}],"source":{"aws_cli_version":" "}}"#;
        let error = validate_catalog(catalog).expect_err("blank version must fail");
        assert!(error.to_string().contains("does not record the AWS CLI version"));
        let catalog = br#"{"format_version":1,"adapters":[{"service":"s3","operation":"CreateBucket","cfn_type":"AWS::S3::Bucket"}],"source":{}}"#;
        assert!(validate_catalog(catalog).is_err(), "missing version must fail");
    }

    #[test]
    fn catalog_agreeing_with_compiled_schemas_has_no_stale_mappings() {
        let catalog = validate_catalog(VALID_CATALOG).expect("catalog should be valid");
        assert!(stale_mappings_against(&catalog, &compiled(&["BucketName"], &[])).is_empty());
    }

    #[test]
    fn mapping_onto_removed_or_read_only_property_is_stale() {
        let catalog = validate_catalog(VALID_CATALOG).expect("catalog should be valid");
        assert_eq!(
            stale_mappings_against(&catalog, &compiled(&["Arn"], &[])),
            vec!["s3:CreateBucket -> AWS::S3::Bucket.BucketName"]
        );
        assert_eq!(
            stale_mappings_against(&catalog, &compiled(&["BucketName"], &["BucketName"])),
            vec!["s3:CreateBucket -> AWS::S3::Bucket.BucketName"]
        );
    }

    #[test]
    fn mapping_onto_removed_type_is_stale() {
        let catalog = validate_catalog(VALID_CATALOG).expect("catalog should be valid");
        assert_eq!(stale_mappings_against(&catalog, &HashMap::new()), vec!["s3:CreateBucket -> AWS::S3::Bucket"]);
    }

    #[test]
    fn preserving_a_missing_catalog_yields_none() {
        let dir = std::env::temp_dir().join(format!("aws-cli-catalog-preserve-{}", std::process::id()));
        fs::create_dir_all(dir.join("data")).expect("temp dir is writable");
        assert!(preserve_aws_cli_catalog(&dir).expect("missing catalog is not an error").is_none());
        fs::remove_dir_all(&dir).expect("temp dir is removable");
    }

    #[test]
    fn preserved_catalog_carries_bytes_and_source_qualified_version() {
        let dir = std::env::temp_dir().join(format!("aws-cli-catalog-preserve-some-{}", std::process::id()));
        fs::create_dir_all(dir.join("data")).expect("temp dir is writable");
        fs::write(dir.join("data").join(AWS_CLI_OPERATION_CATALOG_FILE), VALID_CATALOG).expect("catalog is writable");
        let preserved = preserve_aws_cli_catalog(&dir).expect("valid catalog preserves").expect("catalog exists");
        assert_eq!(preserved.catalog, VALID_CATALOG);
        assert_eq!(preserved.aws_cli_version, format!("{AWS_CLI_SOURCE}@2.36.43"));
        fs::remove_dir_all(&dir).expect("temp dir is removable");
    }
}
