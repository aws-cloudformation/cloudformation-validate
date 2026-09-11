use anyhow::Context;
use data_source::{
    AWS_CLI_OPERATION_CATALOG_FILE, PreservedAwsCliCatalog, generate_all, generate_aws_cli_catalog,
    preserve_aws_cli_catalog, restore_aws_cli_catalog, sync_upstream,
};
use log::{error, info};
use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process;

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args: Vec<String> = env::args().collect();

    let mut rule_source_root: Option<String> = None;
    let mut aws_cli_root: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--cfn-lint-root" => {
                i += 1;
                if i >= args.len() {
                    error!("--cfn-lint-root requires a path argument");
                    process::exit(1);
                }
                rule_source_root = Some(args[i].clone());
            }
            "--aws-cli-root" => {
                i += 1;
                if i >= args.len() {
                    error!("--aws-cli-root requires a path argument");
                    process::exit(1);
                }
                aws_cli_root = Some(PathBuf::from(&args[i]));
            }
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            other => {
                error!("Unknown argument '{}'", other);
                print_usage();
                process::exit(1);
            }
        }
        i += 1;
    }

    let rule_source_root = rule_source_root.ok_or_else(|| anyhow::anyhow!("--cfn-lint-root <DIR> is required"))?;
    if let Some(aws_cli_root) = &aws_cli_root {
        anyhow::ensure!(aws_cli_root.is_dir(), "AWS CLI checkout not found at {}", aws_cli_root.display());
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let upstream_dir = manifest.join("upstream");
    let generated_dir = manifest.join("generated");
    let handwritten_dir = manifest.join("handwritten");

    // The AWS CLI operation catalog lives in `generated/data`, which is cleared
    // below. Without an AWS CLI checkout to regenerate it from, the committed
    // catalog is carried across the sync; the build script cannot compile the
    // data-source crate without one, so a first sync must supply the checkout.
    let catalog_step = match aws_cli_root {
        Some(aws_cli_root) => CatalogStep::Generate(aws_cli_root),
        None => CatalogStep::Restore(preserve_aws_cli_catalog(&generated_dir)?.ok_or_else(|| {
            anyhow::anyhow!(
                "no AWS CLI operation catalog exists at generated/data/{AWS_CLI_OPERATION_CATALOG_FILE}; \
                 pass --aws-cli-root <DIR> so sync can generate it"
            )
        })?),
    };

    // Every file under these directories is rewritten by a full sync, so clear
    // them first: a source that stops being produced must not linger as a stale
    // artifact. `generated/data` is shared by the sync and generate phases and can
    // only be cleared here, ahead of both.
    for cache_directory in [upstream_dir.clone(), generated_dir.join("patched_schemas"), generated_dir.join("data")] {
        clear_cache_directory(&cache_directory)?;
    }

    sync_upstream(&upstream_dir, &rule_source_root)?;
    generate_all(&upstream_dir, &generated_dir, &handwritten_dir)?;
    match catalog_step {
        CatalogStep::Generate(aws_cli_root) => generate_aws_cli_catalog(&upstream_dir, &generated_dir, &aws_cli_root)?,
        CatalogStep::Restore(preserved) => restore_aws_cli_catalog(&generated_dir, preserved)?,
    }

    info!("Sync and generation complete");
    Ok(())
}

/// How the sync ends up with an AWS CLI operation catalog in `generated/data`.
enum CatalogStep {
    /// Derive a fresh catalog from the botocore models bundled in this AWS CLI checkout.
    Generate(PathBuf),
    /// Carry the committed catalog across the sync and re-verify it against the refreshed schemas.
    Restore(PreservedAwsCliCatalog),
}

fn clear_cache_directory(cache_directory: &Path) -> anyhow::Result<()> {
    fs::remove_dir_all(cache_directory)
        .or_else(|error| if error.kind() == ErrorKind::NotFound { Ok(()) } else { Err(error) })
        .with_context(|| format!("failed to clear cache directory {}", cache_directory.display()))
}

fn print_usage() {
    eprintln!(
        "Usage: cargo run -p cloudformation-validate-data-source --features maintenance --example sync -- --cfn-lint-root <DIR> [--aws-cli-root <DIR>]

Refreshes all upstream sources, records their versions, and generates every output.
With --aws-cli-root, the AWS CLI operation catalog is regenerated from that checkout's
bundled botocore models as the final step; without it, the committed catalog is kept
and re-verified against the refreshed schemas.

Options:
  --cfn-lint-root <DIR>         Path to cfn-lint repo (required)
  --aws-cli-root <DIR>          Path to a local aws-cli checkout (optional)
  -h, --help                    Show this help"
    );
}
