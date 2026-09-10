//! Standalone command that (re)generates the AWS CLI operation catalog.
//!
//! This is deliberately separate from the `sync` and `generate` maintenance
//! examples: it only generates the catalog and never downloads or processes
//! schemas. It assumes the resource data is already present - the provider
//! schemas under `upstream/schemas` (written by `sync`) and the committed
//! compiled schemas under `generated/schema-validator`.
//!
//! Usage:
//!   cargo run -p cloudformation-validate-data-source --features maintenance \
//!     --example generate_aws_cli_catalog -- --aws-cli-root <DIR>
//!
//! `--aws-cli-root` points at a local `aws-cli` checkout (its `awscli/` supplies
//! botocore).

use data_source::generate_aws_cli_catalog;
use log::error;
use std::env;
use std::path::PathBuf;
use std::process;

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = env::args().collect();
    let mut aws_cli_root: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--aws-cli-root" => {
                i += 1;
                if i >= args.len() {
                    error!("--aws-cli-root requires a path argument");
                    process::exit(1);
                }
                aws_cli_root = Some(args[i].clone());
            }
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            other => {
                error!("unknown argument: {other}");
                print_usage();
                process::exit(1);
            }
        }
        i += 1;
    }

    let Some(aws_cli_root) = aws_cli_root else {
        print_usage();
        anyhow::bail!("--aws-cli-root <DIR> is required");
    };

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let upstream_dir = manifest.join("upstream");
    let generated_dir = manifest.join("generated");

    generate_aws_cli_catalog(&upstream_dir, &generated_dir, &PathBuf::from(aws_cli_root))?;
    Ok(())
}

fn print_usage() {
    eprintln!(
        "Usage: cargo run -p cloudformation-validate-data-source --features maintenance \\
    --example generate_aws_cli_catalog -- --aws-cli-root <DIR>

Generates the AWS CLI operation catalog (generated/data/aws_cli_operation_catalog.json)
from AWS CLI botocore service models and CloudFormation provider handler metadata.
It only generates the catalog: the resource data must already be present
(upstream/schemas from a prior sync, plus the committed compiled schemas).

Options:
  --aws-cli-root <DIR>          Path to a local aws-cli checkout (required)
  -h, --help                    Show this help"
    );
}
