use anyhow::Context;
use data_source::{generate_all, sync_upstream};
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
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let upstream_dir = manifest.join("upstream");
    let generated_dir = manifest.join("generated");
    let handwritten_dir = manifest.join("handwritten");

    for cache_directory in [upstream_dir.clone(), generated_dir.join("patched_schemas")] {
        clear_cache_directory(&cache_directory)?;
    }

    sync_upstream(&upstream_dir, &rule_source_root)?;
    generate_all(&upstream_dir, &generated_dir, &handwritten_dir)?;

    info!("Sync and generation complete");
    Ok(())
}

fn clear_cache_directory(cache_directory: &Path) -> anyhow::Result<()> {
    fs::remove_dir_all(cache_directory)
        .or_else(|error| if error.kind() == ErrorKind::NotFound { Ok(()) } else { Err(error) })
        .with_context(|| format!("failed to clear cache directory {}", cache_directory.display()))
}

fn print_usage() {
    eprintln!(
        "Usage: cargo run -p cloudformation-validate-data-source --features maintenance --example sync -- --cfn-lint-root <DIR>

Refreshes all upstream sources, records their versions, and generates every output.

Options:
  --cfn-lint-root <DIR>         Path to cfn-lint repo (required)
  -h, --help                    Show this help"
    );
}
