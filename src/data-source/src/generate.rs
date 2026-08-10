use data_source::generate_all;
use log::info;
use std::env;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    if env::args().any(|a| a == "-h" || a == "--help") {
        eprintln!(
            "Usage: cargo run -p data-source --features maintenance --example generate\n\n\
             Generates all outputs from existing upstream data.\n\
             To refresh upstream data first, run `cargo run -p data-source --features maintenance --example sync -- --cfn-lint-root <DIR>`."
        );
        return Ok(());
    }

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let upstream_dir = manifest.join("upstream");
    let generated_dir = manifest.join("generated");
    let handwritten_dir = manifest.join("handwritten");

    generate_all(&upstream_dir, &generated_dir, &handwritten_dir)?;

    info!("Done - all outputs in data-source/generated/");
    Ok(())
}
