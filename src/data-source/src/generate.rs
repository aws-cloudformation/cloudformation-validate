use log::info;
use std::env;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    if env::args().any(|a| a == "-h" || a == "--help") {
        eprintln!(
            "Usage: cargo run -p data-source --example generate\n\n\
             Generates all outputs from existing upstream data.\n\
             Run `cargo run -p data-source --example sync` first to populate upstream/."
        );
        return Ok(());
    }

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let upstream_dir = manifest.join("upstream");
    let generated_dir = manifest.join("generated");
    let handwritten_dir = manifest.join("handwritten");

    data_source::generate_all(&upstream_dir, &generated_dir, &handwritten_dir)?;

    info!("Done — all outputs in data-source/generated/");
    Ok(())
}
