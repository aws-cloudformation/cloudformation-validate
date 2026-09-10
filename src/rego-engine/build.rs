use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

const HANDWRITTEN_REGO_OUTPUT: &str = "handwritten_rego.rs";

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let output_dir = PathBuf::from(env::var("OUT_DIR")?);
    let policy_dir = manifest_dir.join("handwritten").join("rego");

    println!("cargo:rerun-if-changed={}", policy_dir.display());

    if !policy_dir.is_dir() {
        return Err(format!("missing required handwritten Rego directory: {}", policy_dir.display()).into());
    }

    let mut generated_source = String::from("pub(crate) const HANDWRITTEN_REGO_POLICIES: &[(&str, &str)] = &[\n");
    let policy_count = collect_rego_files(&policy_dir, &policy_dir, &mut generated_source)?;
    if policy_count == 0 {
        return Err(
            format!("required handwritten Rego directory contains no .rego files: {}", policy_dir.display()).into()
        );
    }
    generated_source.push_str("];\n");

    fs::write(output_dir.join(HANDWRITTEN_REGO_OUTPUT), generated_source)?;
    Ok(())
}

fn collect_rego_files(
    base_dir: &Path,
    current_dir: &Path,
    generated_source: &mut String,
) -> Result<usize, Box<dyn Error>> {
    let mut entries: Vec<_> = fs::read_dir(current_dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|entry| entry.path());

    let mut policy_count = 0;
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            policy_count += collect_rego_files(base_dir, &path, generated_source)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rego") {
            let relative_path = path.strip_prefix(base_dir)?.display().to_string();
            let policy_source = fs::read_to_string(&path)?;
            generated_source.push_str(&format!("    ({relative_path:?}, {policy_source:?}),\n"));
            policy_count += 1;
        }
    }

    Ok(policy_count)
}
