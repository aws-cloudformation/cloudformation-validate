mod baseline;
mod worker;

use std::env;
use std::path::{Path, PathBuf};

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn usage() -> &'static str {
    "usage:\n  performance-harness measure <rego|cel> <iterations> <warmups> <label> <template>...\n  performance-harness check [--expected <file>] [--output-dir <directory>]\n  performance-harness update [--expected <file>] [--profile <profile>] [--output-dir <directory>]"
}

fn option_value(arguments: &[String], index: &mut usize, option: &str) -> Result<String, String> {
    *index += 1;
    arguments.get(*index).cloned().ok_or_else(|| format!("{option} requires a value"))
}

fn parse_options(arguments: &[String]) -> Result<(Option<PathBuf>, Option<String>, PathBuf), String> {
    let mut expected = None;
    let mut profile = None;
    let mut output_dir = project_root().join("tmp/performance-check");
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--expected" => expected = Some(PathBuf::from(option_value(arguments, &mut index, "--expected")?)),
            "--profile" => profile = Some(option_value(arguments, &mut index, "--profile")?),
            "--output-dir" => {
                output_dir = PathBuf::from(option_value(arguments, &mut index, "--output-dir")?);
            }
            unknown => return Err(format!("unknown option {unknown:?}\n{}", usage())),
        }
        index += 1;
    }
    Ok((expected, profile, output_dir))
}

fn run(arguments: &[String]) -> Result<i32, String> {
    let Some(command) = arguments.first().map(String::as_str) else {
        return Err(usage().into());
    };
    match command {
        "measure" => {
            worker::run(&arguments[1..])?;
            Ok(0)
        }
        "check" => {
            let (expected, profile, output_dir) = parse_options(&arguments[1..])?;
            if profile.is_some() {
                return Err("--profile is valid only with update".into());
            }
            let environment = baseline::detect_environment();
            let expected = match expected {
                Some(path) => path,
                None => baseline::default_expected_file(&environment)?,
            };
            Ok(if baseline::run_check(&expected, &output_dir)? { 0 } else { 1 })
        }
        "update" => {
            let (expected, profile, output_dir) = parse_options(&arguments[1..])?;
            let environment = baseline::detect_environment();
            let expected = match expected {
                Some(path) => path,
                None => baseline::default_expected_file(&environment)?,
            };
            baseline::run_update(&expected, profile.as_deref(), &output_dir)?;
            Ok(0)
        }
        _ => Err(usage().into()),
    }
}

fn main() {
    let arguments: Vec<String> = env::args().skip(1).collect();
    match run(&arguments) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("performance harness failed: {error}");
            std::process::exit(2);
        }
    }
}
