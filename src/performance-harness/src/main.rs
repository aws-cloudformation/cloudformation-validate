mod comparison;
mod measurement;
mod worker;

use std::env;
use std::path::PathBuf;

fn usage() -> &'static str {
    "usage:\n  performance-harness measure <rego|cel|composite> <iterations> <warmups> <label> <template>...\n  performance-harness compare --base-executable <file> [--base-revision <revision>] [--title <text>] [--output-dir <directory>]"
}

#[derive(Debug)]
struct CompareOptions {
    base_executable: Option<PathBuf>,
    base_revision: Option<String>,
    title: Option<String>,
    output_dir: PathBuf,
}

fn parse_compare_options(arguments: &[String]) -> Result<CompareOptions, String> {
    let mut options = CompareOptions {
        base_executable: None,
        base_revision: None,
        title: None,
        output_dir: measurement::project_root().join("tmp/performance-check"),
    };
    let mut index = 0;
    while index < arguments.len() {
        let option = arguments[index].as_str();
        index += 1;
        let value = arguments.get(index).cloned().ok_or_else(|| format!("{option} requires a value"))?;
        match option {
            "--base-executable" => options.base_executable = Some(PathBuf::from(value)),
            "--base-revision" => options.base_revision = Some(value),
            "--title" => options.title = Some(value),
            "--output-dir" => options.output_dir = PathBuf::from(value),
            unknown => return Err(format!("unknown option {unknown:?}\n{}", usage())),
        }
        index += 1;
    }
    Ok(options)
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
        "compare" => {
            let options = parse_compare_options(&arguments[1..])?;
            let base_executable =
                options.base_executable.ok_or_else(|| format!("compare requires --base-executable\n{}", usage()))?;
            let base_revision = options.base_revision.unwrap_or_else(|| base_executable.display().to_string());
            let title = options.title.as_deref().unwrap_or(comparison::DEFAULT_TITLE);
            let passed = comparison::run_compare(&base_executable, &base_revision, title, &options.output_dir)?;
            Ok(if passed { 0 } else { 1 })
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
