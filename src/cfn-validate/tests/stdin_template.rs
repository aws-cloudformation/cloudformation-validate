//! End-to-end checks that the `cfn-validate` binary validates a template piped
//! to standard input (`-`) exactly as it validates the same template on disk.

mod common;

use common::{load_template, templates_dir};
use serde_json::Value;
use std::io::Write;
use std::process::{Command, Output, Stdio};

const TEMPLATE_WITH_DIAGNOSTICS: &str = "bad/invalid_deletion_policy.yaml";
const STDIN_PATH_LABEL: &str = "<stdin>";

fn run_cli(args: &[&str], stdin_bytes: Option<&[u8]>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cfn-validate"))
        .args(args)
        .stdin(if stdin_bytes.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cfn-validate");
    if let Some(bytes) = stdin_bytes {
        child.stdin.take().expect("piped stdin").write_all(bytes).expect("write template to stdin");
    }
    child.wait_with_output().expect("wait for cfn-validate")
}

fn report_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!("stdout is not a JSON report: {e}\nstderr: {}", String::from_utf8_lossy(&output.stderr))
    })
}

#[test]
fn stdin_template_produces_the_same_diagnostics_as_the_file_on_disk() {
    let template_path = templates_dir().join(TEMPLATE_WITH_DIAGNOSTICS);
    let from_file = run_cli(&[template_path.to_str().unwrap(), "--format", "standard"], None);
    let from_stdin = run_cli(&["-", "--format", "standard"], Some(&load_template(TEMPLATE_WITH_DIAGNOSTICS)));

    let file_report = report_json(&from_file);
    let stdin_report = report_json(&from_stdin);
    assert!(
        !file_report["diagnostics"].as_array().unwrap().is_empty(),
        "fixture must produce diagnostics so the comparison is meaningful"
    );
    assert_eq!(stdin_report["diagnostics"], file_report["diagnostics"]);
    assert_eq!(stdin_report["status"], file_report["status"]);
    assert_eq!(from_stdin.status.code(), from_file.status.code(), "exit codes must agree");
}

#[test]
fn stdin_template_report_is_labelled_as_stdin() {
    let output = run_cli(&["-", "--format", "standard"], Some(b"Resources: {}"));

    assert_eq!(report_json(&output)["filePath"], Value::String(STDIN_PATH_LABEL.to_string()));
}

#[test]
fn malformed_stdin_template_is_reported_as_a_parse_diagnostic_not_a_crash() {
    let output = run_cli(&["-", "--format", "standard"], Some(b"not: a: valid: yaml: ["));

    let report = report_json(&output);
    assert_eq!(report["status"], Value::String("ERROR".to_string()));
    assert_eq!(report["diagnostics"][0]["ruleId"], Value::String("F1101".to_string()));
    assert_eq!(output.status.code(), Some(1), "a template with errors exits with status 1");
}
