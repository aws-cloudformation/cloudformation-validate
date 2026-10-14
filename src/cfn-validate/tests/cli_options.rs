use std::process::Command;

#[test]
fn version_option_prints_package_version_and_succeeds() {
    let output =
        Command::new(env!("CARGO_BIN_EXE_cfn-validate")).arg("--version").output().expect("run cfn-validate --version");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stderr: {stderr}");
    assert_eq!(stdout.as_ref(), format!("cfn-validate {}\n", env!("CARGO_PKG_VERSION")));
    assert!(stderr.is_empty(), "unexpected stderr: {stderr}");
}
