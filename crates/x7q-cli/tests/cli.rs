#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[test]
fn cli_parses_valid_fixture() {
    let output = Command::new(env!("CARGO_BIN_EXE_x7q"))
        .arg("parse")
        .arg(fixture("valid_minimal.x7q"))
        .output()
        .expect("CLI should run");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("x7q parse ok"));
    assert!(stdout.contains("sections=0"));
}

#[test]
fn cli_rejects_invalid_fixture() {
    let output = Command::new(env!("CARGO_BIN_EXE_x7q"))
        .arg("parse")
        .arg(fixture("invalid_magic.x7q"))
        .output()
        .expect("CLI should run");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");
    assert!(stderr.contains("invalid x7q container"));
    assert!(stderr.contains("invalid magic"));
}
