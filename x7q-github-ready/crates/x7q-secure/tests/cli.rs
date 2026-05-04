#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn run_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
}

#[test]
fn cli_verify_and_inspect_valid_fixture() {
    let verify = Command::new(env!("CARGO_BIN_EXE_x7q-secure"))
        .arg("verify")
        .arg(fixture("secure_valid.x7q"))
        .output()
        .expect("CLI should run");
    assert!(verify.status.success());
    let stdout = String::from_utf8(verify.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("x7q-secure verify ok"));

    let inspect = Command::new(env!("CARGO_BIN_EXE_x7q-secure"))
        .arg("inspect")
        .arg(fixture("secure_valid.x7q"))
        .output()
        .expect("CLI should run");
    assert!(inspect.status.success());
    let stdout = String::from_utf8(inspect.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("section_count=1"));
    assert!(stdout.contains("content_hash="));
}

#[test]
fn cli_rejects_corrupted_fixture() {
    let output = Command::new(env!("CARGO_BIN_EXE_x7q-secure"))
        .arg("verify")
        .arg(fixture("secure_invalid_hash.x7q"))
        .output()
        .expect("CLI should run");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");
    assert!(stderr.contains("verification failed"));
}

#[test]
fn cli_builds_from_manifest() {
    let temp_dir = run_dir();
    fs::create_dir_all(&temp_dir).expect("temp dir should be created");
    let payload_path = temp_dir.join("payload.bin");
    let output_path = temp_dir.join("built.x7q");
    let manifest_path = temp_dir.join("build.manifest");
    fs::write(&payload_path, b"manifest payload").expect("payload should be written");
    fs::write(
        &manifest_path,
        format!(
            "output={}\nsection=0x01,0x02,{}\n",
            display_path(&output_path),
            display_path(&payload_path)
        ),
    )
    .expect("manifest should be written");

    let build = Command::new(env!("CARGO_BIN_EXE_x7q-secure"))
        .arg("build")
        .arg(&manifest_path)
        .output()
        .expect("CLI should run");
    assert!(build.status.success());

    let verify = Command::new(env!("CARGO_BIN_EXE_x7q-secure"))
        .arg("verify")
        .arg(&output_path)
        .output()
        .expect("CLI should run");
    assert!(verify.status.success());
}

#[test]
fn cli_builds_and_validates_v2_text() {
    let temp_dir = run_dir();
    fs::create_dir_all(&temp_dir).expect("temp dir should be created");
    let text_path = temp_dir.join("prompt.txt");
    let output_path = temp_dir.join("prompt-v2.x7q");
    fs::write(&text_path, "hello\r\nprompt  ").expect("text should be written");

    let build = Command::new(env!("CARGO_BIN_EXE_x7q-secure"))
        .arg("build-v2")
        .arg(&text_path)
        .arg(&output_path)
        .output()
        .expect("CLI should run");
    assert!(build.status.success());

    let validate = Command::new(env!("CARGO_BIN_EXE_x7q-secure"))
        .arg("validate-v2")
        .arg(&output_path)
        .output()
        .expect("CLI should run");
    assert!(validate.status.success());
    let stdout = String::from_utf8(validate.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("x7q-secure validate-v2 ok"));
    assert!(stdout.contains("policy_contract=passive-only"));
}

#[test]
fn cli_converts_basic_pdf_to_v2_x7q() {
    let temp_dir = run_dir();
    fs::create_dir_all(&temp_dir).expect("temp dir should be created");
    let pdf_path = temp_dir.join("sample.pdf");
    let output_path = temp_dir.join("sample.x7q");
    fs::write(
        &pdf_path,
        b"%PDF-1.4\n1 0 obj\n<<>>\nstream\nBT\n(Hello from PDF) Tj\nET\nendstream\nendobj\n%%EOF",
    )
    .expect("PDF should be written");

    let convert = Command::new(env!("CARGO_BIN_EXE_x7q-secure"))
        .arg("pdf-x7q")
        .arg(&pdf_path)
        .arg(&output_path)
        .output()
        .expect("CLI should run");
    assert!(convert.status.success());

    let validate = Command::new(env!("CARGO_BIN_EXE_x7q-secure"))
        .arg("validate-v2")
        .arg(&output_path)
        .output()
        .expect("CLI should run");
    assert!(validate.status.success());
}

#[test]
fn cli_converts_x7q_back_to_pdf() {
    let temp_dir = run_dir();
    fs::create_dir_all(&temp_dir).expect("temp dir should be created");
    let text_path = temp_dir.join("roundtrip.txt");
    let x7q_path = temp_dir.join("roundtrip.x7q");
    let pdf_path = temp_dir.join("roundtrip.pdf");
    fs::write(&text_path, "roundtrip text").expect("text should be written");

    let build = Command::new(env!("CARGO_BIN_EXE_x7q-secure"))
        .arg("build-v2")
        .arg(&text_path)
        .arg(&x7q_path)
        .output()
        .expect("CLI should run");
    assert!(build.status.success());

    let convert = Command::new(env!("CARGO_BIN_EXE_x7q-secure"))
        .arg("x7q-to-pdf")
        .arg(&x7q_path)
        .arg(&pdf_path)
        .output()
        .expect("CLI should run");
    assert!(convert.status.success());

    let pdf = fs::read(&pdf_path).expect("PDF should be readable");
    assert!(pdf.starts_with(b"%PDF-1.4"));
    assert!(
        pdf.windows(b"roundtrip text".len())
            .any(|window| window == b"roundtrip text")
    );
}

#[test]
fn cli_encrypts_and_decrypts_v2_text() {
    let temp_dir = run_dir();
    fs::create_dir_all(&temp_dir).expect("temp dir should be created");
    let text_path = temp_dir.join("secret.txt");
    let x7q_path = temp_dir.join("secret.x7q");
    let pdf_path = temp_dir.join("secret.pdf");
    fs::write(&text_path, "encrypted roundtrip").expect("text should be written");

    let build = Command::new(env!("CARGO_BIN_EXE_x7q-secure"))
        .arg("build-v2")
        .arg(&text_path)
        .arg(&x7q_path)
        .arg("--key")
        .arg("test-key")
        .output()
        .expect("CLI should run");
    assert!(build.status.success());

    let validate_without_key = Command::new(env!("CARGO_BIN_EXE_x7q-secure"))
        .arg("validate-v2")
        .arg(&x7q_path)
        .output()
        .expect("CLI should run");
    assert!(!validate_without_key.status.success());

    let validate_with_key = Command::new(env!("CARGO_BIN_EXE_x7q-secure"))
        .arg("validate-v2")
        .arg(&x7q_path)
        .arg("--key")
        .arg("test-key")
        .output()
        .expect("CLI should run");
    assert!(validate_with_key.status.success());

    let convert = Command::new(env!("CARGO_BIN_EXE_x7q-secure"))
        .arg("x7q-to-pdf")
        .arg(&x7q_path)
        .arg(&pdf_path)
        .arg("--key")
        .arg("test-key")
        .output()
        .expect("CLI should run");
    assert!(convert.status.success());
    assert!(
        fs::read(&pdf_path)
            .expect("PDF should be readable")
            .starts_with(b"%PDF-1.4")
    );
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
