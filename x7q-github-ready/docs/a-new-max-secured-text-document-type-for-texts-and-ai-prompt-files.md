# A New Max Secured Text Document Type For Texts And AI Prompt Files

Developer: Umut Burak Türkcan

Development date: 3 May 2026, 21.21

Project implementation: x7q / x7q-secure

Repository reference: https://github.com/Umutburakrukcan-77

## 1. Project Summary

**A New Max Secured Text Document Type For Texts And AI Prompt Files** is a security-focused binary container system for storing text files, AI prompt files, and similar byte payloads inside a deterministic and verifiable file format.

This system is not a PDF-like document format. It does not render content, execute scripts, load dynamic code, or interpret payloads as active behavior. Its purpose is to package content with strict metadata and integrity verification.

The current workspace contains two compatible layers:

| Layer | Purpose | Status |
|---|---|---:|
| `x7q v0.1` | Minimal secure binary container parser | Implemented |
| `x7q-secure v1.0` | Hash-verified secure binary container | Implemented |

## 2. Architecture Overview

The system is implemented as a Rust Cargo workspace.

Main crates:

| Crate | Responsibility |
|---|---|
| `x7q-format` | Shared v0.1 format constants and metadata types |
| `x7q-parser` | Deterministic v0.1 parser |
| `x7q-core` | Public facade for v0.1 parser API |
| `x7q-cli` | CLI command: `x7q parse <file>` |
| `x7q-secure` | v1.0 secure parser, builder, verifier, inspector, and CLI |

The most important component is `x7q-secure v1.0`. It adds SHA-256 based integrity verification for both the header and payload content.

## 3. x7q-secure v1.0 Format

Header fields:

| Field | Meaning |
|---|---|
| `magic` | Fixed bytes: `X7Q\0` |
| `version` | Strict version byte: `0x02` |
| `header_len` | Exact header length |
| `section_count` | Number of section records |
| `content_hash` | SHA-256 over all section bytes |
| `header_hash` | SHA-256 over the header with the hash field zeroed |

Section fields:

| Field | Meaning |
|---|---|
| `type` | Application-defined section type |
| `offset` | Payload byte offset |
| `length` | Payload byte length |
| `flags` | Metadata flags only; no execution permission |

## 4. Security Model

Implemented security properties:

- No payload execution.
- No dynamic code loading.
- No unsafe Rust in parser or CLI code.
- Strict schema versioning.
- Deterministic parsing.
- Typed parser errors.
- Fail-closed behavior for malformed input.
- Integer overflow checks.
- Section bounds checks.
- Header tampering detection through `header_hash`.
- Payload tampering detection through `content_hash`.
- Reproducible parse result for identical input.

Important limitation:

This version verifies integrity, not identity. A malicious party can still create a new valid container with new hashes. For author/source authenticity, a future version should add public-key digital signatures.

## 5. CLI Commands

Current CLI commands:

```powershell
x7q parse <file>
x7q-secure verify <file>
x7q-secure inspect <file>
x7q-secure build <manifest>
```

The `build` command can package a text file or AI prompt file into an x7q-secure binary container. The `verify` command validates the container integrity. The `inspect` command prints deterministic metadata.

## 6. Test Results

Test execution date: 3 Mayıs 2026

Verification commands executed:

```powershell
cargo build
cargo test
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
```

All required commands passed.

| Command | Result |
|---|---:|
| `cargo build` | PASS |
| `cargo test` | PASS |
| `cargo fmt --check` | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS |

Observed test summary:

| Test group | Result |
|---|---:|
| x7q v0.1 CLI tests | 2 passed, 0 failed |
| x7q v0.1 parser tests | 11 passed, 0 failed |
| x7q-secure v1.0 parser/security tests | 8 passed, 0 failed |
| x7q-secure v1.0 CLI tests | 3 passed, 0 failed |
| Total implemented tests | 24 passed, 0 failed |

## 7. Security Tests Covered

The current test suite covers:

- valid container parsing
- corrupted magic rejection
- corrupted hash rejection
- truncated file rejection
- forged section bounds rejection
- tampered header rejection
- deterministic re-parse behavior
- CLI verification of valid files
- CLI rejection of corrupted files
- CLI build from manifest

## 8. Practical Use Case

The system can store:

- text documents
- AI prompt files
- prompt templates
- structured text payloads
- metadata-controlled binary payloads

The output is not a plain `.txt` file. The output is a secure binary container that can carry text content while protecting against accidental or malicious modification.

## 9. Final Status

The project is implemented, buildable, testable, and suitable for publication as an early secure-container prototype.

Current status:

- `x7q v0.1`: implemented and passing tests.
- `x7q-secure v1.0`: implemented and passing tests.
- Build pipeline: passing.
- Test pipeline: passing.
- Formatting: passing.
- Clippy with warnings denied: passing.

Final verdict: **A New Max Secured Text Document Type For Texts And AI Prompt Files** currently exists as a working Rust implementation with integrity-verified binary containers for text and AI prompt payloads.

