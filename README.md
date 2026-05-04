# x7q

`x7q` is a passive, text-only container format and CLI toolchain for moving text through PDF-like workflows without carrying PDF actions, scripts, embedded files, dynamic loading, or active document behavior.

Creator: **Umut Burak Türkcan**

If you use x7q in a project, product, research prototype, integration, or new file-format/security workflow, please notify the creator by email:

```text
burakturkcan78@gmail.com
```

Please include a short description of where and how x7q is being used. This helps track adoption, real-world use cases, and future compatibility needs.

## License And Commercial Use

x7q is licensed under:

```text
AGPL-3.0-only
```

Copyright remains with **Umut Burak Türkcan**.

Under AGPL-3.0-only, users may use, study, modify, and distribute this project only under the AGPL terms. If someone modifies and distributes x7q, or modifies and provides it as a network service, they must make the corresponding source code available under AGPL-3.0-only.

This license does not grant permission to make a closed-source/proprietary product from x7q. For proprietary use, closed-source integration, private commercial licensing, or any separate commercial agreement, contact:

```text
burakturkcan78@gmail.com
```

This software is provided without warranty. Users are responsible for how they use x7q in their own systems, products, research, or workflows.

The main tool is `x7q-secure`. It can:

- convert PDF text into `.x7q`
- convert `.x7q` text back into a passive text-only PDF
- build `.x7q` from plain text
- validate `.x7q` integrity and policy metadata
- optionally encrypt `.x7q` text payloads with a user-provided key

## Security Model

x7q files are designed to carry text, not executable document behavior.

Implemented guarantees:

- no PDF JavaScript, actions, attachments, launch actions, or embedded active content in `.x7q`
- strict text canonicalization before packaging
- rejection of control characters, zero-width/bidi override characters, executable magic bytes, and common executable/script patterns
- deterministic canonical content hash
- container header and section integrity checks
- passive-only policy metadata bound into the container
- optional AES-256-GCM payload encryption
- Argon2id password-based key derivation
- zero `unsafe` Rust in project crates

Important limits:

- x7q does not prove who authored a file; digital signatures are not implemented yet.
- x7q does not guarantee semantic prompt-injection safety.
- PDF extraction depends on text being extractable from the source PDF. Scanned PDFs need OCR before conversion.
- Command-line `--key` is convenient but can appear in shell history/process lists. For high-security use, add key-file or interactive prompt handling before production deployment.

## Install / Build

Requirements:

- Rust toolchain

Build:

```powershell
cargo build --workspace
```

Run tests:

```powershell
cargo test --workspace
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
```

## CLI Usage

Convert PDF to x7q:

```powershell
x7q-secure pdf-to-x7q input.pdf output.x7q
```

Convert encrypted PDF text to x7q:

```powershell
x7q-secure pdf-to-x7q input.pdf output.x7q --key "my secret key"
```

Convert x7q back to passive text-only PDF:

```powershell
x7q-secure x7q-to-pdf input.x7q output.pdf
```

Convert encrypted x7q back to PDF:

```powershell
x7q-secure x7q-to-pdf input.x7q output.pdf --key "my secret key"
```

Build x7q directly from a text file:

```powershell
x7q-secure build-v2 prompt.txt prompt.x7q
```

Validate x7q:

```powershell
x7q-secure validate-v2 prompt.x7q
x7q-secure validate-v2 encrypted.x7q --key "my secret key"
```

Inspect container metadata:

```powershell
x7q-secure inspect prompt.x7q
```

Legacy v1 commands are still available:

```powershell
x7q-secure verify file.x7q
x7q-secure build manifest.txt
x7q parse file.x7q
```

## Simple Windows GUI

A small PowerShell/WinForms GUI is included:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\x7q-gui.ps1
```

The GUI supports:

- PDF to x7q
- x7q to PDF
- file picker dialogs
- automatic output path selection after choosing an input file
- optional key-based encryption/decryption

On first use it builds `x7q-secure` with Cargo if `target\debug\x7q-secure.exe` does not exist. If the selected input file is in a protected drive root such as `C:\`, the GUI suggests `C:\tmp` as the output folder to avoid Windows access-denied errors.

## Format Overview

`x7q-secure v2.0` uses binary version byte `0x03`.

Required plaintext sections:

| Section | Type | Meaning |
|---|---:|---|
| canonical text | `0x01` | Canonical strict text payload |
| policy | `0xf0` | Passive-only contract |
| provenance | `0xf1` | Source format, extractor, canonicalization log |
| canonical hash | `0xf2` | SHA-256 over canonical text |

Required encrypted sections:

| Section | Type | Meaning |
|---|---:|---|
| encrypted text | `0x02` | AES-256-GCM ciphertext of canonical text |
| policy | `0xf0` | Passive-only contract with encryption marker |
| provenance | `0xf1` | Source format, extractor, canonicalization log |
| canonical hash | `0xf2` | SHA-256 over decrypted canonical text |
| crypto metadata | `0xf3` | Algorithm, KDF, salt, nonce |

## PDF Behavior

PDF to x7q:

- extracts text from the source PDF
- canonicalizes text
- rejects unsafe text profile violations
- stores only text and metadata in `.x7q`

x7q to PDF:

- opens and validates `.x7q`
- decrypts if a key is provided and required
- renders a simple passive PDF containing only text drawing commands
- does not emit JavaScript, attachments, launch actions, forms, embedded files, or external fetch behavior

## Repository Layout

```text
crates/x7q-secure/   Main v2 secure container library and CLI
crates/x7q-cli/      Minimal legacy x7q parser CLI
crates/x7q-core/     Legacy parser facade
crates/x7q-parser/   Legacy v0.1 parser
crates/x7q-format/   Legacy format constants/types
spec/                Format specifications
tests/fixtures/      Test fixtures
docs/                Reports and design notes
tools/x7q-gui.ps1    Simple Windows GUI launcher
```

## Validation Status

Latest local validation:

```text
cargo build --workspace: PASS
cargo test --workspace: PASS
cargo fmt --check: PASS
cargo clippy --workspace --all-targets -- -D warnings: PASS
```

Implemented tests currently cover:

- legacy parser behavior
- v1 integrity parser behavior
- v2 strict text validation
- executable/invisible character rejection
- encrypted payload build/open failure/open success
- PDF to x7q conversion
- x7q to PDF conversion
- CLI roundtrips

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
