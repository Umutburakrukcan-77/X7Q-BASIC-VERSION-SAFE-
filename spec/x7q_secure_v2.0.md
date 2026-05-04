# x7q-secure v2.0 Strict Text Container Specification

## Scope

x7q-secure v2.0 is a strict text transport profile on top of the x7q secure binary container. It is designed to carry text only. It is not a PDF engine, not an execution sandbox, and not a semantic prompt-injection detector.

The profile provides:

- deterministic canonicalization
- fail-closed strict text validation
- passive-only policy metadata
- transformation provenance metadata
- canonical content hashing
- optional payload encryption
- passive text-only PDF output

## Header

The binary header layout is the same as x7q-secure v1.0. The v2 version byte is `0x03`.

All section ranges must:

- start at or after `header_len`
- stay inside the file
- avoid overlap with every other section

## Plaintext Sections

| Type | Name | Meaning |
|---:|---|---|
| `0x01` | canonical text | Strict canonical UTF-8 text payload |
| `0xf0` | policy | Passive-only execution boundary contract |
| `0xf1` | provenance | Source format, source name, extractor, canonicalization log |
| `0xf2` | canonical hash | SHA-256 over canonical text bytes |

## Encrypted Sections

| Type | Name | Meaning |
|---:|---|---|
| `0x02` | encrypted text | AES-256-GCM ciphertext of canonical UTF-8 text |
| `0xf0` | policy | Passive-only contract with encryption marker |
| `0xf1` | provenance | Source format, source name, extractor, canonicalization log |
| `0xf2` | canonical hash | SHA-256 over decrypted canonical text bytes |
| `0xf3` | crypto metadata | Algorithm, KDF, salt, nonce |

## Encryption

Payload encryption uses:

- KDF: Argon2id
- Cipher: AES-256-GCM
- Salt: 16 random bytes
- Nonce: 12 random bytes

The user-provided key is never stored in the container. A wrong key or tampered ciphertext fails closed during decryption.

## Strict Text Profile

Build and validation reject:

- C0 control characters except tab and line feed
- `DEL`
- zero-width and bidirectional override characters
- soft hyphen
- executable patterns such as shebangs, script tags, shell invocations, `eval`, `exec`, `system`, `curl`, and `wget`
- executable magic bytes such as `MZ`, `ELF`, and ZIP local headers

Canonicalization:

- converts CRLF/CR to LF
- strips a leading UTF-8 BOM
- trims trailing spaces and tabs per line
- preserves deterministic bytes for hashing

## PDF to x7q

`x7q-secure pdf-to-x7q <input.pdf> <output.x7q> [--key <key>]`

The converter extracts text from the source PDF, canonicalizes it, validates the strict profile, and stores only text plus metadata in x7q. Scanned PDFs require OCR before conversion.

## x7q to PDF

`x7q-secure x7q-to-pdf <input.x7q> <output.pdf> [--key <key>]`

The converter validates the x7q file, decrypts it when required, and emits a passive text-only PDF. The generated PDF contains text drawing commands only and does not intentionally emit JavaScript, forms, attachments, launch actions, embedded files, or external fetch behavior.

## CLI

```powershell
x7q-secure build-v2 prompt.txt prompt.x7q
x7q-secure build-v2 prompt.txt encrypted.x7q --key "secret"
x7q-secure validate-v2 prompt.x7q
x7q-secure validate-v2 encrypted.x7q --key "secret"
x7q-secure pdf-to-x7q source.pdf source.x7q
x7q-secure pdf-to-x7q source.pdf encrypted.x7q --key "secret"
x7q-secure x7q-to-pdf source.x7q restored.pdf
x7q-secure x7q-to-pdf encrypted.x7q restored.pdf --key "secret"
```
