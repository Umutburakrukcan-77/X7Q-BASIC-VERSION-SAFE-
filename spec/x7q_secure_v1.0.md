# x7q-secure v1.0 Binary Container Specification

Repository reference: https://github.com/Umutburakrukcan-77

## Scope

x7q-secure v1.0 is a secure binary container format with deterministic parsing and hash-based integrity verification. It is not a document format and it performs no payload execution.

## Header

All integer fields are unsigned little-endian values.

| Field | Size | Value |
|---|---:|---|
| `magic` | 4 bytes | `X7Q\0` |
| `version` | 1 byte | `0x02` |
| `header_len` | 4 bytes | Exact byte length of fixed header plus section table |
| `section_count` | 4 bytes | Number of section entries |
| `content_hash` | 32 bytes | SHA-256 over all section bytes in section table order |
| `header_hash` | 32 bytes | SHA-256 over the header with this field zeroed |

The fixed header length is 77 bytes.

## Section Entry

Each section entry is 10 bytes.

| Field | Size | Meaning |
|---|---:|---|
| `type` | 1 byte | Application-defined payload type |
| `offset` | 4 bytes | Byte offset from start of file |
| `length` | 4 bytes | Payload byte length |
| `flags` | 1 byte | Sandboxed payload metadata flags; metadata only, never execution permission |

## Validation Rules

A parser must reject:

- truncated fixed headers
- invalid magic
- versions other than `0x02`
- `header_len < 77`
- section table arithmetic overflow
- `header_len != 77 + section_count * 10`
- files shorter than `header_len`
- header hash mismatch
- section `offset + length` overflow
- section bytes outside the input buffer
- content hash mismatch

No partial acceptance is allowed. The parser returns metadata only after all structural and hash checks pass.

## Security Model

- Payload bytes are never executed.
- Payload metadata flags do not grant runtime capabilities.
- Parsing is deterministic for identical byte input.
- The parser reads from one immutable byte slice to avoid TOCTOU inconsistencies.
- Malformed input fails closed through typed errors.

