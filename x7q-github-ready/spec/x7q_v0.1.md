# x7q v0.1 Binary Container Specification

Repository reference: https://github.com/Umutburakrukcan-77

## Scope

x7q v0.1 is a minimal deterministic binary container format. The v0.1 parser validates container metadata and section byte ranges. It does not execute payloads, decrypt content, or verify signatures.

## Byte Order

All multi-byte integer fields are unsigned little-endian values.

## Header

| Field | Size | Value |
|---|---:|---|
| `magic` | 4 bytes | `58 37 51 00`, the bytes `X7Q\0` |
| `version` | 1 byte | `0x01` |
| `header_len` | 4 bytes | Exact byte length of the fixed header plus section table |
| `section_count` | 4 bytes | Number of section entries |

The fixed header length is 13 bytes.

## Section Entry

Each section table entry is 9 bytes.

| Field | Size | Meaning |
|---|---:|---|
| `type` | 1 byte | Application-defined section type |
| `offset` | 4 bytes | Byte offset from the start of the file |
| `length` | 4 bytes | Section length in bytes |

## Validation Rules

The parser must reject:

- input shorter than 13 bytes
- invalid magic
- unsupported version
- `header_len` smaller than 13
- section table size arithmetic overflow
- `header_len` that does not equal `13 + section_count * 9`
- input shorter than the declared header length
- any section whose `offset + length` overflows `u32`
- any section whose end offset exceeds the file length
- any future header fields in v0.1

All malformed input fails closed. A parser must never read past the end of the provided byte slice.

## Versioning

This document defines only version `0x01`. Version `0x01` has an exact header layout. If a file declares extra header bytes, a v0.1 parser rejects it instead of attempting to interpret future fields.

