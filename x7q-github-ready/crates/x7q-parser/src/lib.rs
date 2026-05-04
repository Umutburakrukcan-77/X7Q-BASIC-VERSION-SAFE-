#![forbid(unsafe_code)]
#![doc = "Deterministic fail-closed parser for x7q v0.1 containers."]

use std::error::Error as StdError;
use std::fmt;

use x7q_format::{Container, FIXED_HEADER_LEN, MAGIC, SECTION_ENTRY_LEN, Section, VERSION_V1};

/// Parser result type.
pub type Result<T> = std::result::Result<T, ParseError>;

/// Explicit parser failures for malformed or unsupported x7q input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Input ended before the fixed header could be read.
    TruncatedHeader {
        /// Required byte count.
        needed: usize,
        /// Available byte count.
        available: usize,
    },
    /// The magic bytes did not match `X7Q\\0`.
    InvalidMagic,
    /// The version byte is not supported by this parser.
    UnsupportedVersion(u8),
    /// The declared header length is smaller than the fixed header.
    HeaderLengthTooSmall {
        /// Declared header length.
        declared: u32,
        /// Minimum accepted header length.
        minimum: usize,
    },
    /// The section table byte size overflowed platform limits.
    SectionTableOverflow,
    /// The declared header length does not match the exact v0.1 layout.
    UnknownMandatoryFields {
        /// Declared header length.
        declared: u32,
        /// Expected v0.1 header length.
        expected: usize,
    },
    /// Input ended before the declared header length.
    TruncatedSectionTable {
        /// Required byte count.
        needed: usize,
        /// Available byte count.
        available: usize,
    },
    /// A section range overflowed while calculating `offset + length`.
    SectionBoundsOverflow {
        /// Section index in file order.
        index: usize,
        /// Declared offset.
        offset: u32,
        /// Declared length.
        length: u32,
    },
    /// A section range extends past the end of the input buffer.
    SectionOutOfBounds {
        /// Section index in file order.
        index: usize,
        /// Declared offset.
        offset: u32,
        /// Declared length.
        length: u32,
        /// Total input length.
        file_len: usize,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader { needed, available } => {
                write!(
                    f,
                    "truncated header: need {needed} bytes, found {available}"
                )
            }
            Self::InvalidMagic => write!(f, "invalid magic"),
            Self::UnsupportedVersion(version) => write!(f, "unsupported version: 0x{version:02x}"),
            Self::HeaderLengthTooSmall { declared, minimum } => write!(
                f,
                "header length too small: declared {declared}, minimum {minimum}"
            ),
            Self::SectionTableOverflow => write!(f, "section table size overflow"),
            Self::UnknownMandatoryFields { declared, expected } => write!(
                f,
                "unsupported v0.1 header length: declared {declared}, expected {expected}"
            ),
            Self::TruncatedSectionTable { needed, available } => write!(
                f,
                "truncated section table: need {needed} bytes, found {available}"
            ),
            Self::SectionBoundsOverflow {
                index,
                offset,
                length,
            } => write!(
                f,
                "section {index} range overflows: offset {offset}, length {length}"
            ),
            Self::SectionOutOfBounds {
                index,
                offset,
                length,
                file_len,
            } => write!(
                f,
                "section {index} exceeds file size: offset {offset}, length {length}, file size {file_len}"
            ),
        }
    }
}

impl StdError for ParseError {}

/// Parses x7q v0.1 container metadata from a byte slice.
///
/// The parser validates all declared ranges before returning metadata and never reads past
/// `input`.
pub fn parse(input: &[u8]) -> Result<Container> {
    if input.len() < FIXED_HEADER_LEN {
        return Err(ParseError::TruncatedHeader {
            needed: FIXED_HEADER_LEN,
            available: input.len(),
        });
    }

    let magic = read_array::<4>(input, 0).ok_or(ParseError::TruncatedHeader {
        needed: FIXED_HEADER_LEN,
        available: input.len(),
    })?;
    if magic != MAGIC {
        return Err(ParseError::InvalidMagic);
    }

    let version = input[4];
    if version != VERSION_V1 {
        return Err(ParseError::UnsupportedVersion(version));
    }

    let header_len = read_u32_le(input, 5).ok_or(ParseError::TruncatedHeader {
        needed: FIXED_HEADER_LEN,
        available: input.len(),
    })?;
    let section_count = read_u32_le(input, 9).ok_or(ParseError::TruncatedHeader {
        needed: FIXED_HEADER_LEN,
        available: input.len(),
    })?;

    let header_len_usize =
        usize::try_from(header_len).map_err(|_| ParseError::SectionTableOverflow)?;
    if header_len_usize < FIXED_HEADER_LEN {
        return Err(ParseError::HeaderLengthTooSmall {
            declared: header_len,
            minimum: FIXED_HEADER_LEN,
        });
    }

    let section_count_usize =
        usize::try_from(section_count).map_err(|_| ParseError::SectionTableOverflow)?;
    let section_table_len = section_count_usize
        .checked_mul(SECTION_ENTRY_LEN)
        .ok_or(ParseError::SectionTableOverflow)?;
    let expected_header_len = FIXED_HEADER_LEN
        .checked_add(section_table_len)
        .ok_or(ParseError::SectionTableOverflow)?;
    if expected_header_len > u32::MAX as usize {
        return Err(ParseError::SectionTableOverflow);
    }

    if header_len_usize != expected_header_len {
        return Err(ParseError::UnknownMandatoryFields {
            declared: header_len,
            expected: expected_header_len,
        });
    }

    if input.len() < expected_header_len {
        return Err(ParseError::TruncatedSectionTable {
            needed: expected_header_len,
            available: input.len(),
        });
    }

    let mut sections = Vec::with_capacity(section_count_usize);
    for index in 0..section_count_usize {
        let base = FIXED_HEADER_LEN
            .checked_add(
                index
                    .checked_mul(SECTION_ENTRY_LEN)
                    .ok_or(ParseError::SectionTableOverflow)?,
            )
            .ok_or(ParseError::SectionTableOverflow)?;
        let section_type = input[base];
        let offset = read_u32_le(input, base + 1).ok_or(ParseError::TruncatedSectionTable {
            needed: expected_header_len,
            available: input.len(),
        })?;
        let length = read_u32_le(input, base + 5).ok_or(ParseError::TruncatedSectionTable {
            needed: expected_header_len,
            available: input.len(),
        })?;

        let end = offset
            .checked_add(length)
            .ok_or(ParseError::SectionBoundsOverflow {
                index,
                offset,
                length,
            })?;
        let end_usize = usize::try_from(end).map_err(|_| ParseError::SectionBoundsOverflow {
            index,
            offset,
            length,
        })?;
        if end_usize > input.len() {
            return Err(ParseError::SectionOutOfBounds {
                index,
                offset,
                length,
                file_len: input.len(),
            });
        }

        sections.push(Section::new(section_type, offset, length));
    }

    Ok(Container::new(version, header_len, sections))
}

fn read_array<const N: usize>(input: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    let bytes = input.get(offset..end)?;
    bytes.try_into().ok()
}

fn read_u32_le(input: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(read_array::<4>(input, offset)?))
}

#[cfg(test)]
mod tests {
    use super::{ParseError, parse};
    use x7q_format::FIXED_HEADER_LEN;

    fn minimal_container() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"X7Q\0");
        bytes.push(0x01);
        bytes.extend_from_slice(&(FIXED_HEADER_LEN as u32).to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes
    }

    fn one_section_container(offset: u32, length: u32, payload_len: usize) -> Vec<u8> {
        let header_len = FIXED_HEADER_LEN as u32 + 9;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"X7Q\0");
        bytes.push(0x01);
        bytes.extend_from_slice(&header_len.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.push(0x10);
        bytes.extend_from_slice(&offset.to_le_bytes());
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.resize(header_len as usize + payload_len, 0xaa);
        bytes
    }

    #[test]
    fn parses_valid_minimal_container() {
        let parsed = parse(&minimal_container()).expect("minimal container should parse");

        assert_eq!(parsed.version(), 0x01);
        assert_eq!(parsed.header_len(), FIXED_HEADER_LEN as u32);
        assert!(parsed.sections().is_empty());
    }

    #[test]
    fn rejects_invalid_magic() {
        let mut bytes = minimal_container();
        bytes[0] = b'Y';

        assert_eq!(parse(&bytes), Err(ParseError::InvalidMagic));
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut bytes = minimal_container();
        bytes[4] = 0x02;

        assert_eq!(parse(&bytes), Err(ParseError::UnsupportedVersion(0x02)));
    }

    #[test]
    fn rejects_truncated_header_and_empty_input() {
        assert_eq!(
            parse(&[]),
            Err(ParseError::TruncatedHeader {
                needed: FIXED_HEADER_LEN,
                available: 0
            })
        );
        assert_eq!(
            parse(&minimal_container()[..12]),
            Err(ParseError::TruncatedHeader {
                needed: FIXED_HEADER_LEN,
                available: 12
            })
        );
    }

    #[test]
    fn rejects_section_table_overflow() {
        let mut bytes = minimal_container();
        bytes[5..9].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[9..13].copy_from_slice(&u32::MAX.to_le_bytes());

        assert_eq!(parse(&bytes), Err(ParseError::SectionTableOverflow));
    }

    #[test]
    fn rejects_header_len_smaller_than_fixed_header() {
        let mut bytes = minimal_container();
        bytes[5..9].copy_from_slice(&12_u32.to_le_bytes());

        assert_eq!(
            parse(&bytes),
            Err(ParseError::HeaderLengthTooSmall {
                declared: 12,
                minimum: FIXED_HEADER_LEN
            })
        );
    }

    #[test]
    fn rejects_future_header_fields() {
        let mut bytes = minimal_container();
        bytes[5..9].copy_from_slice(&14_u32.to_le_bytes());
        bytes.push(0);

        assert_eq!(
            parse(&bytes),
            Err(ParseError::UnknownMandatoryFields {
                declared: 14,
                expected: FIXED_HEADER_LEN
            })
        );
    }

    #[test]
    fn rejects_truncated_section_table() {
        let header_len = FIXED_HEADER_LEN as u32 + 9;
        let mut bytes = minimal_container();
        bytes[5..9].copy_from_slice(&header_len.to_le_bytes());
        bytes[9..13].copy_from_slice(&1_u32.to_le_bytes());

        assert_eq!(
            parse(&bytes),
            Err(ParseError::TruncatedSectionTable {
                needed: header_len as usize,
                available: FIXED_HEADER_LEN
            })
        );
    }

    #[test]
    fn rejects_section_bounds_overflow() {
        let bytes = one_section_container(u32::MAX, 1, 0);

        assert_eq!(
            parse(&bytes),
            Err(ParseError::SectionBoundsOverflow {
                index: 0,
                offset: u32::MAX,
                length: 1
            })
        );
    }

    #[test]
    fn rejects_section_out_of_bounds() {
        let bytes = one_section_container(22, 1, 0);

        assert_eq!(
            parse(&bytes),
            Err(ParseError::SectionOutOfBounds {
                index: 0,
                offset: 22,
                length: 1,
                file_len: 22
            })
        );
    }

    #[test]
    fn parses_valid_section_bounds() {
        let bytes = one_section_container(22, 1, 1);
        let parsed = parse(&bytes).expect("section should be inside file bounds");

        assert_eq!(parsed.sections().len(), 1);
        assert_eq!(parsed.sections()[0].section_type(), 0x10);
        assert_eq!(parsed.sections()[0].offset(), 22);
        assert_eq!(parsed.sections()[0].length(), 1);
    }
}
