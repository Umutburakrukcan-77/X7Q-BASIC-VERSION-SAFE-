#![forbid(unsafe_code)]
#![doc = "Secure-by-design x7q-secure v1.0 container parser and builder."]

use std::error::Error as StdError;
use std::fmt;

use aes_gcm::aead::{Aead, KeyInit, OsRng, rand_core::RngCore};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;

/// Fixed x7q magic prefix.
pub const MAGIC: [u8; 4] = *b"X7Q\0";
/// x7q-secure v1.0 schema version byte.
pub const VERSION: u8 = 0x02;
/// x7q-secure v2.0 schema version byte.
pub const VERSION_V2: u8 = 0x03;
/// SHA-256 digest size.
pub const HASH_LEN: usize = 32;
/// Fixed v1.0 header length before the section table.
pub const FIXED_HEADER_LEN: usize = 77;
/// v1.0 section entry byte length.
pub const SECTION_ENTRY_LEN: usize = 10;
/// v2 canonical text payload section.
pub const V2_SECTION_CANONICAL_TEXT: u8 = 0x01;
/// v2 encrypted canonical text payload section.
pub const V2_SECTION_ENCRYPTED_TEXT: u8 = 0x02;
/// v2 execution boundary policy metadata section.
pub const V2_SECTION_POLICY: u8 = 0xf0;
/// v2 transformation provenance metadata section.
pub const V2_SECTION_PROVENANCE: u8 = 0xf1;
/// v2 canonical content hash metadata section.
pub const V2_SECTION_CANONICAL_HASH: u8 = 0xf2;
/// v2 encryption metadata section.
pub const V2_SECTION_CRYPTO: u8 = 0xf3;
const CONTENT_HASH_OFFSET: usize = 13;
const HEADER_HASH_OFFSET: usize = 45;
const ARGON2_SALT_LEN: usize = 16;
const AES_GCM_NONCE_LEN: usize = 12;

/// Parser result type.
pub type ParseResult<T> = std::result::Result<T, ParseError>;
/// Builder result type.
pub type BuildResult<T> = std::result::Result<T, BuildError>;

/// Parsed x7q-secure v1.0 container metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureContainer {
    version: u8,
    header_len: u32,
    content_hash: [u8; HASH_LEN],
    header_hash: [u8; HASH_LEN],
    sections: Vec<SecureSection>,
}

impl SecureContainer {
    fn new(
        version: u8,
        header_len: u32,
        content_hash: [u8; HASH_LEN],
        header_hash: [u8; HASH_LEN],
        sections: Vec<SecureSection>,
    ) -> Self {
        Self {
            version,
            header_len,
            content_hash,
            header_hash,
            sections,
        }
    }

    /// Returns the parsed schema version.
    #[must_use]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Returns the declared header length.
    #[must_use]
    pub fn header_len(&self) -> u32 {
        self.header_len
    }

    /// Returns the verified content hash.
    #[must_use]
    pub fn content_hash(&self) -> &[u8; HASH_LEN] {
        &self.content_hash
    }

    /// Returns the verified header hash.
    #[must_use]
    pub fn header_hash(&self) -> &[u8; HASH_LEN] {
        &self.header_hash
    }

    /// Returns the parsed section table in file order.
    #[must_use]
    pub fn sections(&self) -> &[SecureSection] {
        &self.sections
    }
}

/// Parsed x7q-secure section metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureSection {
    section_type: u8,
    offset: u32,
    length: u32,
    flags: u8,
}

impl SecureSection {
    fn new(section_type: u8, offset: u32, length: u32, flags: u8) -> Self {
        Self {
            section_type,
            offset,
            length,
            flags,
        }
    }

    /// Returns the section type.
    #[must_use]
    pub fn section_type(&self) -> u8 {
        self.section_type
    }

    /// Returns the byte offset from the start of the file.
    #[must_use]
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// Returns the section byte length.
    #[must_use]
    pub fn length(&self) -> u32 {
        self.length
    }

    /// Returns section metadata flags.
    #[must_use]
    pub fn flags(&self) -> u8 {
        self.flags
    }
}

/// Section payload used by the deterministic builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildSection {
    section_type: u8,
    flags: u8,
    bytes: Vec<u8>,
}

impl BuildSection {
    /// Creates a section payload for `build_container`.
    #[must_use]
    pub fn new(section_type: u8, flags: u8, bytes: Vec<u8>) -> Self {
        Self {
            section_type,
            flags,
            bytes,
        }
    }
}

/// Explicit parser failures for malformed or unverifiable x7q-secure input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Input ended before the fixed header could be read.
    TruncatedHeader { needed: usize, available: usize },
    /// The magic bytes did not match `X7Q\\0`.
    InvalidMagic,
    /// The version byte is not the x7q-secure v1.0 version.
    UnsupportedVersion(u8),
    /// The declared header length is smaller than the fixed v1.0 header.
    HeaderLengthTooSmall { declared: u32, minimum: usize },
    /// Section table size arithmetic overflowed.
    SectionTableOverflow,
    /// The header length does not exactly match the v1.0 schema.
    InvalidHeaderLength { declared: u32, expected: usize },
    /// Input ended before the declared header length.
    TruncatedSectionTable { needed: usize, available: usize },
    /// Header hash did not match the canonical v1.0 header bytes.
    HeaderHashMismatch,
    /// Section `offset + length` overflowed.
    SectionBoundsOverflow {
        index: usize,
        offset: u32,
        length: u32,
    },
    /// Section bytes extend past the input length.
    SectionOutOfBounds {
        index: usize,
        offset: u32,
        length: u32,
        file_len: usize,
    },
    /// Content hash did not match the concatenated section bytes.
    ContentHashMismatch,
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
            Self::InvalidHeaderLength { declared, expected } => write!(
                f,
                "invalid v1.0 header length: declared {declared}, expected {expected}"
            ),
            Self::TruncatedSectionTable { needed, available } => write!(
                f,
                "truncated section table: need {needed} bytes, found {available}"
            ),
            Self::HeaderHashMismatch => write!(f, "header hash mismatch"),
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
            Self::ContentHashMismatch => write!(f, "content hash mismatch"),
        }
    }
}

impl StdError for ParseError {}

/// Builder failures for inputs that cannot be represented in x7q-secure v1.0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// The section table or payload layout cannot fit in v1.0 `u32` fields.
    SizeOverflow,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SizeOverflow => write!(f, "container size exceeds x7q-secure v1.0 limits"),
        }
    }
}

impl StdError for BuildError {}

/// Build-time validation failures for x7q-secure v2.0 strict text containers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2Error {
    /// Input was not accepted by the strict text profile.
    StrictTextViolation(String),
    /// PDF input was not accepted by the built-in basic extractor.
    PdfExtraction(String),
    /// The v2 container could not be represented.
    Build(BuildError),
    /// The v2 container failed structural or hash verification.
    Parse(ParseError),
    /// A required v2 metadata section was missing.
    MissingSection(u8),
    /// A required v2 metadata section was duplicated.
    DuplicateSection(u8),
    /// Metadata bytes were not valid UTF-8.
    InvalidMetadataUtf8,
    /// The canonical hash section did not match the canonical payload.
    CanonicalHashMismatch,
    /// The v2 policy did not contain the required passive-only contract.
    PolicyViolation(String),
    /// v2 section layout violated the strict container profile.
    SectionLayout(String),
    /// Encrypted payload could not be opened.
    Crypto(String),
    /// An encrypted v2 file was opened without a key.
    MissingKey,
}

impl fmt::Display for V2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StrictTextViolation(message) => write!(f, "strict text violation: {message}"),
            Self::PdfExtraction(message) => write!(f, "PDF extraction failed: {message}"),
            Self::Build(err) => write!(f, "{err}"),
            Self::Parse(err) => write!(f, "{err}"),
            Self::MissingSection(section_type) => {
                write!(f, "missing required v2 section: 0x{section_type:02x}")
            }
            Self::DuplicateSection(section_type) => {
                write!(f, "duplicate v2 section: 0x{section_type:02x}")
            }
            Self::InvalidMetadataUtf8 => write!(f, "v2 metadata is not valid UTF-8"),
            Self::CanonicalHashMismatch => write!(f, "canonical hash mismatch"),
            Self::PolicyViolation(message) => write!(f, "policy violation: {message}"),
            Self::SectionLayout(message) => write!(f, "section layout violation: {message}"),
            Self::Crypto(message) => write!(f, "crypto error: {message}"),
            Self::MissingKey => write!(f, "this x7q file is encrypted; provide a key"),
        }
    }
}

impl StdError for V2Error {}

impl From<BuildError> for V2Error {
    fn from(value: BuildError) -> Self {
        Self::Build(value)
    }
}

impl From<ParseError> for V2Error {
    fn from(value: ParseError) -> Self {
        Self::Parse(value)
    }
}

/// Build options for x7q-secure v2.0 strict prompt/text containers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2BuildOptions {
    source_format: String,
    source_name: String,
    extractor: String,
}

impl V2BuildOptions {
    /// Creates v2 build metadata.
    #[must_use]
    pub fn new(source_format: impl Into<String>, source_name: impl Into<String>) -> Self {
        Self {
            source_format: source_format.into(),
            source_name: source_name.into(),
            extractor: "x7q-secure-v2-strict-text".to_owned(),
        }
    }

    /// Overrides the provenance extractor identifier.
    #[must_use]
    pub fn with_extractor(mut self, extractor: impl Into<String>) -> Self {
        self.extractor = extractor.into();
        self
    }
}

/// Verified v2 container view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2Container {
    container: SecureContainer,
    canonical_text: String,
    canonical_hash: [u8; HASH_LEN],
    policy: String,
    provenance: String,
}

impl V2Container {
    /// Returns the structurally verified low-level container.
    #[must_use]
    pub fn container(&self) -> &SecureContainer {
        &self.container
    }

    /// Returns the canonical strict text payload.
    #[must_use]
    pub fn canonical_text(&self) -> &str {
        &self.canonical_text
    }

    /// Returns the canonical content hash.
    #[must_use]
    pub fn canonical_hash(&self) -> &[u8; HASH_LEN] {
        &self.canonical_hash
    }

    /// Returns the policy contract metadata.
    #[must_use]
    pub fn policy(&self) -> &str {
        &self.policy
    }

    /// Returns the provenance metadata.
    #[must_use]
    pub fn provenance(&self) -> &str {
        &self.provenance
    }
}

/// Parses and verifies an x7q-secure v1.0 container.
///
/// The parser reads from a single immutable byte slice, validates hashes before returning
/// metadata, and rejects every malformed or unverifiable input.
pub fn parse_secure(input: &[u8]) -> ParseResult<SecureContainer> {
    parse_secure_with_version(input, VERSION)
}

/// Parses and verifies an x7q-secure v2.0 container.
pub fn parse_secure_v2(input: &[u8]) -> ParseResult<SecureContainer> {
    parse_secure_with_version(input, VERSION_V2)
}

fn parse_secure_with_version(input: &[u8], expected_version: u8) -> ParseResult<SecureContainer> {
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
    if version != expected_version {
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
    let content_hash =
        read_array::<HASH_LEN>(input, CONTENT_HASH_OFFSET).ok_or(ParseError::TruncatedHeader {
            needed: FIXED_HEADER_LEN,
            available: input.len(),
        })?;
    let header_hash =
        read_array::<HASH_LEN>(input, HEADER_HASH_OFFSET).ok_or(ParseError::TruncatedHeader {
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
        return Err(ParseError::InvalidHeaderLength {
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

    if compute_header_hash(input, expected_header_len)? != header_hash {
        return Err(ParseError::HeaderHashMismatch);
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
        let flags = input[base + 9];

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

        sections.push(SecureSection::new(section_type, offset, length, flags));
    }

    if compute_content_hash(input, &sections)? != content_hash {
        return Err(ParseError::ContentHashMismatch);
    }

    Ok(SecureContainer::new(
        version,
        header_len,
        content_hash,
        header_hash,
        sections,
    ))
}

/// Builds a deterministic x7q-secure v1.0 container from section payloads.
pub fn build_container(sections: &[BuildSection]) -> BuildResult<Vec<u8>> {
    build_container_with_version(VERSION, sections)
}

fn build_container_with_version(version: u8, sections: &[BuildSection]) -> BuildResult<Vec<u8>> {
    let section_table_len = sections
        .len()
        .checked_mul(SECTION_ENTRY_LEN)
        .ok_or(BuildError::SizeOverflow)?;
    let header_len = FIXED_HEADER_LEN
        .checked_add(section_table_len)
        .ok_or(BuildError::SizeOverflow)?;
    let header_len_u32 = u32::try_from(header_len).map_err(|_| BuildError::SizeOverflow)?;

    let payload_len = sections.iter().try_fold(0_usize, |total, section| {
        total
            .checked_add(section.bytes.len())
            .ok_or(BuildError::SizeOverflow)
    })?;
    let total_len = header_len
        .checked_add(payload_len)
        .ok_or(BuildError::SizeOverflow)?;
    if total_len > u32::MAX as usize {
        return Err(BuildError::SizeOverflow);
    }

    let mut bytes = Vec::with_capacity(total_len);
    bytes.extend_from_slice(&MAGIC);
    bytes.push(version);
    bytes.extend_from_slice(&header_len_u32.to_le_bytes());
    bytes.extend_from_slice(
        &u32::try_from(sections.len())
            .map_err(|_| BuildError::SizeOverflow)?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&[0_u8; HASH_LEN]);
    bytes.extend_from_slice(&[0_u8; HASH_LEN]);

    let mut offset = header_len_u32;
    for section in sections {
        let length = u32::try_from(section.bytes.len()).map_err(|_| BuildError::SizeOverflow)?;
        bytes.push(section.section_type);
        bytes.extend_from_slice(&offset.to_le_bytes());
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.push(section.flags);
        offset = offset.checked_add(length).ok_or(BuildError::SizeOverflow)?;
    }

    for section in sections {
        bytes.extend_from_slice(&section.bytes);
    }

    let parsed_sections = parse_sections_without_hashes(&bytes, sections.len())?;
    let content_hash =
        compute_content_hash(&bytes, &parsed_sections).map_err(|_| BuildError::SizeOverflow)?;
    bytes[CONTENT_HASH_OFFSET..CONTENT_HASH_OFFSET + HASH_LEN].copy_from_slice(&content_hash);
    let header_hash =
        compute_header_hash(&bytes, header_len).map_err(|_| BuildError::SizeOverflow)?;
    bytes[HEADER_HASH_OFFSET..HEADER_HASH_OFFSET + HASH_LEN].copy_from_slice(&header_hash);

    Ok(bytes)
}

/// Builds an x7q-secure v2.0 container from strict canonical text.
pub fn build_v2_text_container(
    text: &str,
    options: &V2BuildOptions,
) -> std::result::Result<Vec<u8>, V2Error> {
    build_v2_text_container_with_key(text, options, None)
}

/// Builds an x7q-secure v2.0 container from strict text, optionally encrypted with a key.
pub fn build_v2_text_container_with_key(
    text: &str,
    options: &V2BuildOptions,
    key: Option<&str>,
) -> std::result::Result<Vec<u8>, V2Error> {
    let canonical_text = canonicalize_strict_text(text)?;
    let canonical_hash = sha256(canonical_text.as_bytes());
    let policy = build_v2_policy(key.is_some());
    let provenance = build_v2_provenance(options, text.len(), canonical_text.len());
    let mut sections = Vec::new();
    if let Some(key) = key {
        let encrypted = encrypt_text(canonical_text.as_bytes(), key)?;
        sections.push(BuildSection::new(
            V2_SECTION_ENCRYPTED_TEXT,
            0x01,
            encrypted.ciphertext,
        ));
        sections.push(BuildSection::new(
            V2_SECTION_CRYPTO,
            0x00,
            encrypted.metadata.into_bytes(),
        ));
    } else {
        sections.push(BuildSection::new(
            V2_SECTION_CANONICAL_TEXT,
            0x00,
            canonical_text.into_bytes(),
        ));
    }
    sections.push(BuildSection::new(
        V2_SECTION_POLICY,
        0x00,
        policy.into_bytes(),
    ));
    sections.push(BuildSection::new(
        V2_SECTION_PROVENANCE,
        0x00,
        provenance.into_bytes(),
    ));
    sections.push(BuildSection::new(
        V2_SECTION_CANONICAL_HASH,
        0x00,
        canonical_hash.to_vec(),
    ));
    Ok(build_container_with_version(VERSION_V2, &sections)?)
}

/// Parses and validates the x7q-secure v2.0 strict text contract.
pub fn validate_v2(input: &[u8]) -> std::result::Result<V2Container, V2Error> {
    validate_v2_with_key(input, None)
}

/// Parses and validates the x7q-secure v2.0 strict text contract, decrypting when needed.
pub fn validate_v2_with_key(
    input: &[u8],
    key: Option<&str>,
) -> std::result::Result<V2Container, V2Error> {
    let container = parse_secure_v2(input)?;
    validate_v2_section_layout(&container)?;
    let policy_bytes = single_section(input, &container, V2_SECTION_POLICY)?;
    let provenance_bytes = single_section(input, &container, V2_SECTION_PROVENANCE)?;
    let canonical_hash_bytes = single_section(input, &container, V2_SECTION_CANONICAL_HASH)?;

    if canonical_hash_bytes.len() != HASH_LEN {
        return Err(V2Error::CanonicalHashMismatch);
    }
    let canonical_hash: [u8; HASH_LEN] = canonical_hash_bytes
        .try_into()
        .map_err(|_| V2Error::CanonicalHashMismatch)?;

    let policy = std::str::from_utf8(policy_bytes).map_err(|_| V2Error::InvalidMetadataUtf8)?;
    let provenance =
        std::str::from_utf8(provenance_bytes).map_err(|_| V2Error::InvalidMetadataUtf8)?;
    let encrypted = has_section(&container, V2_SECTION_ENCRYPTED_TEXT);
    let canonical_text = if encrypted {
        let key = key.ok_or(V2Error::MissingKey)?;
        let ciphertext = single_section(input, &container, V2_SECTION_ENCRYPTED_TEXT)?;
        let crypto = single_section(input, &container, V2_SECTION_CRYPTO)?;
        decrypt_text(ciphertext, crypto, key)?
    } else {
        let canonical_text_bytes = single_section(input, &container, V2_SECTION_CANONICAL_TEXT)?;
        std::str::from_utf8(canonical_text_bytes)
            .map_err(|_| V2Error::InvalidMetadataUtf8)?
            .to_owned()
    };

    let recanonicalized = canonicalize_strict_text(&canonical_text)?;
    if recanonicalized != canonical_text {
        return Err(V2Error::StrictTextViolation(
            "payload is not in canonical form".to_owned(),
        ));
    }
    if sha256(canonical_text.as_bytes()) != canonical_hash {
        return Err(V2Error::CanonicalHashMismatch);
    }
    validate_policy(policy, encrypted)?;

    Ok(V2Container {
        container,
        canonical_text,
        canonical_hash,
        policy: policy.to_owned(),
        provenance: provenance.to_owned(),
    })
}

fn validate_v2_section_layout(container: &SecureContainer) -> std::result::Result<(), V2Error> {
    let mut ranges = Vec::with_capacity(container.sections().len());
    for section in container.sections() {
        if section.offset() < container.header_len() {
            return Err(V2Error::SectionLayout(format!(
                "section 0x{:02x} starts before header end",
                section.section_type()
            )));
        }
        let end = section
            .offset()
            .checked_add(section.length())
            .ok_or_else(|| V2Error::SectionLayout("section range overflow".to_owned()))?;
        ranges.push((section.offset(), end, section.section_type()));
    }
    ranges.sort_by_key(|range| range.0);
    for pair in ranges.windows(2) {
        let current = pair[0];
        let next = pair[1];
        if current.1 > next.0 {
            return Err(V2Error::SectionLayout(format!(
                "section 0x{:02x} overlaps section 0x{:02x}",
                current.2, next.2
            )));
        }
    }
    Ok(())
}

/// Converts a basic text PDF into an x7q-secure v2.0 container.
///
/// This is intentionally a conservative extractor, not a full PDF engine. It accepts PDFs with
/// literal text strings used by `Tj`/`TJ` operators and records that extractor in provenance.
pub fn build_v2_from_pdf(
    pdf_bytes: &[u8],
    source_name: &str,
) -> std::result::Result<Vec<u8>, V2Error> {
    build_v2_from_pdf_with_key(pdf_bytes, source_name, None)
}

/// Converts a PDF into an x7q-secure v2.0 container, optionally encrypted with a key.
pub fn build_v2_from_pdf_with_key(
    pdf_bytes: &[u8],
    source_name: &str,
    key: Option<&str>,
) -> std::result::Result<Vec<u8>, V2Error> {
    let extracted = extract_pdf_text(pdf_bytes)?;
    let options = V2BuildOptions::new("pdf", source_name).with_extractor("x7q-basic-pdf-text-v1");
    build_v2_text_container_with_key(&extracted, &options, key)
}

/// Canonicalizes text under the v2 strict text profile.
pub fn canonicalize_strict_text(input: &str) -> std::result::Result<String, V2Error> {
    let mut text = input.replace("\r\n", "\n").replace('\r', "\n");
    if let Some(stripped) = text.strip_prefix('\u{feff}') {
        text = stripped.to_owned();
    }

    let mut out = String::with_capacity(text.len());
    for (index, ch) in text.chars().enumerate() {
        if matches!(
            ch,
            '\u{0000}'..='\u{0008}'
                | '\u{000b}'..='\u{000c}'
                | '\u{000e}'..='\u{001f}'
                | '\u{007f}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
                | '\u{00ad}'
        ) {
            return Err(V2Error::StrictTextViolation(format!(
                "disallowed character U+{:04X} at character {index}",
                ch as u32
            )));
        }
        out.push(ch);
    }

    let mut normalized = String::with_capacity(out.len());
    for line in out.lines() {
        normalized.push_str(line.trim_end_matches([' ', '\t']));
        normalized.push('\n');
    }
    if !out.ends_with('\n') && normalized.ends_with('\n') {
        normalized.pop();
    }

    scan_executable_patterns(&normalized)?;
    Ok(normalized)
}

fn single_section<'a>(
    input: &'a [u8],
    container: &SecureContainer,
    section_type: u8,
) -> std::result::Result<&'a [u8], V2Error> {
    let mut found = None;
    for section in container.sections() {
        if section.section_type() == section_type {
            if found.is_some() {
                return Err(V2Error::DuplicateSection(section_type));
            }
            let start = usize::try_from(section.offset()).map_err(|_| {
                V2Error::Parse(ParseError::SectionOutOfBounds {
                    index: 0,
                    offset: section.offset(),
                    length: section.length(),
                    file_len: input.len(),
                })
            })?;
            let len = usize::try_from(section.length()).map_err(|_| {
                V2Error::Parse(ParseError::SectionOutOfBounds {
                    index: 0,
                    offset: section.offset(),
                    length: section.length(),
                    file_len: input.len(),
                })
            })?;
            let end = start.checked_add(len).ok_or(V2Error::Parse(
                ParseError::SectionBoundsOverflow {
                    index: 0,
                    offset: section.offset(),
                    length: section.length(),
                },
            ))?;
            found = Some(input.get(start..end).ok_or(V2Error::Parse(
                ParseError::SectionOutOfBounds {
                    index: 0,
                    offset: section.offset(),
                    length: section.length(),
                    file_len: input.len(),
                },
            ))?);
        }
    }
    found.ok_or(V2Error::MissingSection(section_type))
}

fn has_section(container: &SecureContainer, section_type: u8) -> bool {
    container
        .sections()
        .iter()
        .any(|section| section.section_type() == section_type)
}

fn scan_executable_patterns(input: &str) -> std::result::Result<(), V2Error> {
    const PATTERNS: &[&str] = &[
        "#!",
        "<script",
        "</script",
        "javascript:",
        "data:text/html",
        "powershell",
        "cmd.exe",
        "/bin/sh",
        "eval(",
        "exec(",
        "system(",
        "import os",
        "subprocess",
        "curl ",
        "wget ",
    ];

    let lower = input.to_ascii_lowercase();
    for pattern in PATTERNS {
        if lower.contains(pattern) {
            return Err(V2Error::StrictTextViolation(format!(
                "blocked executable pattern `{pattern}`"
            )));
        }
    }

    let bytes = input.as_bytes();
    for magic in [
        b"MZ".as_slice(),
        b"\x7fELF".as_slice(),
        b"PK\x03\x04".as_slice(),
    ] {
        if bytes.windows(magic.len()).any(|window| window == magic) {
            return Err(V2Error::StrictTextViolation(
                "blocked executable magic bytes".to_owned(),
            ));
        }
    }

    Ok(())
}

fn build_v2_policy(encrypted: bool) -> String {
    [
        "schema=x7q-secure-v2-policy",
        "execution_policy=passive-only",
        "tool_execution=deny",
        "external_fetch=deny",
        "dynamic_loading=deny",
        "strict_text_profile=enabled",
        if encrypted {
            "payload_encryption=aes-256-gcm"
        } else {
            "payload_encryption=none"
        },
    ]
    .join("\n")
}

fn validate_policy(policy: &str, encrypted: bool) -> std::result::Result<(), V2Error> {
    for required in [
        "execution_policy=passive-only",
        "tool_execution=deny",
        "external_fetch=deny",
        "dynamic_loading=deny",
        "strict_text_profile=enabled",
    ] {
        if !policy.lines().any(|line| line.trim() == required) {
            return Err(V2Error::PolicyViolation(format!(
                "missing required policy `{required}`"
            )));
        }
    }
    let encryption_policy = if encrypted {
        "payload_encryption=aes-256-gcm"
    } else {
        "payload_encryption=none"
    };
    if !policy.lines().any(|line| line.trim() == encryption_policy) {
        return Err(V2Error::PolicyViolation(format!(
            "missing required policy `{encryption_policy}`"
        )));
    }
    Ok(())
}

fn build_v2_provenance(
    options: &V2BuildOptions,
    source_len: usize,
    canonical_len: usize,
) -> String {
    [
        "schema=x7q-secure-v2-provenance".to_owned(),
        format!("source_format={}", metadata_value(&options.source_format)),
        format!("source_name={}", metadata_value(&options.source_name)),
        format!("extractor={}", metadata_value(&options.extractor)),
        "canonicalization=line-endings-lf;strip-bom;trim-trailing-space;strict-character-denylist;pattern-scan".to_owned(),
        format!("source_bytes={source_len}"),
        format!("canonical_bytes={canonical_len}"),
    ]
    .join("\n")
}

fn metadata_value(input: &str) -> String {
    input
        .chars()
        .filter(|ch| !matches!(ch, '\n' | '\r' | '\0'))
        .collect()
}

struct EncryptedPayload {
    ciphertext: Vec<u8>,
    metadata: String,
}

fn encrypt_text(plaintext: &[u8], key: &str) -> std::result::Result<EncryptedPayload, V2Error> {
    if key.is_empty() {
        return Err(V2Error::Crypto("encryption key cannot be empty".to_owned()));
    }
    let mut salt = [0_u8; ARGON2_SALT_LEN];
    let mut nonce = [0_u8; AES_GCM_NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let key_bytes = derive_key(key, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|_| V2Error::Crypto("invalid AES key length".to_owned()))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| V2Error::Crypto("AES-GCM encryption failed".to_owned()))?;
    let metadata = [
        "schema=x7q-secure-v2-crypto".to_owned(),
        "algorithm=AES-256-GCM".to_owned(),
        "kdf=Argon2id".to_owned(),
        format!("salt={}", hex_lower(&salt)),
        format!("nonce={}", hex_lower(&nonce)),
    ]
    .join("\n");
    Ok(EncryptedPayload {
        ciphertext,
        metadata,
    })
}

fn decrypt_text(
    ciphertext: &[u8],
    crypto: &[u8],
    key: &str,
) -> std::result::Result<String, V2Error> {
    if key.is_empty() {
        return Err(V2Error::Crypto("decryption key cannot be empty".to_owned()));
    }
    let metadata = std::str::from_utf8(crypto).map_err(|_| V2Error::InvalidMetadataUtf8)?;
    require_metadata(metadata, "algorithm", "AES-256-GCM")?;
    require_metadata(metadata, "kdf", "Argon2id")?;
    let salt = metadata_field(metadata, "salt")
        .ok_or_else(|| V2Error::Crypto("missing encryption salt in crypto metadata".to_owned()))?;
    let nonce = metadata_field(metadata, "nonce")
        .ok_or_else(|| V2Error::Crypto("missing encryption nonce in crypto metadata".to_owned()))?;
    let salt = decode_hex_fixed::<ARGON2_SALT_LEN>(salt)?;
    let nonce = decode_hex_fixed::<AES_GCM_NONCE_LEN>(nonce)?;
    let key_bytes = derive_key(key, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|_| V2Error::Crypto("invalid AES key length".to_owned()))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext)
        .map_err(|_| V2Error::Crypto("decryption failed: wrong key or tampered file".to_owned()))?;
    String::from_utf8(plaintext)
        .map_err(|_| V2Error::Crypto("decrypted text is not UTF-8".to_owned()))
}

fn derive_key(key: &str, salt: &[u8; ARGON2_SALT_LEN]) -> std::result::Result<[u8; 32], V2Error> {
    let mut out = [0_u8; 32];
    Argon2::default()
        .hash_password_into(key.as_bytes(), salt, &mut out)
        .map_err(|err| V2Error::Crypto(format!("Argon2 key derivation failed: {err}")))?;
    Ok(out)
}

fn metadata_field<'a>(metadata: &'a str, key: &str) -> Option<&'a str> {
    metadata.lines().find_map(|line| {
        let (name, value) = line.split_once('=')?;
        (name.trim() == key).then_some(value.trim())
    })
}

fn require_metadata(metadata: &str, key: &str, expected: &str) -> std::result::Result<(), V2Error> {
    match metadata_field(metadata, key) {
        Some(value) if value == expected => Ok(()),
        Some(value) => Err(V2Error::Crypto(format!(
            "unsupported {key}: expected {expected}, found {value}"
        ))),
        None => Err(V2Error::Crypto(format!("missing {key} in crypto metadata"))),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[(byte >> 4) as usize]));
        out.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    out
}

fn decode_hex_fixed<const N: usize>(input: &str) -> std::result::Result<[u8; N], V2Error> {
    if input.len() != N * 2 {
        return Err(V2Error::Crypto(format!(
            "invalid hex length: expected {}, found {}",
            N * 2,
            input.len()
        )));
    }
    let mut out = [0_u8; N];
    for (index, chunk) in input.as_bytes().chunks_exact(2).enumerate() {
        out[index] = (hex_value(chunk[0])? << 4) | hex_value(chunk[1])?;
    }
    Ok(out)
}

fn hex_value(byte: u8) -> std::result::Result<u8, V2Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(V2Error::Crypto("invalid hex character".to_owned())),
    }
}

/// Converts verified x7q v2 text into a passive text-only PDF.
pub fn build_text_pdf(text: &str) -> std::result::Result<Vec<u8>, V2Error> {
    let canonical = canonicalize_strict_text(text)?;
    Ok(render_text_pdf(&canonical))
}

/// Opens an x7q v2 file and renders its text payload as a passive text-only PDF.
pub fn build_pdf_from_x7q(
    input: &[u8],
    key: Option<&str>,
) -> std::result::Result<Vec<u8>, V2Error> {
    let container = validate_v2_with_key(input, key)?;
    build_text_pdf(container.canonical_text())
}

fn extract_pdf_text(pdf_bytes: &[u8]) -> std::result::Result<String, V2Error> {
    match pdf_extract::extract_text_from_mem(pdf_bytes) {
        Ok(text) if !text.trim().is_empty() => Ok(text),
        Ok(_) | Err(_) => extract_basic_pdf_text(pdf_bytes),
    }
}

fn extract_basic_pdf_text(pdf_bytes: &[u8]) -> std::result::Result<String, V2Error> {
    if !pdf_bytes.starts_with(b"%PDF-") {
        return Err(V2Error::PdfExtraction("missing %PDF header".to_owned()));
    }

    let mut index = 0;
    let mut parts = Vec::new();
    while index < pdf_bytes.len() {
        if pdf_bytes[index] == b'('
            && let Some((literal, next)) = read_pdf_literal(pdf_bytes, index + 1)?
        {
            if pdf_text_operator_follows(pdf_bytes, next) {
                parts.push(decode_pdf_text_literal(&literal));
            }
            index = next;
            continue;
        }
        index += 1;
    }

    if parts.is_empty() {
        return Err(V2Error::PdfExtraction(
            "no basic literal text objects found".to_owned(),
        ));
    }

    Ok(parts.join("\n"))
}

fn pdf_text_operator_follows(pdf_bytes: &[u8], start: usize) -> bool {
    let end = start.saturating_add(32).min(pdf_bytes.len());
    let tail = &pdf_bytes[start..end];
    tail.windows(2).any(|window| window == b"Tj") || tail.windows(2).any(|window| window == b"TJ")
}

fn read_pdf_literal(
    pdf_bytes: &[u8],
    start: usize,
) -> std::result::Result<Option<(Vec<u8>, usize)>, V2Error> {
    let mut out = Vec::new();
    let mut index = start;
    let mut depth = 1_u32;

    while index < pdf_bytes.len() {
        let byte = pdf_bytes[index];
        match byte {
            b'\\' => {
                index += 1;
                if index >= pdf_bytes.len() {
                    return Ok(None);
                }
                match pdf_bytes[index] {
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\n'),
                    b't' => out.push(b'\t'),
                    b'b' | b'f' => {}
                    b'(' => out.push(b'('),
                    b')' => out.push(b')'),
                    b'\\' => out.push(b'\\'),
                    b'\n' | b'\r' => {}
                    other => out.push(other),
                }
            }
            b'(' => {
                depth = depth.checked_add(1).ok_or_else(|| {
                    V2Error::PdfExtraction("nested literal depth overflow".to_owned())
                })?;
                out.push(byte);
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(Some((out, index + 1)));
                }
                out.push(byte);
            }
            other => out.push(other),
        }
        index += 1;
    }

    Ok(None)
}

fn decode_pdf_text_literal(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xfe, 0xff]) {
        return decode_utf16_be(&bytes[2..]);
    }
    if bytes.starts_with(&[0xff, 0xfe]) {
        return decode_utf16_le(&bytes[2..]);
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_owned(),
        Err(_) => bytes.iter().map(|byte| char::from(*byte)).collect(),
    }
}

fn decode_utf16_be(bytes: &[u8]) -> String {
    let units = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]));
    char::decode_utf16(units)
        .map(|item| item.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

fn decode_utf16_le(bytes: &[u8]) -> String {
    let units = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]));
    char::decode_utf16(units)
        .map(|item| item.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

fn render_text_pdf(text: &str) -> Vec<u8> {
    let lines = wrap_pdf_lines(text, 88);
    let lines_per_page = 48;
    let pages: Vec<&[String]> = lines.chunks(lines_per_page).collect();
    let page_count = pages.len().max(1);
    let catalog_id = 1;
    let pages_id = 2;
    let font_id = 3;
    let first_page_id = 4;
    let first_content_id = first_page_id + page_count;

    let mut objects = Vec::new();
    objects.push((
        catalog_id,
        format!("<< /Type /Catalog /Pages {pages_id} 0 R >>"),
    ));
    let kids = (0..page_count)
        .map(|index| format!("{} 0 R", first_page_id + index))
        .collect::<Vec<_>>()
        .join(" ");
    objects.push((
        pages_id,
        format!("<< /Type /Pages /Kids [{kids}] /Count {page_count} >>"),
    ));
    objects.push((
        font_id,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned(),
    ));

    for index in 0..page_count {
        let page_id = first_page_id + index;
        let content_id = first_content_id + index;
        objects.push((
            page_id,
            format!(
                "<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>"
            ),
        ));
    }

    for (index, page_lines) in pages.iter().enumerate() {
        let stream = render_pdf_page_stream(page_lines);
        objects.push((
            first_content_id + index,
            format!(
                "<< /Length {} >>\nstream\n{}endstream",
                stream.len(),
                stream
            ),
        ));
    }

    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets = Vec::with_capacity(objects.len() + 1);
    offsets.push(0_usize);
    for (id, body) in &objects {
        offsets.push(bytes.len());
        bytes.extend_from_slice(format!("{id} 0 obj\n{body}\nendobj\n").as_bytes());
    }
    let xref_offset = bytes.len();
    bytes.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    bytes.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        bytes.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    bytes.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root {catalog_id} 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    bytes
}

fn wrap_pdf_lines(text: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    for raw_line in text.lines() {
        if raw_line.is_empty() {
            out.push(String::new());
            continue;
        }
        let mut current = String::new();
        for word in raw_line.split_whitespace() {
            let next_len = if current.is_empty() {
                word.chars().count()
            } else {
                current.chars().count() + 1 + word.chars().count()
            };
            if next_len > width && !current.is_empty() {
                out.push(current);
                current = String::new();
            }
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(word);
        }
        out.push(current);
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

fn render_pdf_page_stream(lines: &[String]) -> String {
    let mut stream = String::from("BT\n/F1 10 Tf\n14 TL\n50 742 Td\n");
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            stream.push_str("T*\n");
        }
        stream.push_str(&format!("{} Tj\n", pdf_text_literal(line)));
    }
    stream.push_str("ET\n");
    stream
}

fn pdf_text_literal(text: &str) -> String {
    if text.is_ascii() {
        let escaped = text
            .replace('\\', "\\\\")
            .replace('(', "\\(")
            .replace(')', "\\)");
        format!("({escaped})")
    } else {
        let mut out = String::from("<FEFF");
        for unit in text.encode_utf16() {
            out.push_str(&format!("{unit:04X}"));
        }
        out.push('>');
        out
    }
}

fn parse_sections_without_hashes(
    input: &[u8],
    section_count: usize,
) -> BuildResult<Vec<SecureSection>> {
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let base = FIXED_HEADER_LEN
            .checked_add(
                index
                    .checked_mul(SECTION_ENTRY_LEN)
                    .ok_or(BuildError::SizeOverflow)?,
            )
            .ok_or(BuildError::SizeOverflow)?;
        let section_type = *input.get(base).ok_or(BuildError::SizeOverflow)?;
        let offset = read_u32_le(input, base + 1).ok_or(BuildError::SizeOverflow)?;
        let length = read_u32_le(input, base + 5).ok_or(BuildError::SizeOverflow)?;
        let flags = *input.get(base + 9).ok_or(BuildError::SizeOverflow)?;
        sections.push(SecureSection::new(section_type, offset, length, flags));
    }
    Ok(sections)
}

fn compute_header_hash(input: &[u8], header_len: usize) -> ParseResult<[u8; HASH_LEN]> {
    let mut header = input
        .get(..header_len)
        .ok_or(ParseError::TruncatedSectionTable {
            needed: header_len,
            available: input.len(),
        })?
        .to_vec();
    let end = HEADER_HASH_OFFSET
        .checked_add(HASH_LEN)
        .ok_or(ParseError::SectionTableOverflow)?;
    let header_hash_field =
        header
            .get_mut(HEADER_HASH_OFFSET..end)
            .ok_or(ParseError::TruncatedHeader {
                needed: FIXED_HEADER_LEN,
                available: input.len(),
            })?;
    header_hash_field.fill(0);
    Ok(sha256(&header))
}

fn compute_content_hash(input: &[u8], sections: &[SecureSection]) -> ParseResult<[u8; HASH_LEN]> {
    let mut hasher = Sha256::new();
    for (index, section) in sections.iter().enumerate() {
        let start =
            usize::try_from(section.offset).map_err(|_| ParseError::SectionOutOfBounds {
                index,
                offset: section.offset,
                length: section.length,
                file_len: input.len(),
            })?;
        let len = usize::try_from(section.length).map_err(|_| ParseError::SectionOutOfBounds {
            index,
            offset: section.offset,
            length: section.length,
            file_len: input.len(),
        })?;
        let end = start
            .checked_add(len)
            .ok_or(ParseError::SectionBoundsOverflow {
                index,
                offset: section.offset,
                length: section.length,
            })?;
        let section_bytes = input
            .get(start..end)
            .ok_or(ParseError::SectionOutOfBounds {
                index,
                offset: section.offset,
                length: section.length,
                file_len: input.len(),
            })?;
        hasher.update(section_bytes);
    }
    Ok(hasher.finalize())
}

fn read_array<const N: usize>(input: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    let bytes = input.get(offset..end)?;
    bytes.try_into().ok()
}

fn read_u32_le(input: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(read_array::<4>(input, offset)?))
}

fn sha256(input: &[u8]) -> [u8; HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize()
}

struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    bit_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0; 64],
            buffer_len: 0,
            bit_len: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.bit_len = self.bit_len.wrapping_add((input.len() as u64) * 8);

        if self.buffer_len > 0 {
            let remaining = 64 - self.buffer_len;
            let take = remaining.min(input.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&input[..take]);
            self.buffer_len += take;
            input = &input[take..];
            if self.buffer_len == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            }
        }

        while input.len() >= 64 {
            let mut block = [0_u8; 64];
            block.copy_from_slice(&input[..64]);
            self.compress(&block);
            input = &input[64..];
        }

        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            self.buffer_len = input.len();
        }
    }

    fn finalize(mut self) -> [u8; HASH_LEN] {
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffer = [0; 64];
            self.buffer_len = 0;
        }

        self.buffer[self.buffer_len..56].fill(0);
        self.buffer[56..64].copy_from_slice(&self.bit_len.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);

        let mut out = [0_u8; HASH_LEN];
        for (chunk, value) in out.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&value.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];

        let mut schedule = [0_u32; 64];
        for (index, chunk) in block.chunks_exact(4).take(16).enumerate() {
            schedule[index] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for index in 16..64 {
            let s0 = schedule[index - 15].rotate_right(7)
                ^ schedule[index - 15].rotate_right(18)
                ^ (schedule[index - 15] >> 3);
            let s1 = schedule[index - 2].rotate_right(17)
                ^ schedule[index - 2].rotate_right(19)
                ^ (schedule[index - 2] >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(schedule[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BuildSection, CONTENT_HASH_OFFSET, FIXED_HEADER_LEN, HASH_LEN, HEADER_HASH_OFFSET,
        ParseError, V2BuildOptions, V2Error, build_container, build_pdf_from_x7q, build_text_pdf,
        build_v2_from_pdf, build_v2_text_container, build_v2_text_container_with_key,
        canonicalize_strict_text, parse_secure, sha256, validate_v2, validate_v2_with_key,
    };

    fn fixture_container() -> Vec<u8> {
        build_container(&[
            BuildSection::new(0x01, 0x00, b"payload-one".to_vec()),
            BuildSection::new(0x02, 0x80, b"metadata".to_vec()),
        ])
        .expect("fixture should build")
    }

    fn rewrite_header_hash(bytes: &mut [u8]) {
        bytes[HEADER_HASH_OFFSET..HEADER_HASH_OFFSET + HASH_LEN].fill(0);
        let header_len = u32::from_le_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) as usize;
        let digest = sha256(&bytes[..header_len]);
        bytes[HEADER_HASH_OFFSET..HEADER_HASH_OFFSET + HASH_LEN].copy_from_slice(&digest);
    }

    #[test]
    fn valid_container_test() {
        let bytes = fixture_container();
        let parsed = parse_secure(&bytes).expect("valid secure container should parse");

        assert_eq!(parsed.version(), 0x02);
        assert_eq!(parsed.sections().len(), 2);
        assert_eq!(parsed.sections()[0].section_type(), 0x01);
        assert_eq!(parsed.sections()[1].flags(), 0x80);
    }

    #[test]
    fn corrupted_magic_test() {
        let mut bytes = fixture_container();
        bytes[0] = b'Y';

        assert_eq!(parse_secure(&bytes), Err(ParseError::InvalidMagic));
    }

    #[test]
    fn corrupted_hash_test() {
        let mut bytes = fixture_container();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;

        assert_eq!(parse_secure(&bytes), Err(ParseError::ContentHashMismatch));
    }

    #[test]
    fn truncated_file_test() {
        let bytes = fixture_container();

        assert_eq!(
            parse_secure(&bytes[..FIXED_HEADER_LEN - 1]),
            Err(ParseError::TruncatedHeader {
                needed: FIXED_HEADER_LEN,
                available: FIXED_HEADER_LEN - 1
            })
        );
    }

    #[test]
    fn forged_section_bounds_test() {
        let mut bytes = fixture_container();
        let section_offset_field = FIXED_HEADER_LEN + 1;
        bytes[section_offset_field..section_offset_field + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[section_offset_field + 4..section_offset_field + 8]
            .copy_from_slice(&1_u32.to_le_bytes());
        rewrite_header_hash(&mut bytes);

        assert_eq!(
            parse_secure(&bytes),
            Err(ParseError::SectionBoundsOverflow {
                index: 0,
                offset: u32::MAX,
                length: 1
            })
        );
    }

    #[test]
    fn tampered_header_test() {
        let mut bytes = fixture_container();
        bytes[FIXED_HEADER_LEN + 9] ^= 0x01;

        assert_eq!(parse_secure(&bytes), Err(ParseError::HeaderHashMismatch));
    }

    #[test]
    fn deterministic_reparse_test() {
        let bytes = fixture_container();
        let first = parse_secure(&bytes).expect("first parse should pass");
        let second = parse_secure(&bytes).expect("second parse should pass");

        assert_eq!(first, second);
    }

    #[test]
    fn content_hash_is_over_section_bytes_only() {
        let bytes = fixture_container();
        let parsed = parse_secure(&bytes).expect("fixture should parse");
        let digest = &bytes[CONTENT_HASH_OFFSET..CONTENT_HASH_OFFSET + HASH_LEN];

        assert_eq!(parsed.content_hash().as_slice(), digest);
    }

    #[test]
    fn v2_builds_and_validates_strict_text_container() {
        let options = V2BuildOptions::new("text", "prompt.txt");
        let bytes =
            build_v2_text_container("hello\r\nworld  ", &options).expect("v2 text should build");
        let parsed = validate_v2(&bytes).expect("v2 should validate");

        assert_eq!(parsed.container().version(), 0x03);
        assert_eq!(parsed.canonical_text(), "hello\nworld");
        assert!(parsed.policy().contains("execution_policy=passive-only"));
        assert!(parsed.provenance().contains("source_format=text"));
    }

    #[test]
    fn v2_rejects_invisible_unicode() {
        let err = canonicalize_strict_text("hello\u{200b}world").expect_err("should reject");

        assert!(matches!(err, V2Error::StrictTextViolation(_)));
    }

    #[test]
    fn v2_rejects_executable_patterns() {
        let options = V2BuildOptions::new("text", "prompt.txt");
        let err = build_v2_text_container("#!/bin/sh\necho nope", &options)
            .expect_err("should reject executable pattern");

        assert!(matches!(err, V2Error::StrictTextViolation(_)));
    }

    #[test]
    fn v2_basic_pdf_converter_builds_valid_container() {
        let pdf = b"%PDF-1.4\n1 0 obj\n<<>>\nstream\nBT\n(Hello from PDF) Tj\nET\nendstream\nendobj\n%%EOF";
        let bytes = build_v2_from_pdf(pdf, "sample.pdf").expect("basic PDF should convert");
        let parsed = validate_v2(&bytes).expect("converted PDF should validate");

        assert_eq!(parsed.canonical_text(), "Hello from PDF");
        assert!(parsed.provenance().contains("source_format=pdf"));
    }

    #[test]
    fn v2_encrypted_text_requires_key_and_decrypts() {
        let options = V2BuildOptions::new("text", "secret.txt");
        let bytes =
            build_v2_text_container_with_key("secret text", &options, Some("correct horse"))
                .expect("encrypted v2 text should build");

        assert_eq!(validate_v2(&bytes), Err(V2Error::MissingKey));
        assert!(validate_v2_with_key(&bytes, Some("wrong key")).is_err());

        let parsed = validate_v2_with_key(&bytes, Some("correct horse"))
            .expect("correct key should decrypt");
        assert_eq!(parsed.canonical_text(), "secret text");
        assert!(parsed.policy().contains("payload_encryption=aes-256-gcm"));
    }

    #[test]
    fn v2_renders_text_only_pdf() {
        let pdf = build_text_pdf("Hello PDF\nSecond line").expect("PDF should render");

        assert!(pdf.starts_with(b"%PDF-1.4"));
        assert!(
            pdf.windows(b"/JavaScript".len())
                .all(|window| window != b"/JavaScript")
        );
        assert!(
            pdf.windows(b"/OpenAction".len())
                .all(|window| window != b"/OpenAction")
        );
    }

    #[test]
    fn v2_converts_x7q_to_pdf_with_key() {
        let options = V2BuildOptions::new("text", "secret.txt");
        let bytes = build_v2_text_container_with_key("pdf body", &options, Some("key"))
            .expect("encrypted v2 text should build");
        let pdf = build_pdf_from_x7q(&bytes, Some("key")).expect("x7q should render to PDF");

        assert!(pdf.starts_with(b"%PDF-1.4"));
        assert!(
            pdf.windows(b"pdf body".len())
                .any(|window| window == b"pdf body")
        );
    }
}
