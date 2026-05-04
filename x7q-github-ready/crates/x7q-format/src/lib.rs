#![forbid(unsafe_code)]
#![doc = "Format constants and metadata types for x7q v0.1 containers."]

/// Fixed x7q v0.1 magic prefix.
pub const MAGIC: [u8; 4] = *b"X7Q\0";

/// Supported x7q format version.
pub const VERSION_V1: u8 = 0x01;

/// Number of bytes in the fixed x7q v0.1 header.
pub const FIXED_HEADER_LEN: usize = 13;

/// Number of bytes in each x7q v0.1 section table entry.
pub const SECTION_ENTRY_LEN: usize = 9;

/// Parsed x7q container metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    version: u8,
    header_len: u32,
    sections: Vec<Section>,
}

impl Container {
    /// Creates parsed container metadata.
    #[must_use]
    pub fn new(version: u8, header_len: u32, sections: Vec<Section>) -> Self {
        Self {
            version,
            header_len,
            sections,
        }
    }

    /// Returns the parsed x7q version byte.
    #[must_use]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Returns the encoded header length.
    #[must_use]
    pub fn header_len(&self) -> u32 {
        self.header_len
    }

    /// Returns parsed section metadata in file order.
    #[must_use]
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }
}

/// Parsed x7q section metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    section_type: u8,
    offset: u32,
    length: u32,
}

impl Section {
    /// Creates section metadata.
    #[must_use]
    pub fn new(section_type: u8, offset: u32, length: u32) -> Self {
        Self {
            section_type,
            offset,
            length,
        }
    }

    /// Returns the section type byte.
    #[must_use]
    pub fn section_type(&self) -> u8 {
        self.section_type
    }

    /// Returns the section byte offset from the start of the file.
    #[must_use]
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// Returns the section length in bytes.
    #[must_use]
    pub fn length(&self) -> u32 {
        self.length
    }
}
