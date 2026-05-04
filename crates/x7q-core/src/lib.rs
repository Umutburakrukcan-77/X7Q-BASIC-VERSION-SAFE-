#![forbid(unsafe_code)]
#![doc = "Public facade for the x7q v0.1 parser implementation."]

pub use x7q_format::{Container, FIXED_HEADER_LEN, MAGIC, SECTION_ENTRY_LEN, Section, VERSION_V1};
pub use x7q_parser::{ParseError, Result, parse};
