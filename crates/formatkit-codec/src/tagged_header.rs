//! Type-tagged stream header: one tag byte followed by a 24-bit little-endian
//! decoded size, with an optional 32-bit extended-size form.
//!
//! A family of compact compression formats frames every stream with a 4-byte
//! little-endian word whose low byte is a codec tag (the high nibble usually
//! names the algorithm and the low nibble a parameter) and whose upper 24 bits
//! carry the decoded length. The extended form stores a zero 24-bit size and
//! then a 32-bit little-endian decoded size, for an 8-byte header.
//!
//! This module only reads and writes that framing. Tag registries, which tags
//! permit the extended form, and trailing-byte policy remain with the caller.
//! The tagged codecs in [`crate::tagged_lz77`], [`crate::tagged_huffman`],
//! [`crate::rle`] and [`crate::delta`] use these helpers.
//!
//! ```
//! use formatkit_codec::tagged_header::{read_tagged_header, write_tagged_header};
//!
//! let mut out = Vec::new();
//! write_tagged_header(&mut out, 0x30, 0x01_2345).unwrap();
//! assert_eq!(out, [0x30, 0x45, 0x23, 0x01]);
//!
//! let header = read_tagged_header(&out).unwrap();
//! assert_eq!((header.tag, header.decoded_size, header.header_len), (0x30, 0x01_2345, 4));
//! ```

use crate::prelude::*;

use formatkit_core::{bytes_at, u32_at, Error, Result};

/// Byte length of the compact tagged header (tag + 24-bit size).
pub const TAGGED_HEADER_LEN: usize = 4;
/// Byte length of the extended tagged header (tag + zero 24-bit size + 32-bit size).
pub const TAGGED_HEADER_EXTENDED_LEN: usize = 8;
/// Largest decoded size representable by the compact 24-bit header field.
pub const MAX_TAGGED_SIZE: usize = 0x00FF_FFFF;

/// Tag of the 12-bit-distance, 4-bit-length LZ77 stream ([`crate::tagged_lz77`]).
pub const TAG_LZ77: u8 = 0x10;
/// Tag of the extended-length LZ77 stream ([`crate::tagged_lz77`]).
pub const TAG_LZ77_EXTENDED: u8 = 0x11;
/// Tag of the 4-bit-symbol packed-tree Huffman stream ([`crate::tagged_huffman`]).
pub const TAG_HUFFMAN_4BIT: u8 = 0x24;
/// Tag of the 8-bit-symbol packed-tree Huffman stream ([`crate::tagged_huffman`]).
pub const TAG_HUFFMAN_8BIT: u8 = 0x28;
/// Tag of the byte run-length stream ([`crate::rle::decode_tagged_rle`]).
pub const TAG_RLE: u8 = 0x30;
/// Tag of the 8-bit delta-filtered stream ([`crate::delta::decode_tagged_delta`]).
pub const TAG_DELTA_8BIT: u8 = 0x81;
/// Tag of the 16-bit little-endian delta-filtered stream ([`crate::delta::decode_tagged_delta`]).
pub const TAG_DELTA_16BIT: u8 = 0x82;

/// Parsed tagged stream header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaggedHeader {
    /// Codec tag byte (`input[0]`).
    pub tag: u8,
    /// Declared decoded size in bytes.
    pub decoded_size: usize,
    /// Header length in bytes ([`TAGGED_HEADER_LEN`] or [`TAGGED_HEADER_EXTENDED_LEN`]).
    pub header_len: usize,
}

/// Read a compact 4-byte tagged header from the start of `input`.
///
/// The returned `decoded_size` may be zero; callers decide whether a zero size
/// is empty, invalid, or (via [`read_tagged_header_extended`]) an escape to the
/// extended form.
pub fn read_tagged_header(input: &[u8]) -> Result<TaggedHeader> {
    let raw = bytes_at(input, 0, TAGGED_HEADER_LEN)?;
    Ok(TaggedHeader {
        tag: raw[0],
        decoded_size: usize::from(raw[1]) | usize::from(raw[2]) << 8 | usize::from(raw[3]) << 16,
        header_len: TAGGED_HEADER_LEN,
    })
}

/// Read a tagged header, following a zero 24-bit size to the 32-bit extended size.
///
/// A nonzero 24-bit size yields a 4-byte header. A zero 24-bit size requires
/// four more bytes holding the little-endian 32-bit decoded size and yields an
/// 8-byte header; that extended size may itself be zero.
pub fn read_tagged_header_extended(input: &[u8]) -> Result<TaggedHeader> {
    let compact = read_tagged_header(input)?;
    if compact.decoded_size != 0 {
        return Ok(compact);
    }
    let extended = u32_at(input, TAGGED_HEADER_LEN)?;
    let decoded_size = usize::try_from(extended).map_err(|_| Error::ResourceLimit {
        resource: "tagged header decoded size",
        requested: u64::from(extended),
        limit: usize::MAX as u64,
    })?;
    Ok(TaggedHeader {
        tag: compact.tag,
        decoded_size,
        header_len: TAGGED_HEADER_EXTENDED_LEN,
    })
}

/// Append a compact 4-byte tagged header.
///
/// Fails with [`Error::InvalidField`] when `decoded_size > MAX_TAGGED_SIZE`.
pub fn write_tagged_header(out: &mut Vec<u8>, tag: u8, decoded_size: usize) -> Result<()> {
    if decoded_size > MAX_TAGGED_SIZE {
        return Err(Error::InvalidField {
            what: "tagged header decoded size",
            value: decoded_size as u64,
        });
    }
    out.push(tag);
    out.extend_from_slice(&(decoded_size as u32).to_le_bytes()[..3]);
    Ok(())
}

/// Append a tagged header, using the 8-byte extended form only when
/// `decoded_size` does not fit the 24-bit field (or is zero).
///
/// Fails with [`Error::InvalidField`] when `decoded_size > u32::MAX`.
pub fn write_tagged_header_extended(out: &mut Vec<u8>, tag: u8, decoded_size: usize) -> Result<()> {
    if decoded_size != 0 && decoded_size <= MAX_TAGGED_SIZE {
        return write_tagged_header(out, tag, decoded_size);
    }
    let extended = u32::try_from(decoded_size).map_err(|_| Error::InvalidField {
        what: "tagged header extended decoded size",
        value: decoded_size as u64,
    })?;
    out.extend_from_slice(&[tag, 0, 0, 0]);
    out.extend_from_slice(&extended.to_le_bytes());
    Ok(())
}

/// Read a compact header, require `tag`, and require `0 < decoded_size <= max_output`.
pub(crate) fn expect_tagged_header(
    input: &[u8],
    tag: u8,
    what: &'static str,
    resource: &'static str,
    max_output: usize,
) -> Result<TaggedHeader> {
    let header = read_tagged_header(input)?;
    expect_tag(header, tag)?;
    check_decoded_size(header, what, resource, max_output)?;
    Ok(header)
}

/// Reject a header whose tag differs from `tag`.
pub(crate) fn expect_tag(header: TaggedHeader, tag: u8) -> Result<()> {
    if header.tag != tag {
        return Err(Error::BadMagic {
            offset: 0,
            expected: u32::from(tag),
            found: u32::from(header.tag),
        });
    }
    Ok(())
}

/// Require `0 < header.decoded_size <= max_output` before any allocation.
pub(crate) fn check_decoded_size(
    header: TaggedHeader,
    what: &'static str,
    resource: &'static str,
    max_output: usize,
) -> Result<()> {
    if header.decoded_size == 0 {
        return Err(Error::InvalidField { what, value: 0 });
    }
    if header.decoded_size > max_output {
        return Err(Error::ResourceLimit {
            resource,
            requested: header.decoded_size as u64,
            limit: max_output as u64,
        });
    }
    Ok(())
}

/// Validate an encoder input length for the compact header: `1..=MAX_TAGGED_SIZE`.
pub(crate) fn check_encode_len(len: usize, what: &'static str) -> Result<()> {
    if len == 0 || len > MAX_TAGGED_SIZE {
        return Err(Error::InvalidField {
            what,
            value: len as u64,
        });
    }
    Ok(())
}

/// Shift a body-relative [`Error::Truncated`] offset into stream coordinates.
pub(crate) fn shift_truncated(err: Error, by: usize) -> Error {
    match err {
        Error::Truncated {
            offset,
            needed,
            available,
        } => Error::Truncated {
            offset: offset.saturating_add(by),
            needed,
            available,
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_header_round_trips_and_rejects_short_input() {
        let mut out = Vec::new();
        write_tagged_header(&mut out, 0x10, MAX_TAGGED_SIZE).unwrap();
        assert_eq!(out, [0x10, 0xFF, 0xFF, 0xFF]);
        assert_eq!(
            read_tagged_header(&out).unwrap(),
            TaggedHeader {
                tag: 0x10,
                decoded_size: MAX_TAGGED_SIZE,
                header_len: 4
            }
        );
        assert!(write_tagged_header(&mut out, 0x10, MAX_TAGGED_SIZE + 1).is_err());
        assert!(matches!(
            read_tagged_header(&[0x10, 0, 0]),
            Err(Error::Truncated { .. })
        ));
    }

    #[test]
    fn extended_header_round_trips_and_keeps_compact_form_when_possible() {
        let mut compact = Vec::new();
        write_tagged_header_extended(&mut compact, 0x11, 5).unwrap();
        assert_eq!(compact, [0x11, 5, 0, 0]);
        assert_eq!(read_tagged_header_extended(&compact).unwrap().header_len, 4);

        let mut extended = Vec::new();
        write_tagged_header_extended(&mut extended, 0x11, MAX_TAGGED_SIZE + 1).unwrap();
        assert_eq!(extended, [0x11, 0, 0, 0, 0x00, 0x00, 0x00, 0x01]);
        let header = read_tagged_header_extended(&extended).unwrap();
        assert_eq!(header.decoded_size, MAX_TAGGED_SIZE + 1);
        assert_eq!(header.header_len, TAGGED_HEADER_EXTENDED_LEN);

        assert!(matches!(
            read_tagged_header_extended(&[0x11, 0, 0, 0, 1]),
            Err(Error::Truncated { .. })
        ));
    }

    #[test]
    fn checks_tag_and_size_before_allocation() {
        let input = [0x30, 0x10, 0x00, 0x00];
        assert!(matches!(
            expect_tagged_header(&input, 0x10, "size", "bytes", 64),
            Err(Error::BadMagic {
                expected: 0x10,
                found: 0x30,
                ..
            })
        ));
        assert!(matches!(
            expect_tagged_header(&input, 0x30, "size", "bytes", 15),
            Err(Error::ResourceLimit { requested: 16, .. })
        ));
        assert!(matches!(
            expect_tagged_header(&[0x30, 0, 0, 0], 0x30, "size", "bytes", 15),
            Err(Error::InvalidField { value: 0, .. })
        ));
    }
}
