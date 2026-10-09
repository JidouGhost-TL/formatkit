//! Checked byte ranges for common resident chunk headers.
//!
//! These helpers describe only the physical relationship between a chunk's
//! fixed header and its bounded payload. Iteration, padding, nesting, tag
//! policy, and format-specific diagnostics remain with the format owner.

use formatkit_core::Endian;
use std::ops::Range;

/// The framing shared by one payload-sized, eight-byte-header chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadChunkSpan {
    /// Four-byte chunk tag.
    pub tag: [u8; 4],
    /// Payload extent after the eight-byte header.
    pub payload: Range<usize>,
}

/// The framing shared by one chunk whose stored size includes its header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusiveChunkSpan {
    /// Four-byte chunk tag.
    pub tag: [u8; 4],
    /// Complete stored extent including the eight-byte header.
    pub whole: Range<usize>,
    /// Payload extent after the eight-byte header.
    pub payload: Range<usize>,
}

/// Structural failures from [`read_payload_chunk`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadChunkError {
    /// Fewer than eight bytes remain at the requested header offset.
    ShortHeader {
        /// Requested absolute header offset.
        offset: usize,
        /// Bytes remaining in the supplied parent prefix.
        available: usize,
    },
    /// The payload end cannot be represented as a `usize`.
    PayloadOverflow {
        /// Absolute payload start.
        offset: usize,
        /// Stored payload size.
        size: u32,
    },
    /// The declared payload escapes the supplied parent prefix.
    PayloadPastEnd {
        /// Four-byte chunk tag.
        tag: [u8; 4],
        /// Absolute chunk-header offset.
        header_offset: usize,
        /// Computed exclusive payload end.
        payload_end: usize,
        /// Exclusive end of the supplied parent prefix.
        parent_end: usize,
    },
}

/// Structural failures from [`read_header_inclusive_chunk`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InclusiveChunkError {
    /// Fewer than eight bytes remain at the requested header offset.
    ShortHeader {
        /// Requested absolute header offset.
        offset: usize,
        /// Bytes remaining in the supplied parent prefix.
        available: usize,
    },
    /// The inclusive size is smaller than the eight-byte header.
    SizeTooSmall {
        /// Absolute chunk-header offset.
        header_offset: usize,
        /// Stored inclusive size.
        size: u32,
    },
    /// The chunk end cannot be represented as a `usize`.
    ChunkOverflow {
        /// Absolute chunk-header offset.
        offset: usize,
        /// Stored inclusive size.
        size: u32,
    },
    /// The declared chunk escapes the supplied parent prefix.
    ChunkPastEnd {
        /// Four-byte chunk tag.
        tag: [u8; 4],
        /// Absolute chunk-header offset.
        header_offset: usize,
        /// Computed exclusive chunk end.
        chunk_end: usize,
        /// Exclusive end of the supplied parent prefix.
        parent_end: usize,
    },
}

fn read_header(
    parent_prefix: &[u8],
    header_offset: usize,
    endian: Endian,
) -> Result<([u8; 4], u32, usize), PayloadChunkError> {
    let available = parent_prefix.len().saturating_sub(header_offset);
    if available < 8 {
        return Err(PayloadChunkError::ShortHeader {
            offset: header_offset,
            available,
        });
    }
    let payload_start = header_offset + 8;
    let header = &parent_prefix[header_offset..payload_start];
    let tag = header[..4].try_into().expect("four-byte chunk tag");
    let size_bytes = header[4..].try_into().expect("four-byte chunk size");
    let size = match endian {
        Endian::Little => u32::from_le_bytes(size_bytes),
        Endian::Big => u32::from_be_bytes(size_bytes),
    };
    Ok((tag, size, payload_start))
}

/// Read one chunk header and return its validated payload range.
///
/// `parent_prefix.len()` is the exclusive absolute bound. The stored size
/// excludes the eight-byte header. No alignment is inferred or consumed.
pub fn read_payload_chunk(
    parent_prefix: &[u8],
    header_offset: usize,
    endian: Endian,
) -> Result<PayloadChunkSpan, PayloadChunkError> {
    let (tag, payload_size, payload_start) = read_header(parent_prefix, header_offset, endian)?;
    let payload_end = payload_start.checked_add(payload_size as usize).ok_or(
        PayloadChunkError::PayloadOverflow {
            offset: payload_start,
            size: payload_size,
        },
    )?;
    if payload_end > parent_prefix.len() {
        return Err(PayloadChunkError::PayloadPastEnd {
            tag,
            header_offset,
            payload_end,
            parent_end: parent_prefix.len(),
        });
    }
    Ok(PayloadChunkSpan {
        tag,
        payload: payload_start..payload_end,
    })
}

/// Read one chunk whose stored size includes its eight-byte header.
///
/// The returned ranges name both the complete stored chunk and its payload.
/// Iteration, alignment, nesting, accepted tags and minimum owner payload sizes
/// remain with the format owner.
pub fn read_header_inclusive_chunk(
    parent_prefix: &[u8],
    header_offset: usize,
    endian: Endian,
) -> Result<InclusiveChunkSpan, InclusiveChunkError> {
    let (tag, inclusive_size, payload_start) = read_header(parent_prefix, header_offset, endian)
        .map_err(|error| match error {
            PayloadChunkError::ShortHeader { offset, available } => {
                InclusiveChunkError::ShortHeader { offset, available }
            }
            PayloadChunkError::PayloadOverflow { .. }
            | PayloadChunkError::PayloadPastEnd { .. } => {
                unreachable!("header decoding only reports short headers")
            }
        })?;
    if inclusive_size < 8 {
        return Err(InclusiveChunkError::SizeTooSmall {
            header_offset,
            size: inclusive_size,
        });
    }
    let chunk_end = header_offset.checked_add(inclusive_size as usize).ok_or(
        InclusiveChunkError::ChunkOverflow {
            offset: header_offset,
            size: inclusive_size,
        },
    )?;
    if chunk_end > parent_prefix.len() {
        return Err(InclusiveChunkError::ChunkPastEnd {
            tag,
            header_offset,
            chunk_end,
            parent_end: parent_prefix.len(),
        });
    }
    Ok(InclusiveChunkSpan {
        tag,
        whole: header_offset..chunk_end,
        payload: payload_start..chunk_end,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_both_endians_and_zero_payload_without_alignment() {
        let le = *b"LE__\x03\0\0\0abc_";
        let span = read_payload_chunk(&le, 0, Endian::Little).unwrap();
        assert_eq!(span.tag, *b"LE__");
        assert_eq!(span.payload, 8..11);

        let be = *b"BE__\0\0\0\0";
        let span = read_payload_chunk(&be, 0, Endian::Big).unwrap();
        assert_eq!(span.payload, 8..8);
    }

    #[test]
    fn enforces_the_supplied_parent_not_just_the_input() {
        let data = *b"TAG_\0\0\0\x04bodytail";
        assert_eq!(
            read_payload_chunk(&data[..11], 0, Endian::Big),
            Err(PayloadChunkError::PayloadPastEnd {
                tag: *b"TAG_",
                header_offset: 0,
                payload_end: 12,
                parent_end: 11,
            })
        );
    }

    #[test]
    fn rejects_invalid_regions_short_headers_and_large_sizes() {
        let short = [0u8; 7];
        assert_eq!(
            read_payload_chunk(&short, 0, Endian::Little),
            Err(PayloadChunkError::ShortHeader {
                offset: 0,
                available: 7,
            })
        );
        assert_eq!(
            read_payload_chunk(&short, usize::MAX, Endian::Little),
            Err(PayloadChunkError::ShortHeader {
                offset: usize::MAX,
                available: 0,
            })
        );
        let huge = *b"TAG_\xff\xff\xff\xff";
        assert!(matches!(
            read_payload_chunk(&huge, 0, Endian::Little),
            Err(PayloadChunkError::PayloadPastEnd { .. })
                | Err(PayloadChunkError::PayloadOverflow { .. })
        ));
    }

    #[test]
    fn reads_header_inclusive_chunks_without_owning_iteration_or_alignment() {
        let le = *b"LE__\x0b\0\0\0abc_";
        let span = read_header_inclusive_chunk(&le, 0, Endian::Little).unwrap();
        assert_eq!(span.tag, *b"LE__");
        assert_eq!(span.whole, 0..11);
        assert_eq!(span.payload, 8..11);

        let too_small = *b"BAD_\x07\0\0\0";
        assert_eq!(
            read_header_inclusive_chunk(&too_small, 0, Endian::Little),
            Err(InclusiveChunkError::SizeTooSmall {
                header_offset: 0,
                size: 7,
            })
        );

        let overrun = *b"END_\x0c\0\0\0abc";
        assert!(matches!(
            read_header_inclusive_chunk(&overrun, 0, Endian::Little),
            Err(InclusiveChunkError::ChunkPastEnd {
                chunk_end: 12,
                parent_end: 11,
                ..
            })
        ));
    }
}
