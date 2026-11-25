//! Checked byte ranges for common resident chunk headers.
//!
//! These helpers describe only the physical relationship between a chunk's
//! fixed header and its bounded payload. Iteration, padding, nesting, tag
//! policy, and format-specific diagnostics remain with the format owner.

use formatkit_core::{checked_align_up_multiple, Endian};
use std::ops::Range;

use crate::spec::{IntFieldSpec, LayoutError};

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

/// How the size field in a [`ChunkStreamSpec`] relates to the chunk header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkSizeMode {
    /// Stored size counts only payload bytes following `header_size`.
    PayloadOnly,
    /// Stored size includes `header_size` (and must be at least `header_size`).
    IncludesHeader,
}

/// `const`-constructible declarative specification for sequential tagged chunk streams.
///
/// # Example
/// ```
/// use formatkit_layout::{
///     parse_chunk_stream, ChunkSizeMode, ChunkStreamSpec, IntFieldSpec,
/// };
///
/// const SPEC: ChunkStreamSpec = ChunkStreamSpec {
///     start_offset: 0,
///     header_size: 8,
///     tag_offset: 0,
///     tag_len: 4,
///     size_field: IntFieldSpec::u32_le(4),
///     size_mode: ChunkSizeMode::PayloadOnly,
///     alignment: 4,
///     terminator_tag: None,
///     require_eof_closure: true,
///     max_chunks: 64,
/// };
///
/// let mut data = Vec::new();
/// // Chunk 0: 3-byte payload + 1 alignment pad byte
/// data.extend_from_slice(b"CHK0");
/// data.extend_from_slice(&3u32.to_le_bytes());
/// data.extend_from_slice(b"abc\0");
/// // Chunk 1: 4-byte payload
/// data.extend_from_slice(b"CHK1");
/// data.extend_from_slice(&4u32.to_le_bytes());
/// data.extend_from_slice(b"WXYZ");
///
/// let chunks = parse_chunk_stream(&data, &SPEC).unwrap();
/// assert_eq!(chunks.len(), 2);
/// assert_eq!(chunks[0].tag, b"CHK0");
/// assert_eq!(chunks[0].payload(&data), Some(&b"abc"[..]));
/// assert_eq!(chunks[1].tag, b"CHK1");
/// assert_eq!(chunks[1].payload(&data), Some(&b"WXYZ"[..]));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkStreamSpec {
    /// Byte offset where the first chunk header begins.
    pub start_offset: usize,
    /// Fixed byte size of every chunk header (must be `>= 1`).
    pub header_size: usize,
    /// Byte offset of the tag within each chunk header.
    pub tag_offset: usize,
    /// Byte length of the tag within each chunk header (e.g. `4` or `8`; must be `>= 1`).
    pub tag_len: usize,
    /// Integer field inside each chunk header carrying the chunk size.
    pub size_field: IntFieldSpec,
    /// Whether `size_field` counts only the payload or includes `header_size`.
    pub size_mode: ChunkSizeMode,
    /// Byte alignment for the next chunk start after each payload (e.g. `1`, `4`, `2048`; must be `>= 1`).
    pub alignment: usize,
    /// Optional tag that terminates the stream cleanly without being emitted.
    pub terminator_tag: Option<&'static [u8]>,
    /// When `true`, reject trailing bytes shorter than `header_size` at stream end.
    pub require_eof_closure: bool,
    /// Maximum number of chunks accepted before returning [`LayoutError::MaxEntriesExceeded`].
    pub max_chunks: usize,
}

/// One validated chunk decoded from a [`ChunkStreamSpec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkEntry {
    /// Decoded tag bytes (length equals [`ChunkStreamSpec::tag_len`]).
    pub tag: Vec<u8>,
    /// Byte offset of the chunk header within the input slice.
    pub header_offset: usize,
    /// Byte offset of the chunk payload (`header_offset + header_size`).
    pub payload_offset: usize,
    /// Byte length of the chunk payload.
    pub payload_size: usize,
}

impl ChunkEntry {
    /// Return the half-open byte range of this chunk's payload.
    #[must_use]
    pub const fn payload_range(&self) -> Range<usize> {
        self.payload_offset..self.payload_offset + self.payload_size
    }

    /// Borrow this chunk's payload slice from `data`.
    #[must_use]
    pub fn payload<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        let end = self.payload_offset.checked_add(self.payload_size)?;
        data.get(self.payload_offset..end)
    }
}

/// Checked iterator over sequential chunks described by a [`ChunkStreamSpec`].
#[derive(Debug, Clone)]
pub struct ChunkStreamIter<'a> {
    data: &'a [u8],
    spec: ChunkStreamSpec,
    pos: usize,
    emitted: usize,
    finished: bool,
}

fn validate_chunk_stream_spec(spec: &ChunkStreamSpec) -> Result<(), LayoutError> {
    if spec.header_size == 0 {
        return Err(LayoutError::InvalidSpec {
            field: "header_size",
            reason: "must be nonzero",
        });
    }
    if spec.tag_len == 0 {
        return Err(LayoutError::InvalidSpec {
            field: "tag_len",
            reason: "must be nonzero",
        });
    }
    let tag_end = spec
        .tag_offset
        .checked_add(spec.tag_len)
        .ok_or(LayoutError::InvalidSpec {
            field: "tag_offset",
            reason: "tag_offset + tag_len overflows usize",
        })?;
    if tag_end > spec.header_size {
        return Err(LayoutError::InvalidSpec {
            field: "tag_offset",
            reason: "tag extends past header_size",
        });
    }
    let size_end = spec
        .size_field
        .end_offset()
        .ok_or(LayoutError::InvalidSpec {
            field: "size_field",
            reason: "size_field end overflows usize",
        })?;
    if size_end > spec.header_size {
        return Err(LayoutError::InvalidSpec {
            field: "size_field",
            reason: "size_field extends past header_size",
        });
    }
    if spec.alignment == 0 {
        return Err(LayoutError::InvalidSpec {
            field: "alignment",
            reason: "must be nonzero",
        });
    }
    if let Some(term) = spec.terminator_tag {
        if term.len() != spec.tag_len {
            return Err(LayoutError::InvalidSpec {
                field: "terminator_tag",
                reason: "terminator_tag length must equal tag_len",
            });
        }
    }
    Ok(())
}

/// Create a checked iterator over sequential tagged chunks in `data`.
pub fn iter_chunk_stream<'a>(
    data: &'a [u8],
    spec: &ChunkStreamSpec,
) -> Result<ChunkStreamIter<'a>, LayoutError> {
    validate_chunk_stream_spec(spec)?;
    if spec.start_offset > data.len() {
        return Err(LayoutError::Truncated {
            offset: spec.start_offset,
            needed: 0,
            available: 0,
        });
    }
    Ok(ChunkStreamIter {
        data,
        spec: *spec,
        pos: spec.start_offset,
        emitted: 0,
        finished: false,
    })
}

impl Iterator for ChunkStreamIter<'_> {
    type Item = Result<ChunkEntry, LayoutError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        if self.pos >= self.data.len() {
            self.finished = true;
            return None;
        }
        let remaining = self.data.len() - self.pos;
        if remaining < self.spec.header_size {
            self.finished = true;
            if self.spec.require_eof_closure {
                return Some(Err(LayoutError::TrailingBytes {
                    offset: self.pos,
                    remaining,
                }));
            }
            return None;
        }

        let header_offset = self.pos;
        let payload_offset = match header_offset.checked_add(self.spec.header_size) {
            Some(off) => off,
            None => {
                self.finished = true;
                return Some(Err(LayoutError::Overflow {
                    what: "payload_offset",
                }));
            }
        };
        let header = &self.data[header_offset..payload_offset];
        let tag_slice = &header[self.spec.tag_offset..self.spec.tag_offset + self.spec.tag_len];

        if self.spec.terminator_tag == Some(tag_slice) {
            self.finished = true;
            return None;
        }

        if self.emitted >= self.spec.max_chunks {
            self.finished = true;
            return Some(Err(LayoutError::MaxEntriesExceeded {
                max: self.spec.max_chunks,
            }));
        }

        let index = self.emitted;
        let raw_size = match self.spec.size_field.read(header) {
            Ok(v) => v,
            Err(e) => {
                self.finished = true;
                return Some(Err(e));
            }
        };

        let payload_size_u64 = match self.spec.size_mode {
            ChunkSizeMode::PayloadOnly => raw_size,
            ChunkSizeMode::IncludesHeader => {
                let hdr_u64 = self.spec.header_size as u64;
                if raw_size < hdr_u64 {
                    self.finished = true;
                    return Some(Err(LayoutError::SizeSmallerThanHeader {
                        index,
                        offset: header_offset,
                        declared: raw_size,
                        header_size: self.spec.header_size,
                    }));
                }
                raw_size - hdr_u64
            }
        };

        let payload_size = match usize::try_from(payload_size_u64) {
            Ok(v) => v,
            Err(_) => {
                self.finished = true;
                return Some(Err(LayoutError::Overflow {
                    what: "payload_size",
                }));
            }
        };

        let payload_end = match payload_offset.checked_add(payload_size) {
            Some(end) => end,
            None => {
                self.finished = true;
                return Some(Err(LayoutError::Overflow {
                    what: "payload_end",
                }));
            }
        };
        if payload_end > self.data.len() {
            self.finished = true;
            return Some(Err(LayoutError::OutOfBounds {
                index,
                offset: payload_offset as u64,
                size: payload_size as u64,
                data_len: self.data.len() as u64,
            }));
        }

        let next_pos = if self.spec.alignment == 1 {
            payload_end
        } else {
            let aligned = match checked_align_up_multiple(payload_end, self.spec.alignment) {
                Some(v) => v,
                None => {
                    self.finished = true;
                    return Some(Err(LayoutError::Overflow {
                        what: "chunk_alignment",
                    }));
                }
            };
            if aligned <= self.data.len() {
                aligned
            } else if payload_end == self.data.len() {
                payload_end
            } else {
                self.finished = true;
                return Some(Err(LayoutError::OutOfBounds {
                    index,
                    offset: payload_offset as u64,
                    size: (aligned - payload_offset) as u64,
                    data_len: self.data.len() as u64,
                }));
            }
        };

        if next_pos <= header_offset {
            self.finished = true;
            return Some(Err(LayoutError::ZeroAdvance {
                index,
                offset: header_offset,
            }));
        }

        self.pos = next_pos;
        self.emitted += 1;

        Some(Ok(ChunkEntry {
            tag: tag_slice.to_vec(),
            header_offset,
            payload_offset,
            payload_size,
        }))
    }
}

/// Parse all chunks in `data` described by `spec` with strict checked bounds
/// and zero-advance protection.
pub fn parse_chunk_stream(
    data: &[u8],
    spec: &ChunkStreamSpec,
) -> Result<Vec<ChunkEntry>, LayoutError> {
    let iter = iter_chunk_stream(data, spec)?;
    let mut chunks = Vec::new();
    for item in iter {
        chunks.push(item?);
    }
    Ok(chunks)
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

    #[test]
    fn chunk_stream_parses_aligned_payload_and_header_inclusive_streams() {
        const PAYLOAD_SPEC: ChunkStreamSpec = ChunkStreamSpec {
            start_offset: 4,
            header_size: 12,
            tag_offset: 0,
            tag_len: 4,
            size_field: IntFieldSpec::u32_le(4),
            size_mode: ChunkSizeMode::PayloadOnly,
            alignment: 4,
            terminator_tag: None,
            require_eof_closure: true,
            max_chunks: 16,
        };
        let mut data = Vec::new();
        data.extend_from_slice(b"HDR0"); // 4-byte prologue
                                         // Chunk 0: 12B header (tag + size + aux4), 5B payload + 3B pad = 20B
        data.extend_from_slice(b"AAA0");
        data.extend_from_slice(&5u32.to_le_bytes());
        data.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        data.extend_from_slice(b"hello\0\0\0");
        // Chunk 1: 12B header, 0B payload (must advance by header_size, no loop)
        data.extend_from_slice(b"BBB0");
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());

        let chunks = parse_chunk_stream(&data, &PAYLOAD_SPEC).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].tag, b"AAA0");
        assert_eq!(chunks[0].header_offset, 4);
        assert_eq!(chunks[0].payload_offset, 16);
        assert_eq!(chunks[0].payload_size, 5);
        assert_eq!(chunks[0].payload(&data), Some(&b"hello"[..]));
        assert_eq!(chunks[1].tag, b"BBB0");
        assert_eq!(chunks[1].header_offset, 24);
        assert_eq!(chunks[1].payload_offset, 36);
        assert_eq!(chunks[1].payload_size, 0);

        // Header-inclusive BE stream with 8-byte tag, 16-byte header, and terminator tag
        const INCLUSIVE_SPEC: ChunkStreamSpec = ChunkStreamSpec {
            start_offset: 0,
            header_size: 16,
            tag_offset: 0,
            tag_len: 8,
            size_field: IntFieldSpec::u32_be(8),
            size_mode: ChunkSizeMode::IncludesHeader,
            alignment: 1,
            terminator_tag: Some(b"END_MARK"),
            require_eof_closure: false,
            max_chunks: 16,
        };
        let mut inc = Vec::new();
        inc.extend_from_slice(b"CHUNK001");
        inc.extend_from_slice(&20u32.to_be_bytes()); // 16 hdr + 4 payload
        inc.extend_from_slice(&0u32.to_be_bytes());
        inc.extend_from_slice(b"DATA");
        inc.extend_from_slice(b"END_MARK");
        inc.extend_from_slice(&16u32.to_be_bytes());
        inc.extend_from_slice(&0u32.to_be_bytes());
        inc.extend_from_slice(b"ignored trailing bytes");

        let inc_chunks = parse_chunk_stream(&inc, &INCLUSIVE_SPEC).unwrap();
        assert_eq!(inc_chunks.len(), 1);
        assert_eq!(inc_chunks[0].tag, b"CHUNK001");
        assert_eq!(inc_chunks[0].payload(&inc), Some(&b"DATA"[..]));
    }

    #[test]
    fn chunk_stream_rejects_invalid_specs_smaller_than_header_oob_and_trailing() {
        let zero_hdr = ChunkStreamSpec {
            start_offset: 0,
            header_size: 0,
            tag_offset: 0,
            tag_len: 4,
            size_field: IntFieldSpec::u32_le(0),
            size_mode: ChunkSizeMode::PayloadOnly,
            alignment: 1,
            terminator_tag: None,
            require_eof_closure: true,
            max_chunks: 8,
        };
        assert!(matches!(
            parse_chunk_stream(&[0u8; 8], &zero_hdr),
            Err(LayoutError::InvalidSpec {
                field: "header_size",
                ..
            })
        ));

        let inc_spec = ChunkStreamSpec {
            start_offset: 0,
            header_size: 8,
            tag_offset: 0,
            tag_len: 4,
            size_field: IntFieldSpec::u32_le(4),
            size_mode: ChunkSizeMode::IncludesHeader,
            alignment: 1,
            terminator_tag: None,
            require_eof_closure: true,
            max_chunks: 8,
        };
        // Declared size 0 < header_size 8 (would be zero-advance if unchecked)
        let bad_inc = *b"BAD_\x00\x00\x00\x00";
        assert_eq!(
            parse_chunk_stream(&bad_inc, &inc_spec),
            Err(LayoutError::SizeSmallerThanHeader {
                index: 0,
                offset: 0,
                declared: 0,
                header_size: 8,
            })
        );

        // OOB payload
        let oob = *b"BIG_\x20\x00\x00\x00abcd";
        assert!(matches!(
            parse_chunk_stream(&oob, &inc_spec),
            Err(LayoutError::OutOfBounds { index: 0, .. })
        ));

        // Trailing bytes rejected when require_eof_closure is true
        let trailing = *b"OK__\x08\x00\x00\x00\xAA\xBB";
        assert_eq!(
            parse_chunk_stream(&trailing, &inc_spec),
            Err(LayoutError::TrailingBytes {
                offset: 8,
                remaining: 2,
            })
        );

        // Max chunks exceeded
        let capped = ChunkStreamSpec {
            max_chunks: 0,
            ..inc_spec
        };
        let one = *b"OK__\x08\x00\x00\x00";
        assert_eq!(
            parse_chunk_stream(&one, &capped),
            Err(LayoutError::MaxEntriesExceeded { max: 0 })
        );
    }
}
