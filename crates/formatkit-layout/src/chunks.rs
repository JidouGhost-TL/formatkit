//! Checked byte ranges for common resident chunk headers and sequential chunk streams.
//!
//! Single-chunk helpers (`read_payload_chunk`, `read_header_inclusive_chunk`)
//! describe only the physical relationship between a fixed 8-byte header and
//! its bounded payload. [`ChunkStreamSpec`] generalizes sequential tagged or
//! tagless chunk streams with configurable header sizes, alignment, optional
//! terminator tags, zero-allocation iteration, and symmetric packing.

use core::ops::Range;

use formatkit_core::{checked_align_up_multiple, Endian};

use crate::spec::{IntFieldSpec, LayoutError, PackPolicy};

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

/// Coordinate origin used when aligning the next chunk start in a [`ChunkStreamSpec`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChunkAlignmentBase {
    /// Align `payload_end` relative to byte `0` of the carrier buffer (default).
    #[default]
    CarrierStart,
    /// Align `payload_end - spec.start_offset` relative to [`ChunkStreamSpec::start_offset`].
    StreamStart,
}

/// `const`-constructible declarative specification for sequential tagged or
/// tagless chunk streams.
///
/// When [`ChunkStreamSpec::alignment`] is greater than `1`, [`iter_chunk_stream`],
/// [`parse_chunk_stream`], and [`pack_chunk_stream`] align offsets relative to
/// byte `0` of the carrier ([`ChunkAlignmentBase::CarrierStart`]). Use
/// [`iter_chunk_stream_with_alignment_base`],
/// [`parse_chunk_stream_with_alignment_base`], or
/// [`pack_chunk_stream_with_alignment_base`] to align relative to
/// [`ChunkStreamSpec::start_offset`] instead.
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
    /// Byte length of the tag within each chunk header (`0` for tagless streams,
    /// or e.g. `4` / `8` for tagged streams).
    pub tag_len: usize,
    /// Integer field inside each chunk header carrying the chunk size.
    pub size_field: IntFieldSpec,
    /// Whether `size_field` counts only the payload or includes `header_size`.
    pub size_mode: ChunkSizeMode,
    /// Byte alignment for the next chunk start after each payload (e.g. `1`, `4`, `2048`; must be `>= 1`).
    pub alignment: usize,
    /// Optional tag that terminates the stream cleanly without being emitted.
    /// Must be `None` when `tag_len == 0`.
    pub terminator_tag: Option<&'static [u8]>,
    /// When `true`, reject trailing bytes shorter than `header_size` at stream end.
    pub require_eof_closure: bool,
    /// Maximum number of chunks accepted before returning [`LayoutError::MaxEntriesExceeded`].
    pub max_chunks: usize,
}

/// Zero-allocation borrowed view of one validated chunk decoded from a [`ChunkStreamSpec`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkView<'a> {
    /// Borrowed tag bytes (length equals [`ChunkStreamSpec::tag_len`]; empty for tagless streams).
    pub tag: &'a [u8],
    /// Byte offset of the chunk header within the input slice.
    pub header_offset: usize,
    /// Byte offset of the chunk payload (`header_offset + header_size`).
    pub payload_offset: usize,
    /// Byte length of the chunk payload.
    pub payload_size: usize,
}

impl<'a> ChunkView<'a> {
    /// Return the checked half-open byte range of this chunk's payload.
    #[must_use]
    pub const fn payload_range(&self) -> Option<Range<usize>> {
        match self.payload_offset.checked_add(self.payload_size) {
            Some(end) => Some(self.payload_offset..end),
            None => None,
        }
    }

    /// Borrow this chunk's payload slice from `data`.
    #[must_use]
    pub fn payload<'d>(&self, data: &'d [u8]) -> Option<&'d [u8]> {
        let range = self.payload_range()?;
        data.get(range)
    }

    /// Convert this borrowed view into an owned [`ChunkEntry`].
    #[must_use]
    pub fn to_owned_entry(&self) -> ChunkEntry {
        ChunkEntry {
            tag: self.tag.to_vec(),
            header_offset: self.header_offset,
            payload_offset: self.payload_offset,
            payload_size: self.payload_size,
        }
    }
}

impl From<ChunkView<'_>> for ChunkEntry {
    fn from(view: ChunkView<'_>) -> Self {
        view.to_owned_entry()
    }
}

/// One validated owned chunk decoded from a [`ChunkStreamSpec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkEntry {
    /// Decoded tag bytes (length equals [`ChunkStreamSpec::tag_len`]; empty for tagless streams).
    pub tag: Vec<u8>,
    /// Byte offset of the chunk header within the input slice.
    pub header_offset: usize,
    /// Byte offset of the chunk payload (`header_offset + header_size`).
    pub payload_offset: usize,
    /// Byte length of the chunk payload.
    pub payload_size: usize,
}

impl ChunkEntry {
    /// Return the checked half-open byte range of this chunk's payload.
    #[must_use]
    pub const fn payload_range(&self) -> Option<Range<usize>> {
        match self.payload_offset.checked_add(self.payload_size) {
            Some(end) => Some(self.payload_offset..end),
            None => None,
        }
    }

    /// Borrow this chunk's payload slice from `data`.
    #[must_use]
    pub fn payload<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        let range = self.payload_range()?;
        data.get(range)
    }
}

/// Zero-allocation checked iterator over sequential chunks described by a [`ChunkStreamSpec`].
#[derive(Debug, Clone)]
pub struct ChunkStreamIter<'a> {
    data: &'a [u8],
    spec: ChunkStreamSpec,
    alignment_base: ChunkAlignmentBase,
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
        if spec.tag_len == 0 {
            return Err(LayoutError::InvalidSpec {
                field: "terminator_tag",
                reason: "terminator_tag requires nonzero tag_len",
            });
        }
        if term.len() != spec.tag_len {
            return Err(LayoutError::InvalidSpec {
                field: "terminator_tag",
                reason: "terminator_tag length must equal tag_len",
            });
        }
    }
    Ok(())
}

fn align_chunk_end(
    payload_end: usize,
    start_offset: usize,
    alignment: usize,
    base: ChunkAlignmentBase,
) -> Option<usize> {
    if alignment <= 1 {
        return Some(payload_end);
    }
    match base {
        ChunkAlignmentBase::CarrierStart => checked_align_up_multiple(payload_end, alignment),
        ChunkAlignmentBase::StreamStart => {
            let rel = payload_end.checked_sub(start_offset)?;
            let aligned_rel = checked_align_up_multiple(rel, alignment)?;
            start_offset.checked_add(aligned_rel)
        }
    }
}

/// Create a checked, zero-allocation iterator over sequential chunks in `data`
/// using [`ChunkAlignmentBase::CarrierStart`].
pub fn iter_chunk_stream<'a>(
    data: &'a [u8],
    spec: &ChunkStreamSpec,
) -> Result<ChunkStreamIter<'a>, LayoutError> {
    iter_chunk_stream_with_alignment_base(data, spec, ChunkAlignmentBase::CarrierStart)
}

/// Create a checked, zero-allocation iterator over sequential chunks in `data`
/// with an explicit [`ChunkAlignmentBase`].
pub fn iter_chunk_stream_with_alignment_base<'a>(
    data: &'a [u8],
    spec: &ChunkStreamSpec,
    alignment_base: ChunkAlignmentBase,
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
        alignment_base,
        pos: spec.start_offset,
        emitted: 0,
        finished: false,
    })
}

impl<'a> Iterator for ChunkStreamIter<'a> {
    type Item = Result<ChunkView<'a>, LayoutError>;

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

        if self.spec.tag_len > 0 && self.spec.terminator_tag == Some(tag_slice) {
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
            let aligned = match align_chunk_end(
                payload_end,
                self.spec.start_offset,
                self.spec.alignment,
                self.alignment_base,
            ) {
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

        Some(Ok(ChunkView {
            tag: tag_slice,
            header_offset,
            payload_offset,
            payload_size,
        }))
    }
}

/// Parse all chunks in `data` described by `spec` with strict checked bounds
/// and zero-advance protection, using [`ChunkAlignmentBase::CarrierStart`].
pub fn parse_chunk_stream(
    data: &[u8],
    spec: &ChunkStreamSpec,
) -> Result<Vec<ChunkEntry>, LayoutError> {
    parse_chunk_stream_with_alignment_base(data, spec, ChunkAlignmentBase::CarrierStart)
}

/// Parse all chunks in `data` described by `spec` with an explicit [`ChunkAlignmentBase`].
pub fn parse_chunk_stream_with_alignment_base(
    data: &[u8],
    spec: &ChunkStreamSpec,
    alignment_base: ChunkAlignmentBase,
) -> Result<Vec<ChunkEntry>, LayoutError> {
    let iter = iter_chunk_stream_with_alignment_base(data, spec, alignment_base)?;
    let mut chunks = Vec::new();
    for item in iter {
        chunks.push(item?.to_owned_entry());
    }
    Ok(chunks)
}

/// One chunk supplied to [`pack_chunk_stream`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkInput<'a> {
    /// Chunk tag bytes (length must equal [`ChunkStreamSpec::tag_len`]; empty for tagless streams).
    pub tag: &'a [u8],
    /// Chunk payload bytes.
    pub payload: &'a [u8],
    /// Optional raw `header_size`-byte header template copied before writing tag and size fields
    /// (preserving owner-specific flags, versions, or auxiliary header fields).
    pub header_template: Option<&'a [u8]>,
}

/// Serialize `chunks` into a sequential chunk stream conforming to `spec` and `policy`
/// using [`ChunkAlignmentBase::CarrierStart`].
pub fn pack_chunk_stream(
    spec: &ChunkStreamSpec,
    policy: &PackPolicy,
    header_prefix: &[u8],
    chunks: &[ChunkInput<'_>],
) -> Result<Vec<u8>, LayoutError> {
    pack_chunk_stream_with_alignment_base(
        spec,
        policy,
        ChunkAlignmentBase::CarrierStart,
        header_prefix,
        chunks,
    )
}

/// Serialize `chunks` into a sequential chunk stream conforming to `spec`,
/// `policy`, and `alignment_base`.
pub fn pack_chunk_stream_with_alignment_base(
    spec: &ChunkStreamSpec,
    policy: &PackPolicy,
    alignment_base: ChunkAlignmentBase,
    header_prefix: &[u8],
    chunks: &[ChunkInput<'_>],
) -> Result<Vec<u8>, LayoutError> {
    validate_chunk_stream_spec(spec)?;
    policy.validate()?;

    if chunks.len() > spec.max_chunks {
        return Err(LayoutError::MaxEntriesExceeded {
            max: spec.max_chunks,
        });
    }
    if header_prefix.len() > spec.start_offset {
        return Err(LayoutError::InvalidInput {
            index: 0,
            reason: "header_prefix exceeds start_offset",
        });
    }

    let mut out = Vec::new();
    out.extend_from_slice(header_prefix);
    out.resize(spec.start_offset, policy.prefix_fill_byte);

    let mut header_buf = vec![policy.record_fill_byte; spec.header_size];

    for (index, chunk) in chunks.iter().enumerate() {
        if chunk.tag.len() != spec.tag_len {
            return Err(LayoutError::InvalidInput {
                index,
                reason: "chunk tag length must equal tag_len",
            });
        }
        if spec.tag_len > 0 && spec.terminator_tag == Some(chunk.tag) {
            return Err(LayoutError::InvalidInput {
                index,
                reason: "chunk tag collides with terminator_tag",
            });
        }

        let declared_size = match spec.size_mode {
            ChunkSizeMode::PayloadOnly => chunk.payload.len() as u64,
            ChunkSizeMode::IncludesHeader => (spec.header_size as u64)
                .checked_add(chunk.payload.len() as u64)
                .ok_or(LayoutError::Overflow { what: "chunk_size" })?,
        };

        if let Some(tmpl) = chunk.header_template {
            if tmpl.len() != spec.header_size {
                return Err(LayoutError::InvalidInput {
                    index,
                    reason: "header_template length must equal header_size",
                });
            }
            header_buf.copy_from_slice(tmpl);
        } else {
            header_buf.fill(policy.record_fill_byte);
        }

        if spec.tag_len > 0 {
            header_buf[spec.tag_offset..spec.tag_offset + spec.tag_len].copy_from_slice(chunk.tag);
        }
        spec.size_field.write(&mut header_buf, declared_size)?;

        out.extend_from_slice(&header_buf);
        out.extend_from_slice(chunk.payload);

        let needs_align =
            index + 1 < chunks.len() || spec.terminator_tag.is_some() || policy.pad_final_entry;
        if needs_align && spec.alignment > 1 {
            let aligned =
                align_chunk_end(out.len(), spec.start_offset, spec.alignment, alignment_base)
                    .ok_or(LayoutError::Overflow {
                        what: "chunk_alignment",
                    })?;
            out.resize(aligned, policy.pad_byte);
        }
    }

    if let Some(term_tag) = spec.terminator_tag {
        header_buf.fill(policy.record_fill_byte);
        header_buf[spec.tag_offset..spec.tag_offset + spec.tag_len].copy_from_slice(term_tag);
        let term_size = match spec.size_mode {
            ChunkSizeMode::PayloadOnly => 0u64,
            ChunkSizeMode::IncludesHeader => spec.header_size as u64,
        };
        spec.size_field.write(&mut header_buf, term_size)?;
        out.extend_from_slice(&header_buf);
    }

    if policy.pad_final_entry && policy.data_alignment > 1 {
        let aligned = checked_align_up_multiple(out.len(), policy.data_alignment).ok_or(
            LayoutError::Overflow {
                what: "data_alignment",
            },
        )?;
        out.resize(aligned, policy.pad_byte);
    }

    Ok(out)
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
        data.extend_from_slice(b"HDR0");
        data.extend_from_slice(b"AAA0");
        data.extend_from_slice(&5u32.to_le_bytes());
        data.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        data.extend_from_slice(b"hello\0\0\0");
        data.extend_from_slice(b"BBB0");
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());

        let chunks = parse_chunk_stream(&data, &PAYLOAD_SPEC).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].tag, b"AAA0");
        assert_eq!(chunks[0].header_offset, 4);
        assert_eq!(chunks[0].payload_offset, 16);
        assert_eq!(chunks[0].payload_size, 5);
        assert_eq!(chunks[0].payload_range(), Some(16..21));
        assert_eq!(chunks[0].payload(&data), Some(&b"hello"[..]));
        assert_eq!(chunks[1].tag, b"BBB0");
        assert_eq!(chunks[1].header_offset, 24);
        assert_eq!(chunks[1].payload_offset, 36);
        assert_eq!(chunks[1].payload_size, 0);

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
        inc.extend_from_slice(&20u32.to_be_bytes());
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
    fn chunk_stream_supports_tagless_and_stream_start_alignment_and_checked_range() {
        const TAGLESS_SPEC: ChunkStreamSpec = ChunkStreamSpec {
            start_offset: 3, // intentionally unaligned relative to byte 0
            header_size: 4,
            tag_offset: 0,
            tag_len: 0,
            size_field: IntFieldSpec::u32_le(0),
            size_mode: ChunkSizeMode::PayloadOnly,
            alignment: 4,
            terminator_tag: None,
            require_eof_closure: true,
            max_chunks: 16,
        };

        let inputs = [
            ChunkInput {
                tag: &[],
                payload: b"abc",
                header_template: None,
            },
            ChunkInput {
                tag: &[],
                payload: b"12345",
                header_template: None,
            },
        ];
        let packed = pack_chunk_stream_with_alignment_base(
            &TAGLESS_SPEC,
            &PackPolicy::TIGHT,
            ChunkAlignmentBase::StreamStart,
            b"PRE",
            &inputs,
        )
        .unwrap();
        let views: Vec<_> = iter_chunk_stream_with_alignment_base(
            &packed,
            &TAGLESS_SPEC,
            ChunkAlignmentBase::StreamStart,
        )
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
        assert_eq!(views.len(), 2);
        assert_eq!(views[0].tag, b"");
        assert_eq!(views[0].payload(&packed), Some(&b"abc"[..]));
        assert_eq!(views[1].header_offset, 3 + 8); // aligned to 4 relative to start_offset=3
        assert_eq!(views[1].payload(&packed), Some(&b"12345"[..]));

        // Overflowing ChunkEntry::payload_range returns None without panicking
        let bad = ChunkEntry {
            tag: Vec::new(),
            header_offset: 0,
            payload_offset: usize::MAX,
            payload_size: 1,
        };
        assert_eq!(bad.payload_range(), None);
    }

    #[test]
    fn pack_chunk_stream_round_trips_templates_terminator_and_rejects_overflow() {
        const SPEC: ChunkStreamSpec = ChunkStreamSpec {
            start_offset: 4,
            header_size: 12,
            tag_offset: 0,
            tag_len: 4,
            size_field: IntFieldSpec::u16_be(4),
            size_mode: ChunkSizeMode::IncludesHeader,
            alignment: 4,
            terminator_tag: Some(b"END!"),
            require_eof_closure: true,
            max_chunks: 16,
        };
        let mut tmpl = [0u8; 12];
        tmpl[6..12].copy_from_slice(b"AUX123");
        let policy = PackPolicy {
            data_alignment: 1,
            pad_byte: 0xAA,
            record_fill_byte: 0x00,
            pad_final_entry: false,
            prefix_fill_byte: 0xFF,
        };
        let chunks = [
            ChunkInput {
                tag: b"ONE_",
                payload: b"hello",
                header_template: Some(&tmpl),
            },
            ChunkInput {
                tag: b"TWO_",
                payload: b"world!",
                header_template: None,
            },
        ];
        let packed = pack_chunk_stream(&SPEC, &policy, b"PF", &chunks).unwrap();
        assert_eq!(&packed[0..4], b"PF\xFF\xFF");
        assert_eq!(&packed[4 + 6..4 + 12], b"AUX123");

        let parsed = parse_chunk_stream(&packed, &SPEC).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].tag, b"ONE_");
        assert_eq!(parsed[0].payload(&packed), Some(&b"hello"[..]));
        assert_eq!(parsed[1].tag, b"TWO_");
        assert_eq!(parsed[1].payload(&packed), Some(&b"world!"[..]));

        // U16 size overflow rejected
        let huge = vec![0u8; 70_000];
        let overflow_chunk = [ChunkInput {
            tag: b"BIG_",
            payload: &huge,
            header_template: None,
        }];
        assert_eq!(
            pack_chunk_stream(&SPEC, &PackPolicy::TIGHT, &[], &overflow_chunk),
            Err(LayoutError::ValueOutOfRange {
                value: 70_012,
                max: u16::MAX as u64,
            })
        );
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

        let tagless_with_term = ChunkStreamSpec {
            header_size: 4,
            tag_len: 0,
            terminator_tag: Some(b""),
            ..zero_hdr
        };
        assert!(matches!(
            parse_chunk_stream(&[0u8; 8], &tagless_with_term),
            Err(LayoutError::InvalidSpec {
                field: "terminator_tag",
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

        let oob = *b"BIG_\x20\x00\x00\x00abcd";
        assert!(matches!(
            parse_chunk_stream(&oob, &inc_spec),
            Err(LayoutError::OutOfBounds { index: 0, .. })
        ));

        let trailing = *b"OK__\x08\x00\x00\x00\xAA\xBB";
        assert_eq!(
            parse_chunk_stream(&trailing, &inc_spec),
            Err(LayoutError::TrailingBytes {
                offset: 8,
                remaining: 2,
            })
        );

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
