//! Checked byte ranges for common resident chunk headers and sequential chunk streams.
//!
//! Single-chunk helpers (`read_payload_chunk`, `read_header_inclusive_chunk`)
//! describe only the physical relationship between a fixed 8-byte header and
//! its bounded payload. [`ChunkStreamSpec`] generalizes sequential tagged or
//! tagless chunk streams with configurable header sizes, alignment, optional
//! terminator tags, zero-allocation iteration, and symmetric packing.

use core::ops::Range;

use formatkit_core::{checked_align_up_multiple, Endian};

use crate::spec::{try_push, IntFieldSpec, LayoutError, PackPolicy};

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
/// # Example
/// ```
/// use formatkit_layout::{
///     parse_chunk_stream, ChunkSizeMode, ChunkStreamSpec, IntFieldSpec,
/// };
///
/// const SPEC: ChunkStreamSpec = ChunkStreamSpec::new(
///     0,
///     8,
///     IntFieldSpec::u32_le(4),
///     ChunkSizeMode::PayloadOnly,
///     64,
/// )
/// .with_tag(0, 4)
/// .with_alignment(4);
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
    /// Non-zero byte multiplier applied to decoded `size_field` values (default `1`).
    pub size_unit: u64,
    /// Whether `size_field` counts only the payload or includes `header_size`.
    pub size_mode: ChunkSizeMode,
    /// Byte alignment for the next chunk start after each payload + trailer (e.g. `1`, `4`, `2048`; must be `>= 1`).
    pub alignment: usize,
    /// Coordinate origin used when applying [`ChunkStreamSpec::alignment`] (default [`ChunkAlignmentBase::CarrierStart`]).
    pub alignment_base: ChunkAlignmentBase,
    /// Fixed number of trailing bytes (e.g. checksum or footer) immediately following each chunk's payload before alignment (default `0`).
    pub trailer_size: usize,
    /// Optional tag that terminates the stream cleanly without being emitted.
    /// Must be `None` when `tag_len == 0`.
    pub terminator_tag: Option<&'static [u8]>,
    /// When `true`, a chunk whose raw `size_field` decodes to `0` terminates the stream cleanly
    /// without being emitted (default `false`).
    pub terminate_on_zero_size: bool,
    /// When `true`, reject trailing bytes shorter than `header_size` at stream end.
    pub require_eof_closure: bool,
    /// Maximum number of chunks accepted before returning [`LayoutError::MaxEntriesExceeded`].
    pub max_chunks: usize,
}

impl ChunkStreamSpec {
    /// Construct a [`ChunkStreamSpec`] with sensible defaults
    /// (`tag_offset: 0`, `tag_len: 0`, `size_unit: 1`, `alignment: 1`,
    /// `alignment_base: ChunkAlignmentBase::CarrierStart`, `trailer_size: 0`,
    /// `terminator_tag: None`, `terminate_on_zero_size: false`, `require_eof_closure: true`).
    #[must_use]
    pub const fn new(
        start_offset: usize,
        header_size: usize,
        size_field: IntFieldSpec,
        size_mode: ChunkSizeMode,
        max_chunks: usize,
    ) -> Self {
        Self {
            start_offset,
            header_size,
            tag_offset: 0,
            tag_len: 0,
            size_field,
            size_unit: 1,
            size_mode,
            alignment: 1,
            alignment_base: ChunkAlignmentBase::CarrierStart,
            trailer_size: 0,
            terminator_tag: None,
            terminate_on_zero_size: false,
            require_eof_closure: true,
            max_chunks,
        }
    }

    /// Set [`ChunkStreamSpec::tag_offset`] and [`ChunkStreamSpec::tag_len`].
    #[must_use]
    pub const fn with_tag(mut self, tag_offset: usize, tag_len: usize) -> Self {
        self.tag_offset = tag_offset;
        self.tag_len = tag_len;
        self
    }

    /// Set [`ChunkStreamSpec::size_unit`].
    #[must_use]
    pub const fn with_size_unit(mut self, unit: u64) -> Self {
        self.size_unit = unit;
        self
    }

    /// Set [`ChunkStreamSpec::alignment`].
    #[must_use]
    pub const fn with_alignment(mut self, alignment: usize) -> Self {
        self.alignment = alignment;
        self
    }

    /// Set [`ChunkStreamSpec::alignment_base`].
    #[must_use]
    pub const fn with_alignment_base(mut self, base: ChunkAlignmentBase) -> Self {
        self.alignment_base = base;
        self
    }

    /// Set [`ChunkStreamSpec::trailer_size`].
    #[must_use]
    pub const fn with_trailer_size(mut self, bytes: usize) -> Self {
        self.trailer_size = bytes;
        self
    }

    /// Set [`ChunkStreamSpec::terminator_tag`].
    #[must_use]
    pub const fn with_terminator_tag(mut self, tag: &'static [u8]) -> Self {
        self.terminator_tag = Some(tag);
        self
    }

    /// Set [`ChunkStreamSpec::terminate_on_zero_size`].
    #[must_use]
    pub const fn with_terminate_on_zero_size(mut self, enabled: bool) -> Self {
        self.terminate_on_zero_size = enabled;
        self
    }

    /// Set [`ChunkStreamSpec::require_eof_closure`].
    #[must_use]
    pub const fn with_require_eof_closure(mut self, require: bool) -> Self {
        self.require_eof_closure = require;
        self
    }
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
    /// Byte length of the fixed trailer following the payload (`0` when no trailer is configured).
    pub trailer_size: usize,
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

    /// Return the checked half-open byte range of this chunk's trailer,
    /// or `None` when [`ChunkView::trailer_size`] is `0` or arithmetic overflows.
    #[must_use]
    pub const fn trailer_range(&self) -> Option<Range<usize>> {
        if self.trailer_size == 0 {
            return None;
        }
        match self.payload_offset.checked_add(self.payload_size) {
            Some(start) => match start.checked_add(self.trailer_size) {
                Some(end) => Some(start..end),
                None => None,
            },
            None => None,
        }
    }

    /// Borrow this chunk's trailer slice from `data`, if configured and in bounds.
    #[must_use]
    pub fn trailer<'d>(&self, data: &'d [u8]) -> Option<&'d [u8]> {
        let range = self.trailer_range()?;
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
            trailer_size: self.trailer_size,
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
    /// Byte length of the fixed trailer following the payload (`0` when no trailer is configured).
    pub trailer_size: usize,
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

    /// Return the checked half-open byte range of this chunk's trailer,
    /// or `None` when [`ChunkEntry::trailer_size`] is `0` or arithmetic overflows.
    #[must_use]
    pub const fn trailer_range(&self) -> Option<Range<usize>> {
        if self.trailer_size == 0 {
            return None;
        }
        match self.payload_offset.checked_add(self.payload_size) {
            Some(start) => match start.checked_add(self.trailer_size) {
                Some(end) => Some(start..end),
                None => None,
            },
            None => None,
        }
    }

    /// Borrow this chunk's trailer slice from `data`, if configured and in bounds.
    #[must_use]
    pub fn trailer<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        let range = self.trailer_range()?;
        data.get(range)
    }
}

/// Zero-allocation checked iterator over sequential chunks described by a [`ChunkStreamSpec`].
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
    if spec.size_unit == 0 {
        return Err(LayoutError::InvalidSpec {
            field: "size_unit",
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
    spec.size_field.validate()?;
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

/// Create a checked, zero-allocation iterator over sequential chunks in `data`.
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

        if self.spec.terminate_on_zero_size && raw_size == 0 {
            self.finished = true;
            return None;
        }

        let scaled_size = match raw_size.checked_mul(self.spec.size_unit) {
            Some(v) => v,
            None => {
                self.finished = true;
                return Some(Err(LayoutError::Overflow { what: "chunk_size" }));
            }
        };

        let payload_size_u64 = match self.spec.size_mode {
            ChunkSizeMode::PayloadOnly => scaled_size,
            ChunkSizeMode::IncludesHeader => {
                let hdr_u64 = self.spec.header_size as u64;
                if scaled_size < hdr_u64 {
                    self.finished = true;
                    return Some(Err(LayoutError::SizeSmallerThanHeader {
                        index,
                        offset: header_offset,
                        declared: scaled_size,
                        header_size: self.spec.header_size,
                    }));
                }
                scaled_size - hdr_u64
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

        let after_trailer = match payload_end.checked_add(self.spec.trailer_size) {
            Some(end) => end,
            None => {
                self.finished = true;
                return Some(Err(LayoutError::Overflow {
                    what: "chunk_trailer",
                }));
            }
        };
        if after_trailer > self.data.len() {
            self.finished = true;
            return Some(Err(LayoutError::OutOfBounds {
                index,
                offset: payload_offset as u64,
                size: (after_trailer - payload_offset) as u64,
                data_len: self.data.len() as u64,
            }));
        }

        let next_pos = if self.spec.alignment == 1 {
            after_trailer
        } else {
            let aligned = match align_chunk_end(
                after_trailer,
                self.spec.start_offset,
                self.spec.alignment,
                self.spec.alignment_base,
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
            } else if after_trailer == self.data.len() {
                after_trailer
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
            trailer_size: self.spec.trailer_size,
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
        try_push(&mut chunks, item?.to_owned_entry())?;
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
    /// Optional raw `trailer_size`-byte trailer written immediately after `payload`.
    /// When `None` and `spec.trailer_size > 0`, the trailer region is filled with [`PackPolicy::pad_byte`].
    pub trailer: Option<&'a [u8]>,
}

/// Serialize `chunks` into a sequential chunk stream conforming to `spec` and `policy`.
pub fn pack_chunk_stream(
    spec: &ChunkStreamSpec,
    policy: &PackPolicy,
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
    out.try_reserve(spec.start_offset)
        .map_err(|_| LayoutError::AllocationFailed {
            requested: spec.start_offset,
        })?;
    out.extend_from_slice(header_prefix);
    out.resize(spec.start_offset, policy.prefix_fill_byte);

    let mut header_buf = Vec::new();
    header_buf
        .try_reserve_exact(spec.header_size)
        .map_err(|_| LayoutError::AllocationFailed {
            requested: spec.header_size,
        })?;
    header_buf.resize(spec.header_size, policy.record_fill_byte);

    let has_terminator = spec.terminator_tag.is_some() || spec.terminate_on_zero_size;

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
        if let Some(trailer_bytes) = chunk.trailer {
            if trailer_bytes.len() != spec.trailer_size {
                return Err(LayoutError::InvalidInput {
                    index,
                    reason: "trailer length must equal trailer_size",
                });
            }
        }

        let declared_bytes = match spec.size_mode {
            ChunkSizeMode::PayloadOnly => chunk.payload.len() as u64,
            ChunkSizeMode::IncludesHeader => (spec.header_size as u64)
                .checked_add(chunk.payload.len() as u64)
                .ok_or(LayoutError::Overflow { what: "chunk_size" })?,
        };
        if !declared_bytes.is_multiple_of(spec.size_unit) {
            return Err(LayoutError::InvalidInput {
                index,
                reason: "chunk size is not a multiple of size_unit",
            });
        }
        let raw_size = declared_bytes / spec.size_unit;
        if spec.terminate_on_zero_size && raw_size == 0 {
            return Err(LayoutError::InvalidInput {
                index,
                reason: "zero-size chunk collides with terminate_on_zero_size",
            });
        }

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
        spec.size_field.write(&mut header_buf, raw_size)?;

        let chunk_bytes = spec
            .header_size
            .checked_add(chunk.payload.len())
            .and_then(|n| n.checked_add(spec.trailer_size))
            .ok_or(LayoutError::Overflow {
                what: "chunk_trailer",
            })?;
        out.try_reserve(chunk_bytes)
            .map_err(|_| LayoutError::AllocationFailed {
                requested: out.len().saturating_add(chunk_bytes),
            })?;
        out.extend_from_slice(&header_buf);
        out.extend_from_slice(chunk.payload);
        if let Some(trailer_bytes) = chunk.trailer {
            out.extend_from_slice(trailer_bytes);
        } else if spec.trailer_size > 0 {
            let new_len =
                out.len()
                    .checked_add(spec.trailer_size)
                    .ok_or(LayoutError::Overflow {
                        what: "chunk_trailer",
                    })?;
            out.resize(new_len, policy.pad_byte);
        }

        let needs_align = index + 1 < chunks.len() || has_terminator || policy.pad_final_entry;
        if needs_align && spec.alignment > 1 {
            let aligned = align_chunk_end(
                out.len(),
                spec.start_offset,
                spec.alignment,
                spec.alignment_base,
            )
            .ok_or(LayoutError::Overflow {
                what: "chunk_alignment",
            })?;
            out.try_reserve(aligned.saturating_sub(out.len()))
                .map_err(|_| LayoutError::AllocationFailed { requested: aligned })?;
            out.resize(aligned, policy.pad_byte);
        }
    }

    if let Some(term_tag) = spec.terminator_tag {
        header_buf.fill(policy.record_fill_byte);
        header_buf[spec.tag_offset..spec.tag_offset + spec.tag_len].copy_from_slice(term_tag);
        let term_raw_size = if spec.terminate_on_zero_size {
            0u64
        } else {
            let term_bytes = match spec.size_mode {
                ChunkSizeMode::PayloadOnly => 0u64,
                ChunkSizeMode::IncludesHeader => spec.header_size as u64,
            };
            if !term_bytes.is_multiple_of(spec.size_unit) {
                return Err(LayoutError::InvalidInput {
                    index: chunks.len(),
                    reason: "terminator header_size is not a multiple of size_unit",
                });
            }
            term_bytes / spec.size_unit
        };
        spec.size_field.write(&mut header_buf, term_raw_size)?;
        out.try_reserve(header_buf.len())
            .map_err(|_| LayoutError::AllocationFailed {
                requested: out.len().saturating_add(header_buf.len()),
            })?;
        out.extend_from_slice(&header_buf);
    } else if spec.terminate_on_zero_size {
        header_buf.fill(policy.record_fill_byte);
        spec.size_field.write(&mut header_buf, 0)?;
        out.try_reserve(header_buf.len())
            .map_err(|_| LayoutError::AllocationFailed {
                requested: out.len().saturating_add(header_buf.len()),
            })?;
        out.extend_from_slice(&header_buf);
    }

    if policy.pad_final_entry && policy.data_alignment > 1 {
        let aligned = checked_align_up_multiple(out.len(), policy.data_alignment).ok_or(
            LayoutError::Overflow {
                what: "data_alignment",
            },
        )?;
        out.try_reserve(aligned.saturating_sub(out.len()))
            .map_err(|_| LayoutError::AllocationFailed { requested: aligned })?;
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
        const PAYLOAD_SPEC: ChunkStreamSpec = ChunkStreamSpec::new(
            4,
            12,
            IntFieldSpec::u32_le(4),
            ChunkSizeMode::PayloadOnly,
            16,
        )
        .with_tag(0, 4)
        .with_alignment(4);

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
        assert_eq!(chunks[0].trailer_range(), None);
        assert_eq!(chunks[0].payload(&data), Some(&b"hello"[..]));
        assert_eq!(chunks[1].tag, b"BBB0");
        assert_eq!(chunks[1].header_offset, 24);
        assert_eq!(chunks[1].payload_offset, 36);
        assert_eq!(chunks[1].payload_size, 0);

        const INCLUSIVE_SPEC: ChunkStreamSpec = ChunkStreamSpec::new(
            0,
            16,
            IntFieldSpec::u32_be(8),
            ChunkSizeMode::IncludesHeader,
            16,
        )
        .with_tag(0, 8)
        .with_terminator_tag(b"END_MARK")
        .with_require_eof_closure(false);

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
        const TAGLESS_SPEC: ChunkStreamSpec = ChunkStreamSpec::new(
            3, // intentionally unaligned relative to byte 0
            4,
            IntFieldSpec::u32_le(0),
            ChunkSizeMode::PayloadOnly,
            16,
        )
        .with_alignment(4)
        .with_alignment_base(ChunkAlignmentBase::StreamStart);

        let inputs = [
            ChunkInput {
                tag: &[],
                payload: b"abc",
                header_template: None,
                trailer: None,
            },
            ChunkInput {
                tag: &[],
                payload: b"12345",
                header_template: None,
                trailer: None,
            },
        ];
        let packed = pack_chunk_stream(&TAGLESS_SPEC, &PackPolicy::TIGHT, b"PRE", &inputs).unwrap();
        let views: Vec<_> = iter_chunk_stream(&packed, &TAGLESS_SPEC)
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
            trailer_size: 4,
        };
        assert_eq!(bad.payload_range(), None);
        assert_eq!(bad.trailer_range(), None);
    }

    #[test]
    fn pack_chunk_stream_round_trips_templates_terminator_and_rejects_overflow() {
        const SPEC: ChunkStreamSpec = ChunkStreamSpec::new(
            4,
            12,
            IntFieldSpec::u16_be(4),
            ChunkSizeMode::IncludesHeader,
            16,
        )
        .with_tag(0, 4)
        .with_alignment(4)
        .with_terminator_tag(b"END!");

        let mut tmpl = [0u8; 12];
        tmpl[6..12].copy_from_slice(b"AUX123");
        let policy = PackPolicy::TIGHT
            .with_pad_byte(0xAA)
            .with_prefix_fill_byte(0xFF);
        let chunks = [
            ChunkInput {
                tag: b"ONE_",
                payload: b"hello",
                header_template: Some(&tmpl),
                trailer: None,
            },
            ChunkInput {
                tag: b"TWO_",
                payload: b"world!",
                header_template: None,
                trailer: None,
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
            trailer: None,
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
        let zero_hdr =
            ChunkStreamSpec::new(0, 0, IntFieldSpec::u32_le(0), ChunkSizeMode::PayloadOnly, 8)
                .with_tag(0, 4);
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

        let zero_unit =
            ChunkStreamSpec::new(0, 8, IntFieldSpec::u32_le(4), ChunkSizeMode::PayloadOnly, 8)
                .with_size_unit(0);
        assert!(matches!(
            parse_chunk_stream(&[0u8; 8], &zero_unit),
            Err(LayoutError::InvalidSpec {
                field: "size_unit",
                ..
            })
        ));

        let inc_spec = ChunkStreamSpec::new(
            0,
            8,
            IntFieldSpec::u32_le(4),
            ChunkSizeMode::IncludesHeader,
            8,
        )
        .with_tag(0, 4);
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

    #[test]
    fn chunk_stream_trailer_size_unit_and_zero_size_termination() {
        // 1. Explicit trailer bytes round-trip with trailer_range() and trailer()
        const SPEC: ChunkStreamSpec = ChunkStreamSpec::new(
            0,
            8,
            IntFieldSpec::u32_le(4),
            ChunkSizeMode::PayloadOnly,
            16,
        )
        .with_tag(0, 4)
        .with_trailer_size(4)
        .with_alignment(8);

        let policy = PackPolicy::TIGHT.with_pad_byte(0xCC);
        let inputs = [
            ChunkInput {
                tag: b"CHK0",
                payload: b"abc", // 8 hdr + 3 payload + 4 trailer = 15 -> aligned to 16
                header_template: None,
                trailer: Some(b"CRC0"),
            },
            ChunkInput {
                tag: b"CHK1",
                payload: b"WXYZ", // 8 hdr + 4 payload + 4 trailer = 16 -> ends at 32
                header_template: None,
                trailer: None, // filled with pad_byte 0xCC
            },
        ];
        let packed = pack_chunk_stream(&SPEC, &policy, &[], &inputs).unwrap();
        assert_eq!(packed.len(), 32);
        assert_eq!(&packed[11..15], b"CRC0");
        assert_eq!(packed[15], 0xCC);
        assert_eq!(&packed[28..32], &[0xCC; 4]);

        let parsed = parse_chunk_stream(&packed, &SPEC).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].header_offset, 0);
        assert_eq!(parsed[0].payload(&packed), Some(&b"abc"[..]));
        assert_eq!(parsed[0].trailer_range(), Some(11..15));
        assert_eq!(parsed[0].trailer(&packed), Some(&b"CRC0"[..]));
        assert_eq!(parsed[1].header_offset, 16);
        assert_eq!(parsed[1].payload(&packed), Some(&b"WXYZ"[..]));
        assert_eq!(parsed[1].trailer_range(), Some(28..32));
        assert_eq!(parsed[1].trailer(&packed), Some(&[0xCC; 4][..]));

        // Truncated trailer on final chunk is rejected
        assert!(matches!(
            parse_chunk_stream(&packed[..30], &SPEC),
            Err(LayoutError::OutOfBounds { index: 1, .. })
        ));

        // Overflowing trailer_size is rejected
        let overflow_spec = SPEC.with_trailer_size(usize::MAX);
        assert_eq!(
            parse_chunk_stream(&packed, &overflow_spec),
            Err(LayoutError::Overflow {
                what: "chunk_trailer"
            })
        );

        // Wrong trailer length on pack is rejected
        let bad_trailer = [ChunkInput {
            tag: b"CHK0",
            payload: b"abc",
            header_template: None,
            trailer: Some(b"SHORT"),
        }];
        assert!(matches!(
            pack_chunk_stream(&SPEC, &policy, &[], &bad_trailer),
            Err(LayoutError::InvalidInput { index: 0, .. })
        ));

        // 2. size_unit scaling + terminate_on_zero_size round-trip
        const UNIT_TERM_SPEC: ChunkStreamSpec = ChunkStreamSpec::new(
            0,
            4,
            IntFieldSpec::u32_le(0),
            ChunkSizeMode::PayloadOnly,
            16,
        )
        .with_size_unit(4)
        .with_terminate_on_zero_size(true);

        let unit_inputs = [
            ChunkInput {
                tag: &[],
                payload: b"ABCD",
                header_template: None,
                trailer: None,
            },
            ChunkInput {
                tag: &[],
                payload: b"12345678",
                header_template: None,
                trailer: None,
            },
        ];
        let mut unit_packed =
            pack_chunk_stream(&UNIT_TERM_SPEC, &PackPolicy::TIGHT, &[], &unit_inputs).unwrap();
        // Verify stored raw sizes are 1 (4/4), 2 (8/4), and terminator 0
        assert_eq!(u32::from_le_bytes(unit_packed[0..4].try_into().unwrap()), 1);
        assert_eq!(
            u32::from_le_bytes(unit_packed[8..12].try_into().unwrap()),
            2
        );
        assert_eq!(
            u32::from_le_bytes(unit_packed[20..24].try_into().unwrap()),
            0
        );
        // Trailing bytes after zero-size terminator are ignored
        unit_packed.extend_from_slice(b"TRAILING");

        let unit_parsed = parse_chunk_stream(&unit_packed, &UNIT_TERM_SPEC).unwrap();
        assert_eq!(unit_parsed.len(), 2);
        assert_eq!(unit_parsed[0].payload(&unit_packed), Some(&b"ABCD"[..]));
        assert_eq!(unit_parsed[1].payload(&unit_packed), Some(&b"12345678"[..]));

        // Reject non-multiple of size_unit and zero-size payload under terminate_on_zero_size
        let bad_unit_in = [ChunkInput {
            tag: &[],
            payload: b"ABC",
            header_template: None,
            trailer: None,
        }];
        assert!(matches!(
            pack_chunk_stream(&UNIT_TERM_SPEC, &PackPolicy::TIGHT, &[], &bad_unit_in),
            Err(LayoutError::InvalidInput { index: 0, .. })
        ));
        let zero_in = [ChunkInput {
            tag: &[],
            payload: b"",
            header_template: None,
            trailer: None,
        }];
        assert!(matches!(
            pack_chunk_stream(&UNIT_TERM_SPEC, &PackPolicy::TIGHT, &[], &zero_in),
            Err(LayoutError::InvalidInput { index: 0, .. })
        ));
    }
}
