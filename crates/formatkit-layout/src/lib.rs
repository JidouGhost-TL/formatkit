//! Configured, reusable descriptions of binary fields and layout ranges.
//!
//! `formatkit-layout` describes repeatable relationships among resident bytes. Raw
//! checked reads, numeric decoding, and source coordinates remain in
//! [`formatkit_core`]; format identity, semantic validation, limits, diagnostics,
//! and capabilities remain with each format owner.
//!
//! The API deliberately contains only concrete field descriptors and checked
//! layout relationships. It is not a runtime schema language and performs no
//! source I/O.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod chunks;
pub mod edit;
pub mod field;
pub mod ranges;
pub mod records;
pub mod tables;
pub mod text;

pub use chunks::{
    read_header_inclusive_chunk, read_payload_chunk, InclusiveChunkError, InclusiveChunkSpan,
    PayloadChunkError, PayloadChunkSpan,
};
pub use edit::{patch_bytes, patched_bytes, same_size_splice, SameSizeSpliceError};
pub use field::{
    BytesField, F32ArrayField, F32Field, I16ArrayField, I16Field, I32ArrayField, I32Field, I8Field,
    ScaledU32Field, U16ArrayField, U16Field, U32ArrayField, U32Field, U64Field, U8Field,
};
pub use ranges::{
    audit_exact_tiling, audit_ordered_contiguous_run, audit_ordered_non_overlapping,
    checked_align_up_u64, child_run, nondecreasing_successor_ranges, strict_successor_ranges,
    ChildRunError, NondecreasingSuccessorRangesError, OrderedExtentError, SuccessorRangesError,
};
pub use records::{FixedRecords, RecordOverflow};
pub use tables::{
    AlignedSizeChain, AlignedSizeCursor, AlignedSizeError, AlignedSizeExtent, CountedBoundaryError,
    CountedBoundaryTable, DerivedAlignedSizes, FirstWordOffsetError, FirstWordOffsetTable,
    OffsetLengthRow, OffsetLengthRows, PositiveSizeError, PositiveSizeExtent, PositiveSizeList,
    SizeAlignment, TerminalOffsetError, TerminalOffsetTable, ValidatedCountedBoundaries,
    ValidatedPositiveSizes, ValidatedTerminalOffsets,
};
pub use text::FixedByteStringField;
