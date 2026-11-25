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

/// Header-inclusive and payload-sized tagged or tagless chunk spans and streams.
pub mod chunks;
/// Checked in-place patching and same-size splicing on resident byte slices.
pub mod edit;
/// Typed scalar, array, and fixed-byte field descriptors.
pub mod field;
/// Generic IFF `FORM` and RIFF container chunk parsing.
pub mod iff;
/// Aligned magic-marker delimited stream scanning and packing.
pub mod marker_scan;
/// Claimed-byte reading and conflict-checked placement for exact rewrites of offset-linked regions.
#[doc(alias = "pointer graph")]
#[doc(alias = "claimed bytes")]
#[doc(alias = "exact write")]
pub mod offset_graph;
/// Extent tiling, ordered-run audits, and successor-range derivation.
pub mod ranges;
/// Fixed-stride record views with checked bounds.
pub mod records;
/// Shared declarative field, offset-base, pack-policy, and error types for layout specs.
pub mod spec;
/// Offset tables, boundary tables, and aligned-size chains.
pub mod tables;
/// Fixed-width byte strings, hex formatting, and compiled multi-byte charmaps.
pub mod text;

pub use chunks::{
    iter_chunk_stream, iter_chunk_stream_with_alignment_base, pack_chunk_stream,
    pack_chunk_stream_with_alignment_base, parse_chunk_stream,
    parse_chunk_stream_with_alignment_base, read_header_inclusive_chunk, read_payload_chunk,
    ChunkAlignmentBase, ChunkEntry, ChunkInput, ChunkSizeMode, ChunkStreamIter, ChunkStreamSpec,
    ChunkView, InclusiveChunkError, InclusiveChunkSpan, PayloadChunkError, PayloadChunkSpan,
};
pub use edit::{patch_bytes, patched_bytes, same_size_splice, SameSizeSpliceError};
pub use field::{
    BytesField, F32ArrayField, F32Field, F64Field, I16ArrayField, I16Field, I32ArrayField,
    I32Field, I64Field, I8Field, ScaledU32Field, U16ArrayField, U16Field, U32ArrayField, U32Field,
    U64Field, U8Field,
};
pub use iff::{parse_iff_form, parse_riff_form, IffChunk, IffForm, IFF_FORM_MAGIC, RIFF_MAGIC};
pub use marker_scan::{pack_marker_scan_stream, parse_marker_scan_stream, MarkerScanStreamSpec};
pub use offset_graph::{
    checked_element, checked_offset, ClaimedReader, OverlapPolicy, PlacementCanvas, UnclaimedGap,
};
pub use ranges::{
    audit_exact_tiling, audit_ordered_contiguous_run, audit_ordered_non_overlapping,
    checked_align_up_u64, child_run, nondecreasing_successor_ranges, strict_successor_ranges,
    ChildRunError, NondecreasingSuccessorRangesError, OrderedExtentError, SuccessorRangesError,
};
pub use records::{FixedRecords, RecordOverflow};
pub use spec::{IntFieldSpec, IntWidth, LayoutError, OffsetBase, PackPolicy};
pub use tables::{
    iter_fixed_record_table, iter_fixed_record_table_counted,
    iter_fixed_record_table_counted_metadata, iter_fixed_record_table_metadata,
    iter_fixed_record_table_with_name_pool, pack_counted_offset_array, pack_fixed_record_table,
    pack_fixed_record_table_with_post_table, parse_counted_offset_array,
    parse_counted_offset_array_metadata, parse_counted_offset_array_with_count,
    parse_counted_offset_array_with_count_metadata, parse_fixed_record_table,
    parse_fixed_record_table_bounded, parse_fixed_record_table_counted,
    parse_fixed_record_table_counted_metadata, parse_fixed_record_table_metadata,
    parse_fixed_record_table_with_name_pool, AlignedSizeChain, AlignedSizeCursor, AlignedSizeError,
    AlignedSizeExtent, CountedBoundaryError, CountedBoundaryTable, CountedOffsetArraySpec,
    CountedU16BoundaryError, CountedU16BoundaryTable, DerivedAlignedSizes, FirstWordOffsetError,
    FirstWordOffsetTable, FixedRecordEntry, FixedRecordInput, FixedRecordTableIter,
    FixedRecordTableSpec, FixedRecordView, FixedStrideOffsetTable, NameEncoding, NameFieldSpec,
    NamePoolSpec, OffsetLengthRow, OffsetLengthRows, OffsetSpan, PositiveSizeError,
    PositiveSizeExtent, PositiveSizeList, SizeAlignment, SizeMode, TableSizeMode, TableTermination,
    TerminalOffsetError, TerminalOffsetTable, ValidatedCountedBoundaries,
    ValidatedCountedU16Boundaries, ValidatedPositiveSizes, ValidatedTerminalOffsets,
};
pub use text::{
    format_hex_bytes, parse_hex_bytes, Charmap, CharmapControl, CharmapDecoded, CharmapEntry,
    CharmapLimits, CharmapToken, FixedByteStringField,
};
