//! Checked binary data primitives and bounded source access.

#![deny(unsafe_code)]

mod error;
pub use error::{Error, ErrorContext, Result, ResultExt};

mod reader;
pub use reader::Reader;

mod bytes;
pub use bytes::{
    bytes_at, bytes_at_mut, checked_align_up, checked_align_up_multiple, i16_at, i16_at_endian,
    i32_at, i32_at_endian, i64_at, i64_at_endian, i8_at, monotone_bounded, u16_at, u16_at_endian,
    u32_at, u32_at_endian, u64_at, u64_at_endian, u8_at, uint_be_at, uint_le_at, write_uint_be_at,
    write_uint_le_at, zero_tail_lt, Endian,
};

mod bits;
pub use bits::{Bit, BitRange, BitValueTooWide};

mod bit_cursor;
pub use bit_cursor::{LsbBitCursor, LsbBitWriter, MsbBitCursor, MsbBitWriter};

mod interleaved_bits;
pub use interleaved_bits::{
    InterleavedBitReader, InterleavedBitWriter, LsbInterleavedBitReader, LsbInterleavedBitWriter,
    MsbInterleavedBitReader, MsbInterleavedBitWriter,
};

mod scalar;
pub use scalar::{NotZeroOne, ZeroOne};

mod writer;
pub use writer::Writer;

mod format;
pub use format::Format;

mod image;
pub use image::Image;

mod extent;
pub use extent::{audit_extent, Extent, ExtentAudit, ExtentStatus};

mod work_budget;
pub use work_budget::{
    CancellationToken, DepthScope, ResidentReservation, RetainedResidentPermit, WorkBudget,
    WorkLimits, WorkResource, WorkScope, WorkUsage,
};

mod resident_buffer;
mod source_copy;
pub use resident_buffer::ResidentBuffer;
pub use source_copy::{copy_source_range, SourceCopyError};

mod source_metadata;
pub use source_metadata::{SourceMetadataReader, SourceMetadataWindow};

mod range_source;
pub use range_source::{
    read_exact_at, read_shared_exact_at, validate_exact_read_length, ArchiveMemberRangeSource,
    CompositeRangeSource, CompositeSegment, CoordinateMappingDescription,
    CoordinateSpaceDescription, ExactReadLengthMismatch, ExactReadLengthMismatchKind,
    ExactReadRoute, FileRangeSource, MappingPrecision, MaterializationPolicy, MaterializedContent,
    MemoryRangeSource, ObjectPackRangeSource, RangeSource, ReadBudget,
    RevalidatedExactSliceErrorPolicy, RevalidatedExactSliceSource, SharedBytes, SliceRangeSource,
    SourceRange, StridedRangeSource, TransformedRangeSource,
};

#[doc(hidden)]
mod range_source_test_double;
#[doc(hidden)]
pub use range_source_test_double::{InjectedError, RangeSourceTestDouble, ReadFault};

mod namespace;
mod source_bindings;
pub use source_bindings::{SourceBindings, SourceHandle, SourceViewHandle};

pub use namespace::{
    ContextualMemberNamespace, IndexedNamespace, MemberAccessMode, MemberContentSource,
    MemberLayout, MemberSemanticView, MemberTransform, MountedMember, MountedMembers,
    NamespaceEntry, NamespaceTraversalContext, StoredRangeNamespace, StoredRangeNamespaceLimits,
    StoredRangeRevalidation, TransformKind, TransformRecipe,
};

mod transformed_member;
pub use transformed_member::{materialize_transformed_member, TransformMaterialization};

pub mod text;
pub use text::{
    fixed_field, nul_terminated, nul_terminated_len, u16_be_prefixed, u16_le_prefixed, u8_prefixed,
    write_nul_or_full, write_nul_padded, write_nul_terminated,
};

mod bounded_cstr;
pub use bounded_cstr::{
    apply_bounded_cstr_patches, verify_input_sha256, BoundedCstrApplied, BoundedCstrPatch,
    BoundedCstrReport,
};

pub mod audio;
pub use audio::{wav_header_pcm, Pcm};

mod bit_rows;
pub use bit_rows::MsbFirst1bppRows;

pub mod checksum;
pub use checksum::{
    compute_with_zeroed_range, sum_bytes_u16, xor_bytes, Crc32, Crc32Params, FoldChecksum, FoldOp,
    FoldUnit,
};

pub mod pointer_table;
pub use pointer_table::{scan_u32_pointer_tables, PointerTable};

pub mod padding;
pub use padding::{
    classify_padding, classify_padding_source, detect_trailing_padding, PaddingKind,
    PaddingSummary, TrailingPadding,
};

pub mod math;

pub mod topology;

#[cfg(test)]
mod tests {
    #[test]
    fn workspace_builds() {
        assert_eq!(2 + 2, 4);
    }
}
