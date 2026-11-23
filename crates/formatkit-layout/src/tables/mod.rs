//! Configured table row descriptions without owner grammar policy.

mod aligned_sizes;
mod counted_boundaries;
mod counted_u16_boundaries;
mod first_word_offsets;
mod fixed_stride_offset;
mod offset_length;
mod positive_sizes;
mod terminal_offsets;

pub use aligned_sizes::{
    AlignedSizeChain, AlignedSizeCursor, AlignedSizeError, AlignedSizeExtent, DerivedAlignedSizes,
};
pub use counted_boundaries::{
    CountedBoundaryError, CountedBoundaryTable, ValidatedCountedBoundaries,
};
pub use counted_u16_boundaries::{
    CountedU16BoundaryError, CountedU16BoundaryTable, ValidatedCountedU16Boundaries,
};
pub use first_word_offsets::{FirstWordOffsetError, FirstWordOffsetTable};
pub use fixed_stride_offset::{FixedStrideOffsetTable, TableSizeMode};
pub use offset_length::{OffsetLengthRow, OffsetLengthRows};
pub use positive_sizes::{
    PositiveSizeError, PositiveSizeExtent, PositiveSizeList, SizeAlignment, ValidatedPositiveSizes,
};
pub use terminal_offsets::{TerminalOffsetError, TerminalOffsetTable, ValidatedTerminalOffsets};
