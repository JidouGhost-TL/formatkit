//! Configured table row descriptions without owner grammar policy.

mod aligned_sizes;
mod counted_boundaries;
mod first_word_offsets;
mod offset_length;
mod positive_sizes;
mod terminal_offsets;

pub use aligned_sizes::{
    AlignedSizeChain, AlignedSizeCursor, AlignedSizeError, AlignedSizeExtent, DerivedAlignedSizes,
};
pub use counted_boundaries::{
    CountedBoundaryError, CountedBoundaryTable, ValidatedCountedBoundaries,
};
pub use first_word_offsets::{FirstWordOffsetError, FirstWordOffsetTable};
pub use offset_length::{OffsetLengthRow, OffsetLengthRows};
pub use positive_sizes::{
    PositiveSizeError, PositiveSizeExtent, PositiveSizeList, SizeAlignment, ValidatedPositiveSizes,
};
pub use terminal_offsets::{TerminalOffsetError, TerminalOffsetTable, ValidatedTerminalOffsets};
