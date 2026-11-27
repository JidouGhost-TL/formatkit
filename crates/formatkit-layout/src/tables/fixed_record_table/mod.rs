//! Declarative fixed-stride record table specification, checked parser, and symmetric writer.
//!
//! [`FixedRecordTableSpec`] describes fixed-stride directory tables with
//! configurable integer widths (`u8`/`u16`/`u24`/`u32`/`u64`), endianness,
//! optional embedded or pooled names, offset base/unit scaling, size derivation modes,
//! row predicates, and table termination rules.

mod pack;
mod parse;
mod spec;
#[cfg(test)]
mod tests;

pub use pack::{pack_fixed_record_table, pack_fixed_record_table_with_post_table};
pub use parse::{
    iter_fixed_record_table, iter_fixed_record_table_counted,
    iter_fixed_record_table_counted_metadata, iter_fixed_record_table_metadata,
    iter_fixed_record_table_with_name_pool, parse_fixed_record_table,
    parse_fixed_record_table_bounded, parse_fixed_record_table_counted,
    parse_fixed_record_table_counted_metadata, parse_fixed_record_table_metadata,
    parse_fixed_record_table_with_extent, parse_fixed_record_table_with_name_pool,
    FixedRecordTableIter, FixedRecordTableResult,
};
pub use spec::{
    FixedRecordEntry, FixedRecordInput, FixedRecordTableSpec, FixedRecordView, NameEncoding,
    NameFieldSpec, NamePoolFormat, NamePoolSpec, RowFieldPredicate, SizeMode, TableParseOptions,
    TableTermination,
};
