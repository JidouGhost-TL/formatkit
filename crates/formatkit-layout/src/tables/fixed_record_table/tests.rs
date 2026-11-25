use formatkit_core::Endian;

use super::*;
use crate::spec::{IntFieldSpec, IntWidth, LayoutError, OffsetBase, PackPolicy};

#[test]
fn parses_counted_stored_be_u24_and_sector_units() {
    const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        16,
        0,
        16,
        Some(IntFieldSpec::new(8, IntWidth::U24, Endian::Big)),
        SizeMode::Stored(IntFieldSpec::u32_be(12)),
        TableTermination::Counted(2),
    )
    .with_name_field(NameFieldSpec::new(0, 8, NameEncoding::NulOrSpacePadded))
    .with_offset_unit(2048);

    let mut data = vec![0u8; 2048 * 3];
    data[0..8].copy_from_slice(b"alpha   ");
    data[8..11].copy_from_slice(&[0x00, 0x00, 0x01]);
    data[12..16].copy_from_slice(&100u32.to_be_bytes());
    data[16..24].copy_from_slice(b"beta\0pad");
    data[24..27].copy_from_slice(&[0x00, 0x00, 0x02]);
    data[28..32].copy_from_slice(&2048u32.to_be_bytes());

    let entries = parse_fixed_record_table(&data, &SPEC).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name_str(), Some("alpha"));
    assert_eq!(entries[0].offset, 2048);
    assert_eq!(entries[0].size, 100);
    assert_eq!(entries[1].name_str(), Some("beta"));
    assert_eq!(entries[1].offset, 4096);
    assert_eq!(entries[1].size, 2048);
}

#[test]
fn parses_first_offset_derived_and_next_offset() {
    const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        16,
        0,
        16,
        Some(IntFieldSpec::u32_le(12)),
        SizeMode::NextOffset,
        TableTermination::FirstOffsetDerived,
    )
    .with_name_field(NameFieldSpec::new(0, 12, NameEncoding::Ascii));

    let mut data = Vec::new();
    data.extend_from_slice(b"first.bin\0\0\0");
    data.extend_from_slice(&32u32.to_le_bytes());
    data.extend_from_slice(b"second.bin\0\0");
    data.extend_from_slice(&42u32.to_le_bytes());
    data.extend_from_slice(&[0xAA; 10]);
    data.extend_from_slice(&[0xBB; 6]);

    let entries = parse_fixed_record_table(&data, &SPEC).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name_str(), Some("first.bin"));
    assert_eq!(entries[0].offset, 32);
    assert_eq!(entries[0].size, 10);
    assert_eq!(entries[1].name_str(), Some("second.bin"));
    assert_eq!(entries[1].offset, 42);
    assert_eq!(entries[1].size, 6);
}

#[test]
fn next_offset_final_entry_past_eof_returns_out_of_bounds_without_panic() {
    const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        4,
        0,
        8,
        Some(IntFieldSpec::u32_le(0)),
        SizeMode::NextOffset,
        TableTermination::Counted(2),
    );
    let mut data = Vec::new();
    data.extend_from_slice(&8u32.to_le_bytes());
    data.extend_from_slice(&999u32.to_le_bytes());
    data.extend_from_slice(&[0u8; 4]);

    assert_eq!(
        parse_fixed_record_table(&data, &SPEC),
        Err(LayoutError::OutOfBounds {
            index: 0,
            offset: 8,
            size: 991,
            data_len: 12,
        })
    );

    const SINGLE_SPEC: FixedRecordTableSpec = FixedRecordTableSpec {
        termination: TableTermination::Counted(1),
        ..SPEC
    };
    let single = 999u32.to_le_bytes();
    assert_eq!(
        parse_fixed_record_table(&single, &SINGLE_SPEC),
        Err(LayoutError::OutOfBounds {
            index: 0,
            offset: 999,
            size: 0,
            data_len: 4,
        })
    );
}

#[test]
fn next_offset_non_monotonic_reports_true_physical_index_and_sentinel_index() {
    // Interior skipped slot 1 -> non-monotonic at physical slot 2 (not 1!)
    const SKIP_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        8,
        0,
        16,
        Some(IntFieldSpec::u32_le(4)),
        SizeMode::NextOffset,
        TableTermination::Counted(3),
    )
    .with_skip_field_equals(IntFieldSpec::u32_le(0), 0xFFFF_FFFF);

    let mut data = Vec::new();
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&40u32.to_le_bytes()); // slot 0: offset 40
    data.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes()); // slot 1: skipped
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&30u32.to_le_bytes()); // slot 2: offset 30 < 40!
    data.extend_from_slice(&[0u8; 32]);

    assert_eq!(
        parse_fixed_record_table(&data, &SKIP_SPEC),
        Err(LayoutError::NonMonotonic {
            index: 2,
            previous: 40,
            current: 30,
        })
    );

    // Terminal sentinel offset < last active entry -> reports raw_count (3)
    const SENTINEL_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        8,
        0,
        16,
        Some(IntFieldSpec::u32_le(4)),
        SizeMode::NextOffset,
        TableTermination::FieldEquals {
            field: IntFieldSpec::u32_le(0),
            value: 0,
        },
    )
    .with_skip_field_equals(IntFieldSpec::u32_le(0), 0xFFFF_FFFF)
    .with_sentinel_closes_next_offset(true);

    let mut sdata = Vec::new();
    sdata.extend_from_slice(&1u32.to_le_bytes());
    sdata.extend_from_slice(&40u32.to_le_bytes()); // slot 0: active
    sdata.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    sdata.extend_from_slice(&0u32.to_le_bytes()); // slot 1: skipped
    sdata.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    sdata.extend_from_slice(&0u32.to_le_bytes()); // slot 2: skipped
    sdata.extend_from_slice(&0u32.to_le_bytes());
    sdata.extend_from_slice(&35u32.to_le_bytes()); // slot 3 (raw_count=3): sentinel 35 < 40!
    sdata.extend_from_slice(&[0u8; 32]);

    assert_eq!(
        parse_fixed_record_table(&sdata, &SENTINEL_SPEC),
        Err(LayoutError::NonMonotonic {
            index: 3,
            previous: 40,
            current: 35,
        })
    );
}

#[test]
fn parses_zero_row_and_first_byte_zero_termination_with_table_end_base() {
    const ZERO_ROW_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        8,
        0,
        16,
        Some(IntFieldSpec::u32_le(0)),
        SizeMode::Stored(IntFieldSpec::u32_le(4)),
        TableTermination::ZeroRow,
    )
    .with_offset_base(OffsetBase::TableEnd);

    let mut data = Vec::new();
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&4u32.to_le_bytes());
    data.extend_from_slice(&4u32.to_le_bytes());
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&[0u8; 8]);
    data.extend_from_slice(b"ABCD");
    data.extend_from_slice(b"EF");

    let entries = parse_fixed_record_table(&data, &ZERO_ROW_SPEC).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].offset, 24);
    assert_eq!(entries[0].payload(&data), Some(&b"ABCD"[..]));
    assert_eq!(entries[1].offset, 28);
    assert_eq!(entries[1].payload(&data), Some(&b"EF"[..]));

    const FIRST_ZERO_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        12,
        0,
        16,
        Some(IntFieldSpec::u32_le(4)),
        SizeMode::Stored(IntFieldSpec::u32_le(8)),
        TableTermination::FirstByteZero,
    )
    .with_name_field(NameFieldSpec::new(0, 4, NameEncoding::NulTerminated));
    let mut data2 = Vec::new();
    data2.extend_from_slice(b"A\0\0\0");
    data2.extend_from_slice(&24u32.to_le_bytes());
    data2.extend_from_slice(&3u32.to_le_bytes());
    data2.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    data2.extend_from_slice(b"XYZ");
    let entries2 = parse_fixed_record_table(&data2, &FIRST_ZERO_SPEC).unwrap();
    assert_eq!(entries2.len(), 1);
    assert_eq!(entries2[0].name_str(), Some("A"));
    assert_eq!(entries2[0].payload(&data2), Some(&b"XYZ"[..]));
}

#[test]
fn parses_cumulative_with_size_unit_and_rejects_first_offset_derived() {
    const CUMULATIVE_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        4,
        0,
        16,
        Some(IntFieldSpec::u32_le(0)),
        SizeMode::cumulative_from(OffsetBase::Fixed(8)),
        TableTermination::Counted(2),
    )
    .with_size_unit(4);
    let mut data = Vec::new();
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(b"1234abcdefgh");
    let entries = parse_fixed_record_table(&data, &CUMULATIVE_SPEC).unwrap();
    assert_eq!(entries[0].offset, 8);
    assert_eq!(entries[0].size, 4);
    assert_eq!(entries[1].offset, 12);
    assert_eq!(entries[1].size, 8);

    let invalid_combo = FixedRecordTableSpec {
        termination: TableTermination::FirstOffsetDerived,
        ..CUMULATIVE_SPEC
    };
    assert!(matches!(
        parse_fixed_record_table(&data, &invalid_combo),
        Err(LayoutError::InvalidSpec {
            field: "size_mode",
            ..
        })
    ));

    let invalid_start = FixedRecordTableSpec {
        size_mode: SizeMode::cumulative_from(OffsetBase::SubtractBase(8)),
        ..CUMULATIVE_SPEC
    };
    assert!(matches!(
        parse_fixed_record_table(&data, &invalid_start),
        Err(LayoutError::InvalidSpec {
            field: "size_mode",
            ..
        })
    ));
}

#[test]
fn parses_fixed_slot_and_record_start_and_metadata_700mb() {
    const FIXED_SLOT_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        4,
        0,
        16,
        None,
        SizeMode::FixedSlot(4),
        TableTermination::Counted(2),
    )
    .with_offset_base(OffsetBase::Fixed(8));
    let slot_data = [0u8; 16];
    let slot_entries = parse_fixed_record_table(&slot_data, &FIXED_SLOT_SPEC).unwrap();
    assert_eq!(slot_entries[0].offset, 8);
    assert_eq!(slot_entries[0].size, 4);
    assert_eq!(slot_entries[1].offset, 12);
    assert_eq!(slot_entries[1].size, 4);

    const DISC_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        16,
        0,
        64,
        Some(IntFieldSpec::u32_le(8)),
        SizeMode::Stored(IntFieldSpec::u32_le(12)),
        TableTermination::Counted(0),
    )
    .with_name_field(NameFieldSpec::new(0, 8, NameEncoding::Ascii))
    .with_offset_unit(2048);
    let mut dir_bytes = Vec::new();
    dir_bytes.extend_from_slice(b"big.bin\0");
    dir_bytes.extend_from_slice(&350_000u32.to_le_bytes());
    dir_bytes.extend_from_slice(&4096u32.to_le_bytes());
    let carrier_len: u64 = 750 * 1024 * 1024;
    let views: Vec<_> =
        iter_fixed_record_table_counted_metadata(&dir_bytes, &DISC_SPEC, 1, carrier_len)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].name_str(), Some("big.bin"));
    assert_eq!(views[0].offset, 350_000 * 2048);
    assert_eq!(views[0].size, 4096);

    let parsed =
        parse_fixed_record_table_counted_metadata(&dir_bytes, &DISC_SPEC, 1, carrier_len).unwrap();
    assert_eq!(parsed[0].offset, 350_000 * 2048);
}

#[test]
fn table_parse_options_supports_all_overrides() {
    const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        10,
        0,
        64,
        Some(IntFieldSpec::u32_le(2)),
        SizeMode::Stored(IntFieldSpec::u32_le(6)),
        TableTermination::Counted(0),
    )
    .with_name_pool(NamePoolSpec::new(
        IntFieldSpec::u16_le(0),
        OffsetBase::Absolute,
        NameEncoding::Ascii,
        16,
    ));

    let mut buf = Vec::new();
    buf.extend_from_slice(b"SKIP"); // 4-byte prefix overridden via with_table_offset(4)
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&100u32.to_le_bytes());
    buf.extend_from_slice(&20u32.to_le_bytes());
    buf.extend_from_slice(&6u16.to_le_bytes());
    buf.extend_from_slice(&120u32.to_le_bytes());
    buf.extend_from_slice(&30u32.to_le_bytes());
    let pool = b"alpha\0beta\0";

    let opts = TableParseOptions::new()
        .with_table_offset(4)
        .with_count(2)
        .with_carrier_len(200)
        .with_name_pool(pool)
        .with_max_entries(4);
    let parsed = SPEC.parse_with(&buf, opts).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].name_str(), Some("alpha"));
    assert_eq!(parsed[0].offset, 100);
    assert_eq!(parsed[1].name_str(), Some("beta"));
    assert_eq!(parsed[1].offset, 120);

    // max_entries cap in TableParseOptions enforced
    assert_eq!(
        SPEC.parse_with(&buf, opts.with_max_entries(1)),
        Err(LayoutError::MaxEntriesExceeded { max: 1 })
    );
}

#[test]
fn rejects_oob_overflow_non_monotonic_invalid_name_and_max_entries() {
    const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        12,
        0,
        4,
        Some(IntFieldSpec::u32_le(4)),
        SizeMode::Stored(IntFieldSpec::u32_le(8)),
        TableTermination::Counted(1),
    )
    .with_name_field(NameFieldSpec::new(0, 4, NameEncoding::Ascii));

    let mut oob = Vec::new();
    oob.extend_from_slice(b"ok\0\0");
    oob.extend_from_slice(&12u32.to_le_bytes());
    oob.extend_from_slice(&5u32.to_le_bytes());
    oob.extend_from_slice(b"123");
    assert!(matches!(
        parse_fixed_record_table(&oob, &SPEC),
        Err(LayoutError::OutOfBounds { index: 0, .. })
    ));

    let mut bad_name = Vec::new();
    bad_name.extend_from_slice(&[0xFF, b'a', 0, 0]);
    bad_name.extend_from_slice(&12u32.to_le_bytes());
    bad_name.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(
        parse_fixed_record_table(&bad_name, &SPEC),
        Err(LayoutError::InvalidName { index: 0 })
    );

    let overflow_spec = FixedRecordTableSpec {
        offset_unit: u64::MAX,
        ..SPEC
    };
    let mut ov = Vec::new();
    ov.extend_from_slice(b"ok\0\0");
    ov.extend_from_slice(&2u32.to_le_bytes());
    ov.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(
        parse_fixed_record_table(&ov, &overflow_spec),
        Err(LayoutError::Overflow {
            what: "scaled_offset"
        })
    );

    assert_eq!(
        parse_fixed_record_table_bounded(&oob, &SPEC, 0),
        Err(LayoutError::MaxEntriesExceeded { max: 0 })
    );
}

#[test]
fn pack_fixed_record_table_round_trips_all_modes_widths_and_templates() {
    const STORED_U64_BE: FixedRecordTableSpec = FixedRecordTableSpec::new(
        28,
        8,
        16,
        Some(IntFieldSpec::u64_be(8)),
        SizeMode::Stored(IntFieldSpec::u64_be(16)),
        TableTermination::Counted(0),
    )
    .with_name_field(NameFieldSpec::new(0, 8, NameEncoding::Ascii));
    let mut tmpl0 = [0u8; 28];
    tmpl0[24..28].copy_from_slice(b"FLAG");
    let policy = PackPolicy::TIGHT
        .with_data_alignment(16)
        .with_pad_byte(0xCC)
        .with_pad_final_entry(true)
        .with_prefix_fill_byte(0xEE);
    let inputs = [
        FixedRecordInput {
            name: Some(b"alpha"),
            key: None,
            payload: b"hello",
            record_template: Some(&tmpl0),
        },
        FixedRecordInput {
            name: Some(b"beta"),
            key: None,
            payload: b"world!",
            record_template: None,
        },
    ];
    let packed = pack_fixed_record_table(&STORED_U64_BE, &policy, b"HDR!", &inputs).unwrap();
    assert_eq!(&packed[0..4], b"HDR!");
    assert_eq!(&packed[4..8], &[0xEE; 4]);
    assert_eq!(&packed[8 + 24..8 + 28], b"FLAG");
    assert_eq!(packed.len() % 16, 0);

    let parsed = parse_fixed_record_table_counted(&packed, &STORED_U64_BE, 2).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].name_str(), Some("alpha"));
    assert_eq!(parsed[0].offset % 16, 0);
    assert_eq!(parsed[0].payload(&packed), Some(&b"hello"[..]));
    assert_eq!(parsed[1].name_str(), Some("beta"));
    assert_eq!(parsed[1].offset % 16, 0);
    assert_eq!(parsed[1].payload(&packed), Some(&b"world!"[..]));

    const SECTOR_ZERO_ROW: FixedRecordTableSpec = FixedRecordTableSpec::new(
        8,
        0,
        16,
        Some(IntFieldSpec::u24_be(0)),
        SizeMode::Stored(IntFieldSpec::u32_be(4)),
        TableTermination::ZeroRow,
    )
    .with_offset_unit(2048);
    let sec_inputs = [
        FixedRecordInput {
            name: None,
            key: None,
            payload: b"sector-one",
            record_template: None,
        },
        FixedRecordInput {
            name: None,
            key: None,
            payload: b"sector-two",
            record_template: None,
        },
    ];
    let sec_packed =
        pack_fixed_record_table(&SECTOR_ZERO_ROW, &PackPolicy::TIGHT, &[], &sec_inputs).unwrap();
    let sec_parsed = parse_fixed_record_table(&sec_packed, &SECTOR_ZERO_ROW).unwrap();
    assert_eq!(sec_parsed.len(), 2);
    assert_eq!(sec_parsed[0].offset, 2048);
    assert_eq!(sec_parsed[0].payload(&sec_packed), Some(&b"sector-one"[..]));
    assert_eq!(sec_parsed[1].offset, 4096);
    assert_eq!(sec_parsed[1].payload(&sec_packed), Some(&b"sector-two"[..]));

    const FIRST_DERIVED: FixedRecordTableSpec = FixedRecordTableSpec::new(
        8,
        0,
        16,
        Some(IntFieldSpec::u16_le(6)),
        SizeMode::NextOffset,
        TableTermination::FirstOffsetDerived,
    )
    .with_name_field(NameFieldSpec::new(0, 6, NameEncoding::Ascii));
    let fd_inputs = [
        FixedRecordInput {
            name: Some(b"a.bin"),
            key: None,
            payload: b"1234",
            record_template: None,
        },
        FixedRecordInput {
            name: Some(b"b.bin"),
            key: None,
            payload: b"567890",
            record_template: None,
        },
    ];
    let fd_packed =
        pack_fixed_record_table(&FIRST_DERIVED, &PackPolicy::TIGHT, &[], &fd_inputs).unwrap();
    let fd_parsed = parse_fixed_record_table(&fd_packed, &FIRST_DERIVED).unwrap();
    assert_eq!(fd_parsed.len(), 2);
    assert_eq!(fd_parsed[0].payload(&fd_packed), Some(&b"1234"[..]));
    assert_eq!(fd_parsed[1].payload(&fd_packed), Some(&b"567890"[..]));

    const FIRST_BYTE_U8: FixedRecordTableSpec = FixedRecordTableSpec::new(
        6,
        0,
        16,
        Some(IntFieldSpec::u8(4)),
        SizeMode::Stored(IntFieldSpec::u8(5)),
        TableTermination::FirstByteZero,
    )
    .with_name_field(NameFieldSpec::new(0, 4, NameEncoding::Ascii))
    .with_offset_base(OffsetBase::TableEnd);
    let u8_inputs = [FixedRecordInput {
        name: Some(b"item"),
        key: None,
        payload: b"tiny",
        record_template: None,
    }];
    let u8_packed =
        pack_fixed_record_table(&FIRST_BYTE_U8, &PackPolicy::TIGHT, &[], &u8_inputs).unwrap();
    let u8_parsed = parse_fixed_record_table(&u8_packed, &FIRST_BYTE_U8).unwrap();
    assert_eq!(u8_parsed.len(), 1);
    assert_eq!(u8_parsed[0].name_str(), Some("item"));
    assert_eq!(u8_parsed[0].payload(&u8_packed), Some(&b"tiny"[..]));

    const EOF_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        8,
        0,
        16,
        Some(IntFieldSpec::u16_le(4)),
        SizeMode::Stored(IntFieldSpec::u16_le(6)),
        TableTermination::Eof,
    )
    .with_name_field(NameFieldSpec::new(0, 4, NameEncoding::Ascii));
    let eof_inputs = [
        FixedRecordInput {
            name: Some(b"rec0"),
            key: None,
            payload: &[],
            record_template: None,
        },
        FixedRecordInput {
            name: Some(b"rec1"),
            key: None,
            payload: &[],
            record_template: None,
        },
    ];
    let eof_packed =
        pack_fixed_record_table(&EOF_SPEC, &PackPolicy::TIGHT, &[], &eof_inputs).unwrap();
    let eof_parsed = parse_fixed_record_table(&eof_packed, &EOF_SPEC).unwrap();
    assert_eq!(eof_parsed.len(), 2);
    assert_eq!(eof_parsed[0].name_str(), Some("rec0"));
    assert_eq!(eof_parsed[1].name_str(), Some("rec1"));

    let too_big = [FixedRecordInput {
        name: Some(b"big"),
        key: None,
        payload: &[0u8; 300],
        record_template: None,
    }];
    assert_eq!(
        pack_fixed_record_table(&FIRST_BYTE_U8, &PackPolicy::TIGHT, &[], &too_big),
        Err(LayoutError::ValueOutOfRange {
            value: 300,
            max: 255
        })
    );
}

#[test]
fn pack_guards_reject_skip_empty_zero_and_eof_overflows() {
    // 1. skip_empty_zero rejects rows that encode to (offset=0, size=0)
    const SKIP_ZERO_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        8,
        0,
        16,
        Some(IntFieldSpec::u32_le(0)),
        SizeMode::Stored(IntFieldSpec::u32_le(4)),
        TableTermination::Counted(1),
    )
    .with_offset_base(OffsetBase::TableEnd)
    .with_skip_empty_zero(true);
    let empty_row = [FixedRecordInput {
        name: None,
        key: None,
        payload: &[],
        record_template: None,
    }];
    assert!(matches!(
        pack_fixed_record_table(&SKIP_ZERO_SPEC, &PackPolicy::TIGHT, &[], &empty_row),
        Err(LayoutError::InvalidInput { index: 0, .. })
    ));

    // 2. TableTermination::Eof rejects non-empty name_pool
    const EOF_POOL_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        12,
        0,
        16,
        Some(IntFieldSpec::u32_le(4)),
        SizeMode::Stored(IntFieldSpec::u32_le(8)),
        TableTermination::Eof,
    )
    .with_name_pool(NamePoolSpec::new(
        IntFieldSpec::u32_le(0),
        OffsetBase::TableEnd,
        NameEncoding::Ascii,
        16,
    ));
    let pool_in = [FixedRecordInput {
        name: Some(b"a"),
        key: None,
        payload: &[],
        record_template: None,
    }];
    assert!(matches!(
        pack_fixed_record_table(&EOF_POOL_SPEC, &PackPolicy::TIGHT, &[], &pool_in),
        Err(LayoutError::InvalidInput { index: 0, .. })
    ));

    // 3. TableTermination::Eof rejects cursor > table_end (e.g. from TableEndPlus or data_alignment)
    const EOF_PAST_END_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        8,
        0,
        16,
        Some(IntFieldSpec::u32_le(0)),
        SizeMode::Stored(IntFieldSpec::u32_le(4)),
        TableTermination::Eof,
    )
    .with_offset_base(OffsetBase::TableEndPlus(16));
    assert!(matches!(
        pack_fixed_record_table(&EOF_PAST_END_SPEC, &PackPolicy::TIGHT, &[], &empty_row),
        Err(LayoutError::InvalidInput { index: 0, .. })
    ));
}

#[test]
fn k2_masked_fields_preserve_template_flags_and_support_packed_words() {
    const PACKED_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        8,
        0,
        16,
        Some(IntFieldSpec::u32_le(0).masked(0, 0x000F_FFFF)),
        SizeMode::Stored(IntFieldSpec::u32_le(0).masked(20, 0x0FFF)),
        TableTermination::Counted(2),
    )
    .with_key_field(IntFieldSpec::u32_le(4).masked(0, 0x0FFF_FFFF));

    let mut tmpl0 = [0u8; 8];
    tmpl0[4..8].copy_from_slice(&0xB000_0000u32.to_le_bytes());
    let mut tmpl1 = [0u8; 8];
    tmpl1[4..8].copy_from_slice(&0x7000_0000u32.to_le_bytes());

    let inputs = [
        FixedRecordInput {
            name: None,
            key: Some(0x0123_4567),
            payload: b"hello",
            record_template: Some(&tmpl0),
        },
        FixedRecordInput {
            name: None,
            key: Some(0x00AB_CDEF),
            payload: b"world!!",
            record_template: Some(&tmpl1),
        },
    ];

    let packed = pack_fixed_record_table(&PACKED_SPEC, &PackPolicy::TIGHT, &[], &inputs).unwrap();

    assert_eq!(
        u32::from_le_bytes(packed[4..8].try_into().unwrap()) >> 28,
        0xB
    );
    assert_eq!(
        u32::from_le_bytes(packed[12..16].try_into().unwrap()) >> 28,
        0x7
    );

    let parsed = parse_fixed_record_table(&packed, &PACKED_SPEC).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].key, Some(0x0123_4567));
    assert_eq!(parsed[0].payload(&packed), Some(&b"hello"[..]));
    assert_eq!(parsed[1].key, Some(0x00AB_CDEF));
    assert_eq!(parsed[1].payload(&packed), Some(&b"world!!"[..]));
}

#[test]
fn k3_cumulative_aligned_parses_packs_and_validates() {
    const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        4,
        0,
        16,
        Some(IntFieldSpec::u32_le(0)),
        SizeMode::cumulative_aligned(OffsetBase::Fixed(16), 16),
        TableTermination::Counted(3),
    );
    let inputs = [
        FixedRecordInput {
            name: None,
            key: None,
            payload: b"abc",
            record_template: None,
        },
        FixedRecordInput {
            name: None,
            key: None,
            payload: &[0x55; 16],
            record_template: None,
        },
        FixedRecordInput {
            name: None,
            key: None,
            payload: b"tail!",
            record_template: None,
        },
    ];

    let packed_tight = pack_fixed_record_table(&SPEC, &PackPolicy::TIGHT, &[], &inputs).unwrap();
    assert_eq!(packed_tight.len(), 53);
    let parsed = parse_fixed_record_table(&packed_tight, &SPEC).unwrap();
    assert_eq!(parsed.len(), 3);
    assert_eq!((parsed[0].offset, parsed[0].size), (16, 3));
    assert_eq!(parsed[0].payload(&packed_tight), Some(&b"abc"[..]));
    assert_eq!((parsed[1].offset, parsed[1].size), (32, 16));
    assert_eq!((parsed[2].offset, parsed[2].size), (48, 5));
    assert_eq!(parsed[2].payload(&packed_tight), Some(&b"tail!"[..]));

    let pad_policy = PackPolicy::TIGHT.with_pad_final_entry(true);
    let packed_padded = pack_fixed_record_table(&SPEC, &pad_policy, &[], &inputs).unwrap();
    assert_eq!(packed_padded.len(), 64);
    let parsed_padded = parse_fixed_record_table(&packed_padded, &SPEC).unwrap();
    assert_eq!(
        parsed_padded[2].payload(&packed_padded),
        Some(&b"tail!"[..])
    );

    let meta = parse_fixed_record_table_metadata(&packed_tight[..12], &SPEC, 53).unwrap();
    assert_eq!(meta.len(), 3);
    assert_eq!(meta[2].offset, 48);

    const BAD_ALIGN: FixedRecordTableSpec = FixedRecordTableSpec::new(
        4,
        0,
        16,
        Some(IntFieldSpec::u32_le(0)),
        SizeMode::cumulative_aligned(OffsetBase::Fixed(8), 0),
        TableTermination::Counted(1),
    );
    assert!(matches!(
        parse_fixed_record_table(&[0u8; 8], &BAD_ALIGN),
        Err(LayoutError::InvalidSpec {
            field: "size_mode",
            ..
        })
    ));
}

#[test]
fn k4_end_offset_parses_packs_and_rejects_inverted_or_oob() {
    const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        8,
        0,
        16,
        Some(IntFieldSpec::u32_le(0)),
        SizeMode::EndOffset(IntFieldSpec::u32_le(4)),
        TableTermination::Counted(2),
    )
    .with_offset_base(OffsetBase::TableEnd);

    let inputs = [
        FixedRecordInput {
            name: None,
            key: None,
            payload: b"alpha",
            record_template: None,
        },
        FixedRecordInput {
            name: None,
            key: None,
            payload: b"beta-payload",
            record_template: None,
        },
    ];
    let packed = pack_fixed_record_table(&SPEC, &PackPolicy::TIGHT, &[], &inputs).unwrap();
    let parsed = parse_fixed_record_table(&packed, &SPEC).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].offset, 16);
    assert_eq!(parsed[0].size, 5);
    assert_eq!(parsed[0].payload(&packed), Some(&b"alpha"[..]));
    assert_eq!(parsed[1].offset, 21);
    assert_eq!(parsed[1].size, 12);
    assert_eq!(parsed[1].payload(&packed), Some(&b"beta-payload"[..]));

    let mut inverted = Vec::new();
    inverted.extend_from_slice(&10u32.to_le_bytes());
    inverted.extend_from_slice(&4u32.to_le_bytes());
    inverted.extend_from_slice(&[0u8; 32]);
    const ONE_SPEC: FixedRecordTableSpec = FixedRecordTableSpec {
        termination: TableTermination::Counted(1),
        ..SPEC
    };
    assert_eq!(
        parse_fixed_record_table(&inverted, &ONE_SPEC),
        Err(LayoutError::NonMonotonic {
            index: 0,
            previous: 18,
            current: 12,
        })
    );

    let mut oob = Vec::new();
    oob.extend_from_slice(&0u32.to_le_bytes());
    oob.extend_from_slice(&100u32.to_le_bytes());
    assert!(matches!(
        parse_fixed_record_table_metadata(&oob, &ONE_SPEC, 20),
        Err(LayoutError::OutOfBounds { index: 0, .. })
    ));
}

#[test]
fn k5_field_equals_sentinel_and_skip_empty_zero() {
    const SENTINEL_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        8,
        0,
        16,
        Some(IntFieldSpec::u32_le(0)),
        SizeMode::Stored(IntFieldSpec::u32_le(4)),
        TableTermination::FieldEquals {
            field: IntFieldSpec::u32_le(0),
            value: 0xFFFF_FFFF,
        },
    );
    let inputs = [
        FixedRecordInput {
            name: None,
            key: None,
            payload: b"one",
            record_template: None,
        },
        FixedRecordInput {
            name: None,
            key: None,
            payload: b"two!",
            record_template: None,
        },
    ];
    let packed = pack_fixed_record_table(&SENTINEL_SPEC, &PackPolicy::TIGHT, &[], &inputs).unwrap();
    assert_eq!(
        u32::from_le_bytes(packed[16..20].try_into().unwrap()),
        0xFFFF_FFFF
    );
    let parsed = parse_fixed_record_table(&packed, &SENTINEL_SPEC).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].payload(&packed), Some(&b"one"[..]));
    assert_eq!(parsed[1].payload(&packed), Some(&b"two!"[..]));

    const SKIP_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        12,
        0,
        16,
        Some(IntFieldSpec::u32_le(4)),
        SizeMode::Stored(IntFieldSpec::u32_le(8)),
        TableTermination::Counted(4),
    )
    .with_key_field(IntFieldSpec::u32_le(0))
    .with_skip_empty_zero(true);

    let mut data = Vec::new();
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&48u32.to_le_bytes());
    data.extend_from_slice(&3u32.to_le_bytes());
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(&99u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&51u32.to_le_bytes());
    data.extend_from_slice(&4u32.to_le_bytes());
    data.extend_from_slice(b"AAAbbbb");

    let iter = iter_fixed_record_table(&data, &SKIP_SPEC).unwrap();
    assert_eq!(iter.len(), 2);
    assert_eq!(iter.entry_count(), 2);
    let views: Vec<_> = iter.collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(views.len(), 2);
    assert_eq!(views[0].index, 0);
    assert_eq!(views[0].key, Some(1));
    assert_eq!(views[0].payload(&data), Some(&b"AAA"[..]));
    assert_eq!(views[1].index, 3);
    assert_eq!(views[1].key, Some(2));
    assert_eq!(views[1].payload(&data), Some(&b"bbbb"[..]));
}

#[test]
fn k6_name_pool_nul_and_length_prefixed_round_trip_and_limits() {
    const POOL_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        12,
        0,
        16,
        Some(IntFieldSpec::u32_le(4)),
        SizeMode::Stored(IntFieldSpec::u32_le(8)),
        TableTermination::Counted(2),
    )
    .with_name_pool(NamePoolSpec::new(
        IntFieldSpec::u32_le(0),
        OffsetBase::TableEnd,
        NameEncoding::Ascii,
        32,
    ));

    let inputs = [
        FixedRecordInput {
            name: Some(b"dir/first.bin"),
            key: None,
            payload: b"DATA0",
            record_template: None,
        },
        FixedRecordInput {
            name: Some(b"dir/second.bin"),
            key: None,
            payload: b"DATA1!",
            record_template: None,
        },
    ];
    let packed = pack_fixed_record_table(&POOL_SPEC, &PackPolicy::TIGHT, &[], &inputs).unwrap();
    let parsed = parse_fixed_record_table(&packed, &POOL_SPEC).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].name_str(), Some("dir/first.bin"));
    assert_eq!(parsed[0].payload(&packed), Some(&b"DATA0"[..]));
    assert_eq!(parsed[1].name_str(), Some("dir/second.bin"));
    assert_eq!(parsed[1].payload(&packed), Some(&b"DATA1!"[..]));

    // Length-prefixed (u16 LE) string pool round-trip
    const LEN_POOL_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        12,
        0,
        16,
        Some(IntFieldSpec::u32_le(4)),
        SizeMode::Stored(IntFieldSpec::u32_le(8)),
        TableTermination::Counted(2),
    )
    .with_name_pool(
        NamePoolSpec::new(
            IntFieldSpec::u32_le(0),
            OffsetBase::TableEnd,
            NameEncoding::PrintableAscii,
            32,
        )
        .with_format(NamePoolFormat::LengthPrefixed {
            len_width: IntWidth::U16,
            endian: Endian::Little,
        }),
    );
    let lp_packed =
        pack_fixed_record_table(&LEN_POOL_SPEC, &PackPolicy::TIGHT, &[], &inputs).unwrap();
    let lp_parsed = parse_fixed_record_table(&lp_packed, &LEN_POOL_SPEC).unwrap();
    assert_eq!(lp_parsed.len(), 2);
    assert_eq!(lp_parsed[0].name_str(), Some("dir/first.bin"));
    assert_eq!(lp_parsed[0].payload(&lp_packed), Some(&b"DATA0"[..]));
    assert_eq!(lp_parsed[1].name_str(), Some("dir/second.bin"));
    assert_eq!(lp_parsed[1].payload(&lp_packed), Some(&b"DATA1!"[..]));

    // Detached name pool slice with Absolute base inside pool_data
    const DETACHED_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        10,
        0,
        16,
        Some(IntFieldSpec::u32_le(2)),
        SizeMode::Stored(IntFieldSpec::u32_le(6)),
        TableTermination::Counted(2),
    )
    .with_name_pool(NamePoolSpec::new(
        IntFieldSpec::u16_le(0),
        OffsetBase::Absolute,
        NameEncoding::Ascii,
        8,
    ));
    let mut table = Vec::new();
    table.extend_from_slice(&0u16.to_le_bytes());
    table.extend_from_slice(&0u32.to_le_bytes());
    table.extend_from_slice(&100u32.to_le_bytes());
    table.extend_from_slice(&6u16.to_le_bytes());
    table.extend_from_slice(&100u32.to_le_bytes());
    table.extend_from_slice(&50u32.to_le_bytes());
    let pool_slice = b"alpha\0beta\0";
    let detached =
        parse_fixed_record_table_with_name_pool(&table, pool_slice, &DETACHED_SPEC, 200).unwrap();
    assert_eq!(detached.len(), 2);
    assert_eq!(detached[0].name_str(), Some("alpha"));
    assert_eq!(detached[1].name_str(), Some("beta"));

    let too_long_pool = b"0123456789\0";
    assert_eq!(
        parse_fixed_record_table_with_name_pool(&table, too_long_pool, &DETACHED_SPEC, 200),
        Err(LayoutError::InvalidName { index: 0 })
    );

    let both = POOL_SPEC.with_name_field(NameFieldSpec::new(0, 4, NameEncoding::Ascii));
    assert!(matches!(
        parse_fixed_record_table(&packed, &both),
        Err(LayoutError::InvalidSpec {
            field: "name_pool",
            ..
        })
    ));
}

#[test]
fn k7_key_field_u64_and_k8_subtract_base_round_trip_and_errors() {
    const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        16,
        0,
        16,
        Some(IntFieldSpec::u32_le(8)),
        SizeMode::Stored(IntFieldSpec::u32_le(12)),
        TableTermination::Counted(2),
    )
    .with_key_field(IntFieldSpec::u64_le(0))
    .with_offset_base(OffsetBase::SubtractBase(0x8001_0000));

    let inputs = [
        FixedRecordInput {
            name: None,
            key: Some(0xDEAD_BEEF_CAFE_BABE),
            payload: b"first",
            record_template: None,
        },
        FixedRecordInput {
            name: None,
            key: Some(0x0123_4567_89AB_CDEF),
            payload: b"second",
            record_template: None,
        },
    ];
    let packed = pack_fixed_record_table(&SPEC, &PackPolicy::TIGHT, &[], &inputs).unwrap();
    assert_eq!(
        u32::from_le_bytes(packed[8..12].try_into().unwrap()),
        0x8001_0020
    );
    let parsed = parse_fixed_record_table(&packed, &SPEC).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].key, Some(0xDEAD_BEEF_CAFE_BABE));
    assert_eq!(parsed[0].offset, 32);
    assert_eq!(parsed[0].payload(&packed), Some(&b"first"[..]));
    assert_eq!(parsed[1].key, Some(0x0123_4567_89AB_CDEF));
    assert_eq!(parsed[1].offset, 37);
    assert_eq!(parsed[1].payload(&packed), Some(&b"second"[..]));

    let mut underflow = packed.clone();
    underflow[8..12].copy_from_slice(&0x8000_FFFFu32.to_le_bytes());
    assert_eq!(
        parse_fixed_record_table(&underflow, &SPEC),
        Err(LayoutError::Overflow {
            what: "offset_subtract_base"
        })
    );
}

#[test]
fn knob1_field_not_equals_round_trip_and_validation() {
    const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        12,
        0,
        16,
        Some(IntFieldSpec::u32_le(4)),
        SizeMode::Stored(IntFieldSpec::u32_le(8)),
        TableTermination::FieldNotEquals {
            field: IntFieldSpec::u32_le(0),
            value: 1,
        },
    );
    let mut tmpl = [0u8; 12];
    tmpl[0..4].copy_from_slice(&1u32.to_le_bytes());
    let inputs = [
        FixedRecordInput {
            name: None,
            key: None,
            payload: b"first",
            record_template: Some(&tmpl),
        },
        FixedRecordInput {
            name: None,
            key: None,
            payload: b"second!",
            record_template: Some(&tmpl),
        },
    ];
    let packed = pack_fixed_record_table(&SPEC, &PackPolicy::TIGHT, &[], &inputs).unwrap();
    assert_eq!(u32::from_le_bytes(packed[24..28].try_into().unwrap()), 0);
    let parsed = parse_fixed_record_table(&packed, &SPEC).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].payload(&packed), Some(&b"first"[..]));
    assert_eq!(parsed[1].payload(&packed), Some(&b"second!"[..]));

    let meta =
        parse_fixed_record_table_metadata(&packed[..36], &SPEC, packed.len() as u64).unwrap();
    assert_eq!(meta.len(), 2);

    let bad_inputs = [FixedRecordInput {
        name: None,
        key: None,
        payload: b"bad",
        record_template: None,
    }];
    assert!(matches!(
        pack_fixed_record_table(&SPEC, &PackPolicy::TIGHT, &[], &bad_inputs),
        Err(LayoutError::InvalidInput { index: 0, .. })
    ));

    const ZERO_ACTIVE: FixedRecordTableSpec = FixedRecordTableSpec::new(
        12,
        0,
        16,
        Some(IntFieldSpec::u32_le(4)),
        SizeMode::Stored(IntFieldSpec::u32_le(8)),
        TableTermination::FieldNotEquals {
            field: IntFieldSpec::u32_le(0),
            value: 0,
        },
    );
    let zero_packed = pack_fixed_record_table(
        &ZERO_ACTIVE,
        &PackPolicy::TIGHT,
        &[],
        &[FixedRecordInput {
            name: None,
            key: None,
            payload: b"ok",
            record_template: None,
        }],
    )
    .unwrap();
    assert_eq!(
        u32::from_le_bytes(zero_packed[12..16].try_into().unwrap()),
        1
    );
    let zero_parsed = parse_fixed_record_table(&zero_packed, &ZERO_ACTIVE).unwrap();
    assert_eq!(zero_parsed.len(), 1);
    assert_eq!(zero_parsed[0].payload(&zero_packed), Some(&b"ok"[..]));
}

#[test]
fn knob2_skip_predicate_equals_and_not_equals_preserve_index_and_exact_len() {
    const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        8,
        0,
        16,
        Some(IntFieldSpec::u32_le(4)),
        SizeMode::NextOffset,
        TableTermination::Counted(4),
    )
    .with_key_field(IntFieldSpec::u32_le(0))
    .with_skip_field_equals(IntFieldSpec::u32_le(0), 0xFFFF_FFFF);

    let mut data = Vec::new();
    data.extend_from_slice(&10u32.to_le_bytes());
    data.extend_from_slice(&32u32.to_le_bytes());
    data.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&20u32.to_le_bytes());
    data.extend_from_slice(&36u32.to_le_bytes());
    data.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(b"AAAAbbbbb");

    let iter = iter_fixed_record_table(&data, &SPEC).unwrap();
    assert_eq!(iter.len(), 2);
    let entries: Vec<_> = iter.collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].index, 0);
    assert_eq!(entries[0].key, Some(10));
    assert_eq!(entries[0].payload(&data), Some(&b"AAAA"[..]));
    assert_eq!(entries[1].index, 2);
    assert_eq!(entries[1].key, Some(20));
    assert_eq!(entries[1].payload(&data), Some(&b"bbbbb"[..]));

    // RowFieldPredicate::NotEquals skips any row whose type tag != 1
    const NEQ_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        8,
        0,
        16,
        Some(IntFieldSpec::u32_le(4)),
        SizeMode::NextOffset,
        TableTermination::Counted(3),
    )
    .with_skip_field_not_equals(IntFieldSpec::u32_le(0), 1);

    let mut ndata = Vec::new();
    ndata.extend_from_slice(&2u32.to_le_bytes()); // skipped (2 != 1)
    ndata.extend_from_slice(&0u32.to_le_bytes());
    ndata.extend_from_slice(&1u32.to_le_bytes()); // active (slot 1)
    ndata.extend_from_slice(&24u32.to_le_bytes());
    ndata.extend_from_slice(&0u32.to_le_bytes()); // skipped (0 != 1)
    ndata.extend_from_slice(&0u32.to_le_bytes());
    ndata.extend_from_slice(b"HELLO");

    let nentries = parse_fixed_record_table(&ndata, &NEQ_SPEC).unwrap();
    assert_eq!(nentries.len(), 1);
    assert_eq!(nentries[0].index, 1);
    assert_eq!(nentries[0].payload(&ndata), Some(&b"HELLO"[..]));

    // Pack rejects row violating skip_field_not_equals
    let bad_row = [FixedRecordInput {
        name: None,
        key: None,
        payload: b"X",
        record_template: None, // tag == 0 != 1
    }];
    assert!(matches!(
        pack_fixed_record_table(&NEQ_SPEC, &PackPolicy::TIGHT, &[], &bad_row),
        Err(LayoutError::InvalidInput { index: 0, .. })
    ));
}

#[test]
fn knob3_table_start_table_end_plus_and_cumulative_from_table_end() {
    const TS_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        8,
        16,
        16,
        Some(IntFieldSpec::u32_le(0)),
        SizeMode::Stored(IntFieldSpec::u32_le(4)),
        TableTermination::Counted(2),
    )
    .with_offset_base(OffsetBase::TableStart);
    let inputs = [
        FixedRecordInput {
            name: None,
            key: None,
            payload: b"hello",
            record_template: None,
        },
        FixedRecordInput {
            name: None,
            key: None,
            payload: b"world",
            record_template: None,
        },
    ];
    let packed = pack_fixed_record_table(&TS_SPEC, &PackPolicy::TIGHT, b"HDR!", &inputs).unwrap();
    assert_eq!(u32::from_le_bytes(packed[16..20].try_into().unwrap()), 16);
    let parsed = parse_fixed_record_table(&packed, &TS_SPEC).unwrap();
    assert_eq!(parsed[0].offset, 32);
    assert_eq!(parsed[0].payload(&packed), Some(&b"hello"[..]));
    assert_eq!(parsed[1].offset, 37);
    assert_eq!(parsed[1].payload(&packed), Some(&b"world"[..]));

    const TEP_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        8,
        4,
        16,
        Some(IntFieldSpec::u32_le(0)),
        SizeMode::Stored(IntFieldSpec::u32_le(4)),
        TableTermination::Counted(2),
    )
    .with_offset_base(OffsetBase::TableEndPlus(12));
    let tep_packed = pack_fixed_record_table_with_post_table(
        &TEP_SPEC,
        &PackPolicy::TIGHT,
        b"PFX!",
        b"INTER_SECTION",
        &inputs,
    )
    .unwrap();
    let tep_parsed = parse_fixed_record_table(&tep_packed, &TEP_SPEC).unwrap();
    assert_eq!(tep_parsed[0].payload(&tep_packed), Some(&b"hello"[..]));
    assert_eq!(tep_parsed[1].payload(&tep_packed), Some(&b"world"[..]));

    const CUM_TE_SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        4,
        4,
        16,
        Some(IntFieldSpec::u32_le(0)),
        SizeMode::cumulative_from_table_end(8, 16),
        TableTermination::Counted(2),
    );
    let cum_packed = pack_fixed_record_table_with_post_table(
        &CUM_TE_SPEC,
        &PackPolicy::TIGHT,
        b"HDR0",
        b"POST_BLK",
        &inputs,
    )
    .unwrap();
    let cum_parsed = parse_fixed_record_table(&cum_packed, &CUM_TE_SPEC).unwrap();
    assert_eq!(cum_parsed.len(), 2);
    assert_eq!((cum_parsed[0].offset, cum_parsed[0].size), (20, 5));
    assert_eq!(cum_parsed[0].payload(&cum_packed), Some(&b"hello"[..]));
    assert_eq!((cum_parsed[1].offset, cum_parsed[1].size), (36, 5));
    assert_eq!(cum_parsed[1].payload(&cum_packed), Some(&b"world"[..]));
}

#[test]
fn knob5_sentinel_closes_next_offset_round_trips_with_trailing_bytes() {
    const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        12,
        0,
        16,
        Some(IntFieldSpec::u32_le(8)),
        SizeMode::NextOffset,
        TableTermination::FirstByteZero,
    )
    .with_name_field(NameFieldSpec::new(0, 8, NameEncoding::PrintableAscii))
    .with_sentinel_closes_next_offset(true);

    let inputs = [
        FixedRecordInput {
            name: Some(b"first"),
            key: None,
            payload: b"1234",
            record_template: None,
        },
        FixedRecordInput {
            name: Some(b"second"),
            key: None,
            payload: b"56789",
            record_template: None,
        },
    ];
    let mut packed = pack_fixed_record_table(&SPEC, &PackPolicy::TIGHT, &[], &inputs).unwrap();
    packed.extend_from_slice(b"TRAILING_JUNK_OUTSIDE_SENTINEL");

    let parsed = parse_fixed_record_table(&packed, &SPEC).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].name_str(), Some("first"));
    assert_eq!(parsed[0].payload(&packed), Some(&b"1234"[..]));
    assert_eq!(parsed[1].name_str(), Some("second"));
    assert_eq!(parsed[1].payload(&packed), Some(&b"56789"[..]));
}

#[test]
fn knob8_printable_ascii_and_post_table_bytes() {
    const SPEC: FixedRecordTableSpec = FixedRecordTableSpec::new(
        16,
        0,
        16,
        Some(IntFieldSpec::u32_le(8)),
        SizeMode::Stored(IntFieldSpec::u32_le(12)),
        TableTermination::Counted(1),
    )
    .with_name_field(NameFieldSpec::new(0, 8, NameEncoding::PrintableAscii));

    let inputs = [FixedRecordInput {
        name: Some(b"ok_1.bin"),
        key: None,
        payload: b"PAYLOAD",
        record_template: None,
    }];
    let post = b"SORTED_INDEX_BLOCK";
    let packed =
        pack_fixed_record_table_with_post_table(&SPEC, &PackPolicy::TIGHT, &[], post, &inputs)
            .unwrap();
    assert_eq!(&packed[16..16 + post.len()], post);
    let parsed = parse_fixed_record_table(&packed, &SPEC).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].name_str(), Some("ok_1.bin"));
    assert_eq!(parsed[0].offset, (16 + post.len()) as u64);
    assert_eq!(parsed[0].payload(&packed), Some(&b"PAYLOAD"[..]));

    let mut bad_ctrl = packed.clone();
    bad_ctrl[0..8].copy_from_slice(b"ab\x09   \0\0");
    assert_eq!(
        parse_fixed_record_table(&bad_ctrl, &SPEC),
        Err(LayoutError::InvalidName { index: 0 })
    );

    let mut bad_del = packed.clone();
    bad_del[0..8].copy_from_slice(b"ab\x7F\0\0\0\0\0");
    assert_eq!(
        parse_fixed_record_table(&bad_del, &SPEC),
        Err(LayoutError::InvalidName { index: 0 })
    );
    let bad_pack = [FixedRecordInput {
        name: Some(b"ab\x1F"),
        key: None,
        payload: b"X",
        record_template: None,
    }];
    assert_eq!(
        pack_fixed_record_table(&SPEC, &PackPolicy::TIGHT, &[], &bad_pack),
        Err(LayoutError::InvalidName { index: 0 })
    );
}
