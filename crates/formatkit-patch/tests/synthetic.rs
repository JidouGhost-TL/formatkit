use formatkit_patch::ips::{
    create, ApplyOptions, GrowthPolicy, OverlapPolicy, Patch, Record, RecordData, EOF_OFFSET,
    MAX_OFFSET,
};

fn growing() -> ApplyOptions {
    ApplyOptions {
        growth: GrowthPolicy::ZeroFill,
        ..ApplyOptions::default()
    }
}

#[test]
fn literal_rle_and_eof_truncation_fixture() {
    let bytes = b"PATCH\0\0\x02\0\x02ab\0\0\x06\0\0\0\x03zEOF\0\0\x08";
    let patch = Patch::parse(bytes).unwrap();
    assert_eq!(patch.records.len(), 2);
    assert_eq!(patch.truncate_to, Some(8));
    assert_eq!(
        patch.apply(b"0123456789", ApplyOptions::default()).unwrap(),
        b"01ab45zz"
    );
    assert_eq!(patch.encode().unwrap(), bytes);
}

#[test]
fn growth_is_explicit_and_zero_fills_gaps_and_eof_extension() {
    let patch = Patch::parse(b"PATCH\0\0\x04\0\0\0\x02xEOF\0\0\x08").unwrap();
    assert!(patch.apply(b"ab", ApplyOptions::default()).is_err());
    assert_eq!(patch.apply(b"ab", growing()).unwrap(), b"ab\0\0xx\0\0");
    assert!(patch
        .apply(
            b"ab",
            ApplyOptions {
                max_output_size: 7,
                ..growing()
            }
        )
        .is_err());
    // Even writes discarded by a final truncation must obey growth policy.
    let patch = Patch::parse(b"PATCH\0\0\x04\0\x01xEOF\0\0\x01").unwrap();
    assert!(patch.apply(b"ab", ApplyOptions::default()).is_err());
    assert_eq!(patch.apply(b"ab", growing()).unwrap(), b"a");
}

#[test]
fn overlaps_are_valid_grammar_but_require_policy_and_keep_file_order() {
    let bytes = b"PATCH\0\0\x02\0\x02ab\0\0\x01\0\x02cdEOF";
    let patch = Patch::parse(bytes).unwrap();
    assert!(patch.apply(b"01234", ApplyOptions::default()).is_err());
    let options = ApplyOptions {
        overlaps: OverlapPolicy::LastWriteWins,
        ..ApplyOptions::default()
    };
    assert_eq!(patch.validate(5, options).unwrap().overlapping_records, 1);
    assert_eq!(patch.apply(b"01234", options).unwrap(), b"0cdb4");
}

#[test]
fn malformed_and_short_inputs_return_errors() {
    let fixture = b"PATCH\0\0\x01\0\x02ab\0\0\x06\0\0\0\x03zEOF";
    for end in 0..fixture.len() {
        assert!(Patch::parse(&fixture[..end]).is_err(), "prefix {end}");
    }
    for bytes in [
        b"WRONGEOF".as_slice(),
        b"PATCHEOFx",
        b"PATCHEOFxx",
        b"PATCHEOFxxxx",
        b"PATCH\0\0\x01\0\0\0\0xEOF",
    ] {
        assert!(Patch::parse(bytes).is_err());
    }
    assert!(Patch::parse_with_record_limit(fixture, 1).is_err());
    assert!(Patch::parse_with_record_limit(b"PATCHEOF", 0).is_ok());
}

#[test]
fn programmatic_invalid_records_and_final_size_are_rejected() {
    for record in [
        Record {
            offset: MAX_OFFSET + 1,
            data: RecordData::Literal(b"x"),
        },
        Record {
            offset: EOF_OFFSET,
            data: RecordData::Literal(b"x"),
        },
        Record {
            offset: 0,
            data: RecordData::Literal(b""),
        },
        Record {
            offset: 0,
            data: RecordData::Rle { len: 0, value: 0 },
        },
    ] {
        let patch = Patch {
            records: vec![record],
            truncate_to: None,
        };
        assert!(patch.encode().is_err());
        assert!(patch.apply(b"", growing()).is_err());
    }
    let patch = Patch {
        records: vec![],
        truncate_to: Some(MAX_OFFSET + 1),
    };
    assert!(patch.encode().is_err());
    assert!(patch.validate(0, growing()).is_err());
}

#[test]
fn diff_round_trips_empty_shrinking_growing_and_constant_images() {
    for (base, target) in [
        (b"abc".as_slice(), b"abc".as_slice()),
        (b"abc", b""),
        (b"", b"abc"),
        (b"abc", b"a"),
        (b"abc", b"ab\0\0\0"),
        (b"aaaa", b"bbbb"),
    ] {
        let bytes = create(base, target).unwrap();
        let patch = Patch::parse(&bytes).unwrap();
        assert_eq!(patch.apply(base, growing()).unwrap(), target);
    }
    assert_eq!(create(b"abc", b"abc").unwrap(), b"PATCHEOF");
    let bytes = create(b"aaaa", b"bbbb").unwrap();
    assert!(matches!(
        Patch::parse(&bytes).unwrap().records[0].data,
        RecordData::Rle {
            len: 4,
            value: b'b'
        }
    ));
}

#[test]
fn diff_splits_maximum_record_lengths() {
    let target = vec![7; 0x10001];
    let bytes = create(&[], &target).unwrap();
    let patch = Patch::parse(&bytes).unwrap();
    assert_eq!(patch.records.len(), 2);
    assert_eq!(patch.records[0].data.len(), 0xffff);
    assert_eq!(patch.apply(&[], growing()).unwrap(), target);
}

#[test]
fn encoding_and_application_limits_check_maximum_extents_before_allocation() {
    let patch = Patch {
        records: vec![],
        truncate_to: None,
    };
    assert_eq!(patch.encode_with_size_limit(8).unwrap(), b"PATCHEOF");
    assert!(patch.encode_with_size_limit(7).is_err());
    let long = vec![0; 0x10000];
    let patch = Patch {
        records: vec![Record {
            offset: 0,
            data: RecordData::Literal(&long),
        }],
        truncate_to: None,
    };
    assert!(patch.encode().is_err());
    let patch = Patch {
        records: vec![Record {
            offset: MAX_OFFSET,
            data: RecordData::Rle {
                len: 0xffff,
                value: 1,
            },
        }],
        truncate_to: None,
    };
    let extent = MAX_OFFSET as usize + 0xffff;
    assert_eq!(patch.validate(0, growing()).unwrap().output_size, extent);
    assert!(patch
        .apply(
            &[],
            ApplyOptions {
                max_output_size: extent - 1,
                ..growing()
            }
        )
        .is_err());
    let bytes = patch.encode().unwrap();
    assert_eq!(Patch::parse(&bytes).unwrap(), patch);
    let zero = Patch::parse(b"PATCHEOF\0\0\0").unwrap();
    assert_eq!(zero.apply(b"abc", ApplyOptions::default()).unwrap(), b"");
}

#[test]
fn generated_inputs_never_panic_and_diff_outputs_match_independent_targets() {
    let mut state = 0x6d2b_79f5u32;
    let mut byte = || {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        state as u8
    };
    for size in 0..512 {
        let mut input: Vec<_> = (0..size).map(|_| byte()).collect();
        if size >= 5 {
            input[..5].copy_from_slice(b"PATCH");
        }
        if let Ok(patch) = Patch::parse_with_record_limit(&input, 32) {
            let _ = patch.apply(
                &[0; 32],
                ApplyOptions {
                    max_output_size: 32,
                    ..growing()
                },
            );
        }
    }
    for case in 0..2048 {
        let base: Vec<_> = (0..case % 129).map(|_| byte()).collect();
        let mut target = base.clone();
        target.resize((case * 37) % 145, 0);
        for value in &mut target {
            if byte() & 3 == 0 {
                *value = byte();
            }
        }
        let bytes = create(&base, &target).unwrap();
        let patch = Patch::parse(&bytes).unwrap();
        assert_eq!(
            patch.apply(&base, growing()).unwrap(),
            target,
            "case {case}"
        );
    }
}

#[test]
fn diff_escapes_reserved_eof_offset_including_record_splits() {
    let mut target = vec![0; EOF_OFFSET as usize + 2];
    let base = target.clone();
    target[EOF_OFFSET as usize] = 1;
    let bytes = create(&base, &target).unwrap();
    let patch = Patch::parse(&bytes).unwrap();
    assert_eq!(patch.records[0].offset, EOF_OFFSET - 1);
    assert_eq!(patch.apply(&base, growing()).unwrap(), target);
    let start = EOF_OFFSET as usize - 0xffff;
    target[start..].fill(7);
    let bytes = create(&base, &target).unwrap();
    let patch = Patch::parse(&bytes).unwrap();
    assert_eq!(patch.records[1].offset, EOF_OFFSET - 1);
    assert_eq!(patch.apply(&base, growing()).unwrap(), target);
}
