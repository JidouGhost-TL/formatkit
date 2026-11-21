use super::*;
use formatkit_core::{CancellationToken, LsbInterleavedBitWriter, WorkLimits};
fn work() -> WorkBudget {
    WorkBudget::new(WorkLimits::unlimited())
}

#[test]
fn literal_count_zero_and_wrapped_counts_are_caller_choices() {
    let d = decode_with_work(b"suffix", 0, &[], 0, &mut work()).unwrap();
    assert!(d.bytes().is_empty());
    assert_eq!(d.extent().consumed, 0);
    let mut writer = LsbInterleavedBitWriter::new();
    for _ in 0..65536 {
        writer.write_bit(false);
        writer.write_byte(b'A');
    }
    let raw = writer.into_bytes();
    let d = decode_with_work(&raw, 65536, &[], 65536, &mut work()).unwrap();
    assert_eq!(d.bytes(), vec![b'A'; 65536]);
    assert_eq!(d.extent().consumed, raw.len());
}

#[test]
fn known_history_transitions_to_overlapping_output() {
    // One distance-three, length-six match. Full token consumed; tail untouched.
    let raw = [3, 2, 0x40, 0xee];
    let d = decode_with_work(&raw, 1, b"ABC", 6, &mut work()).unwrap();
    assert_eq!(d.bytes(), b"ABCABC");
    assert_eq!(d.extent().consumed, 3);
    assert_eq!(d.extent().unused_control_bits, 6);
    assert_eq!(d.extent().token_kinds, [0, 0, 1, 0]);
    assert!(decode_with_work(&raw, 1, b"AB", 6, &mut work()).is_err());
    assert!(decode_with_work(&raw, 1, &[], 6, &mut work()).is_err());
    assert!(decode_with_work(&raw, 1, b"ABC", 5, &mut work()).is_err());
    for end in 0..3 {
        assert!(decode_with_work(&raw[..end], 1, b"ABC", 6, &mut work()).is_err());
    }
    // History is the immediately preceding window, not its oldest prefix.
    let mut history = vec![0; 5000];
    history[4997..].copy_from_slice(b"XYZ");
    assert_eq!(
        decode_with_work(&raw, 1, &history, 6, &mut work())
            .unwrap()
            .bytes(),
        b"XYZXYZ"
    );
}

#[test]
fn both_control_branches_refill_and_preserve_suffix() {
    for prefix in 0..8 {
        let mut w = LsbInterleavedBitWriter::new();
        let mut expected = vec![b'Q'; prefix];
        for _ in 0..prefix {
            w.write_bit(false);
            w.write_byte(b'Q');
        }
        w.write_bit(true);
        w.write_bit(false);
        w.write_byte(0);
        w.write_bytes(b"hello world");
        expected.extend_from_slice(b"hello world");
        w.write_bit(true);
        w.write_bit(true);
        w.write_bytes(&[0, 0, 0]);
        expected.extend_from_slice(&[b'd'; 18]);
        let mut raw = w.into_bytes();
        let used = raw.len();
        raw.extend_from_slice(b"tail");
        let d =
            decode_with_work(&raw, prefix as u32 + 2, &[], expected.len(), &mut work()).unwrap();
        assert_eq!(d.bytes(), expected);
        assert_eq!(d.extent().consumed, used);
        assert_eq!(
            scan_with_work(&raw, prefix as u32 + 2, &[], expected.len(), &mut work()).unwrap(),
            d.extent()
        );
    }
}

#[test]
fn work_limits_exact_output_and_retained_lifetime() {
    let raw = [3, 0, 0x10]; // length three at distance one, supplied history
    let mut w = work();
    let held = decode_exact_with_work(&raw, 1, b"Z", 3, &mut w).unwrap();
    let capacity = held.capacity_bytes();
    assert_eq!(w.spent(R::Nodes), 4);
    assert_eq!(w.spent(R::MaterializedBytes), capacity);
    assert_eq!(w.usage().resident_bytes(), capacity);
    drop(held);
    assert_eq!(w.usage().resident_bytes(), 0);
    for resource in [R::Nodes, R::MaterializedBytes] {
        let needed = if resource == R::Nodes { 4 } else { capacity };
        let mut w = WorkBudget::new(WorkLimits::unlimited().with(resource, needed - 1));
        assert!(decode_exact_with_work(&raw, 1, b"Z", 3, &mut w).is_err());
        assert_eq!(w.usage().resident_bytes(), 0);
    }
    let mut w = WorkBudget::new(WorkLimits::unlimited().with_resident_bytes(capacity - 1));
    assert!(decode_exact_with_work(&raw, 1, b"Z", 3, &mut w).is_err());
    assert!(decode_exact_with_work(&raw, 1, b"Z", 4, &mut work()).is_err());
    let cancel = CancellationToken::new();
    cancel.cancel();
    let mut w = work().with_cancellation(cancel);
    assert!(matches!(
        decode_exact_with_work(&raw, 1, b"Z", 3, &mut w),
        Err(Error::Cancelled)
    ));
    assert_eq!(w.spent(R::MaterializedBytes), 0);
}
