use super::*;

fn dxt1_block(c0: u16, c1: u16, indices: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&c0.to_le_bytes());
    b.extend_from_slice(&c1.to_le_bytes());
    b.extend_from_slice(&indices.to_le_bytes());
    b
}

// ---- the trap ----------------------------------------------------------

/// The DXT5 alpha interpolants are convex combinations of the two
/// endpoints, so every one of them must lie between those endpoints. The
/// off-by-one this pins — weights summing past the denominator — pushes an
/// interpolant above `a0` and, on bright blocks, past 255, where the cast to
/// `u8` wraps it to near-zero. That renders as a plausible image, so only an
/// invariant check catches it.
#[test]
fn dxt5_alpha_interpolants_never_leave_the_endpoint_range() {
    for a0 in 0..=255u8 {
        for a1 in 0..=255u8 {
            let table = dxt5_alpha_table(a0, a1);
            let (lo, hi) = (a0.min(a1), a0.max(a1));
            // In the six-interpolant mode every slot is interpolated; in the
            // four-interpolant mode slots 6 and 7 are the reserved 0 and 255.
            let interpolated = if a0 > a1 { &table[2..8] } else { &table[2..6] };
            for &v in interpolated {
                assert!(
                    v >= lo && v <= hi,
                    "a0={a0} a1={a1}: interpolant {v} outside [{lo},{hi}] in {table:?}"
                );
            }
        }
    }
}

/// The exact constants, spelled out, for both endpoint orderings.
#[test]
fn dxt5_alpha_table_matches_the_spec_constants() {
    // Six-interpolant mode: ((6-i)*a0 + (i+1)*a1) / 7.
    assert_eq!(
        dxt5_alpha_table(255, 0),
        [255, 0, 218, 182, 145, 109, 72, 36]
    );
    // Four-interpolant mode plus the reserved 0 and 255 terminators.
    assert_eq!(
        dxt5_alpha_table(0, 255),
        [0, 255, 51, 102, 153, 204, 0, 255]
    );
    // Equal endpoints take the four-interpolant branch and must stay flat.
    assert_eq!(
        dxt5_alpha_table(255, 255),
        [255, 255, 255, 255, 255, 255, 0, 255]
    );
}

/// The colour interpolants are convex combinations too, and the same class
/// of off-by-one overshoots them.
#[test]
fn dxt_color_interpolants_never_leave_the_endpoint_range() {
    for &(c0, c1) in &[
        (0xffffu16, 0x0000u16),
        (0x0000, 0xffff),
        (0xf800, 0x001f),
        (0xffff, 0xfffe),
    ] {
        let table = dxt_color_table(&dxt1_block(c0, c1, 0), false);
        for ch in 0..3 {
            let (lo, hi) = (
                table[0][ch].min(table[1][ch]),
                table[0][ch].max(table[1][ch]),
            );
            assert!(table[2][ch] >= lo && table[2][ch] <= hi, "{table:?}");
            assert!(table[3][ch] >= lo && table[3][ch] <= hi, "{table:?}");
        }
    }
}

// ---- texel expansion ---------------------------------------------------

/// RGB565 puts red in the high bits — the opposite of the low-red-bit-order helper
/// next door. Confusing them swaps red and blue and still looks like a
/// picture.
#[test]
fn rgb565_reads_red_from_the_high_bits() {
    assert_eq!(rgb565_to_rgba(0xf800), [255, 0, 0, 255]);
    assert_eq!(rgb565_to_rgba(0x07e0), [0, 255, 0, 255]);
    assert_eq!(rgb565_to_rgba(0x001f), [0, 0, 255, 255]);
    // The other helper is the mirror image; if these ever agree, one of them
    // has changed channel order.
    assert_eq!(crate::rgba5650_to_rgba(0xf800), [0, 0, 255, 255]);
}

/// Channel expansion is bit replication at every width, and full scale
/// always reaches 255. A plain left shift would leave 5-bit white at 248,
/// which bands every gradient without ever failing.
#[test]
fn channel_expansion_replicates_bits_and_reaches_full_scale() {
    for v in 0..16u32 {
        assert_eq!(expand_channel(v, 4), ((v << 4) | v) as u8);
    }
    for v in 0..32u32 {
        assert_eq!(expand_channel(v, 5), ((v << 3) | (v >> 2)) as u8);
    }
    for v in 0..64u32 {
        assert_eq!(expand_channel(v, 6), ((v << 2) | (v >> 4)) as u8);
    }
    for bits in 1..=8u32 {
        let max = (1u32 << bits) - 1;
        assert_eq!(expand_channel(max, bits), 255, "full scale at {bits} bits");
        assert_eq!(expand_channel(0, bits), 0, "zero at {bits} bits");
    }
}
