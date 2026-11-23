//! Bit-depth widening ("bit unpack") with a conditional additive offset.
//!
//! Each input byte is split into `src_bits`-wide units, least-significant
//! unit first. Every unit is widened to `dst_bits`, optionally offset, and
//! packed back little-endian: sub-byte destination units fill each output
//! byte from bit 0 upward, and 16-bit or 32-bit units are written as
//! little-endian words. The offset is added to nonzero units, and also to zero
//! units when [`BitUnpackConfig::offset_zero`] is set; sums wrap and are then
//! truncated to `dst_bits`.
//!
//! Typical uses expand 1bpp font or mask data into 4bpp or 8bpp indices with a
//! palette base. The output length is always `input.len() * dst_bits / src_bits`
//! and is checked against `max_output` before allocating.
//!
//! ```
//! use formatkit_codec::bit_unpack::{bit_unpack, BitUnpackConfig};
//!
//! // 1bpp 0b1010_0101 -> 4bpp, nonzero units become 1 + 2 = 3.
//! let cfg = BitUnpackConfig { src_bits: 1, dst_bits: 4, offset: 2, offset_zero: false };
//! assert_eq!(bit_unpack(&[0b1010_0101], cfg, 64).unwrap(), [0x03, 0x03, 0x30, 0x30]);
//! ```

use formatkit_core::{Error, Result};

/// Parameters for [`bit_unpack`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitUnpackConfig {
    /// Source unit width in bits (`1`, `2`, `4`, or `8`).
    pub src_bits: u8,
    /// Destination unit width in bits (`1`, `2`, `4`, `8`, `16`, or `32`), at least `src_bits`.
    pub dst_bits: u8,
    /// Value added (wrapping) to each nonzero source unit.
    pub offset: u32,
    /// When `true`, `offset` is also added to zero source units.
    pub offset_zero: bool,
}

/// Widen every `cfg.src_bits` unit of `input` to `cfg.dst_bits`, applying the offset.
///
/// Fails with [`Error::InvalidField`] for unsupported or narrowing widths and
/// with [`Error::ResourceLimit`] when the output would exceed `max_output`.
#[doc(alias = "bitunpack")]
#[doc(alias = "bit depth")]
pub fn bit_unpack(input: &[u8], cfg: BitUnpackConfig, max_output: usize) -> Result<Vec<u8>> {
    if !matches!(cfg.src_bits, 1 | 2 | 4 | 8) {
        return Err(Error::InvalidField {
            what: "bit unpack source bits",
            value: u64::from(cfg.src_bits),
        });
    }
    if !matches!(cfg.dst_bits, 1 | 2 | 4 | 8 | 16 | 32) {
        return Err(Error::InvalidField {
            what: "bit unpack destination bits",
            value: u64::from(cfg.dst_bits),
        });
    }
    if cfg.dst_bits < cfg.src_bits {
        return Err(Error::InvalidField {
            what: "bit unpack destination narrower than source",
            value: u64::from(cfg.dst_bits),
        });
    }

    let ratio = usize::from(cfg.dst_bits / cfg.src_bits);
    let out_len = input.len().checked_mul(ratio);
    let Some(out_len) = out_len.filter(|&n| n <= max_output) else {
        return Err(Error::ResourceLimit {
            resource: "bit unpack output bytes",
            requested: out_len.map_or(u64::MAX, |n| n as u64),
            limit: max_output as u64,
        });
    };

    let mut out = Vec::with_capacity(out_len);
    let src_mask = (1u32 << cfg.src_bits) - 1;
    let dst_mask = if cfg.dst_bits == 32 {
        u32::MAX
    } else {
        (1u32 << cfg.dst_bits) - 1
    };
    let units = input.iter().flat_map(|&byte| {
        (0..8).step_by(usize::from(cfg.src_bits)).map(move |shift| {
            let raw = (u32::from(byte) >> shift) & src_mask;
            if raw != 0 || cfg.offset_zero {
                raw.wrapping_add(cfg.offset) & dst_mask
            } else {
                0
            }
        })
    });

    match cfg.dst_bits {
        8 => out.extend(units.map(|v| v as u8)),
        16 => units.for_each(|v| out.extend_from_slice(&(v as u16).to_le_bytes())),
        32 => units.for_each(|v| out.extend_from_slice(&v.to_le_bytes())),
        sub_byte => {
            let mut acc = 0u8;
            let mut bit = 0u8;
            for v in units {
                acc |= (v as u8) << bit;
                bit += sub_byte;
                if bit == 8 {
                    out.push(acc);
                    acc = 0;
                    bit = 0;
                }
            }
        }
    }
    debug_assert_eq!(out.len(), out_len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn cfg(src_bits: u8, dst_bits: u8, offset: u32, offset_zero: bool) -> BitUnpackConfig {
        BitUnpackConfig {
            src_bits,
            dst_bits,
            offset,
            offset_zero,
        }
    }

    #[test]
    fn reference_vectors_cover_sub_byte_byte_and_word_outputs() {
        let one = [0b1010_0101u8];
        assert_eq!(
            bit_unpack(&one, cfg(1, 4, 2, false), 64).unwrap(),
            [0x03, 0x03, 0x30, 0x30]
        );
        assert_eq!(
            bit_unpack(&one, cfg(1, 4, 2, true), 64).unwrap(),
            [0x23, 0x23, 0x32, 0x32]
        );
        assert_eq!(
            bit_unpack(&[0b11_10_01_00], cfg(2, 8, 10, false), 64).unwrap(),
            [0, 11, 12, 13]
        );
        assert_eq!(
            bit_unpack(&[0xA0], cfg(4, 16, 0x1000, true), 64).unwrap(),
            [0x00, 0x10, 0x0A, 0x10]
        );
        assert_eq!(
            bit_unpack(&[0x00, 0x05], cfg(8, 32, 0x0102_0300, false), 64).unwrap(),
            [0, 0, 0, 0, 0x05, 0x03, 0x02, 0x01]
        );
        assert_eq!(
            bit_unpack(&[0b0000_1010], cfg(1, 2, 0, false), 64).unwrap(),
            [0x44, 0x00]
        );
        // Offsets wrap and truncate to the destination width.
        assert_eq!(
            bit_unpack(&[0xFF], cfg(8, 8, 1, false), 64).unwrap(),
            [0x00]
        );
        assert_eq!(
            bit_unpack(&[0x0F], cfg(4, 4, 1, false), 64).unwrap(),
            [0x00]
        );
        // Identity widths copy input.
        assert_eq!(
            bit_unpack(&[0x12, 0x34], cfg(4, 4, 0, false), 64).unwrap(),
            [0x12, 0x34]
        );
        assert!(bit_unpack(&[], cfg(1, 4, 0, false), 64).unwrap().is_empty());
    }

    #[test]
    fn output_length_matches_ratio_for_every_width_pair() {
        let input: Vec<u8> = (0..=255).collect();
        for src in [1u8, 2, 4, 8] {
            for dst in [1u8, 2, 4, 8, 16, 32].into_iter().filter(|&d| d >= src) {
                let out = bit_unpack(&input, cfg(src, dst, 3, true), usize::MAX).unwrap();
                assert_eq!(out.len(), input.len() * usize::from(dst / src));
            }
        }
    }

    #[test]
    fn rejects_invalid_widths_and_output_limit() {
        for bad in [
            cfg(3, 4, 0, false),
            cfg(16, 16, 0, false),
            cfg(1, 3, 0, false),
        ] {
            assert!(matches!(
                bit_unpack(&[0], bad, 64),
                Err(Error::InvalidField { .. })
            ));
        }
        assert!(matches!(
            bit_unpack(&[0], cfg(1, 64, 0, false), 64),
            Err(Error::InvalidField { .. })
        ));
        assert!(matches!(
            bit_unpack(&[0], cfg(4, 2, 0, false), 64),
            Err(Error::InvalidField { .. })
        ));
        assert!(matches!(
            bit_unpack(&[0, 0], cfg(1, 4, 0, false), 7),
            Err(Error::ResourceLimit {
                requested: 8,
                limit: 7,
                ..
            })
        ));
    }
}
