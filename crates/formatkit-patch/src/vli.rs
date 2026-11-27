//! Bijective base-128 variable-length integer (VLI) encoder and decoder.
//!
//! Used by both UPS and BPS patch formats:
//! - Lower 7 bits of each byte store payload bits.
//! - Bit 7 (`0x80`) is the termination flag (set on the final byte).
//! - Non-final bytes shift left by 7 and bias by subtracting 1 during encoding
//!   (adding `shift` during decoding).

use crate::prelude::*;

use formatkit_core::{Error, Reader, Result};

/// Decode a bijective base-128 variable-length integer from a [`Reader`].
pub fn decode_vli(reader: &mut Reader<'_>) -> Result<u64> {
    let mut data: u64 = 0;
    let mut shift: u64 = 1;
    loop {
        let x = reader.u8()?;
        let term = u64::from(x & 0x7f)
            .checked_mul(shift)
            .ok_or_else(|| Error::Malformed("VLI integer overflow".into()))?;
        data = data
            .checked_add(term)
            .ok_or_else(|| Error::Malformed("VLI integer overflow".into()))?;
        if (x & 0x80) != 0 {
            break;
        }
        shift = shift
            .checked_shl(7)
            .ok_or_else(|| Error::Malformed("VLI shift overflow".into()))?;
        data = data
            .checked_add(shift)
            .ok_or_else(|| Error::Malformed("VLI integer overflow".into()))?;
    }
    Ok(data)
}

/// Decode a bijective base-128 variable-length integer from `slice` starting at `*offset`.
///
/// Advances `*offset` past the consumed bytes on success.
pub fn decode_vli_from_slice(slice: &[u8], offset: &mut usize) -> Result<u64> {
    if *offset > slice.len() {
        return Err(Error::Truncated {
            offset: *offset,
            needed: 1,
            available: 0,
        });
    }
    let mut reader = Reader::new(&slice[*offset..]);
    let value = decode_vli(&mut reader).map_err(|err| match err {
        Error::Truncated {
            offset: rel,
            needed,
            available,
        } => Error::Truncated {
            offset: offset.saturating_add(rel),
            needed,
            available,
        },
        other => other,
    })?;
    *offset += reader.pos();
    Ok(value)
}

/// Encode an unsigned 64-bit integer into bijective base-128 VLI bytes and append to `out`.
pub fn encode_vli(mut data: u64, out: &mut Vec<u8>) {
    loop {
        let x = (data & 0x7f) as u8;
        data >>= 7;
        if data == 0 {
            out.push(0x80 | x);
            break;
        }
        out.push(x);
        data -= 1;
    }
}

/// Encode an unsigned 64-bit integer into a newly allocated byte vector.
pub fn encode_vli_vec(data: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    encode_vli(data, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vli_round_trips() {
        let test_values = [
            0u64,
            1,
            2,
            127,
            128,
            129,
            255,
            256,
            16_383,
            16_384,
            65_535,
            16_777_216,
            0x1000_0000,
            0xffff_ffff,
            0x7fff_ffff_ffff_ffff,
            u64::MAX - 1,
            u64::MAX,
        ];

        for &val in &test_values {
            let encoded = encode_vli_vec(val);
            let mut offset = 0;
            let decoded = decode_vli_from_slice(&encoded, &mut offset).expect("slice decode");
            assert_eq!(offset, encoded.len());
            assert_eq!(decoded, val, "mismatch for value {val}");

            let mut reader = Reader::new(&encoded);
            let decoded_reader = decode_vli(&mut reader).expect("reader decode");
            assert_eq!(decoded_reader, val);
            assert_eq!(reader.remaining(), 0);
        }
    }

    #[test]
    fn vli_known_encodings() {
        assert_eq!(encode_vli_vec(0), vec![0x80]);
        assert_eq!(encode_vli_vec(1), vec![0x81]);
        assert_eq!(encode_vli_vec(127), vec![0xff]);
        assert_eq!(encode_vli_vec(128), vec![0x00, 0x80]);
        assert_eq!(encode_vli_vec(255), vec![0x7f, 0x80]);
        assert_eq!(encode_vli_vec(256), vec![0x00, 0x81]);
    }

    #[test]
    fn vli_unexpected_eof_and_overflow() {
        let incomplete = [0x00u8, 0x01];
        let mut offset = 0;
        assert!(matches!(
            decode_vli_from_slice(&incomplete, &mut offset),
            Err(Error::Truncated {
                offset: 2,
                needed: 1,
                available: 0
            })
        ));

        // 10 continuation bytes overflow shift/data.
        let overflow = [0x7fu8; 10];
        let mut reader = Reader::new(&overflow);
        assert!(matches!(decode_vli(&mut reader), Err(Error::Malformed(_))));

        // 10th byte with payload >= 2 overflows (x & 0x7f) * (1 << 63).
        let mul_overflow = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x82];
        let mut reader = Reader::new(&mul_overflow);
        assert!(matches!(decode_vli(&mut reader), Err(Error::Malformed(_))));
    }
}
