//! Generic 8-bit and 16-bit wrapping delta (prefix-sum / difference) filters.
//!
//! The `*_into` filters are allocation-free; callers own any container header,
//! framing, and output size limits. [`decode_tagged_delta`] and
//! [`encode_tagged_delta`] add a [`crate::tagged_header`] frame (tag
//! [`TAG_DELTA_8BIT`] `0x81` or [`TAG_DELTA_16BIT`] `0x82`) whose body is the
//! raw filtered bytes, with 16-bit words little-endian.
//!
//! ```
//! use formatkit_codec::delta::{decode_tagged_delta, encode_tagged_delta, TaggedDeltaWidth};
//!
//! let data = [10u8, 15, 10, 10, 0];
//! let stream = encode_tagged_delta(&data, TaggedDeltaWidth::Bits8).unwrap();
//! assert_eq!(stream, [0x81, 5, 0, 0, 10, 5, 251, 0, 246]);
//! let decoded = decode_tagged_delta(&stream, 64).unwrap();
//! assert_eq!((decoded.bytes.as_slice(), decoded.consumed), (&data[..], 9));
//! ```
//!
//! [`TAG_DELTA_16BIT`]: crate::tagged_header::TAG_DELTA_16BIT
//! [`TAG_DELTA_8BIT`]: crate::tagged_header::TAG_DELTA_8BIT

use formatkit_core::{bytes_at, Error, Result};

use crate::tagged_header::{
    check_decoded_size, check_encode_len, read_tagged_header, shift_truncated, write_tagged_header,
    TAGGED_HEADER_LEN,
};
pub use crate::tagged_header::{TAG_DELTA_16BIT, TAG_DELTA_8BIT};
use crate::DecodeOutcome;

/// Decode an 8-bit wrapping delta stream (`out[i] = acc.wrapping_add(src[i])`).
pub fn delta_decode_u8_into(src: &[u8], out: &mut Vec<u8>) {
    let mut acc = 0u8;
    for &delta in src {
        acc = acc.wrapping_add(delta);
        out.push(acc);
    }
}

/// Encode bytes as an 8-bit wrapping delta stream (`out[i] = src[i].wrapping_sub(prev)`).
pub fn delta_encode_u8_into(src: &[u8], out: &mut Vec<u8>) {
    let mut prev = 0u8;
    for &byte in src {
        out.push(byte.wrapping_sub(prev));
        prev = byte;
    }
}

/// Decode a little-endian 16-bit wrapping delta stream (`src.len()` must be even).
pub fn delta_decode_u16_le_into(src: &[u8], out: &mut Vec<u8>) {
    let mut acc = 0u16;
    for &chunk in src.as_chunks::<2>().0 {
        acc = acc.wrapping_add(u16::from_le_bytes(chunk));
        out.extend_from_slice(&acc.to_le_bytes());
    }
}

/// Encode little-endian 16-bit words as a wrapping delta stream (`src.len()` must be even).
pub fn delta_encode_u16_le_into(src: &[u8], out: &mut Vec<u8>) {
    let mut prev = 0u16;
    for &chunk in src.as_chunks::<2>().0 {
        let word = u16::from_le_bytes(chunk);
        out.extend_from_slice(&word.wrapping_sub(prev).to_le_bytes());
        prev = word;
    }
}

/// Decode a big-endian 16-bit wrapping delta stream (`src.len()` must be even).
pub fn delta_decode_u16_be_into(src: &[u8], out: &mut Vec<u8>) {
    let mut acc = 0u16;
    for &chunk in src.as_chunks::<2>().0 {
        acc = acc.wrapping_add(u16::from_be_bytes(chunk));
        out.extend_from_slice(&acc.to_be_bytes());
    }
}

/// Encode big-endian 16-bit words as a wrapping delta stream (`src.len()` must be even).
pub fn delta_encode_u16_be_into(src: &[u8], out: &mut Vec<u8>) {
    let mut prev = 0u16;
    for &chunk in src.as_chunks::<2>().0 {
        let word = u16::from_be_bytes(chunk);
        out.extend_from_slice(&word.wrapping_sub(prev).to_be_bytes());
        prev = word;
    }
}

/// Unit width of a tagged delta-filtered stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaggedDeltaWidth {
    /// 8-bit units ([`TAG_DELTA_8BIT`]).
    Bits8,
    /// Little-endian 16-bit units ([`TAG_DELTA_16BIT`]); sizes must be even.
    Bits16,
}

impl TaggedDeltaWidth {
    /// Stream tag for this width.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Bits8 => TAG_DELTA_8BIT,
            Self::Bits16 => TAG_DELTA_16BIT,
        }
    }

    /// Width for a stream tag, if it names a tagged delta stream.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            TAG_DELTA_8BIT => Some(Self::Bits8),
            TAG_DELTA_16BIT => Some(Self::Bits16),
            _ => None,
        }
    }
}

/// Decode an 8-bit (`0x81`) or 16-bit little-endian (`0x82`) tagged delta
/// stream starting at `input[0]`.
///
/// Rejects an unknown tag, a zero declared size, an odd 16-bit size, a
/// declared size above `max_output`, or a body shorter than the declared size
/// before allocating. The consumed extent is exactly header plus declared size.
pub fn decode_tagged_delta(input: &[u8], max_output: usize) -> Result<DecodeOutcome> {
    let header = read_tagged_header(input)?;
    let width = TaggedDeltaWidth::from_tag(header.tag).ok_or(Error::BadMagic {
        offset: 0,
        expected: u32::from(TAG_DELTA_8BIT),
        found: u32::from(header.tag),
    })?;
    check_decoded_size(
        header,
        "tagged delta decoded size",
        "tagged delta decoded output",
        max_output,
    )?;
    if width == TaggedDeltaWidth::Bits16 && !header.decoded_size.is_multiple_of(2) {
        return Err(Error::InvalidField {
            what: "tagged 16-bit delta decoded size",
            value: header.decoded_size as u64,
        });
    }
    let body = bytes_at(&input[TAGGED_HEADER_LEN..], 0, header.decoded_size)
        .map_err(|err| shift_truncated(err, TAGGED_HEADER_LEN))?;
    let mut out = Vec::with_capacity(header.decoded_size);
    match width {
        TaggedDeltaWidth::Bits8 => delta_decode_u8_into(body, &mut out),
        TaggedDeltaWidth::Bits16 => delta_decode_u16_le_into(body, &mut out),
    }
    Ok(DecodeOutcome {
        bytes: out,
        consumed: TAGGED_HEADER_LEN + header.decoded_size,
    })
}

/// Encode `data` (`1..=0xFF_FFFF` bytes; even for [`TaggedDeltaWidth::Bits16`])
/// as a tagged delta stream.
pub fn encode_tagged_delta(data: &[u8], width: TaggedDeltaWidth) -> Result<Vec<u8>> {
    check_encode_len(data.len(), "tagged delta input size")?;
    if width == TaggedDeltaWidth::Bits16 && !data.len().is_multiple_of(2) {
        return Err(Error::InvalidField {
            what: "tagged 16-bit delta input size",
            value: data.len() as u64,
        });
    }
    let mut out = Vec::with_capacity(TAGGED_HEADER_LEN + data.len());
    write_tagged_header(&mut out, width.tag(), data.len())?;
    match width {
        TaggedDeltaWidth::Bits8 => delta_encode_u8_into(data, &mut out),
        TaggedDeltaWidth::Bits16 => delta_encode_u16_le_into(data, &mut out),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_delta_reference_vectors_and_round_trip() {
        // 16-bit deltas 0x0100, 0x0050, 0xFFFE -> words 0x0100, 0x0150, 0x014E.
        let d16 = [0x82, 6, 0, 0, 0x00, 0x01, 0x50, 0x00, 0xFE, 0xFF, 0xDD];
        let dec16 = decode_tagged_delta(&d16, 64).unwrap();
        assert_eq!(dec16.bytes, [0x00, 0x01, 0x50, 0x01, 0x4E, 0x01]);
        assert_eq!(dec16.consumed, 10);

        let data: Vec<u8> = (0..64u8)
            .map(|i| i.wrapping_mul(37).wrapping_add(11))
            .collect();
        for width in [TaggedDeltaWidth::Bits8, TaggedDeltaWidth::Bits16] {
            let mut stream = encode_tagged_delta(&data, width).unwrap();
            assert_eq!(stream[0], width.tag());
            let exact = stream.len();
            stream.extend_from_slice(&[0xAA, 0xBB]);
            let decoded = decode_tagged_delta(&stream, data.len()).unwrap();
            assert_eq!(decoded.bytes, data);
            assert_eq!(decoded.consumed, exact);
        }
    }

    #[test]
    fn tagged_delta_rejects_malformed_frames() {
        assert!(encode_tagged_delta(&[], TaggedDeltaWidth::Bits8).is_err());
        assert!(encode_tagged_delta(&[1, 2, 3], TaggedDeltaWidth::Bits16).is_err());
        assert!(matches!(
            decode_tagged_delta(&[0x82, 3, 0, 0, 1, 2, 3], 64),
            Err(Error::InvalidField { .. })
        ));
        assert!(matches!(
            decode_tagged_delta(&[0x80, 2, 0, 0, 1, 2], 64),
            Err(Error::BadMagic { .. })
        ));
        assert!(matches!(
            decode_tagged_delta(&[0x81, 0, 0, 0], 64),
            Err(Error::InvalidField { .. })
        ));
        assert!(matches!(
            decode_tagged_delta(&[0x81, 4, 0, 0, 1, 2], 64),
            Err(Error::Truncated { offset: 4, .. })
        ));
        assert!(matches!(
            decode_tagged_delta(&[0x81, 4, 0, 0, 1, 2, 3, 4], 3),
            Err(Error::ResourceLimit { .. })
        ));
        assert!(matches!(
            decode_tagged_delta(&[0x81, 0, 0, 0x40, 0], 1 << 23),
            Err(Error::Truncated { .. })
        ));
        for cut in 0..4 {
            assert!(decode_tagged_delta(&[0x81, 1, 0, 0][..cut], 64).is_err());
        }
    }

    #[test]
    fn u8_and_u16_le_be_delta_round_trip() {
        let src = [10u8, 12, 12, 5, 250, 3];
        let mut enc = Vec::new();
        delta_encode_u8_into(&src, &mut enc);
        let mut dec = Vec::new();
        delta_decode_u8_into(&enc, &mut dec);
        assert_eq!(dec, src);

        let src16 = [0x10u8, 0x00, 0x20, 0x01, 0x05, 0xFF, 0x00, 0x00];
        let mut enc16 = Vec::new();
        delta_encode_u16_le_into(&src16, &mut enc16);
        let mut dec16 = Vec::new();
        delta_decode_u16_le_into(&enc16, &mut dec16);
        assert_eq!(dec16, src16);

        let mut enc16_be = Vec::new();
        delta_encode_u16_be_into(&src16, &mut enc16_be);
        assert_ne!(enc16_be, enc16);
        let mut dec16_be = Vec::new();
        delta_decode_u16_be_into(&enc16_be, &mut dec16_be);
        assert_eq!(dec16_be, src16);
    }
}
