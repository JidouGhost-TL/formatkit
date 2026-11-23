//! Generic 8-bit and 16-bit wrapping delta (prefix-sum / difference) filters.
//!
//! Callers own any container header, framing, and output size limits.

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

#[cfg(test)]
mod tests {
    use super::*;

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
