//! Deterministic DEFLATE encoders for formats whose native member storage is
//! an ordinary zlib stream.

/// Compress `data` as a zlib-wrapped DEFLATE stream at the library's normal
/// level 9 compression.
///
/// This is deliberately distinct from [`crate::zlib_store`]: the latter emits
/// DEFLATE stored blocks and is useful as a tiny dependency-free fallback,
/// while this function performs real match finding and Huffman coding. Given
/// the same `formatkit-codec` build and input, the output is deterministic.
pub fn zlib_compress(data: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(data, 9)
}

/// Compress `data` as a raw RFC 1951 DEFLATE stream at level 9.
///
/// ZIP members carry raw DEFLATE bytes: unlike [`zlib_compress`], there is no
/// RFC 1950 header or Adler-32 trailer around the coded blocks.
pub fn deflate_compress(data: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec(data, 9)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_zlib_round_trips_and_is_not_a_stored_block() {
        let input = b"deterministic script replacement. ".repeat(512);
        let encoded = zlib_compress(&input);
        assert!(encoded.len() < input.len() / 4);
        // First DEFLATE block follows the two-byte zlib header. BTYPE 00 is a
        // stored block; a normal encoder should choose a coded block here.
        assert_ne!((encoded[2] >> 1) & 0b11, 0);
        assert_eq!(
            crate::zlib_inflate_with_limit(&encoded, input.len()).unwrap(),
            input
        );
        assert_eq!(encoded, zlib_compress(&input));
    }

    #[test]
    fn raw_deflate_round_trips_deterministically() {
        let input = b"ZIP member payload. ".repeat(512);
        let encoded = deflate_compress(&input);
        assert!(encoded.len() < input.len() / 4);
        assert_eq!(
            crate::inflate_with_limit(&encoded, input.len()).unwrap(),
            input
        );
        assert_eq!(encoded, deflate_compress(&input));
    }
}
