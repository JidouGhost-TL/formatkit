//! **DEFLATE** (RFC 1951) and its **zlib** wrapper (RFC 1950).
//!
//! Unlike the other codecs here, DEFLATE is a published general-purpose format
//! rather than a per-title variant, so there are no parameters to pin. It is
//! present because several containers store their members as zlib streams and
//! the archive layer needs to hand back the asset, not the stored bytes.
//!
//! The decoder is canonical-Huffman, decoding a symbol bit by bit against
//! per-length counts. Malformed input yields `None` rather than panicking, and
//! every write is bounded by `max_output_len`, so a hostile declared length
//! cannot force an allocation.

use formatkit_core::checksum::adler32;
use formatkit_core::LsbBitCursor;

use crate::DecodeOutcome;

type Bits<'a> = LsbBitCursor<'a>;

/// A canonical Huffman table: symbol counts per code length, and symbols in
/// canonical order.
struct Huffman {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl Huffman {
    /// Build from a code-length-per-symbol table.
    fn new(lengths: &[u8]) -> Option<Huffman> {
        let mut counts = [0u16; 16];
        for &l in lengths {
            if l as usize >= 16 {
                return None;
            }
            counts[l as usize] += 1;
        }
        counts[0] = 0;
        // Reject over-subscribed sets; an incomplete set is legal only for a
        // single-symbol distance tree, which the caller tolerates.
        let mut left = 1i32;
        for &count in &counts[1..16] {
            left = (left << 1) - i32::from(count);
            if left < 0 {
                return None;
            }
        }
        let mut offs = [0u16; 16];
        for len in 1..15 {
            offs[len + 1] = offs[len] + counts[len];
        }
        let mut symbols = vec![0u16; lengths.len()];
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                symbols[offs[l as usize] as usize] = sym as u16;
                offs[l as usize] += 1;
            }
        }
        Some(Huffman { counts, symbols })
    }

    /// Decode one symbol.
    fn decode(&self, b: &mut Bits<'_>) -> Option<u16> {
        let mut code = 0i32;
        let mut first = 0i32;
        let mut index = 0i32;
        for len in 1..16 {
            code |= b.read(1)? as i32;
            let count = i32::from(self.counts[len]);
            if code - count < first {
                return self.symbols.get((index + (code - first)) as usize).copied();
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        None
    }
}

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// RFC 1951 order in which code-length code lengths are stored.
const CLEN_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// Build the fixed literal/length and distance trees of RFC 1951 §3.2.6.
fn fixed_trees() -> Option<(Huffman, Huffman)> {
    let mut lit = [0u8; 288];
    for (i, l) in lit.iter_mut().enumerate() {
        *l = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    Some((Huffman::new(&lit)?, Huffman::new(&[5u8; 30])?))
}

/// Read the dynamic trees of RFC 1951 §3.2.7.
fn dynamic_trees(b: &mut Bits<'_>) -> Option<(Huffman, Huffman)> {
    let hlit = b.read(5)? as usize + 257;
    let hdist = b.read(5)? as usize + 1;
    let hclen = b.read(4)? as usize + 4;
    if hlit > 286 || hdist > 30 {
        return None;
    }
    let mut clen = [0u8; 19];
    for &slot in CLEN_ORDER.iter().take(hclen) {
        clen[slot] = b.read(3)? as u8;
    }
    let cl = Huffman::new(&clen)?;

    let mut lengths = vec![0u8; hlit + hdist];
    let mut i = 0;
    while i < lengths.len() {
        let sym = cl.decode(b)?;
        match sym {
            0..=15 => {
                lengths[i] = sym as u8;
                i += 1;
            }
            16 => {
                // Repeat the previous length 3-6 times.
                let prev = if i == 0 { return None } else { lengths[i - 1] };
                let n = 3 + b.read(2)? as usize;
                if i + n > lengths.len() {
                    return None;
                }
                for _ in 0..n {
                    lengths[i] = prev;
                    i += 1;
                }
            }
            17 | 18 => {
                // Repeat a zero length 3-10 (17) or 11-138 (18) times.
                let n = if sym == 17 {
                    3 + b.read(3)? as usize
                } else {
                    11 + b.read(7)? as usize
                };
                if i + n > lengths.len() {
                    return None;
                }
                i += n;
            }
            _ => return None,
        }
    }
    let lit = Huffman::new(&lengths[..hlit])?;
    let dist = Huffman::new(&lengths[hlit..])?;
    Some((lit, dist))
}

/// Decode one Huffman-coded block body into `out`.
fn inflate_block(
    b: &mut Bits<'_>,
    out: &mut Vec<u8>,
    lit: &Huffman,
    dist: &Huffman,
    max_output_len: usize,
) -> Option<()> {
    loop {
        let sym = lit.decode(b)?;
        match sym {
            0..=255 => {
                if out.len() >= max_output_len {
                    return None;
                }
                out.push(sym as u8);
            }
            256 => return Some(()),
            257..=285 => {
                let i = sym as usize - 257;
                let len = LEN_BASE[i] as usize + b.read(u32::from(LEN_EXTRA[i]))? as usize;
                let dsym = dist.decode(b)? as usize;
                if dsym >= 30 {
                    return None;
                }
                let d = DIST_BASE[dsym] as usize + b.read(u32::from(DIST_EXTRA[dsym]))? as usize;
                if d == 0 || d > out.len() || out.len() + len > max_output_len {
                    return None;
                }
                let start = out.len() - d;
                // Byte-at-a-time: DEFLATE back-references may overlap the
                // output being produced (run-length encoding).
                for k in 0..len {
                    let byte = out[start + k];
                    out.push(byte);
                }
            }
            _ => return None,
        }
    }
}

/// Decompress one raw DEFLATE stream and report its exact encoded extent,
/// refusing to produce more than `max_output_len` bytes.
///
/// Bytes after the final block are not consumed. This is the framing-aware
/// entry point for containers that concatenate streams or retain padding.
pub fn inflate_one_with_limit(src: &[u8], max_output_len: usize) -> Option<DecodeOutcome> {
    let mut b = Bits::new(src);
    let mut out: Vec<u8> = Vec::new();
    loop {
        let final_block = b.read(1)?;
        match b.read(2)? {
            0 => {
                b.align_to_byte();
                let header = b.read_aligned_bytes(4)?;
                let len = usize::from(header[0]) | usize::from(header[1]) << 8;
                let nlen = usize::from(header[2]) | usize::from(header[3]) << 8;
                if len != !nlen & 0xffff {
                    return None;
                }
                let chunk = b.read_aligned_bytes(len)?;
                if out.len() + len > max_output_len {
                    return None;
                }
                out.extend_from_slice(chunk);
            }
            1 => {
                let (lit, dist) = fixed_trees()?;
                inflate_block(&mut b, &mut out, &lit, &dist, max_output_len)?;
            }
            2 => {
                let (lit, dist) = dynamic_trees(&mut b)?;
                inflate_block(&mut b, &mut out, &lit, &dist, max_output_len)?;
            }
            _ => return None,
        }
        if final_block == 1 {
            return Some(DecodeOutcome {
                bytes: out,
                consumed: b.byte_extent(),
            });
        }
    }
}

/// Decompress a raw DEFLATE stream, refusing to produce more than
/// `max_output_len` bytes.
///
/// This compatibility entry point returns only the decoded bytes. Use
/// [`inflate_one_with_limit`] when the encoded extent is part of the caller's
/// framing contract.
pub fn inflate_with_limit(src: &[u8], max_output_len: usize) -> Option<Vec<u8>> {
    inflate_one_with_limit(src, max_output_len).map(|outcome| outcome.bytes)
}

/// Decode a raw DEFLATE stream with an exact, pre-charged output contract.
///
/// Compatibility callers can continue using [`inflate_with_limit`]. Execution
/// pipelines which share a [`formatkit_core::WorkBudget`] use this overload so the
/// complete output is admitted before the decoder can allocate it.
///
/// This is a top-level charging entry point. Do not call it from a
/// [`formatkit_core::materialize_transformed_member`] codec closure: that executor
/// already owns the materialized-byte charge. Use the bounded compatibility
/// decoder inside such a closure instead.
pub fn inflate_exact_with_work_budget(
    src: &[u8],
    expected_output_len: usize,
    budget: &mut formatkit_core::WorkBudget,
) -> formatkit_core::Result<Vec<u8>> {
    budget.charge(
        formatkit_core::WorkResource::MaterializedBytes,
        expected_output_len as u64,
    )?;
    let decoded = inflate_with_limit(src, expected_output_len)
        .ok_or_else(|| formatkit_core::Error::Malformed("invalid DEFLATE stream".into()))?;
    if decoded.len() != expected_output_len {
        return Err(formatkit_core::Error::Malformed(format!(
            "DEFLATE stream decoded to {} bytes, expected {expected_output_len}",
            decoded.len()
        )));
    }
    Ok(decoded)
}

/// Decompress a raw DEFLATE stream.
pub fn inflate(src: &[u8]) -> Option<Vec<u8>> {
    inflate_with_limit(src, usize::MAX)
}

/// Wrap `raw` as a valid zlib stream using only DEFLATE stored blocks.
///
/// This produces a stream any standard inflate implementation accepts without
/// implementing match search. Archive rebuilds can therefore exercise the real
/// decompression path instead of marking replaced members as verbatim bytes.
pub fn zlib_store(raw: &[u8]) -> Vec<u8> {
    const CMF: u8 = 0x78;
    const MAX_STORED: usize = u16::MAX as usize;

    let fcheck = (31 - ((u16::from(CMF) << 8) % 31)) % 31;
    let flg = u8::try_from(fcheck).expect("zlib check bits fit in u8");
    let block_count = raw.len().max(1).div_ceil(MAX_STORED);
    let mut out = Vec::with_capacity(2 + 5 * block_count + raw.len() + 4);
    out.push(CMF);
    out.push(flg);

    if raw.is_empty() {
        out.push(0x01);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(!0u16).to_le_bytes());
    } else {
        for (i, chunk) in raw.chunks(MAX_STORED).enumerate() {
            let final_block = i + 1 == block_count;
            out.push(if final_block { 0x01 } else { 0x00 });
            let len = u16::try_from(chunk.len()).expect("stored chunk length is bounded");
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&(!len).to_le_bytes());
            out.extend_from_slice(chunk);
        }
    }

    out.extend_from_slice(&adler32(raw).to_be_bytes());
    out
}

/// Decompress one zlib stream (RFC 1950): a two-byte header, a DEFLATE body,
/// and a trailing big-endian Adler-32 of the decompressed bytes.
///
/// The header's method must be 8 (DEFLATE), the check bits must satisfy the
/// RFC 1950 modulo, and a preset dictionary is rejected. The checksum is read
/// immediately after the final DEFLATE block and verified. Bytes after that
/// checksum are not consumed.
pub fn zlib_inflate_one_with_limit(src: &[u8], max_output_len: usize) -> Option<DecodeOutcome> {
    let cmf = *src.first()?;
    let flg = *src.get(1)?;
    if cmf & 0x0f != 8 {
        return None;
    }
    if (u16::from(cmf) << 8 | u16::from(flg)) % 31 != 0 {
        return None;
    }
    if flg & 0x20 != 0 {
        // FDICT: a preset dictionary we do not have.
        return None;
    }
    let raw = inflate_one_with_limit(src.get(2..)?, max_output_len)?;
    let checksum_start = 2usize.checked_add(raw.consumed)?;
    let consumed = checksum_start.checked_add(4)?;
    let checksum: [u8; 4] = src.get(checksum_start..consumed)?.try_into().ok()?;
    if u32::from_be_bytes(checksum) != adler32(&raw.bytes) {
        return None;
    }
    Some(DecodeOutcome {
        bytes: raw.bytes,
        consumed,
    })
}

/// Decompress exactly one complete zlib stream, rejecting trailing bytes and
/// refusing to produce more than `max_output_len` bytes.
pub fn zlib_inflate_with_limit(src: &[u8], max_output_len: usize) -> Option<Vec<u8>> {
    let outcome = zlib_inflate_one_with_limit(src, max_output_len)?;
    (outcome.consumed == src.len()).then_some(outcome.bytes)
}

/// Decode one complete zlib stream with an exact, pre-charged output contract.
///
/// This is a top-level charging entry point. Do not call it from a
/// [`formatkit_core::materialize_transformed_member`] codec closure: that executor
/// already owns the materialized-byte charge. Use the bounded compatibility
/// decoder inside such a closure instead.
pub fn zlib_inflate_exact_with_work_budget(
    src: &[u8],
    expected_output_len: usize,
    budget: &mut formatkit_core::WorkBudget,
) -> formatkit_core::Result<Vec<u8>> {
    budget.charge(
        formatkit_core::WorkResource::MaterializedBytes,
        expected_output_len as u64,
    )?;
    let decoded = zlib_inflate_with_limit(src, expected_output_len)
        .ok_or_else(|| formatkit_core::Error::Malformed("invalid zlib stream".into()))?;
    if decoded.len() != expected_output_len {
        return Err(formatkit_core::Error::Malformed(format!(
            "zlib stream decoded to {} bytes, expected {expected_output_len}",
            decoded.len()
        )));
    }
    Ok(decoded)
}

/// Decompress a zlib stream.
pub fn zlib_inflate(src: &[u8]) -> Option<Vec<u8>> {
    zlib_inflate_with_limit(src, usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_block_round_trips() {
        // BFINAL=1, BTYPE=00, then LEN/NLEN and the literal bytes.
        let mut s = vec![0x01, 0x05, 0x00, 0xfa, 0xff];
        s.extend_from_slice(b"hello");
        assert_eq!(inflate(&s).as_deref(), Some(&b"hello"[..]));
    }

    #[test]
    fn reports_one_raw_stream_extent_without_consuming_a_follower() {
        let mut s = vec![0x01, 0x05, 0x00, 0xfa, 0xff];
        s.extend_from_slice(b"hello");
        let stream_len = s.len();
        s.extend_from_slice(b"following carrier bytes");
        let outcome = inflate_one_with_limit(&s, 5).unwrap();
        assert_eq!(outcome.bytes, b"hello");
        assert_eq!(outcome.consumed, stream_len);
    }

    #[test]
    fn reports_one_zlib_stream_extent_and_exact_wrapper_rejects_trailing() {
        let stream = zlib_store(b"first");
        let mut carrier = stream.clone();
        carrier.extend_from_slice(&zlib_store(b"second"));

        let outcome = zlib_inflate_one_with_limit(&carrier, 5).unwrap();
        assert_eq!(outcome.bytes, b"first");
        assert_eq!(outcome.consumed, stream.len());
        assert!(zlib_inflate_with_limit(&carrier, 64).is_none());
    }

    #[test]
    fn rejects_bad_stored_complement() {
        let mut s = vec![0x01, 0x05, 0x00, 0x00, 0x00];
        s.extend_from_slice(b"hello");
        assert!(inflate(&s).is_none());
    }

    #[test]
    fn rejects_non_deflate_zlib_method() {
        assert!(zlib_inflate(&[0x79, 0xda, 0x00]).is_none());
    }

    #[test]
    fn rejects_bad_zlib_check_bits() {
        assert!(zlib_inflate(&[0x78, 0x00, 0x00]).is_none());
    }

    #[test]
    fn limit_is_enforced() {
        let mut s = vec![0x01, 0x05, 0x00, 0xfa, 0xff];
        s.extend_from_slice(b"hello");
        assert!(inflate_with_limit(&s, 4).is_none());
        assert!(inflate_with_limit(&s, 5).is_some());
    }

    #[test]
    fn truncated_input_is_none() {
        assert!(inflate(&[]).is_none());
        assert!(inflate(&[0x01, 0x05]).is_none());
    }

    /// How a vector's expected plaintext is produced. Generating it rather than
    /// embedding it keeps the fixtures small; only the encoded stream is a
    /// literal.
    #[derive(Clone, Copy)]
    enum Gen {
        Empty,
        Abc,
        RunA,
        Fox,
        Ramp,
    }

    impl Gen {
        fn plain(self) -> Vec<u8> {
            match self {
                Gen::Empty => Vec::new(),
                Gen::Abc => b"abc".to_vec(),
                // Long single-byte run: forces overlapping back-references.
                Gen::RunA => vec![b'A'; 5000],
                // Repeating phrase: dynamic Huffman with a small alphabet.
                Gen::Fox => b"the quick brown fox. ".repeat(400),
                // Full 0..=255 ramp repeated: dynamic Huffman, large alphabet.
                Gen::Ramp => (0..=255u8).collect::<Vec<u8>>().repeat(64),
            }
        }
    }

    /// Streams produced by an independent encoder at levels 0, 6 and 9, so the
    /// three block types (stored, fixed, dynamic) are all exercised.
    const VECTORS: &[(Gen, &[u8])] = &[
        (Gen::Empty, b"\x78\x01\x01\x00\x00\xff\xff\x00\x00\x00\x01"),
        (Gen::Empty, b"\x78\x9c\x03\x00\x00\x00\x00\x01"),
        (Gen::Empty, b"\x78\xda\x03\x00\x00\x00\x00\x01"),
        (Gen::Abc, b"\x78\x01\x01\x03\x00\xfc\xff\x61\x62\x63\x02\x4d\x01\x27"),
        (Gen::Abc, b"\x78\x9c\x4b\x4c\x4a\x06\x00\x02\x4d\x01\x27"),
        (Gen::Abc, b"\x78\xda\x4b\x4c\x4a\x06\x00\x02\x4d\x01\x27"),
        (Gen::RunA, b"\x78\x9c\xed\xc1\x31\x01\x00\x00\x00\xc2\xa0\x6c\xeb\x5f\xca\x14\x7e\x40\x01\x00\x00\x00\x00\x6f\x03\x29\x29\xf5\xc5"),
        (Gen::RunA, b"\x78\xda\xed\xc1\x31\x01\x00\x00\x00\xc2\xa0\x6c\xeb\x5f\xca\x14\x7e\x40\x01\x00\x00\x00\x00\x6f\x03\x29\x29\xf5\xc5"),
        (Gen::Fox, b"\x78\x9c\xed\xc8\xd1\x09\x80\x20\x14\x00\xc0\x55\xde\x04\x0d\xa5\x14\x8a\xa0\x24\x46\x8e\xdf\x18\xfd\xdc\x7d\xde\x2a\x67\xdc\x4f\xcd\x2d\xd2\x1c\x6f\x8f\x6b\xec\x23\x96\x94\x52\x4a\x29\xa5\x94\x52\x4a\x29\xa5\x94\x52\x4a\x29\xa5\x94\x52\x4a\x29\xe5\x7f\xf9\x01\x9e\xf5\xba\x36"),
        (Gen::Ramp, b"\x78\x9c\xed\xcf\xd7\x22\x10\x00\x00\x05\x50\x42\x19\x49\x64\x66\x66\xaf\xec\x2d\x23\x49\x66\xf6\x2a\xd9\xab\x8c\x10\x4a\xc8\x4c\xa5\x8c\x50\x14\xb2\xa5\x61\x13\x29\x7b\x36\xcc\xa6\x51\xb2\x65\x35\xec\x15\xbf\xd1\xc3\x3d\x7f\x70\x08\x08\xf7\x10\x11\x93\xec\xdd\x47\x4a\x46\x4e\xb1\x9f\xf2\x00\xd5\x41\x6a\x9a\x43\xb4\x74\xf4\x0c\x8c\x4c\x87\x99\x59\x58\xd9\xd8\x39\x8e\x70\x72\x71\xf3\xf0\xf2\xf1\x0b\x08\x0a\x09\x1f\x15\x11\x15\x13\x97\x90\x94\x92\x96\x91\x95\x93\x57\x50\x3c\xa6\xa4\xac\xa2\x7a\x5c\xed\x84\xfa\x49\x8d\x53\x9a\x5a\xda\x3a\xba\x7a\xa7\xf5\x0d\x0c\x8d\x8c\x4d\x4c\xcd\xcc\x2d\x2c\xcf\x9c\xb5\x3a\x67\x6d\x63\x6b\x67\xef\xe0\xe8\xe4\xec\xe2\x7a\xfe\x82\x9b\xbb\x87\xe7\x45\x2f\x6f\x9f\x4b\xbe\x7e\xfe\x97\xaf\x04\x5c\x0d\x0c\x0a\xbe\x16\x12\x1a\x16\x1e\x11\x79\x3d\xea\xc6\xcd\x5b\xd1\xb7\xef\xc4\xc4\xc6\xc5\xdf\x4d\x48\x4c\xba\x77\x3f\x39\xe5\xc1\xc3\xd4\xb4\xf4\x47\x19\x99\x59\xd9\x39\xb9\x79\xf9\x8f\x0b\x9e\x3c\x7d\xf6\xbc\xb0\xa8\xb8\xa4\xb4\xac\xbc\xa2\xf2\x45\x55\xf5\xcb\x9a\x57\xaf\x6b\xeb\xea\x1b\x1a\x9b\x9a\x5b\x5a\xdb\xda\x3b\xde\xbc\x7d\xf7\xbe\xb3\xab\xbb\xa7\xb7\xef\xc3\xc7\x4f\x9f\xbf\x7c\xed\x1f\x18\x1c\xfa\xf6\x7d\xf8\xc7\xc8\xe8\xd8\xf8\xc4\xe4\xd4\xf4\xcf\x99\xd9\xb9\xf9\x85\x5f\xbf\xff\xfc\x5d\x5c\x5a\x5e\x59\x5d\x5b\xdf\xd8\xdc\xda\xfe\xb7\x43\x80\x3f\xfe\xf8\xe3\x8f\x3f\xfe\xf8\xe3\x8f\x3f\xfe\xf8\xe3\x8f\x3f\xfe\xf8\xe3\x8f\x3f\xfe\xf8\xe3\x8f\x3f\xfe\xf8\xe3\x8f\x3f\xfe\xf8\xe3\x8f\x3f\xfe\xf8\xe3\x8f\x3f\xfe\xf8\xe3\x8f\x3f\xfe\xf8\xe3\x8f\x3f\xfe\xf8\xe3\x8f\x3f\xfe\xf8\xe3\x8f\x3f\xfe\xf8\xe3\x8f\x3f\xfe\xf8\xe3\x8f\x3f\xfe\xf8\xe3\x8f\x3f\xfe\xff\xc1\x7f\x17\x58\x6a\xe1\xd2"),
    ];

    #[test]
    fn matches_independent_encoder() {
        for (i, (gen, stream)) in VECTORS.iter().enumerate() {
            let want = gen.plain();
            let got = zlib_inflate(stream);
            assert_eq!(got.as_deref(), Some(&want[..]), "vector {i}");
        }
    }

    #[test]
    fn limit_rejects_oversized_output() {
        for (i, (gen, stream)) in VECTORS.iter().enumerate() {
            let want = gen.plain();
            if want.is_empty() {
                continue;
            }
            assert!(
                zlib_inflate_with_limit(stream, want.len() - 1).is_none(),
                "vector {i} ignored its limit"
            );
            assert!(zlib_inflate_with_limit(stream, want.len()).is_some());
        }
    }

    #[test]
    fn corrupt_body_is_rejected_by_checksum() {
        // Flip a byte in the middle of a dynamic-Huffman body; either the
        // Huffman decode fails outright or the Adler-32 catches it.
        let (_, stream) = VECTORS[VECTORS.len() - 1];
        let mut bad = stream.to_vec();
        let mid = bad.len() / 2;
        bad[mid] ^= 0x40;
        assert!(zlib_inflate(&bad).is_none());
    }

    #[test]
    fn truncated_stream_is_rejected() {
        for (i, (_, stream)) in VECTORS.iter().enumerate() {
            let cut = &stream[..stream.len() - 1];
            assert!(
                zlib_inflate(cut).is_none(),
                "vector {i} accepted truncation"
            );
        }
    }

    fn lcg_bytes(len: usize) -> Vec<u8> {
        let mut x = 0x1234_5678u32;
        (0..len)
            .map(|i| {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (x.rotate_left((i % 23) as u32) ^ (i as u32)).to_le_bytes()[1]
            })
            .collect()
    }

    fn stored_block_count(raw_len: usize) -> usize {
        raw_len.max(1).div_ceil(u16::MAX as usize)
    }

    fn assert_final_bit_only_on_last(stream: &[u8], raw_len: usize) {
        let mut pos = 2;
        for i in 0..stored_block_count(raw_len) {
            let header = stream[pos];
            assert_eq!(header & 0b110, 0, "stored block {i} has non-zero BTYPE");
            let final_block = i + 1 == stored_block_count(raw_len);
            assert_eq!(
                header & 1,
                u8::from(final_block),
                "stored block {i} has wrong BFINAL"
            );
            let len = u16::from_le_bytes([stream[pos + 1], stream[pos + 2]]) as usize;
            let nlen = u16::from_le_bytes([stream[pos + 3], stream[pos + 4]]);
            assert_eq!(u16::try_from(len).unwrap(), !nlen);
            pos += 5 + len;
        }
        assert_eq!(pos + 4, stream.len());
    }

    #[test]
    fn zlib_store_round_trips_stored_blocks() {
        for raw in [
            Vec::new(),
            lcg_bytes(1),
            lcg_bytes(65_534),
            lcg_bytes(65_535),
            lcg_bytes(65_536),
            lcg_bytes(65_537),
            lcg_bytes(200_000),
        ] {
            let stream = zlib_store(&raw);
            assert_eq!(zlib_inflate(&stream).as_deref(), Some(&raw[..]));
            let check = u16::from(stream[0]) << 8 | u16::from(stream[1]);
            assert_eq!(check % 31, 0);
            assert_eq!(
                stream.len(),
                2 + 5 * stored_block_count(raw.len()) + raw.len() + 4
            );
            assert_final_bit_only_on_last(&stream, raw.len());
        }
    }
}
