use crate::DecodeOutcome;

/// Okumura LZSS parameters shared by every variant.
const RING: usize = 4096;
const MAX_MATCH: usize = 18;
const THRESHOLD: usize = 2; // min match = THRESHOLD + 1 = 3

/// Flag-byte bit order: which bit of the flag byte a variant consumes first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitOrder {
    /// Bit 0 (0x01) first — Okumura's original `LZSS.C`.
    LsbFirst,
    /// Bit 7 (0x80) first.
    MsbFirst,
}

/// Why a strict Okumura stream could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OkumuraDecodeError {
    /// The requested or produced output exceeds the caller's allocation limit.
    OutputLimit {
        /// Output bytes requested by a frame, or needed by the next token.
        requested: usize,
        /// Maximum output bytes allowed by the caller.
        limit: usize,
    },
    /// The encoded stream ended while a flag or token was being read.
    Truncated {
        /// First unavailable byte offset in the encoded stream.
        offset: usize,
    },
    /// A complete back-reference would cross the declared output boundary.
    TokenOvershoot {
        /// Bytes produced before the rejected token.
        produced: usize,
        /// Bytes the rejected token would produce.
        token_len: usize,
        /// Declared total output bytes.
        expected: usize,
    },
}

/// Strict decode extent and whether its last token completed a flag group.
///
/// Some envelopes permit the encoder's eagerly emitted next flag byte only
/// after a complete eight-token group. This records that boundary while the
/// shared decoder is already walking tokens; owners need not duplicate the
/// codec grammar merely to validate their trailing-byte policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OkumuraBoundaryOutcome {
    pub outcome: DecodeOutcome,
    pub completed_flag_group: bool,
    /// Number of literal and back-reference tokens consumed by the stream.
    pub token_count: usize,
}

/// Decompress an Okumura ring-buffer LZSS stream of exactly `out_len` bytes.
///
/// `src` is the raw stream (no size header — the caller supplies `out_len`).
/// `bit_order` selects which flag bit is consumed first and `fill` is the ring
/// buffer's initial byte (classic `LZSS.C` uses `0x20`; some dialects use
/// `0x00`). A flag bit of 1 is a literal; a 0 is a 2-byte back-reference
/// `{lo, hi}` giving `pos = lo | ((hi & 0xf0) << 4)` and `len = (hi & 0x0f) + 3`.
/// Returns `None` if the stream ends before `out_len` bytes are produced.
pub fn okumura_lzss(src: &[u8], out_len: usize, bit_order: BitOrder, fill: u8) -> Option<Vec<u8>> {
    okumura_lzss_with_limit(src, out_len, bit_order, fill, usize::MAX)
}

/// Bounded variant of [`okumura_lzss`]. Returns `None` without allocating when
/// the requested output exceeds `max_output_len`.
pub fn okumura_lzss_with_limit(
    src: &[u8],
    out_len: usize,
    bit_order: BitOrder,
    fill: u8,
    max_output_len: usize,
) -> Option<Vec<u8>> {
    okumura_lzss_inner(src, out_len, bit_order, fill, max_output_len, false)
        .ok()
        .map(|result| result.outcome.bytes)
}

/// Strictly decode one Okumura stream and report its exact encoded extent.
///
/// Unlike [`okumura_lzss_with_limit`], a back-reference must fit completely
/// inside `out_len`; it is not truncated at the output boundary. Bytes after
/// the token that completes the declared output are left unconsumed so the
/// caller can reject, preserve, or interpret them as carrier padding.
pub fn okumura_lzss_consumed_with_limit(
    src: &[u8],
    out_len: usize,
    bit_order: BitOrder,
    fill: u8,
    max_output_len: usize,
) -> Result<DecodeOutcome, OkumuraDecodeError> {
    okumura_lzss_inner(src, out_len, bit_order, fill, max_output_len, true)
        .map(|result| result.outcome)
}

/// Strict decode with the final flag-group boundary retained for an owner.
pub fn okumura_lzss_consumed_with_boundary(
    src: &[u8],
    out_len: usize,
    bit_order: BitOrder,
    fill: u8,
    max_output_len: usize,
) -> Result<OkumuraBoundaryOutcome, OkumuraDecodeError> {
    okumura_lzss_inner(src, out_len, bit_order, fill, max_output_len, true)
}

/// Decode an Okumura stream whose encoded extent, rather than its decoded
/// length, terminates the stream.
///
/// Some containers store the compressed byte count and omit the decoded size.
/// A final flag group may contain fewer than eight tokens; EOF immediately
/// after any complete token ends that group. EOF before the first token of a
/// flag group, or partway through a token, is rejected. Output growth is
/// checked before every token so an untrusted stream cannot exceed
/// `max_output_len`.
pub fn okumura_lzss_to_end_with_limit(
    src: &[u8],
    bit_order: BitOrder,
    fill: u8,
    max_output_len: usize,
) -> Result<DecodeOutcome, OkumuraDecodeError> {
    let mut ring = [fill; RING];
    let mut r = RING - MAX_MATCH;
    let mut out = Vec::with_capacity(src.len().min(max_output_len));
    let mut p = 0usize;
    let bit = |flags: u8, i: u32| match bit_order {
        BitOrder::LsbFirst => flags & (1 << i),
        BitOrder::MsbFirst => flags & (0x80 >> i),
    };

    while p < src.len() {
        let flags = src[p];
        p += 1;
        for (tokens, i) in (0..8).enumerate() {
            if p == src.len() {
                if tokens == 0 {
                    return Err(OkumuraDecodeError::Truncated { offset: p });
                }
                return Ok(DecodeOutcome {
                    bytes: out,
                    consumed: p,
                });
            }

            if bit(flags, i) != 0 {
                let requested = out.len().saturating_add(1);
                if requested > max_output_len {
                    return Err(OkumuraDecodeError::OutputLimit {
                        requested,
                        limit: max_output_len,
                    });
                }
                let c = src[p];
                p += 1;
                out.push(c);
                ring[r] = c;
                r = (r + 1) % RING;
            } else {
                let lo = *src
                    .get(p)
                    .ok_or(OkumuraDecodeError::Truncated { offset: p })?
                    as usize;
                let hi = *src
                    .get(p + 1)
                    .ok_or(OkumuraDecodeError::Truncated { offset: p + 1 })?
                    as usize;
                p += 2;
                let pos = lo | ((hi & 0xf0) << 4);
                let len = (hi & 0x0f) + THRESHOLD + 1;
                let requested = out.len().saturating_add(len);
                if requested > max_output_len {
                    return Err(OkumuraDecodeError::OutputLimit {
                        requested,
                        limit: max_output_len,
                    });
                }
                for k in 0..len {
                    let c = ring[(pos + k) % RING];
                    out.push(c);
                    ring[r] = c;
                    r = (r + 1) % RING;
                }
            }
        }
    }

    Ok(DecodeOutcome {
        bytes: out,
        consumed: p,
    })
}

fn okumura_lzss_inner(
    src: &[u8],
    out_len: usize,
    bit_order: BitOrder,
    fill: u8,
    max_output_len: usize,
    reject_token_overshoot: bool,
) -> Result<OkumuraBoundaryOutcome, OkumuraDecodeError> {
    if out_len > max_output_len {
        return Err(OkumuraDecodeError::OutputLimit {
            requested: out_len,
            limit: max_output_len,
        });
    }
    let mut ring = [fill; RING];
    let mut r = RING - MAX_MATCH; // 4078

    // A declared length is not evidence that any compressed payload exists.
    // Reserve only an amount justified by the available stream; Vec can grow
    // as valid tokens actually produce output.
    let initial_capacity = out_len.min(src.len().saturating_mul(MAX_MATCH));
    let mut out = Vec::with_capacity(initial_capacity);
    let mut p = 0usize;
    let mut completed_flag_group = false;
    let mut token_count = 0usize;
    let bit = |flags: u8, i: u32| match bit_order {
        BitOrder::LsbFirst => flags & (1 << i),
        BitOrder::MsbFirst => flags & (0x80 >> i),
    };
    while out.len() < out_len {
        let flags = *src
            .get(p)
            .ok_or(OkumuraDecodeError::Truncated { offset: p })?;
        p += 1;
        for i in 0..8 {
            if out.len() >= out_len {
                break;
            }
            token_count += 1;
            if bit(flags, i) != 0 {
                let c = *src
                    .get(p)
                    .ok_or(OkumuraDecodeError::Truncated { offset: p })?;
                p += 1;
                out.push(c);
                ring[r] = c;
                r = (r + 1) % RING;
            } else {
                let lo = *src
                    .get(p)
                    .ok_or(OkumuraDecodeError::Truncated { offset: p })?
                    as usize;
                let hi = *src
                    .get(p + 1)
                    .ok_or(OkumuraDecodeError::Truncated { offset: p + 1 })?
                    as usize;
                p += 2;
                let pos = lo | ((hi & 0xf0) << 4);
                let len = (hi & 0x0f) + THRESHOLD + 1;
                if reject_token_overshoot && out.len().saturating_add(len) > out_len {
                    return Err(OkumuraDecodeError::TokenOvershoot {
                        produced: out.len(),
                        token_len: len,
                        expected: out_len,
                    });
                }
                for k in 0..len {
                    if out.len() >= out_len {
                        break;
                    }
                    let c = ring[(pos + k) % RING];
                    out.push(c);
                    ring[r] = c;
                    r = (r + 1) % RING;
                }
            }
            completed_flag_group = i == 7 && out.len() == out_len;
        }
    }
    Ok(OkumuraBoundaryOutcome {
        outcome: DecodeOutcome {
            bytes: out,
            consumed: p,
        },
        completed_flag_group,
        token_count,
    })
}

const NIL: usize = RING;

/// Okumura's original 256-root binary search tree over the 4 KiB ring.
/// Equal-length matches retain the first tree candidate. Modeling the tree,
/// rather than merely finding any longest match, makes that tie policy
/// deterministic.
struct MatchTree {
    left: [usize; RING + 257],
    right: [usize; RING + 257],
    parent: [usize; RING + 1],
    position: usize,
    length: usize,
}

impl MatchTree {
    fn new() -> Self {
        Self {
            left: [NIL; RING + 257],
            right: [NIL; RING + 257],
            parent: [NIL; RING + 1],
            position: 0,
            length: 0,
        }
    }

    fn insert(&mut self, node: usize, text: &[u8; RING + MAX_MATCH - 1]) {
        let mut comparison = 1i16;
        let mut candidate = RING + 1 + usize::from(text[node]);
        self.left[node] = NIL;
        self.right[node] = NIL;
        self.length = 0;

        loop {
            if comparison >= 0 {
                if self.right[candidate] != NIL {
                    candidate = self.right[candidate];
                } else {
                    self.right[candidate] = node;
                    self.parent[node] = candidate;
                    return;
                }
            } else if self.left[candidate] != NIL {
                candidate = self.left[candidate];
            } else {
                self.left[candidate] = node;
                self.parent[node] = candidate;
                return;
            }

            let mut matched = 1usize;
            while matched < MAX_MATCH {
                comparison = i16::from(text[node + matched]) - i16::from(text[candidate + matched]);
                if comparison != 0 {
                    break;
                }
                matched += 1;
            }
            if matched > self.length {
                self.position = candidate;
                self.length = matched;
                if matched >= MAX_MATCH {
                    break;
                }
            }
        }

        self.parent[node] = self.parent[candidate];
        self.left[node] = self.left[candidate];
        self.right[node] = self.right[candidate];
        self.parent[self.left[candidate]] = node;
        self.parent[self.right[candidate]] = node;
        let parent = self.parent[candidate];
        if self.right[parent] == candidate {
            self.right[parent] = node;
        } else {
            self.left[parent] = node;
        }
        self.parent[candidate] = NIL;
    }

    fn delete(&mut self, node: usize) {
        if self.parent[node] == NIL {
            return;
        }
        let replacement = if self.right[node] == NIL {
            self.left[node]
        } else if self.left[node] == NIL {
            self.right[node]
        } else {
            let mut replacement = self.left[node];
            if self.right[replacement] != NIL {
                while self.right[replacement] != NIL {
                    replacement = self.right[replacement];
                }
                let parent = self.parent[replacement];
                self.right[parent] = self.left[replacement];
                self.parent[self.left[replacement]] = parent;
                self.left[replacement] = self.left[node];
                self.parent[self.left[node]] = replacement;
            }
            self.right[replacement] = self.right[node];
            self.parent[self.right[node]] = replacement;
            replacement
        };
        self.parent[replacement] = self.parent[node];
        let parent = self.parent[node];
        if self.right[parent] == node {
            self.right[parent] = replacement;
        } else {
            self.left[parent] = replacement;
        }
        self.parent[node] = NIL;
    }
}

/// Runtime-exact **encoder** for the Okumura ring-buffer LZSS codec — the inverse
/// of [`okumura_lzss`]. It uses the original 256-root binary-search-tree match
/// policy, including its insertion-order tie breaks, while emitting either LSB-
/// or MSB-first flag groups as requested.
///
/// `bit_order` and `fill` must match what the decoder is later called with. A
/// match is emitted only when it reaches the minimum match length
/// (`THRESHOLD + 1 == 3`); otherwise the byte is a literal.
///
/// Round-trips for every input, both bit orders and any fill:
/// `okumura_lzss(&okumura_lzss_compress(s, bo, f), s.len(), bo, f) == Some(s)`.
pub fn okumura_lzss_compress(src: &[u8], bit_order: BitOrder, fill: u8) -> Vec<u8> {
    if src.is_empty() {
        return Vec::new();
    }

    let mut text = [fill; RING + MAX_MATCH - 1];
    let mut tree = MatchTree::new();
    let mut read = 0usize;
    let mut lookahead = src.len().min(MAX_MATCH);
    let mut ring_read = 0usize;
    let mut ring_write = RING - MAX_MATCH;
    text[ring_write..ring_write + lookahead].copy_from_slice(&src[..lookahead]);
    read += lookahead;

    // Seed the tree exactly as the original encoder: the F predecessor nodes
    // first, then the current lookahead node.
    for distance in 1..=MAX_MATCH {
        tree.insert(ring_write - distance, &text);
    }
    tree.insert(ring_write, &text);

    let mut out = Vec::new();

    // Position of the current 8-item flag byte in `out`, and how many items have
    // been placed under it (0..8). A fresh flag byte (all zero) is pushed at the
    // start of each group; literal bits are OR-ed in, match bits stay 0.
    let mut flag_pos = 0usize;
    let mut item_count = 0usize;

    loop {
        if item_count == 0 {
            flag_pos = out.len();
            out.push(0);
        }
        let matched = tree.length.min(lookahead);

        // Flag-bit mask for this item's slot under the current bit order.
        let mask = match bit_order {
            BitOrder::LsbFirst => 1u8 << item_count,
            BitOrder::MsbFirst => 0x80u8 >> item_count,
        };

        let consumed = if matched > THRESHOLD {
            // Match: flag bit stays 0. Encode 12-bit pos + (len-3) nibble as the
            // decoder reads it: pos = lo | ((hi & 0xf0) << 4), len = (hi & 0x0f) + 3.
            let lo = (tree.position & 0xff) as u8;
            let hi = ((((tree.position >> 8) & 0x0f) << 4) | (matched - (THRESHOLD + 1))) as u8;
            out.push(lo);
            out.push(hi);
            matched
        } else {
            // Literal: flag bit is 1.
            out[flag_pos] |= mask;
            out.push(text[ring_write]);
            1
        };

        item_count += 1;
        if item_count == 8 {
            item_count = 0;
        }

        let mut advanced = 0usize;
        while advanced < consumed && read < src.len() {
            let byte = src[read];
            read += 1;
            tree.delete(ring_read);
            text[ring_read] = byte;
            if ring_read < MAX_MATCH - 1 {
                text[ring_read + RING] = byte;
            }
            ring_read = (ring_read + 1) % RING;
            ring_write = (ring_write + 1) % RING;
            tree.insert(ring_write, &text);
            advanced += 1;
        }
        while advanced < consumed {
            tree.delete(ring_read);
            ring_read = (ring_read + 1) % RING;
            ring_write = (ring_write + 1) % RING;
            lookahead -= 1;
            if lookahead != 0 {
                tree.insert(ring_write, &text);
            }
            advanced += 1;
        }
        if lookahead == 0 {
            break;
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn all_literals(data: &[u8], order: BitOrder) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in data.chunks(8) {
            let flag = match order {
                BitOrder::LsbFirst => ((1u16 << chunk.len()) - 1) as u8,
                BitOrder::MsbFirst => (0xffu8) << (8 - chunk.len()),
            };
            out.push(flag);
            out.extend_from_slice(chunk);
        }
        out
    }

    /// Deterministic byte stream over a bounded alphabet, so pseudo-random test
    /// inputs still contain enough repeats to exercise the match path.
    fn lcg_bytes(seed: u64, len: usize, alphabet: u8) -> Vec<u8> {
        let mut s = seed;
        (0..len)
            .map(|_| {
                s = s
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                ((s >> 33) as u8) % alphabet
            })
            .collect()
    }

    /// Encode with the greedy encoder, decode with the reference decoder, assert
    /// the round-trip is byte-exact for the given bit order and ring fill.
    fn okumura_round_trips(data: &[u8], order: BitOrder, fill: u8) {
        let enc = okumura_lzss_compress(data, order, fill);
        let dec = okumura_lzss(&enc, data.len(), order, fill).unwrap_or_else(|| {
            panic!(
                "decode failed: len={}, order={order:?}, fill={fill:#x}",
                data.len()
            )
        });
        assert_eq!(
            dec,
            data,
            "round-trip mismatch: len={}, order={order:?}, fill={fill:#x}",
            data.len()
        );
    }

    #[test]
    fn literal_round_trip_both_orders() {
        let data = b"Hello, Okumura LZSS world!";
        for order in [BitOrder::LsbFirst, BitOrder::MsbFirst] {
            let enc = all_literals(data, order);
            let dec = okumura_lzss(&enc, data.len(), order, 0x00).unwrap();
            assert_eq!(dec, data);
        }
    }

    #[test]
    fn compressor_round_trips_synthetic_literals_and_matches() {
        for order in [BitOrder::LsbFirst, BitOrder::MsbFirst] {
            for fill in [0, 0x20] {
                for len in [0, 1, 7, 8, 9, 17, 18, 19, 4096, 8193] {
                    for alphabet in [4, 127, 255] {
                        okumura_round_trips(&lcg_bytes(42, len, alphabet), order, fill);
                    }
                    okumura_round_trips(&vec![fill; len], order, fill);
                }
            }
        }
    }

    #[test]
    fn back_reference_copies_from_ring() {
        // "ABAB": literal A, literal B, then a match {pos=r-2, len=2} copying "AB".
        // r starts at 4078; after 2 literals the last two ring cells written are
        // 4078='A', 4079='B'; a backref at pos=4078 len=2 reproduces "AB".
        let mut s = Vec::new();
        s.push(0b0000_0011); // LSB: bits 0,1 literals; bit 2 is a match
        s.push(b'A');
        s.push(b'B');
        // match: lo/hi encode pos=4078, len=2 -> (hi&0x0f)+3=2 => (hi&0x0f)=-1? use len=3
        // len must be >=3; make it copy "ABA": pos=4078,len=3
        let pos = 4078usize;
        let lo = (pos & 0xff) as u8;
        let hi = (((pos >> 8) & 0x0f) << 4) as u8; // len=(0)+3=3
        s.push(lo);
        s.push(hi);
        let out = okumura_lzss(&s, 5, BitOrder::LsbFirst, 0x00).unwrap();
        assert_eq!(&out, b"ABABA");
    }

    #[test]
    fn strict_decode_reports_extent_and_rejects_token_overshoot() {
        let encoded = all_literals(b"abc", BitOrder::LsbFirst);
        let mut carrier = encoded.clone();
        carrier.extend_from_slice(b"padding");
        let outcome =
            okumura_lzss_consumed_with_limit(&carrier, 3, BitOrder::LsbFirst, 0, 3).unwrap();
        assert_eq!(outcome.bytes, b"abc");
        assert_eq!(outcome.consumed, encoded.len());

        assert!(matches!(
            okumura_lzss_consumed_with_limit(&[0, 0, 0], 1, BitOrder::LsbFirst, 0, 1,),
            Err(OkumuraDecodeError::TokenOvershoot {
                produced: 0,
                token_len: 3,
                expected: 1,
            })
        ));
        // The compatibility decoder retains the retail-style truncation of a
        // final match at the requested output boundary.
        assert_eq!(
            okumura_lzss(&[0, 0, 0], 1, BitOrder::LsbFirst, 0),
            Some(vec![0])
        );
    }

    #[test]
    fn strict_decode_reports_final_flag_group_boundary() {
        let partial = all_literals(b"abc", BitOrder::LsbFirst);
        let partial_result = okumura_lzss_consumed_with_boundary(
            &[partial.as_slice(), &[0]].concat(),
            3,
            BitOrder::LsbFirst,
            0,
            3,
        )
        .unwrap();
        assert_eq!(partial_result.outcome.consumed, partial.len());
        assert!(!partial_result.completed_flag_group);

        let complete = all_literals(b"abcdefgh", BitOrder::LsbFirst);
        let complete_result = okumura_lzss_consumed_with_boundary(
            &[complete.as_slice(), &[0]].concat(),
            8,
            BitOrder::LsbFirst,
            0,
            8,
        )
        .unwrap();
        assert_eq!(complete_result.outcome.consumed, complete.len());
        assert!(complete_result.completed_flag_group);
        assert_eq!(complete_result.outcome.bytes, b"abcdefgh");
    }

    #[test]
    fn short_stream_is_none() {
        assert!(okumura_lzss(&[0xff, b'a'], 4, BitOrder::LsbFirst, 0).is_none());
    }
}
