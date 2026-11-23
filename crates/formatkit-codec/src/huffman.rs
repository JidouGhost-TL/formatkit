//! Canonical Huffman codebook construction, Kraft-inequality validation,
//! bounded LSB/MSB decoding, and deterministic frequency-to-code-lengths
//! tree construction.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use formatkit_core::{Error, LsbBitCursor, LsbBitWriter, MsbBitCursor, MsbBitWriter, Result};

/// Maximum supported canonical Huffman code length in bits.
pub const MAX_HUFFMAN_CODE_BITS: u8 = 32;

/// Bit ordering used when serializing or reading canonical Huffman codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HuffmanBitOrder {
    /// Codes are read and written most-significant bit first.
    MsbFirst,
    /// Codes are bit-reversed and read/written least-significant bit first.
    LsbFirst,
}

/// One symbol's canonical code and bit length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalCode {
    /// Bit pattern in the requested [`HuffmanBitOrder`], stored in the low `length` bits.
    pub code: u32,
    /// Number of significant bits (`1..=32`).
    pub length: u8,
}

#[inline]
fn reverse_bits(code: u32, length: u8) -> u32 {
    if length == 0 {
        return 0;
    }
    code.reverse_bits() >> (32 - u32::from(length))
}

/// Canonical Huffman codebook supporting both MSB-first and LSB-first bitstreams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalHuffmanTable {
    max_len: u8,
    complete: bool,
    symbol_count: usize,
    /// Per-symbol `(msb_code, length)`; `length == 0` means absent.
    codes: Vec<(u32, u8)>,
    /// Number of codes of each length `0..=max_len`.
    counts: Vec<u32>,
    /// First canonical MSB-first code at each length `0..=max_len`.
    first_code: Vec<u64>,
    /// Starting offset into `symbols` for each length `0..=max_len`.
    first_symbol: Vec<usize>,
    /// Active symbols ordered by `(length, symbol)`.
    symbols: Vec<usize>,
}

impl CanonicalHuffmanTable {
    /// Build a canonical Huffman table from per-symbol bit lengths (`0` = absent).
    ///
    /// Rejects empty codebooks, lengths exceeding [`MAX_HUFFMAN_CODE_BITS`], and
    /// oversubscribed codebooks that violate the Kraft inequality. Incomplete
    /// (under-subscribed) codebooks are accepted; use
    /// [`Self::from_code_lengths_strict`] or [`Self::is_complete`] when a
    /// format requires a complete prefix tree.
    pub fn from_code_lengths(lengths: &[u8]) -> Result<Self> {
        let max_len = lengths.iter().copied().max().unwrap_or(0);
        if max_len == 0 {
            return Err(Error::Malformed(
                "Huffman codebook has no active symbols".into(),
            ));
        }
        if max_len > MAX_HUFFMAN_CODE_BITS {
            return Err(Error::InvalidField {
                what: "Huffman code length",
                value: u64::from(max_len),
            });
        }

        let max_bits = usize::from(max_len);
        let mut counts = vec![0u32; max_bits + 1];
        for &len in lengths {
            if len > 0 {
                counts[usize::from(len)] = counts[usize::from(len)]
                    .checked_add(1)
                    .ok_or_else(|| Error::Malformed("Huffman symbol count overflow".into()))?;
            }
        }

        // Validate Kraft inequality: sum(count[l] * 2^(max_len - l)) <= 2^max_len.
        let limit: u64 = 1u64 << u32::from(max_len);
        let mut kraft: u64 = 0;
        for (len, &count) in counts.iter().enumerate().skip(1) {
            let weight = 1u64 << (max_bits - len);
            let term = u64::from(count)
                .checked_mul(weight)
                .ok_or_else(|| Error::Malformed("Huffman Kraft sum overflow".into()))?;
            kraft = kraft
                .checked_add(term)
                .ok_or_else(|| Error::Malformed("Huffman Kraft sum overflow".into()))?;
            if kraft > limit {
                return Err(Error::Malformed(
                    "Huffman codebook violates Kraft inequality (oversubscribed)".into(),
                ));
            }
        }

        let complete = kraft == limit;

        let mut first_code = vec![0u64; max_bits + 1];
        let mut first_symbol = vec![0usize; max_bits + 1];
        let mut code = 0u64;
        let mut sym_offset = 0usize;
        for bits in 1..=max_bits {
            code = (code + u64::from(counts[bits - 1])) << 1;
            first_code[bits] = code;
            first_symbol[bits] = sym_offset;
            sym_offset += counts[bits] as usize;
        }

        let mut next_code = first_code.clone();
        let mut next_symbol = first_symbol.clone();
        let mut codes = vec![(0u32, 0u8); lengths.len()];
        let mut symbols = vec![0usize; sym_offset];

        for (sym, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let l = usize::from(len);
            let c = next_code[l];
            next_code[l] += 1;
            codes[sym] = (c as u32, len);
            symbols[next_symbol[l]] = sym;
            next_symbol[l] += 1;
        }

        Ok(Self {
            max_len,
            complete,
            symbol_count: lengths.len(),
            codes,
            counts,
            first_code,
            first_symbol,
            symbols,
        })
    }

    /// Build a canonical Huffman table requiring a complete prefix tree
    /// (Kraft sum strictly equal to `1.0`).
    pub fn from_code_lengths_strict(lengths: &[u8]) -> Result<Self> {
        let table = Self::from_code_lengths(lengths)?;
        if !table.complete {
            return Err(Error::Malformed(
                "Huffman codebook is incomplete (under-subscribed)".into(),
            ));
        }
        Ok(table)
    }

    /// Whether the prefix tree is complete (Kraft sum equals `1.0`).
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Longest active code length in bits.
    #[must_use]
    pub const fn max_code_length(&self) -> u8 {
        self.max_len
    }

    /// Total alphabet size (length of the input `lengths` slice).
    #[must_use]
    pub const fn symbol_count(&self) -> usize {
        self.symbol_count
    }

    /// Look up the canonical code for `symbol` in `bit_order`, or `None` if absent.
    #[must_use]
    pub fn code_for(&self, symbol: usize, bit_order: HuffmanBitOrder) -> Option<CanonicalCode> {
        let &(msb_code, length) = self.codes.get(symbol)?;
        if length == 0 {
            return None;
        }
        let code = match bit_order {
            HuffmanBitOrder::MsbFirst => msb_code,
            HuffmanBitOrder::LsbFirst => reverse_bits(msb_code, length),
        };
        Some(CanonicalCode { code, length })
    }

    /// Decode one symbol from an MSB-first bitstream cursor.
    pub fn decode_symbol_msb(&self, cursor: &mut MsbBitCursor<'_>) -> Result<usize> {
        let mut code = 0u64;
        for len in 1..=usize::from(self.max_len) {
            let bit = cursor.read(1).ok_or(Error::Truncated {
                offset: cursor.byte_extent(),
                needed: 1,
                available: 0,
            })?;
            code = (code << 1) | u64::from(bit);
            let count = u64::from(self.counts[len]);
            if count > 0 && code >= self.first_code[len] {
                let delta = code - self.first_code[len];
                if delta < count {
                    return Ok(self.symbols[self.first_symbol[len] + delta as usize]);
                }
            }
        }
        Err(Error::Malformed("invalid Huffman code".into()))
    }

    /// Decode one symbol from an LSB-first bitstream cursor.
    pub fn decode_symbol_lsb(&self, cursor: &mut LsbBitCursor<'_>) -> Result<usize> {
        let mut code = 0u64;
        for len in 1..=usize::from(self.max_len) {
            let bit = cursor.read(1).ok_or(Error::Truncated {
                offset: cursor.byte_extent(),
                needed: 1,
                available: 0,
            })?;
            code = (code << 1) | u64::from(bit);
            let count = u64::from(self.counts[len]);
            if count > 0 && code >= self.first_code[len] {
                let delta = code - self.first_code[len];
                if delta < count {
                    return Ok(self.symbols[self.first_symbol[len] + delta as usize]);
                }
            }
        }
        Err(Error::Malformed("invalid Huffman code".into()))
    }

    /// Decode exactly `symbol_count` symbols from `bytes` in `bit_order`,
    /// returning `(symbols, bytes_consumed)`.
    pub fn decode_symbols(
        &self,
        bytes: &[u8],
        bit_order: HuffmanBitOrder,
        symbol_count: usize,
    ) -> Result<(Vec<usize>, usize)> {
        let mut out = Vec::with_capacity(symbol_count.min(64 * 1024));
        match bit_order {
            HuffmanBitOrder::MsbFirst => {
                let mut cursor = MsbBitCursor::new(bytes);
                for _ in 0..symbol_count {
                    out.push(self.decode_symbol_msb(&mut cursor)?);
                }
                Ok((out, cursor.byte_extent()))
            }
            HuffmanBitOrder::LsbFirst => {
                let mut cursor = LsbBitCursor::new(bytes);
                for _ in 0..symbol_count {
                    out.push(self.decode_symbol_lsb(&mut cursor)?);
                }
                Ok((out, cursor.byte_extent()))
            }
        }
    }

    /// Encode `symbols` into a contiguous bitstream in `bit_order` (zero-padded
    /// to a byte boundary at the end).
    pub fn encode_symbols(&self, symbols: &[usize], bit_order: HuffmanBitOrder) -> Result<Vec<u8>> {
        match bit_order {
            HuffmanBitOrder::MsbFirst => {
                let mut writer = MsbBitWriter::new();
                for &sym in symbols {
                    let cc = self.code_for(sym, HuffmanBitOrder::MsbFirst).ok_or(
                        Error::InvalidField {
                            what: "Huffman symbol",
                            value: sym as u64,
                        },
                    )?;
                    writer.write_bits(cc.code, u32::from(cc.length))?;
                }
                Ok(writer.finish())
            }
            HuffmanBitOrder::LsbFirst => {
                let mut writer = LsbBitWriter::new();
                for &sym in symbols {
                    let cc = self.code_for(sym, HuffmanBitOrder::LsbFirst).ok_or(
                        Error::InvalidField {
                            what: "Huffman symbol",
                            value: sym as u64,
                        },
                    )?;
                    writer.write_bits(cc.code, u32::from(cc.length))?;
                }
                Ok(writer.finish())
            }
        }
    }
}

/// Build deterministic canonical Huffman code lengths from symbol frequencies,
/// capped at `max_bits` (`1..=32`).
///
/// Symbols with frequency `0` receive code length `0`. If exactly one symbol
/// has a non-zero frequency, it receives code length `1`. When the natural
/// Huffman tree exceeds `max_bits`, lengths are deterministically clamped and
/// rebalanced to satisfy the Kraft equality.
pub fn build_code_lengths(frequencies: &[u64], max_bits: u8) -> Result<Vec<u8>> {
    if max_bits == 0 || max_bits > MAX_HUFFMAN_CODE_BITS {
        return Err(Error::InvalidField {
            what: "Huffman max_bits",
            value: u64::from(max_bits),
        });
    }

    let mut active: Vec<(usize, u64)> = frequencies
        .iter()
        .enumerate()
        .filter_map(|(sym, &freq)| (freq > 0).then_some((sym, freq)))
        .collect();

    let mut lengths = vec![0u8; frequencies.len()];
    if active.is_empty() {
        return Ok(lengths);
    }
    if active.len() == 1 {
        lengths[active[0].0] = 1;
        return Ok(lengths);
    }

    let max_symbols: u64 = 1u64 << u32::from(max_bits);
    if (active.len() as u64) > max_symbols {
        return Err(Error::Malformed(
            "active symbol count exceeds maximum Huffman code length capacity".into(),
        ));
    }

    // Build deterministic binary Huffman tree with parent pointers.
    let leaf_count = active.len();
    let mut parent = vec![usize::MAX; leaf_count * 2 - 1];
    let mut heap: BinaryHeap<Reverse<(u64, usize)>> = BinaryHeap::with_capacity(leaf_count);
    for (node_idx, &(_, freq)) in active.iter().enumerate() {
        heap.push(Reverse((freq, node_idx)));
    }

    let mut next_node = leaf_count;
    while heap.len() > 1 {
        let Reverse((f1, n1)) = heap.pop().expect("heap has >= 2 items");
        let Reverse((f2, n2)) = heap.pop().expect("heap has >= 1 item");
        parent[n1] = next_node;
        parent[n2] = next_node;
        heap.push(Reverse((f1.saturating_add(f2), next_node)));
        next_node += 1;
    }

    let mut leaf_depths = vec![0u32; leaf_count];
    let mut overflowed = false;
    for (leaf, depth_slot) in leaf_depths.iter_mut().enumerate() {
        let mut depth = 0u32;
        let mut cur = leaf;
        while parent[cur] != usize::MAX {
            depth += 1;
            cur = parent[cur];
        }
        if depth > u32::from(max_bits) {
            overflowed = true;
            *depth_slot = u32::from(max_bits);
        } else {
            *depth_slot = depth;
        }
    }

    if overflowed {
        // Order leaves by descending frequency (ties by symbol index) so higher
        // frequency symbols keep shorter codes during Kraft rebalancing.
        let mut order: Vec<usize> = (0..leaf_count).collect();
        order.sort_by(|&a, &b| {
            active[b]
                .1
                .cmp(&active[a].1)
                .then_with(|| active[a].0.cmp(&active[b].0))
        });

        let limit = 1u64 << u32::from(max_bits);
        let kraft_sum = |depths: &[u32]| -> u64 {
            depths
                .iter()
                .map(|&d| 1u64 << (u32::from(max_bits) - d))
                .sum()
        };

        // Reduce Kraft sum if oversubscribed by lengthening the least-frequent
        // symbols that are still shorter than max_bits.
        let mut current = kraft_sum(&leaf_depths);
        while current > limit {
            let mut lengthened = false;
            for &idx in order.iter().rev() {
                if leaf_depths[idx] < u32::from(max_bits) {
                    leaf_depths[idx] += 1;
                    current -= 1u64 << (u32::from(max_bits) - leaf_depths[idx]);
                    lengthened = true;
                    break;
                }
            }
            if !lengthened {
                break;
            }
        }

        // Fill any remaining Kraft slack by shortening the most-frequent symbols
        // whose weight increase fits inside the slack.
        while current < limit {
            let slack = limit - current;
            let mut shortened = false;
            for &idx in &order {
                if leaf_depths[idx] > 1 {
                    let delta = 1u64 << (u32::from(max_bits) - leaf_depths[idx]);
                    if delta <= slack {
                        leaf_depths[idx] -= 1;
                        current += delta;
                        shortened = true;
                        break;
                    }
                }
            }
            if !shortened {
                break;
            }
        }
    }

    for (leaf, (sym, _)) in active.drain(..).enumerate() {
        lengths[sym] = leaf_depths[leaf] as u8;
    }
    Ok(lengths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_table_validates_kraft_and_round_trips_both_bit_orders() {
        // Complete 4-symbol codebook: lengths [1, 2, 3, 3] -> codes 0, 10, 110, 111.
        let table = CanonicalHuffmanTable::from_code_lengths_strict(&[1, 2, 3, 3]).unwrap();
        assert!(table.is_complete());
        assert_eq!(table.max_code_length(), 3);
        assert_eq!(table.symbol_count(), 4);
        assert_eq!(
            table.code_for(0, HuffmanBitOrder::MsbFirst),
            Some(CanonicalCode {
                code: 0b0,
                length: 1
            })
        );
        assert_eq!(
            table.code_for(2, HuffmanBitOrder::MsbFirst),
            Some(CanonicalCode {
                code: 0b110,
                length: 3
            })
        );
        assert_eq!(
            table.code_for(2, HuffmanBitOrder::LsbFirst),
            Some(CanonicalCode {
                code: 0b011,
                length: 3
            })
        );

        let message = [0, 1, 2, 3, 2, 1, 0, 3, 3, 0];
        for order in [HuffmanBitOrder::MsbFirst, HuffmanBitOrder::LsbFirst] {
            let encoded = table.encode_symbols(&message, order).unwrap();
            let (decoded, consumed) = table
                .decode_symbols(&encoded, order, message.len())
                .unwrap();
            assert_eq!(decoded, message);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn rejects_empty_oversubscribed_and_incomplete_strict_codebooks() {
        assert!(CanonicalHuffmanTable::from_code_lengths(&[0, 0, 0]).is_err());
        // Oversubscribed: three symbols of length 1 (Kraft = 1.5 > 1.0).
        assert!(CanonicalHuffmanTable::from_code_lengths(&[1, 1, 1]).is_err());
        // Incomplete: single symbol of length 1 (Kraft = 0.5 < 1.0).
        let single = CanonicalHuffmanTable::from_code_lengths(&[0, 1, 0]).unwrap();
        assert!(!single.is_complete());
        assert!(CanonicalHuffmanTable::from_code_lengths_strict(&[0, 1, 0]).is_err());
        // Length > 32 rejected.
        assert!(CanonicalHuffmanTable::from_code_lengths(&[33]).is_err());
    }

    #[test]
    fn build_code_lengths_handles_fibonacci_length_limiting_and_edge_cases() {
        // Edge cases.
        assert_eq!(build_code_lengths(&[0, 0, 0], 15).unwrap(), vec![0, 0, 0]);
        assert_eq!(build_code_lengths(&[0, 42, 0], 15).unwrap(), vec![0, 1, 0]);
        assert!(build_code_lengths(&[1, 1], 0).is_err());
        assert!(build_code_lengths(&[1, 1, 1, 1, 1], 2).is_err());

        // Fibonacci frequencies force a skewed tree of depth 9; limit to max_bits = 5.
        let freqs = [1, 1, 2, 3, 5, 8, 13, 21, 34, 55];
        let lengths = build_code_lengths(&freqs, 5).unwrap();
        assert!(lengths.iter().all(|&l| (1..=5).contains(&l)));
        let table = CanonicalHuffmanTable::from_code_lengths_strict(&lengths).unwrap();
        assert!(table.is_complete());

        let symbols: Vec<usize> = (0..freqs.len()).collect();
        for order in [HuffmanBitOrder::MsbFirst, HuffmanBitOrder::LsbFirst] {
            let encoded = table.encode_symbols(&symbols, order).unwrap();
            let (decoded, _) = table
                .decode_symbols(&encoded, order, symbols.len())
                .unwrap();
            assert_eq!(decoded, symbols);
        }
    }

    #[test]
    fn build_code_lengths_handles_large_skewed_alphabet_within_max_bits() {
        // 256-symbol heavily skewed frequency distribution forcing deep natural tree
        // and Kraft rebalancing down to max_bits = 12.
        let mut freqs = vec![0u64; 256];
        for (i, slot) in freqs.iter_mut().enumerate() {
            *slot = if i < 60 {
                1u64 << (i / 2)
            } else {
                1 + (i as u64)
            };
        }
        let lengths = build_code_lengths(&freqs, 12).unwrap();
        assert_eq!(lengths.len(), 256);
        assert!(lengths.iter().all(|&l| (1..=12).contains(&l)));

        let table = CanonicalHuffmanTable::from_code_lengths_strict(&lengths).unwrap();
        assert!(table.is_complete());
        assert!(table.max_code_length() <= 12);

        let message: Vec<usize> = (0..256).collect();
        for order in [HuffmanBitOrder::MsbFirst, HuffmanBitOrder::LsbFirst] {
            let encoded = table.encode_symbols(&message, order).unwrap();
            let (decoded, consumed) = table
                .decode_symbols(&encoded, order, message.len())
                .unwrap();
            assert_eq!(decoded, message);
            assert_eq!(consumed, encoded.len());
        }
    }
}
