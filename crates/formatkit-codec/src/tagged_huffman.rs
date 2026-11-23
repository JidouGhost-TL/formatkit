//! Tagged-header Huffman streams with a packed 6-bit-offset node tree and
//! 4-bit or 8-bit symbols.
//!
//! After a compact [`crate::tagged_header`] (tag [`TAG_HUFFMAN_4BIT`] `0x24` or
//! [`TAG_HUFFMAN_8BIT`] `0x28`; the low nibble is the symbol width) comes the
//! tree table. Its first byte `n` gives the table length `(n + 1) * 2`
//! including that byte; the root node follows at table index `1`. Each
//! internal node byte stores a 6-bit offset in its low bits and two leaf flags
//! (`0x80`: the `0` child is a leaf, `0x40`: the `1` child is a leaf). The
//! children of the node at index `i` live at `(i & !1) + offset * 2 + 2` (`0`
//! branch) and the following byte (`1` branch); a leaf entry holds the symbol.
//!
//! The bitstream that follows the table is a sequence of little-endian 32-bit
//! words read most-significant bit first. With 4-bit symbols, the first symbol
//! of each pair fills the low nibble of the output byte. Decoding stops after
//! the word that completes the declared size, so the consumed extent is
//! word-aligned and exact.
//!
//! ```
//! use formatkit_codec::tagged_huffman::{
//!     decode_tagged_huffman, encode_tagged_huffman, TaggedHuffmanWidth,
//! };
//!
//! let data = b"mississippi river delta".repeat(8);
//! for width in [TaggedHuffmanWidth::Bits4, TaggedHuffmanWidth::Bits8] {
//!     let stream = encode_tagged_huffman(&data, width).unwrap();
//!     let decoded = decode_tagged_huffman(&stream, 1 << 20).unwrap();
//!     assert_eq!(decoded.bytes, data);
//!     assert_eq!(decoded.consumed, stream.len());
//! }
//! ```
//!
//! [`TAG_HUFFMAN_4BIT`]: crate::tagged_header::TAG_HUFFMAN_4BIT
//! [`TAG_HUFFMAN_8BIT`]: crate::tagged_header::TAG_HUFFMAN_8BIT

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use formatkit_core::{bytes_at, Error, MsbBitWriter, Result};

use crate::tagged_header::{
    check_decoded_size, check_encode_len, read_tagged_header, write_tagged_header,
    TAGGED_HEADER_LEN,
};
pub use crate::tagged_header::{TAG_HUFFMAN_4BIT, TAG_HUFFMAN_8BIT};
use crate::DecodeOutcome;

/// Largest serialized tree table in bytes (size byte included).
pub const TAGGED_HUFFMAN_MAX_TREE_LEN: usize = 512;

/// Symbol width of a tagged Huffman stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaggedHuffmanWidth {
    /// 16-symbol alphabet; two symbols per output byte, low nibble first.
    Bits4,
    /// 256-symbol alphabet; one symbol per output byte.
    Bits8,
}

impl TaggedHuffmanWidth {
    /// Stream tag for this width.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Bits4 => TAG_HUFFMAN_4BIT,
            Self::Bits8 => TAG_HUFFMAN_8BIT,
        }
    }

    /// Width for a stream tag, if it names a tagged Huffman stream.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            TAG_HUFFMAN_4BIT => Some(Self::Bits4),
            TAG_HUFFMAN_8BIT => Some(Self::Bits8),
            _ => None,
        }
    }

    const fn alphabet(self) -> usize {
        match self {
            Self::Bits4 => 16,
            Self::Bits8 => 256,
        }
    }
}

/// Decode a 4-bit (`0x24`) or 8-bit (`0x28`) tagged Huffman stream starting at `input[0]`.
///
/// Rejects an unknown tag, a zero declared size, or a declared size above
/// `max_output` before allocating, and rejects tree offsets that leave the
/// table. Returns the exact consumed extent (header, tree, and bitstream words).
pub fn decode_tagged_huffman(input: &[u8], max_output: usize) -> Result<DecodeOutcome> {
    let header = read_tagged_header(input)?;
    let width = TaggedHuffmanWidth::from_tag(header.tag).ok_or(Error::BadMagic {
        offset: 0,
        expected: u32::from(TAG_HUFFMAN_4BIT),
        found: u32::from(header.tag),
    })?;
    // The tree size byte is part of the minimum frame.
    bytes_at(input, TAGGED_HEADER_LEN, 1)?;
    check_decoded_size(
        header,
        "tagged Huffman decoded size",
        "tagged Huffman decoded output",
        max_output,
    )?;
    let expected = header.decoded_size;

    let tree_len = (usize::from(input[TAGGED_HEADER_LEN]) + 1) * 2;
    let tree = bytes_at(input, TAGGED_HEADER_LEN, tree_len)?;
    let mut pos = TAGGED_HEADER_LEN + tree_len;

    let mut out = Vec::with_capacity(expected.min(input.len().saturating_mul(8)));
    let mut node_idx = 1usize;
    let mut low_nibble: Option<u8> = None;

    while out.len() < expected {
        let raw = bytes_at(input, pos, 4)?;
        let word = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        pos += 4;

        for shift in (0..32).rev() {
            if out.len() >= expected {
                break;
            }
            let bit = ((word >> shift) & 1) as usize;
            let node = *tree.get(node_idx).ok_or(Error::InvalidField {
                what: "tagged Huffman node index",
                value: node_idx as u64,
            })?;
            let is_leaf = node & (0x80 >> bit) != 0;
            let next_idx = (node_idx & !1) + usize::from(node & 0x3F) * 2 + 2 + bit;
            let child = *tree.get(next_idx).ok_or(Error::InvalidField {
                what: "tagged Huffman child offset",
                value: next_idx as u64,
            })?;
            if !is_leaf {
                node_idx = next_idx;
                continue;
            }
            match width {
                TaggedHuffmanWidth::Bits8 => out.push(child),
                TaggedHuffmanWidth::Bits4 => {
                    if let Some(lo) = low_nibble.take() {
                        out.push(lo | (child & 0x0F) << 4);
                    } else {
                        low_nibble = Some(child & 0x0F);
                    }
                }
            }
            node_idx = 1;
        }
    }

    Ok(DecodeOutcome {
        bytes: out,
        consumed: pos,
    })
}

/// Encode `data` (`1..=0xFF_FFFF` bytes) as a tagged Huffman stream of `width` symbols.
///
/// Builds a frequency-ordered Huffman tree (a single distinct symbol gets a
/// two-leaf tree), lays it out so every 6-bit child offset fits, and pads the
/// bitstream to whole 32-bit words.
pub fn encode_tagged_huffman(data: &[u8], width: TaggedHuffmanWidth) -> Result<Vec<u8>> {
    check_encode_len(data.len(), "tagged Huffman input size")?;

    let alphabet = width.alphabet();
    let mut freqs = vec![0u64; alphabet];
    match width {
        TaggedHuffmanWidth::Bits4 => {
            for &b in data {
                freqs[usize::from(b & 0x0F)] += 1;
                freqs[usize::from(b >> 4)] += 1;
            }
        }
        TaggedHuffmanWidth::Bits8 => {
            for &b in data {
                freqs[usize::from(b)] += 1;
            }
        }
    }

    let (nodes, root_id) = build_tree(&freqs);
    let tree = serialize_tree(&nodes, root_id)?;
    let mut codes = vec![(0u64, 0u8); alphabet];
    assign_codes(&nodes, root_id, &mut codes);

    let mut out = Vec::with_capacity(TAGGED_HEADER_LEN + tree.len() + data.len());
    write_tagged_header(&mut out, width.tag(), data.len())?;
    out.extend_from_slice(&tree);

    let mut writer = MsbBitWriter::with_capacity(data.len());
    let mut emit = |sym: u8| -> Result<()> {
        let (code, len) = codes[usize::from(sym)];
        let len = u32::from(len);
        if len > 32 {
            writer.write_bits((code >> 32) as u32, len - 32)?;
            writer.write_bits(code as u32, 32)
        } else {
            writer.write_bits(code as u32, len)
        }
    };
    match width {
        TaggedHuffmanWidth::Bits4 => {
            for &b in data {
                emit(b & 0x0F)?;
                emit(b >> 4)?;
            }
        }
        TaggedHuffmanWidth::Bits8 => {
            for &b in data {
                emit(b)?;
            }
        }
    }
    let mut bitstream = writer.finish();
    bitstream.resize(bitstream.len().next_multiple_of(4), 0);
    for chunk in bitstream.as_chunks::<4>().0 {
        out.extend_from_slice(&[chunk[3], chunk[2], chunk[1], chunk[0]]);
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy)]
enum Node {
    Leaf(u8),
    Internal {
        left: usize,
        right: usize,
        desc_internals: usize,
    },
}

/// Build a Huffman tree with deterministic `(frequency, node id)` tie-breaking.
fn build_tree(freqs: &[u64]) -> (Vec<Node>, usize) {
    let mut nodes = Vec::with_capacity(freqs.len() * 2);
    let mut heap = BinaryHeap::new();
    for (sym, &freq) in freqs.iter().enumerate() {
        if freq > 0 {
            heap.push(Reverse((freq, nodes.len())));
            nodes.push(Node::Leaf(sym as u8));
        }
    }
    if heap.len() == 1 {
        let only = 0usize;
        let Node::Leaf(sym) = nodes[only] else {
            unreachable!("only node is a leaf")
        };
        nodes.push(Node::Leaf(sym));
        nodes.push(Node::Internal {
            left: only,
            right: 1,
            desc_internals: 0,
        });
        return (nodes, 2);
    }
    let internals_below = |node: Node| match node {
        Node::Leaf(_) => 0,
        Node::Internal { desc_internals, .. } => desc_internals + 1,
    };
    while heap.len() > 1 {
        let Some(Reverse((f1, n1))) = heap.pop() else {
            unreachable!()
        };
        let Some(Reverse((f2, n2))) = heap.pop() else {
            unreachable!()
        };
        let parent = nodes.len();
        nodes.push(Node::Internal {
            left: n1,
            right: n2,
            desc_internals: internals_below(nodes[n1]) + internals_below(nodes[n2]),
        });
        heap.push(Reverse((f1 + f2, parent)));
    }
    let root = heap.pop().map_or(0, |Reverse((_, id))| id);
    (nodes, root)
}

fn assign_codes(nodes: &[Node], root: usize, table: &mut [(u64, u8)]) {
    let mut stack = vec![(root, 0u64, 0u8)];
    while let Some((id, code, depth)) = stack.pop() {
        match nodes[id] {
            Node::Leaf(sym) => table[usize::from(sym)] = (code, depth),
            Node::Internal { left, right, .. } => {
                stack.push((right, code << 1 | 1, depth + 1));
                stack.push((left, code << 1, depth + 1));
            }
        }
    }
}

/// Lay out the tree so that every internal node's child pair sits at most 63
/// pairs after the node's own pair.
fn serialize_tree(nodes: &[Node], root: usize) -> Result<Vec<u8>> {
    struct Pending {
        tree_idx: usize,
        pair_idx: usize,
        node_id: usize,
    }

    let mut tree = Vec::with_capacity(TAGGED_HUFFMAN_MAX_TREE_LEN);
    tree.extend_from_slice(&[0, 0]); // size byte and root placeholders
    let mut pending = vec![Pending {
        tree_idx: 1,
        pair_idx: 0,
        node_id: root,
    }];
    let mut next_pair = 1usize;

    while !pending.is_empty() {
        // Invariant: for every i, next_pair + i - pending[i].pair_idx - 1 <= 63.
        // Restricting the choice to 0..=limit keeps every pending offset in range.
        let limit = pending
            .iter()
            .enumerate()
            .find(|(i, p)| next_pair + i >= p.pair_idx + 64)
            .map_or(pending.len() - 1, |(i, _)| i);
        // Prefer the node with the fewest internal descendants (earliest on ties).
        let mut best = 0usize;
        let mut best_desc = usize::MAX;
        for (i, p) in pending.iter().enumerate().take(limit + 1) {
            let desc = match nodes[p.node_id] {
                Node::Internal { desc_internals, .. } => desc_internals,
                Node::Leaf(_) => 0,
            };
            if desc < best_desc {
                best_desc = desc;
                best = i;
            }
        }

        let p = pending.remove(best);
        let offset = next_pair
            .checked_sub(p.pair_idx + 1)
            .filter(|&o| o <= 63)
            .ok_or(Error::InvalidField {
                what: "tagged Huffman tree offset",
                value: next_pair as u64,
            })?;
        let Node::Internal { left, right, .. } = nodes[p.node_id] else {
            unreachable!("pending nodes are internal")
        };

        let mut flags = offset as u8;
        let child_base = next_pair * 2;
        for (bit, child) in [(0x80u8, left), (0x40u8, right)] {
            match nodes[child] {
                Node::Leaf(sym) => {
                    flags |= bit;
                    tree.push(sym);
                }
                Node::Internal { .. } => {
                    pending.push(Pending {
                        tree_idx: child_base + usize::from(bit == 0x40),
                        pair_idx: next_pair,
                        node_id: child,
                    });
                    tree.push(0);
                }
            }
        }
        tree[p.tree_idx] = flags;
        next_pair += 1;
    }

    // Pad the table so the 32-bit bitstream starts on a word boundary.
    if !tree.len().is_multiple_of(4) && tree.len() + 2 <= TAGGED_HUFFMAN_MAX_TREE_LEN {
        tree.extend_from_slice(&[0, 0]);
    }
    if tree.len() > TAGGED_HUFFMAN_MAX_TREE_LEN {
        return Err(Error::InvalidField {
            what: "tagged Huffman tree size",
            value: tree.len() as u64,
        });
    }
    tree[0] = (tree.len() / 2 - 1) as u8;
    Ok(tree)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lcg_bytes(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                (state >> 56) as u8
            })
            .collect()
    }

    #[test]
    fn reference_vectors_decode_with_exact_word_extent() {
        // Two-leaf tree: bit 0 -> 'A', bit 1 -> 'B'; word 0x5000_0000 -> "ABAB".
        let h8 = [
            0x28, 0x04, 0x00, 0x00, 0x01, 0xC0, b'A', b'B', 0x00, 0x00, 0x00, 0x50, 0xFF,
        ];
        let dec8 = decode_tagged_huffman(&h8, 64).unwrap();
        assert_eq!(dec8.bytes, b"ABAB");
        assert_eq!(dec8.consumed, 12);

        // Nibbles 3, A, A, 3 (bits 0110) -> bytes [0xA3, 0x3A], low nibble first.
        let h4 = [
            0x24, 0x02, 0x00, 0x00, 0x01, 0xC0, 0x03, 0x0A, 0x00, 0x00, 0x00, 0x60, 0xFF,
        ];
        let dec4 = decode_tagged_huffman(&h4, 64).unwrap();
        assert_eq!(dec4.bytes, [0xA3, 0x3A]);
        assert_eq!(dec4.consumed, 12);
    }

    #[test]
    fn round_trips_degenerate_skewed_and_full_alphabets() {
        let mut skewed = Vec::new();
        for sym in 0..=255u8 {
            let count = if sym < 8 {
                (usize::from(sym) + 1) * 40
            } else {
                usize::from(sym) % 5 + 1
            };
            skewed.extend(std::iter::repeat_n(sym, count));
        }
        // Fibonacci-like frequencies force a deep, unbalanced tree.
        let mut deep = Vec::new();
        let (mut a, mut b) = (1usize, 1usize);
        for sym in 0..20u8 {
            deep.extend(std::iter::repeat_n(sym, a));
            (a, b) = (b, a + b);
        }
        let cases: [Vec<u8>; 6] = [
            vec![0x77; 31],
            vec![0xE2; 25],
            (0..=255).collect(),
            skewed,
            deep,
            lcg_bytes(0x1234_5678, 4096),
        ];
        for case in &cases {
            for width in [TaggedHuffmanWidth::Bits4, TaggedHuffmanWidth::Bits8] {
                let mut stream = encode_tagged_huffman(case, width).unwrap();
                assert_eq!(stream[0], width.tag());
                assert_eq!((stream[4] as usize + 1) * 2 % 4, 0);
                let exact = stream.len();
                stream.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
                let dec = decode_tagged_huffman(&stream, case.len()).unwrap();
                assert_eq!(&dec.bytes, case);
                assert_eq!(dec.consumed, exact);
            }
        }
        assert!(encode_tagged_huffman(&[], TaggedHuffmanWidth::Bits8).is_err());
    }

    #[test]
    fn rejects_bad_tag_size_limits_and_out_of_table_offsets() {
        assert!(matches!(
            decode_tagged_huffman(&[0x20, 1, 0, 0, 1], 64),
            Err(Error::BadMagic { .. })
        ));
        assert!(matches!(
            decode_tagged_huffman(&[0x28, 0, 0, 0, 1], 64),
            Err(Error::InvalidField { .. })
        ));
        assert!(matches!(
            decode_tagged_huffman(&[0x28, 0, 0, 0x40, 1], 1024),
            Err(Error::ResourceLimit { .. })
        ));
        assert!(matches!(
            decode_tagged_huffman(&[0x28, 1, 0, 0], 64),
            Err(Error::Truncated { .. })
        ));
        // Tree claims 0x80 * 2 bytes on a short input.
        assert!(matches!(
            decode_tagged_huffman(&[0x28, 1, 0, 0, 0x7F, 0xC0], 64),
            Err(Error::Truncated { .. })
        ));
        // Root offset 0x3F points beyond a four-byte table.
        let bad = [0x28, 1, 0, 0, 0x01, 0x3F, 0, 0, 0, 0, 0, 0];
        assert!(matches!(
            decode_tagged_huffman(&bad, 64),
            Err(Error::InvalidField { .. })
        ));
    }

    #[test]
    fn truncated_and_mutated_streams_never_panic() {
        let data = lcg_bytes(99, 600);
        for width in [TaggedHuffmanWidth::Bits4, TaggedHuffmanWidth::Bits8] {
            let stream = encode_tagged_huffman(&data, width).unwrap();
            for cut in 0..stream.len() {
                assert!(decode_tagged_huffman(&stream[..cut], 1 << 16).is_err());
            }
            for seed in 0..256u64 {
                let mut mutated = stream.clone();
                for (i, noise) in lcg_bytes(seed, 4).into_iter().enumerate() {
                    let at = (seed as usize * 13 + i * 101) % mutated.len();
                    mutated[at] ^= noise | 1;
                }
                if let Ok(dec) = decode_tagged_huffman(&mutated, 1 << 16) {
                    assert!(dec.consumed <= mutated.len());
                }
            }
        }
    }
}
