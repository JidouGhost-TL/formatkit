# formatkit-codec

Reusable bounded compression and image codecs with exact consumed-byte reporting
(`DecodeOutcome`) and no platform catalog or container envelope policy.

## Compression & LZSS primitives

- `okumura` — 4096-byte pre-filled ring-buffer LZSS (LSB-first and MSB-first variants).
- `flag_lzss` — parameterized flag-byte / flag-word LZSS stream executor for custom
  match-token grammars and linear sliding-window history.
- `counted_lsb` — externally counted LZ commands with lazy interleaved LSB-first control bytes.
- `sliding_window` — low-level `append_match`, `find_longest_match`, and `RingBuffer`.
- `deflate`, `inflate`, `gzip`, `lzma`, `rnc` — bounded standard stream codecs.
- `huffman`, `rle`, `delta` — canonical Huffman tables, configurable high-bit RLE,
  and allocation-free byte/16-bit delta transforms.

## Tagged-header stream family

Streams framed by one tag byte plus a 24-bit little-endian decoded size, with
exact consumed extents and `max_output` checks before allocation:

- `tagged_header` — read/write the 4-byte header and its 8-byte extended-size form.
- `tagged_lz77` — compact (`0x10`, 2-byte tokens, optional minimum distance) and
  extended-length (`0x11`, 2/3/4-byte tokens) LZ77, decode and encode.
- `tagged_huffman` — packed 6-bit-offset tree Huffman with 4-bit (`0x24`) or
  8-bit (`0x28`) symbols, decode and encode.
- `rle::{decode_tagged_rle, encode_tagged_rle}` — byte run-length (`0x30`).
- `delta::{decode_tagged_delta, encode_tagged_delta}` — 8-bit (`0x81`) and
  16-bit little-endian (`0x82`) delta filters.
- `bit_unpack` — widen packed 1/2/4/8-bit units to 1..=32 bits with a
  conditional offset.

## Image codecs

- `png` — PNG decoding and RGBA encoding.
- `pcx` — PCX decoding and indexed/RGBA encoding.
- `tga` — TGA decoding and indexed/RGBA encoding.
- `dds` — DirectDraw Surface decoding, encoding, and rect patching (gated behind
  the default `dds` feature, which depends on `formatkit-pixel`).

## License

MIT OR Apache-2.0.
