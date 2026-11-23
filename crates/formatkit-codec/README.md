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

## Image codecs

- `png` — PNG decoding and RGBA encoding.
- `pcx` — PCX decoding and indexed/RGBA encoding.
- `tga` — TGA decoding and indexed/RGBA encoding.
- `dds` — DirectDraw Surface decoding, encoding, and rect patching (gated behind
  the default `dds` feature, which depends on `formatkit-pixel`).

## License

MIT OR Apache-2.0.
