# formatkit-pixel

Container-independent palette, packed-pixel, planar-tile, glyph, Morton swizzle,
atlas, and S3TC/DXT block-codec mechanics.

## Modules

- `atlas` — RGBA cropping, blitting, and grid atlas composition (`GridAtlasLayout`).
- `dxt` — S3TC / DXT1–DXT5 block decoding and arbitrary `ChannelMasks` unpacking.
- `glyph` — allocation-free 1bpp, 2bpp, and 4bpp bitmap glyph unpacking and packing.
- `morton` — Morton (Z-order) coordinate interleaving and 2D texture swizzle/unswizzle.
- `palette` — grayscale palette generation, nearest-color lookup, and RGBA quantization.
- `planar` — interleaved-row planar 8×8 tile unpacking and packing (1, 2, or 4 bitplanes).

## Crate-root helpers

The crate root provides allocation-free 4bpp/8bpp index packing with explicit
`NibbleOrder`, `BitOrder`, and `IndexPolicy` controls, plus 16-bit color-word
conversions (`RGB565`, `BGR555`, `RGBA5551`, `RGBA4444`, `RGB444`).

## License

MIT OR Apache-2.0.
