# FormatKit Capabilities Cookbook

Task-oriented reference for every reusable, platform-neutral binary-data mechanism in FormatKit. Look here (or query [`docs/capabilities.json`](docs/capabilities.json)) before implementing a local parser, codec, checksum, pixel unpacker, table decoder, or archive service.

---

## I need to… → use…

### 1. Bytes, Numbers, Bitstreams & Framing

| I need to… | Use… | Crate / Feature |
| --- | --- | --- |
| Read sequential little/big-endian integers, floats, slices, or fixed arrays with cursor tracking | `formatkit_core::Reader` | `formatkit-core` |
| Read or write a single integer or slice at an explicit byte offset without cursor state | `formatkit_core::{u8_at, u16_at, u32_at, u64_at, i8_at, i16_at, i32_at, i64_at, *_at_endian, uint_le_at, uint_be_at, bytes_at, bytes_at_mut, write_uint_le_at, write_uint_be_at}` | `formatkit-core` |
| Align an offset up to a power-of-two or arbitrary multiple with overflow checks | `formatkit_core::{checked_align_up, checked_align_up_multiple}` / `formatkit_layout::checked_align_up_u64` | `formatkit-core` / `formatkit-layout` |
| Build a binary buffer sequentially with checked LE/BE writes | `formatkit_core::Writer` | `formatkit-core` |
| Extract or replace individual bits or bitfields in a decoded integer word | `formatkit_core::{Bit, BitRange}` | `formatkit-core` |
| Read or write a contiguous LSB-first or MSB-first bitstream across byte boundaries | `formatkit_core::{LsbBitCursor, MsbBitCursor, LsbBitWriter, MsbBitWriter}` | `formatkit-core` |
| Read or write an interleaved control-bit / raw-byte stream (flag bytes mixed with operand bytes) | `formatkit_core::{InterleavedBitReader, MsbInterleavedBitReader, LsbInterleavedBitReader, InterleavedBitWriter, MsbInterleavedBitWriter, LsbInterleavedBitWriter}` | `formatkit-core` |
| Decode packed BCD (binary-coded decimal) bytes to binary or encode `0..=99` to BCD | `formatkit_core::bcd::{bcd_to_u8, u8_to_bcd}` | `formatkit-core` |
| Decode fixed-point Q12, IEEE 754 binary16 (half-float), fixed-turn sin/cos, 3×3/3×4 matrices, or quaternions | `formatkit_core::math::{q12_i16_to_f32, binary16_to_f32, fixed_turn_sin_cos, Matrix, quaternion_multiply, normalize_quaternion}` | `formatkit-core` |
| Expand a triangle strip or triangle fan into indexed triangles | `formatkit_core::topology::{triangle_strip, triangle_fan}` | `formatkit-core` |
| Read or write NUL-terminated, fixed-width NUL-padded, or `u8`/`u16` length-prefixed raw byte strings | `formatkit_core::text::{nul_terminated, nul_terminated_len, fixed_field, u8_prefixed, u16_le_prefixed, u16_be_prefixed, write_nul_terminated, write_nul_padded, write_nul_or_full}` | `formatkit-core` |
| Decode, encode, validate, or classify Shift-JIS / CP932 / JIS X 0201 text | `formatkit_core::text::{decode_cp932, encode_cp932, decode_shift_jis_jis0208, decode_jis_x_0201, encode_jis_x_0201, classify_shift_jis_byte, shift_jis_to_ku_ten, ku_ten_to_shift_jis}` | `formatkit-core` (default feature `shift-jis`) |
| Apply bounded in-place C-string patches with SHA-256 input verification | `formatkit_core::{apply_bounded_cstr_patches, verify_input_sha256, BoundedCstrPatch}` | `formatkit-core` |
| Scan a binary image for candidate `u32` pointer tables | `formatkit_core::pointer_table::{scan_u32_pointer_tables, PointerTable}` | `formatkit-core` |
| Detect or classify trailing/gap padding bytes (`0x00`, `0xFF`, repeated byte, pattern) | `formatkit_core::padding::{detect_trailing_padding, classify_padding, classify_padding_source, PaddingKind}` | `formatkit-core` |
| Audit byte extents for gaps, overlaps, and exact coverage | `formatkit_core::{Extent, ExtentAudit, ExtentStatus, audit_extent}` | `formatkit-core` |

### 2. Checksums & Integrity

| I need to… | Use… | Crate / Feature |
| --- | --- | --- |
| Compute CRC-16 (ARC, KERMIT, X.25, BUYPASS, XMODEM, CCITT-FALSE, MODBUS, or custom parameters) | `formatkit_core::checksum::{Crc16, Crc16Params}` | `formatkit-core` |
| Compute CRC-32 (ISO-HDLC / IEEE 802.3, MPEG-2, or custom parameters) | `formatkit_core::checksum::{Crc32, Crc32Params, Crc32IsoHdlc, crc32_iso_hdlc, Crc32Mpeg2, crc32_mpeg2}` | `formatkit-core` |
| Compute rolling Adler-32 (zlib / streaming) | `formatkit_core::checksum::{Adler32, adler32}` | `formatkit-core` |
| Compute additive byte or word sums (`u8`/`u16`/`u32`, LE or BE) | `formatkit_core::checksum::{sum_bytes_u8, sum_bytes_u16, sum_bytes_u32, sum_u16_le_words, sum_u16_be_words, sum_u32_le_words, sum_u32_be_words}` | `formatkit-core` |
| Compute XOR byte or word checksums (`u8`/`u16`/`u32`, LE or BE) | `formatkit_core::checksum::{xor_bytes, xor_bytes_u8, xor_u16_le_words, xor_u16_be_words, xor_u32_le_words, xor_u32_be_words}` | `formatkit-core` |
| Compute a configurable add/XOR fold checksum over bytes or words | `formatkit_core::checksum::{FoldChecksum, FoldOp, FoldUnit}` | `formatkit-core` |
| Compute any checksum while treating an embedded checksum field range as zero bytes without copying | `formatkit_core::checksum::compute_with_zeroed_range` / `Crc16Params::compute_with_zeroed_range` | `formatkit-core` |

### 3. Compression, RLE, Huffman & Delta Codecs

| I need to… | Use… | Crate / Feature |
| --- | --- | --- |
| Decompress or compress classic 4 KiB ring-buffer Okumura LZSS | `formatkit_codec::okumura::{okumura_lzss, okumura_lzss_with_limit, okumura_lzss_consumed_with_limit, okumura_lzss_consumed_with_boundary, okumura_lzss_to_end_with_limit, okumura_lzss_compress}` | `formatkit-codec` (`formatkit` feature `codec`) |
| Execute a parameterized flag-byte / flag-word LZSS stream with a custom match-token parser | `formatkit_codec::flag_lzss::{decode_flag_lzss, FlagLzssConfig, FlagWidth, FlagBitOrder, FlagPolarity, OvershootPolicy, FlagLzssMatch}` | `formatkit-codec` |
| Scan or decode a counted LSB-flag LZ stream with `WorkBudget` accounting | `formatkit_codec::counted_lsb::{scan_with_work, decode_exact_with_work, decode_with_work}` | `formatkit-codec` |
| Build a custom LZ decoder/encoder with overlapping back-reference copies or ring-buffer history | `formatkit_codec::sliding_window::{append_match, find_longest_match, RingBuffer}` | `formatkit-codec` |
| Decompress or compress raw Deflate, zlib, or gzip streams with explicit output/work limits | `formatkit_codec::inflate::{inflate, inflate_with_limit, inflate_one_with_limit, inflate_exact_with_work_budget, zlib_inflate, zlib_inflate_with_limit, zlib_inflate_one_with_limit, zlib_inflate_exact_with_work_budget, zlib_store}`, `formatkit_codec::deflate::{deflate_compress, zlib_compress}`, `formatkit_codec::gzip::{gzip_with_limit, gzip_one_with_limit, gzip_compress}` | `formatkit-codec` |
| Decompress bounded LZMA-Alone streams | `formatkit_codec::lzma::{lzma_alone_declared_size, lzma_alone_decompress_with_limit}` | `formatkit-codec` |
| Identify or decompress RNC Method 2 streams (with optional key or `WorkBudget`) | `formatkit_codec::rnc::{rnc2_identifies, rnc2_decompress, rnc2_decompress_with_limit, rnc2_decompress_with_work_budget, rnc2_decompress_with_key_and_limit, rnc_crc16}` | `formatkit-codec` |
| Build canonical Huffman code lengths and decode/encode tables (MSB- or LSB-first) | `formatkit_codec::huffman::{CanonicalHuffmanTable, CanonicalCode, HuffmanBitOrder, build_code_lengths}` | `formatkit-codec` |
| Decode or encode high-bit run-length encoding (PackBits-style literal/run control bytes) | `formatkit_codec::rle::{decode_high_bit_rle, encode_high_bit_rle, HighBitRleConfig}` | `formatkit-codec` |
| Apply or invert byte or 16-bit LE/BE delta coding in place | `formatkit_codec::delta::{delta_decode_u8_into, delta_encode_u8_into, delta_decode_u16_le_into, delta_encode_u16_le_into, delta_decode_u16_be_into, delta_encode_u16_be_into}` | `formatkit-codec` |
| Read or write a tag byte + 24-bit LE size stream header (with zero-size 32-bit extended form) | `formatkit_codec::tagged_header::{read_tagged_header, read_tagged_header_extended, write_tagged_header, write_tagged_header_extended, TaggedHeader, TAG_*}` | `formatkit-codec` |
| Decode or encode tagged-header LZ77 with 12-bit distances: compact `0x10` (length `3..=18`, optional minimum distance) or extended-length `0x11` (length `3..=65808`) | `formatkit_codec::tagged_lz77::{decode_tagged_lz77, encode_tagged_lz77, encode_tagged_lz77_with_min_distance, decode_tagged_lz77_extended, encode_tagged_lz77_extended}` | `formatkit-codec` |
| Decode or encode tagged-header Huffman with a packed 6-bit-offset tree and 4-bit (`0x24`) or 8-bit (`0x28`) symbols | `formatkit_codec::tagged_huffman::{decode_tagged_huffman, encode_tagged_huffman, TaggedHuffmanWidth}` | `formatkit-codec` |
| Decode or encode tagged-header byte RLE (`0x30`) or 8/16-bit delta-filtered (`0x81`/`0x82`) streams | `formatkit_codec::rle::{decode_tagged_rle, encode_tagged_rle}`, `formatkit_codec::delta::{decode_tagged_delta, encode_tagged_delta, TaggedDeltaWidth}` | `formatkit-codec` |
| Widen packed 1/2/4/8-bit units to 1/2/4/8/16/32-bit units with a conditional additive offset | `formatkit_codec::bit_unpack::{bit_unpack, BitUnpackConfig}` | `formatkit-codec` |

### 4. Pixels, Palettes, Tiles, Swizzling & Image/Audio Codecs

| I need to… | Use… | Crate / Feature |
| --- | --- | --- |
| Pack or unpack linear 1bpp, 2bpp, or 4bpp indexed pixels without allocation | `formatkit_pixel::{unpack_1bpp_into, pack_1bpp_into, unpack_2bpp_into, pack_2bpp_into, unpack_4bpp_into, pack_4bpp_into, NibbleOrder, BitOrder, IndexPolicy}` | `formatkit-pixel` (`formatkit` feature `pixel`) |
| Expand packed 4bpp/8bpp CLUT indices into `Vec<u16>` or map indices through an owner palette callback | `formatkit_pixel::{expand_indices, IndexBits, apply_palette}` | `formatkit-pixel` |
| Pack or unpack byte-aligned 2D bitmap font glyphs (1bpp, 2bpp, 4bpp) | `formatkit_pixel::glyph::{unpack_glyph_1bpp, pack_glyph_1bpp, unpack_glyph_2bpp, pack_glyph_2bpp, unpack_glyph_4bpp, pack_glyph_4bpp}` (or `formatkit_core::MsbFirst1bppRows` for row-by-row 1bpp) | `formatkit-pixel` / `formatkit-core` |
| Pack or unpack interleaved-row planar 8×8 bitplane tiles (1, 2, or 4 planes) | `formatkit_pixel::planar::{unpack_planar_tile_8x8_into, pack_planar_tile_8x8_into}` | `formatkit-pixel` |
| Swizzle or unswizzle Morton (Z-order) 2D textures | `formatkit_pixel::morton::{morton_index, swizzle_morton, unswizzle_morton, MortonAxisOrder}` | `formatkit-pixel` |
| Convert 12/15/16-bit packed colors (`BGR555`, `RGB565`, `RGBA5650`, `RGBA5551`, `RGBA4444`, `RGB444`, `BGR444`) to/from RGBA8888 | `formatkit_pixel::{bgr555_to_rgba, bgr555_le_words_to_rgba, rgb8_to_bgr555, rgba8_to_bgr555, rgba_to_bgr555_le_words, Alpha555Policy, rgb565_to_rgba, rgba8_to_rgb565, rgba5650_to_rgba, rgba8_to_rgba5650, rgba5551_to_rgba, rgba8_to_rgba5551, rgba4444_to_rgba, rgba8_to_rgba4444, rgb444_to_rgba, rgb8_to_rgb444, bgr444_to_rgba, rgb8_to_bgr444}` | `formatkit-pixel` |
| Decode bitmask-described pixel formats or S3TC / DXT1 / DXT3 / DXT5 block-compressed textures | `formatkit_pixel::dxt::{decode_dxt, DxtFormat, decode_masked, ChannelMasks, is_contiguous}` | `formatkit-pixel` |
| Quantize RGBA images to a palette, find nearest palette color, or generate grayscale palettes | `formatkit_pixel::palette::{quantize_rgba, nearest_palette_index, grayscale_palette, PaletteDistanceMetric}` | `formatkit-pixel` |
| Blit, crop, or compose sprites/tiles into a grid atlas | `formatkit_pixel::atlas::{blit_rgba, crop_rgba, compose_grid_atlas, GridAtlasLayout}` | `formatkit-pixel` |
| Compute floor-halved mipmap dimensions | `formatkit_pixel::mip_extent` | `formatkit-pixel` |
| Decode or encode PNG, PCX, TGA, or DDS images | `formatkit_codec::png`, `formatkit_codec::pcx`, `formatkit_codec::tga`, `formatkit_codec::dds` (default feature `dds`) | `formatkit-codec` |
| Represent decoded RGBA images or 16-bit PCM audio / emit WAV headers | `formatkit_core::{Image, Pcm, wav_header_pcm}` | `formatkit-core` |

### 5. Resident Layouts, Chunks, Tables, Charmaps & Binary Patches

| I need to… | Use… | Crate / Feature |
| --- | --- | --- |
| Declare typed fixed-offset fields, scaled fields, or fixed arrays over a resident byte slice | `formatkit_layout::field::{U8Field, I8Field, U16Field, I16Field, U32Field, I32Field, U64Field, I64Field, F32Field, F64Field, ScaledU32Field, BytesField, U16ArrayField, I16ArrayField, U32ArrayField, I32ArrayField, F32ArrayField}` | `formatkit-layout` |
| Slice fixed-stride records safely with overflow checks | `formatkit_layout::records::{FixedRecords, RecordOverflow}` | `formatkit-layout` |
| Validate ordered, contiguous, non-overlapping, or exact-tiling extent runs | `formatkit_layout::ranges::{audit_exact_tiling, audit_ordered_contiguous_run, audit_ordered_non_overlapping, child_run, strict_successor_ranges, nondecreasing_successor_ranges}` | `formatkit-layout` |
| Patch bytes or perform same-size splices on resident buffers | `formatkit_layout::edit::{patch_bytes, patched_bytes, same_size_splice}` | `formatkit-layout` |
| Parse generic payload-length or header-inclusive framed chunks | `formatkit_layout::chunks::{read_payload_chunk, read_header_inclusive_chunk}` | `formatkit-layout` |
| Parse IFF (`FORM`) or RIFF (`RIFF`) chunk containers | `formatkit_layout::iff::{parse_iff_form, parse_riff_form, IffForm, IffChunk}` | `formatkit-layout` |
| Parse `.tbl` character-mapping tables and decode/encode custom text encodings | `formatkit_layout::text::{Charmap, CharmapLimits, CharmapEntry, CharmapControl, CharmapToken, CharmapDecoded, FixedByteStringField, parse_hex_bytes, format_hex_bytes}` | `formatkit-layout` |
| Decode directory / pointer / offset / size tables into validated ranges or namespace entries | `formatkit_layout::tables::{AlignedSizeChain, CountedBoundaryTable, CountedU16BoundaryTable, FirstWordOffsetTable, FixedStrideOffsetTable, OffsetLengthRows, PositiveSizeList, TerminalOffsetTable}` (see Table 5 below) | `formatkit-layout` |
| Parse, create, serialize, or apply IPS, BPS, or UPS binary patches, or encode/decode BPS/UPS variable-length integers (varints) | `formatkit_patch::ips`, `formatkit_patch::bps`, `formatkit_patch::ups`, `formatkit_patch::vli` | `formatkit-patch` (`formatkit` feature `patch`) |

### 6. Bounded Sources, Budgets, Archives, Catalog & Corpus Testing

| I need to… | Use… | Crate / Feature |
| --- | --- | --- |
| Enforce cumulative I/O, materialization, output, node, member, depth, active resident memory, and cooperative cancellation limits | `formatkit_core::{WorkBudget, WorkLimits, WorkResource, CancellationToken, ResidentReservation, RetainedResidentPermit, DepthScope, WorkScope}` | `formatkit-core` |
| Perform lazy, bounded, random-access reads over slices, memory, files, archive members, composites, or transformed streams | `formatkit_core::{RangeSource, SliceRangeSource, MemoryRangeSource, FileRangeSource, ArchiveMemberRangeSource, RevalidatedExactSliceSource, CompositeRangeSource, StridedRangeSource, TransformedRangeSource, ObjectPackRangeSource, SourceMetadataReader, copy_source_range}` | `formatkit-core` |
| Expose an archive or container as a lazy indexed namespace | `formatkit_core::{IndexedNamespace, StoredRangeNamespace, StoredRangeNamespaceLimits, NamespaceEntry, MountedMember, MemberLayout, MemberTransform, TransformRecipe, materialize_transformed_member}` | `formatkit-core` |
| Mount paired index+data archives, select members by index/name, extract to `Write` sinks, or recursively walk nested containers | `formatkit_archive::{extract, ExtractionMode, select_index, select_name, walk, WalkOptions, WalkEvent, WalkControl, Resolver, paired_stored_mount::PairedStoredMount}` | `formatkit-archive` (`formatkit` feature `archive`) |
| Define open format identities, detection descriptors, leaf/namespace/writer contracts, and compose them into a runtime catalog | `formatkit_catalog::{FormatId, Category, FormatDescriptor, Probe, FormatCatalog, LeafOperationProvider, NamespaceProvider, RoleBoundNamespaceProvider, WriterContract}` & `formatkit_runtime::{FormatModule, ModuleState, ModuleOperation, ModuleCatalog, ResidentWriterProvider}` | `formatkit-catalog` + `formatkit-runtime` |
| Discover external corpus samples and run JSON-spec golden digest / codec-oracle / sealed-package tests | `formatkit_corpus::{dir, subdir, file, samples, samples_all, first}` & `formatkit_corpus_test::{Digest, Registry, run_dir, run_all, run_manifest, compress_oracle, sealed_package}` | `formatkit-corpus` + `formatkit-corpus-test` (`formatkit` feature `corpus`) |

---

## When to use X vs Y

### 1. LZ & Compression Family

| Mechanism | History / Window Model | Control Stream | When to use | Avoid when |
| --- | --- | --- | --- | --- |
| `formatkit_codec::okumura` | Fixed 4 KiB ring buffer pre-filled with configurable `fill: u8` (`0x20` default, `0x00` supported; `RingBuffer` at `pos = 4078`), 12-bit ring position + 4-bit length (`3..=18`) | 8-bit LSB-first flag byte (`1` = literal, `0` = 2-byte match) | Standard Okumura LZSS streams (decode, consumed-extent scanning, or compression, with `0x20` or `0x00` ring fill) | Format uses linear distance-back history, different flag polarity/width, or custom match packing |
| `formatkit_codec::flag_lzss` | Linear `history \|\| output` with overlapping copies via `sliding_window::append_match` | Configurable flag word (`U8`, `U16Le`, `U16Be`, `U32Le`, `U32Be`), LSB/MSB order, `LiteralIsOne`/`LiteralIsZero`, `Reject`/`ClampToDecodedSize` overshoot | Any flag-word LZSS variant whose match token is parsed by a caller callback returning `FlagLzssMatch { distance, length }` | Format uses bit-packed variable-length tokens without fixed-width flag words, or needs a pre-filled ring buffer |
| `formatkit_codec::counted_lsb` | Explicit caller-supplied linear history + output; zero-count means empty | Counted LSB-first command stream with `WorkBudget` accounting and allocation-free `scan_with_work` | Formats using the counted-LSB command grammar that need `WorkBudget` integration or pre-scan validation without allocating output | Format has different command encoding, implicit history fill, or needs a format-specific `u16` zero-means-65536 wrapper (wrap at the owner layer) |
| `formatkit_codec::tagged_lz77` | Linear output history (no preset), 12-bit one-based distance (`1..=4096`); final match clipped to the declared size | 8-bit MSB-first flag byte (`0` = literal, `1` = match) after a tagged 4/8-byte header | Tagged-header LZ77 streams with 2-byte (`0x10`) or 2/3/4-byte extended-length (`0x11`) match tokens, including encoders that must avoid distance `1` | Header or token layout differs (use `flag_lzss` with a custom match parser) |
| `formatkit_codec::sliding_window::{append_match, find_longest_match, RingBuffer}` | Either linear (`append_match`, `find_longest_match`) or explicit ring buffer (`RingBuffer`) | None (primitive building blocks; caller owns framing and control loop) | Implementing a custom LZ grammar (e.g., variable-width bit codes, opcode-based LZ, RLE/LZ hybrids) while reusing checked overlapping-copy and match-finding logic | One of `okumura`, `flag_lzss`, or `counted_lsb` already matches your control loop |

### 2. Byte & Structure Reading

| Mechanism | Input Type | State & Allocation | When to use | Avoid when |
| --- | --- | --- | --- | --- |
| `formatkit_core::Reader` | Resident `&[u8]` | Cursor offset (`usize`), zero allocation | Sequential parsing of headers, variable-length streams, or records where each field immediately follows the previous one | Random-access lookups by fixed offset, or reading from disc-scale files |
| `formatkit_core::bytes::*_at` (`u32_at`, `bytes_at`, …) | Resident `&[u8]` | Stateless, zero allocation | One-off or random-access checked reads/writes at computed offsets inside an already-resident slice | Parsing many sequential fields (verbose offset math) or defining reusable typed record layouts |
| `formatkit_layout::field::*Field` (`U32Field`, `ScaledU32Field`, …) | Resident `&[u8]` | `const`-constructible static field descriptors, zero allocation | Declarative fixed-offset header/record definitions shared across readers, validators, and in-place editors | Variable-length sequential streams where offsets depend on earlier decoded values |
| `formatkit_core::SourceMetadataReader` / `RangeSource` | Lazy `dyn RangeSource` (file, slice, archive member) | Bounded I/O via `WorkBudget`, optional metadata windowing | Disc-scale files, archives, and containers where you must read headers/tables without loading the entire carrier into RAM | Small already-resident slices where direct `&[u8]` access is simpler and faster |

### 3. Bitstreams

| Mechanism | Operates On | Bit / Byte Interleaving | When to use | Avoid when |
| --- | --- | --- | --- | --- |
| `formatkit_core::{Bit, BitRange}` | Already-decoded integer words (`u8`..`u64`) | N/A (in-word bit manipulation) | Extracting or updating flags and packed bitfields inside header/entry words after endian decoding | Streaming variable-width codes across multiple bytes |
| `formatkit_core::{LsbBitCursor, MsbBitCursor, LsbBitWriter, MsbBitWriter}` | Contiguous `&[u8]` / `Vec<u8>` | Pure bitstream; all reads/writes come from the bit accumulator | Huffman codes, Deflate/RNC-style bitstreams, packed bit arrays, or variable-width bitfields crossing byte boundaries | Streams where raw operand bytes are interleaved between control bytes |
| `formatkit_core::{InterleavedBitReader, InterleavedBitWriter}` (`Msb*`, `Lsb*`) | `&[u8]` / `Vec<u8>` | Control-bit byte is fetched on demand from the *same* byte cursor as raw operand bytes | Interleaved flag-byte / raw-byte compression streams where operand bytes are consumed while earlier control bits remain buffered | Pure bitstreams (use `LsbBitCursor`/`MsbBitCursor`) or fixed-width flag-word LZSS (use `flag_lzss`) |

### 4. Pixel Layouts

| Mechanism | Topology | Bit Depths / Parameters | When to use | Avoid when |
| --- | --- | --- | --- | --- |
| `formatkit_pixel::{unpack_1bpp_into, unpack_2bpp_into, unpack_4bpp_into}` (and `pack_*_into`) | Flat 1D linear pixel stream | 1bpp, 2bpp (`BitOrder`), 4bpp (`NibbleOrder`), explicit `IndexPolicy` | Linearly packed pixel buffers or scanlines with no per-row byte padding; allocation-free into caller slice | 2D glyphs with per-row byte alignment, bitplane tiles, or Z-order swizzled textures |
| `formatkit_pixel::glyph::{unpack_glyph_*bpp, pack_glyph_*bpp}` | 2D `(width, height)` bitmap with byte-aligned rows | 1bpp, 2bpp, 4bpp with `BitOrder` / `NibbleOrder` | Bitmap fonts and 2D glyphs where each row is padded to a whole byte (`width.div_ceil(pixels_per_byte)`) | Continuous 1D packed streams without row padding, or planar tiles |
| `formatkit_pixel::planar::{unpack_planar_tile_8x8_into, pack_planar_tile_8x8_into}` | Fixed 8×8 tile, interleaved-row bitplanes | 1, 2, or 4 bitplanes (8, 16, or 32 bytes per tile) | Classic 8×8 planar tile sheets where each row stores bitplane bytes consecutively | Non-8×8 tiles, chunky/packed pixels, or non-interleaved full-plane layouts |
| `formatkit_pixel::morton::{morton_index, swizzle_morton, unswizzle_morton}` | 2D Morton (Z-order) tiled texture | `MortonAxisOrder` (`XFirst` / `YFirst`), arbitrary element byte size; shorter dimension must be power of two | GPU/hardware textures stored in Z-order / Morton curve order (square or rectangular power-of-two tiles) | Linear row-major textures, block-compressed DXT blocks without Morton tiling, or custom non-Morton swizzles |

### 5. `formatkit-layout::tables` (All 8 Table Types Side-by-Side)

| Table Type | On-Disk Layout | Scaling / Alignment | Empty Ranges Allowed? | Closes at EOF? | Output Type | Use when… |
| --- | --- | --- | --- | --- | --- | --- |
| `AlignedSizeChain` | Caller-decoded sequence of member sizes + `first_offset` | Rounds each next start up to power-of-two `alignment` | Format-controlled | Format-controlled | `DerivedAlignedSizes` (`AlignedSizeExtent`) | Members are stored back-to-back with alignment padding and only sizes are recorded |
| `PositiveSizeList` | Sequence of positive `u32` sizes | Optional `SizeAlignment` divisibility check | No (all sizes > 0) | Yes (exact EOF closure) | `ValidatedPositiveSizes` (`PositiveSizeExtent`) | Consecutive positive-sized payloads packed tightly to exact carrier EOF |
| `CountedBoundaryTable` | `u32` count + `(count + 1)` LE `u32` absolute byte boundaries | Configurable power-of-two alignment | No (strictly increasing) | Yes (exact EOF closure) | `ValidatedCountedBoundaries` | Directory starts with `u32` count followed by `count + 1` aligned, strictly increasing byte offsets ending at EOF |
| `CountedU16BoundaryTable` | `u16` count + `(count + 1)` `u16` cumulative offsets | Configurable `unit_scale` (e.g., `1` byte or `2048` sector) | Yes (nondecreasing; equal adjacent = 0-byte slot) | Bounded by carrier size | `ValidatedCountedU16Boundaries` | Compact 16-bit cumulative offset tables (byte- or sector-scaled) that allow empty slots |
| `FirstWordOffsetTable` | First `u32` is both table byte length and first data offset; remaining `u32` words are strictly increasing offsets | Configurable alignment/bounds | No (strictly increasing) | Derived from next offset / carrier EOF | `Vec<SourceRange>` | Self-delimiting offset table where word 0 tells you how many offset words exist (`word0 / 4`) |
| `TerminalOffsetTable` | First `u32` is table byte length & first data offset; final `u32` equals carrier EOF | Byte offsets | Yes (nondecreasing; equal adjacent = empty range) | Yes (final word == carrier EOF) | `ValidatedTerminalOffsets` | Self-delimiting offset table with an explicit EOF sentinel word and optional empty entries |
| `FixedStrideOffsetTable` | Fixed-stride records containing a LE `u32` offset (and optional explicit size via `TableSizeMode`) | Configurable `unit_scale` | Depends on `TableSizeMode` | Monotone bounded by carrier | `Vec<NamespaceEntry>` | Directory entries have extra per-entry metadata around a `u32` offset and map straight to `NamespaceEntry` rows |
| `OffsetLengthRows<const STRIDE: usize>` | Fixed-stride rows with arbitrary unsigned `(offset, length)` fields at configured column offsets | Raw unsigned values (no forced alignment/order) | Yes | No (no ordering, overlap, or closure enforced) | Iterator of `OffsetLengthRow` | General-purpose directory where entries may be unsorted, sparse, overlapping, or validated by custom owner rules |
