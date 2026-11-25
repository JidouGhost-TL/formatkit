# formatkit-layout

Configured, reusable descriptions of binary fields, declarative table/chunk/marker
specifications, symmetric writers, charmaps, offset-graph rewrites, and checked
layout ranges over resident byte slices.

## Modules

- `spec` — shared declarative primitives: `IntFieldSpec` (with optional bit-shift/mask),
  `IntWidth`, `OffsetBase` (including `TableStart`, `TableEndPlus`, `SubtractBase`),
  `PackPolicy`, and `LayoutError`.
- `field` — typed scalar, array, scaled integer, and fixed-byte field descriptors.
- `records` — `FixedRecords` fixed-stride views with checked overflow handling.
- `tables` — declarative `FixedRecordTableSpec` (`TableParseOptions`, `NamePoolSpec` +
  `NamePoolFormat`, `RowFieldPredicate`, `SizeMode::Cumulative`, `TableTermination`,
  zero-alloc `iter_with`, metadata-only parsing, and symmetric `pack_fixed_record_table` /
  `pack_fixed_record_table_with_post_table`) and `CountedOffsetArraySpec`
  (`OffsetOrderPolicy`, `skip_sentinel`, bit-masking, and symmetric
  `pack_counted_offset_array`), plus specialized offset/length, counted boundary,
  terminal offset, positive-size, and aligned-size tables.
- `chunks` — single header-inclusive / payload-sized chunk spans and declarative
  `ChunkStreamSpec` (`alignment_base`, `size_unit`, `trailer_size`,
  `terminate_on_zero_size`, zero-alloc `iter_chunk_stream`, and symmetric
  `pack_chunk_stream`).
- `marker_scan` — declarative `MarkerScanStreamSpec` for aligned magic-marker delimited
  streams (`iter_marker_scan_stream`, `parse_marker_scan_stream`, and symmetric
  `pack_marker_scan_stream`).
- `offset_graph` — `ClaimedReader`, `PlacementCanvas`, and `OverlapPolicy` for
  claimed-byte tracking and exact rewrites of offset-linked regions.
- `iff` — generic IFF `FORM` and RIFF container chunk parsing.
- `ranges` — exact tiling, ordered-run audits, and successor-range derivation.
- `text` — fixed byte-string fields, hex helpers, and compiled multi-byte `Charmap`
  byte/UTF-8 tries.
- `edit` — checked in-place patching and same-size splicing on resident bytes.

## Scope

`formatkit-layout` performs no source I/O and is not a runtime schema language.
Raw checked reads remain in `formatkit-core`; semantic validation and diagnostics
remain with format owners.

## License

MIT OR Apache-2.0.
