# formatkit-layout

Configured, reusable descriptions of binary fields, tables, chunks, charmaps,
and checked layout ranges over resident byte slices.

## Modules

- `field` — typed scalar, array, scaled integer, and fixed-byte field descriptors.
- `records` — `FixedRecords` fixed-stride views with checked overflow handling.
- `tables` — offset/length tables, counted boundary tables, terminal offset tables,
  and aligned-size chains.
- `chunks` — header-inclusive and payload-sized tagged chunk spans.
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
