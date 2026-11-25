# formatkit-core

Checked binary data primitives, bounded source access, work budgets, and shared
value types for independent format libraries.

## What is included

- **Checked I/O & cursors**: `Reader`, `Writer`, explicit-endian slice helpers
  (`u16_at`, `u32_at`, `uint_le_at`, …), `bounded_cstr`, `extent` / `checked_align_up`,
  bit cursors (`LsbBitCursor`, `MsbBitCursor`), and interleaved bit readers/writers.
- **Sources & accounting**: `RangeSource` implementations (memory, file, slice,
  strided, composite, transformed), `SourceBindings`, `WorkBudget`,
  `ResidentReservation`, `CancellationToken`, and `copy_source_range`.
- **Mounted namespaces**: `IndexedNamespace`, `MountedMember`, `MemberLayout`,
  and `StoredRangeNamespace`.
- **Checksums (`checksum`)**: `Crc16`, `Crc32`, `Crc32IsoHdlc`, `Crc32Mpeg2`,
  `Adler32`, wrapping sums/XORs, and configurable `FoldChecksum`.
- **Shared values & utilities**: `Image`, `audio` (`Pcm`, `parse_wav`, `fact` and
  `smpl` loop chunks), `bcd`, `math` (`binary16_to_f32`, Q12 fixed-point transforms,
  matrices, and quaternions), `topology` (triangle strips/fans), `pointer_table`,
  `padding`, and `text` (with optional Shift-JIS tables via the default `shift-jis`
  feature).

## Ownership boundary

`formatkit-core` provides checked arithmetic and bounded access mechanisms only.
Format grammars, identity registries, and validation policies belong to format
owners.

## License

MIT OR Apache-2.0.
