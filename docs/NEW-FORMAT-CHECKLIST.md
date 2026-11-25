# New Format Checklist

Pre-implementation and code-review checklist for adding a new format to any kit built on FormatKit.

---

## 1. Reuse Before Writing

- [ ] Checked [`CAPABILITIES.md`](../CAPABILITIES.md) and [`docs/capabilities.json`](capabilities.json) for existing primitives before writing local readers, bitstreams, checksums, LZ/RLE/Huffman/delta codecs, pixel unpackers, swizzlers, charmaps, or table decoders.
- [ ] Evaluated `formatkit_layout`'s declarative specs (`FixedRecordTableSpec`, `CountedOffsetArraySpec`, `ChunkStreamSpec`, `MarkerScanStreamSpec`) and symmetric `PackPolicy` writers (`pack_fixed_record_table`, `pack_fixed_record_table_with_post_table`, `pack_counted_offset_array`, `pack_chunk_stream`, `pack_marker_scan_stream`) before writing custom table/chunk parsers or packers.
- [ ] Confirmed that any reused mechanism matches the format's exact semantics (byte order, checksum coverage, LZ history/overshoot/consumed extent, pixel bit/nibble order) rather than relying on a similar name or an accidental round-trip.
- [ ] Kept format identity, framing, validation error order, bounds, and writer policy in the format owner crate rather than branching inside generic services.

## 2. Checked Math & Input Safety

- [ ] No `unsafe` code (`#![forbid(unsafe_code)]`).
- [ ] All offset, length, stride, count, and dimension arithmetic uses `checked_add`, `checked_mul`, `checked_sub`, or `formatkit_core::checked_align_up` — zero unchecked casts or wrapping arithmetic on untrusted header fields.
- [ ] Explicit `MAX_*` ceilings (entries, dimensions, decompressed size, nesting depth, string length) are validated **before** allocating any buffer or indexing into slices.
- [ ] Malformed, truncated, and adversarial inputs return structured `formatkit_core::Error` variants (`Truncated`, `InvalidField`, `Malformed`, `ResourceLimit`, `Unsupported`) and never panic.
- [ ] Exact consumed byte extents are tracked and verified where streams are embedded in larger containers.

## 3. Resource Budgets & Cancellation

- [ ] Public parse, mount, decode, extract, and write entry points accept `&mut WorkBudget` (never legacy `ReadBudget`).
- [ ] `budget.check_cancelled()?` is polled at loop boundaries and before expensive decode/transform steps.
- [ ] Retained allocations reserve active resident memory via `budget.reserve_resident(...)` before allocating, and release on drop.
- [ ] Cumulative `WorkResource` charges (`LogicalReadBytes`, `MaterializedBytes`, `OutputBytes`, `Nodes`, `Members`) and `DepthScope` guards are accurately maintained.

## 4. Lazy Mounting for Archives & Containers

- [ ] Container/archive parsers accept `&dyn RangeSource` / `Arc<dyn RangeSource>` and read only header/directory metadata via `SourceMetadataReader` during mount — never eagerly reading the whole carrier into memory.
- [ ] Uncompressed members expose zero-copy subranges via `StoredRangeNamespace` / `ArchiveMemberRangeSource` (or `PairedStoredMount` for paired index+data formats).
- [ ] Compressed/encrypted members use `materialize_transformed_member` with an explicit `TransformRecipe` and `WorkBudget`.
- [ ] Member names, duplicate-name ambiguity, and collision policies are explicit and preserved.

## 5. Catalog & Runtime Registration

- [ ] Format has a unique `FormatId`, `FormatDescriptor` with bounded probes (`Probe::Magic`, `Probe::Structural`, or `Probe::ContextualStructural`), explicit `precedence`, and accurate `FormatCapabilities`.
- [ ] Registered as `ModuleState::Strict` in `FormatModule` (no `ModuleState::Legacy` or `CompatibilityRecognitionRule` in new formats).
- [ ] `InputSchema`, `OperationCapabilities`, `LeafOperationProvider` / `NamespaceProvider` / `ResidentWriterProvider`, and `WriterContract` pass `ModuleCatalog::new` validation.
- [ ] Read-only formats do not claim `edit`, `write`, or `round_trip` capabilities; writers declare and pass their `WriterContract` proof oracles.

## 6. Testing & Corpus Hygiene

- [ ] Unit tests use neutral synthetic fixtures covering valid inputs, boundary cases, truncation, overflow, bad magic/checksums, budget exhaustion, and cancellation.
- [ ] Real-world samples stay strictly outside Git and are verified through `formatkit-corpus` + `formatkit-corpus-test` (`Digest` + external `spec.json`, `compress_oracle`, or `SealedPackage`) under `tools/run-corpus-safe.sh` with `FORMATKIT_CORPUS_REQUIRED=1`.
- [ ] Zero game titles, platform/console brand names, product codes, donor paths, or workstation paths appear in source, tests, docs, or commit messages.

## 7. Criteria for Upstreaming a Mechanism to FormatKit

Consider proposing a mechanism for upstreaming into FormatKit **only** when all of the following hold:

- [ ] **Platform-neutral contract:** The mechanism is a pure binary, codec, pixel, layout, or container primitive with zero platform, console, engine, or format-specific policy.
- [ ] **Independent demand:** At least two concrete, independent format owners need the exact same contract (not just a similar-sounding name).
- [ ] **Clear boundary:** Framing, identity, diagnostics, and policy remain cleanly with the caller/owner.
- [ ] **Bounded & tested:** No `unsafe`, checked arithmetic throughout, neutral synthetic unit tests + doctests, and `python3 tools/check-public.py` + `python3 tools/check-capabilities.py` pass cleanly.
