# Formatkit

Platform-neutral Rust foundations for reading, writing and inspecting binary data.

Formatkit supplies checked byte and bit operations, resident layouts, bounded
source access, mounted archive services, format catalogs, runtime composition,
pixel mechanics, selected compression codecs, binary patches and specification-driven corpus testing. Format owners retain
their grammars, validation policies, diagnostics and read/write capabilities.

The libraries require Rust 1.94.1 or newer. By default they use the Rust standard
library; every crate except the corpus pair also builds `no_std` + `alloc` (see
[`no_std`](#no_std)).
No platform catalog, game assets or implicit corpus location is included.

```rust
use formatkit::core::{Reader, Result};

fn read_tag(bytes: &[u8]) -> Result<u32> {
    Reader::new(bytes).u32_le()
}
```

The umbrella package enables `core`, `layout`, `catalog` and `runtime` with `default = ["std"]`
(no optional crates enabled by default). Archive, pixel, codec, patch, gltf and corpus re-exports
are opt-in via the `archive`, `pixel`, `codec`, `patch`, `gltf` and `corpus` features. Individual
packages can also be consumed directly without the umbrella.

## Quick Navigation

- [CAPABILITIES.md](CAPABILITIES.md) — Complete crate-by-crate mechanism inventory and decision guide
- [docs/NEW-KIT-ONBOARDING.md](docs/NEW-KIT-ONBOARDING.md) — Guide for building a new format kit on Formatkit
- [docs/NEW-FORMAT-CHECKLIST.md](docs/NEW-FORMAT-CHECKLIST.md) — Checklist for adding a new format owner
- [docs/capabilities.json](docs/capabilities.json) — Machine-readable capability index

## Packages

| Package | Responsibility |
| --- | --- |
| `formatkit` | Umbrella re-export crate (`default = ["std"]`; optional `archive`, `pixel`, `codec`, `patch`, `gltf`, `corpus` features) |
| `formatkit-core` | Checked bytes/bits, sources, budgets, errors, images, PCM/WAV reader & writer (with `fact` and `smpl` loops), `checksum`, `bcd`, `math`, `topology`, `pointer_table`, `padding`, and optional Shift-JIS text |
| `formatkit-layout` | Configured fields, records, declarative `spec` (`IntFieldSpec`, `OffsetBase`, `PackPolicy`), `tables`, `chunks`, `marker_scan`, `iff`, `charmap`, ranges, resident edits, symmetric `pack_*` writers, and `offset_graph` exact rewrites |
| `formatkit-catalog` | Open typed identities, detection catalogs and executable operation contracts |
| `formatkit-runtime` | Explicit owner-module composition (`Strict`/`Legacy`), resident writers and operation dispatch |
| `formatkit-archive` | Mounted browsing, extraction to caller sinks, injected traversal and `paired_stored_mount` |
| `formatkit-pixel` | Generic packed pixels, `palette`, `planar`, `glyph`, `morton`, `atlas`, `tilemap`, channel masks and `dxt` (S3TC) |
| `formatkit-codec` | Bounded compression (`okumura`, `flag_lzss`, `counted_lsb`, `sliding_window`, deflate/inflate/gzip/lzma/rnc), tagged-header LZ77/Huffman/RLE/delta streams, `bit_unpack`, delta, Huffman, RLE, `ima_adpcm`, `smf` (MIDI reader/writer), `sf2` (SoundFont 2 writer/validator), PNG (stored or compressed), PCX, TGA and optional DDS |
| `formatkit-gltf` | Dependency-free glTF 2.0 (`.glb` and split `.gltf` + `.bin`) builder, strict GLB reader/writer, and 3D transform helpers |
| `formatkit-patch` | `ips`, `bps`, `ups`, and `vli` parsing, serialization, creation and policy-controlled application |
| `formatkit-corpus` | Explicit-root discovery without a built-in sample set |
| `formatkit-corpus-test` | JSON specs, golden digests, codec pairs and sealed packages |

There are no platform dependency cycles: layout, pixel, patch and catalog depend on
core; codec depends on core and optionally on pixel (via its default `dds` feature);
archive and runtime depend on catalog and core. `formatkit-core` also gates its
Shift-JIS/CP932 conversion tables behind a default-enabled `shift-jis` feature.
Corpus discovery has no dependencies, and the golden-test harness is opt-in.

## `no_std`

Every library crate except `formatkit-corpus` and `formatkit-corpus-test` has a
default `std` feature. With `default-features = false` it is `no_std` + `alloc`
and builds for bare-metal targets such as `thumbv7em-none-eabi`. Enabling `std`
adds API and never changes the behaviour of the rest. What needs `std`:

- `formatkit-core`: `FileRangeSource`, `MaterializationPolicy::NewFile` /
  `MaterializedContent::File`, `copy_source_range` / `SourceCopyError`,
  `Pcm::write_wav`, `WorkBudget::read_external_exact_into` and the
  `RangeSourceTestDouble` test helpers. Without `std`, Shift-JIS encoding scans
  the decode tables instead of caching a reverse table (same results), and
  `math::{fixed_turn_sin_cos, normalize_quaternion, Matrix::from_trs}` need the
  `libm` feature.
- `formatkit-catalog`: `DetectionContext::with_path`. `HostPath` is
  `std::path::Path` with `std` and an uninhabited stand-in without it, so path
  fields keep their shape but can only be `None`.
- `formatkit-runtime`: `ResidentWriteOutput::write_to` and `ResidentWriteError`.
- `formatkit-archive`: `extract`.
- `formatkit-codec`: `lzma_alone_decompress_with_limit`, behind the default `lzma`
  feature (it uses `lzma-rs`, which needs `std`).
- `formatkit-gltf`: `transform` needs `std` or the `libm` feature.

Hash maps and sets are `std`'s with `std` and `alloc`'s B-tree collections without
it; no result depends on their iteration order. Forward `std` to the formatkit
crates you depend on:

```toml
[features]
default = ["std"]
std = ["formatkit-core/std", "formatkit-layout/std"]

[dependencies]
formatkit-core = { version = "0.1", default-features = false, features = ["shift-jis"] }
formatkit-layout = { version = "0.1", default-features = false }
```

`tools/check-no-std.sh` builds each crate, with every combination of its other
features, for `thumbv7em-none-eabi`.

## Verification

Ordinary tests use synthetic data and temporary files:

```sh
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
tools/check-no-std.sh
```

Real corpus data remains external. Configure `FORMATKIT_CORPUS_DIR` explicitly
and use `tools/run-corpus-safe.sh` from this repository, run from your consumer
workspace. The Linux runner uses `flock`, `setsid`, `timeout`, `nice` and `ionice`
to serialize and contain the job, setting `FORMATKIT_CORPUS_RUNNER_LOCKED=1`.
Other hosts must provide an equivalent bounded, serialized runner; setting the
marker alone does not provide those operational guarantees.
Set `FORMATKIT_CORPUS_REQUIRED=1` to reject missing or empty selections.
`FORMATKIT_CORPUS_WRITE=1` is an explicit enrollment/regeneration operation;
never enable it against a frozen corpus. Expectations live in JSON specs,
not hard-coded sample counts in Rust tests.

## License

MIT OR Apache-2.0. See LICENSE-MIT, LICENSE-APACHE and NOTICE.
