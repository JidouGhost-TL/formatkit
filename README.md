# Formatkit

Platform-neutral Rust foundations for reading, writing and inspecting binary data.

Formatkit supplies checked byte and bit operations, resident layouts, bounded
source access, mounted archive services, format catalogs, runtime composition,
pixel mechanics, selected compression codecs and specification-driven corpus testing. Format owners retain
their grammars, validation policies, diagnostics and read/write capabilities.

The libraries use the Rust standard library and require Rust 1.94.1 or newer.
No platform catalog, game assets or implicit corpus location is included.

```rust
use formatkit::core::{Reader, Result};

fn read_tag(bytes: &[u8]) -> Result<u32> {
    Reader::new(bytes).u32_le()
}
```

The umbrella package enables core, layout, catalog and runtime by default.
Archive, pixel, codec and corpus re-exports are selected with the `archive`,
`pixel`, `codec` and `corpus` features. Individual packages can be consumed
without the umbrella.

| Package | Responsibility |
| --- | --- |
| `formatkit-core` | Checked bytes/bits, sources, budgets, errors, images and PCM |
| `formatkit-layout` | Configured fields, records, tables, ranges and resident edits |
| `formatkit-catalog` | Open typed identities, detection and operation contracts |
| `formatkit-runtime` | Explicit owner-module composition and operation dispatch |
| `formatkit-archive` | Mounted browsing, extraction to caller sinks and injected traversal |
| `formatkit-pixel` | Generic packed pixels, palettes, channel masks and S3TC |
| `formatkit-codec` | Bounded generic compression and consumed-stream extents |
| `formatkit-corpus` | Explicit-root discovery without a built-in sample set |
| `formatkit-corpus-test` | JSON specs, golden digests, codec pairs and sealed packages |

There are no platform dependency cycles: layout, pixel and codec depend on
core; catalog depends on core; archive and runtime depend on catalog and core.
Corpus discovery has no dependencies, and the golden-test harness is opt-in.

## Verification

Ordinary tests use synthetic data and temporary files:

```sh
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
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
