# formatkit-corpus-test

Specification-driven corpus test harness for golden digests, codec pairs,
mounted namespaces, and sealed packages.

## Modules & capabilities

- **Golden-digest runner (`run_dir`, `run_all`, `run_root`, `Registry`, `Digest`)**:
  walks subdirectories of `FORMATKIT_CORPUS_DIR` containing `spec.json`, dispatches
  samples to registered `Digest` handlers, and compares output against golden
  expectations.
- `compress_oracle` — codec round-trip oracle over paired compressed/decompressed
  corpus samples.
- `manifest` — manifest-driven corpus evaluation (`run_manifest`).
- `namespace` — mounted namespace digest and traversal verification helpers.
- `sealed_package` — SHA-256 manifest verification and bounded admission tests.
- `helpers` — common hashing, archive digest, and round-trip assertion utilities.

## Environment controls

- `FORMATKIT_CORPUS_REQUIRED=1` fails on missing or empty selections instead of skipping.
- `FORMATKIT_CORPUS_WRITE=1` is an explicit enrollment/regeneration mode and must
  never be enabled against a frozen corpus.

## License

MIT OR Apache-2.0.
