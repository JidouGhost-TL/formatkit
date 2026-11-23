# formatkit-corpus

Dependency-free, explicit-root corpus discovery for opt-in round-trip and
regression tests.

## Behavior

- Reads one environment variable: `FORMATKIT_CORPUS_DIR`.
- Has no fallback paths, no home-directory probes, and no built-in sample set.
- When `FORMATKIT_CORPUS_DIR` is unset or empty, helpers (`dir`, `subdir`, `file`,
  `samples`, `samples_all`, `first`) return `None` or an empty `Vec` so ordinary
  synthetic test runs skip cleanly.
- Fails closed if `FORMATKIT_CORPUS_DIR` is configured without
  `FORMATKIT_CORPUS_RUNNER_LOCKED=1` (set by `tools/run-corpus-safe.sh`),
  preventing unbounded or overlapping real-corpus runs.
- Filters out harness bookkeeping files (`spec.json`, `manifest.json`,
  `versions.json`) and dotfiles via `is_sample_name`.

## License

MIT OR Apache-2.0.
