# Contributing

Bug reports, documentation improvements and code contributions are welcome.
For a bug report, include the version you used, what you expected, and a small
reproducible example. Generated test data is preferable to uploading files you
cannot redistribute.

Formatkit provides reusable binary-data building blocks. Support for a
particular file format usually belongs in a library that uses Formatkit. If
you need a new shared API, open an issue to discuss its use cases first.

Keep changes focused and include tests for new behavior or bug fixes. Before
submitting a change, run:

```sh
cargo fmt --all -- --check
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
tools/check-no-std.sh   # needs `rustup target add thumbv7em-none-eabi`
```

Library code must build without `std`: use `core::`/`alloc::` paths, import
`crate::prelude::*` for `Vec`, `String`, `Box`, `format!` and `vec!`, and put
host I/O behind `#[cfg(feature = "std")]`.

Contributions are licensed under MIT OR Apache-2.0, like the rest of the project.
