# formatkit

Umbrella re-export crate for the Formatkit platform-neutral binary data toolkit.

With `default = []`, `formatkit` re-exports the four core foundation crates:

- `formatkit::core` (`formatkit-core`) — checked bytes/bits, sources, work budgets, checksums, and shared values
- `formatkit::layout` (`formatkit-layout`) — configured fields, records, tables, chunks, IFF/RIFF, charmaps, and edits
- `formatkit::catalog` (`formatkit-catalog`) — open format identities, detection catalogs, and operation contracts
- `formatkit::runtime` (`formatkit-runtime`) — explicit owner-module composition and dispatch

## Optional features

Enable additional crates as needed:

- `archive` — `formatkit::archive` (`formatkit-archive`)
- `pixel` — `formatkit::pixel` (`formatkit-pixel`)
- `codec` — `formatkit::codec` (`formatkit-codec`)
- `patch` — `formatkit::patch` (`formatkit-patch`)
- `gltf` — `formatkit::gltf` (`formatkit-gltf`)
- `corpus` — `formatkit::corpus` (`formatkit-corpus`) and `formatkit::corpus_test` (`formatkit-corpus-test`)

Individual crates can also be depended on directly without the umbrella.

## License

MIT OR Apache-2.0.
