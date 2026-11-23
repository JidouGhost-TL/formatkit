# formatkit-runtime

Explicit composition kernel, resident writer bridges, and operation dispatch for
owner-defined format modules.

## Key concepts

- **`FormatModule`**: one static ownership row per `FormatId`, bundling its
  descriptor, embedded support, writer contract, namespace semantics, and named
  `ModuleOperation` entries.
- **`ModuleState::Strict` vs `ModuleState::Legacy`**:
  - `Strict` rows are owner-authorized modules whose named operations carry typed
    callbacks, canonical `InputSchema` validation, and syntax-checked proof
    selectors, and participate in strict runtime lookup.
  - `Legacy` rows preserve compatibility projections during migration without
    entering strict lookup.
- **Resident writers**: `ResidentWriterProvider` and `ResidentWriteOutput` tie
  writer allocations to the caller's `WorkBudget` via `ResidentReservation` and
  enforce exact output-byte accounting.
- **Namespace adapters**: `invoke_bound_namespace_adapter`,
  `invoke_bound_runner_namespace_adapter`, and work-native role-bound adapters
  revalidate input schemas before invoking owner I/O.

## License

MIT OR Apache-2.0.
