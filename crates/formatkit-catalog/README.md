# formatkit-catalog

Platform-neutral format identities, descriptors, detection catalogs, and
executable operation contracts.

## What is included

- **Open identities**: `FormatId`, `Id`, `Category`, and `Method` represent
  format and codec identities without baking a closed registry into the library.
- **Catalog contracts (`catalog`)**: `FormatDescriptor`, `FormatCatalog`,
  `SupportCatalog`, `InputSchema`, `BoundInputs`, `SourceProbeOutcome`,
  `NamespaceMountContract`, `RoleBoundNamespaceContract`, `LeafOperationCatalog`,
  and `WriterContract`.
- **Compatibility projections**: `CompatibilityRecognitionContribution` and
  `CompatibilityRecognitionRule` bridge legacy recognition metadata while format
  owners migrate toward `Strict` rows in `formatkit-runtime`.

## Ownership boundary

`formatkit-catalog` defines the shared contract vocabulary. Concrete format
libraries supply their own descriptors, probe logic, and capability declarations.

## License

MIT OR Apache-2.0.
