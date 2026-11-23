# formatkit-patch

Bounded, platform-neutral binary patch parsing, creation, serialization, and
policy-controlled application.

## Modules

- `ips` — International Patching System (IPS) record parsing, patch creation,
  and policy-controlled application (bounds, truncation, and target-size checks).
- `bps` — Beat Patching System (`BPS1`) parsing, encoding, CRC-32 verification,
  and bounded application.
- `ups` — Universal Patching System (`UPS1`) XOR-delta parsing, encoding,
  CRC-32 verification, and bounded application.
- `vli` — Bijective base-128 variable-length integer (VLI) encoder and decoder
  shared by BPS and UPS.

## Scope

All patch operations validate offsets and output size limits before allocating.
No platform headers, ROM checksums, or external file-layout policies are assumed.

## License

MIT OR Apache-2.0.
