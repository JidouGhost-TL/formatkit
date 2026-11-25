# formatkit-gltf

Dependency-free, platform-neutral glTF 2.0 (`.glb` and split `.gltf` + `.bin` +
image) builder, strict GLB container reader/writer, and 3D transform/topology
helpers.

## Modules

- `gltf` — `GltfBuilder` for meshes, primitives, PBR and `KHR_materials_unlit`
  materials, embedded PNG or external images, samplers, skins, morph targets,
  nodes (TRS or matrix), and animations (`LINEAR` and `CUBICSPLINE`), emitting
  `.glb` (`try_finish_glb` / `finish_glb`) or split `.gltf` + `.bin` + textures
  (`finish_split`).
- `glb` — Strict `read_glb` and `write_glb` container framing with 4-byte
  alignment and chunk bounds checks.
- `json` — Compact, zero-dependency JSON value tree and serializer.
- `transform` — Basis-column normalization and Shepperd quaternion extraction.
- `topology` — Re-exports of `formatkit_core::topology::{triangle_strip, triangle_fan}`.

## Features

- `png` (enabled by default): enables embedded RGBA-to-PNG texture encoding via
  `formatkit_codec::png`.

## License

MIT OR Apache-2.0.
