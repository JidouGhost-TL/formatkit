# New Kit Onboarding Guide

Step-by-step guide for launching a greenfield format kit on top of FormatKit.

FormatKit provides platform-neutral binary mechanics, bounded I/O, archive services, catalog contracts, runtime composition, and corpus-testing infrastructure. Your kit retains full ownership of format identities, grammars, validation rules, diagnostics, and read/write policies.

---

## 1. Workspace Dependency Setup

You can consume FormatKit either through **individual crates** (recommended for library crates inside a multi-crate workspace to keep compile graphs minimal) or through the **umbrella `formatkit` crate** (convenient for CLIs and top-level product crates).

### Option A: Individual Crates (Recommended for Library Crates)

```toml
[workspace.dependencies]
formatkit-core = "0.1.15"
formatkit-layout = "0.1.15"
formatkit-catalog = "0.1.15"
formatkit-runtime = "0.1.15"
formatkit-archive = "0.1.15"
formatkit-pixel = "0.1.15"
formatkit-codec = "0.1.15"
formatkit-patch = "0.1.15"
formatkit-gltf = "0.1.15"
formatkit-corpus = "0.1.15"
formatkit-corpus-test = "0.1.15"
```

Keep `formatkit-corpus` and `formatkit-corpus-test` in `[dev-dependencies]` so production builds do not pull in test harness dependencies.

Optional features on individual crates:
- `formatkit-core`: `shift-jis` (enabled by default; disable with `default-features = false` if you do not need Shift-JIS/CP932 tables).
- `formatkit-codec`: `dds` (enabled by default; pulls in `formatkit-pixel`).
- `formatkit-gltf`: `png` (enabled by default; pulls in `formatkit-codec`).

### Option B: Umbrella `formatkit` Crate

The umbrella crate re-exports `core`, `layout`, `catalog`, and `runtime` by default, and gates optional families behind features (`archive`, `pixel`, `codec`, `patch`, `gltf`, `corpus`):

```toml
[dependencies]
formatkit = { version = "0.1.15", features = ["archive", "pixel", "codec"] }

[dev-dependencies]
formatkit = { version = "0.1.15", features = ["corpus"] }
```

---

## 2. Resource Budgets, Cancellation & Resident Memory Protocol

Every entry point that parses untrusted input, mounts an archive, walks nested containers, or materializes decoded bytes should accept a mutable `&mut WorkBudget`.

> **Avoid legacy `ReadBudget`:** `ReadBudget` exists only for backward-compatibility bridges. Greenfield kits should use `WorkBudget` everywhere.

```rust
use formatkit_core::{
    CancellationToken, WorkBudget, WorkLimits, WorkResource,
};

let cancel = CancellationToken::new();
let limits = WorkLimits::unlimited()
    .with(WorkResource::LogicalReadBytes, 64 * 1024 * 1024)
    .with(WorkResource::IoRequestedBytes, 64 * 1024 * 1024)
    .with(WorkResource::IoReadCalls, 10_000)
    .with(WorkResource::MaterializedBytes, 32 * 1024 * 1024)
    .with(WorkResource::OutputBytes, 64 * 1024 * 1024)
    .with(WorkResource::Nodes, 4_096)
    .with(WorkResource::Members, 65_536)
    .with_depth(16)
    .with_resident_bytes(32 * 1024 * 1024);

let mut budget = WorkBudget::new(limits).with_cancellation(cancel.clone());
```

Key rules for format owners:
1. **Check cancellation explicitly** at loop boundaries and before expensive work via `budget.check_cancelled()?` (charging a resource does not implicitly poll the token).
2. **Reserve active resident memory before allocating** retained buffers via `let reservation = budget.reserve_resident(byte_len)?;`. Dropping `ResidentReservation` automatically releases the active resident total while preserving peak telemetry.
3. **Enter nested scopes** with `budget.enter_depth()?` (`DepthScope`) when descending into nested containers.
4. **Charge cumulative dimensions** (`LogicalReadBytes`, `MaterializedBytes`, `OutputBytes`, `Nodes`, `Members`) before allocating or writing.

---

## 3. Choosing a `RangeSource`

Never force callers to read an entire disc image or multi-gigabyte archive into a `Vec<u8>`. Accept `&dyn RangeSource` (or `Arc<dyn RangeSource>`) and read headers/tables lazily via `SourceMetadataReader` or `read_exact_at`.

| `RangeSource` Type | Backing Storage | Use when… |
| --- | --- | --- |
| `SliceRangeSource` | Borrowed `&'a [u8]` | Short-lived, zero-copy parsing over an already-resident slice (e.g., unit tests or borrowed buffers). |
| `MemoryRangeSource` | Owned `SharedBytes` / `Arc<[u8]>` | `'static` in-memory buffers that need cheap zero-copy subrange sharing across nested mounts. |
| `FileRangeSource` | Open `std::fs::File` + open-time inode/path snapshot | Disc-scale files on disk; supports revalidation proving the held descriptor and path still refer to the same snapshot. |
| `ArchiveMemberRangeSource` | Subrange of a parent `Arc<dyn RangeSource>` | Exposing an uncompressed archive member as a lazy child source without copying its bytes. |
| `RevalidatedExactSliceSource` | Exact subrange with strict revalidation policy | Guarding a mounted view so any underlying file mutation or length drift fails closed before reading. |

Additional combinators in `formatkit-core`: `CompositeRangeSource` (concatenated segments), `StridedRangeSource` (fixed-stride sector/block slices), `TransformedRangeSource` (bounded materialized transform), and `ObjectPackRangeSource`.

---

## 4. Implementing `IndexedNamespace` & Using `formatkit-archive`

If your format is an archive or container with child entries, implement `IndexedNamespace` (or construct `StoredRangeNamespace` directly when members are stored raw byte ranges).

### Stored-Range Archives (Single File)

1. Read and validate the header/directory lazily using `SourceMetadataReader` and an appropriate table helper from `formatkit_layout::tables`.
2. Build `Vec<NamespaceEntry>` (each with `name: Option<String>`, `offset: u64`, `size: u64`).
3. Construct `StoredRangeNamespace::new(source, entries, StoredRangeNamespaceLimits::default())?` (which implements `IndexedNamespace` with zero-copy `ArchiveMemberRangeSource` views).

### Paired Index + Data Archives

When the directory lives in an index file and member payloads live in a separate data file, use `formatkit_archive::paired_stored_mount::PairedStoredMount` to share role resolution, source revalidation, bounded index I/O, and `StoredRangeNamespace` construction while keeping the directory grammar in your owner callback.

### Transformed (Compressed / Encrypted) Members

For containers whose members require decompression or decryption, implement `IndexedNamespace` and use `formatkit_core::materialize_transformed_member` inside `validated_content_source_with_work` with an explicit `TransformRecipe` and `WorkBudget`.

### Free Services from `formatkit-archive`

Once your container implements `IndexedNamespace`, you immediately get:
- `select_index(&ns, idx)` / `select_name(&ns, "entry.bin")` — exact selection that rejects missing or ambiguous duplicate names.
- `extract(member, ExtractionMode::Stored | ExtractionMode::Content { max_output_len }, &mut sink, &mut buf, &mut budget)` — streaming extraction with partial-write accounting and cancellation.
- `walk(root, &mut resolver, &WalkOptions::default(), &mut budget, &mut visitor)` — depth- and budget-bounded recursive traversal across nested containers.

---

## 5. Greenfield `Strict` Wiring with `formatkit-catalog` + `formatkit-runtime`

In a brand-new kit, register every format as `ModuleState::Strict` from day one.

> **Strict vs Legacy:** `ModuleState::Legacy` and `formatkit_catalog::CompatibilityRecognitionRule` exist solely as migration scaffolding for pre-existing kits transitioning from ad-hoc registries. Greenfield kits should never introduce `Legacy` rows or `CompatibilityRecognitionRule` entries.

### Step-by-Step Wiring

1. **Define a `FormatId`:**
   ```rust
   use formatkit_catalog::{Category, FormatId};

   pub const MY_IMAGE_ID: FormatId = FormatId::new("my-kit.image.sample");
   ```
2. **Define a `FormatDescriptor`:**
   ```rust
   use formatkit_catalog::{
       Confidence, DecoderRequirement, FormatCapabilities, FormatDescriptor, Probe,
   };

   pub static MY_IMAGE_DESCRIPTOR: FormatDescriptor = FormatDescriptor {
       id: MY_IMAGE_ID,
       category: Category::IMAGE,
       decoder: Some("my-kit-image"),
       precedence: 100,
       probes: &[Probe::Magic { offset: 0, bytes: b"SMPL" }],
       extension_hints: &["smpl"],
       requirement: DecoderRequirement::None,
       capabilities: FormatCapabilities {
           parse: true,
           decode: true,
           edit: false,
           write: false,
           round_trip: false,
           corpus: false,
           bindings: false,
           confidence: Confidence::ExactMagic,
       },
   };
   ```
3. **Define a `LeafOperationProvider` (for images/audio) or `NamespaceProvider` / `RoleBoundNamespaceProvider` (for archives):**
   Declare the input/selection/output contract (`LeafOperationContract` or `NamespaceMountContract`) and attach your typed budgeted decode/mount function pointer.
4. **Publish a `FormatModule` with `ModuleState::Strict`:**
   Attach `descriptor`, `operations` (`&[ModuleOperation]` using `ExistingExecutableOperation::Leaf(...)`, `Namespace { .. }`, `RunnerNamespace { .. }`, `RoleBoundNamespace { .. }`, or `ResidentWriter(...)`), and optional `writer_contract` / `namespace_semantics`.
5. **Compose a `ModuleCatalog`:**
   ```rust
   use formatkit_runtime::ModuleCatalog;

   let catalog = ModuleCatalog::new([&MY_IMAGE_MODULE])?;
   ```
   `ModuleCatalog::new` validates identity agreement, owner attribution, input-schema topology, strict capability alignment, and contract/provider consistency at startup.
6. **Identify and dispatch:**
   - Identify unknown bytes: `catalog.formats().identify(prefix, &DetectionContext::default())`
   - Decode a leaf format: `catalog.leaf_operations().decode(...)`
   - Mount an archive: `catalog.invoke_bound_namespace(...)`, `catalog.invoke_bound_namespace_work(...)`, `catalog.invoke_role_bound_namespace_work(...)`, or `catalog.invoke_runner_namespace(...)`
   - Execute a resident writer: `catalog.invoke_resident_writer(...)`

---

## 6. External Corpus Golden Tests (`formatkit-corpus` + `formatkit-corpus-test`)

Keep real-world samples completely outside your Git repository. Ordinary `cargo test` runs use synthetic fixtures and skip cleanly when `FORMATKIT_CORPUS_DIR` is unset.

1. **Implement `formatkit_corpus_test::Digest`** for each format:
   ```rust
   use formatkit_corpus_test::{Args, Digest, hash_bytes};
   use serde_json::json;

   struct SampleImageDigest;

   impl Digest for SampleImageDigest {
       fn digest(
           &self,
           bytes: &[u8],
           _args: &Args,
       ) -> formatkit_core::Result<serde_json::Value> {
           let img = my_kit_image::decode(bytes)?;
           Ok(json!({
               "width": img.width,
               "height": img.height,
               "rgba_sha256": hash_bytes(&img.rgba),
           }))
       }
   }
   ```
2. **Register handlers in a `Registry` and invoke `run_dir` or `run_all`:**
   ```rust
   use formatkit_corpus_test::{Registry, run_all};

   #[test]
   fn corpus_golden_digests() {
       let mut registry = Registry::new();
       registry.register("sample_image", SampleImageDigest);
       run_all(&registry);
   }
   ```
   For compression codecs, use `formatkit_corpus_test::compress_oracle::run_from_corpus`. For frozen corpora with a SHA-256-sealed manifest, validate via `formatkit_corpus_test::sealed_package::SealedPackage`.
3. **Run real-corpus validation through the safe serialized runner:**
   ```sh
   FORMATKIT_CORPUS_DIR=/path/to/corpus \
   FORMATKIT_CORPUS_REQUIRED=1 \
   /path/to/formatkit/tools/run-corpus-safe.sh \
       cargo test --test corpus -- --nocapture
   ```
   - `FORMATKIT_CORPUS_REQUIRED=1` ensures a missing or empty corpus fails instead of silently skipping.
   - Never set `FORMATKIT_CORPUS_WRITE=1` against a frozen corpus; use it only during explicit initial enrollment.
