//! Synthetic `ModuleCatalog` construction, lookup, and dispatch scale baseline.
//!
//! This baseline does not close a percentage-regression gate: elapsed-time
//! floors are host-dependent and full product parity is not present yet. An
//! exact lookup-comparison ratchet also remains open because the public catalog
//! deliberately exposes no instrumentation hook; adding one solely for this
//! example would pollute the production API. Allocation-free lookup is locked
//! independently by `tests/no_alloc_lookup.rs`.

use formatkit_catalog::catalog::{
    ByteRole, CargoTestOracle, Confidence, DecoderRequirement, FormatCapabilities,
    FormatDescriptor, InputForm, InputSchema, LeafDecodeLimits, LeafDecodeRequest,
    LeafInputContract, LeafOperationContract, LeafOperationProvider, LeafOutput,
    LeafOutputContract, LeafOutputKind, LeafOutputMultiplicity, LeafSelection,
    LeafSelectionContract, Probe,
};
use formatkit_catalog::{Category, FormatId};
use formatkit_runtime::{
    ExistingExecutableOperation, FormatModule, ModuleCatalog, ModuleOperation, ModuleState,
    OperationCapabilities, OperationId,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::io;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

const SCHEMA: &str = "formatkit.module-catalog-scale.v2";
const SIZES: [usize; 4] = [427, 1_000, 5_000, 10_000];
const OWNER: &str = "synthetic-scale-owner";
const OPERATION_NAME: &str = "decode-synthetic";
const INPUT_ROLES: &[ByteRole] = &[ByteRole::one("file")];
const INPUT_FORMS: &[InputForm<'static>] = &[InputForm {
    name: "file",
    bytes: INPUT_ROLES,
    selectors: &[],
}];
const INPUT_SCHEMA: InputSchema<'static> = InputSchema {
    forms: INPUT_FORMS,
    relationships: &[],
};

struct TrackingAllocator;
static TRACKING: AtomicBool = AtomicBool::new(false);
static ALLOCATION_CALLS: AtomicU64 = AtomicU64::new(0);
static ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);

// SAFETY: every allocation operation is forwarded unchanged to `System`;
// atomic counters only observe calls while the single-threaded benchmark asks.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if TRACKING.load(Ordering::Relaxed) {
            ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
            ALLOCATED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        }
        // SAFETY: the caller supplied `layout`, forwarded unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: `pointer` and `layout` came from the allocator above.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if TRACKING.load(Ordering::Relaxed) {
            ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
            ALLOCATED_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        }
        // SAFETY: all arguments are forwarded unchanged to `System`.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

#[derive(Clone, Copy)]
struct Config {
    rounds: usize,
    lookup_iterations: u64,
    callback_iterations: u64,
    dispatch_iterations: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rounds: 11,
            lookup_iterations: 2_500_000,
            callback_iterations: 20_000_000,
            dispatch_iterations: 2_000_000,
        }
    }
}

#[derive(Clone, Copy)]
struct AllocationObservation {
    calls: u64,
    bytes: u64,
}

#[derive(Clone, Copy)]
struct Timed {
    elapsed_ns: u128,
    allocations: AllocationObservation,
    checksum: u64,
}

fn parse_positive(flag: &str, value: Option<String>) -> io::Result<u64> {
    let raw = value.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{flag} requires a value"),
        )
    })?;
    let parsed = raw.parse::<u64>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid {flag} value: {raw}"),
        )
    })?;
    if parsed == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{flag} must be positive"),
        ));
    }
    Ok(parsed)
}

fn parse_config() -> io::Result<Config> {
    let mut config = Config::default();
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--rounds" => {
                config.rounds = usize::try_from(parse_positive(&argument, arguments.next())?)
                    .map_err(|_| io::Error::other("--rounds exceeds usize"))?;
            }
            "--lookup-iterations" => {
                config.lookup_iterations = parse_positive(&argument, arguments.next())?;
            }
            "--callback-iterations" => {
                config.callback_iterations = parse_positive(&argument, arguments.next())?;
            }
            "--dispatch-iterations" => {
                config.dispatch_iterations = parse_positive(&argument, arguments.next())?;
            }
            "--help" | "-h" => {
                println!(
                    "usage: module_catalog_scale [--rounds N] \
                     [--lookup-iterations N] [--callback-iterations N] \
                     [--dispatch-iterations N]"
                );
                std::process::exit(0);
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown argument: {argument}"),
                ));
            }
        }
    }
    Ok(config)
}

fn decode_synthetic(
    _bytes: &[u8],
    _request: LeafDecodeRequest,
) -> formatkit_core::Result<Vec<LeafOutput>> {
    Ok(Vec::new())
}

fn leak<T>(value: T) -> &'static T {
    Box::leak(Box::new(value))
}

fn leak_slice<T>(values: Vec<T>) -> &'static [T] {
    Box::leak(values.into_boxed_slice())
}

#[derive(Clone, Copy)]
enum SyntheticProbeShape {
    ExactMagic,
    MixedUniqueStructural,
}

fn structural_probe_accepts(_bytes: &[u8]) -> bool {
    true
}

fn synthetic_modules(count: usize, probe_shape: SyntheticProbeShape) -> Vec<&'static FormatModule> {
    (0..count)
        .map(|index| {
            let identity: &'static str =
                Box::leak(format!("synthetic.scale-{index:05}").into_boxed_str());
            let id = FormatId::new(identity);
            let probes = match probe_shape {
                SyntheticProbeShape::ExactMagic => {
                    let magic: &'static [u8] = Box::leak(Box::new((index as u64).to_be_bytes()));
                    leak_slice(vec![Probe::Magic {
                        offset: 0,
                        bytes: magic,
                    }])
                }
                SyntheticProbeShape::MixedUniqueStructural if index == 0 => {
                    leak_slice(vec![Probe::Magic {
                        offset: 0,
                        bytes: b"MIXED000",
                    }])
                }
                SyntheticProbeShape::MixedUniqueStructural => {
                    let name: &'static str =
                        Box::leak(format!("synthetic-structural-{index:05}").into_boxed_str());
                    leak_slice(vec![Probe::Structural {
                        name,
                        check: structural_probe_accepts,
                    }])
                }
            };
            let descriptor = leak(FormatDescriptor {
                id,
                category: Category::Unknown,
                decoder: Some(OWNER),
                precedence: 100,
                probes,
                extension_hints: &[],
                requirement: DecoderRequirement::None,
                ambiguity_group: None,
                capabilities: FormatCapabilities {
                    parse: true,
                    decode: true,
                    edit: false,
                    write: false,
                    round_trip: false,
                    corpus: false,
                    bindings: false,
                    confidence: match probe_shape {
                        SyntheticProbeShape::ExactMagic => Confidence::ExactMagic,
                        SyntheticProbeShape::MixedUniqueStructural => Confidence::Structural,
                    },
                },
            });
            let provider = leak(LeafOperationProvider {
                contract: LeafOperationContract {
                    id,
                    input: LeafInputContract::file("file"),
                    selection: LeafSelectionContract::NONE,
                    output: LeafOutputContract {
                        kind: LeafOutputKind::RgbaImage,
                        multiplicity: LeafOutputMultiplicity::One,
                    },
                    max_input_bytes: 1,
                    default_limits: LeafDecodeLimits {
                        max_output_bytes: 1,
                        max_work_bytes: 1,
                    },
                    max_limits: LeafDecodeLimits {
                        max_output_bytes: 1,
                        max_work_bytes: 1,
                    },
                    oracle: CargoTestOracle::integration(
                        "formatkit-runtime",
                        "module_catalog_scale",
                        "synthetic_callback_contract",
                    ),
                },
                decode: decode_synthetic,
                decode_budgeted: None,
                decode_budgeted_source: None,
                decode_budgeted_file: None,
            });
            let operations = leak_slice(vec![ModuleOperation {
                name: OPERATION_NAME,
                purpose: "measure one synthetic leaf callback",
                owner: OWNER,
                capabilities: OperationCapabilities::PARSE.union(OperationCapabilities::DECODE),
                input_schema: &INPUT_SCHEMA,
                bound_namespace: None,
                executable: ExistingExecutableOperation::Leaf(provider),
            }]);
            leak(FormatModule {
                format: id,
                owner: OWNER,
                state: ModuleState::Strict,
                descriptor: Some(descriptor),
                embedded_support: None,
                writer_contract: None,
                namespace_semantics: None,
                operations,
            })
        })
        .collect()
}

fn begin_tracking() {
    ALLOCATION_CALLS.store(0, Ordering::Relaxed);
    ALLOCATED_BYTES.store(0, Ordering::Relaxed);
    TRACKING.store(true, Ordering::SeqCst);
}

fn end_tracking() -> AllocationObservation {
    TRACKING.store(false, Ordering::SeqCst);
    AllocationObservation {
        calls: ALLOCATION_CALLS.load(Ordering::Relaxed),
        bytes: ALLOCATED_BYTES.load(Ordering::Relaxed),
    }
}

fn measure(mut operation: impl FnMut() -> u64) -> Timed {
    begin_tracking();
    let started = Instant::now();
    let checksum = operation();
    let elapsed_ns = started.elapsed().as_nanos();
    let allocations = end_tracking();
    Timed {
        elapsed_ns,
        allocations,
        checksum,
    }
}

fn request() -> LeafDecodeRequest {
    LeafDecodeRequest {
        selection: LeafSelection::default(),
        limits: LeafDecodeLimits {
            max_output_bytes: 1,
            max_work_bytes: 1,
        },
    }
}

fn command_output(program: &str, arguments: &[&str]) -> String {
    Command::new(program)
        .args(arguments)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_else(|| "unavailable".into())
}

fn git_dirty_state() -> &'static str {
    match Command::new("git")
        .args(["status", "--porcelain=v1", "--untracked-files=normal"])
        .output()
    {
        Ok(output) if output.status.success() && output.stdout.is_empty() => "clean",
        Ok(output) if output.status.success() => "dirty",
        _ => "unknown",
    }
}

fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(escaped, "\\u{:04x}", character as u32);
            }
            character => escaped.push(character),
        }
    }
    escaped.push('"');
    escaped
}

fn emit_timed(name: &str, timed: Timed) -> String {
    format!(
        concat!(
            "\"{}_ns\":{},\"{}_allocation_calls\":{},",
            "\"{}_allocated_bytes\":{},\"{}_checksum\":{}"
        ),
        name,
        timed.elapsed_ns,
        name,
        timed.allocations.calls,
        name,
        timed.allocations.bytes,
        name,
        timed.checksum,
    )
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config()?;
    let rustc = command_output("rustc", &["--version"]);
    let rustc_host = command_output("rustc", &["-vV"])
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .unwrap_or("unavailable")
        .to_owned();
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let commit = command_output("git", &["rev-parse", "HEAD"]);
    let git_dirty = git_dirty_state();
    println!(
        concat!(
            "{{\"schema\":\"{}\",\"kind\":\"metadata\",",
            "\"sizes\":[427,1000,5000,10000],\"live_support_union_baseline\":427,\"rounds\":{},",
            "\"lookup_iterations\":{},\"callback_iterations\":{},",
            "\"dispatch_iterations\":{},\"lookup_hit_positions\":[\"first\",\"middle\",\"last\"],",
            "\"input_order\":\"alternating-ascending-descending\",\"rustc\":{},\"rustc_host\":{},",
            "\"compiled_target_arch\":{},\"compiled_target_os\":{},\"profile\":{},",
            "\"git_commit\":{},\"git_dirty\":{},\"phase_gate\":\"open\",",
            "\"percentage_regression_gate\":\"open\",",
            "\"lookup_complexity_gate\":\"open-no-production-comparison-counter\",",
            "\"construction_scale_gate\":\"measured-single-exact-magic-fast-path\",",
            "\"sample_duration_target_ns\":100000000,",
            "\"open_reasons\":[\"full-product-parity-not-yet-proven\",",
            "\"mixed-probe-shapes-retain-exact-pairwise-conflict-oracle\",",
            "\"elapsed-time-floor-is-observed-not-enforced-across-hosts\"]}}"
        ),
        SCHEMA,
        config.rounds,
        config.lookup_iterations,
        config.callback_iterations,
        config.dispatch_iterations,
        json_string(&rustc),
        json_string(&rustc_host),
        json_string(std::env::consts::ARCH),
        json_string(std::env::consts::OS),
        json_string(profile),
        json_string(&commit),
        json_string(git_dirty),
    );

    let missing_module = FormatId::new("synthetic.missing");
    for &size in &SIZES {
        let modules = synthetic_modules(size, SyntheticProbeShape::ExactMagic);
        let mixed_modules = synthetic_modules(size, SyntheticProbeShape::MixedUniqueStructural);
        let successful_ids = [
            modules[0].format,
            modules[size / 2].format,
            modules[size - 1].format,
        ];
        let successful_operations = successful_ids.map(|format| OperationId {
            format,
            name: OPERATION_NAME,
        });
        let successful_operation = successful_operations[1];
        let missing_operation = OperationId {
            format: successful_ids[1],
            name: "missing-operation",
        };
        // One unmeasured construction and one pass over every lookup class
        // removes first-touch work from the eleven default measured rounds.
        let warm_catalog = ModuleCatalog::new(modules.iter().copied())?;
        for id in successful_ids {
            assert!(warm_catalog.module(id).is_some());
        }
        assert!(warm_catalog.module(missing_module).is_none());
        for id in successful_operations {
            assert!(warm_catalog.operation(id).is_some());
        }
        assert!(warm_catalog.operation(missing_operation).is_none());
        drop(warm_catalog);
        for round in 0..config.rounds {
            begin_tracking();
            let started = Instant::now();
            let catalog = if round % 2 == 0 {
                ModuleCatalog::new(modules.iter().copied())?
            } else {
                ModuleCatalog::new(modules.iter().rev().copied())?
            };
            let construction_ns = started.elapsed().as_nanos();
            let construction_allocations = end_tracking();

            // Deliberately retain one separately labelled adversarial shape:
            // the first exact-magic row transitions its precedence group to
            // Mixed when the first structural row arrives, after which unique
            // structural names exercise the exact prior-prefix oracle. This is
            // measurement of known open construction debt, not an optimized
            // scale-gate claim.
            begin_tracking();
            let mixed_started = Instant::now();
            let mixed_catalog = if round % 2 == 0 {
                ModuleCatalog::new(mixed_modules.iter().copied())?
            } else {
                ModuleCatalog::new(mixed_modules.iter().rev().copied())?
            };
            let mixed_construction_ns = mixed_started.elapsed().as_nanos();
            let mixed_construction_allocations = end_tracking();
            println!(
                concat!(
                    "{{\"schema\":\"{}\",\"kind\":\"construction-measurement\",",
                    "\"scenario\":\"mixed-unique-structural-prior-scan\",",
                    "\"scale_gate\":\"open-known-pairwise-oracle\",",
                    "\"size\":{},\"round\":{},\"input_order\":\"{}\",",
                    "\"module_count\":{},\"operation_count\":{},",
                    "\"construction_ns\":{},\"construction_allocation_calls\":{},",
                    "\"construction_allocated_bytes\":{}}}"
                ),
                SCHEMA,
                size,
                round,
                if round % 2 == 0 {
                    "ascending"
                } else {
                    "descending"
                },
                mixed_catalog.modules().len(),
                mixed_catalog.operations().len(),
                mixed_construction_ns,
                mixed_construction_allocations.calls,
                mixed_construction_allocations.bytes,
            );
            drop(mixed_catalog);

            let successful_module_lookup = measure(|| {
                let mut checksum = 0u64;
                for _ in 0..config.lookup_iterations {
                    for id in successful_ids {
                        checksum = checksum.wrapping_add(u64::from(
                            black_box(catalog.module(black_box(id))).is_some(),
                        ));
                    }
                }
                checksum
            });
            let missing_module_lookup = measure(|| {
                let mut checksum = 0u64;
                for _ in 0..config.lookup_iterations {
                    checksum = checksum.wrapping_add(u64::from(
                        black_box(catalog.module(missing_module)).is_none(),
                    ));
                }
                checksum
            });
            let successful_operation_lookup = measure(|| {
                let mut checksum = 0u64;
                for _ in 0..config.lookup_iterations {
                    for id in successful_operations {
                        checksum = checksum.wrapping_add(u64::from(
                            black_box(catalog.operation(black_box(id))).is_some(),
                        ));
                    }
                }
                checksum
            });
            let missing_operation_lookup = measure(|| {
                let mut checksum = 0u64;
                for _ in 0..config.lookup_iterations {
                    checksum = checksum.wrapping_add(u64::from(
                        black_box(catalog.operation(missing_operation)).is_none(),
                    ));
                }
                checksum
            });
            let direct = || {
                let mut checksum = 0u64;
                let callback = black_box(
                    decode_synthetic
                        as fn(&[u8], LeafDecodeRequest) -> formatkit_core::Result<Vec<LeafOutput>>,
                );
                for _ in 0..config.callback_iterations {
                    let outputs = black_box(
                        callback(black_box(&[]), request()).expect("synthetic callback succeeds"),
                    );
                    checksum = checksum.wrapping_add(1 + outputs.len() as u64);
                }
                checksum
            };
            let operation = catalog
                .operation(successful_operation)
                .expect("synthetic operation is indexed");
            let ExistingExecutableOperation::Leaf(resolved_provider) = operation.executable else {
                panic!("synthetic operation must remain a leaf")
            };
            let resolved = || {
                let mut checksum = 0u64;
                for _ in 0..config.callback_iterations {
                    let outputs = black_box(
                        (black_box(resolved_provider.decode))(black_box(&[]), request())
                            .expect("synthetic resolved callback succeeds"),
                    );
                    checksum = checksum.wrapping_add(1 + outputs.len() as u64);
                }
                checksum
            };
            let lookup_and_invoke = || {
                let mut checksum = 0u64;
                for _ in 0..config.dispatch_iterations {
                    let operation = catalog
                        .operation(black_box(successful_operation))
                        .expect("synthetic operation is indexed");
                    let ExistingExecutableOperation::Leaf(provider) = operation.executable else {
                        panic!("synthetic operation must remain a leaf")
                    };
                    let outputs = black_box(
                        (provider.decode)(black_box(&[]), request())
                            .expect("synthetic dispatch succeeds"),
                    );
                    checksum = checksum.wrapping_add(1 + outputs.len() as u64);
                }
                checksum
            };

            // Warm all three paths before timing. Alternate their order by
            // round so cache/thermal position does not always favor one path.
            assert!(decode_synthetic(&[], request())?.is_empty());
            assert!((resolved_provider.decode)(&[], request())?.is_empty());
            let warm_operation = catalog
                .operation(successful_operation)
                .expect("synthetic operation is indexed");
            let ExistingExecutableOperation::Leaf(warm_provider) = warm_operation.executable else {
                panic!("synthetic operation must remain a leaf")
            };
            assert!((warm_provider.decode)(&[], request())?.is_empty());
            let (direct_callback, resolved_callback, operation_lookup_and_invoke) =
                if round % 2 == 0 {
                    (
                        measure(direct),
                        measure(resolved),
                        measure(lookup_and_invoke),
                    )
                } else {
                    let lookup = measure(lookup_and_invoke);
                    let resolved = measure(resolved);
                    let direct = measure(direct);
                    (direct, resolved, lookup)
                };

            println!(
                concat!(
                    "{{\"schema\":\"{}\",\"kind\":\"measurement\",",
                    "\"size\":{},\"round\":{},\"input_order\":\"{}\",\"module_count\":{},",
                    "\"operation_count\":{},\"construction_ns\":{},",
                    "\"construction_allocation_calls\":{},",
                    "\"construction_allocated_bytes\":{},{},{},{},{},{},{},{}}}"
                ),
                SCHEMA,
                size,
                round,
                if round % 2 == 0 {
                    "ascending"
                } else {
                    "descending"
                },
                catalog.modules().len(),
                catalog.operations().len(),
                construction_ns,
                construction_allocations.calls,
                construction_allocations.bytes,
                emit_timed("successful_module_lookup", successful_module_lookup),
                emit_timed("missing_module_lookup", missing_module_lookup),
                emit_timed("successful_operation_lookup", successful_operation_lookup),
                emit_timed("missing_operation_lookup", missing_operation_lookup),
                emit_timed("direct_callback", direct_callback),
                emit_timed("resolved_callback", resolved_callback),
                emit_timed("operation_lookup_and_invoke", operation_lookup_and_invoke),
            );
        }
    }
    Ok(())
}
