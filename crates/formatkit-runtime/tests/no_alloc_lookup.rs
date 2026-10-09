use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use formatkit_catalog::catalog::{
    Confidence, DecoderRequirement, FormatCapabilities, FormatDescriptor, LeafDecodeLimits,
    LeafDecodeRequest, LeafInputContract, LeafOperationContract, LeafOperationProvider, LeafOutput,
    LeafOutputContract, LeafOutputKind, LeafOutputMultiplicity, LeafSelectionContract, Probe,
};
use formatkit_catalog::{Category, FormatId};
use formatkit_runtime::{
    ExistingExecutableOperation, FormatModule, ModuleCatalog, ModuleOperation, ModuleState,
    OperationId,
};

const SYNTHETIC_IMAGE: FormatId = FormatId::new("synthetic-image");

struct TrackingAllocator;
thread_local! {
    static TRACKING: Cell<bool> = const { Cell::new(false) };
    static CALLS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: allocation and deallocation are forwarded unchanged to `System`;
// only allocation-call observation is added for the current test thread.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        TRACKING.with(|tracking| {
            if tracking.get() {
                CALLS.with(|calls| calls.set(calls.get() + 1));
            }
        });
        // SAFETY: `layout` is forwarded unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the pointer and layout came from the system allocator above.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

const DESCRIPTOR: FormatDescriptor = FormatDescriptor {
    id: SYNTHETIC_IMAGE,
    category: Category::Image,
    decoder: Some("test-owner"),
    precedence: 100,
    probes: &[Probe::Magic {
        offset: 0,
        bytes: b"IMG!",
    }],
    extension_hints: &["img"],
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
        confidence: Confidence::ExactMagic,
    },
};
fn decode(_bytes: &[u8], _request: LeafDecodeRequest) -> formatkit_core::Result<Vec<LeafOutput>> {
    Ok(Vec::new())
}
const LEAF: LeafOperationProvider = LeafOperationProvider {
    contract: LeafOperationContract {
        id: SYNTHETIC_IMAGE,
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
        oracle: formatkit_catalog::catalog::CargoTestOracle::integration(
            "formatkit-runtime",
            "no_alloc_lookup",
            "module_and_operation_lookup_are_indexed_and_allocation_free",
        ),
    },
    decode,
    decode_budgeted: None,
    decode_budgeted_source: None,
    decode_budgeted_file: None,
};
const OPERATION: ModuleOperation = ModuleOperation {
    name: "decode-image",
    purpose: "decode image",
    owner: "test-owner",
    capabilities: formatkit_runtime::OperationCapabilities::PARSE
        .union(formatkit_runtime::OperationCapabilities::DECODE),
    input_schema: &formatkit_catalog::catalog::InputSchema {
        forms: &[formatkit_catalog::catalog::InputForm {
            name: "file",
            bytes: &[formatkit_catalog::catalog::ByteRole::one("file")],
            selectors: &[],
        }],
        relationships: &[],
    },
    bound_namespace: None,
    executable: ExistingExecutableOperation::Leaf(&LEAF),
};
static MODULE: FormatModule = FormatModule {
    format: SYNTHETIC_IMAGE,
    owner: "test-owner",
    state: ModuleState::Strict,
    descriptor: Some(&DESCRIPTOR),
    embedded_support: None,
    writer_contract: None,
    namespace_semantics: None,
    operations: &[OPERATION],
};

#[test]
fn module_and_operation_lookup_are_indexed_and_allocation_free() {
    let catalog = ModuleCatalog::new([&MODULE]).unwrap();
    let operation = OperationId {
        format: SYNTHETIC_IMAGE,
        name: "decode-image",
    };
    CALLS.with(|calls| calls.set(0));
    TRACKING.with(|tracking| tracking.set(true));
    for _ in 0..10_000 {
        std::hint::black_box(catalog.module(SYNTHETIC_IMAGE)).unwrap();
        std::hint::black_box(catalog.operation(operation)).unwrap();
    }
    TRACKING.with(|tracking| tracking.set(false));
    assert_eq!(CALLS.with(Cell::get), 0);
}
