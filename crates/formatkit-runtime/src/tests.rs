use formatkit_catalog::catalog::{
    ByteRole, CargoTestOracle, Confidence, ContextRequirement, DecoderRequirement,
    EmbeddedFormatSupport, FormatCapabilities, FormatDescriptor, FormatFamilyId, InputForm,
    InputSchema, LeafDecodeLimits, LeafDecodeRequest, LeafInputContract, LeafOperationContract,
    LeafOperationProvider, LeafOutput, LeafOutputContract, LeafOutputKind, LeafOutputMultiplicity,
    LeafSelectionContract, NamespaceAddressing, NamespaceMountContract, NamespaceMountInput,
    NamespaceMountStrategy, NamespaceProvider, NamespaceProviderMount, NamespaceSemantics, Probe,
};
use formatkit_catalog::{Category, FormatId};
use formatkit_core::{Error, IndexedNamespace, RangeSource, ReadBudget, Result};

use super::*;

mod namespace_projection;

const TIM_PROBES: &[Probe] = &[Probe::Magic {
    offset: 0,
    bytes: b"TIM!",
}];
const VAG_PROBES: &[Probe] = &[Probe::Magic {
    offset: 0,
    bytes: b"VAG!",
}];

const fn capabilities() -> FormatCapabilities {
    FormatCapabilities {
        parse: true,
        decode: true,
        edit: false,
        write: false,
        round_trip: false,
        corpus: false,
        bindings: false,
        confidence: Confidence::ExactMagic,
    }
}

mod resident_writer {
    use std::io::{Cursor, Write};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use formatkit_catalog::catalog::{
        AuthoringContract, CargoTestOracle, EditContract, EditMode, EditPrecondition,
        FormatCapabilities, InputForm, InputSchema, OperationScope, OutputLengthGuarantee,
        RelocationObligation, ReproductionContract, WriterContract,
    };
    use formatkit_core::{CancellationToken, SourceBindings, WorkBudget, WorkLimits, WorkResource};

    use super::*;

    const TEST_ORACLE: CargoTestOracle = CargoTestOracle::lib(
        "formatkit-runtime",
        "tests::resident_writer::strict_writer_executes",
    );
    const EMPTY_SCHEMA: InputSchema<'static> = InputSchema {
        forms: &[InputForm {
            name: "empty",
            bytes: &[],
            selectors: &[],
        }],
        relationships: &[],
    };
    const WRITER_CAPABILITIES: FormatCapabilities = FormatCapabilities {
        parse: true,
        decode: true,
        edit: true,
        write: true,
        round_trip: true,
        corpus: false,
        bindings: false,
        confidence: Confidence::ExactMagic,
    };
    const WRITER_DESCRIPTOR: FormatDescriptor = FormatDescriptor {
        id: crate::synthetic::ID_B38504826C7B,
        category: Category::Image,
        decoder: Some("writer-owner"),
        precedence: 100,
        probes: TIM_PROBES,
        extension_hints: &["synthetic-id-b38504826c7b"],
        requirement: DecoderRequirement::None,
        ambiguity_group: None,
        capabilities: WRITER_CAPABILITIES,
    };
    const EDITS: &[EditContract] = &[EditContract {
        mode: EditMode::SameSizeEdit,
        scope: OperationScope::Format,
        precondition: EditPrecondition::ReplacementLengthsUnchanged,
        output_length: OutputLengthGuarantee::Preserved,
        relocation: RelocationObligation::PreserveExistingOffsets,
        mutation_oracle: TEST_ORACLE,
        parse_after_write_oracle: TEST_ORACLE,
    }];
    const WRITER_CONTRACT: WriterContract = WriterContract {
        id: crate::synthetic::ID_B38504826C7B,
        reproduction: Some(ReproductionContract {
            scope: OperationScope::Format,
            oracle: TEST_ORACLE,
        }),
        edits: EDITS,
        authoring: Some(AuthoringContract {
            output_scope: OperationScope::Format,
            parse_after_write_oracle: TEST_ORACLE,
            semantic_oracle: TEST_ORACLE,
            independent_extent_oracle: TEST_ORACLE,
        }),
    };

    fn write_four<'budget>(
        _sources: &SourceBindings,
        _bound: &BoundInputs,
        budget: &'budget mut WorkBudget,
    ) -> Result<ResidentWriteOutput<'budget>> {
        ResidentWriteOutput::build(budget, 4, |bytes, _| {
            bytes.copy_from_slice(b"DATA");
            Ok(())
        })
    }

    const REPRO_PROVIDER: ResidentWriterProvider = ResidentWriterProvider {
        id: crate::synthetic::ID_B38504826C7B,
        owner: "writer-owner",
        proof: WriterProofSelector::Reproduction {
            scope: OperationScope::Format,
        },
        write: write_four,
    };
    const EDIT_PROVIDER: ResidentWriterProvider = ResidentWriterProvider {
        id: crate::synthetic::ID_B38504826C7B,
        owner: "writer-owner",
        proof: WriterProofSelector::Edit {
            mode: EditMode::SameSizeEdit,
            scope: OperationScope::Format,
        },
        write: write_four,
    };
    const AUTHOR_PROVIDER: ResidentWriterProvider = ResidentWriterProvider {
        id: crate::synthetic::ID_B38504826C7B,
        owner: "writer-owner",
        proof: WriterProofSelector::Authoring {
            scope: OperationScope::Format,
        },
        write: write_four,
    };
    const REPRO_OPERATION: ModuleOperation = ModuleOperation {
        name: "reproduce",
        purpose: "reproduce bytes",
        owner: "writer-owner",
        capabilities: OperationCapabilities::ROUND_TRIP,
        input_schema: &EMPTY_SCHEMA,
        bound_namespace: None,
        executable: ExistingExecutableOperation::ResidentWriter(&REPRO_PROVIDER),
    };
    const PARSE_OPERATION: ModuleOperation = ModuleOperation {
        name: "decode-image",
        purpose: "parse and decode the image",
        owner: "writer-owner",
        capabilities: OperationCapabilities::PARSE.union(OperationCapabilities::DECODE),
        input_schema: &FILE_SCHEMA,
        bound_namespace: None,
        executable: ExistingExecutableOperation::Leaf(&LEAF),
    };
    const EDIT_OPERATION: ModuleOperation = ModuleOperation {
        name: "edit",
        purpose: "edit bytes",
        owner: "writer-owner",
        capabilities: OperationCapabilities::EDIT,
        input_schema: &EMPTY_SCHEMA,
        bound_namespace: None,
        executable: ExistingExecutableOperation::ResidentWriter(&EDIT_PROVIDER),
    };
    const AUTHOR_OPERATION: ModuleOperation = ModuleOperation {
        name: "author",
        purpose: "author bytes",
        owner: "writer-owner",
        capabilities: OperationCapabilities::WRITE,
        input_schema: &EMPTY_SCHEMA,
        bound_namespace: None,
        executable: ExistingExecutableOperation::ResidentWriter(&AUTHOR_PROVIDER),
    };
    static WRITER_MODULE: FormatModule = FormatModule {
        format: crate::synthetic::ID_B38504826C7B,
        owner: "writer-owner",
        state: ModuleState::Strict,
        descriptor: Some(&WRITER_DESCRIPTOR),
        embedded_support: None,
        writer_contract: Some(&WRITER_CONTRACT),
        namespace_semantics: None,
        operations: &[
            PARSE_OPERATION,
            REPRO_OPERATION,
            EDIT_OPERATION,
            AUTHOR_OPERATION,
        ],
    };

    fn empty_binding() -> (SourceBindings, BoundInputs) {
        let sources = SourceBindings::new();
        let bound = EMPTY_SCHEMA.bind(&sources, &[], &[]).unwrap();
        (sources, bound)
    }

    #[test]
    fn strict_writer_executes_and_capability_union_is_exact() {
        let catalog = ModuleCatalog::new([&WRITER_MODULE]).unwrap();
        let (sources, bound) = empty_binding();
        let mut budget = WorkBudget::new(WorkLimits::unlimited());
        let mut output = catalog
            .invoke_resident_writer(
                OperationId {
                    format: crate::synthetic::ID_B38504826C7B,
                    name: "edit",
                },
                &sources,
                &bound,
                &mut budget,
            )
            .unwrap()
            .unwrap();
        assert_eq!(output.bytes(), b"DATA");
        let mut published = Vec::new();
        output.write_to(&mut published).unwrap();
        assert_eq!(published, b"DATA");
        output
            .with_output_and_budget::<_, Error>(|bytes, budget| {
                assert_eq!(bytes, b"DATA");
                assert_eq!(budget.usage().resident_bytes(), 4);
                Ok(())
            })
            .unwrap();
        drop(output);
        assert_eq!(budget.usage().resident_bytes(), 0);
        assert_eq!(budget.spent(WorkResource::MaterializedBytes), 4);
        assert_eq!(budget.spent(WorkResource::OutputBytes), 4);
        assert_eq!(budget.spent(WorkResource::Nodes), 1);
    }

    #[test]
    fn proof_selection_rejects_missing_duplicate_and_mismatched_authority() {
        const WRONG_PROOF: ResidentWriterProvider = ResidentWriterProvider {
            proof: WriterProofSelector::Edit {
                mode: EditMode::Rebuild,
                scope: OperationScope::Format,
            },
            ..EDIT_PROVIDER
        };
        const WRONG_OPERATION: ModuleOperation = ModuleOperation {
            executable: ExistingExecutableOperation::ResidentWriter(&WRONG_PROOF),
            ..EDIT_OPERATION
        };
        static WRONG_MODULE: FormatModule = FormatModule {
            operations: &[
                PARSE_OPERATION,
                REPRO_OPERATION,
                WRONG_OPERATION,
                AUTHOR_OPERATION,
            ],
            ..WRITER_MODULE
        };
        assert_eq!(
            ModuleCatalog::new([&WRONG_MODULE]).err().unwrap(),
            ModuleCatalogError::WriterProofDisagreement(OperationId {
                format: crate::synthetic::ID_B38504826C7B,
                name: "edit",
            })
        );

        static MISSING_CONTRACT: FormatModule = FormatModule {
            writer_contract: None,
            ..WRITER_MODULE
        };
        assert_eq!(
            ModuleCatalog::new([&MISSING_CONTRACT]).err().unwrap(),
            ModuleCatalogError::MissingWriterContract(OperationId {
                format: crate::synthetic::ID_B38504826C7B,
                name: "reproduce",
            })
        );

        static MISSING_PROVIDER_MODULE: FormatModule = FormatModule {
            operations: &[PARSE_OPERATION, REPRO_OPERATION, EDIT_OPERATION],
            ..WRITER_MODULE
        };
        assert_eq!(
            ModuleCatalog::new([&MISSING_PROVIDER_MODULE])
                .err()
                .unwrap(),
            ModuleCatalogError::MissingWriterProvider {
                format: crate::synthetic::ID_B38504826C7B,
                proof: AUTHOR_PROVIDER.proof,
            }
        );

        const DUPLICATE: ModuleOperation = ModuleOperation {
            name: "edit-again",
            ..EDIT_OPERATION
        };
        static DUPLICATE_MODULE: FormatModule = FormatModule {
            operations: &[
                PARSE_OPERATION,
                REPRO_OPERATION,
                EDIT_OPERATION,
                DUPLICATE,
                AUTHOR_OPERATION,
            ],
            ..WRITER_MODULE
        };
        assert_eq!(
            ModuleCatalog::new([&DUPLICATE_MODULE]).err().unwrap(),
            ModuleCatalogError::DuplicateWriterProof {
                format: crate::synthetic::ID_B38504826C7B,
                proof: EDIT_PROVIDER.proof,
            }
        );

        const LEAF_OVERCLAIM: ModuleOperation = ModuleOperation {
            capabilities: OperationCapabilities::EDIT,
            owner: "owner-a",
            ..LEAF_OPERATION
        };
        static LEAF_OVERCLAIM_MODULE: FormatModule = FormatModule {
            operations: &[LEAF_OVERCLAIM],
            ..MODULE_A
        };
        assert_eq!(
            ModuleCatalog::new([&LEAF_OVERCLAIM_MODULE]).err().unwrap(),
            ModuleCatalogError::UnsupportedOperationCapabilities(OperationId {
                format: crate::synthetic::ID_B38504826C7B,
                name: "decode-image",
            })
        );

        const WRONG_OWNER_PROVIDER: ResidentWriterProvider = ResidentWriterProvider {
            owner: "other-owner",
            ..EDIT_PROVIDER
        };
        const WRONG_OWNER_OPERATION: ModuleOperation = ModuleOperation {
            executable: ExistingExecutableOperation::ResidentWriter(&WRONG_OWNER_PROVIDER),
            ..EDIT_OPERATION
        };
        static WRONG_OWNER_MODULE: FormatModule = FormatModule {
            operations: &[
                PARSE_OPERATION,
                REPRO_OPERATION,
                WRONG_OWNER_OPERATION,
                AUTHOR_OPERATION,
            ],
            ..WRITER_MODULE
        };
        assert!(matches!(
            ModuleCatalog::new([&WRONG_OWNER_MODULE]),
            Err(ModuleCatalogError::OwnerDisagreement {
                declared_owner: "other-owner",
                ..
            })
        ));

        const WRONG_ID_PROVIDER: ResidentWriterProvider = ResidentWriterProvider {
            id: crate::synthetic::ID_71C0E0E93923,
            ..EDIT_PROVIDER
        };
        const WRONG_ID_OPERATION: ModuleOperation = ModuleOperation {
            executable: ExistingExecutableOperation::ResidentWriter(&WRONG_ID_PROVIDER),
            ..EDIT_OPERATION
        };
        static WRONG_ID_MODULE: FormatModule = FormatModule {
            operations: &[
                PARSE_OPERATION,
                REPRO_OPERATION,
                WRONG_ID_OPERATION,
                AUTHOR_OPERATION,
            ],
            ..WRITER_MODULE
        };
        assert_eq!(
            ModuleCatalog::new([&WRONG_ID_MODULE]).err().unwrap(),
            ModuleCatalogError::IdentityDisagreement {
                module: crate::synthetic::ID_B38504826C7B,
                contributed: crate::synthetic::ID_71C0E0E93923,
            }
        );

        const WRONG_CAPABILITY_OPERATION: ModuleOperation = ModuleOperation {
            capabilities: OperationCapabilities::WRITE,
            ..EDIT_OPERATION
        };
        static WRONG_CAPABILITY_MODULE: FormatModule = FormatModule {
            operations: &[
                PARSE_OPERATION,
                REPRO_OPERATION,
                WRONG_CAPABILITY_OPERATION,
                AUTHOR_OPERATION,
            ],
            ..WRITER_MODULE
        };
        assert_eq!(
            ModuleCatalog::new([&WRONG_CAPABILITY_MODULE])
                .err()
                .unwrap(),
            ModuleCatalogError::UnsupportedOperationCapabilities(OperationId {
                format: crate::synthetic::ID_B38504826C7B,
                name: "edit",
            })
        );

        const INVALID_SCHEMA: InputSchema<'static> = InputSchema {
            forms: &[],
            relationships: &[],
        };
        const INVALID_SCHEMA_OPERATION: ModuleOperation = ModuleOperation {
            input_schema: &INVALID_SCHEMA,
            ..EDIT_OPERATION
        };
        static INVALID_SCHEMA_MODULE: FormatModule = FormatModule {
            operations: &[
                PARSE_OPERATION,
                REPRO_OPERATION,
                INVALID_SCHEMA_OPERATION,
                AUTHOR_OPERATION,
            ],
            ..WRITER_MODULE
        };
        assert_eq!(
            ModuleCatalog::new([&INVALID_SCHEMA_MODULE]).err().unwrap(),
            ModuleCatalogError::InvalidInputSchema(OperationId {
                format: crate::synthetic::ID_B38504826C7B,
                name: "edit",
            })
        );
    }

    fn complete_limits() -> WorkLimits {
        WorkLimits::unlimited()
            .with(WorkResource::MaterializedBytes, 4)
            .with(WorkResource::OutputBytes, 4)
            .with(WorkResource::Nodes, 1)
            .with(WorkResource::LogicalReadBytes, 4)
            .with(WorkResource::IoRequestedBytes, 4)
            .with(WorkResource::IoReadCalls, 1)
            .with_resident_bytes(4)
    }

    fn build_with_read(budget: &mut WorkBudget) -> Result<ResidentWriteOutput<'_>> {
        ResidentWriteOutput::build(budget, 4, |bytes, budget| {
            budget.charge(WorkResource::LogicalReadBytes, 4)?;
            budget.read_external_exact_into(&mut Cursor::new(*b"DATA"), bytes)
        })
    }

    #[test]
    fn every_resource_dimension_has_exact_and_one_short_admission() {
        let mut exact = WorkBudget::new(complete_limits());
        let mut output = build_with_read(&mut exact).unwrap();
        assert_eq!(output.bytes(), b"DATA");
        let mut published = Vec::new();
        output.write_to(&mut published).unwrap();
        assert_eq!(published, b"DATA");
        drop(output);
        let usage = exact.usage();
        assert_eq!(usage.spent(WorkResource::MaterializedBytes), 4);
        assert_eq!(usage.spent(WorkResource::OutputBytes), 4);
        assert_eq!(usage.spent(WorkResource::Nodes), 1);
        assert_eq!(usage.spent(WorkResource::LogicalReadBytes), 4);
        assert_eq!(usage.spent(WorkResource::IoRequestedBytes), 4);
        assert_eq!(usage.spent(WorkResource::IoReadCalls), 1);
        assert_eq!(usage.io_completed_bytes(), 4);
        assert_eq!(usage.peak_resident_bytes(), 4);
        assert!(usage.complete_io_accounting());

        let one_short = [
            (WorkResource::MaterializedBytes, 3),
            (WorkResource::Nodes, 0),
            (WorkResource::LogicalReadBytes, 3),
            (WorkResource::IoRequestedBytes, 3),
            (WorkResource::IoReadCalls, 0),
        ];
        for (resource, limit) in one_short {
            let mut budget = WorkBudget::new(complete_limits().with(resource, limit));
            assert!(matches!(
                build_with_read(&mut budget),
                Err(Error::ResourceLimit { resource: denied, .. }) if denied == resource.label()
            ));
            assert_eq!(budget.usage().resident_bytes(), 0);
        }
        let mut resident = WorkBudget::new(complete_limits().with_resident_bytes(3));
        assert!(matches!(
            build_with_read(&mut resident),
            Err(Error::ResourceLimit {
                resource: "resident bytes",
                ..
            })
        ));
        assert_eq!(resident.usage().resident_bytes(), 0);

        let mut failed = WorkBudget::new(complete_limits());
        assert!(matches!(
            ResidentWriteOutput::build(&mut failed, 4, |_, _| {
                Err(Error::Malformed("injected writer failure".into()))
            }),
            Err(Error::Malformed(message)) if message == "injected writer failure"
        ));
        let failed = failed.usage();
        assert_eq!(failed.spent(WorkResource::MaterializedBytes), 4);
        assert_eq!(failed.spent(WorkResource::Nodes), 1);
        assert_eq!(failed.spent(WorkResource::OutputBytes), 0);
        assert_eq!(failed.resident_bytes(), 0);
        assert_eq!(failed.peak_resident_bytes(), 4);
    }

    struct CountWrites {
        calls: usize,
        bytes: Vec<u8>,
    }

    impl Write for CountWrites {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.calls += 1;
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct FailsAfter {
        bytes: Vec<u8>,
        limit: usize,
    }

    impl Write for FailsAfter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.bytes.len() == self.limit {
                return Err(std::io::Error::other("injected destination failure"));
            }
            let count = bytes.len().min(self.limit - self.bytes.len());
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct WritesZero;

    impl Write for WritesZero {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Ok(0)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn publication_has_exact_preflight_and_partial_write_accounting() {
        let mut exact = WorkBudget::new(complete_limits());
        let mut output = ResidentWriteOutput::build(&mut exact, 4, |bytes, _| {
            bytes.copy_from_slice(b"DATA");
            Ok(())
        })
        .unwrap();
        let mut destination = CountWrites {
            calls: 0,
            bytes: Vec::new(),
        };
        output.write_to(&mut destination).unwrap();
        assert_eq!(destination.bytes, b"DATA");
        assert_eq!(destination.calls, 1);
        output
            .with_output_and_budget::<_, Error>(|_, budget| {
                assert_eq!(budget.spent(WorkResource::OutputBytes), 4);
                assert_eq!(budget.usage().resident_bytes(), 4);
                Ok(())
            })
            .unwrap();
        drop(output);

        let mut one_short = WorkBudget::new(complete_limits().with(WorkResource::OutputBytes, 3));
        let mut output = ResidentWriteOutput::build(&mut one_short, 4, |bytes, _| {
            bytes.copy_from_slice(b"DATA");
            Ok(())
        })
        .unwrap();
        let mut destination = CountWrites {
            calls: 0,
            bytes: Vec::new(),
        };
        assert!(matches!(
            output.write_to(&mut destination),
            Err(ResidentWriteError::Work(Error::ResourceLimit {
                resource: "output bytes",
                requested: 4,
                limit: 3,
            }))
        ));
        assert_eq!(destination.calls, 0);
        assert!(destination.bytes.is_empty());
        drop(output);
        assert_eq!(one_short.spent(WorkResource::OutputBytes), 0);

        let mut partial = WorkBudget::new(complete_limits());
        let mut output = ResidentWriteOutput::build(&mut partial, 4, |bytes, _| {
            bytes.copy_from_slice(b"DATA");
            Ok(())
        })
        .unwrap();
        let mut destination = FailsAfter {
            bytes: Vec::new(),
            limit: 2,
        };
        assert!(matches!(
            output.write_to(&mut destination),
            Err(ResidentWriteError::Write(error))
                if error.to_string() == "injected destination failure"
        ));
        assert_eq!(destination.bytes, b"DA");
        output
            .with_output_and_budget::<_, Error>(|_, budget| {
                assert_eq!(budget.spent(WorkResource::OutputBytes), 2);
                assert_eq!(budget.usage().resident_bytes(), 4);
                Ok(())
            })
            .unwrap();

        let mut write_zero = WorkBudget::new(complete_limits());
        let mut output = ResidentWriteOutput::build(&mut write_zero, 4, |bytes, _| {
            bytes.copy_from_slice(b"DATA");
            Ok(())
        })
        .unwrap();
        assert!(matches!(
            output.write_to(&mut WritesZero),
            Err(ResidentWriteError::Write(error))
                if error.kind() == std::io::ErrorKind::WriteZero
        ));
        drop(output);
        assert_eq!(write_zero.spent(WorkResource::OutputBytes), 0);
    }

    struct CancelAfterWrite {
        token: CancellationToken,
        fail: bool,
        bytes: Vec<u8>,
    }

    impl Write for CancelAfterWrite {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.token.cancel();
            if self.fail {
                return Err(std::io::Error::other("cancelled destination failure"));
            }
            let count = bytes.len().min(2);
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn publication_cancellation_preserves_completed_bytes_and_error_precedence() {
        let token = CancellationToken::new();
        let mut budget = WorkBudget::new(complete_limits()).with_cancellation(token.clone());
        let mut output = ResidentWriteOutput::build(&mut budget, 4, |bytes, _| {
            bytes.copy_from_slice(b"DATA");
            Ok(())
        })
        .unwrap();
        let mut destination = CancelAfterWrite {
            token,
            fail: false,
            bytes: Vec::new(),
        };
        assert!(matches!(
            output.write_to(&mut destination),
            Err(ResidentWriteError::Work(Error::Cancelled))
        ));
        assert_eq!(destination.bytes, b"DA");
        output
            .with_output_and_budget::<_, Error>(|_, budget| {
                assert_eq!(budget.spent(WorkResource::OutputBytes), 2);
                assert!(budget.usage().cancellation_observed());
                Ok(())
            })
            .unwrap();

        let token = CancellationToken::new();
        let mut budget = WorkBudget::new(complete_limits()).with_cancellation(token.clone());
        let mut output = ResidentWriteOutput::build(&mut budget, 4, |bytes, _| {
            bytes.copy_from_slice(b"DATA");
            Ok(())
        })
        .unwrap();
        let mut destination = CancelAfterWrite {
            token,
            fail: true,
            bytes: Vec::new(),
        };
        assert!(matches!(
            output.write_to(&mut destination),
            Err(ResidentWriteError::Write(error))
                if error.to_string() == "cancelled destination failure"
        ));
        output
            .with_output_and_budget::<_, Error>(|_, budget| {
                assert_eq!(budget.spent(WorkResource::OutputBytes), 0);
                assert!(budget.usage().cancellation_observed());
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn cancellation_drop_replacement_and_unwind_preserve_guard_truth() {
        let token = CancellationToken::new();
        token.cancel();
        let mut cancelled = WorkBudget::new(complete_limits()).with_cancellation(token);
        assert!(matches!(
            build_with_read(&mut cancelled),
            Err(Error::Cancelled)
        ));
        assert_eq!(cancelled.spent(WorkResource::MaterializedBytes), 0);

        let token = CancellationToken::new();
        let mut cancelled_after_fill =
            WorkBudget::new(complete_limits()).with_cancellation(token.clone());
        assert!(matches!(
            ResidentWriteOutput::build(&mut cancelled_after_fill, 4, |_, _| {
                token.cancel();
                Ok(())
            }),
            Err(Error::Cancelled)
        ));
        assert_eq!(
            cancelled_after_fill.spent(WorkResource::MaterializedBytes),
            4
        );
        assert_eq!(cancelled_after_fill.spent(WorkResource::OutputBytes), 0);
        assert_eq!(cancelled_after_fill.usage().resident_bytes(), 0);
        assert!(cancelled_after_fill.usage().cancellation_observed());

        let token = CancellationToken::new();
        let mut operation_error =
            WorkBudget::new(complete_limits()).with_cancellation(token.clone());
        assert!(matches!(
            ResidentWriteOutput::build(&mut operation_error, 4, |_, _| {
                token.cancel();
                Err(Error::Malformed("operation wins".into()))
            }),
            Err(Error::Malformed(message)) if message == "operation wins"
        ));
        assert!(operation_error.usage().cancellation_observed());
        assert_eq!(operation_error.spent(WorkResource::OutputBytes), 0);

        let mut replaced = WorkBudget::new(complete_limits());
        let mut output = ResidentWriteOutput::build(&mut replaced, 4, |bytes, _| {
            bytes.copy_from_slice(b"DATA");
            Ok(())
        })
        .unwrap();
        let error = output
            .with_output_and_budget::<_, Error>(|_, budget| {
                *budget = WorkBudget::new(WorkLimits::unlimited());
                Ok(())
            })
            .unwrap_err();
        assert!(
            matches!(error, Error::Malformed(message) if message.contains("ledger was replaced"))
        );
        drop(output);
        assert!(!replaced.usage().complete_resident_accounting());
        assert_eq!(replaced.usage().resident_bytes(), 0);

        let mut unwound = WorkBudget::new(complete_limits());
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let mut output = ResidentWriteOutput::build(&mut unwound, 4, |_, _| Ok(())).unwrap();
            let _: Result<()> = output.with_output_and_budget(|_, _| panic!("injected"));
        }));
        assert!(panic.is_err());
        assert_eq!(unwound.usage().resident_bytes(), 0);
        assert!(unwound.usage().complete_resident_accounting());
    }
}

const TIM_DESCRIPTOR: FormatDescriptor = FormatDescriptor {
    id: crate::synthetic::ID_B38504826C7B,
    category: Category::Image,
    decoder: Some("owner-a"),
    precedence: 100,
    probes: TIM_PROBES,
    extension_hints: &["synthetic-id-b38504826c7b"],
    requirement: DecoderRequirement::None,
    ambiguity_group: None,
    capabilities: capabilities(),
};
const VAG_DESCRIPTOR: FormatDescriptor = FormatDescriptor {
    id: crate::synthetic::ID_71C0E0E93923,
    category: Category::Audio,
    decoder: Some("owner-b"),
    precedence: 100,
    probes: VAG_PROBES,
    extension_hints: &["synthetic-id-71c0e0e93923"],
    requirement: DecoderRequirement::None,
    ambiguity_group: None,
    capabilities: FormatCapabilities {
        parse: false,
        decode: false,
        ..capabilities()
    },
};

fn decode(_bytes: &[u8], _request: LeafDecodeRequest) -> Result<Vec<LeafOutput>> {
    Ok(Vec::new())
}

const ORACLE: CargoTestOracle =
    CargoTestOracle::lib("formatkit-runtime", "tests::module_order_is_stable");
const LEAF: LeafOperationProvider = LeafOperationProvider {
    contract: LeafOperationContract {
        id: crate::synthetic::ID_B38504826C7B,
        input: LeafInputContract::file("file"),
        selection: LeafSelectionContract::NONE,
        output: LeafOutputContract {
            kind: LeafOutputKind::RgbaImage,
            multiplicity: LeafOutputMultiplicity::One,
        },
        max_input_bytes: 1024,
        default_limits: LeafDecodeLimits {
            max_output_bytes: 1024,
            max_work_bytes: 1024,
        },
        max_limits: LeafDecodeLimits {
            max_output_bytes: 2048,
            max_work_bytes: 2048,
        },
        oracle: ORACLE,
    },
    decode,
    decode_budgeted: None,
    decode_budgeted_source: None,
    decode_budgeted_file: None,
};
const FILE_ROLES: &[ByteRole] = &[ByteRole::one("file")];
const FILE_FORMS: &[InputForm<'static>] = &[InputForm {
    name: "file",
    bytes: FILE_ROLES,
    selectors: &[],
}];
const FILE_SCHEMA: InputSchema<'static> = InputSchema {
    forms: FILE_FORMS,
    relationships: &[],
};
const LEAF_OPERATION: ModuleOperation = ModuleOperation {
    name: "decode-image",
    purpose: "decode a selected image",
    owner: "owner-a",
    capabilities: OperationCapabilities::PARSE.union(OperationCapabilities::DECODE),
    input_schema: &FILE_SCHEMA,
    bound_namespace: None,
    executable: ExistingExecutableOperation::Leaf(&LEAF),
};

static MODULE_A: FormatModule = FormatModule {
    format: crate::synthetic::ID_B38504826C7B,
    owner: "owner-a",
    state: ModuleState::Strict,
    descriptor: Some(&TIM_DESCRIPTOR),
    embedded_support: None,
    writer_contract: None,
    namespace_semantics: None,
    operations: &[LEAF_OPERATION],
};
static MODULE_B: FormatModule = FormatModule {
    format: crate::synthetic::ID_71C0E0E93923,
    owner: "owner-b",
    state: ModuleState::Strict,
    descriptor: Some(&VAG_DESCRIPTOR),
    embedded_support: None,
    writer_contract: None,
    namespace_semantics: None,
    operations: &[],
};

const OWNER_DEFINED_ID: FormatId = FormatId::new("owner.custom-format.v2");
const OWNER_DEFINED_DESCRIPTOR: FormatDescriptor = FormatDescriptor {
    id: OWNER_DEFINED_ID,
    category: Category::Unknown,
    decoder: None,
    precedence: 1,
    probes: &[Probe::Magic {
        offset: 0,
        bytes: b"OWNR",
    }],
    extension_hints: &[],
    requirement: DecoderRequirement::None,
    ambiguity_group: None,
    capabilities: FormatCapabilities {
        parse: false,
        decode: false,
        edit: false,
        write: false,
        round_trip: false,
        corpus: false,
        bindings: false,
        confidence: Confidence::ExactMagic,
    },
};
static OWNER_DEFINED_MODULE: FormatModule = FormatModule {
    format: OWNER_DEFINED_ID,
    owner: "owner-custom",
    state: ModuleState::Strict,
    descriptor: Some(&OWNER_DEFINED_DESCRIPTOR),
    embedded_support: None,
    writer_contract: None,
    namespace_semantics: None,
    operations: &[],
};

#[test]
fn owner_crates_can_define_typed_ids_without_a_detect_constant() {
    let catalog = ModuleCatalog::new([&OWNER_DEFINED_MODULE]).unwrap();
    assert_eq!(
        catalog.module(OWNER_DEFINED_ID).map(|module| module.owner),
        Some("owner-custom")
    );
}

#[test]
fn malformed_and_unknown_module_identities_are_typed_errors() {
    const MALFORMED: FormatId = FormatId::new("owner..malformed");
    const MALFORMED_DESCRIPTOR: FormatDescriptor = FormatDescriptor {
        id: MALFORMED,
        ..OWNER_DEFINED_DESCRIPTOR
    };
    static MALFORMED_MODULE: FormatModule = FormatModule {
        format: MALFORMED,
        descriptor: Some(&MALFORMED_DESCRIPTOR),
        ..OWNER_DEFINED_MODULE
    };
    static UNKNOWN_MODULE: FormatModule = FormatModule {
        format: FormatId::UNKNOWN,
        ..OWNER_DEFINED_MODULE
    };
    static MALFORMED_CONTRIBUTION: FormatModule = FormatModule {
        descriptor: Some(&MALFORMED_DESCRIPTOR),
        ..OWNER_DEFINED_MODULE
    };
    const MALFORMED_CARRIER_SUPPORT: EmbeddedFormatSupport = EmbeddedFormatSupport {
        id: OWNER_DEFINED_ID,
        detectable_carrier: Some(MALFORMED),
        family: FormatFamilyId::new("synthetic-family-0"),
        decoder: "owner-custom",
        context: ContextRequirement::ExplicitSelection,
        local_discriminator: "owner-custom",
        dialect_group: None,
        typed_context: true,
        capabilities: OWNER_DEFINED_DESCRIPTOR.capabilities,
        corpus_evidence: None,
    };
    static MALFORMED_CARRIER: FormatModule = FormatModule {
        embedded_support: Some(&MALFORMED_CARRIER_SUPPORT),
        ..OWNER_DEFINED_MODULE
    };

    assert_eq!(
        ModuleCatalog::new([&MALFORMED_MODULE]).err().unwrap(),
        ModuleCatalogError::InvalidFormatId(MALFORMED)
    );
    assert_eq!(
        ModuleCatalog::new([&UNKNOWN_MODULE]).err().unwrap(),
        ModuleCatalogError::InvalidFormatId(FormatId::UNKNOWN)
    );
    assert_eq!(
        ModuleCatalog::new([&MALFORMED_CONTRIBUTION]).err().unwrap(),
        ModuleCatalogError::InvalidFormatId(MALFORMED)
    );
    assert_eq!(
        ModuleCatalog::new([&MALFORMED_CARRIER]).err().unwrap(),
        ModuleCatalogError::InvalidFormatId(MALFORMED)
    );
}

#[test]
fn duplicate_module_and_named_operation_ids_are_rejected() {
    assert_eq!(
        ModuleCatalog::new([&MODULE_A, &MODULE_A]).err().unwrap(),
        ModuleCatalogError::DuplicateModule(crate::synthetic::ID_B38504826C7B)
    );
    const DUPLICATE: ModuleOperation = ModuleOperation { ..LEAF_OPERATION };
    static DUPLICATE_OPERATIONS: FormatModule = FormatModule {
        operations: &[LEAF_OPERATION, DUPLICATE],
        ..MODULE_A
    };
    assert_eq!(
        ModuleCatalog::new([&DUPLICATE_OPERATIONS]).err().unwrap(),
        ModuleCatalogError::DuplicateOperation(OperationId {
            format: crate::synthetic::ID_B38504826C7B,
            name: "decode-image",
        })
    );
}

#[test]
fn module_order_is_stable_and_lookup_uses_open_names() {
    let left = ModuleCatalog::new([&MODULE_A, &MODULE_B]).unwrap();
    let right = ModuleCatalog::new([&MODULE_B, &MODULE_A]).unwrap();
    let module_ids = |catalog: &ModuleCatalog| {
        catalog
            .modules()
            .iter()
            .map(|module| module.format)
            .collect::<Vec<_>>()
    };
    let operation_ids =
        |catalog: &ModuleCatalog| catalog.operations().map(|(id, _)| id).collect::<Vec<_>>();
    assert_eq!(module_ids(&left), module_ids(&right));
    assert_eq!(operation_ids(&left), operation_ids(&right));
    assert_eq!(
        left.module(crate::synthetic::ID_71C0E0E93923)
            .map(|module| module.owner),
        Some("owner-b")
    );
    assert_eq!(
        left.operation(OperationId {
            format: crate::synthetic::ID_B38504826C7B,
            name: "decode-image"
        })
        .map(|operation| operation.purpose),
        Some("decode a selected image")
    );
}

#[test]
fn identity_owner_and_missing_support_are_rejected() {
    static WRONG_ID: FormatModule = FormatModule {
        format: crate::synthetic::ID_71C0E0E93923,
        owner: "owner-a",
        descriptor: Some(&TIM_DESCRIPTOR),
        ..MODULE_B
    };
    assert_eq!(
        ModuleCatalog::new([&WRONG_ID]).err().unwrap(),
        ModuleCatalogError::IdentityDisagreement {
            module: crate::synthetic::ID_71C0E0E93923,
            contributed: crate::synthetic::ID_B38504826C7B,
        }
    );
    static WRONG_OWNER: FormatModule = FormatModule {
        owner: "other",
        ..MODULE_A
    };
    assert_eq!(
        ModuleCatalog::new([&WRONG_OWNER]).err().unwrap(),
        ModuleCatalogError::OwnerDisagreement {
            format: crate::synthetic::ID_B38504826C7B,
            module_owner: "other",
            declared_owner: "owner-a",
        }
    );
    static NO_SUPPORT: FormatModule = FormatModule {
        descriptor: None,
        operations: &[LEAF_OPERATION],
        ..MODULE_A
    };
    assert_eq!(
        ModuleCatalog::new([&NO_SUPPORT]).err().unwrap(),
        ModuleCatalogError::MissingSupportIdentity(crate::synthetic::ID_B38504826C7B)
    );
    const WRONG_OPERATION_OWNER: ModuleOperation = ModuleOperation {
        owner: "other",
        ..LEAF_OPERATION
    };
    static WRONG_OPERATION_OWNER_MODULE: FormatModule = FormatModule {
        operations: &[WRONG_OPERATION_OWNER],
        ..MODULE_A
    };
    assert_eq!(
        ModuleCatalog::new([&WRONG_OPERATION_OWNER_MODULE])
            .err()
            .unwrap(),
        ModuleCatalogError::OwnerDisagreement {
            format: crate::synthetic::ID_B38504826C7B,
            module_owner: "owner-a",
            declared_owner: "other",
        }
    );
}

const WRITER_CLAIM: FormatDescriptor = FormatDescriptor {
    capabilities: FormatCapabilities {
        edit: true,
        ..capabilities()
    },
    ..TIM_DESCRIPTOR
};
static STRICT_WRITER_CLAIM: FormatModule = FormatModule {
    descriptor: Some(&WRITER_CLAIM),
    operations: &[LEAF_OPERATION],
    ..MODULE_A
};
static LEGACY_WRITER_CLAIM: FormatModule = FormatModule {
    state: ModuleState::Legacy,
    ..STRICT_WRITER_CLAIM
};

#[test]
fn strict_writer_claim_needs_callable_planner_but_legacy_debt_remains_visible() {
    assert_eq!(
        ModuleCatalog::new([&STRICT_WRITER_CLAIM]).err().unwrap(),
        ModuleCatalogError::StrictCapabilityDisagreement(crate::synthetic::ID_B38504826C7B)
    );
    let legacy = ModuleCatalog::new([&LEGACY_WRITER_CLAIM]).unwrap();
    assert_eq!(legacy.legacy_module_count(), 1);
    assert_eq!(legacy.legacy_operation_count(), 1);
    assert_eq!(legacy.operations().len(), 0);
    assert!(legacy
        .operation(OperationId {
            format: crate::synthetic::ID_B38504826C7B,
            name: "decode-image",
        })
        .is_none());
    let legacy_provider = legacy
        .leaf_operations()
        .provider(crate::synthetic::ID_B38504826C7B)
        .expect("legacy callback remains in compatibility projection");
    assert!((legacy_provider.decode)(
        &[],
        LeafDecodeRequest {
            selection: Default::default(),
            limits: legacy_provider.contract.default_limits,
        },
    )
    .unwrap()
    .is_empty());
}

#[test]
fn strict_named_operation_without_valid_proof_is_rejected() {
    const UNPROVED_LEAF: LeafOperationProvider = LeafOperationProvider {
        contract: LeafOperationContract {
            oracle: CargoTestOracle::lib("formatkit-runtime", ""),
            ..LEAF.contract
        },
        decode,
        decode_budgeted: None,
        decode_budgeted_source: None,
        decode_budgeted_file: None,
    };
    const UNPROVED_OPERATION: ModuleOperation = ModuleOperation {
        name: "unproved-decode",
        purpose: "operation with no resolvable proof selector",
        owner: "owner-a",
        capabilities: OperationCapabilities::PARSE.union(OperationCapabilities::DECODE),
        input_schema: &FILE_SCHEMA,
        bound_namespace: None,
        executable: ExistingExecutableOperation::Leaf(&UNPROVED_LEAF),
    };
    static UNPROVED_MODULE: FormatModule = FormatModule {
        operations: &[UNPROVED_OPERATION],
        ..MODULE_A
    };
    assert_eq!(
        ModuleCatalog::new([&UNPROVED_MODULE]).err().unwrap(),
        ModuleCatalogError::InvalidLeafCatalog
    );
}

#[test]
fn proof_resolution_is_an_external_strict_activation_gate() {
    const UNRESOLVED_LEAF: LeafOperationProvider = LeafOperationProvider {
        contract: LeafOperationContract {
            oracle: CargoTestOracle::lib(
                "syntactically-valid-but-missing-package",
                "missing::exact_test",
            ),
            ..LEAF.contract
        },
        decode,
        decode_budgeted: None,
        decode_budgeted_source: None,
        decode_budgeted_file: None,
    };
    const UNRESOLVED_OPERATION: ModuleOperation = ModuleOperation {
        executable: ExistingExecutableOperation::Leaf(&UNRESOLVED_LEAF),
        ..LEAF_OPERATION
    };
    static UNRESOLVED_MODULE: FormatModule = FormatModule {
        operations: &[UNRESOLVED_OPERATION],
        ..MODULE_A
    };
    assert!(ModuleCatalog::new([&UNRESOLVED_MODULE]).is_ok());
}

#[test]
fn strict_parse_and_decode_claims_require_typed_executable_operations() {
    const PARSE_ONLY: FormatDescriptor = FormatDescriptor {
        capabilities: FormatCapabilities {
            decode: false,
            ..capabilities()
        },
        ..TIM_DESCRIPTOR
    };
    static PARSE_WITHOUT_CALLBACK: FormatModule = FormatModule {
        descriptor: Some(&PARSE_ONLY),
        operations: &[],
        ..MODULE_A
    };
    static DECODE_WITHOUT_CALLBACK: FormatModule = FormatModule {
        operations: &[],
        ..MODULE_A
    };
    const DECODE_NAMESPACE: ModuleOperation = ModuleOperation {
        capabilities: OperationCapabilities::PARSE.union(OperationCapabilities::DECODE),
        ..MATCHED_NAMESPACE
    };
    static DECODE_WITH_NAMESPACE_ONLY: FormatModule = FormatModule {
        namespace_semantics: Some(&NAMESPACE_SEMANTICS),
        operations: &[DECODE_NAMESPACE],
        ..MODULE_A
    };
    assert_eq!(
        ModuleCatalog::new([&PARSE_WITHOUT_CALLBACK]).err().unwrap(),
        ModuleCatalogError::StrictCapabilityDisagreement(crate::synthetic::ID_B38504826C7B)
    );
    assert_eq!(
        ModuleCatalog::new([&DECODE_WITHOUT_CALLBACK])
            .err()
            .unwrap(),
        ModuleCatalogError::StrictCapabilityDisagreement(crate::synthetic::ID_B38504826C7B)
    );
    assert!(ModuleCatalog::new([&DECODE_WITH_NAMESPACE_ONLY]).is_ok());
    assert!(ModuleCatalog::new([&MODULE_B]).is_ok());
}

#[test]
fn strict_capabilities_reject_overclaims_and_undeclared_operations() {
    const PARSE_ONLY_DESCRIPTOR: FormatDescriptor = FormatDescriptor {
        capabilities: FormatCapabilities {
            decode: false,
            ..capabilities()
        },
        ..TIM_DESCRIPTOR
    };
    const PARSE_ONLY_OPERATION: ModuleOperation = ModuleOperation {
        capabilities: OperationCapabilities::PARSE,
        ..LEAF_OPERATION
    };
    static DECODE_OVERCLAIM: FormatModule = FormatModule {
        operations: &[PARSE_ONLY_OPERATION],
        ..MODULE_A
    };
    assert_eq!(
        ModuleCatalog::new([&DECODE_OVERCLAIM]).err().unwrap(),
        ModuleCatalogError::StrictCapabilityDisagreement(crate::synthetic::ID_B38504826C7B)
    );

    static UNDECLARED_DECODE: FormatModule = FormatModule {
        descriptor: Some(&PARSE_ONLY_DESCRIPTOR),
        operations: &[LEAF_OPERATION],
        ..MODULE_A
    };
    assert_eq!(
        ModuleCatalog::new([&UNDECLARED_DECODE]).err().unwrap(),
        ModuleCatalogError::StrictCapabilityDisagreement(crate::synthetic::ID_B38504826C7B)
    );

    const UNSUPPORTED_WRITER_OPERATION: ModuleOperation = ModuleOperation {
        capabilities: OperationCapabilities::EDIT,
        ..LEAF_OPERATION
    };
    static UNSUPPORTED_WRITER_MODULE: FormatModule = FormatModule {
        operations: &[UNSUPPORTED_WRITER_OPERATION],
        ..MODULE_A
    };
    assert_eq!(
        ModuleCatalog::new([&UNSUPPORTED_WRITER_MODULE])
            .err()
            .unwrap(),
        ModuleCatalogError::UnsupportedOperationCapabilities(OperationId {
            format: crate::synthetic::ID_B38504826C7B,
            name: "decode-image",
        })
    );

    const UNDECLARED_OPERATION: ModuleOperation = ModuleOperation {
        capabilities: OperationCapabilities::NONE,
        ..LEAF_OPERATION
    };
    static UNDECLARED_OPERATION_MODULE: FormatModule = FormatModule {
        state: ModuleState::Legacy,
        operations: &[UNDECLARED_OPERATION],
        ..MODULE_A
    };
    assert_eq!(
        ModuleCatalog::new([&UNDECLARED_OPERATION_MODULE])
            .err()
            .unwrap(),
        ModuleCatalogError::UnsupportedOperationCapabilities(OperationId {
            format: crate::synthetic::ID_B38504826C7B,
            name: "decode-image",
        })
    );
}

#[test]
fn descriptor_and_embedded_capabilities_must_agree() {
    const EMBEDDED: EmbeddedFormatSupport = EmbeddedFormatSupport {
        id: crate::synthetic::ID_B38504826C7B,
        detectable_carrier: Some(crate::synthetic::ID_B38504826C7B),
        family: FormatFamilyId::new("synthetic-family-0"),
        decoder: "owner-a",
        context: ContextRequirement::ExplicitSelection,
        local_discriminator: "tim-overlay",
        dialect_group: None,
        typed_context: true,
        capabilities: FormatCapabilities {
            decode: false,
            ..capabilities()
        },
        corpus_evidence: None,
    };
    static DISAGREEMENT: FormatModule = FormatModule {
        embedded_support: Some(&EMBEDDED),
        ..MODULE_A
    };
    assert_eq!(
        ModuleCatalog::new([&DISAGREEMENT]).err().unwrap(),
        ModuleCatalogError::CapabilityDisagreement(crate::synthetic::ID_B38504826C7B)
    );
}

fn mount(
    _source: std::sync::Arc<dyn RangeSource>,
    _budget: &mut ReadBudget,
) -> Result<Box<dyn IndexedNamespace>> {
    Err(Error::Unsupported("test mount".into()))
}

fn bound_mount(
    _sources: &formatkit_core::SourceBindings,
    _bound: &formatkit_catalog::catalog::BoundInputs,
    _prefix: &[u8],
    _budget: &mut formatkit_core::WorkBudget,
) -> Result<formatkit_catalog::catalog::SourceProbeOutcome<Box<dyn IndexedNamespace>>> {
    Ok(formatkit_catalog::catalog::SourceProbeOutcome::Mismatch)
}

const NAMESPACE_ROLES: &[ByteRole] = &[ByteRole::one("carrier")];
const NAMESPACE_FORMS: &[InputForm<'static>] = &[InputForm {
    name: "single",
    bytes: NAMESPACE_ROLES,
    selectors: &[],
}];
const NAMESPACE_SCHEMA: InputSchema<'static> = InputSchema {
    forms: NAMESPACE_FORMS,
    relationships: &[],
};

const NAMESPACE_CONTRACT: NamespaceMountContract = NamespaceMountContract {
    id: crate::synthetic::ID_B38504826C7B,
    input: NamespaceMountInput::SingleSource { role: "carrier" },
    strategy: NamespaceMountStrategy::MetadataOnly,
    parser_parity_oracle: ORACLE,
    independent_layout_oracle: ORACLE,
    budget_oracle: ORACLE,
    stability_oracle: ORACLE,
    dispatch_oracle: ORACLE,
    malformed_oracle: ORACLE,
    collision: None,
    cli_oracle: ORACLE,
    corpus_oracle: None,
};
const MISMATCHED_PROVIDER: NamespaceProvider = NamespaceProvider {
    id: crate::synthetic::ID_B38504826C7B,
    owner: "owner-a",
    input: NamespaceMountInput::SingleSource { role: "carrier" },
    strategy: NamespaceMountStrategy::WholeCarrier,
    mount: NamespaceProviderMount::Single(mount),
    source_probe: None,
    work_source_probe: None,
    early_probe_prefix: None,
};
const MATCHED_PROVIDER: NamespaceProvider = NamespaceProvider {
    strategy: NamespaceMountStrategy::MetadataOnly,
    ..MISMATCHED_PROVIDER
};
const MISMATCHED_NAMESPACE: ModuleOperation = ModuleOperation {
    name: "mount",
    purpose: "mount members",
    owner: "owner-a",
    capabilities: OperationCapabilities::PARSE,
    input_schema: &NAMESPACE_SCHEMA,
    bound_namespace: Some(bound_mount),
    executable: ExistingExecutableOperation::Namespace {
        contract: &NAMESPACE_CONTRACT,
        provider: &MISMATCHED_PROVIDER,
    },
};
static MISMATCHED_MODULE: FormatModule = FormatModule {
    operations: &[MISMATCHED_NAMESPACE],
    ..MODULE_A
};

const PARSE_NAMESPACE_DESCRIPTOR: FormatDescriptor = FormatDescriptor {
    capabilities: FormatCapabilities {
        decode: false,
        ..capabilities()
    },
    ..TIM_DESCRIPTOR
};
const MATCHED_NAMESPACE: ModuleOperation = ModuleOperation {
    name: "mount",
    purpose: "mount members",
    owner: "owner-a",
    capabilities: OperationCapabilities::PARSE,
    input_schema: &NAMESPACE_SCHEMA,
    bound_namespace: Some(bound_mount),
    executable: ExistingExecutableOperation::Namespace {
        contract: &NAMESPACE_CONTRACT,
        provider: &MATCHED_PROVIDER,
    },
};
const NAMESPACE_SEMANTICS: NamespaceSemantics = NamespaceSemantics::carrier(
    crate::synthetic::ID_B38504826C7B,
    NamespaceAddressing::DirectRanges,
);
static PARSE_NAMESPACE_MODULE: FormatModule = FormatModule {
    descriptor: Some(&PARSE_NAMESPACE_DESCRIPTOR),
    namespace_semantics: Some(&NAMESPACE_SEMANTICS),
    operations: &[MATCHED_NAMESPACE],
    ..MODULE_A
};

#[test]
fn namespace_contract_provider_disagreement_is_rejected() {
    assert_eq!(
        ModuleCatalog::new([&MISMATCHED_MODULE]).err().unwrap(),
        ModuleCatalogError::ContractProviderDisagreement(crate::synthetic::ID_B38504826C7B)
    );
    assert!(ModuleCatalog::new([&PARSE_NAMESPACE_MODULE]).is_ok());
}

#[test]
fn strict_operations_require_valid_schemas_and_bound_namespace_adapters() {
    const EMPTY_SCHEMA: InputSchema<'static> = InputSchema {
        forms: &[],
        relationships: &[],
    };
    const INVALID_SCHEMA_OPERATION: ModuleOperation = ModuleOperation {
        input_schema: &EMPTY_SCHEMA,
        ..LEAF_OPERATION
    };
    static INVALID_SCHEMA_MODULE: FormatModule = FormatModule {
        operations: &[INVALID_SCHEMA_OPERATION],
        ..MODULE_A
    };
    assert_eq!(
        ModuleCatalog::new([&INVALID_SCHEMA_MODULE]).err().unwrap(),
        ModuleCatalogError::InvalidInputSchema(OperationId {
            format: crate::synthetic::ID_B38504826C7B,
            name: "decode-image",
        })
    );

    const MISSING_ADAPTER: ModuleOperation = ModuleOperation {
        bound_namespace: None,
        ..MATCHED_NAMESPACE
    };
    static MISSING_ADAPTER_MODULE: FormatModule = FormatModule {
        descriptor: Some(&PARSE_NAMESPACE_DESCRIPTOR),
        namespace_semantics: Some(&NAMESPACE_SEMANTICS),
        operations: &[MISSING_ADAPTER],
        ..MODULE_A
    };
    assert_eq!(
        ModuleCatalog::new([&MISSING_ADAPTER_MODULE]).err().unwrap(),
        ModuleCatalogError::InvalidBoundNamespaceAdapter(OperationId {
            format: crate::synthetic::ID_B38504826C7B,
            name: "mount",
        })
    );

    const WRONG_ROLE_SCHEMA: InputSchema<'static> = InputSchema {
        forms: &[InputForm {
            name: "single",
            bytes: &[ByteRole::one("other")],
            selectors: &[],
        }],
        relationships: &[],
    };
    const EXTRA_FORM_SCHEMA: InputSchema<'static> = InputSchema {
        forms: &[
            InputForm {
                name: "single",
                bytes: NAMESPACE_ROLES,
                selectors: &[],
            },
            InputForm {
                name: "other-form",
                bytes: NAMESPACE_ROLES,
                selectors: &[],
            },
        ],
        relationships: &[],
    };
    const WRONG_SELECTOR_SCHEMA: InputSchema<'static> = InputSchema {
        forms: &[InputForm {
            name: "single",
            bytes: NAMESPACE_ROLES,
            selectors: &[formatkit_catalog::catalog::SelectorRole {
                name: "variant",
                required: true,
            }],
        }],
        relationships: &[],
    };
    for schema in [
        &WRONG_ROLE_SCHEMA,
        &EXTRA_FORM_SCHEMA,
        &WRONG_SELECTOR_SCHEMA,
    ] {
        let operations = Box::leak(
            vec![ModuleOperation {
                input_schema: schema,
                ..MATCHED_NAMESPACE
            }]
            .into_boxed_slice(),
        );
        let module: &'static FormatModule = Box::leak(Box::new(FormatModule {
            descriptor: Some(&PARSE_NAMESPACE_DESCRIPTOR),
            namespace_semantics: Some(&NAMESPACE_SEMANTICS),
            operations,
            ..MODULE_A
        }));
        assert_eq!(
            ModuleCatalog::new([module]).err().unwrap(),
            ModuleCatalogError::InputSchemaTopologyDisagreement(OperationId {
                format: crate::synthetic::ID_B38504826C7B,
                name: "mount",
            })
        );
    }
}
