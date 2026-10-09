//! Typed, owner-provided operations for decoded leaf formats.

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use formatkit_core::{Error, Image, Pcm, RangeSource, Result};

use super::writer::valid_cargo_test_oracle;
use super::CargoTestOracle;
use crate::FormatId;

/// The complete-file input role accepted by the initial leaf-operation layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafInputContract {
    pub role: &'static str,
}

impl LeafInputContract {
    pub const fn file(role: &'static str) -> Self {
        Self { role }
    }
}

/// How one independent selector participates in an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafSelector {
    Unsupported,
    Optional { default: u32 },
    Required,
}

/// Selection policy for image, mip/level, and audio-track dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafSelectionContract {
    pub picture: LeafSelector,
    pub level: LeafSelector,
    pub track: LeafSelector,
}

impl LeafSelectionContract {
    pub const NONE: Self = Self {
        picture: LeafSelector::Unsupported,
        level: LeafSelector::Unsupported,
        track: LeafSelector::Unsupported,
    };

    fn resolve(self, selection: LeafSelection) -> Result<LeafSelection> {
        fn one(
            name: &'static str,
            policy: LeafSelector,
            value: Option<u32>,
        ) -> Result<Option<u32>> {
            match (policy, value) {
                (LeafSelector::Unsupported, None) => Ok(None),
                (LeafSelector::Unsupported, Some(_)) => Err(Error::Unsupported(format!(
                    "leaf operation does not support {name} selection"
                ))),
                (LeafSelector::Optional { default }, None) => Ok(Some(default)),
                (LeafSelector::Optional { .. } | LeafSelector::Required, Some(value)) => {
                    Ok(Some(value))
                }
                (LeafSelector::Required, None) => Err(Error::Malformed(format!(
                    "leaf operation requires {name} selection"
                ))),
            }
        }

        Ok(LeafSelection {
            picture: one("picture", self.picture, selection.picture)?,
            level: one("level", self.level, selection.level)?,
            track: one("track", self.track, selection.track)?,
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LeafSelection {
    pub picture: Option<u32>,
    pub level: Option<u32>,
    pub track: Option<u32>,
}

/// Independent retained-output and live-working-storage byte limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafDecodeLimits {
    pub max_output_bytes: u64,
    pub max_work_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafDecodeRequest {
    pub selection: LeafSelection,
    pub limits: LeafDecodeLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafOutputKind {
    RgbaImage,
    Pcm16,
    /// Decoded bytes with no implied image, audio, or word interpretation.
    ByteStream,
    /// Raw 16-bit words in decode order. Unlike [`LeafDecoded::RgbaImage`]
    /// this claims no display color mapping: the words are the decoded
    /// artifact itself, serialized little-endian for hashing and export.
    U16Words,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafOutputMultiplicity {
    One,
    Many { max_outputs: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafOutputContract {
    pub kind: LeafOutputKind,
    pub multiplicity: LeafOutputMultiplicity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeafDecoded {
    RgbaImage(Image),
    Pcm16(Pcm),
    ByteStream(Vec<u8>),
    U16Words(Vec<u16>),
}

impl LeafDecoded {
    pub const fn kind(&self) -> LeafOutputKind {
        match self {
            Self::RgbaImage(_) => LeafOutputKind::RgbaImage,
            Self::Pcm16(_) => LeafOutputKind::Pcm16,
            Self::ByteStream(_) => LeafOutputKind::ByteStream,
            Self::U16Words(_) => LeafOutputKind::U16Words,
        }
    }

    fn retained_bytes(&self) -> u64 {
        match self {
            Self::RgbaImage(image) => image.rgba.len() as u64,
            Self::Pcm16(pcm) => (pcm.samples().len() as u64).saturating_mul(2),
            Self::ByteStream(bytes) => bytes.len() as u64,
            Self::U16Words(words) => (words.len() as u64).saturating_mul(2),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafOutput {
    pub suggested_name: Option<String>,
    pub decoded: LeafDecoded,
}

/// Declarative policy for one owner-provided decode operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafOperationContract {
    pub id: FormatId,
    pub input: LeafInputContract,
    pub selection: LeafSelectionContract,
    pub output: LeafOutputContract,
    pub max_input_bytes: u64,
    pub default_limits: LeafDecodeLimits,
    pub max_limits: LeafDecodeLimits,
    pub oracle: CargoTestOracle,
}

pub type LeafDecodeHandler = fn(&[u8], LeafDecodeRequest) -> Result<Vec<LeafOutput>>;

/// Budgeted leaf decode: the caller's native [`formatkit_core::WorkBudget`] and
/// cancellation token reach the owner callback, and the returned outputs keep
/// their nominal retained-allocation permit for their full lifetime.
pub type LeafDecodeHandlerBudgeted =
    fn(&[u8], LeafDecodeRequest, &mut formatkit_core::WorkBudget) -> Result<BudgetedLeafOutput>;

/// Budgeted source-backed leaf decode: the same callback authority as
/// [`LeafDecodeHandlerBudgeted`] but bound to a [`RangeSource`] so product
/// routes can read carriers through the native ledger without an intermediate
/// unbudgeted copy. The caller's budget is created before the source is
/// opened; the owner preflights `source.size()` before any charge, then
/// charges logical reads, physical I/O, materialization, nodes, output, and
/// resident bytes through that same ledger.
pub type LeafDecodeHandlerBudgetedSource = fn(
    Arc<dyn RangeSource>,
    LeafDecodeRequest,
    &mut formatkit_core::WorkBudget,
) -> Result<BudgetedLeafOutput>;

/// Budgeted file-backed leaf decode: the same callback authority, but the
/// owner opens the carrier path itself after the caller budget exists, so the
/// file-wrapper graph (path, coordinate names, descriptor pinning, shared
/// handle) is admitted before allocation and retained for the source
/// lifetime on the one native ledger. Selection, limit, output, and permit
/// behavior match [`LeafDecodeHandlerBudgetedSource`] exactly; only the input
/// binding differs.
pub type LeafDecodeHandlerBudgetedFile = fn(
    &std::path::Path,
    LeafDecodeRequest,
    &mut formatkit_core::WorkBudget,
) -> Result<BudgetedLeafOutput>;

/// Leaf outputs whose owner-admitted, input-dependent retained allocation
/// graph stays reserved until the value is dropped. Fixed bootstrap objects
/// may be excluded by the shared allocation policy.
#[must_use = "dropping the outputs releases their resident-byte reservation"]
pub struct BudgetedLeafOutput {
    outputs: Vec<LeafOutput>,
    resident: formatkit_core::RetainedResidentPermit,
}

impl BudgetedLeafOutput {
    /// Wrap catalog-validated outputs with the permit covering their retained
    /// bytes. Owners admit the outputs before allocation and move the live
    /// permit here; only dropping this value releases it.
    pub fn new(outputs: Vec<LeafOutput>, resident: formatkit_core::RetainedResidentPermit) -> Self {
        Self { outputs, resident }
    }

    pub fn outputs(&self) -> &[LeafOutput] {
        &self.outputs
    }

    /// Number of decoded payload bytes retained on the caller's ledger.
    pub fn retained_bytes(&self) -> u64 {
        self.resident.amount()
    }
}

impl std::fmt::Debug for BudgetedLeafOutput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BudgetedLeafOutput")
            .field("outputs", &self.outputs.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
pub struct LeafOperationProvider {
    pub contract: LeafOperationContract,
    pub decode: LeafDecodeHandler,
    /// Native-budget projection of the same callback authority. `None` keeps
    /// the legacy in-memory decode only; product routes that must observe
    /// caller spends, cancellation, and output lifetimes require `Some`.
    pub decode_budgeted: Option<LeafDecodeHandlerBudgeted>,
    /// Source-backed native-budget projection of the same callback authority.
    /// Product file routes with already-bound sources use this seam so the
    /// carrier is read through the caller ledger with no intermediate
    /// unbudgeted copy. `None` keeps the in-memory projections only.
    pub decode_budgeted_source: Option<LeafDecodeHandlerBudgetedSource>,
    /// File-backed native-budget projection of the same callback authority.
    /// Explicit file routes use this seam so the owner opens the carrier
    /// through the caller ledger with its input-dependent retained graph
    /// admitted. Fixed source bootstrap may be policy-excluded.
    /// `None` keeps the caller-bound projections only.
    pub decode_budgeted_file: Option<LeafDecodeHandlerBudgetedFile>,
}

impl fmt::Debug for LeafOperationProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeafOperationProvider")
            .field("contract", &self.contract)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeafOperationCatalogError {
    InvalidFormatId(FormatId),
    DuplicateId(FormatId),
    InvalidContract(FormatId),
}

impl fmt::Display for LeafOperationCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormatId(id) => {
                write!(formatter, "invalid leaf operation identity: {id:?}")
            }
            Self::DuplicateId(id) => write!(formatter, "duplicate leaf operation identity: {id}"),
            Self::InvalidContract(id) => write!(formatter, "invalid leaf operation contract: {id}"),
        }
    }
}

impl std::error::Error for LeafOperationCatalogError {}

#[derive(Debug, Clone)]
pub struct LeafOperationCatalog {
    providers: Vec<LeafOperationProvider>,
}

impl LeafOperationCatalog {
    pub fn new(
        providers: impl IntoIterator<Item = LeafOperationProvider>,
    ) -> std::result::Result<Self, LeafOperationCatalogError> {
        let mut ids = HashSet::new();
        let mut providers = providers.into_iter().collect::<Vec<_>>();
        for provider in &providers {
            let contract = provider.contract;
            if !contract.id.is_valid() {
                return Err(LeafOperationCatalogError::InvalidFormatId(contract.id));
            }
            if !ids.insert(contract.id) {
                return Err(LeafOperationCatalogError::DuplicateId(contract.id));
            }
            if !valid_contract(contract) {
                return Err(LeafOperationCatalogError::InvalidContract(contract.id));
            }
        }
        providers.sort_by_key(|provider| provider.contract.id.as_str());
        Ok(Self { providers })
    }

    pub fn providers(&self) -> &[LeafOperationProvider] {
        &self.providers
    }

    pub fn provider(&self, id: FormatId) -> Option<&LeafOperationProvider> {
        self.providers
            .binary_search_by_key(&id.as_str(), |provider| provider.contract.id.as_str())
            .ok()
            .map(|index| &self.providers[index])
    }

    /// Execute an operation when this catalog owns `id`; return `None` only
    /// when the caller should continue through another dispatch layer.
    pub fn decode(
        &self,
        id: FormatId,
        input: &[u8],
        request: Option<LeafDecodeRequest>,
    ) -> Result<Option<Vec<LeafOutput>>> {
        let Some(provider) = self.provider(id) else {
            return Ok(None);
        };
        let contract = provider.contract;
        if input.len() as u64 > contract.max_input_bytes {
            return Err(Error::ResourceLimit {
                resource: "leaf operation input bytes",
                requested: input.len() as u64,
                limit: contract.max_input_bytes,
            });
        }
        let mut request = request.unwrap_or(LeafDecodeRequest {
            selection: LeafSelection::default(),
            limits: contract.default_limits,
        });
        request.selection = contract.selection.resolve(request.selection)?;
        enforce_limit(
            "leaf decoded output bytes",
            request.limits.max_output_bytes,
            contract.max_limits.max_output_bytes,
        )?;
        enforce_limit(
            "leaf decode work bytes",
            request.limits.max_work_bytes,
            contract.max_limits.max_work_bytes,
        )?;

        let outputs = (provider.decode)(input, request)?;
        validate_outputs(contract.output, request.limits, &outputs)?;
        Ok(Some(outputs))
    }

    /// Execute the budgeted projection when this catalog owns `id`; return
    /// `None` only when the caller should continue through another dispatch
    /// layer. Input, selection, and limit policy match [`Self::decode`]; the
    /// caller's budget reaches the owner callback and the returned outputs
    /// keep their resident permit.
    pub fn decode_budgeted(
        &self,
        id: FormatId,
        input: &[u8],
        request: Option<LeafDecodeRequest>,
        budget: &mut formatkit_core::WorkBudget,
    ) -> Result<Option<BudgetedLeafOutput>> {
        let Some(provider) = self.provider(id) else {
            return Ok(None);
        };
        let contract = provider.contract;
        if input.len() as u64 > contract.max_input_bytes {
            return Err(Error::ResourceLimit {
                resource: "leaf operation input bytes",
                requested: input.len() as u64,
                limit: contract.max_input_bytes,
            });
        }
        let mut request = request.unwrap_or(LeafDecodeRequest {
            selection: LeafSelection::default(),
            limits: contract.default_limits,
        });
        request.selection = contract.selection.resolve(request.selection)?;
        enforce_limit(
            "leaf decoded output bytes",
            request.limits.max_output_bytes,
            contract.max_limits.max_output_bytes,
        )?;
        enforce_limit(
            "leaf decode work bytes",
            request.limits.max_work_bytes,
            contract.max_limits.max_work_bytes,
        )?;

        let Some(handler) = provider.decode_budgeted else {
            return Err(Error::Unsupported(format!(
                "leaf operation {id} has no budgeted decode projection"
            )));
        };
        let outputs = handler(input, request, budget)?;
        validate_outputs(contract.output, request.limits, outputs.outputs())?;
        Ok(Some(outputs))
    }

    /// Execute the source-backed budgeted projection when this catalog owns
    /// `id`; return `None` only when the caller should continue through another
    /// dispatch layer. The source size is preflighted against
    /// `max_input_bytes` before any owner I/O; selection and limit policy match
    /// [`Self::decode_budgeted`]. The caller's budget reaches the owner
    /// callback for source reads, parse, grouping, decode, and output retention.
    pub fn decode_budgeted_source(
        &self,
        id: FormatId,
        source: Arc<dyn RangeSource>,
        request: Option<LeafDecodeRequest>,
        budget: &mut formatkit_core::WorkBudget,
    ) -> Result<Option<BudgetedLeafOutput>> {
        let Some(provider) = self.provider(id) else {
            return Ok(None);
        };
        let contract = provider.contract;
        if source.size() > contract.max_input_bytes {
            return Err(Error::ResourceLimit {
                resource: "leaf operation input bytes",
                requested: source.size(),
                limit: contract.max_input_bytes,
            });
        }
        let mut request = request.unwrap_or(LeafDecodeRequest {
            selection: LeafSelection::default(),
            limits: contract.default_limits,
        });
        request.selection = contract.selection.resolve(request.selection)?;
        enforce_limit(
            "leaf decoded output bytes",
            request.limits.max_output_bytes,
            contract.max_limits.max_output_bytes,
        )?;
        enforce_limit(
            "leaf decode work bytes",
            request.limits.max_work_bytes,
            contract.max_limits.max_work_bytes,
        )?;

        let Some(handler) = provider.decode_budgeted_source else {
            return Err(Error::Unsupported(format!(
                "leaf operation {id} has no source-backed budgeted decode projection"
            )));
        };
        let outputs = handler(source, request, budget)?;
        validate_outputs(contract.output, request.limits, outputs.outputs())?;
        Ok(Some(outputs))
    }

    /// Execute the file-backed budgeted projection when this catalog owns
    /// `id`; return `None` only when the caller should continue through another
    /// dispatch layer. Selection and limit policy match
    /// [`Self::decode_budgeted_source`]; the owner opens the path and
    /// preflights its size internally (the catalog cannot size a path without
    /// opening it), admitting its input-dependent retained graph before
    /// allocation on the caller's ledger. Fixed source bootstrap may be
    /// policy-excluded.
    pub fn decode_budgeted_file(
        &self,
        id: FormatId,
        path: &std::path::Path,
        request: Option<LeafDecodeRequest>,
        budget: &mut formatkit_core::WorkBudget,
    ) -> Result<Option<BudgetedLeafOutput>> {
        let Some(provider) = self.provider(id) else {
            return Ok(None);
        };
        let contract = provider.contract;
        let mut request = request.unwrap_or(LeafDecodeRequest {
            selection: LeafSelection::default(),
            limits: contract.default_limits,
        });
        request.selection = contract.selection.resolve(request.selection)?;
        enforce_limit(
            "leaf decoded output bytes",
            request.limits.max_output_bytes,
            contract.max_limits.max_output_bytes,
        )?;
        enforce_limit(
            "leaf decode work bytes",
            request.limits.max_work_bytes,
            contract.max_limits.max_work_bytes,
        )?;

        let Some(handler) = provider.decode_budgeted_file else {
            return Err(Error::Unsupported(format!(
                "leaf operation {id} has no file-backed budgeted decode projection"
            )));
        };
        let outputs = handler(path, request, budget)?;
        validate_outputs(contract.output, request.limits, outputs.outputs())?;
        Ok(Some(outputs))
    }
}

fn valid_contract(contract: LeafOperationContract) -> bool {
    let role_ok = !contract.input.role.trim().is_empty()
        && contract
            .input
            .role
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    let limits_ok = contract.max_input_bytes > 0
        && contract.default_limits.max_output_bytes > 0
        && contract.default_limits.max_work_bytes > 0
        && contract.default_limits.max_output_bytes <= contract.max_limits.max_output_bytes
        && contract.default_limits.max_work_bytes <= contract.max_limits.max_work_bytes;
    let output_ok = !matches!(
        contract.output.multiplicity,
        LeafOutputMultiplicity::Many { max_outputs: 0 }
    );
    role_ok && limits_ok && output_ok && valid_cargo_test_oracle(contract.oracle)
}

fn enforce_limit(resource: &'static str, requested: u64, limit: u64) -> Result<()> {
    if requested > limit {
        Err(Error::ResourceLimit {
            resource,
            requested,
            limit,
        })
    } else {
        Ok(())
    }
}

fn valid_leaf_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\'])
        && !name.chars().any(char::is_control)
}

fn validate_outputs(
    contract: LeafOutputContract,
    limits: LeafDecodeLimits,
    outputs: &[LeafOutput],
) -> Result<()> {
    match contract.multiplicity {
        LeafOutputMultiplicity::One if outputs.len() != 1 => {
            return Err(Error::Malformed(format!(
                "leaf operation declared one output but returned {}",
                outputs.len()
            )));
        }
        LeafOutputMultiplicity::Many { max_outputs }
            if outputs.len() as u64 > u64::from(max_outputs) =>
        {
            return Err(Error::ResourceLimit {
                resource: "leaf operation output count",
                requested: outputs.len() as u64,
                limit: u64::from(max_outputs),
            });
        }
        _ => {}
    }

    let require_names = matches!(contract.multiplicity, LeafOutputMultiplicity::Many { .. });
    let mut names = HashSet::new();
    let mut retained = 0u64;
    for output in outputs {
        if output.decoded.kind() != contract.kind {
            return Err(Error::Malformed(
                "leaf operation returned an undeclared output type".into(),
            ));
        }
        retained = retained
            .checked_add(output.decoded.retained_bytes())
            .ok_or(Error::ResourceLimit {
                resource: "leaf decoded output bytes",
                requested: u64::MAX,
                limit: limits.max_output_bytes,
            })?;
        if retained > limits.max_output_bytes {
            return Err(Error::ResourceLimit {
                resource: "leaf decoded output bytes",
                requested: retained,
                limit: limits.max_output_bytes,
            });
        }
        match output.suggested_name.as_deref() {
            Some(name) if valid_leaf_name(name) && names.insert(name) => {}
            Some(_) => {
                return Err(Error::Malformed(
                    "leaf operation returned an unsafe or duplicate output name".into(),
                ));
            }
            None if require_names => {
                return Err(Error::Malformed(
                    "multi-output leaf operation omitted an output name".into(),
                ));
            }
            None => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: FormatId = crate::synthetic::ID_9FB2F33B693C;
    const CONTRACT: LeafOperationContract = LeafOperationContract {
        id: ID,
        input: LeafInputContract::file("texture"),
        selection: LeafSelectionContract::NONE,
        output: LeafOutputContract {
            kind: LeafOutputKind::RgbaImage,
            multiplicity: LeafOutputMultiplicity::One,
        },
        max_input_bytes: 64,
        default_limits: LeafDecodeLimits {
            max_output_bytes: 4,
            max_work_bytes: 4,
        },
        max_limits: LeafDecodeLimits {
            max_output_bytes: 16,
            max_work_bytes: 16,
        },
        oracle: CargoTestOracle::lib(
            "formatkit-catalog",
            "catalog::leaf::tests::validates_execution_policy",
        ),
    };

    fn image(_: &[u8], _: LeafDecodeRequest) -> Result<Vec<LeafOutput>> {
        Ok(vec![LeafOutput {
            suggested_name: None,
            decoded: LeafDecoded::RgbaImage(Image::try_new(1, 1, vec![0; 4])?),
        }])
    }

    fn variable_output(input: &[u8], _: LeafDecodeRequest) -> Result<Vec<LeafOutput>> {
        let decoded = if input == b"wrong-type" {
            LeafDecoded::Pcm16(Pcm::new(8_000, vec![0]))
        } else {
            LeafDecoded::RgbaImage(Image::try_new(1, 1, vec![0; 4])?)
        };
        Ok(vec![LeafOutput {
            suggested_name: match input {
                b"named" => Some("image.png".into()),
                b"unsafe" => Some("../image.png".into()),
                _ => None,
            },
            decoded,
        }])
    }

    fn byte_stream(input: &[u8], _: LeafDecodeRequest) -> Result<Vec<LeafOutput>> {
        Ok(vec![LeafOutput {
            suggested_name: None,
            decoded: LeafDecoded::ByteStream(input.to_vec()),
        }])
    }

    #[test]
    fn byte_stream_output_has_exact_retained_byte_limit() {
        let mut contract = CONTRACT;
        contract.output.kind = LeafOutputKind::ByteStream;
        let catalog = LeafOperationCatalog::new([LeafOperationProvider {
            contract,
            decode: byte_stream,
            decode_budgeted: None,
            decode_budgeted_source: None,
            decode_budgeted_file: None,
        }])
        .unwrap();
        let outputs = catalog.decode(ID, b"four", None).unwrap().unwrap();
        assert_eq!(
            outputs[0].decoded,
            LeafDecoded::ByteStream(b"four".to_vec())
        );
        assert!(matches!(
            catalog.decode(ID, b"five!", None),
            Err(Error::ResourceLimit {
                resource: "leaf decoded output bytes",
                ..
            })
        ));
    }

    #[test]
    fn validates_execution_policy() {
        let catalog = LeafOperationCatalog::new([LeafOperationProvider {
            contract: CONTRACT,
            decode: image,
            decode_budgeted: None,
            decode_budgeted_source: None,
            decode_budgeted_file: None,
        }])
        .unwrap();
        assert!(catalog.decode(ID, &[0; 64], None).unwrap().is_some());
        assert!(matches!(
            catalog.decode(ID, &[0; 65], None),
            Err(Error::ResourceLimit {
                resource: "leaf operation input bytes",
                ..
            })
        ));
        assert!(matches!(
            catalog.decode(
                ID,
                &[],
                Some(LeafDecodeRequest {
                    selection: LeafSelection {
                        picture: Some(0),
                        ..LeafSelection::default()
                    },
                    limits: CONTRACT.default_limits,
                }),
            ),
            Err(Error::Unsupported(_))
        ));
        assert!(catalog
            .decode(crate::synthetic::ID_44895F217E35, &[], None)
            .unwrap()
            .is_none());
    }

    #[test]
    fn rejects_duplicate_and_invalid_contracts() {
        let provider = LeafOperationProvider {
            contract: CONTRACT,
            decode: image,
            decode_budgeted: None,
            decode_budgeted_source: None,
            decode_budgeted_file: None,
        };
        assert_eq!(
            LeafOperationCatalog::new([provider, provider]).unwrap_err(),
            LeafOperationCatalogError::DuplicateId(ID)
        );
        let mut invalid = provider;
        invalid.contract.input.role = "../texture";
        assert_eq!(
            LeafOperationCatalog::new([invalid]).unwrap_err(),
            LeafOperationCatalogError::InvalidContract(ID)
        );

        let mut invalid_id = provider;
        invalid_id.contract.id = FormatId::new("invalid_id");
        assert_eq!(
            LeafOperationCatalog::new([invalid_id]).unwrap_err(),
            LeafOperationCatalogError::InvalidFormatId(FormatId::new("invalid_id"))
        );
    }

    #[test]
    fn validates_output_type_count_and_names() {
        let mut contract = CONTRACT;
        contract.output.multiplicity = LeafOutputMultiplicity::Many { max_outputs: 2 };
        let catalog = LeafOperationCatalog::new([LeafOperationProvider {
            contract,
            decode: variable_output,
            decode_budgeted: None,
            decode_budgeted_source: None,
            decode_budgeted_file: None,
        }])
        .unwrap();
        assert!(catalog.decode(ID, b"named", None).is_ok());
        assert!(matches!(
            catalog.decode(ID, b"unnamed", None),
            Err(Error::Malformed(message)) if message.contains("omitted an output name")
        ));
        assert!(matches!(
            catalog.decode(ID, b"unsafe", None),
            Err(Error::Malformed(message)) if message.contains("unsafe or duplicate")
        ));
        assert!(matches!(
            catalog.decode(ID, b"wrong-type", None),
            Err(Error::Malformed(message)) if message.contains("undeclared output type")
        ));
    }

    fn budgeted_image(
        _: &[u8],
        _: LeafDecodeRequest,
        budget: &mut formatkit_core::WorkBudget,
    ) -> Result<BudgetedLeafOutput> {
        budget.check_cancelled()?;
        budget.charge(formatkit_core::WorkResource::MaterializedBytes, 4)?;
        let resident = budget.retain_resident(4)?;
        let outputs = vec![LeafOutput {
            suggested_name: None,
            decoded: LeafDecoded::RgbaImage(Image::try_new(1, 1, vec![0; 4])?),
        }];
        Ok(BudgetedLeafOutput::new(outputs, resident))
    }

    fn budgeted_source_image(
        source: Arc<dyn formatkit_core::RangeSource>,
        request: LeafDecodeRequest,
        budget: &mut formatkit_core::WorkBudget,
    ) -> Result<BudgetedLeafOutput> {
        budget.charge(formatkit_core::WorkResource::MaterializedBytes, 4)?;
        let resident = budget.retain_resident(4)?;
        if source.size() > 0 {
            let mut probe = [0u8; 1];
            source.read_exact_into(0, &mut probe, budget)?;
        }
        let _ = request;
        let outputs = vec![LeafOutput {
            suggested_name: None,
            decoded: LeafDecoded::RgbaImage(Image::try_new(1, 1, vec![0; 4])?),
        }];
        Ok(BudgetedLeafOutput::new(outputs, resident))
    }

    fn budgeted_file_image(
        path: &std::path::Path,
        request: LeafDecodeRequest,
        budget: &mut formatkit_core::WorkBudget,
    ) -> Result<BudgetedLeafOutput> {
        budget.charge(formatkit_core::WorkResource::MaterializedBytes, 4)?;
        let source = formatkit_core::FileRangeSource::open(path)?;
        let _ = (source, request);
        let resident = budget.retain_resident(4)?;
        let outputs = vec![LeafOutput {
            suggested_name: None,
            decoded: LeafDecoded::RgbaImage(Image::try_new(1, 1, vec![0; 4])?),
        }];
        Ok(BudgetedLeafOutput::new(outputs, resident))
    }

    #[test]
    fn budgeted_decode_matches_unbudgeted_policy_and_holds_its_permit() {
        use formatkit_core::{CancellationToken, WorkBudget, WorkLimits};

        let catalog = LeafOperationCatalog::new([LeafOperationProvider {
            contract: CONTRACT,
            decode: image,
            decode_budgeted: Some(budgeted_image),
            decode_budgeted_source: None,
            decode_budgeted_file: None,
        }])
        .unwrap();
        let mut budget = WorkBudget::new(WorkLimits::unlimited());
        let outputs = catalog
            .decode_budgeted(ID, &[0; 64], None, &mut budget)
            .unwrap()
            .unwrap();
        assert_eq!(outputs.outputs().len(), 1);
        assert_eq!(outputs.retained_bytes(), 4);
        assert_eq!(
            budget.spent(formatkit_core::WorkResource::MaterializedBytes),
            4
        );
        drop(outputs);
        assert_eq!(budget.usage().resident_bytes(), 0);

        assert!(matches!(
            catalog.decode_budgeted(ID, &[0; 65], None, &mut budget),
            Err(Error::ResourceLimit { .. })
        ));
        assert!(catalog
            .decode_budgeted(crate::synthetic::ID_44895F217E35, &[], None, &mut budget)
            .unwrap()
            .is_none());

        let token = CancellationToken::new();
        token.cancel();
        let mut cancelled = WorkBudget::new(WorkLimits::unlimited()).with_cancellation(token);
        assert!(matches!(
            catalog.decode_budgeted(ID, &[], None, &mut cancelled),
            Err(Error::Cancelled)
        ));
        assert_eq!(cancelled.usage().resident_bytes(), 0);

        let unbudgeted = LeafOperationCatalog::new([LeafOperationProvider {
            contract: CONTRACT,
            decode: image,
            decode_budgeted: None,
            decode_budgeted_source: None,
            decode_budgeted_file: None,
        }])
        .unwrap();
        assert!(matches!(
            unbudgeted.decode_budgeted(ID, &[], None, &mut budget),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn source_and_file_projections_preflight_size_and_hold_permits() {
        use formatkit_core::{MemoryRangeSource, WorkBudget, WorkLimits};

        let catalog = LeafOperationCatalog::new([LeafOperationProvider {
            contract: CONTRACT,
            decode: image,
            decode_budgeted: Some(budgeted_image),
            decode_budgeted_source: Some(budgeted_source_image),
            decode_budgeted_file: Some(budgeted_file_image),
        }])
        .unwrap();

        let mut budget = WorkBudget::new(WorkLimits::unlimited());
        let source: Arc<dyn formatkit_core::RangeSource> =
            Arc::new(MemoryRangeSource::new(vec![7u8; 8], "leaf-probe"));
        let outputs = catalog
            .decode_budgeted_source(ID, source, None, &mut budget)
            .unwrap()
            .unwrap();
        assert_eq!(outputs.outputs().len(), 1);
        assert_eq!(outputs.retained_bytes(), 4);
        drop(outputs);
        assert_eq!(budget.usage().resident_bytes(), 0);

        let oversized: Arc<dyn formatkit_core::RangeSource> = Arc::new(MemoryRangeSource::new(
            vec![0u8; CONTRACT.max_input_bytes as usize + 1],
            "leaf-oversize",
        ));
        assert!(matches!(
            catalog.decode_budgeted_source(ID, oversized, None, &mut budget),
            Err(Error::ResourceLimit { .. })
        ));

        let directory = std::env::temp_dir().join(format!(
            "formatkit-catalog-leaf-file-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("carrier.bin");
        std::fs::write(&path, b"leaf-file-probe").unwrap();
        let outputs = catalog
            .decode_budgeted_file(ID, &path, None, &mut budget)
            .unwrap()
            .unwrap();
        assert_eq!(outputs.outputs().len(), 1);
        assert_eq!(outputs.retained_bytes(), 4);
        drop(outputs);
        assert_eq!(budget.usage().resident_bytes(), 0);
        assert!(matches!(
            catalog.decode_budgeted_file(ID, &directory.join("missing"), None, &mut budget),
            Err(Error::Malformed(_))
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
