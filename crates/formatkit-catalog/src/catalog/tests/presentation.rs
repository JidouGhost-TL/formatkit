use super::super::*;
use super::fixtures::*;
use crate::FormatId;

const PRESENTED: FormatId = FormatId::new("synthetic-display-envelope");
const RECOGNIZED: FormatId = FormatId::new("synthetic-recognized-envelope");
const CONTEXT_ONLY: FormatId = FormatId::new("synthetic-display-body");

fn canonical_descriptor() -> FormatDescriptor {
    let mut row = descriptor(PRESENTED, 10, MAGIC, &[]);
    row.decoder = Some("canonical-owner");
    row.requirement = DecoderRequirement::PairedData;
    row
}

fn display(format: FormatId, decoder: Option<&'static str>) -> Option<&'static str> {
    match (format, decoder) {
        (PRESENTED, Some("canonical-owner")) => Some("display-owner"),
        (CONTEXT_ONLY, Some("image-owner")) => Some("display-body-owner"),
        _ => decoder,
    }
}

#[test]
fn capability_decoder_display_changes_only_its_cell() {
    let catalog = FormatCatalog::new([
        canonical_descriptor(),
        descriptor(RECOGNIZED, 10, STRUCTURAL, &[]),
    ])
    .unwrap();
    let original = catalog.capability_markdown();
    assert_eq!(
        original,
        catalog.capability_markdown_with_decoder_display(|_, decoder| decoder)
    );
    let projected = catalog.capability_markdown_with_decoder_display(display);
    assert_eq!(
        projected,
        original.replace("canonical-owner", "display-owner")
    );
    assert_eq!(catalog.capability_markdown(), original);
    assert_eq!(catalog.descriptors()[0].decoder, Some("canonical-owner"));
    assert!(catalog.validate_decoders(&["canonical-owner"]).is_ok());
    assert!(matches!(
        catalog.validate_decoders(&["display-owner"]),
        Err(CatalogError::MissingDecoder {
            format: PRESENTED,
            decoder: "canonical-owner"
        })
    ));
    let context = DetectionContext::from_bytes(b"TEST");
    assert_eq!(catalog.identify(context).unwrap().opener, None);
    assert_eq!(
        catalog
            .identify(context.with_paired_data(true))
            .unwrap()
            .opener,
        Some("canonical-owner")
    );
    assert_eq!(
        catalog
            .identify(DetectionContext::from_bytes(&[0x10]))
            .unwrap()
            .opener,
        None
    );
    assert!(catalog
        .resolve(DetectionContext::from_bytes(b"unmatched"))
        .is_unknown());
}

#[test]
fn support_decoder_display_preserves_support_and_context_only_rows() {
    let catalog = SupportCatalog::new(
        [
            canonical_descriptor(),
            descriptor(RECOGNIZED, 10, STRUCTURAL, &[]),
        ],
        [embedded(CONTEXT_ONLY)],
    )
    .unwrap();
    let original = catalog.capability_markdown();
    assert_eq!(
        original,
        catalog.capability_markdown_with_decoder_display(|_, decoder| decoder)
    );
    assert_eq!(
        catalog.capability_markdown_with_decoder_display(display),
        original
            .replace("canonical-owner", "display-owner")
            .replace("image-owner", "display-body-owner")
    );
    assert_eq!(catalog.capability_markdown(), original);
    let canonical = catalog.get(PRESENTED).unwrap();
    assert_eq!(canonical.decoder(), Some("canonical-owner"));
    assert_eq!(
        canonical.detectable.unwrap().requirement,
        DecoderRequirement::PairedData
    );
    assert_eq!(
        canonical.capabilities(),
        canonical_descriptor().capabilities
    );
    assert!(canonical.writer.is_none());
    assert!(canonical.namespace_mount.is_none());
    let contextual = catalog.get(CONTEXT_ONLY).unwrap();
    assert_eq!(contextual.decoder(), Some("image-owner"));
    assert!(contextual.detectable.is_none());
    assert_eq!(contextual.context(), Some(embedded(CONTEXT_ONLY).context));
    assert_eq!(catalog.get(RECOGNIZED).unwrap().decoder(), None);
    assert!(catalog.get(FormatId::new("unselected-envelope")).is_none());
}
