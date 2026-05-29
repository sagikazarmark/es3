mod bergshamra_verify;
mod document;
mod dossier;
mod error;
mod output;
mod parsed;
mod transform;
mod verify;
mod xml;

pub use crate::document::{DocumentEntry, ExtractedDocument, ExtractionCapability, MimeType};
pub use crate::dossier::Dossier;
pub use crate::error::{Error, Result};
pub use crate::transform::{ExtractionUnavailableReason, Transform};
pub use crate::verify::{
    DossierValidationError, Finding, SignatureEvidence, SignatureFinding, SignatureFindingKind,
    SignatureKeyInfo, SignatureReference, SignatureReport, SignatureResult, SignatureScope,
    SignerCertificateReport, StructureReport, ValidationLayerStatus, ValidationLayers,
    VerificationFailed, VerificationOptions, VerificationReport, XadesSigningCertificateStatus,
    verify_str, verify_structure_str,
};
