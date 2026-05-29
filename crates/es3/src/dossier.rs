use std::io::Read;
use std::str::FromStr;
use std::sync::Arc;

use crate::document::{DocumentEntry, ExtractedDocument, StoredDocument};
use crate::error::{Error, Result};
use crate::output;
use crate::parsed::ParsedDossier;
use crate::verify::{
    DossierValidationError, StructureReport, ValidationLayerStatus, ValidationLayers,
    VerificationFailed, VerificationOptions, VerificationReport,
};

#[derive(Debug, Clone)]
pub struct Dossier {
    pub(crate) source_xml: Arc<str>,
    pub(crate) documents: Vec<StoredDocument>,
    pub(crate) dossier_signature_count: usize,
    pub(crate) dossier_timestamp_count: usize,
}

impl Dossier {
    pub fn from_reader(mut reader: impl Read) -> Result<Self> {
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .map_err(|source| Error::ReadInput { source })?;

        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        std::str::from_utf8(bytes)?.parse()
    }

    pub fn source_xml(&self) -> &str {
        &self.source_xml
    }

    pub fn documents(&self) -> Vec<DocumentEntry> {
        self.documents
            .iter()
            .map(|document| document.entry.clone())
            .collect()
    }

    pub fn documents_iter(&self) -> impl Iterator<Item = &DocumentEntry> {
        self.documents.iter().map(|document| &document.entry)
    }

    pub fn dossier_signature_count(&self) -> usize {
        self.dossier_signature_count
    }

    pub fn dossier_timestamp_count(&self) -> usize {
        self.dossier_timestamp_count
    }

    pub fn extract_document(&self, index: usize) -> Result<ExtractedDocument> {
        let document = self
            .documents
            .get(index)
            .ok_or(Error::DocumentIndexOutOfRange { index })?;

        self.extract_stored_document(document)
    }

    pub fn extract_document_by_title(&self, title: &str) -> Result<ExtractedDocument> {
        let matches = self
            .documents
            .iter()
            .filter(|document| document.entry.title() == title)
            .collect::<Vec<_>>();

        match matches.as_slice() {
            [] => Err(Error::DocumentTitleNotFound {
                title: title.to_owned(),
            }),
            [document] => self.extract_document(document.entry.index()),
            _ => Err(Error::AmbiguousDocumentTitle {
                title: title.to_owned(),
            }),
        }
    }

    pub fn verify_structure(&self) -> StructureReport {
        crate::verify::verify_parsed_dossier(self)
    }

    pub fn verify(&self, options: VerificationOptions) -> VerificationReport {
        let structure = self.verify_structure();
        let signatures = crate::verify::verify_signatures_for_dossier(self, &options);
        let cryptographic = match signatures.as_ref() {
            None => ValidationLayerStatus::NotChecked,
            Some(report) if report.cryptographic_ok() => ValidationLayerStatus::Passed,
            Some(_) => ValidationLayerStatus::Failed,
        };
        let trust_requested = !options.pinned_certificates.is_empty()
            || !options.trusted_anchor_certificates.is_empty();
        let trust = match (trust_requested, signatures.as_ref()) {
            (false, _) | (_, None) => ValidationLayerStatus::NotChecked,
            (true, Some(report)) if report.trust_ok() => ValidationLayerStatus::Passed,
            (true, Some(_)) => ValidationLayerStatus::Failed,
        };
        let structural = if structure.is_ok() {
            ValidationLayerStatus::Passed
        } else {
            ValidationLayerStatus::Failed
        };

        VerificationReport {
            validation: ValidationLayers {
                structural,
                cryptographic,
                trust,
                ..ValidationLayers::default()
            },
            structure,
            signatures,
        }
    }

    pub fn require_checked_layers_ok(
        self,
        options: VerificationOptions,
    ) -> std::result::Result<Self, VerificationFailed> {
        let report = self.verify(options);
        if report.checked_layers_ok() {
            Ok(self)
        } else {
            Err(VerificationFailed { report })
        }
    }

    fn extract_stored_document(&self, document: &StoredDocument) -> Result<ExtractedDocument> {
        Ok(ExtractedDocument {
            filename: output::filename_for(&document.entry),
            bytes: document
                .transform_chain
                .decode_payload(&document.payload_text)?,
            entry: document.entry.clone(),
        })
    }
}

impl FromStr for Dossier {
    type Err = Error;

    fn from_str(xml: &str) -> Result<Self> {
        let parsed = xml.parse::<ParsedDossier>()?;
        Self::try_from(parsed).map_err(Error::from)
    }
}

impl TryFrom<ParsedDossier> for Dossier {
    type Error = DossierValidationError;

    fn try_from(parsed: ParsedDossier) -> std::result::Result<Self, Self::Error> {
        parsed.validate()?;

        Ok(Self {
            source_xml: parsed.source_xml,
            documents: parsed
                .documents
                .into_iter()
                .map(StoredDocument::from_parsed)
                .collect(),
            dossier_signature_count: parsed.dossier_signature_count,
            dossier_timestamp_count: parsed.dossier_timestamp_count,
        })
    }
}

impl TryFrom<&[u8]> for Dossier {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::from_bytes(bytes)
    }
}

impl TryFrom<&str> for Dossier {
    type Error = Error;

    fn try_from(xml: &str) -> Result<Self> {
        xml.parse()
    }
}
