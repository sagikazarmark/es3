use std::str::FromStr;
use std::sync::Arc;

use crate::document::MimeType;
use crate::transform::{TransformChain, TransformPayloadIssue};
use crate::xml::{self, child_es, child_text, children_ds, children_es, document_profile_path};
use crate::{Error, Result, Transform};

const ENCRYPTED_PAYLOAD_WARNING: &str =
    "document payload is encrypted; encrypted content is not verified";

#[derive(Debug, Clone)]
pub(crate) struct ParsedDossier {
    pub(crate) source_xml: Arc<str>,
    pub(crate) root_valid: bool,
    pub(crate) documents_present: bool,
    pub(crate) documents: Vec<ParsedDocument>,
    pub(crate) dossier_signature_count: usize,
    pub(crate) dossier_timestamp_count: usize,
}

impl ParsedDossier {
    pub(crate) fn from_xml_document(xml: &str, document: &roxmltree::Document<'_>) -> Self {
        let source_xml = Arc::from(xml);
        let root = document.root_element();
        if !xml::is_es(root, "Dossier") {
            return Self {
                source_xml,
                root_valid: false,
                documents_present: false,
                documents: Vec::new(),
                dossier_signature_count: 0,
                dossier_timestamp_count: 0,
            };
        }

        let dossier_signature_count = children_ds(root, "Signature").count();
        let dossier_timestamp_count = children_es(root, "TimeStamp").count();
        let Some(documents_node) = child_es(root, "Documents") else {
            return Self {
                source_xml,
                root_valid: true,
                documents_present: false,
                documents: Vec::new(),
                dossier_signature_count,
                dossier_timestamp_count,
            };
        };

        let documents = children_es(documents_node, "Document")
            .enumerate()
            .map(|(index, node)| ParsedDocument::from_node(index, node))
            .collect();

        Self {
            source_xml,
            root_valid: true,
            documents_present: true,
            documents,
            dossier_signature_count,
            dossier_timestamp_count,
        }
    }

    pub(crate) fn validation_messages(&self) -> Vec<ValidationMessage> {
        let mut messages = Vec::new();

        if !self.root_valid {
            messages.push(ValidationMessage::error(
                None,
                Error::InvalidRoot.to_string(),
            ));
            return messages;
        }

        if !self.documents_present {
            messages.push(ValidationMessage::error(
                None,
                Error::MissingElement {
                    element: "Documents".to_owned(),
                }
                .to_string(),
            ));
            return messages;
        }

        for document in &self.documents {
            messages.extend(document.validation_messages());
        }

        messages
    }
}

impl FromStr for ParsedDossier {
    type Err = Error;

    fn from_str(xml: &str) -> Result<Self> {
        let document = xml::parse_xml_document(xml)?;
        Ok(Self::from_xml_document(xml, &document))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedDocument {
    pub(crate) index: usize,
    pub(crate) profiles: Vec<ParsedDocumentProfile>,
    pub(crate) payloads: Vec<ParsedPayload>,
    pub(crate) signature_count: usize,
    pub(crate) timestamp_count: usize,
}

impl ParsedDocument {
    fn from_node(index: usize, node: roxmltree::Node<'_, '_>) -> Self {
        Self {
            index,
            profiles: children_es(node, "DocumentProfile")
                .map(|node| ParsedDocumentProfile::from_node(index, node))
                .collect(),
            payloads: children_ds(node, "Object")
                .map(ParsedPayload::from_node)
                .collect(),
            signature_count: children_ds(node, "Signature").count(),
            timestamp_count: children_es(node, "TimeStamp").count(),
        }
    }

    pub(crate) fn validation_messages(&self) -> Vec<ValidationMessage> {
        let mut messages = Vec::new();

        if self.profiles.len() != 1 {
            messages.push(ValidationMessage::error(
                Some(self.index),
                format!(
                    "document {} must have exactly one es:DocumentProfile, found {}",
                    self.index,
                    self.profiles.len()
                ),
            ));
        }

        if self.payloads.len() != 1 {
            messages.push(ValidationMessage::error(
                Some(self.index),
                Error::InvalidPayloadCount {
                    index: self.index,
                    count: self.payloads.len(),
                }
                .to_string(),
            ));
        }

        let profile = self.profiles.first();
        if let Some(profile) = profile {
            profile.validate_fields(&mut messages);
        }

        let transforms = profile
            .map(|profile| profile.valid_transforms(&mut messages))
            .unwrap_or_default();
        if profile
            .map(|profile| profile.base_transform_present && transforms.is_empty())
            .unwrap_or(false)
        {
            messages.push(ValidationMessage::error(
                Some(self.index),
                Error::MissingElement {
                    element: document_profile_path(
                        self.index,
                        "DocumentProfile/BaseTransform/Transform",
                    ),
                }
                .to_string(),
            ));
        }

        let transform_chain = match TransformChain::try_from(transforms.as_slice()) {
            Ok(transform_chain) => Some(transform_chain),
            Err(error) => {
                messages.push(ValidationMessage::error(
                    Some(self.index),
                    error.to_string(),
                ));
                None
            }
        };

        let payload_text = self
            .payloads
            .first()
            .and_then(|payload| match &payload.text {
                ParsedPayloadText::Text(text) => Some(text.as_str()),
                ParsedPayloadText::TooLarge { size, limit } => {
                    messages.push(ValidationMessage::error(
                        Some(self.index),
                        Error::PayloadTextTooLarge {
                            size: *size,
                            limit: *limit,
                        }
                        .to_string(),
                    ));
                    None
                }
            });

        if let (Some(transform_chain), Some(payload_text)) = (&transform_chain, payload_text) {
            messages.extend(
                transform_chain
                    .inspect_payload(payload_text)
                    .into_iter()
                    .map(|issue| {
                        ValidationMessage::from_transform_payload_issue(self.index, issue)
                    }),
            );
        }

        messages
    }

    pub(crate) fn profile(&self) -> Option<&ParsedDocumentProfile> {
        self.profiles.first()
    }

    pub(crate) fn payload_text(&self) -> Option<&str> {
        self.payloads
            .first()
            .and_then(|payload| match &payload.text {
                ParsedPayloadText::Text(text) => Some(text.as_str()),
                ParsedPayloadText::TooLarge { .. } => None,
            })
    }

    pub(crate) fn valid_transforms(&self) -> Vec<Transform> {
        self.profile()
            .map(|profile| profile.valid_transforms(&mut Vec::new()))
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedDocumentProfile {
    title: Option<String>,
    format_present: bool,
    mime_type: Option<MimeType>,
    source_size: ParsedSourceSize,
    base_transform_present: bool,
    transforms: Vec<ParsedTransform>,
    index: usize,
}

impl ParsedDocumentProfile {
    fn from_node(index: usize, node: roxmltree::Node<'_, '_>) -> Self {
        let format = child_es(node, "Format");
        let mime_type = format
            .and_then(|format| child_es(format, "MIME-Type"))
            .map(MimeType::from_node);
        let source_size = match child_es(node, "SourceSize") {
            None => ParsedSourceSize::MissingElement,
            Some(source_size) => source_size
                .attribute("sizeValue")
                .map(ToOwned::to_owned)
                .map(ParsedSourceSize::Present)
                .unwrap_or(ParsedSourceSize::MissingAttribute),
        };
        let base_transform = child_es(node, "BaseTransform");
        let transforms = base_transform
            .map(|base_transform| {
                children_es(base_transform, "Transform")
                    .map(ParsedTransform::from_node)
                    .collect()
            })
            .unwrap_or_default();

        Self {
            title: child_text(node, "Title"),
            format_present: format.is_some(),
            mime_type,
            source_size,
            base_transform_present: base_transform.is_some(),
            transforms,
            index,
        }
    }

    pub(crate) fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    pub(crate) fn mime_type(&self) -> Option<&MimeType> {
        self.mime_type.as_ref()
    }

    pub(crate) fn source_size(&self) -> Option<u64> {
        match &self.source_size {
            ParsedSourceSize::Present(value) => value.parse().ok(),
            ParsedSourceSize::MissingElement | ParsedSourceSize::MissingAttribute => None,
        }
    }

    fn validate_fields(&self, messages: &mut Vec<ValidationMessage>) {
        if self.title.is_none() {
            messages.push(self.missing("DocumentProfile/Title"));
        }

        match &self.source_size {
            ParsedSourceSize::MissingElement => {
                messages.push(self.missing("DocumentProfile/SourceSize"));
            }
            ParsedSourceSize::MissingAttribute => {
                messages.push(self.missing("DocumentProfile/SourceSize/@sizeValue"));
            }
            ParsedSourceSize::Present(value) => {
                if value.parse::<u64>().is_err() {
                    messages.push(ValidationMessage::error(
                        Some(self.index),
                        Error::InvalidInteger {
                            field: document_profile_path(
                                self.index,
                                "DocumentProfile/SourceSize/@sizeValue",
                            ),
                            value: value.clone(),
                        }
                        .to_string(),
                    ));
                }
            }
        }

        if !self.format_present {
            messages.push(self.missing("DocumentProfile/Format"));
        } else if self.mime_type.is_none() {
            messages.push(self.missing("DocumentProfile/Format/MIME-Type"));
        }

        if !self.base_transform_present {
            messages.push(self.missing("DocumentProfile/BaseTransform"));
        }
    }

    fn valid_transforms(&self, messages: &mut Vec<ValidationMessage>) -> Vec<Transform> {
        let mut transforms = Vec::new();
        for transform in &self.transforms {
            match transform.algorithm.as_deref() {
                None => messages
                    .push(self.missing("DocumentProfile/BaseTransform/Transform/@Algorithm")),
                Some(algorithm) => match algorithm.parse::<Transform>() {
                    Ok(transform) => transforms.push(transform),
                    Err(error) => messages.push(ValidationMessage::error(
                        Some(self.index),
                        error.to_string(),
                    )),
                },
            }
        }
        transforms
    }

    fn missing(&self, suffix: &str) -> ValidationMessage {
        ValidationMessage::error(
            Some(self.index),
            Error::MissingElement {
                element: document_profile_path(self.index, suffix),
            }
            .to_string(),
        )
    }
}

#[derive(Debug, Clone)]
enum ParsedSourceSize {
    MissingElement,
    MissingAttribute,
    Present(String),
}

#[derive(Debug, Clone)]
struct ParsedTransform {
    algorithm: Option<String>,
}

impl ParsedTransform {
    fn from_node(node: roxmltree::Node<'_, '_>) -> Self {
        Self {
            algorithm: node.attribute("Algorithm").map(ToOwned::to_owned),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedPayload {
    text: ParsedPayloadText,
}

impl ParsedPayload {
    fn from_node(node: roxmltree::Node<'_, '_>) -> Self {
        Self {
            text: ParsedPayloadText::from_node(node),
        }
    }
}

#[derive(Debug, Clone)]
enum ParsedPayloadText {
    Text(String),
    TooLarge { size: usize, limit: usize },
}

impl ParsedPayloadText {
    fn from_node(node: roxmltree::Node<'_, '_>) -> Self {
        let mut text_len = 0usize;
        for child in node.children().filter(|child| child.is_text()) {
            let text = child.text().unwrap_or_default();
            text_len = text_len.saturating_add(text.len());
            if text_len > crate::transform::MAX_PAYLOAD_TEXT_SIZE {
                return Self::TooLarge {
                    size: text_len,
                    limit: crate::transform::MAX_PAYLOAD_TEXT_SIZE,
                };
            }
        }

        let mut payload_text = String::with_capacity(text_len);
        for child in node.children().filter(|child| child.is_text()) {
            payload_text.push_str(child.text().unwrap_or_default());
        }
        Self::Text(payload_text)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidationMessage {
    pub(crate) document_index: Option<usize>,
    pub(crate) severity: ValidationSeverity,
    pub(crate) message: String,
}

impl ValidationMessage {
    fn error(document_index: Option<usize>, message: impl Into<String>) -> Self {
        Self {
            document_index,
            severity: ValidationSeverity::Error,
            message: message.into(),
        }
    }

    fn warning(document_index: Option<usize>, message: impl Into<String>) -> Self {
        Self {
            document_index,
            severity: ValidationSeverity::Warning,
            message: message.into(),
        }
    }

    fn from_transform_payload_issue(index: usize, issue: TransformPayloadIssue) -> Self {
        match issue {
            TransformPayloadIssue::Error(error) => Self::error(Some(index), error.to_string()),
            TransformPayloadIssue::EncryptedPayloadWarning => {
                Self::warning(Some(index), ENCRYPTED_PAYLOAD_WARNING)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValidationSeverity {
    Error,
    Warning,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(xml: &str) -> ParsedDossier {
        xml.parse().unwrap()
    }

    #[test]
    fn parsed_dossier_collects_document_facts_without_validating() {
        let dossier = parse(
            r##"<es:Dossier xmlns:es="urn:test" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <es:Documents>
    <es:Document>
      <es:DocumentProfile>
        <es:Title>Invoice</es:Title>
        <es:Format><es:MIME-Type type="text" subtype="plain"/></es:Format>
        <es:SourceSize sizeValue="11"/>
        <es:BaseTransform><es:Transform Algorithm="base64"/></es:BaseTransform>
      </es:DocumentProfile>
      <ds:Object>SGVsbG8=</ds:Object>
      <ds:Signature/>
      <es:TimeStamp/>
    </es:Document>
  </es:Documents>
  <ds:Signature/>
  <es:TimeStamp/>
</es:Dossier>"##,
        );

        assert!(dossier.root_valid);
        assert!(dossier.documents_present);
        assert_eq!(dossier.documents.len(), 1);
        assert_eq!(dossier.documents[0].signature_count, 1);
        assert_eq!(dossier.documents[0].timestamp_count, 1);
        assert_eq!(dossier.dossier_signature_count, 1);
        assert_eq!(dossier.dossier_timestamp_count, 1);
    }
}
