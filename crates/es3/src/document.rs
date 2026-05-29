use std::fmt;

use serde::{Deserialize, Serialize};

use crate::parsed::{ParsedDocument, ValidationMessage, ValidationSeverity};
use crate::transform::{ExtractionUnavailableReason, Transform, TransformChain};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MimeType {
    #[serde(rename = "type")]
    top_level_type: String,
    subtype: String,
    extension: Option<String>,
    charset: Option<String>,
}

impl MimeType {
    pub fn top_level_type(&self) -> &str {
        &self.top_level_type
    }

    pub fn subtype(&self) -> &str {
        &self.subtype
    }

    pub fn extension(&self) -> Option<&str> {
        self.extension.as_deref()
    }

    pub fn charset(&self) -> Option<&str> {
        self.charset.as_deref()
    }

    pub(crate) fn from_node(node: roxmltree::Node<'_, '_>) -> Self {
        Self {
            top_level_type: node.attribute("type").unwrap_or_default().to_owned(),
            subtype: node.attribute("subtype").unwrap_or_default().to_owned(),
            extension: non_empty_attribute(node, "extension"),
            charset: non_empty_attribute(node, "charset")
                .or_else(|| non_empty_attribute(node, "charSet")),
        }
    }
}

impl fmt::Display for MimeType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.top_level_type, self.subtype)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentEntry {
    index: usize,
    title: String,
    mime_type: MimeType,
    source_size: u64,
    transforms: Vec<Transform>,
    extraction: ExtractionCapability,
    signature_count: usize,
    timestamp_count: usize,
}

impl DocumentEntry {
    pub fn index(&self) -> usize {
        self.index
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn mime_type(&self) -> &MimeType {
        &self.mime_type
    }

    pub fn source_size(&self) -> u64 {
        self.source_size
    }

    pub fn transforms(&self) -> &[Transform] {
        &self.transforms
    }

    pub fn extraction(&self) -> &ExtractionCapability {
        &self.extraction
    }

    pub fn signature_count(&self) -> usize {
        self.signature_count
    }

    pub fn timestamp_count(&self) -> usize {
        self.timestamp_count
    }

    pub fn suggested_filename(&self) -> String {
        crate::output::filename_for(self)
    }

    pub fn can_extract(&self) -> bool {
        self.extraction.can_extract()
    }

    pub fn unavailable_reason(&self) -> Option<&str> {
        self.extraction.unavailable_reason()
    }

    pub fn unavailable_reason_code(&self) -> Option<ExtractionUnavailableReason> {
        self.extraction.unavailable_reason_code()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractionCapability {
    can_extract: bool,
    unavailable_reason: Option<String>,
    unavailable_reason_code: Option<ExtractionUnavailableReason>,
}

impl ExtractionCapability {
    pub fn can_extract(&self) -> bool {
        self.can_extract
    }

    pub fn unavailable_reason(&self) -> Option<&str> {
        self.unavailable_reason.as_deref()
    }

    pub fn unavailable_reason_code(&self) -> Option<ExtractionUnavailableReason> {
        self.unavailable_reason_code
    }

    pub(crate) fn from_chain(transform_chain: &TransformChain) -> Self {
        let support = transform_chain.extraction_support();
        let unavailable_reason_code = support.unavailable_reason_code();

        Self {
            can_extract: support.can_extract(),
            unavailable_reason: unavailable_reason_code.map(|reason| reason.message().to_owned()),
            unavailable_reason_code,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct StoredDocument {
    pub(crate) entry: DocumentEntry,
    pub(crate) payload_text: String,
    pub(crate) transform_chain: TransformChain,
    pub(crate) structural_warnings: Vec<ValidationMessage>,
}

impl StoredDocument {
    pub(crate) fn from_parsed(document: ParsedDocument) -> Self {
        let index = document.index;
        let profile = document
            .profile()
            .expect("validated parsed document must have a profile");
        let title = profile
            .title()
            .expect("validated parsed document profile must have a title")
            .to_owned();
        let mime_type = profile
            .mime_type()
            .expect("validated parsed document profile must have a MIME type")
            .clone();
        let source_size = profile
            .source_size()
            .expect("validated parsed document profile must have a valid source size");
        let payload_text = document
            .payload_text()
            .expect("validated parsed document must have payload text")
            .to_owned();
        let transforms = document.valid_transforms();
        let transform_chain = TransformChain::try_from(transforms.as_slice())
            .expect("validated parsed document must have a valid transform chain");
        let extraction = ExtractionCapability::from_chain(&transform_chain);
        let structural_warnings = document
            .validation_messages()
            .into_iter()
            .filter(|message| message.severity == ValidationSeverity::Warning)
            .collect();

        Self {
            entry: DocumentEntry {
                index,
                title,
                mime_type,
                source_size,
                transforms,
                extraction,
                signature_count: document.signature_count,
                timestamp_count: document.timestamp_count,
            },
            payload_text,
            transform_chain,
            structural_warnings,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedDocument {
    pub entry: DocumentEntry,
    pub filename: String,
    pub bytes: Vec<u8>,
}

fn non_empty_attribute(node: roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
    node.attribute(name)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}
