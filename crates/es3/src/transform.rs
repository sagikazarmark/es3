use std::fmt;
use std::io::{Cursor, Read};
use std::str::FromStr;

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transform {
    Zip,
    Encrypt,
    Base64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionUnavailableReason {
    EncryptedDocument,
}

impl ExtractionUnavailableReason {
    pub fn message(self) -> &'static str {
        match self {
            Self::EncryptedDocument => "Encrypted document extraction is not supported",
        }
    }
}

impl Transform {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::Encrypt => "encrypt",
            Self::Base64 => "base64",
        }
    }
}

impl fmt::Display for Transform {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Transform {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "zip" => Ok(Self::Zip),
            "encrypt" => Ok(Self::Encrypt),
            "base64" => Ok(Self::Base64),
            other => Err(Error::UnknownTransform {
                algorithm: other.to_owned(),
            }),
        }
    }
}

impl TryFrom<&str> for Transform {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        value.parse()
    }
}

pub(crate) const MAX_ZIP_ENTRY_SIZE: u64 = 512 * 1024 * 1024;
pub(crate) const MAX_PAYLOAD_TEXT_SIZE: usize = 16 * 1024 * 1024;
const MAX_BASE64_PAYLOAD_TEXT_SIZE: usize = MAX_PAYLOAD_TEXT_SIZE;
const INVALID_TRANSFORM_ORDER_MESSAGE: &str =
    "invalid transform order: expected base64, zip+base64, encrypt+base64, or zip+encrypt+base64";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransformValidationError {
    InvalidOrder,
}

impl TransformValidationError {
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::InvalidOrder => INVALID_TRANSFORM_ORDER_MESSAGE,
        }
    }
}

impl fmt::Display for TransformValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransformChain {
    transforms: Vec<Transform>,
}

impl TryFrom<&[Transform]> for TransformChain {
    type Error = TransformValidationError;

    fn try_from(transforms: &[Transform]) -> std::result::Result<Self, Self::Error> {
        match transforms {
            [Transform::Base64]
            | [Transform::Zip, Transform::Base64]
            | [Transform::Encrypt, Transform::Base64]
            | [Transform::Zip, Transform::Encrypt, Transform::Base64] => Ok(Self {
                transforms: transforms.to_vec(),
            }),
            _ => Err(TransformValidationError::InvalidOrder),
        }
    }
}

impl TransformChain {
    pub(crate) fn extraction_support(&self) -> ExtractionSupport {
        if self.transforms.contains(&Transform::Encrypt) {
            ExtractionSupport::EncryptedUnsupported
        } else {
            ExtractionSupport::Supported
        }
    }

    pub(crate) fn decode_payload(&self, payload_text: &str) -> Result<Vec<u8>> {
        let mut bytes = None;

        for transform in self.transforms.iter().rev() {
            let current = bytes.take();
            bytes = Some(match transform {
                Transform::Base64 => decode_base64(
                    std::str::from_utf8(
                        current
                            .as_deref()
                            .unwrap_or_else(|| payload_text.as_bytes()),
                    )
                    .unwrap_or_default(),
                )?,
                Transform::Zip => unzip_single_file(
                    current
                        .as_deref()
                        .unwrap_or_else(|| payload_text.as_bytes()),
                )?,
                Transform::Encrypt => return Err(Error::EncryptedDocumentUnsupported),
            });
        }

        Ok(bytes.unwrap_or_else(|| payload_text.as_bytes().to_vec()))
    }

    pub(crate) fn inspect_payload(&self, payload_text: &str) -> Vec<TransformPayloadIssue> {
        let mut issues = Vec::new();

        if payload_text.len() > MAX_PAYLOAD_TEXT_SIZE {
            issues.push(TransformPayloadIssue::Error(Error::PayloadTextTooLarge {
                size: payload_text.len(),
                limit: MAX_PAYLOAD_TEXT_SIZE,
            }));
            return issues;
        }

        if self.is_encrypted_payload() {
            issues.push(TransformPayloadIssue::EncryptedPayloadWarning);
        }

        let bytes = match decode_base64(payload_text) {
            Ok(decoded) => Some(decoded),
            Err(error) => {
                issues.push(TransformPayloadIssue::Error(error));
                None
            }
        };

        if !self.is_encrypted_payload() && self.has_zip() {
            if let Some(bytes) = bytes {
                if let Err(error) = unzip_single_file(&bytes) {
                    issues.push(TransformPayloadIssue::Error(error));
                }
            }
        }

        issues
    }

    fn is_encrypted_payload(&self) -> bool {
        matches!(
            self.transforms.as_slice(),
            [Transform::Encrypt, Transform::Base64]
                | [Transform::Zip, Transform::Encrypt, Transform::Base64]
        )
    }

    fn has_zip(&self) -> bool {
        self.transforms.contains(&Transform::Zip)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtractionSupport {
    Supported,
    EncryptedUnsupported,
}

impl ExtractionSupport {
    pub(crate) fn can_extract(self) -> bool {
        matches!(self, Self::Supported)
    }

    pub(crate) fn unavailable_reason_code(self) -> Option<ExtractionUnavailableReason> {
        match self {
            Self::Supported => None,
            Self::EncryptedUnsupported => Some(ExtractionUnavailableReason::EncryptedDocument),
        }
    }
}

pub(crate) enum TransformPayloadIssue {
    Error(Error),
    EncryptedPayloadWarning,
}

fn decode_base64(payload_text: &str) -> Result<Vec<u8>> {
    if payload_text.len() > MAX_BASE64_PAYLOAD_TEXT_SIZE {
        return Err(Error::Base64PayloadTooLarge {
            size: payload_text.len(),
            limit: MAX_BASE64_PAYLOAD_TEXT_SIZE,
        });
    }

    let stripped = payload_text
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();

    Ok(base64::engine::general_purpose::STANDARD.decode(stripped)?)
}

fn unzip_single_file(bytes: &[u8]) -> Result<Vec<u8>> {
    let cursor = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor)?;
    let mut file_index = None;
    let mut file_count = 0;

    for index in 0..archive.len() {
        let file = archive.by_index(index)?;
        if !file.is_dir() {
            file_index = Some(index);
            file_count += 1;
        }
    }

    let Some(file_index) = file_index.filter(|_| file_count == 1) else {
        return Err(Error::InvalidZipEntryCount { count: file_count });
    };

    let file = archive.by_index(file_index)?;
    let name = file.name()?.into_owned();
    let declared_size = file.size();
    if declared_size > MAX_ZIP_ENTRY_SIZE {
        return Err(Error::ZipEntryTooLarge {
            size: declared_size,
            limit: MAX_ZIP_ENTRY_SIZE,
        });
    }

    let mut output = Vec::new();
    file.take(MAX_ZIP_ENTRY_SIZE + 1)
        .read_to_end(&mut output)
        .map_err(|source| Error::ReadZipEntry { name, source })?;

    if output.len() as u64 > MAX_ZIP_ENTRY_SIZE {
        return Err(Error::ZipEntryTooLarge {
            size: output.len() as u64,
            limit: MAX_ZIP_ENTRY_SIZE,
        });
    }

    Ok(output)
}
