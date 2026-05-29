use thiserror::Error as ThisError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, ThisError)]
#[non_exhaustive]
pub enum Error {
    #[error("failed to read ES3 XML input: {source}")]
    ReadInput { source: std::io::Error },

    #[error("ES3 XML is not valid UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("failed to parse XML: {0}")]
    Xml(#[from] roxmltree::Error),

    #[error(
        "XML parser attribute marker limit reached: {markers} attribute markers exceeds {limit} marker limit"
    )]
    XmlAttributeMarkerLimitReached { markers: usize, limit: usize },

    #[error("root element must be es:Dossier in the ES3 namespace")]
    InvalidRoot,

    #[error("missing required element {element}")]
    MissingElement { element: String },

    #[error("document {index} must have exactly one direct ds:Object payload, found {count}")]
    InvalidPayloadCount { index: usize, count: usize },

    #[error("unknown transform algorithm {algorithm}")]
    UnknownTransform { algorithm: String },

    #[error(
        "invalid transform order: expected base64, zip+base64, encrypt+base64, or zip+encrypt+base64"
    )]
    InvalidTransformOrder,

    #[error("invalid integer in {field}: {value}")]
    InvalidInteger { field: String, value: String },

    #[error("{message}")]
    InvalidStructure { message: String },

    #[error("invalid base64 payload: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("base64 payload text is too large: {size} bytes exceeds {limit} byte limit")]
    Base64PayloadTooLarge { size: usize, limit: usize },

    #[error("document payload text is too large: {size} bytes exceeds {limit} byte limit")]
    PayloadTextTooLarge { size: usize, limit: usize },

    #[error("zip payload error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("zip payload must contain exactly one file entry, found {count}")]
    InvalidZipEntryCount { count: usize },

    #[error("zip entry is too large: {size} bytes exceeds {limit} byte limit")]
    ZipEntryTooLarge { size: u64, limit: u64 },

    #[error("failed to read zip entry {name}: {source}")]
    ReadZipEntry {
        name: String,
        source: std::io::Error,
    },

    #[error("encrypted document extraction is not supported")]
    EncryptedDocumentUnsupported,

    #[error("document index {index} is out of range")]
    DocumentIndexOutOfRange { index: usize },

    #[error("no document title matches {title:?}")]
    DocumentTitleNotFound { title: String },

    #[error("multiple documents match title {title:?}; use --index")]
    AmbiguousDocumentTitle { title: String },
}
