#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentRow {
    pub index: usize,
    pub title: String,
    pub filename: String,
    pub mime_type: String,
    pub source_size: u64,
    pub transforms: String,
    pub signature_count: usize,
    pub timestamp_count: usize,
    pub can_download: bool,
    pub unavailable_reason: Option<String>,
    pub unavailable_reason_code: Option<es3::ExtractionUnavailableReason>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadFile {
    pub filename: String,
    pub bytes: Vec<u8>,
}
