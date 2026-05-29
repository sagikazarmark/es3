use es3::{DocumentEntry, Dossier, StructureReport, Transform, VerificationOptions};

use crate::model::{DocumentRow, DownloadFile};

#[derive(Debug, Clone)]
pub struct LoadedDossier {
    pub file_name: String,
    pub dossier: Dossier,
    pub rows: Vec<DocumentRow>,
    pub report: StructureReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadDecision {
    Current,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadAllCandidate {
    pub index: usize,
    pub title: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadAllDecision {
    NoSupportedFiles {
        notice: String,
    },
    RequestDownloads {
        files: Vec<DownloadFile>,
        failures: Vec<String>,
    },
}

pub fn load_decision(current_generation: usize, generation: usize) -> LoadDecision {
    if current_generation == generation {
        LoadDecision::Current
    } else {
        LoadDecision::Stale
    }
}

pub fn parse_file(file_name: String, xml: &str) -> Result<LoadedDossier, String> {
    let report = es3::verify_str(xml, VerificationOptions::without_signatures()).structure;
    let dossier = xml.parse::<Dossier>().map_err(|error| error.to_string())?;
    let rows = document_rows(&dossier);

    Ok(LoadedDossier {
        file_name,
        dossier,
        rows,
        report,
    })
}

pub fn document_rows(dossier: &Dossier) -> Vec<DocumentRow> {
    dossier
        .documents()
        .into_iter()
        .map(|entry| row_from_entry(&entry))
        .collect()
}

pub fn plan_download_all(loaded: &LoadedDossier) -> Vec<DownloadAllCandidate> {
    loaded
        .dossier
        .documents()
        .into_iter()
        .filter(DocumentEntry::can_extract)
        .map(|entry| DownloadAllCandidate {
            index: entry.index(),
            title: entry.title().to_owned(),
        })
        .collect()
}

pub fn extract_all_supported(loaded: &LoadedDossier) -> DownloadAllDecision {
    let mut files = Vec::new();
    let mut failures = Vec::new();

    for candidate in plan_download_all(loaded) {
        match extract_document_for_download(&loaded.dossier, candidate.index) {
            Ok(file) => files.push(file),
            Err(error) => failures.push(extraction_failure(&candidate.title, &error)),
        }
    }

    download_all_decision(files, failures)
}

pub fn extract_for_download(loaded: &LoadedDossier, index: usize) -> Result<DownloadFile, String> {
    extract_document_for_download(&loaded.dossier, index).map_err(|error| {
        loaded
            .rows
            .iter()
            .find(|row| row.index == index)
            .map(|row| extraction_failure(&row.title, &error))
            .unwrap_or(error)
    })
}

fn extract_document_for_download(dossier: &Dossier, index: usize) -> Result<DownloadFile, String> {
    let extracted = dossier
        .extract_document(index)
        .map_err(|error| error.to_string())?;

    Ok(DownloadFile {
        filename: extracted.filename,
        bytes: extracted.bytes,
    })
}

pub fn extraction_failure(title: &str, error: &str) -> String {
    format!("{title}: {error}")
}

pub fn download_failure(filename: &str, error: &str) -> String {
    format!("{filename}: {error}")
}

pub fn download_all_decision(
    files: Vec<DownloadFile>,
    failures: Vec<String>,
) -> DownloadAllDecision {
    if files.is_empty() {
        DownloadAllDecision::NoSupportedFiles {
            notice: no_supported_files_notice(&failures),
        }
    } else {
        DownloadAllDecision::RequestDownloads { files, failures }
    }
}

pub fn no_supported_files_notice(failures: &[String]) -> String {
    if failures.is_empty() {
        "No supported files are available to download.".to_owned()
    } else {
        join_failures(failures)
    }
}

fn row_from_entry(entry: &DocumentEntry) -> DocumentRow {
    DocumentRow {
        index: entry.index(),
        title: entry.title().to_owned(),
        filename: entry.suggested_filename(),
        mime_type: entry.mime_type().to_string(),
        source_size: entry.source_size(),
        transforms: transform_list(entry.transforms()),
        signature_count: entry.signature_count(),
        timestamp_count: entry.timestamp_count(),
        can_download: entry.can_extract(),
        unavailable_reason: entry.unavailable_reason().map(ToOwned::to_owned),
        unavailable_reason_code: entry.unavailable_reason_code(),
    }
}

fn transform_list(transforms: &[Transform]) -> String {
    if transforms.is_empty() {
        "-".to_owned()
    } else {
        transforms
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn join_failures(failures: &[String]) -> String {
    failures.join("; ")
}
