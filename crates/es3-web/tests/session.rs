mod common;

use es3_web::model::DownloadFile;
use es3_web::session::{self, DownloadAllCandidate, DownloadAllDecision};

#[test]
fn supported_download_plan_uses_loaded_dossier_session_interface() {
    let loaded =
        session::parse_file("sample.es3".to_owned(), &common::xml_with_two_documents()).unwrap();

    let candidates = session::plan_download_all(&loaded);

    assert_eq!(
        candidates,
        vec![DownloadAllCandidate {
            index: 0,
            title: "Plain".to_owned()
        }]
    );
}

#[test]
fn download_all_decision_preserves_partial_extraction_failures() {
    let decision = session::download_all_decision(
        vec![DownloadFile {
            filename: "Plain.txt".to_owned(),
            bytes: b"Hello world".to_vec(),
        }],
        vec!["Broken: invalid base64 payload: Invalid padding".to_owned()],
    );

    assert_eq!(
        decision,
        DownloadAllDecision::RequestDownloads {
            files: vec![DownloadFile {
                filename: "Plain.txt".to_owned(),
                bytes: b"Hello world".to_vec(),
            }],
            failures: vec!["Broken: invalid base64 payload: Invalid padding".to_owned()],
        }
    );
}

#[test]
fn parse_file_rejects_invalid_base64_before_download_planning() {
    let error = session::parse_file(
        "bad.es3".to_owned(),
        &common::xml_with_document("Broken", "not valid base64", &["base64"]),
    )
    .unwrap_err();

    assert!(
        error.contains("invalid base64 payload"),
        "expected base64 validation error, got {error}"
    );
}

#[test]
fn unsupported_documents_report_no_supported_files_through_loaded_session() {
    let loaded = session::parse_file(
        "encrypted.es3".to_owned(),
        &common::xml_with_document("Secret", "SGVsbG8gd29ybGQ=", &["encrypt", "base64"]),
    )
    .unwrap();

    let decision = session::extract_all_supported(&loaded);

    assert_eq!(
        decision,
        DownloadAllDecision::NoSupportedFiles {
            notice: "No supported files are available to download.".to_owned()
        }
    );
}
