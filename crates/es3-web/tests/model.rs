mod common;

use es3::Dossier;
use es3_web::session::{document_rows, extract_for_download, parse_file};

#[test]
fn document_rows_include_download_metadata() {
    let xml = common::xml_with_transform("Invoice / 1", &["base64"]);
    let dossier = xml.parse::<Dossier>().unwrap();

    let rows = document_rows(&dossier);

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].title, "Invoice / 1");
    assert_eq!(rows[0].filename, "Invoice _ 1.txt");
    assert_eq!(rows[0].mime_type, "text/plain");
    assert_eq!(rows[0].transforms, "base64");
    assert!(rows[0].can_download);
    assert_eq!(rows[0].unavailable_reason, None);
    assert_eq!(rows[0].unavailable_reason_code, None);

    let entry = dossier.documents().remove(0);
    assert_eq!(rows[0].can_download, entry.can_extract());
}

#[test]
fn encrypted_documents_are_visible_but_disabled() {
    let xml = common::xml_with_transform("Secret", &["encrypt", "base64"]);
    let dossier = xml.parse::<Dossier>().unwrap();

    let rows = document_rows(&dossier);

    assert_eq!(rows[0].title, "Secret");
    assert!(!rows[0].can_download);
    assert_eq!(
        rows[0].unavailable_reason.as_deref(),
        Some(es3::ExtractionUnavailableReason::EncryptedDocument.message())
    );
    assert_eq!(
        rows[0].unavailable_reason_code,
        Some(es3::ExtractionUnavailableReason::EncryptedDocument)
    );
}

#[test]
fn parse_file_builds_loaded_state_without_persistence() {
    let xml = common::xml_with_transform("Invoice", &["base64"]);

    let loaded = parse_file("sample.es3".to_owned(), &xml).unwrap();

    assert_eq!(loaded.file_name, "sample.es3");
    assert_eq!(loaded.rows.len(), 1);
    assert_eq!(loaded.report.document_count, 1);
}

#[test]
fn extract_for_download_returns_filename_and_bytes() {
    let xml = common::xml_with_transform("Invoice", &["base64"]);
    let loaded = parse_file("sample.es3".to_owned(), &xml).unwrap();

    let file = extract_for_download(&loaded, 0).unwrap();

    assert_eq!(file.filename, "Invoice.txt");
    assert_eq!(file.bytes, b"Hello world");
}
