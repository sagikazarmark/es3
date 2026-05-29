use std::io::Write;

use es3::{Dossier, Error, ExtractionUnavailableReason, Transform};
use zip::write::SimpleFileOptions;

fn dossier_with_payload(
    title: &str,
    extension: Option<&str>,
    transforms: &[&str],
    payload: &str,
) -> String {
    let extension_attr = extension
        .map(|extension| format!(" extension=\"{extension}\""))
        .unwrap_or_default();
    let transform_xml = transforms
        .iter()
        .map(|algorithm| format!("<es:Transform Algorithm=\"{algorithm}\"/>"))
        .collect::<String>();

    format!(
        r##"<es:Dossier xmlns:es="https://www.microsec.hu/ds/e-szigno30#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <es:DossierProfile Id="Profile0" OBJREF="#Object0"><es:Title>Dossier</es:Title><es:CreationDate>2026-05-16T00:00:00Z</es:CreationDate></es:DossierProfile>
  <es:Documents Id="Object0">
    <es:Document>
      <es:DocumentProfile Id="Profile1" OBJREF="#Payload1">
        <es:Title>{title}</es:Title>
        <es:CreationDate>2026-05-16T00:00:00Z</es:CreationDate>
        <es:Format><es:MIME-Type type="text" subtype="plain"{extension_attr}/></es:Format>
        <es:SourceSize sizeValue="11" sizeUnit="B"/>
        <es:BaseTransform>{transform_xml}</es:BaseTransform>
      </es:DocumentProfile>
      <ds:Object Id="Payload1">{payload}</ds:Object>
    </es:Document>
  </es:Documents>
</es:Dossier>"##
    )
}

fn zipped_base64_payload() -> String {
    let mut zip_bytes = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut zip_bytes);
        let mut writer = zip::ZipWriter::new(cursor);
        writer
            .start_file("payload.txt", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"Hello world").unwrap();
        writer.finish().unwrap();
    }
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, zip_bytes)
}

fn zipped_base64_payload_with_declared_size(size: u32) -> String {
    let mut zip_bytes = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut zip_bytes);
        let mut writer = zip::ZipWriter::new(cursor);
        writer
            .start_file("payload.txt", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"x").unwrap();
        writer.finish().unwrap();
    }

    zip_bytes[22..26].copy_from_slice(&size.to_le_bytes());
    let central_directory = zip_bytes
        .windows(4)
        .position(|window| window == [0x50, 0x4b, 0x01, 0x02])
        .unwrap();
    zip_bytes[central_directory + 24..central_directory + 28].copy_from_slice(&size.to_le_bytes());

    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, zip_bytes)
}

#[test]
fn extracts_base64_document_bytes_and_filename() {
    let xml = dossier_with_payload("Invoice / 1", Some("txt"), &["base64"], "SGVsbG8gd29ybGQ=");
    let dossier = xml.parse::<Dossier>().unwrap();

    let extracted = dossier.extract_document(0).unwrap();

    assert_eq!(extracted.bytes, b"Hello world");
    assert_eq!(extracted.filename, "Invoice _ 1.txt");
}

#[test]
fn extracts_base64_zip_document_bytes() {
    let payload = zipped_base64_payload();
    let xml = dossier_with_payload("Archive", Some("txt"), &["zip", "base64"], &payload);
    let dossier = xml.parse::<Dossier>().unwrap();

    let extracted = dossier.extract_document(0).unwrap();

    assert_eq!(extracted.bytes, b"Hello world");
    assert_eq!(extracted.filename, "Archive.txt");
}

#[test]
fn extraction_reports_unsupported_encryption() {
    let xml = dossier_with_payload(
        "Secret",
        Some("txt"),
        &["encrypt", "base64"],
        "SGVsbG8gd29ybGQ=",
    );
    let dossier = xml.parse::<Dossier>().unwrap();

    let error = dossier.extract_document(0).unwrap_err();

    assert!(matches!(error, Error::EncryptedDocumentUnsupported));
}

#[test]
fn document_entry_exposes_transform_chain_extraction_support() {
    let encrypted_xml = dossier_with_payload(
        "Secret",
        Some("txt"),
        &["encrypt", "base64"],
        "SGVsbG8gd29ybGQ=",
    );
    let dossier = encrypted_xml.parse::<Dossier>().unwrap();
    let encrypted = dossier.documents().remove(0);

    assert!(!encrypted.can_extract());
    assert_eq!(
        encrypted.transforms(),
        &[Transform::Encrypt, Transform::Base64]
    );
    assert_eq!(
        encrypted.unavailable_reason(),
        Some(ExtractionUnavailableReason::EncryptedDocument.message())
    );
    assert_eq!(
        encrypted.unavailable_reason_code(),
        Some(ExtractionUnavailableReason::EncryptedDocument)
    );
    assert_eq!(
        encrypted.extraction().unavailable_reason_code(),
        Some(ExtractionUnavailableReason::EncryptedDocument)
    );

    let plain_xml = dossier_with_payload("Plain", Some("txt"), &["base64"], "SGVsbG8=");
    let dossier = plain_xml.parse::<Dossier>().unwrap();
    let plain = dossier.documents().remove(0);

    assert!(plain.can_extract());
    assert_eq!(plain.unavailable_reason(), None);
    assert_eq!(plain.unavailable_reason_code(), None);
}

#[test]
fn dossier_parse_rejects_invalid_transform_chain() {
    let invalid_xml = dossier_with_payload("Broken", Some("txt"), &["zip"], "not a zip payload");
    let error = invalid_xml.parse::<Dossier>().unwrap_err();
    let report = es3::verify_structure_str(&invalid_xml);

    assert_eq!(
        error.to_string(),
        "invalid transform order: expected base64, zip+base64, encrypt+base64, or zip+encrypt+base64"
    );
    assert!(
        report
            .errors
            .iter()
            .any(|finding| finding.message.contains("transform order"))
    );
}

#[test]
fn dossier_parse_rejects_zip_entry_over_size_limit() {
    let size = 512 * 1024 * 1024 + 1;
    let payload = zipped_base64_payload_with_declared_size(size);
    let xml = dossier_with_payload("Too large", Some("txt"), &["zip", "base64"], &payload);

    let error = xml.parse::<Dossier>().unwrap_err();

    assert_eq!(
        error.to_string(),
        "zip entry is too large: 536870913 bytes exceeds 536870912 byte limit"
    );
}
