use es3::{Dossier, Transform, VerificationOptions};

const ES3_WITH_SIGNATURE_OBJECT: &str = r##"<?xml version="1.0" encoding="UTF-8"?>
<e:Dossier xmlns:e="https://www.microsec.hu/ds/e-szigno30#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <e:DossierProfile Id="Profile0" OBJREF="#Object0">
    <e:Title>Test dossier</e:Title>
    <e:CreationDate>2026-05-16T00:00:00Z</e:CreationDate>
  </e:DossierProfile>
  <e:Documents Id="Object0">
    <e:Document>
      <e:DocumentProfile Id="Profile1" OBJREF="#Payload1">
        <e:Title>Invoice 1</e:Title>
        <e:CreationDate>2026-05-16T00:00:00Z</e:CreationDate>
        <e:Format><e:MIME-Type type="text" subtype="plain" extension="txt" charset="utf-8"/></e:Format>
        <e:SourceSize sizeValue="11" sizeUnit="B"/>
        <e:BaseTransform><e:Transform Algorithm="base64"/></e:BaseTransform>
      </e:DocumentProfile>
      <ds:Object Id="Payload1">SGVsbG8gd29ybGQ=</ds:Object>
      <ds:Signature Id="Sig1"><ds:Object Id="SignatureObject">not a payload</ds:Object></ds:Signature>
      <e:TimeStamp>timestamp</e:TimeStamp>
    </e:Document>
  </e:Documents>
  <ds:Signature Id="FrameSig"><ds:Object Id="FrameObject">frame signature object</ds:Object></ds:Signature>
  <e:TimeStamp>frame timestamp</e:TimeStamp>
</e:Dossier>"##;

fn es3_with_payload(payload: &str) -> String {
    ES3_WITH_SIGNATURE_OBJECT.replace("SGVsbG8gd29ybGQ=", payload)
}

fn es3_with_payload_children(children: &str) -> String {
    ES3_WITH_SIGNATURE_OBJECT.replace("SGVsbG8gd29ybGQ=", children)
}

fn oversized_payload_text() -> String {
    "A".repeat(16_777_220)
}

fn assert_public_parse_success(dossier: Dossier) {
    assert_eq!(dossier.documents()[0].title(), "Invoice 1");
    assert_eq!(dossier.source_xml(), ES3_WITH_SIGNATURE_OBJECT);
}

#[test]
fn lists_document_metadata_and_ignores_signature_objects() {
    let dossier = ES3_WITH_SIGNATURE_OBJECT.parse::<Dossier>().unwrap();
    let documents = dossier.documents();

    assert_eq!(documents.len(), 1);
    assert_eq!(documents[0].index(), 0);
    assert_eq!(documents[0].title(), "Invoice 1");
    assert_eq!(documents[0].source_size(), 11);
    assert_eq!(documents[0].transforms(), &[Transform::Base64]);
    assert_eq!(documents[0].signature_count(), 1);
    assert_eq!(documents[0].timestamp_count(), 1);
    assert_eq!(dossier.dossier_signature_count(), 1);
    assert_eq!(dossier.dossier_timestamp_count(), 1);
    assert_eq!(documents[0].mime_type().top_level_type(), "text");
    assert_eq!(documents[0].mime_type().subtype(), "plain");
    assert_eq!(documents[0].mime_type().extension(), Some("txt"));
    assert_eq!(documents[0].mime_type().charset(), Some("utf-8"));
}

#[test]
fn verifies_structure_before_materializing_dossier() {
    let report = es3::verify_str("<not-es3/>", VerificationOptions::without_signatures());

    assert!(!report.structure.is_ok());
    assert_eq!(
        report.structure.errors[0].message,
        "root element must be es:Dossier in the ES3 namespace"
    );
}

#[test]
fn dossier_parse_runs_validation() {
    let dossier = ES3_WITH_SIGNATURE_OBJECT.parse::<Dossier>().unwrap();

    assert_eq!(dossier.documents()[0].title(), "Invoice 1");

    let error = "<not-es3/>".parse::<Dossier>().unwrap_err();

    assert_eq!(
        error.to_string(),
        "root element must be es:Dossier in the ES3 namespace"
    );
}

#[test]
fn parses_public_success_adapters() {
    assert_public_parse_success(ES3_WITH_SIGNATURE_OBJECT.parse::<Dossier>().unwrap());
    assert_public_parse_success(Dossier::from_bytes(ES3_WITH_SIGNATURE_OBJECT.as_bytes()).unwrap());
    assert_public_parse_success(Dossier::try_from(ES3_WITH_SIGNATURE_OBJECT.as_bytes()).unwrap());
    assert_public_parse_success(Dossier::try_from(ES3_WITH_SIGNATURE_OBJECT).unwrap());
    assert_public_parse_success(
        Dossier::from_reader(std::io::Cursor::new(ES3_WITH_SIGNATURE_OBJECT.as_bytes())).unwrap(),
    );
}

#[test]
fn from_bytes_rejects_non_utf8_input() {
    let error = Dossier::from_bytes(&[0xff, b'<', b'e', b's']).unwrap_err();

    assert!(
        error.to_string().contains("ES3 XML is not valid UTF-8"),
        "expected UTF-8 error, got {error:?}"
    );
}

#[test]
fn from_reader_reports_path_free_read_errors() {
    struct BrokenReader;

    impl std::io::Read for BrokenReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "reader failed",
            ))
        }
    }

    let error = Dossier::from_reader(BrokenReader).unwrap_err();

    assert!(
        error.to_string().contains("failed to read ES3 XML input"),
        "expected path-free read error, got {error:?}"
    );
    assert!(
        !error.to_string().contains("sample.es3"),
        "reader error must not invent a filesystem path: {error:?}"
    );
}

#[test]
fn documents_iter_borrows_document_entries() {
    let dossier = ES3_WITH_SIGNATURE_OBJECT.parse::<Dossier>().unwrap();
    let titles = dossier
        .documents_iter()
        .map(|document| document.title())
        .collect::<Vec<_>>();

    assert_eq!(titles, vec!["Invoice 1"]);
}

#[test]
fn accepts_xsd_charset_spelling() {
    let xml = ES3_WITH_SIGNATURE_OBJECT.replace("charset=\"utf-8\"", "charSet=\"iso-8859-2\"");
    let dossier = xml.parse::<Dossier>().unwrap();
    assert_eq!(
        dossier.documents()[0].mime_type().charset(),
        Some("iso-8859-2")
    );
}

#[test]
fn parses_schema_specific_dossier_namespace() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<es:Dossier xmlns="http://uri.etsi.org/01903/v1.3.2#" xmlns:es="http://www.e-cegjegyzek.hu/2023/e-cegeljaras#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <es:DossierProfile Id="PObject0" OBJREF="Object0">
    <es:Title>Schema specific dossier</es:Title>
    <es:CreationDate>2026-05-13T12:53:21Z</es:CreationDate>
  </es:DossierProfile>
  <es:Documents Id="Object0">
    <es:Document>
      <es:DocumentProfile Id="Profile1" OBJREF="Payload1">
        <es:Title>A létesítő okirat</es:Title>
        <es:CreationDate>2026-05-13T12:53:56Z</es:CreationDate>
        <es:Format><es:MIME-Type type="application" subtype="pdf" extension="pdf"/></es:Format>
        <es:SourceSize sizeValue="11" sizeUnit="B"/>
        <es:BaseTransform><es:Transform Algorithm="base64"/></es:BaseTransform>
      </es:DocumentProfile>
      <ds:Object Id="Payload1">SGVsbG8gd29ybGQ=</ds:Object>
    </es:Document>
  </es:Documents>
</es:Dossier>"#;

    let dossier = xml.parse::<Dossier>().unwrap();
    let documents = dossier.documents();

    assert_eq!(documents.len(), 1);
    assert_eq!(documents[0].title(), "A létesítő okirat");
    assert_eq!(documents[0].mime_type().extension(), Some("pdf"));
}

#[test]
fn parser_rejects_xml_over_node_limit_before_building_dossier() {
    let payload_children = (0..5_000).map(|_| "<x/>").collect::<String>();
    let xml = es3_with_payload_children(&payload_children);

    let error = xml.parse::<Dossier>().unwrap_err();

    assert!(
        error.to_string().contains("nodes limit reached"),
        "expected parser node-limit error, got {error:?}"
    );
}

#[test]
fn structural_verification_rejects_oversized_base64_payload_text() {
    let payload = oversized_payload_text();
    let xml = es3_with_payload(&payload);

    let report = es3::verify_structure_str(&xml);

    assert!(!report.is_ok(), "{report:#?}");
    assert!(
        report.errors.iter().any(|finding| finding
            .message
            .contains("document payload text is too large")),
        "{report:#?}"
    );
}

#[test]
fn parser_rejects_xml_over_attribute_marker_limit_before_building_dossier() {
    let attributes = (0..5_000)
        .map(|index| format!(r#" a{index}="value""#))
        .collect::<String>();
    let xml = ES3_WITH_SIGNATURE_OBJECT.replace("<e:Dossier ", &format!("<e:Dossier{attributes} "));

    let error = xml.parse::<Dossier>().unwrap_err();

    assert!(
        error
            .to_string()
            .contains("XML parser attribute marker limit reached"),
        "expected parser attribute marker error, got {error:?}"
    );
}

#[test]
fn dossier_parse_rejects_oversized_split_payload_text() {
    let payload = format!("A<!-- split -->{}", oversized_payload_text());
    let xml = es3_with_payload(&payload);

    let error = xml.parse::<Dossier>().unwrap_err();

    assert!(
        error
            .to_string()
            .contains("document payload text is too large"),
        "expected split payload text limit error, got {error:?}"
    );
}
