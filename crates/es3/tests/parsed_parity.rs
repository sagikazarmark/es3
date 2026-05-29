use std::io::Write;

use es3::{Dossier, Finding, StructureReport, Transform, VerificationOptions};
use zip::write::SimpleFileOptions;

const INVALID_TRANSFORM_ORDER: &str =
    "invalid transform order: expected base64, zip+base64, encrypt+base64, or zip+encrypt+base64";

fn valid_xml() -> &'static str {
    r##"<es:Dossier xmlns:es="https://www.microsec.hu/ds/e-szigno30#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <es:DossierProfile Id="Profile0" OBJREF="#Object0"><es:Title>Dossier</es:Title><es:CreationDate>2026-05-16T00:00:00Z</es:CreationDate></es:DossierProfile>
  <es:Documents Id="Object0">
    <es:Document>
      <es:DocumentProfile Id="Profile1" OBJREF="#Payload1">
        <es:Title>Invoice</es:Title>
        <es:CreationDate>2026-05-16T00:00:00Z</es:CreationDate>
        <es:Format><es:MIME-Type type="text" subtype="plain" extension="txt"/></es:Format>
        <es:SourceSize sizeValue="11" sizeUnit="B"/>
        <es:BaseTransform><es:Transform Algorithm="base64"/></es:BaseTransform>
      </es:DocumentProfile>
      <ds:Object Id="Payload1">SGVsbG8gd29ybGQ=</ds:Object>
      <ds:Signature/>
      <es:TimeStamp/>
    </es:Document>
  </es:Documents>
  <ds:Signature Id="FrameSig"/>
  <es:TimeStamp/>
</es:Dossier>"##
}

fn parsed_report(xml: &str) -> StructureReport {
    es3::verify_str(xml, VerificationOptions::without_signatures()).structure
}

fn direct_report(xml: &str) -> StructureReport {
    es3::verify_structure_str(xml)
}

fn expected_ok_report() -> StructureReport {
    StructureReport {
        errors: Vec::new(),
        warnings: Vec::new(),
        document_count: 1,
        document_signature_count: 1,
        document_timestamp_count: 1,
        dossier_signature_count: 1,
        dossier_timestamp_count: 1,
    }
}

fn expected_report(errors: Vec<Finding>) -> StructureReport {
    StructureReport {
        errors,
        ..expected_ok_report()
    }
}

fn error(document_index: Option<usize>, message: impl Into<String>) -> Finding {
    Finding {
        document_index,
        message: message.into(),
    }
}

fn assert_first_parse_error_and_report(xml: &str, expected: StructureReport) {
    let parse_error = xml.parse::<Dossier>().unwrap_err().to_string();

    assert_eq!(parse_error, expected.errors[0].message);
    assert_eq!(direct_report(xml), expected);
}

fn assert_same_report(xml: &str) {
    assert_eq!(parsed_report(xml), direct_report(xml));
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

#[test]
fn valid_dossier_reports_match_after_parse() {
    let expected = expected_ok_report();

    assert_eq!(parsed_report(valid_xml()), expected);
    assert_eq!(direct_report(valid_xml()), expected);
    assert_same_report(valid_xml());
}

#[test]
fn parsed_interface_and_structure_report_expose_same_document_facts() {
    let dossier = valid_xml().parse::<Dossier>().unwrap();
    let documents = dossier.documents();
    let report = dossier.verify_structure();

    assert_eq!(report.document_count, documents.len());
    assert_eq!(
        report.document_signature_count,
        documents
            .iter()
            .map(|document| document.signature_count())
            .sum::<usize>()
    );
    assert_eq!(
        report.document_timestamp_count,
        documents
            .iter()
            .map(|document| document.timestamp_count())
            .sum::<usize>()
    );
    assert_eq!(
        report.dossier_signature_count,
        dossier.dossier_signature_count()
    );
    assert_eq!(
        report.dossier_timestamp_count,
        dossier.dossier_timestamp_count()
    );
}

#[test]
fn transform_reports_match_after_parse() {
    let transform_discovery = valid_xml().replace(
        "<es:Transform Algorithm=\"base64\"/>",
        "<es:Transform Algorithm=\"zip\"/><es:Transform Algorithm=\"base64\"/>",
    );
    let transform_discovery =
        transform_discovery.replace("SGVsbG8gd29ybGQ=", &zipped_base64_payload());
    let dossier = transform_discovery.parse::<Dossier>().unwrap();

    assert_eq!(
        dossier.documents()[0].transforms(),
        &[Transform::Zip, Transform::Base64]
    );
    assert_eq!(parsed_report(&transform_discovery), expected_ok_report());
    assert_eq!(direct_report(&transform_discovery), expected_ok_report());
    assert_same_report(&transform_discovery);

    let invalid_order = valid_xml().replace(
        "<es:Transform Algorithm=\"base64\"/>",
        "<es:Transform Algorithm=\"base64\"/><es:Transform Algorithm=\"zip\"/>",
    );
    let parse_error = invalid_order.parse::<Dossier>().unwrap_err().to_string();
    let expected = expected_report(vec![error(Some(0), INVALID_TRANSFORM_ORDER)]);

    assert_eq!(parse_error, INVALID_TRANSFORM_ORDER);
    assert_eq!(direct_report(&invalid_order), expected);
}

#[test]
fn payload_reports_match_after_parse() {
    let invalid_base64 = valid_xml().replace("SGVsbG8gd29ybGQ=", "not base64");
    let parsed = parsed_report(&invalid_base64);
    let direct = direct_report(&invalid_base64);

    assert_eq!(parsed, direct);
    assert!(!parsed.is_ok(), "{parsed:#?}");
    assert!(
        parsed
            .errors
            .iter()
            .any(|finding| finding.message.contains("invalid base64"))
    );

    let encrypted = valid_xml().replace(
        "<es:Transform Algorithm=\"base64\"/>",
        "<es:Transform Algorithm=\"encrypt\"/><es:Transform Algorithm=\"base64\"/>",
    );
    let parsed = parsed_report(&encrypted);
    let direct = direct_report(&encrypted);

    assert_eq!(parsed, direct);
    assert!(parsed.is_ok(), "{parsed:#?}");
    assert!(
        parsed
            .warnings
            .iter()
            .any(|finding| finding.message.contains("encrypted"))
    );
}

#[test]
fn invalid_root_validation_error_is_stable() {
    let parse_error = "<not-es3/>".parse::<Dossier>().unwrap_err().to_string();
    let report = direct_report("<not-es3/>");
    let expected = StructureReport {
        errors: vec![error(
            None,
            "root element must be es:Dossier in the ES3 namespace",
        )],
        ..StructureReport::default()
    };

    assert_eq!(
        parse_error,
        "root element must be es:Dossier in the ES3 namespace"
    );
    assert_eq!(report, expected);
}

#[test]
fn missing_documents_validation_error_is_stable() {
    let missing_documents = valid_xml().replace(
        r##"  <es:Documents Id="Object0">
    <es:Document>
      <es:DocumentProfile Id="Profile1" OBJREF="#Payload1">
        <es:Title>Invoice</es:Title>
        <es:CreationDate>2026-05-16T00:00:00Z</es:CreationDate>
        <es:Format><es:MIME-Type type="text" subtype="plain" extension="txt"/></es:Format>
        <es:SourceSize sizeValue="11" sizeUnit="B"/>
        <es:BaseTransform><es:Transform Algorithm="base64"/></es:BaseTransform>
      </es:DocumentProfile>
      <ds:Object Id="Payload1">SGVsbG8gd29ybGQ=</ds:Object>
      <ds:Signature/>
      <es:TimeStamp/>
    </es:Document>
  </es:Documents>
"##,
        "",
    );
    let expected = StructureReport {
        errors: vec![error(None, "missing required element Documents")],
        warnings: Vec::new(),
        document_count: 0,
        document_signature_count: 0,
        document_timestamp_count: 0,
        dossier_signature_count: 1,
        dossier_timestamp_count: 1,
    };

    assert_first_parse_error_and_report(&missing_documents, expected);
}

#[test]
fn missing_document_profile_validation_error_is_stable() {
    let missing_profile = valid_xml().replace(
        r##"      <es:DocumentProfile Id="Profile1" OBJREF="#Payload1">
        <es:Title>Invoice</es:Title>
        <es:CreationDate>2026-05-16T00:00:00Z</es:CreationDate>
        <es:Format><es:MIME-Type type="text" subtype="plain" extension="txt"/></es:Format>
        <es:SourceSize sizeValue="11" sizeUnit="B"/>
        <es:BaseTransform><es:Transform Algorithm="base64"/></es:BaseTransform>
      </es:DocumentProfile>
"##,
        "",
    );
    let expected = expected_report(vec![
        error(
            Some(0),
            "document 0 must have exactly one es:DocumentProfile, found 0",
        ),
        error(Some(0), INVALID_TRANSFORM_ORDER),
    ]);

    assert_first_parse_error_and_report(&missing_profile, expected);
}

#[test]
fn missing_document_field_validation_errors_are_stable() {
    let missing_title = valid_xml().replace("        <es:Title>Invoice</es:Title>\n", "");
    let expected = expected_report(vec![error(
        Some(0),
        "missing required element Document[0]/DocumentProfile/Title",
    )]);
    assert_first_parse_error_and_report(&missing_title, expected);

    let missing_format = valid_xml().replace(
        "        <es:Format><es:MIME-Type type=\"text\" subtype=\"plain\" extension=\"txt\"/></es:Format>\n",
        "",
    );
    let expected = expected_report(vec![error(
        Some(0),
        "missing required element Document[0]/DocumentProfile/Format",
    )]);
    assert_first_parse_error_and_report(&missing_format, expected);

    let missing_mime = valid_xml().replace(
        "<es:Format><es:MIME-Type type=\"text\" subtype=\"plain\" extension=\"txt\"/></es:Format>",
        "<es:Format/>",
    );
    let expected = expected_report(vec![error(
        Some(0),
        "missing required element Document[0]/DocumentProfile/Format/MIME-Type",
    )]);
    assert_first_parse_error_and_report(&missing_mime, expected);

    let missing_source_size = valid_xml().replace(
        "        <es:SourceSize sizeValue=\"11\" sizeUnit=\"B\"/>\n",
        "",
    );
    let expected = expected_report(vec![error(
        Some(0),
        "missing required element Document[0]/DocumentProfile/SourceSize",
    )]);
    assert_first_parse_error_and_report(&missing_source_size, expected);

    let missing_source_size_attribute = valid_xml().replace("sizeValue=\"11\" ", "");
    let expected = expected_report(vec![error(
        Some(0),
        "missing required element Document[0]/DocumentProfile/SourceSize/@sizeValue",
    )]);

    assert_first_parse_error_and_report(&missing_source_size_attribute, expected);
}

#[test]
fn missing_transform_validation_errors_are_stable() {
    let missing_base_transform = valid_xml().replace(
        "        <es:BaseTransform><es:Transform Algorithm=\"base64\"/></es:BaseTransform>\n",
        "",
    );
    let expected = expected_report(vec![
        error(
            Some(0),
            "missing required element Document[0]/DocumentProfile/BaseTransform",
        ),
        error(Some(0), INVALID_TRANSFORM_ORDER),
    ]);

    assert_first_parse_error_and_report(&missing_base_transform, expected);

    let missing_transform = valid_xml().replace(
        "<es:BaseTransform><es:Transform Algorithm=\"base64\"/></es:BaseTransform>",
        "<es:BaseTransform></es:BaseTransform>",
    );
    let expected = expected_report(vec![
        error(
            Some(0),
            "missing required element Document[0]/DocumentProfile/BaseTransform/Transform",
        ),
        error(Some(0), INVALID_TRANSFORM_ORDER),
    ]);

    assert_first_parse_error_and_report(&missing_transform, expected);

    let missing_transform_and_payload = missing_transform.replace(
        "      <ds:Object Id=\"Payload1\">SGVsbG8gd29ybGQ=</ds:Object>\n",
        "",
    );
    let expected = expected_report(vec![
        error(
            Some(0),
            "document 0 must have exactly one direct ds:Object payload, found 0",
        ),
        error(
            Some(0),
            "missing required element Document[0]/DocumentProfile/BaseTransform/Transform",
        ),
        error(Some(0), INVALID_TRANSFORM_ORDER),
    ]);

    assert_eq!(direct_report(&missing_transform_and_payload), expected);

    let missing_transform_algorithm =
        valid_xml().replace("<es:Transform Algorithm=\"base64\"/>", "<es:Transform/>");
    let expected = expected_report(vec![
        error(
            Some(0),
            "missing required element Document[0]/DocumentProfile/BaseTransform/Transform/@Algorithm",
        ),
        error(
            Some(0),
            "missing required element Document[0]/DocumentProfile/BaseTransform/Transform",
        ),
        error(Some(0), INVALID_TRANSFORM_ORDER),
    ]);

    assert_first_parse_error_and_report(&missing_transform_algorithm, expected);
}

#[test]
fn invalid_payload_count_validation_error_is_stable() {
    let missing_payload = valid_xml().replace(
        "      <ds:Object Id=\"Payload1\">SGVsbG8gd29ybGQ=</ds:Object>\n",
        "",
    );
    let parse_error = missing_payload.parse::<Dossier>().unwrap_err().to_string();
    let report = direct_report(&missing_payload);

    let expected = expected_report(vec![error(
        Some(0),
        "document 0 must have exactly one direct ds:Object payload, found 0",
    )]);

    assert_eq!(parse_error, expected.errors[0].message);
    assert_eq!(report, expected);

    let duplicate_payload = valid_xml().replace(
        "      <ds:Object Id=\"Payload1\">SGVsbG8gd29ybGQ=</ds:Object>\n",
        "      <ds:Object Id=\"Payload1\">SGVsbG8gd29ybGQ=</ds:Object>\n      <ds:Object Id=\"Payload2\">SGVsbG8=</ds:Object>\n",
    );
    let parse_error = duplicate_payload
        .parse::<Dossier>()
        .unwrap_err()
        .to_string();
    let expected = expected_report(vec![error(
        Some(0),
        "document 0 must have exactly one direct ds:Object payload, found 2",
    )]);

    assert_eq!(parse_error, expected.errors[0].message);
    assert_eq!(direct_report(&duplicate_payload), expected);
}

#[test]
fn oversized_payload_validation_error_is_stable() {
    let payload = "A".repeat(16_777_220);
    let xml = valid_xml().replace("SGVsbG8gd29ybGQ=", &payload);
    let parse_error = xml.parse::<Dossier>().unwrap_err().to_string();
    let report = direct_report(&xml);
    let expected_message =
        "document payload text is too large: 16777220 bytes exceeds 16777216 byte limit";
    let expected = expected_report(vec![error(Some(0), expected_message)]);

    assert_eq!(parse_error, expected_message);
    assert_eq!(report, expected);
}
