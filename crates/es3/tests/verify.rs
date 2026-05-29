use base64::Engine;
use es3::{
    Dossier, SignatureFindingKind, SignatureScope, ValidationLayerStatus, VerificationOptions,
    XadesSigningCertificateStatus,
};
use sha2::Digest;
use x509_cert::der::Encode;

const TARGET_SHAPE: &str = include_str!("fixtures/vendor/generated/es3-xades-bt-target-shape.es3");
const TEST_PRIVATE_KEY: &str = include_str!("fixtures/xmldsig-test-private-key.pem");
const TEST_CERTIFICATE: &str = include_str!("fixtures/xmldsig-test-certificate.pem");
const OTHER_CERTIFICATE: &str = include_str!("fixtures/xmldsig-other-certificate.pem");

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
      <ds:Signature><ds:Object>signature object</ds:Object></ds:Signature>
    </es:Document>
  </es:Documents>
  <ds:Signature Id="FrameSig"/>
</es:Dossier>"##
}

fn certificate_der(pem: &str) -> Vec<u8> {
    x509_cert::Certificate::load_pem_chain(pem.as_bytes())
        .unwrap()
        .into_iter()
        .next()
        .unwrap()
        .to_der()
        .unwrap()
}

fn signed_dossier_template(signer_certificate: &[u8]) -> String {
    let cert_digest =
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(signer_certificate));

    format!(
        r##"<?xml version="1.0" encoding="UTF-8"?>
<es:Dossier xmlns:es="https://www.microsec.hu/ds/e-szigno30#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">
  <es:DossierProfile Id="Profile0" OBJREF="#Object0">
    <es:Title>Generated signed test dossier</es:Title>
    <es:CreationDate>2026-05-16T00:00:00Z</es:CreationDate>
  </es:DossierProfile>
  <es:Documents Id="Object0">
    <es:Document>
      <es:DocumentProfile Id="Profile1" OBJREF="#Payload1">
        <es:Title>Invoice</es:Title>
        <es:CreationDate>2026-05-16T00:00:00Z</es:CreationDate>
        <es:Format><es:MIME-Type type="text" subtype="plain" extension="txt" charset="utf-8"/></es:Format>
        <es:SourceSize sizeValue="11" sizeUnit="B"/>
        <es:BaseTransform><es:Transform Algorithm="base64"/></es:BaseTransform>
      </es:DocumentProfile>
      <ds:Object Id="Payload1">SGVsbG8gd29ybGQ=</ds:Object>
    </es:Document>
  </es:Documents>
  <ds:Signature Id="Signature1">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#Object0">
        <ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue></ds:DigestValue>
      </ds:Reference>
      <ds:Reference URI="#Profile0">
        <ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue></ds:DigestValue>
      </ds:Reference>
      <ds:Reference URI="#SignedProperties1" Type="http://uri.etsi.org/01903#SignedProperties">
        <ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue></ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue></ds:SignatureValue>
    <ds:KeyInfo><ds:X509Data/></ds:KeyInfo>
    <ds:Object Id="XadesObject1">
      <xades:QualifyingProperties Target="#Signature1">
        <xades:SignedProperties Id="SignedProperties1">
          <xades:SignedSignatureProperties>
            <xades:SigningTime>2026-05-16T00:00:00Z</xades:SigningTime>
            <xades:SigningCertificate>
              <xades:Cert>
                <xades:CertDigest>
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                  <ds:DigestValue>{cert_digest}</ds:DigestValue>
                </xades:CertDigest>
              </xades:Cert>
            </xades:SigningCertificate>
          </xades:SignedSignatureProperties>
        </xades:SignedProperties>
        <xades:UnsignedProperties>
          <xades:UnsignedSignatureProperties>
            <xades:SignatureTimeStamp><xades:EncapsulatedTimeStamp>AA==</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp>
          </xades:UnsignedSignatureProperties>
        </xades:UnsignedProperties>
      </xades:QualifyingProperties>
    </ds:Object>
  </ds:Signature>
</es:Dossier>"##
    )
}

fn generated_signed_dossier() -> (String, Vec<u8>) {
    let certificate = certificate_der(TEST_CERTIFICATE);
    let mut key = bergshamra_keys::loader::load_rsa_private_pem(TEST_PRIVATE_KEY.as_bytes())
        .expect("test private key should parse");
    key.x509_chain = vec![certificate.clone()];

    let mut keys = bergshamra_keys::KeysManager::new();
    keys.add_key(key);
    let context = bergshamra_dsig::DsigContext::new(keys);
    let xml = bergshamra_dsig::sign::sign(&context, &signed_dossier_template(&certificate))
        .expect("generated ES3 signature should be created");

    (xml, certificate)
}

fn all_scope_xml_with_document_and_dossier_signatures() -> String {
    valid_xml().replace(
        "<ds:Signature><ds:Object>signature object</ds:Object></ds:Signature>",
        "<ds:Signature Id=\"DocumentSignature\"><ds:Object>signature object</ds:Object></ds:Signature>",
    )
}

#[test]
fn generated_frame_signature_reports_signer_certificate_and_pinned_trust() {
    let (xml, signer_certificate) = generated_signed_dossier();
    let dossier = xml.parse::<Dossier>().unwrap();

    let report = dossier.verify(
        VerificationOptions::default()
            .with_signature_scope(SignatureScope::All)
            .with_pinned_certificate(signer_certificate),
    );

    assert_eq!(report.validation.structural, ValidationLayerStatus::Passed);
    assert_eq!(
        report.validation.cryptographic,
        ValidationLayerStatus::Passed,
        "{report:#?}"
    );
    assert_eq!(report.validation.trust, ValidationLayerStatus::Passed);
    let signature = &report.signatures.as_ref().unwrap().signatures[0];
    assert_eq!(signature.scope, SignatureScope::Dossier);
    assert!(signature.signature_value_valid, "{report:#?}");
    assert_eq!(signature.trust, ValidationLayerStatus::Passed);
    assert_eq!(
        signature.xades_signing_certificate,
        XadesSigningCertificateStatus::Matched
    );
    let signer_certificate = signature.signer_certificate.as_ref().unwrap();
    assert_eq!(signer_certificate.sha256_fingerprint.len(), 64);
    assert!(!signer_certificate.subject.is_empty());
    assert_eq!(signature.evidence.timestamp_count, 1);
    assert_eq!(signature.evidence.certificate_value_count, 0);
    assert_eq!(signature.evidence.ocsp_value_count, 0);
    assert!(
        !report
            .signatures
            .as_ref()
            .unwrap()
            .errors
            .iter()
            .any(|finding| finding.kind == SignatureFindingKind::TrustError)
    );
}

#[test]
fn generated_frame_signature_rejects_wrong_pinned_certificate() {
    let (xml, _) = generated_signed_dossier();
    let other_certificate = certificate_der(OTHER_CERTIFICATE);
    let dossier = xml.parse::<Dossier>().unwrap();

    let report = dossier.verify(
        VerificationOptions::default()
            .with_signature_scope(SignatureScope::All)
            .with_pinned_certificate(other_certificate),
    );

    assert_eq!(
        report.validation.cryptographic,
        ValidationLayerStatus::Passed,
        "{report:#?}"
    );
    assert_eq!(report.validation.trust, ValidationLayerStatus::Failed);
    let signatures = report.signatures.as_ref().unwrap();
    let signature = &signatures.signatures[0];
    assert_eq!(signature.trust, ValidationLayerStatus::Failed);
    assert!(signature.signer_certificate.is_some(), "{report:#?}");
    assert_eq!(
        signature.xades_signing_certificate,
        XadesSigningCertificateStatus::Matched
    );
    assert!(signatures.errors.iter().any(|finding| {
        finding.kind == SignatureFindingKind::TrustError
            && finding
                .message
                .contains("does not match a pinned certificate")
    }));
}

#[test]
fn generated_frame_signature_accepts_trusted_anchor_certificate() {
    let (xml, signer_certificate) = generated_signed_dossier();
    let dossier = xml.parse::<Dossier>().unwrap();

    let report = dossier.verify(
        VerificationOptions::default()
            .with_signature_scope(SignatureScope::All)
            .with_trusted_anchor_certificate(signer_certificate),
    );

    assert_eq!(
        report.validation.cryptographic,
        ValidationLayerStatus::Passed,
        "{report:#?}"
    );
    assert_eq!(report.validation.trust, ValidationLayerStatus::Passed);
    let signatures = report.signatures.as_ref().unwrap();
    let signature = &signatures.signatures[0];
    assert_eq!(signature.trust, ValidationLayerStatus::Passed);
    assert!(signature.signer_certificate.is_some(), "{report:#?}");
    assert_eq!(
        signature.xades_signing_certificate,
        XadesSigningCertificateStatus::Matched
    );
    assert!(
        !signatures
            .errors
            .iter()
            .any(|finding| finding.kind == SignatureFindingKind::TrustError)
    );
}

#[test]
fn generated_all_scope_reports_document_and_dossier_signatures() {
    let xml = all_scope_xml_with_document_and_dossier_signatures();
    let dossier = xml.parse::<Dossier>().unwrap();

    let report =
        dossier.verify(VerificationOptions::default().with_signature_scope(SignatureScope::All));

    assert_eq!(report.validation.structural, ValidationLayerStatus::Passed);
    assert_eq!(
        report.validation.cryptographic,
        ValidationLayerStatus::Failed
    );
    let signatures = report.signatures.as_ref().unwrap();
    assert_eq!(signatures.signature_count, 2);
    assert_eq!(
        signatures
            .signatures
            .iter()
            .filter(|signature| signature.scope == SignatureScope::Document)
            .count(),
        1
    );
    assert_eq!(
        signatures
            .signatures
            .iter()
            .filter(|signature| signature.scope == SignatureScope::Dossier)
            .count(),
        1
    );
    assert!(signatures.errors.iter().any(|finding| {
        finding.kind == SignatureFindingKind::InvalidSignature
            && finding.signature_id.as_deref() == Some("DocumentSignature")
    }));
}

#[test]
fn default_verification_uses_signature_report_for_present_frame_signature() {
    let dossier = TARGET_SHAPE.parse::<Dossier>().unwrap();
    let report = dossier.verify(VerificationOptions::default());

    assert!(report.structure.is_ok(), "{report:#?}");
    assert_eq!(report.validation.structural, ValidationLayerStatus::Passed);
    assert_eq!(
        report.validation.cryptographic,
        ValidationLayerStatus::Failed
    );
    let signatures = report.signatures.as_ref().expect("signature report");
    assert_eq!(signatures.signature_count, 1);
    assert_eq!(signatures.signatures.len(), 1);
    assert_eq!(signatures.signatures[0].id.as_deref(), Some("Signature1"));
    assert!(!signatures.signatures[0].signature_value_valid);
    assert_eq!(
        signatures.signatures[0].trust,
        ValidationLayerStatus::Failed
    );
    assert!(
        signatures.errors.iter().any(|finding| {
            finding.kind == SignatureFindingKind::InvalidSignature
                && finding.signature_id.as_deref() == Some("Signature1")
        }),
        "{report:#?}"
    );
}

#[test]
fn multiple_frame_signatures_fail_closed() {
    let xml = TARGET_SHAPE.replace(
        "</es:Dossier>",
        "  <ds:Signature Id=\"SecondFrameSignature\"><ds:SignedInfo/></ds:Signature>\n</es:Dossier>",
    );
    let dossier = xml.parse::<Dossier>().unwrap();

    let report = dossier.verify(VerificationOptions::default());
    let signatures = report.signatures.as_ref().expect("signature report");

    assert_eq!(signatures.signature_count, 2);
    assert_eq!(
        report.validation.cryptographic,
        ValidationLayerStatus::Failed
    );
    assert!(signatures.errors.iter().any(|finding| {
        finding.kind == es3::SignatureFindingKind::VerificationPolicyDenied
            && finding
                .message
                .contains("multiple ES3 dossier signatures are not supported")
    }));
}

#[test]
fn verification_options_debug_reports_certificate_counts() {
    let options = VerificationOptions::default().with_pinned_certificate(b"not a cert".to_vec());

    let debug = format!("{options:?}");

    assert!(debug.contains("pinned_certificates"), "{debug}");
    assert!(debug.contains("1"), "{debug}");
    assert!(!debug.contains("not a cert"), "{debug}");
}

#[test]
fn frame_signature_verification_ignores_document_level_signature_decoys() {
    let xml = TARGET_SHAPE.replace(
        "      <ds:Object Id=\"Payload1\">SGVsbG8gd29ybGQ=</ds:Object>",
        "      <ds:Object Id=\"Payload1\">SGVsbG8gd29ybGQ=</ds:Object>\n      <ds:Signature Id=\"DocumentDecoy\"><ds:Object>decoy</ds:Object></ds:Signature>",
    );
    let dossier = xml.parse::<Dossier>().unwrap();

    let report = dossier.verify(VerificationOptions::default());
    let signatures = report.signatures.as_ref().expect("signature report");

    assert_eq!(signatures.signature_count, 1);
    assert!(signatures.errors.iter().any(|finding| {
        finding.kind == SignatureFindingKind::InvalidSignature
            && finding.signature_id.as_deref() == Some("Signature1")
    }));
    assert!(
        !signatures
            .errors
            .iter()
            .any(|finding| finding.signature_id.as_deref() == Some("DocumentDecoy")),
        "document-level decoy must not be reported as the verified frame signature: {report:#?}"
    );
}

#[test]
fn signature_verification_can_be_skipped() {
    let dossier = TARGET_SHAPE.parse::<Dossier>().unwrap();
    let report = dossier.verify(VerificationOptions::without_signatures());

    assert!(report.structure.is_ok(), "{report:#?}");
    assert_eq!(report.validation.structural, ValidationLayerStatus::Passed);
    assert_eq!(
        report.validation.cryptographic,
        ValidationLayerStatus::NotChecked
    );
    assert_eq!(report.validation.trust, ValidationLayerStatus::NotChecked);
    assert!(report.signatures.is_none(), "{report:#?}");
    assert!(report.checked_layers_ok(), "{report:#?}");
}

#[test]
fn verification_report_separates_structural_success_from_failed_signature() {
    let dossier = valid_xml().parse::<Dossier>().unwrap();
    let report = dossier.verify(VerificationOptions::default());

    assert_eq!(report.validation.structural, ValidationLayerStatus::Passed);
    assert_eq!(
        report.validation.cryptographic,
        ValidationLayerStatus::Failed
    );
    assert_eq!(report.validation.trust, ValidationLayerStatus::NotChecked);
    assert!(report.structure.is_ok(), "{report:#?}");
    assert!(
        report
            .signatures
            .as_ref()
            .expect("signature report")
            .errors
            .iter()
            .any(|finding| finding.kind == SignatureFindingKind::InvalidSignature),
        "{report:#?}"
    );
    assert!(!report.checked_layers_ok(), "{report:#?}");
}

#[test]
fn verification_report_records_missing_frame_signature_as_not_checked() {
    let xml = valid_xml()
        .replace(
            "      <ds:Signature><ds:Object>signature object</ds:Object></ds:Signature>\n",
            "",
        )
        .replace("  <ds:Signature Id=\"FrameSig\"/>\n", "");

    let dossier = xml.parse::<Dossier>().unwrap();
    let report = dossier.verify(VerificationOptions::default());

    assert!(report.structure.is_ok(), "{report:#?}");
    assert_eq!(report.validation.structural, ValidationLayerStatus::Passed);
    assert_eq!(
        report.validation.cryptographic,
        ValidationLayerStatus::NotChecked
    );
    assert!(report.signatures.is_none(), "{report:#?}");
    assert!(report.checked_layers_ok(), "{report:#?}");
}

#[test]
fn require_checked_layers_ok_rejects_failed_signature_verification() {
    let dossier = valid_xml().parse::<Dossier>().unwrap();
    let error = dossier
        .require_checked_layers_ok(VerificationOptions::default())
        .unwrap_err();

    assert_eq!(
        error.report.validation.cryptographic,
        ValidationLayerStatus::Failed
    );
}

#[test]
fn require_checked_layers_ok_accepts_valid_checked_layers() {
    let dossier = valid_xml().parse::<Dossier>().unwrap();
    let dossier = dossier
        .require_checked_layers_ok(VerificationOptions::without_signatures())
        .unwrap();

    assert_eq!(dossier.documents()[0].title(), "Invoice");
}

#[test]
fn invalid_transform_structures_are_reported() {
    for transforms in [
        "<es:Transform Algorithm=\"encrypt\"/><es:Transform Algorithm=\"zip\"/><es:Transform Algorithm=\"base64\"/>",
        "<es:Transform Algorithm=\"zip\"/>",
        "<es:Transform Algorithm=\"encrypt\"/>",
        "<es:Transform Algorithm=\"zip\"/><es:Transform Algorithm=\"encrypt\"/>",
    ] {
        let xml = valid_xml().replace("<es:Transform Algorithm=\"base64\"/>", transforms);

        let report = es3::verify_structure_str(&xml);

        assert!(!report.is_ok(), "{transforms}: {report:#?}");
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.message.contains("transform order")),
            "{transforms}: {report:#?}"
        );
    }
}

#[test]
fn document_signature_and_timestamp_counts_are_separate_from_dossier_counts() {
    let xml = valid_xml()
        .replace(
            "<ds:Signature><ds:Object>signature object</ds:Object></ds:Signature>",
            "<ds:Signature><ds:Object>signature object</ds:Object></ds:Signature><es:TimeStamp/>",
        )
        .replace(
            "<ds:Signature Id=\"FrameSig\"/>",
            "<ds:Signature Id=\"FrameSig\"/><es:TimeStamp/>",
        );

    let report = es3::verify_structure_str(&xml);

    assert!(report.is_ok(), "{report:#?}");
    assert_eq!(report.document_signature_count, 1);
    assert_eq!(report.document_timestamp_count, 1);
    assert_eq!(report.dossier_signature_count, 1);
    assert_eq!(report.dossier_timestamp_count, 1);
}

#[test]
fn encrypted_payload_still_reports_invalid_base64() {
    let xml = valid_xml()
        .replace(
            "<es:Transform Algorithm=\"base64\"/>",
            "<es:Transform Algorithm=\"encrypt\"/><es:Transform Algorithm=\"base64\"/>",
        )
        .replace(
            "<ds:Object Id=\"Payload1\">SGVsbG8gd29ybGQ=</ds:Object>",
            "<ds:Object Id=\"Payload1\">not base64</ds:Object>",
        );

    let report = es3::verify_structure_str(&xml);

    assert!(!report.is_ok());
    assert!(
        report
            .errors
            .iter()
            .any(|finding| finding.message.contains("invalid base64"))
    );
    assert!(
        report
            .warnings
            .iter()
            .any(|finding| finding.message.contains("encrypted"))
    );
}
