use es3::verify_structure_str;

const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XADES_NS: &str = "http://uri.etsi.org/01903/v1.3.2#";
const EXCLUSIVE_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const TARGET_SHAPE: &str = include_str!("fixtures/vendor/generated/es3-xades-bt-target-shape.es3");

fn parse_target_shape() -> roxmltree::Document<'static> {
    roxmltree::Document::parse(TARGET_SHAPE).unwrap()
}

fn count_elements(document: &roxmltree::Document<'_>, namespace: &str, name: &str) -> usize {
    document
        .descendants()
        .filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(namespace)
                && node.tag_name().name() == name
        })
        .count()
}

fn has_reference_uri(document: &roxmltree::Document<'_>, uri: &str) -> bool {
    document.descendants().any(|node| {
        node.is_element()
            && node.tag_name().namespace() == Some(DS_NS)
            && node.tag_name().name() == "Reference"
            && node.attribute("URI") == Some(uri)
    })
}

fn count_timestamp_descendants(
    document: &roxmltree::Document<'_>,
    namespace: &str,
    name: &str,
) -> usize {
    document
        .descendants()
        .find(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(XADES_NS)
                && node.tag_name().name() == "SignatureTimeStamp"
        })
        .unwrap()
        .descendants()
        .filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(namespace)
                && node.tag_name().name() == name
        })
        .count()
}

#[test]
fn xades_bt_target_shape_is_parseable_es3() {
    let report = verify_structure_str(TARGET_SHAPE);

    assert!(report.is_ok(), "{report:#?}");
    assert_eq!(report.document_count, 1);
    assert_eq!(report.dossier_signature_count, 1);
    assert_eq!(report.document_signature_count, 0);
}

#[test]
fn xades_bt_target_shape_marks_signed_documents_properties_and_timestamp() {
    let document = parse_target_shape();

    assert!(has_reference_uri(&document, "#Object0"));
    assert!(has_reference_uri(&document, "#Profile0"));
    assert!(has_reference_uri(&document, "#SignedProperties1"));
    assert_eq!(count_elements(&document, DS_NS, "Signature"), 1);
    assert_eq!(count_elements(&document, DS_NS, "SignatureValue"), 1);
    assert_eq!(count_elements(&document, DS_NS, "KeyInfo"), 1);
    assert_eq!(
        count_elements(&document, XADES_NS, "QualifyingProperties"),
        1
    );
    assert_eq!(count_elements(&document, XADES_NS, "SignedProperties"), 1);
    assert_eq!(count_elements(&document, XADES_NS, "SigningCertificate"), 1);
    assert_eq!(
        count_elements(&document, XADES_NS, "SigningCertificateV2"),
        0
    );
    assert_eq!(count_elements(&document, XADES_NS, "SignatureTimeStamp"), 1);
    assert_eq!(
        count_timestamp_descendants(&document, DS_NS, "CanonicalizationMethod"),
        1
    );
    assert_eq!(
        count_timestamp_descendants(&document, XADES_NS, "CanonicalizationMethod"),
        0
    );
    assert!(TARGET_SHAPE.contains(EXCLUSIVE_C14N));
    assert!(!TARGET_SHAPE.contains("http://www.w3.org/2006/12/xml-c14n11"));
}
