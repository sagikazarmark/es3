use std::collections::BTreeSet;
use std::path::PathBuf;

#[derive(Debug)]
struct FixtureMetadata<'a> {
    id: &'a str,
    path: &'a str,
    subsets: BTreeSet<&'a str>,
    source: &'a str,
    license_or_permission: &'a str,
    generation: &'a str,
    expected_status: &'a str,
    sensitive_data: &'a str,
}

#[test]
fn vendor_fixture_corpus_manifest_documents_fixture_metadata() {
    let manifest = load_fixture_text("vendor/manifest.tsv");
    let entries = parse_manifest(&manifest);
    let allowed_subsets = allowed_subsets();

    assert!(
        !entries.is_empty(),
        "vendor fixture corpus should have seed metadata"
    );

    for entry in entries {
        assert!(!entry.id.trim().is_empty());
        assert!(entry.path.starts_with("vendor/"), "{entry:?}");
        let path = fixture_path(entry.path);
        if entry.sensitive_data == "excluded-sensitive" {
            assert!(
                !path.exists(),
                "excluded sensitive fixture must not be committed: {entry:?}"
            );
        } else {
            let fixture = std::fs::read(&path).unwrap_or_else(|error| {
                panic!(
                    "{} should point at a checked-in fixture: {error}",
                    entry.path
                )
            });
            assert!(!fixture.is_empty(), "{} should not be empty", entry.path);
            assert_no_forbidden_sensitive_markers(entry.path, &fixture);
        }
        assert!(
            entry.subsets.iter().any(|subset| matches!(
                *subset,
                "profile"
                    | "extraction"
                    | "document-signature"
                    | "frame-signature"
                    | "timestamp"
                    | "policy"
                    | "revocation"
            )),
            "{entry:?} should be selectable by a compatibility subset"
        );
        for subset in &entry.subsets {
            assert!(
                allowed_subsets.contains(subset),
                "{entry:?} has unknown subset {subset:?}"
            );
        }
        assert!(!entry.source.trim().is_empty(), "{entry:?}");
        assert!(!entry.license_or_permission.trim().is_empty(), "{entry:?}");
        assert!(!entry.generation.trim().is_empty(), "{entry:?}");
        assert!(
            matches!(
                entry.expected_status,
                "pass" | "unsupported" | "blocked-missing-vendor-sample"
            ),
            "{entry:?} has an unknown expected status"
        );
        assert!(
            matches!(
                entry.sensitive_data,
                "none" | "public-test-material" | "excluded-sensitive"
            ),
            "{entry:?} should classify sensitive data handling"
        );
    }
}

#[test]
fn generated_multi_document_profile_fixture_exercises_reader_and_extractor() {
    let fixture = load_fixture_text("vendor/generated/es3-multi-document-profiles.es3");
    let dossier = fixture.parse::<es3::Dossier>().unwrap();
    let documents = dossier.documents();

    assert_eq!(documents.len(), 3);
    assert_eq!(documents[0].title(), "Invoice 2026-05");
    assert_eq!(documents[0].source_size(), 7);
    assert_eq!(documents[1].title(), "metadata.json");
    assert_eq!(documents[1].source_size(), 12);
    assert_eq!(documents[2].title(), "signed-reference-targets");
    assert_eq!(documents[2].source_size(), 16);
    assert_eq!(dossier.extract_document(0).unwrap().bytes, b"%PDF-1\n");
    assert_eq!(
        dossier.extract_document(1).unwrap().bytes,
        b"{\"ok\":true}\n"
    );
    assert_eq!(
        dossier.extract_document(2).unwrap().bytes,
        b"<root>hi</root>\n"
    );
}

fn parse_manifest(text: &str) -> Vec<FixtureMetadata<'_>> {
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let header = lines.next().expect("manifest should have a header");
    assert_eq!(
        header,
        "id\tpath\tsubsets\tsource\tlicense_or_permission\tgeneration\texpected_status\tsensitive_data"
    );

    lines
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let columns = line.split('\t').collect::<Vec<_>>();
            assert_eq!(columns.len(), 8, "malformed manifest row: {line}");
            FixtureMetadata {
                id: columns[0],
                path: columns[1],
                subsets: columns[2].split(',').collect(),
                source: columns[3],
                license_or_permission: columns[4],
                generation: columns[5],
                expected_status: columns[6],
                sensitive_data: columns[7],
            }
        })
        .collect()
}

fn load_fixture_text(path: &str) -> String {
    std::fs::read_to_string(fixture_path(path))
        .unwrap_or_else(|error| panic!("failed to read fixture {path}: {error}"))
}

fn fixture_path(path: &str) -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path)
}

fn allowed_subsets() -> BTreeSet<&'static str> {
    [
        "document-signature",
        "profile",
        "extraction",
        "frame-signature",
        "timestamp",
        "policy",
        "revocation",
    ]
    .into_iter()
    .collect()
}

fn assert_no_forbidden_sensitive_markers(path: &str, bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    for marker in [
        "BEGIN PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "live password",
        "customer data",
    ] {
        assert!(
            !text.contains(marker),
            "{path} appears to contain forbidden sensitive material marker {marker:?}"
        );
    }
}
