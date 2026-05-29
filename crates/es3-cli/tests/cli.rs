use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

fn sample_xml() -> &'static str {
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
    </es:Document>
  </es:Documents>
</es:Dossier>"##
}

fn xmlsec1_style_options_not_exposed_in_es3_cli() -> &'static [&'static str] {
    &[
        "--add-id-attr",
        "--trusted-pem",
        "--keys-file",
        "--crypto",
        "--xxe",
    ]
}

fn assert_no_xmlsec1_style_options(stdout: &[u8]) {
    let stdout = String::from_utf8(stdout.to_vec()).unwrap();
    for option in xmlsec1_style_options_not_exposed_in_es3_cli() {
        assert!(
            !stdout.contains(option),
            "ES3 CLI help unexpectedly exposed xmlsec1-style option {option}\n{stdout}"
        );
    }
}

#[test]
fn cli_help_does_not_expose_xmlsec1_generic_options() {
    for help_args in [
        vec!["--help"],
        vec!["list", "--help"],
        vec!["extract", "--help"],
        vec!["verify", "--help"],
    ] {
        let output = Command::cargo_bin("es3")
            .unwrap()
            .args(help_args)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        assert_no_xmlsec1_style_options(&output);
    }
}

#[test]
fn cli_help_does_not_expose_sign_command() {
    let output = Command::cargo_bin("es3")
        .unwrap()
        .args(["--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).unwrap();

    assert!(
        !stdout.contains(" sign"),
        "CLI must not expose sign command\n{stdout}"
    );
}

#[test]
fn verify_help_uses_user_facing_signature_selection_terms() {
    let output = Command::cargo_bin("es3")
        .unwrap()
        .args(["verify", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).unwrap();

    assert!(stdout.contains("--check-signatures"), "{stdout}");
    assert!(stdout.contains("dossier"), "{stdout}");
    assert!(stdout.contains("documents"), "{stdout}");
    assert!(!stdout.contains("frame"), "{stdout}");
    assert!(!stdout.contains("XMLDSIG"), "{stdout}");
}

#[test]
fn cli_rejects_representative_xmlsec1_options() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.es3");
    std::fs::write(&input, sample_xml()).unwrap();
    let input = input.to_str().unwrap();

    for args in [
        vec!["verify", input, "--trusted-pem", "cert.pem"],
        vec!["verify", input, "--add-id-attr", "ID"],
        vec!["verify", input, "--keys-file", "keys.xml"],
        vec!["verify", input, "--crypto", "openssl"],
        vec!["verify", input, "--xxe"],
    ] {
        Command::cargo_bin("es3")
            .unwrap()
            .args(args)
            .assert()
            .failure()
            .stderr(predicate::str::contains("unexpected argument"));
    }
}

#[test]
fn list_prints_human_readable_rows() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.es3");
    std::fs::write(&input, sample_xml()).unwrap();

    Command::cargo_bin("es3")
        .unwrap()
        .args(["list", input.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Invoice"))
        .stdout(predicate::str::contains("text/plain"));
}

#[test]
fn list_prints_json() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.es3");
    std::fs::write(&input, sample_xml()).unwrap();

    let output = Command::cargo_bin("es3")
        .unwrap()
        .args(["list", input.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(json[0]["title"], "Invoice");
    assert_eq!(json[0]["transforms"], serde_json::json!(["base64"]));
    assert_eq!(
        json[0]["extraction"],
        serde_json::json!({
            "can_extract": true,
            "unavailable_reason": null,
            "unavailable_reason_code": null
        })
    );
}

#[test]
fn list_prints_extraction_unavailable_reason() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("encrypted.es3");
    let xml = sample_xml().replace(
        "<es:Transform Algorithm=\"base64\"/>",
        "<es:Transform Algorithm=\"encrypt\"/><es:Transform Algorithm=\"base64\"/>",
    );
    std::fs::write(&input, xml).unwrap();

    Command::cargo_bin("es3")
        .unwrap()
        .args(["list", input.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Encrypted document extraction is not supported",
        ));
}

#[test]
fn list_json_preserves_raw_transforms_with_extraction_fact() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("encrypted.es3");
    let xml = sample_xml().replace(
        "<es:Transform Algorithm=\"base64\"/>",
        "<es:Transform Algorithm=\"encrypt\"/><es:Transform Algorithm=\"base64\"/>",
    );
    std::fs::write(&input, xml).unwrap();

    let output = Command::cargo_bin("es3")
        .unwrap()
        .args(["list", input.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(
        json[0]["transforms"],
        serde_json::json!(["encrypt", "base64"])
    );
    assert_eq!(
        json[0]["extraction"],
        serde_json::json!({
            "can_extract": false,
            "unavailable_reason": "Encrypted document extraction is not supported",
            "unavailable_reason_code": "encrypted_document"
        })
    );
}

#[test]
fn list_escapes_human_title_column() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.es3");
    let xml = sample_xml().replace(
        "<es:Title>Invoice</es:Title>",
        "<es:Title>Invoice\nTotal with spaces</es:Title>",
    );
    std::fs::write(&input, xml).unwrap();

    let output = Command::cargo_bin("es3")
        .unwrap()
        .args(["list", input.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).unwrap();

    assert!(
        stdout.contains("INDEX\tTITLE\tMIME\tSIZE\tTRANSFORMS\tEXTRACTION\tSIGNATURES\tTIMESTAMPS")
    );
    assert!(stdout.contains(
        "0\t\"Invoice\\nTotal with spaces\"\t\"text/plain\"\t11\tbase64\t\"available\"\t0\t0"
    ));
    assert!(!stdout.contains("Invoice\nTotal with spaces"));
    assert_eq!(stdout.lines().count(), 2);
}

#[test]
fn list_escapes_human_mime_column() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.es3");
    let xml = sample_xml().replace("type=\"text\"", "type=\"text&#10;FAKE\"");
    std::fs::write(&input, xml).unwrap();

    let output = Command::cargo_bin("es3")
        .unwrap()
        .args(["list", input.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).unwrap();

    assert!(
        stdout.contains("0\t\"Invoice\"\t\"text\\nFAKE/plain\"\t11\tbase64\t\"available\"\t0\t0")
    );
    assert!(!stdout.contains("text\nFAKE/plain"));
    assert_eq!(stdout.lines().count(), 2);
}

#[test]
fn extract_writes_selected_document() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.es3");
    let output = dir.path().join("out");
    std::fs::write(&input, sample_xml()).unwrap();

    Command::cargo_bin("es3")
        .unwrap()
        .args([
            "extract",
            input.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--index",
            "0",
        ])
        .assert()
        .success();

    assert_eq!(
        std::fs::read(output.join("Invoice.txt")).unwrap(),
        b"Hello world"
    );
}

#[test]
fn verify_reports_non_cryptographic_scope() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.es3");
    std::fs::write(&input, sample_xml()).unwrap();

    Command::cargo_bin("es3")
        .unwrap()
        .args(["verify", "--structure-only", input.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("not cryptographic"));
}

#[test]
fn verify_json_reports_structural_errors_without_runtime_stderr() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("invalid-structure.es3");
    std::fs::write(
        &input,
        r#"<es:Dossier xmlns:es="https://www.microsec.hu/ds/e-szigno30#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <es:Documents><es:Document/></es:Documents>
</es:Dossier>"#,
    )
    .unwrap();

    Command::cargo_bin("es3")
        .unwrap()
        .args(["verify", "--json", input.to_str().unwrap()])
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains("\"errors\""))
        .stdout(predicate::str::contains("DocumentProfile"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn verify_reports_invalid_utf8_as_read_error() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("invalid.es3");
    std::fs::write(&input, [0xff]).unwrap();

    Command::cargo_bin("es3")
        .unwrap()
        .args(["verify", input.to_str().unwrap()])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("failed to read"));
}
