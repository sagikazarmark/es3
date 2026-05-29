use std::fmt;

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_cert::der::{Decode, Encode};

use crate::error::Error;
use crate::parsed::{ParsedDossier, ValidationMessage, ValidationSeverity};
use crate::xml::{self, children_ds, is_ds, parse_xml_document};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub document_index: Option<usize>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StructureReport {
    pub errors: Vec<Finding>,
    pub warnings: Vec<Finding>,
    pub document_count: usize,
    pub document_signature_count: usize,
    pub document_timestamp_count: usize,
    pub dossier_signature_count: usize,
    pub dossier_timestamp_count: usize,
}

impl StructureReport {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }

    pub(crate) fn error(&mut self, document_index: Option<usize>, message: impl Into<String>) {
        self.errors.push(Finding {
            document_index,
            message: message.into(),
        });
    }

    pub(crate) fn warning(&mut self, document_index: Option<usize>, message: impl Into<String>) {
        self.warnings.push(Finding {
            document_index,
            message: message.into(),
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DossierValidationError {
    report: StructureReport,
}

impl DossierValidationError {
    pub fn report(&self) -> &StructureReport {
        &self.report
    }

    pub fn into_report(self) -> StructureReport {
        self.report
    }

    fn from_report(report: StructureReport) -> Self {
        Self { report }
    }
}

impl fmt::Display for DossierValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.report.errors.first() {
            Some(finding) => formatter.write_str(&finding.message),
            None => formatter.write_str("dossier validation failed"),
        }
    }
}

impl std::error::Error for DossierValidationError {}

impl From<DossierValidationError> for Error {
    fn from(error: DossierValidationError) -> Self {
        Self::InvalidStructure {
            message: error.to_string(),
        }
    }
}

impl ParsedDossier {
    pub fn structure_report(&self) -> StructureReport {
        report_from_parsed_dossier(self)
    }

    pub fn validate(&self) -> std::result::Result<(), DossierValidationError> {
        let report = self.structure_report();
        if report.is_ok() {
            Ok(())
        } else {
            Err(DossierValidationError::from_report(report))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationLayerStatus {
    NotChecked,
    Passed,
    Failed,
}

impl Default for ValidationLayerStatus {
    fn default() -> Self {
        Self::NotChecked
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ValidationLayers {
    pub structural: ValidationLayerStatus,
    pub cryptographic: ValidationLayerStatus,
    pub trust: ValidationLayerStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureFindingKind {
    Unsupported,
    VerificationPolicyDenied,
    MissingInput,
    InvalidSignature,
    KeyError,
    ParseError,
    TrustError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureScope {
    Dossier,
    Document,
    All,
}

impl Default for SignatureScope {
    fn default() -> Self {
        Self::Dossier
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureFinding {
    pub kind: SignatureFindingKind,
    pub signature_id: Option<String>,
    pub message: String,
}

impl SignatureFinding {
    pub(crate) fn new(kind: SignatureFindingKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            signature_id: None,
            message: message.into(),
        }
    }

    pub(crate) fn with_signature_id(
        kind: SignatureFindingKind,
        signature_id: Option<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            signature_id,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureReference {
    pub uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum XadesSigningCertificateStatus {
    NotPresent,
    Matched,
    Mismatched,
    Invalid,
}

impl Default for XadesSigningCertificateStatus {
    fn default() -> Self {
        Self::NotPresent
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerCertificateReport {
    pub sha256_fingerprint: String,
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub key_algorithm: String,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SignatureEvidence {
    pub timestamp_count: usize,
    pub certificate_value_count: usize,
    pub ocsp_value_count: usize,
    pub crl_value_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureKeyInfo {
    pub algorithm: String,
    pub key_name: Option<String>,
    pub x509_certificate_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureResult {
    pub id: Option<String>,
    pub scope: SignatureScope,
    pub references: Vec<SignatureReference>,
    pub key_info: Option<SignatureKeyInfo>,
    pub signer_certificate: Option<SignerCertificateReport>,
    pub xades_signing_certificate: XadesSigningCertificateStatus,
    pub evidence: SignatureEvidence,
    pub trust: ValidationLayerStatus,
    pub signature_value_valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SignatureReport {
    pub signature_count: usize,
    pub signatures: Vec<SignatureResult>,
    pub errors: Vec<SignatureFinding>,
    pub warnings: Vec<SignatureFinding>,
}

impl SignatureReport {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
            && self
                .signatures
                .iter()
                .all(|signature| signature.signature_value_valid)
    }

    pub fn cryptographic_ok(&self) -> bool {
        self.errors
            .iter()
            .all(|finding| finding.kind == SignatureFindingKind::TrustError)
            && self
                .signatures
                .iter()
                .all(|signature| signature.signature_value_valid)
    }

    pub fn trust_ok(&self) -> bool {
        !self.signatures.is_empty()
            && self
                .signatures
                .iter()
                .all(|signature| signature.trust == ValidationLayerStatus::Passed)
            && self
                .errors
                .iter()
                .all(|finding| finding.kind != SignatureFindingKind::TrustError)
    }

    pub(crate) fn error(&mut self, finding: SignatureFinding) {
        self.errors.push(finding);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub validation: ValidationLayers,
    pub structure: StructureReport,
    pub signatures: Option<SignatureReport>,
}

impl VerificationReport {
    pub fn checked_layers_ok(&self) -> bool {
        self.structure.is_ok()
            && self
                .signatures
                .as_ref()
                .map_or(true, SignatureReport::is_ok)
            && [
                self.validation.structural,
                self.validation.cryptographic,
                self.validation.trust,
            ]
            .into_iter()
            .all(|status| status != ValidationLayerStatus::Failed)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CertificateInput {
    pub(crate) bytes: Vec<u8>,
}

impl std::fmt::Debug for CertificateInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateInput")
            .field("bytes", &format!("{} byte(s)", self.bytes.len()))
            .finish()
    }
}

impl From<Vec<u8>> for CertificateInput {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl From<&[u8]> for CertificateInput {
    fn from(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct VerificationOptions {
    pub(crate) verify_signatures: bool,
    pub(crate) signature_scope: SignatureScope,
    pub(crate) pinned_certificates: Vec<CertificateInput>,
    pub(crate) trusted_anchor_certificates: Vec<CertificateInput>,
}

impl std::fmt::Debug for VerificationOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerificationOptions")
            .field("verify_signatures", &self.verify_signatures)
            .field("signature_scope", &self.signature_scope)
            .field("pinned_certificates", &self.pinned_certificates.len())
            .field(
                "trusted_anchor_certificates",
                &self.trusted_anchor_certificates.len(),
            )
            .finish()
    }
}

impl Default for VerificationOptions {
    fn default() -> Self {
        Self {
            verify_signatures: true,
            signature_scope: SignatureScope::Dossier,
            pinned_certificates: Vec::new(),
            trusted_anchor_certificates: Vec::new(),
        }
    }
}

impl VerificationOptions {
    pub fn without_signatures() -> Self {
        Self {
            verify_signatures: false,
            ..Self::default()
        }
    }

    pub fn with_signature_scope(mut self, scope: SignatureScope) -> Self {
        self.signature_scope = scope;
        self
    }

    pub fn with_pinned_certificate(mut self, certificate: impl Into<Vec<u8>>) -> Self {
        self.pinned_certificates.push(CertificateInput {
            bytes: certificate.into(),
        });
        self
    }

    pub fn with_trusted_anchor_certificate(mut self, certificate: impl Into<Vec<u8>>) -> Self {
        self.trusted_anchor_certificates.push(CertificateInput {
            bytes: certificate.into(),
        });
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationFailed {
    pub report: VerificationReport,
}

pub fn verify_structure_str(xml: &str) -> StructureReport {
    let parsed = match xml.parse::<ParsedDossier>() {
        Ok(parsed) => parsed,
        Err(error) => return report_error(error),
    };

    parsed.structure_report()
}

pub fn verify_str(xml: &str, options: VerificationOptions) -> VerificationReport {
    let parsed = match xml.parse::<ParsedDossier>() {
        Ok(parsed) => parsed,
        Err(error) => {
            let structure = report_error(error);
            return VerificationReport {
                validation: ValidationLayers {
                    structural: ValidationLayerStatus::Failed,
                    ..ValidationLayers::default()
                },
                structure,
                signatures: None,
            };
        }
    };

    let structure = parsed.structure_report();
    if !structure.is_ok() {
        return VerificationReport {
            validation: ValidationLayers {
                structural: ValidationLayerStatus::Failed,
                ..ValidationLayers::default()
            },
            structure,
            signatures: None,
        };
    }

    match crate::Dossier::try_from(parsed) {
        Ok(dossier) => dossier.verify(options),
        Err(error) => VerificationReport {
            validation: ValidationLayers {
                structural: ValidationLayerStatus::Failed,
                ..ValidationLayers::default()
            },
            structure: error.into_report(),
            signatures: None,
        },
    }
}

pub(crate) fn verify_parsed_dossier(dossier: &crate::Dossier) -> StructureReport {
    let mut report = StructureReport {
        document_count: dossier.documents.len(),
        document_signature_count: dossier
            .documents
            .iter()
            .map(|document| document.entry.signature_count())
            .sum(),
        document_timestamp_count: dossier
            .documents
            .iter()
            .map(|document| document.entry.timestamp_count())
            .sum(),
        dossier_signature_count: dossier.dossier_signature_count,
        dossier_timestamp_count: dossier.dossier_timestamp_count,
        ..StructureReport::default()
    };

    for document in &dossier.documents {
        report_validation_messages(&mut report, &document.structural_warnings);
    }

    report
}

fn report_from_parsed_dossier(parsed: &ParsedDossier) -> StructureReport {
    let mut report = StructureReport {
        document_count: parsed.documents.len(),
        document_signature_count: parsed
            .documents
            .iter()
            .map(|document| document.signature_count)
            .sum(),
        document_timestamp_count: parsed
            .documents
            .iter()
            .map(|document| document.timestamp_count)
            .sum(),
        dossier_signature_count: parsed.dossier_signature_count,
        dossier_timestamp_count: parsed.dossier_timestamp_count,
        ..StructureReport::default()
    };

    report_validation_messages(&mut report, &parsed.validation_messages());
    report
}

pub(crate) fn verify_signatures_for_dossier(
    dossier: &crate::Dossier,
    options: &VerificationOptions,
) -> Option<SignatureReport> {
    if !options.verify_signatures {
        return None;
    }

    let document = match parse_xml_document(dossier.source_xml()) {
        Ok(document) => document,
        Err(error) => {
            let mut report = SignatureReport::default();
            report.error(SignatureFinding::new(
                SignatureFindingKind::ParseError,
                format!("ES3 signature XML parsing failed: {error}"),
            ));
            return Some(report);
        }
    };

    let targets = signature_targets(&document, options.signature_scope);
    if targets.is_empty() {
        return None;
    }

    let mut report = SignatureReport {
        signature_count: targets.len(),
        ..SignatureReport::default()
    };

    if targets
        .iter()
        .filter(|target| target.scope == SignatureScope::Dossier)
        .count()
        > 1
    {
        report.error(SignatureFinding::new(
            SignatureFindingKind::VerificationPolicyDenied,
            "multiple ES3 dossier signatures are not supported",
        ));
        return Some(report);
    }

    let pinned_certificates = load_certificate_inputs(
        &mut report,
        &options.pinned_certificates,
        "pinned certificate",
    );
    let trusted_anchor_certificates = load_certificate_inputs(
        &mut report,
        &options.trusted_anchor_certificates,
        "trusted anchor certificate",
    );
    let pinned_fingerprints = pinned_certificates
        .iter()
        .map(|certificate| sha256_fingerprint(certificate))
        .collect::<Vec<_>>();

    for target in targets {
        verify_signature_target(
            dossier.source_xml(),
            &document,
            target,
            &pinned_certificates,
            &pinned_fingerprints,
            &trusted_anchor_certificates,
            &mut report,
        );
    }

    Some(report)
}

#[derive(Clone, Copy)]
struct SignatureTarget<'a, 'input> {
    node: roxmltree::Node<'a, 'input>,
    scope: SignatureScope,
}

fn signature_targets<'a, 'input>(
    document: &'a roxmltree::Document<'input>,
    scope: SignatureScope,
) -> Vec<SignatureTarget<'a, 'input>> {
    let root = document.root_element();
    document
        .descendants()
        .filter(|node| is_ds(*node, "Signature"))
        .filter_map(|node| signature_scope(node, root).map(|scope| SignatureTarget { node, scope }))
        .filter(|target| match scope {
            SignatureScope::All => true,
            selected => target.scope == selected,
        })
        .collect()
}

fn signature_scope(
    signature: roxmltree::Node<'_, '_>,
    root: roxmltree::Node<'_, '_>,
) -> Option<SignatureScope> {
    if signature.parent() == Some(root) {
        return Some(SignatureScope::Dossier);
    }

    if signature
        .ancestors()
        .any(|ancestor| is_non_dsig_element(ancestor, "Document"))
    {
        return Some(SignatureScope::Document);
    }

    None
}

#[allow(clippy::too_many_arguments)]
fn verify_signature_target(
    xml: &str,
    document: &roxmltree::Document<'_>,
    target: SignatureTarget<'_, '_>,
    pinned_certificates: &[Vec<u8>],
    pinned_fingerprints: &[String],
    trusted_anchor_certificates: &[Vec<u8>],
    report: &mut SignatureReport,
) {
    let signature_id = target.node.attribute("Id").map(ToOwned::to_owned);
    let signer_certificate_der = first_key_info_certificate(target.node);
    let signer_certificate = signer_certificate_der
        .as_deref()
        .and_then(|certificate| signer_certificate_report(certificate).ok());
    let xades_signing_certificate = signer_certificate_der
        .as_deref()
        .map_or(XadesSigningCertificateStatus::NotPresent, |certificate| {
            xades_signing_certificate_status(target.node, certificate)
        });
    let evidence = signature_evidence(target.node);
    let embedded_certificate_values = embedded_certificate_values(target.node);

    let target_xml = match signature_verification_xml(xml, document, target.node) {
        Ok(target_xml) => target_xml,
        Err(error) => {
            report.error(SignatureFinding::with_signature_id(
                SignatureFindingKind::ParseError,
                signature_id.clone(),
                format!("ES3 signature XML target selection failed: {error}"),
            ));
            report.signatures.push(failed_signature_result(
                signature_id,
                target.scope,
                signer_certificate,
                xades_signing_certificate,
                evidence,
            ));
            return;
        }
    };

    match crate::bergshamra_verify::verify_signature_target(
        &target_xml,
        pinned_certificates,
        trusted_anchor_certificates,
        &embedded_certificate_values,
    ) {
        crate::bergshamra_verify::TargetOutcome::Valid(verified) => {
            let mut signature = SignatureResult {
                id: signature_id.clone(),
                scope: target.scope,
                references: verified.references,
                key_info: Some(verified.key_info),
                signer_certificate,
                xades_signing_certificate,
                evidence,
                trust: ValidationLayerStatus::NotChecked,
                signature_value_valid: true,
            };

            enforce_signature_policy(report, document.root_element(), target, &signature);
            apply_signature_trust(
                &embedded_certificate_values,
                pinned_certificates,
                pinned_fingerprints,
                trusted_anchor_certificates,
                &target_xml,
                &mut signature,
                report,
            );
            report.signatures.push(signature);
        }
        crate::bergshamra_verify::TargetOutcome::Failed { kind, message } => {
            report.error(SignatureFinding::with_signature_id(
                kind,
                signature_id.clone(),
                message,
            ));
            report.signatures.push(failed_signature_result(
                signature_id,
                target.scope,
                signer_certificate,
                xades_signing_certificate,
                evidence,
            ));
        }
    }
}

fn failed_signature_result(
    id: Option<String>,
    scope: SignatureScope,
    signer_certificate: Option<SignerCertificateReport>,
    xades_signing_certificate: XadesSigningCertificateStatus,
    evidence: SignatureEvidence,
) -> SignatureResult {
    SignatureResult {
        id,
        scope,
        references: Vec::new(),
        key_info: None,
        signer_certificate,
        xades_signing_certificate,
        evidence,
        trust: ValidationLayerStatus::Failed,
        signature_value_valid: false,
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_signature_trust(
    embedded_certificate_values: &[Vec<u8>],
    pinned_certificates: &[Vec<u8>],
    pinned_fingerprints: &[String],
    trusted_anchor_certificates: &[Vec<u8>],
    target_xml: &str,
    signature: &mut SignatureResult,
    report: &mut SignatureReport,
) {
    let trust_requested =
        !pinned_certificates.is_empty() || !trusted_anchor_certificates.is_empty();
    if !trust_requested {
        signature.trust = ValidationLayerStatus::NotChecked;
        return;
    }

    let mut trusted = signature.signature_value_valid;
    if !pinned_certificates.is_empty() {
        match signature.signer_certificate.as_ref() {
            Some(certificate)
                if pinned_fingerprints
                    .iter()
                    .any(|fingerprint| fingerprint == &certificate.sha256_fingerprint)
                    && signature.xades_signing_certificate
                        == XadesSigningCertificateStatus::Matched => {}
            Some(certificate) => {
                trusted = false;
                report.error(SignatureFinding::with_signature_id(
                    SignatureFindingKind::TrustError,
                    signature.id.clone(),
                    format!(
                        "signer certificate {} does not match a pinned certificate or its XAdES SigningCertificate digest",
                        certificate.sha256_fingerprint
                    ),
                ));
            }
            None => {
                trusted = false;
                report.error(SignatureFinding::with_signature_id(
                    SignatureFindingKind::TrustError,
                    signature.id.clone(),
                    "signature does not expose a parseable signer certificate for pinning",
                ));
            }
        }
    }

    if !trusted_anchor_certificates.is_empty() {
        match crate::bergshamra_verify::validate_trusted_anchor(
            target_xml,
            pinned_certificates,
            trusted_anchor_certificates,
            embedded_certificate_values,
        ) {
            Ok(()) => {}
            Err(reason) => {
                trusted = false;
                report.error(SignatureFinding::with_signature_id(
                    SignatureFindingKind::TrustError,
                    signature.id.clone(),
                    format!("trusted-anchor certificate validation failed: {reason}"),
                ));
            }
        }
    }

    signature.trust = if trusted {
        ValidationLayerStatus::Passed
    } else {
        ValidationLayerStatus::Failed
    };
}

fn signature_verification_xml(
    xml: &str,
    document: &roxmltree::Document<'_>,
    signature: roxmltree::Node<'_, '_>,
) -> std::result::Result<String, crate::Error> {
    let first_signature = document
        .descendants()
        .find(|node| is_ds(*node, "Signature"));
    if first_signature == Some(signature) {
        return Ok(xml.to_owned());
    }

    let root = document.root_element();
    let signature_range = signature.range();
    let signature_xml = &xml[signature_range.clone()];
    let root_start = root.range().start;
    let insert_at = xml[root_start..]
        .find('>')
        .map(|offset| root_start + offset + 1)
        .ok_or(Error::InvalidRoot)?;

    let mut reordered = xml.to_owned();
    reordered.replace_range(signature_range.clone(), "");
    let insert_at = if signature_range.start < insert_at {
        insert_at - (signature_range.end - signature_range.start)
    } else {
        insert_at
    };
    reordered.insert_str(insert_at, signature_xml);

    Ok(reordered)
}

fn enforce_signature_policy(
    report: &mut SignatureReport,
    root: roxmltree::Node<'_, '_>,
    target: SignatureTarget<'_, '_>,
    signature: &SignatureResult,
) {
    for required_reference in expected_reference_uris(root, target) {
        if !signature
            .references
            .iter()
            .any(|reference| reference.uri == required_reference)
        {
            report.error(SignatureFinding::with_signature_id(
                SignatureFindingKind::VerificationPolicyDenied,
                signature.id.clone(),
                format!(
                    "XMLDSIG {:?} signature is missing required reference {required_reference}",
                    target.scope
                ),
            ));
        }
    }
}

fn expected_reference_uris(
    root: roxmltree::Node<'_, '_>,
    target: SignatureTarget<'_, '_>,
) -> Vec<String> {
    let mut uris = Vec::new();

    match target.scope {
        SignatureScope::Dossier => {
            push_id_uri(&mut uris, child_non_dsig(root, "Documents"));
            push_id_uri(&mut uris, child_non_dsig(root, "DossierProfile"));
        }
        SignatureScope::Document => {
            if let Some(document) = target
                .node
                .ancestors()
                .find(|ancestor| is_non_dsig_element(*ancestor, "Document"))
            {
                push_id_uri(&mut uris, child_non_dsig(document, "DocumentProfile"));
                push_id_uri(&mut uris, children_ds(document, "Object").next());
            }
        }
        SignatureScope::All => unreachable!("target scope is concrete"),
    }

    push_id_uri(
        &mut uris,
        target
            .node
            .descendants()
            .find(|node| is_non_dsig_element(*node, "SignatureProfile")),
    );
    push_id_uri(
        &mut uris,
        target
            .node
            .descendants()
            .find(|node| is_non_dsig_element(*node, "SignedProperties")),
    );

    uris
}

fn push_id_uri(uris: &mut Vec<String>, node: Option<roxmltree::Node<'_, '_>>) {
    if let Some(id) = node.and_then(|node| node.attribute("Id")) {
        let uri = format!("#{id}");
        if !uris.contains(&uri) {
            uris.push(uri);
        }
    }
}

fn load_certificate_inputs(
    report: &mut SignatureReport,
    inputs: &[CertificateInput],
    label: &str,
) -> Vec<Vec<u8>> {
    let mut certificates = Vec::new();
    for input in inputs {
        match certificate_der_values(&input.bytes) {
            Ok(loaded) => certificates.extend(loaded),
            Err(error) => report.error(SignatureFinding::new(
                SignatureFindingKind::TrustError,
                format!("failed to load {label}: {error}"),
            )),
        }
    }
    certificates
}

fn certificate_der_values(input: &[u8]) -> std::result::Result<Vec<Vec<u8>>, String> {
    if input.starts_with(b"-----BEGIN") {
        let certificates = x509_cert::Certificate::load_pem_chain(input)
            .map_err(|error| format!("invalid PEM certificate: {error}"))?;
        certificates
            .into_iter()
            .map(|certificate| {
                certificate
                    .to_der()
                    .map_err(|error| format!("failed to re-encode PEM certificate: {error}"))
            })
            .collect()
    } else {
        x509_cert::Certificate::from_der(input)
            .map_err(|error| format!("invalid DER certificate: {error}"))?;
        Ok(vec![input.to_vec()])
    }
}

fn embedded_certificate_values(signature: roxmltree::Node<'_, '_>) -> Vec<Vec<u8>> {
    signature
        .descendants()
        .filter(|node| is_local_element(*node, "EncapsulatedX509Certificate"))
        .filter_map(decode_base64_node_text)
        .filter(|certificate| x509_cert::Certificate::from_der(certificate).is_ok())
        .collect()
}

fn first_key_info_certificate(signature: roxmltree::Node<'_, '_>) -> Option<Vec<u8>> {
    signature
        .children()
        .find(|node| is_ds(*node, "KeyInfo"))?
        .descendants()
        .find(|node| is_ds(*node, "X509Certificate"))
        .and_then(decode_base64_node_text)
}

fn signer_certificate_report(
    certificate_der: &[u8],
) -> std::result::Result<SignerCertificateReport, String> {
    let certificate = x509_cert::Certificate::from_der(certificate_der)
        .map_err(|error| format!("invalid signer certificate: {error}"))?;
    let tbs_certificate = &certificate.tbs_certificate;
    let key_algorithm = crate::bergshamra_verify::certificate_key_algorithm(certificate_der)
        .unwrap_or_else(|| {
            tbs_certificate
                .subject_public_key_info
                .algorithm
                .oid
                .to_string()
        });
    let validity = &tbs_certificate.validity;

    Ok(SignerCertificateReport {
        sha256_fingerprint: sha256_fingerprint(certificate_der),
        subject: tbs_certificate.subject.to_string(),
        issuer: tbs_certificate.issuer.to_string(),
        serial_number: tbs_certificate.serial_number.to_string(),
        not_before: validity.not_before.to_string(),
        not_after: validity.not_after.to_string(),
        key_algorithm,
        key_usage: key_usage(&certificate),
        extended_key_usage: extended_key_usage(&certificate),
    })
}

fn key_usage(certificate: &x509_cert::Certificate) -> Vec<String> {
    let Ok(Some((_, usage))) = certificate
        .tbs_certificate
        .get::<x509_cert::ext::pkix::KeyUsage>()
    else {
        return Vec::new();
    };

    let mut usages = Vec::new();
    if usage.digital_signature() {
        usages.push("digital_signature".to_owned());
    }
    if usage.non_repudiation() {
        usages.push("content_commitment".to_owned());
    }
    if usage.key_encipherment() {
        usages.push("key_encipherment".to_owned());
    }
    if usage.data_encipherment() {
        usages.push("data_encipherment".to_owned());
    }
    if usage.key_agreement() {
        usages.push("key_agreement".to_owned());
    }
    if usage.key_cert_sign() {
        usages.push("key_cert_sign".to_owned());
    }
    if usage.crl_sign() {
        usages.push("crl_sign".to_owned());
    }

    usages
}

fn extended_key_usage(certificate: &x509_cert::Certificate) -> Vec<String> {
    let Ok(Some((_, usage))) = certificate
        .tbs_certificate
        .get::<x509_cert::ext::pkix::ExtendedKeyUsage>()
    else {
        return Vec::new();
    };

    usage.0.iter().map(ToString::to_string).collect()
}

fn xades_signing_certificate_status(
    signature: roxmltree::Node<'_, '_>,
    signer_certificate_der: &[u8],
) -> XadesSigningCertificateStatus {
    let actual_digest = Sha256::digest(signer_certificate_der).to_vec();
    let mut found = false;
    let mut invalid = false;

    for cert in signature
        .descendants()
        .filter(|node| is_non_dsig_element(*node, "Cert"))
    {
        let Some(digest_value) = cert.descendants().find(|node| is_ds(*node, "DigestValue")) else {
            continue;
        };
        found = true;
        match decode_base64_node_text(digest_value) {
            Some(expected_digest) if expected_digest == actual_digest => {
                return XadesSigningCertificateStatus::Matched;
            }
            Some(_) => {}
            None => invalid = true,
        }
    }

    match (found, invalid) {
        (false, _) => XadesSigningCertificateStatus::NotPresent,
        (_, true) => XadesSigningCertificateStatus::Invalid,
        (true, false) => XadesSigningCertificateStatus::Mismatched,
    }
}

fn signature_evidence(signature: roxmltree::Node<'_, '_>) -> SignatureEvidence {
    SignatureEvidence {
        timestamp_count: signature
            .descendants()
            .filter(|node| is_local_element(*node, "SignatureTimeStamp"))
            .count(),
        certificate_value_count: signature
            .descendants()
            .filter(|node| is_local_element(*node, "EncapsulatedX509Certificate"))
            .count(),
        ocsp_value_count: signature
            .descendants()
            .filter(|node| is_local_element(*node, "EncapsulatedOCSPValue"))
            .count(),
        crl_value_count: signature
            .descendants()
            .filter(|node| is_local_element(*node, "EncapsulatedCRLValue"))
            .count(),
    }
}

fn decode_base64_node_text(node: roxmltree::Node<'_, '_>) -> Option<Vec<u8>> {
    let text = node.text()?;
    let cleaned = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    base64::engine::general_purpose::STANDARD
        .decode(cleaned)
        .ok()
}

fn sha256_fingerprint(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn child_non_dsig<'a, 'input>(
    node: roxmltree::Node<'a, 'input>,
    name: &str,
) -> Option<roxmltree::Node<'a, 'input>> {
    node.children()
        .find(|child| is_non_dsig_element(*child, name))
}

fn is_non_dsig_element(node: roxmltree::Node<'_, '_>, name: &str) -> bool {
    node.is_element()
        && node.tag_name().name() == name
        && node.tag_name().namespace() != Some(xml::DS_NS)
}

fn is_local_element(node: roxmltree::Node<'_, '_>, name: &str) -> bool {
    node.is_element() && node.tag_name().name() == name
}

fn report_error(error: Error) -> StructureReport {
    let mut report = StructureReport::default();
    report.error(None, error.to_string());
    report
}

fn report_validation_messages(report: &mut StructureReport, messages: &[ValidationMessage]) {
    for message in messages {
        match message.severity {
            ValidationSeverity::Error => {
                report.error(message.document_index, message.message.clone())
            }
            ValidationSeverity::Warning => {
                report.warning(message.document_index, message.message.clone())
            }
        }
    }
}
