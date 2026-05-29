use crate::verify::{SignatureFindingKind, SignatureKeyInfo, SignatureReference};

pub(crate) struct VerifiedTarget {
    pub(crate) references: Vec<SignatureReference>,
    pub(crate) key_info: SignatureKeyInfo,
}

pub(crate) enum TargetOutcome {
    Valid(VerifiedTarget),
    Failed {
        kind: SignatureFindingKind,
        message: String,
    },
}

pub(crate) fn verify_signature_target(
    target_xml: &str,
    pinned_certificates: &[Vec<u8>],
    trusted_anchor_certificates: &[Vec<u8>],
    embedded_certificate_values: &[Vec<u8>],
) -> TargetOutcome {
    let context = match context(
        pinned_certificates,
        trusted_anchor_certificates,
        embedded_certificate_values,
        false,
    ) {
        Ok(context) => context,
        Err(error) => {
            return TargetOutcome::Failed {
                kind: SignatureFindingKind::KeyError,
                message: format!("Bergshamra key loading failed: {error}"),
            };
        }
    };

    match bergshamra_dsig::verify::verify(&context, target_xml) {
        Ok(bergshamra_dsig::VerifyResult::Valid {
            references,
            key_info,
            ..
        }) => {
            let references = references
                .into_iter()
                .map(|reference| SignatureReference { uri: reference.uri })
                .collect::<Vec<_>>();
            TargetOutcome::Valid(VerifiedTarget {
                references,
                key_info: SignatureKeyInfo {
                    algorithm: key_info.algorithm,
                    key_name: key_info.key_name,
                    x509_certificate_count: key_info.x509_chain.len(),
                },
            })
        }
        Ok(bergshamra_dsig::VerifyResult::Invalid { reason }) => TargetOutcome::Failed {
            kind: SignatureFindingKind::InvalidSignature,
            message: format!("Bergshamra XMLDSIG verification failed: {reason}"),
        },
        Err(error) => TargetOutcome::Failed {
            kind: SignatureFindingKind::InvalidSignature,
            message: format!("Bergshamra XMLDSIG verification failed: {error}"),
        },
    }
}

pub(crate) fn validate_trusted_anchor(
    target_xml: &str,
    pinned_certificates: &[Vec<u8>],
    trusted_anchor_certificates: &[Vec<u8>],
    embedded_certificate_values: &[Vec<u8>],
) -> Result<(), String> {
    context(
        pinned_certificates,
        trusted_anchor_certificates,
        embedded_certificate_values,
        true,
    )
    .and_then(|context| bergshamra_dsig::verify::verify(&context, target_xml))
    .map_err(|error| error.to_string())
    .and_then(|result| match result {
        bergshamra_dsig::VerifyResult::Valid { .. } => Ok(()),
        bergshamra_dsig::VerifyResult::Invalid { reason } => Err(reason),
    })
}

pub(crate) fn certificate_key_algorithm(certificate_der: &[u8]) -> Option<String> {
    bergshamra_keys::loader::load_x509_cert_der(certificate_der)
        .ok()
        .map(|key| key.data.algorithm_name().to_owned())
}

fn context(
    pinned_certificates: &[Vec<u8>],
    trusted_anchor_certificates: &[Vec<u8>],
    untrusted_certificates: &[Vec<u8>],
    validate_x509: bool,
) -> std::result::Result<bergshamra_dsig::DsigContext, bergshamra_core::Error> {
    let mut keys_manager = bergshamra_keys::KeysManager::new();

    for certificate in pinned_certificates {
        keys_manager.add_key(bergshamra_keys::loader::load_x509_cert_der(certificate)?);
    }
    for certificate in trusted_anchor_certificates {
        keys_manager.add_trusted_cert(certificate.clone());
    }
    for certificate in untrusted_certificates {
        keys_manager.add_untrusted_cert(certificate.clone());
    }
    let context = bergshamra_dsig::DsigContext::new(keys_manager)
        .with_enabled_key_data_x509(validate_x509 && !trusted_anchor_certificates.is_empty());

    Ok(context)
}
