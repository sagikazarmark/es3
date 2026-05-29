#[cfg(not(target_arch = "wasm32"))]
#[path = "bergshamra_verify_native.rs"]
mod imp;

#[cfg(target_arch = "wasm32")]
mod imp {
    use crate::verify::{SignatureFindingKind, SignatureKeyInfo, SignatureReference};

    pub(crate) struct VerifiedTarget {
        pub(crate) references: Vec<SignatureReference>,
        pub(crate) key_info: SignatureKeyInfo,
    }

    #[allow(dead_code)]
    pub(crate) enum TargetOutcome {
        Valid(VerifiedTarget),
        Failed {
            kind: SignatureFindingKind,
            message: String,
        },
    }

    pub(crate) fn verify_signature_target(
        _target_xml: &str,
        _pinned_certificates: &[Vec<u8>],
        _trusted_anchor_certificates: &[Vec<u8>],
        _embedded_certificate_values: &[Vec<u8>],
    ) -> TargetOutcome {
        TargetOutcome::Failed {
            kind: SignatureFindingKind::VerificationPolicyDenied,
            message: "cryptographic XMLDSIG verification is not available on wasm32".to_owned(),
        }
    }

    pub(crate) fn validate_trusted_anchor(
        _target_xml: &str,
        _pinned_certificates: &[Vec<u8>],
        _trusted_anchor_certificates: &[Vec<u8>],
        _embedded_certificate_values: &[Vec<u8>],
    ) -> Result<(), String> {
        Err("trusted-anchor validation is not available on wasm32".to_owned())
    }

    pub(crate) fn certificate_key_algorithm(_certificate_der: &[u8]) -> Option<String> {
        None
    }
}

pub(crate) use imp::*;
