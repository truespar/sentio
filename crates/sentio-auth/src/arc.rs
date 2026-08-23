use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use mail_auth::common::crypto::{Ed25519Key, RsaKey, Sha256};
use mail_auth::common::headers::HeaderWriter;
use mail_auth::{ArcOutput, AuthenticatedMessage, AuthenticationResults, DkimResult};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::PrivateKeyDer;
use sentio_core::auth::DkimAlgorithm;
use sentio_core::error::SentioError;
use sentio_core::traits::DkimKeyRecord;
use serde::{Deserialize, Serialize};

use crate::dns::Authenticator;

// ──────────────────────────────────────────────────────────────────────────────
// Sentio-owned ARC result types
// ──────────────────────────────────────────────────────────────────────────────

/// Overall ARC chain validation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArcVerifyResult {
    Pass,
    Neutral,
    Fail,
    PermError,
    TempError,
    None,
}

impl ArcVerifyResult {
    fn from_mail_auth(r: &DkimResult) -> Self {
        match r {
            DkimResult::Pass => Self::Pass,
            DkimResult::Neutral(_) => Self::Neutral,
            DkimResult::Fail(_) => Self::Fail,
            DkimResult::PermError(_) => Self::PermError,
            DkimResult::TempError(_) => Self::TempError,
            DkimResult::None => Self::None,
        }
    }
}

/// ARC chain verification output.
#[derive(Debug, Clone)]
pub struct ArcVerifyOutput {
    pub result: ArcVerifyResult,
    /// Number of ARC sets found in the chain.
    pub set_count: usize,
    /// Whether the chain can be extended with a new ARC seal.
    pub can_seal: bool,
}

/// Headers produced by ARC sealing, ready to prepend to the message.
#[derive(Debug, Clone)]
pub struct ArcSealOutput {
    /// The three ARC headers (ARC-Seal, ARC-Message-Signature,
    /// ARC-Authentication-Results) concatenated with CRLF terminators.
    pub headers: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Verification
// ──────────────────────────────────────────────────────────────────────────────

impl Authenticator {
    /// Validate the ARC chain in a raw RFC 5322 message.
    pub async fn verify_arc(&self, raw_message: &[u8]) -> Result<ArcVerifyOutput, SentioError> {
        let authenticated = AuthenticatedMessage::parse(raw_message).ok_or_else(|| {
            SentioError::Auth("failed to parse message for ARC verification".into())
        })?;

        let set_count = authenticated.as_headers.len();
        let output: ArcOutput<'_> = self.inner.verify_arc(&authenticated).await;

        Ok(ArcVerifyOutput {
            result: ArcVerifyResult::from_mail_auth(output.result()),
            set_count,
            can_seal: output.can_be_sealed(),
        })
    }

    /// Verify the ARC chain and, if it can be sealed, produce new ARC headers.
    ///
    /// * `raw_message`         - the raw RFC 5322 message bytes
    /// * `key`                 - the signing key (same as DKIM)
    /// * `domain`              - signing domain (our hostname)
    /// * `auth_results_header` - the Authentication-Results value for this hop
    /// * `headers`             - headers to cover in the ARC-Message-Signature
    pub async fn seal_arc(
        &self,
        raw_message: &[u8],
        key: &DkimKeyRecord,
        domain: &str,
        auth_results_header: &str,
        headers: &[&str],
    ) -> Result<ArcSealOutput, SentioError> {
        let authenticated = AuthenticatedMessage::parse(raw_message)
            .ok_or_else(|| SentioError::Auth("failed to parse message for ARC sealing".into()))?;

        let arc_output: ArcOutput<'_> = self.inner.verify_arc(&authenticated).await;

        if !arc_output.can_be_sealed() {
            return Err(SentioError::Auth(
                "ARC chain cannot be sealed (broken or too long)".into(),
            ));
        }

        let auth_results = AuthenticationResults::new(auth_results_header);

        let headers_owned: Vec<String> = headers.iter().map(|h| h.to_string()).collect();
        let header_refs: Vec<&str> = headers_owned.iter().map(|s| s.as_str()).collect();

        let arc_set = match key.algorithm {
            DkimAlgorithm::Rsa => {
                // Match the dkim_sign() dual-format handling: API-generated
                // keys are stored as base64 PKCS#8 DER (no PEM armor); keys
                // imported with -----BEGIN markers stay as PEM.
                let der = if key.private_key.trim_start().starts_with("-----") {
                    PrivateKeyDer::from_pem_slice(key.private_key.as_bytes())
                        .map_err(|e| SentioError::Auth(format!("invalid RSA PEM for ARC: {e}")))?
                } else {
                    let der_bytes = BASE64.decode(&key.private_key).map_err(|e| {
                        SentioError::Auth(format!("invalid RSA key for ARC (base64): {e}"))
                    })?;
                    PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(der_bytes))
                };
                let rsa_key = RsaKey::<Sha256>::from_key_der(der)
                    .map_err(|e| SentioError::Auth(format!("invalid RSA key for ARC: {e}")))?;

                mail_auth::arc::ArcSealer::from_key(rsa_key)
                    .domain(domain)
                    .selector(&key.selector)
                    .headers(header_refs)
                    .seal(&authenticated, &auth_results, &arc_output)
                    .map_err(|e| SentioError::Auth(format!("ARC RSA sealing failed: {e}")))?
            }
            DkimAlgorithm::Ed25519 => {
                let seed = BASE64
                    .decode(&key.private_key)
                    .map_err(|e| SentioError::Auth(format!("invalid Ed25519 seed for ARC: {e}")))?;
                let pubkey = BASE64.decode(&key.public_key).map_err(|e| {
                    SentioError::Auth(format!("invalid Ed25519 pubkey for ARC: {e}"))
                })?;

                let ed_key = Ed25519Key::from_seed_and_public_key(&seed, &pubkey).map_err(|e| {
                    SentioError::Auth(format!("invalid Ed25519 keypair for ARC: {e}"))
                })?;

                mail_auth::arc::ArcSealer::from_key(ed_key)
                    .domain(domain)
                    .selector(&key.selector)
                    .headers(header_refs)
                    .seal(&authenticated, &auth_results, &arc_output)
                    .map_err(|e| SentioError::Auth(format!("ARC Ed25519 sealing failed: {e}")))?
            }
        };

        // Render the three ARC headers to a string.
        let mut buf = Vec::new();
        arc_set.write_header(&mut buf);
        let headers = String::from_utf8(buf)
            .map_err(|e| SentioError::Auth(format!("ARC header encoding error: {e}")))?;

        Ok(ArcSealOutput { headers })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arc_result_maps_pass() {
        assert_eq!(
            ArcVerifyResult::from_mail_auth(&DkimResult::Pass),
            ArcVerifyResult::Pass
        );
    }

    #[test]
    fn arc_result_maps_fail() {
        assert_eq!(
            ArcVerifyResult::from_mail_auth(&DkimResult::Fail(mail_auth::Error::ParseError)),
            ArcVerifyResult::Fail
        );
    }

    #[test]
    fn arc_result_maps_none() {
        assert_eq!(
            ArcVerifyResult::from_mail_auth(&DkimResult::None),
            ArcVerifyResult::None
        );
    }

    #[test]
    fn arc_result_serde_roundtrip() {
        let result = ArcVerifyResult::Neutral;
        let json = serde_json::to_string(&result).unwrap();
        assert_eq!(json, "\"neutral\"");
        let parsed: ArcVerifyResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, result);
    }
}
