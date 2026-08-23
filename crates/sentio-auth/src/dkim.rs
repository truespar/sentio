use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use mail_auth::common::crypto::{Ed25519Key, RsaKey, Sha256};
use mail_auth::common::headers::HeaderWriter;
use mail_auth::dkim::DkimSigner;
use mail_auth::{AuthenticatedMessage, DkimResult};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::PrivateKeyDer;
use sentio_core::auth::{DkimAlgorithm, DkimKeyStatus};
use sentio_core::error::SentioError;
use sentio_core::traits::DkimKeyRecord;
use serde::{Deserialize, Serialize};

use crate::dns::Authenticator;

// ──────────────────────────────────────────────────────────────────────────────
// Sentio-owned result types (no mail-auth re-exports leak out)
// ──────────────────────────────────────────────────────────────────────────────

/// Outcome of verifying a single DKIM signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DkimVerifyResult {
    Pass,
    Neutral,
    Fail,
    PermError,
    TempError,
    None,
}

impl DkimVerifyResult {
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

/// Per-signature verification result with metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimSignatureResult {
    pub result: DkimVerifyResult,
    pub domain: String,
    pub selector: String,
    pub algorithm: String,
}

/// Aggregate DKIM verification output (one entry per signature found).
#[derive(Debug, Clone)]
pub struct DkimVerifyOutput {
    pub signatures: Vec<DkimSignatureResult>,
}

impl DkimVerifyOutput {
    /// Returns `true` if at least one signature passed verification.
    pub fn has_pass(&self) -> bool {
        self.signatures
            .iter()
            .any(|s| s.result == DkimVerifyResult::Pass)
    }
}

/// The DKIM-Signature header produced by signing.
#[derive(Debug, Clone)]
pub struct DkimSignOutput {
    /// The full `DKIM-Signature: …` header value (with trailing CRLF).
    pub header: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Signing
// ──────────────────────────────────────────────────────────────────────────────

/// Sign a message with the given DKIM key, returning the `DKIM-Signature` header.
///
/// This is a synchronous operation - no DNS lookups are needed for signing.
pub fn dkim_sign(
    key: &DkimKeyRecord,
    domain_name: &str,
    message: &[u8],
    headers: &[&str],
) -> Result<DkimSignOutput, SentioError> {
    let header_strings: Vec<String> = headers.iter().map(|h| h.to_string()).collect();
    let header_refs: Vec<&str> = header_strings.iter().map(|s| s.as_str()).collect();

    let header = match key.algorithm {
        DkimAlgorithm::Rsa => {
            // Keys may be stored as PEM (-----BEGIN ... -----) or base64-encoded PKCS#8 DER.
            // The API key generator stores base64 DER; detect format and handle both.
            let der = if key.private_key.trim_start().starts_with("-----") {
                PrivateKeyDer::from_pem_slice(key.private_key.as_bytes())
                    .map_err(|e| SentioError::Auth(format!("invalid RSA PEM: {e}")))?
            } else {
                let der_bytes = BASE64.decode(&key.private_key).map_err(|e| {
                    SentioError::Auth(format!("invalid RSA key (base64 decode): {e}"))
                })?;
                PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(der_bytes))
            };
            let rsa_key = RsaKey::<Sha256>::from_key_der(der)
                .map_err(|e| SentioError::Auth(format!("invalid RSA private key: {e}")))?;

            let signature = DkimSigner::from_key(rsa_key)
                .domain(domain_name)
                .selector(&key.selector)
                .headers(header_refs)
                .sign(message)
                .map_err(|e| SentioError::Auth(format!("DKIM RSA signing failed: {e}")))?;

            signature.to_header()
        }
        DkimAlgorithm::Ed25519 => {
            let seed = BASE64
                .decode(&key.private_key)
                .map_err(|e| SentioError::Auth(format!("invalid Ed25519 seed (base64): {e}")))?;
            let pubkey = BASE64.decode(&key.public_key).map_err(|e| {
                SentioError::Auth(format!("invalid Ed25519 public key (base64): {e}"))
            })?;

            let ed_key = Ed25519Key::from_seed_and_public_key(&seed, &pubkey)
                .map_err(|e| SentioError::Auth(format!("invalid Ed25519 key pair: {e}")))?;

            let signature = DkimSigner::from_key(ed_key)
                .domain(domain_name)
                .selector(&key.selector)
                .headers(header_refs)
                .sign(message)
                .map_err(|e| SentioError::Auth(format!("DKIM Ed25519 signing failed: {e}")))?;

            signature.to_header()
        }
    };

    Ok(DkimSignOutput { header })
}

/// Pick the best active signing key from a list.
///
/// Strategy: only consider `Active` keys; among those, prefer Ed25519 over RSA.
pub fn select_signing_key(keys: &[DkimKeyRecord]) -> Option<&DkimKeyRecord> {
    let active: Vec<&DkimKeyRecord> = keys
        .iter()
        .filter(|k| k.status == DkimKeyStatus::Active)
        .collect();

    // Prefer Ed25519 over RSA.
    active
        .iter()
        .find(|k| k.algorithm == DkimAlgorithm::Ed25519)
        .or_else(|| active.first())
        .copied()
}

// ──────────────────────────────────────────────────────────────────────────────
// Verification
// ──────────────────────────────────────────────────────────────────────────────

impl Authenticator {
    /// Verify all DKIM signatures present in the raw RFC 5322 message.
    pub async fn verify_dkim(&self, raw_message: &[u8]) -> Result<DkimVerifyOutput, SentioError> {
        let authenticated = AuthenticatedMessage::parse(raw_message).ok_or_else(|| {
            SentioError::Auth("failed to parse message for DKIM verification".into())
        })?;

        let outputs = self.inner.verify_dkim(&authenticated).await;

        let signatures = outputs
            .iter()
            .map(|o| {
                let (domain, selector, algorithm) = match o.signature() {
                    Some(sig) => (sig.d.clone(), sig.s.clone(), format!("{:?}", sig.a)),
                    None => (String::new(), String::new(), String::new()),
                };
                DkimSignatureResult {
                    result: DkimVerifyResult::from_mail_auth(o.result()),
                    domain,
                    selector,
                    algorithm,
                }
            })
            .collect();

        Ok(DkimVerifyOutput { signatures })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sentio_core::ids::DkimKeyId;
    use sentio_core::message::DomainId;
    use uuid::Uuid;

    fn make_key(
        algorithm: DkimAlgorithm,
        status: DkimKeyStatus,
        private_key: &str,
        public_key: &str,
    ) -> DkimKeyRecord {
        DkimKeyRecord {
            id: DkimKeyId(Uuid::new_v4()),
            domain_id: DomainId(Uuid::new_v4()),
            selector: "test".to_string(),
            algorithm,
            private_key: private_key.to_string(),
            public_key: public_key.to_string(),
            key_size: None,
            status,
            activated_at: Some(Utc::now()),
            retired_at: None,
            created_at: Utc::now(),
        }
    }

    // ── Key selection ────────────────────────────────────────────────────────

    #[test]
    fn select_signing_key_prefers_ed25519() {
        let keys = vec![
            make_key(DkimAlgorithm::Rsa, DkimKeyStatus::Active, "", ""),
            make_key(DkimAlgorithm::Ed25519, DkimKeyStatus::Active, "", ""),
        ];
        let selected = select_signing_key(&keys).unwrap();
        assert_eq!(selected.algorithm, DkimAlgorithm::Ed25519);
    }

    #[test]
    fn select_signing_key_falls_back_to_rsa() {
        let keys = vec![make_key(DkimAlgorithm::Rsa, DkimKeyStatus::Active, "", "")];
        let selected = select_signing_key(&keys).unwrap();
        assert_eq!(selected.algorithm, DkimAlgorithm::Rsa);
    }

    #[test]
    fn select_signing_key_skips_rotating_and_retired() {
        let keys = vec![
            make_key(DkimAlgorithm::Ed25519, DkimKeyStatus::Rotating, "", ""),
            make_key(DkimAlgorithm::Rsa, DkimKeyStatus::Retired, "", ""),
        ];
        assert!(select_signing_key(&keys).is_none());
    }

    #[test]
    fn select_signing_key_empty_list() {
        let keys: Vec<DkimKeyRecord> = vec![];
        assert!(select_signing_key(&keys).is_none());
    }

    // ── RSA signing ──────────────────────────────────────────────────────────

    /// A 2048-bit RSA test key in PKCS#1 PEM format (generated via openssl).
    const TEST_RSA_PRIVATE_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEowIBAAKCAQEAwdqNnNOGQj3nqCt7E+je3srC7tsB42OCukX57WQGMIz5JRyd\n\
nDovpDIraoZ+4wAisbhQ0Pd+wvCXMCqfOgy6Mw2tgoL88B03HeItt5BF12Hym0qo\n\
f6K5mO4b91DtF9/g1K6ZJF/VoH/DS+Kj9HSU7UgcA/7WhseJf4ZkpxsgmLg5RTyX\n\
Q/gmuYweyX+jIiRrwyaOeL4Kbnc71qVeQdW7L8V8Dxm75ZlbSIguGoeSrIRzi2OP\n\
tKpv17xrfsYM90MGB4LTO+lvWGPvLtbKeC+3jBKxmUTB3WgMt1a3TEoShxgJXB2L\n\
m0+hC2GNJoYJSzdWPVHyC67HivHsgnL5YM7BEQIDAQABAoIBAAnHpz9TOJcc8mlR\n\
5ZVdOT6Ph4LEunVTWY62Ow6r7i1YNLWXmlKoaNY60GVBFc5ep7bERWeAJP1cD/SW\n\
dzlW17SoVambnCaCWCaCI6uldAXoDh+hhkYHhUo0MRBVcoYIKG/ybbgfvEeq9Rpd\n\
+8bjHs79xVQPm5kUdgO2BFvzNWjJmVRouEgcTvDhabkjT5i7R2+5UxYBmfnBvKd7\n\
w3248W/ARQVs6mkCnjmqsF/ObYVGczFp9f+HhcpDQmrs1+JAnSv4O66dQikV6n1H\n\
hQDzgojH2lPcPmIpIuPw7DzMESBxMQOTC2ihewfc+n/b1RrS3dKcviROclNhBn0T\n\
q70MMLUCgYEA7t4vNFE+MwYwcmAjfteMY65MVS1eBklqsW2o5GYcHqnlwgzGnlTv\n\
QnRnu52rPvYLiiyBy4QjJsSfh8niDaU7YEG/4iOLTRNzo+xxQBkboDDzmnz2KfIx\n\
dpwDVXHq51nMmA7B1UqZHQVaL1OSwJZRlfkoAFsKyF+Vw3PKk7800ocCgYEAz8He\n\
2dZ4rUdlsTiUA1sR1ljgt3MEIypPe7vGbw7sIhvFFV71T/M6HnwMDg1a5STcIxB8\n\
5gNZHTdEesCw4mgpS6daVr44ppdrIFl+u+oFPT83usMeSSt9OMZ0RmNXtzqjn2O0\n\
UOKRiCBacY4Ds46SwC11r9jopslwZ6l/8VTm/acCgYAtH1OTcnVpdhXYxUhvQZCH\n\
k/lfbb6BOYUqFyj8XD2bnUSFr5wldK3tw8eErXgX4Kq1Y0rxgviQ7jukjwJgyYG5\n\
4TG6KjS6Tp5drOCH1zZcwGKEIG7v5Yxqd3Y5wdc59MCtSLxc6kaaMNSkdAkY0EyB\n\
JBvmVUxoJYZI8aqm1kvIKQKBgC08q4eHOZORXkUuapwockPX6mZHdvkpN1Fb26NG\n\
/oeWwF0c5hFYhqkonX9ZzRbj5cMEzg1PYVIJPLH1zw4dXBCLChKlLLSpd7v9gKju\n\
FeH2J+5Umf2YqJV6MMs6ylitPf9wuEx8aO/ZC5h6MbghLTcHLv7xHgdjCUSpFaC4\n\
ues1AoGBAMcchcDomXgg11Zw814yQmbeew3/xrZ/ti+V1mbwBNpZx03gY/7SbaNW\n\
4WfLg+t4w0Z3thxYOhOdUv8yzT2eDF/u+ZfCEIxH21YMZxJLxJaHsPLu/lqE9+O6\n\
puOr7Y0asUkL7mvq3Zne3qEJqEtHHXRTMI8IE6UGskVv3LKElIvX\n\
-----END RSA PRIVATE KEY-----";

    const SAMPLE_MESSAGE: &str = "\
From: sender@example.com\r\n\
To: recipient@example.org\r\n\
Subject: Test message\r\n\
Date: Thu, 01 Jan 2025 00:00:00 +0000\r\n\
Message-ID: <test@example.com>\r\n\
\r\n\
Hello, this is a test message.\r\n";

    #[test]
    fn dkim_sign_rsa_produces_header() {
        let key = make_key(
            DkimAlgorithm::Rsa,
            DkimKeyStatus::Active,
            TEST_RSA_PRIVATE_KEY,
            "",
        );
        let result = dkim_sign(
            &key,
            "example.com",
            SAMPLE_MESSAGE.as_bytes(),
            &["From", "To", "Subject", "Date"],
        );
        let output = result.expect("RSA signing should succeed");
        assert!(
            output.header.contains("dkim-signature:") || output.header.contains("DKIM-Signature"),
            "header should contain DKIM-Signature: {}",
            output.header
        );
        assert!(
            output.header.contains("d=example.com"),
            "header should contain domain"
        );
        assert!(
            output.header.contains("s=test"),
            "header should contain selector"
        );
    }

    #[test]
    fn dkim_sign_with_bad_rsa_key_returns_error() {
        let key = make_key(
            DkimAlgorithm::Rsa,
            DkimKeyStatus::Active,
            "not-a-valid-pem",
            "",
        );
        let result = dkim_sign(
            &key,
            "example.com",
            SAMPLE_MESSAGE.as_bytes(),
            &["From", "To", "Subject"],
        );
        assert!(result.is_err());
    }

    // ── DkimVerifyResult mapping ─────────────────────────────────────────────

    #[test]
    fn verify_result_maps_pass() {
        assert_eq!(
            DkimVerifyResult::from_mail_auth(&DkimResult::Pass),
            DkimVerifyResult::Pass
        );
    }

    #[test]
    fn verify_result_maps_none() {
        assert_eq!(
            DkimVerifyResult::from_mail_auth(&DkimResult::None),
            DkimVerifyResult::None
        );
    }

    // ── DkimVerifyOutput ─────────────────────────────────────────────────────

    #[test]
    fn verify_output_has_pass_when_one_passes() {
        let output = DkimVerifyOutput {
            signatures: vec![
                DkimSignatureResult {
                    result: DkimVerifyResult::Fail,
                    domain: "a.com".into(),
                    selector: "s1".into(),
                    algorithm: "rsa-sha256".into(),
                },
                DkimSignatureResult {
                    result: DkimVerifyResult::Pass,
                    domain: "b.com".into(),
                    selector: "s2".into(),
                    algorithm: "ed25519-sha256".into(),
                },
            ],
        };
        assert!(output.has_pass());
    }

    #[test]
    fn verify_output_no_pass_when_all_fail() {
        let output = DkimVerifyOutput {
            signatures: vec![DkimSignatureResult {
                result: DkimVerifyResult::Fail,
                domain: "a.com".into(),
                selector: "s1".into(),
                algorithm: "rsa-sha256".into(),
            }],
        };
        assert!(!output.has_pass());
    }

    #[test]
    fn verify_output_no_pass_when_empty() {
        let output = DkimVerifyOutput { signatures: vec![] };
        assert!(!output.has_pass());
    }

    // ── DKIM sign-then-parse roundtrip ──────────────────────────────────

    #[test]
    fn dkim_sign_rsa_produces_parseable_header() {
        let key = make_key(
            DkimAlgorithm::Rsa,
            DkimKeyStatus::Active,
            TEST_RSA_PRIVATE_KEY,
            "",
        );
        let output = dkim_sign(
            &key,
            "example.com",
            SAMPLE_MESSAGE.as_bytes(),
            &["From", "To", "Subject", "Date"],
        )
        .expect("signing should succeed");

        // Prepend the DKIM-Signature header to the raw message
        let signed_message = format!("{}{}", output.header, SAMPLE_MESSAGE);

        // Parse with mail_auth
        let parsed = AuthenticatedMessage::parse(signed_message.as_bytes());
        assert!(parsed.is_some(), "signed message should be parseable");

        let auth_msg = parsed.unwrap();
        // Should find at least one DKIM signature in the parsed message
        assert!(
            !auth_msg.dkim_headers.is_empty(),
            "should find at least one DKIM signature header"
        );
    }

    #[test]
    fn dkim_sign_header_contains_correct_fields() {
        let key = make_key(
            DkimAlgorithm::Rsa,
            DkimKeyStatus::Active,
            TEST_RSA_PRIVATE_KEY,
            "",
        );
        let output = dkim_sign(
            &key,
            "example.com",
            SAMPLE_MESSAGE.as_bytes(),
            &["From", "To", "Subject", "Date"],
        )
        .expect("signing should succeed");

        let header = &output.header;
        assert!(
            header.contains("d=example.com"),
            "header should contain d=example.com: {header}"
        );
        assert!(
            header.contains("s=test"),
            "header should contain s=test: {header}"
        );
        assert!(
            header.contains("a=rsa-sha256"),
            "header should contain a=rsa-sha256: {header}"
        );
        assert!(
            header.contains("bh="),
            "header should contain bh= (body hash): {header}"
        );
        assert!(
            header.contains("b="),
            "header should contain b= (signature): {header}"
        );
    }

    #[test]
    fn dkim_sign_different_headers_list_changes_signature() {
        let key = make_key(
            DkimAlgorithm::Rsa,
            DkimKeyStatus::Active,
            TEST_RSA_PRIVATE_KEY,
            "",
        );

        let output1 = dkim_sign(
            &key,
            "example.com",
            SAMPLE_MESSAGE.as_bytes(),
            &["From", "To", "Subject"],
        )
        .expect("signing should succeed");

        let output2 = dkim_sign(
            &key,
            "example.com",
            SAMPLE_MESSAGE.as_bytes(),
            &["From", "To"],
        )
        .expect("signing should succeed");

        // Extract the b= values
        let extract_b = |header: &str| -> String {
            let b_pos = header.find("b=").expect("should have b=");
            let after_b = &header[b_pos + 2..];
            // b= value ends at the next ';' or end of header
            after_b
                .split(';')
                .next()
                .unwrap()
                .trim()
                .replace([' ', '\t', '\r', '\n'], "")
        };

        let b1 = extract_b(&output1.header);
        let b2 = extract_b(&output2.header);
        assert_ne!(
            b1, b2,
            "different header lists should produce different b= values"
        );
    }
}
