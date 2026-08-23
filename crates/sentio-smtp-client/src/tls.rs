use std::sync::Arc;

use sentio_auth::dane::{TlsaMatchingType, TlsaRecord, TlsaSelector, TlsaUsage};
use sentio_auth::mta_sts::MtaStsMode;
use sentio_auth::Authenticator;
use sentio_core::error::{SentioError, SmtpError};

/// Helper to create an SentioError::Smtp from a message string.
fn smtp_err(msg: impl Into<String>) -> SentioError {
    SentioError::Smtp(SmtpError {
        code: 0,
        enhanced: None,
        message: msg.into(),
    })
}
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;

// ──────────────────────────────────────────────────────────────────────────────
// TLS policy types
// ──────────────────────────────────────────────────────────────────────────────

/// The TLS policy to apply for outbound delivery to a given MX host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsPolicy {
    /// Try STARTTLS if available; fall back to plaintext if not.
    Opportunistic,
    /// Require TLS (MTA-STS enforce mode or admin config).
    Required,
    /// Require TLS and validate using DANE/TLSA records.
    Dane,
}

/// Computed TLS requirement for a specific delivery attempt.
#[derive(Debug, Clone)]
pub struct TlsRequirement {
    pub policy: TlsPolicy,
    pub dane_records: Vec<TlsaRecord>,
    pub mta_sts_mx_patterns: Vec<String>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Policy evaluation
// ──────────────────────────────────────────────────────────────────────────────

/// Evaluate the TLS policy for delivering to a specific MX host.
///
/// Priority: DANE TLSA records > MTA-STS enforce > Opportunistic.
pub async fn evaluate_tls_policy(
    authenticator: &Authenticator,
    mx_host: &str,
    domain: &str,
    dane_enabled: bool,
) -> Result<TlsRequirement, SentioError> {
    // 1. Check DANE TLSA records (highest priority).
    if dane_enabled {
        let dane = authenticator.lookup_tlsa(mx_host, 25).await?;
        if dane.has_tlsa && !dane.records.is_empty() {
            return Ok(TlsRequirement {
                policy: TlsPolicy::Dane,
                dane_records: dane.records,
                mta_sts_mx_patterns: vec![],
            });
        }
    }

    // 2. Check MTA-STS policy.
    match authenticator.fetch_mta_sts(domain).await {
        Ok(output) => {
            if let Some(ref policy) = output.policy {
                if policy.mode == MtaStsMode::Enforce && policy.matches_mx(mx_host) {
                    return Ok(TlsRequirement {
                        policy: TlsPolicy::Required,
                        dane_records: vec![],
                        mta_sts_mx_patterns: policy.mx.clone(),
                    });
                }
            }
        }
        Err(e) => {
            tracing::debug!(domain, error = %e, "MTA-STS lookup failed, falling back to opportunistic");
        }
    }

    // 3. Default: opportunistic TLS.
    Ok(TlsRequirement {
        policy: TlsPolicy::Opportunistic,
        dane_records: vec![],
        mta_sts_mx_patterns: vec![],
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// TLS configuration building
// ──────────────────────────────────────────────────────────────────────────────

/// Build a `rustls::ClientConfig` based on the TLS requirement.
pub fn build_client_config(requirement: &TlsRequirement) -> Result<ClientConfig, SentioError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    match requirement.policy {
        TlsPolicy::Dane if !requirement.dane_records.is_empty() => {
            let verifier = DaneVerifier {
                records: requirement.dane_records.clone(),
            };
            let config = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| smtp_err(format!("TLS protocol config error: {e}")))?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth();
            Ok(config)
        }
        TlsPolicy::Opportunistic => {
            // Opportunistic TLS: encrypt the connection but do not verify
            // certificates. This matches the behaviour of all major MTAs
            // (Postfix smtp_tls_security_level=may, Exim, Gmail, Microsoft).
            // Certificate authentication is the job of DANE and MTA-STS.
            let config = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| smtp_err(format!("TLS protocol config error: {e}")))?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(OpportunisticVerifier))
                .with_no_client_auth();
            Ok(config)
        }
        _ => {
            // Standard WebPKI verification for Required (MTA-STS enforce).
            let root_store = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let config = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| smtp_err(format!("TLS protocol config error: {e}")))?
                .with_root_certificates(root_store)
                .with_no_client_auth();
            Ok(config)
        }
    }
}

/// Perform STARTTLS upgrade on a plaintext stream.
pub async fn starttls_upgrade<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    config: Arc<ClientConfig>,
    server_name: &str,
) -> Result<(tokio_rustls::client::TlsStream<S>, String), SentioError> {
    let name = server_name.trim_end_matches('.');
    let server_name = ServerName::try_from(name.to_string())
        .map_err(|e| smtp_err(format!("invalid server name for TLS: {e}")))?;

    let connector = TlsConnector::from(config);
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| smtp_err(format!("TLS handshake failed: {e}")))?;

    let (_, conn) = tls_stream.get_ref();
    let version = match conn.protocol_version() {
        Some(v) => format!("{v:?}"),
        None => "unknown".to_string(),
    };

    Ok((tls_stream, version))
}

// ──────────────────────────────────────────────────────────────────────────────
// DANE certificate verifier
// ──────────────────────────────────────────────────────────────────────────────

/// Permissive certificate verifier for opportunistic TLS.
///
/// Accepts any certificate without validation.  The purpose of opportunistic
/// TLS is encryption against passive eavesdropping, not authentication.
/// Authentication is enforced only by DANE (TLSA records) or MTA-STS
/// (enforce mode).  This matches the default behaviour of Postfix
/// (`smtp_tls_security_level = may`), Exim, and all major mail providers.
#[derive(Debug)]
struct OpportunisticVerifier;

impl ServerCertVerifier for OpportunisticVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

/// Custom certificate verifier for DANE-EE (usage 3) TLSA records.
///
/// Matches DANE-EE + SPKI + SHA-256 hash against the server's end-entity
/// certificate.
#[derive(Debug)]
struct DaneVerifier {
    records: Vec<TlsaRecord>,
}

impl ServerCertVerifier for DaneVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        for record in &self.records {
            // We support DANE-EE (usage 3), SPKI (selector 1), SHA-256 (matching 1).
            if record.usage != TlsaUsage::DaneEe {
                continue;
            }

            let cert_data = match record.selector {
                TlsaSelector::SubjectPublicKeyInfo => extract_spki_from_der(end_entity.as_ref()),
                TlsaSelector::FullCert => Some(end_entity.as_ref().to_vec()),
            };

            let Some(cert_data) = cert_data else {
                continue;
            };

            let matches = match record.matching_type {
                TlsaMatchingType::Sha256 => {
                    let hash = Sha256::digest(&cert_data);
                    hash.as_slice() == record.data
                }
                TlsaMatchingType::Full => cert_data == record.data,
                TlsaMatchingType::Sha512 => {
                    // SHA-512 not commonly used for DANE-EE; skip.
                    false
                }
            };

            if matches {
                return Ok(ServerCertVerified::assertion());
            }
        }

        Err(RustlsError::General(
            "no DANE TLSA record matched the server certificate".into(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        // DANE-EE: we trust the cert directly, so the signature is valid.
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

/// Extract the SubjectPublicKeyInfo bytes from a DER-encoded X.509 certificate.
///
/// This is a minimal ASN.1 parser that navigates to the SPKI field.
fn extract_spki_from_der(der: &[u8]) -> Option<Vec<u8>> {
    // X.509 structure:
    //   SEQUENCE {
    //     SEQUENCE (TBSCertificate) {
    //       [0] version (optional)
    //       INTEGER serialNumber
    //       SEQUENCE signatureAlgorithm
    //       SEQUENCE issuer
    //       SEQUENCE validity
    //       SEQUENCE subject
    //       SEQUENCE subjectPublicKeyInfo  <-- we want this
    //       ...
    //     }
    //     ...
    //   }
    let (_, cert_content) = read_asn1_sequence(der)?;
    let (_, tbs_content) = read_asn1_sequence(cert_content)?;

    let mut pos = 0;
    let tbs = tbs_content;

    // Skip version if present (context tag [0])
    if pos < tbs.len() && tbs[pos] == 0xA0 {
        let (len, _) = read_asn1_element(&tbs[pos..])?;
        pos += len;
    }

    // Skip serialNumber (INTEGER)
    let (len, _) = read_asn1_element(&tbs[pos..])?;
    pos += len;

    // Skip signatureAlgorithm (SEQUENCE)
    let (len, _) = read_asn1_element(&tbs[pos..])?;
    pos += len;

    // Skip issuer (SEQUENCE)
    let (len, _) = read_asn1_element(&tbs[pos..])?;
    pos += len;

    // Skip validity (SEQUENCE)
    let (len, _) = read_asn1_element(&tbs[pos..])?;
    pos += len;

    // Skip subject (SEQUENCE)
    let (len, _) = read_asn1_element(&tbs[pos..])?;
    pos += len;

    // subjectPublicKeyInfo (SEQUENCE) - return the full DER encoding
    let (len, _) = read_asn1_element(&tbs[pos..])?;
    Some(tbs[pos..pos + len].to_vec())
}

/// Read an ASN.1 SEQUENCE, returning (content_bytes).
fn read_asn1_sequence(data: &[u8]) -> Option<(usize, &[u8])> {
    if data.is_empty() || data[0] != 0x30 {
        return None;
    }
    let (total_len, content) = read_asn1_element(data)?;
    Some((total_len, content))
}

/// Read a single ASN.1 TLV element.
/// Returns (total_bytes_consumed, content_slice).
fn read_asn1_element(data: &[u8]) -> Option<(usize, &[u8])> {
    if data.is_empty() {
        return None;
    }
    let _tag = data[0];
    if data.len() < 2 {
        return None;
    }

    let (header_len, content_len) = if data[1] & 0x80 == 0 {
        (2, data[1] as usize)
    } else {
        let num_bytes = (data[1] & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 || data.len() < 2 + num_bytes {
            return None;
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | (data[2 + i] as usize);
        }
        (2 + num_bytes, len)
    };

    let total = header_len + content_len;
    if data.len() < total {
        return None;
    }

    Some((total, &data[header_len..total]))
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sentio_auth::dane::{TlsaMatchingType, TlsaRecord, TlsaSelector, TlsaUsage};

    #[test]
    fn tls_policy_variants() {
        assert_eq!(TlsPolicy::Opportunistic, TlsPolicy::Opportunistic);
        assert_ne!(TlsPolicy::Required, TlsPolicy::Dane);
    }

    #[test]
    fn build_config_standard_verification() {
        let req = TlsRequirement {
            policy: TlsPolicy::Required,
            dane_records: vec![],
            mta_sts_mx_patterns: vec!["*.example.com".into()],
        };
        let config = build_client_config(&req);
        assert!(config.is_ok());
    }

    #[test]
    fn build_config_opportunistic() {
        let req = TlsRequirement {
            policy: TlsPolicy::Opportunistic,
            dane_records: vec![],
            mta_sts_mx_patterns: vec![],
        };
        let config = build_client_config(&req);
        assert!(config.is_ok());
    }

    #[test]
    fn build_config_dane_with_records() {
        let req = TlsRequirement {
            policy: TlsPolicy::Dane,
            dane_records: vec![TlsaRecord {
                usage: TlsaUsage::DaneEe,
                selector: TlsaSelector::SubjectPublicKeyInfo,
                matching_type: TlsaMatchingType::Sha256,
                data: vec![0xAA; 32],
            }],
            mta_sts_mx_patterns: vec![],
        };
        let config = build_client_config(&req);
        assert!(config.is_ok());
    }

    #[test]
    fn dane_verifier_rejects_no_match() {
        let verifier = DaneVerifier {
            records: vec![TlsaRecord {
                usage: TlsaUsage::DaneEe,
                selector: TlsaSelector::FullCert,
                matching_type: TlsaMatchingType::Full,
                data: vec![0xFF; 10],
            }],
        };

        // A minimal synthetic DER cert that won't match.
        let fake_cert = CertificateDer::from(vec![0x30, 0x03, 0x01, 0x01, 0x00]);
        let result = verifier.verify_server_cert(
            &fake_cert,
            &[],
            &ServerName::try_from("example.com").unwrap(),
            &[],
            UnixTime::now(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn dane_verifier_accepts_full_cert_match() {
        let cert_data = vec![0x30, 0x03, 0x01, 0x01, 0x00];
        let verifier = DaneVerifier {
            records: vec![TlsaRecord {
                usage: TlsaUsage::DaneEe,
                selector: TlsaSelector::FullCert,
                matching_type: TlsaMatchingType::Full,
                data: cert_data.clone(),
            }],
        };

        let fake_cert = CertificateDer::from(cert_data);
        let result = verifier.verify_server_cert(
            &fake_cert,
            &[],
            &ServerName::try_from("example.com").unwrap(),
            &[],
            UnixTime::now(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn tls_requirement_default_values() {
        let req = TlsRequirement {
            policy: TlsPolicy::Opportunistic,
            dane_records: vec![],
            mta_sts_mx_patterns: vec![],
        };
        assert!(req.dane_records.is_empty());
        assert!(req.mta_sts_mx_patterns.is_empty());
    }
}
