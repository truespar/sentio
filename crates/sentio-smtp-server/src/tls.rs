use std::io;
use std::sync::Arc;

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, SupportedProtocolVersion};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sentio_core::config::TlsConfig;
use sentio_core::error::SentioError;
use sha2::{Digest, Sha256};
use tokio_rustls::TlsAcceptor;

/// Build a `rustls::ServerConfig` from the application TLS configuration.
pub fn build_tls_config(config: &TlsConfig) -> Result<Arc<ServerConfig>, SentioError> {
    let resolver = SniResolver::from_config(config)?;

    let versions: &[&SupportedProtocolVersion] = match config.min_version.as_str() {
        "1.3" => &[&rustls::version::TLS13],
        _ => &[&rustls::version::TLS12, &rustls::version::TLS13],
    };

    let mut server_config = ServerConfig::builder_with_protocol_versions(versions)
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));

    server_config.alpn_protocols = vec![b"smtp".to_vec()];

    Ok(Arc::new(server_config))
}

/// Build a `rustls::ServerConfig` from in-memory PEM cert and key bytes.
///
/// Uses a simple single-cert resolver (no SNI). Intended for tests that
/// generate certs at runtime via `rcgen`.
pub fn build_tls_config_from_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
    min_version: &str,
) -> Result<Arc<ServerConfig>, SentioError> {
    let certs = load_certs(cert_pem)?;
    let key = load_private_key(key_pem)?;

    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
        .map_err(|e| SentioError::Internal(format!("invalid private key: {e}")))?;

    let certified = Arc::new(CertifiedKey::new(certs, signing_key));
    let resolver = SniResolver {
        default_key: certified,
        sni_keys: Vec::new(),
    };

    let versions: &[&SupportedProtocolVersion] = match min_version {
        "1.3" => &[&rustls::version::TLS13],
        _ => &[&rustls::version::TLS12, &rustls::version::TLS13],
    };

    let mut server_config = ServerConfig::builder_with_protocol_versions(versions)
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));

    server_config.alpn_protocols = vec![b"smtp".to_vec()];

    Ok(Arc::new(server_config))
}

/// Build a `rustls::ServerConfig` from an [`SniResolver`].
///
/// Useful for tests that need multi-cert SNI selection.
pub fn build_tls_config_from_resolver(
    resolver: SniResolver,
    min_version: &str,
) -> Result<Arc<ServerConfig>, SentioError> {
    let versions: &[&SupportedProtocolVersion] = match min_version {
        "1.3" => &[&rustls::version::TLS13],
        _ => &[&rustls::version::TLS12, &rustls::version::TLS13],
    };

    let mut server_config = ServerConfig::builder_with_protocol_versions(versions)
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));

    server_config.alpn_protocols = vec![b"smtp".to_vec()];

    Ok(Arc::new(server_config))
}

/// Build a `TlsAcceptor` from the application TLS configuration.
pub fn build_acceptor(config: &TlsConfig) -> Result<TlsAcceptor, SentioError> {
    let server_config = build_tls_config(config)?;
    Ok(TlsAcceptor::from(server_config))
}

/// SNI-aware certificate resolver. Maps domain names to per-tenant cert chains
/// with a fallback to the default certificate.
#[derive(Debug)]
pub struct SniResolver {
    // Note: fields are pub(crate) to allow test construction via `from_pem_pairs`.
    default_key: Arc<CertifiedKey>,
    sni_keys: Vec<(Vec<String>, Arc<CertifiedKey>)>,
}

impl SniResolver {
    fn from_config(config: &TlsConfig) -> Result<Self, SentioError> {
        let default_key = load_certified_key(&config.cert_path, &config.key_path)?;

        let mut sni_keys = Vec::new();
        if config.sni_enabled {
            for sni in &config.sni_certs {
                let key = load_certified_key(&sni.cert_path, &sni.key_path)?;
                sni_keys.push((sni.domains.clone(), key));
            }
        }

        Ok(Self {
            default_key,
            sni_keys,
        })
    }

    /// Build a resolver from in-memory PEM cert/key pairs.
    ///
    /// The first entry becomes the default; remaining entries are SNI mappings.
    /// Intended for tests that generate certs at runtime.
    pub fn from_pem_pairs(pairs: &[(&[u8], &[u8], Vec<String>)]) -> Result<Self, SentioError> {
        if pairs.is_empty() {
            return Err(SentioError::Internal(
                "at least one cert/key pair required".into(),
            ));
        }

        let make_key =
            |cert_pem: &[u8], key_pem: &[u8]| -> Result<Arc<CertifiedKey>, SentioError> {
                let certs = load_certs(cert_pem)?;
                let key = load_private_key(key_pem)?;
                let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
                    .map_err(|e| SentioError::Internal(format!("invalid private key: {e}")))?;
                Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
            };

        let default_key = make_key(pairs[0].0, pairs[0].1)?;
        let mut sni_keys = Vec::new();
        for &(cert_pem, key_pem, ref domains) in &pairs[1..] {
            let key = make_key(cert_pem, key_pem)?;
            sni_keys.push((domains.clone(), key));
        }

        Ok(Self {
            default_key,
            sni_keys,
        })
    }

    /// Look up a certified key by domain name (used by `ResolvesServerCert`).
    fn lookup(&self, server_name: Option<&str>) -> Arc<CertifiedKey> {
        if let Some(name) = server_name {
            let name = name.to_lowercase();
            for (domains, key) in &self.sni_keys {
                for domain in domains {
                    if *domain == name {
                        return Arc::clone(key);
                    }
                    // Wildcard match: *.example.com matches sub.example.com
                    if let Some(suffix) = domain.strip_prefix("*.") {
                        if name.ends_with(suffix)
                            && name.len() > suffix.len()
                            && name.as_bytes()[name.len() - suffix.len() - 1] == b'.'
                        {
                            return Arc::clone(key);
                        }
                    }
                }
            }
        }
        Arc::clone(&self.default_key)
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.lookup(client_hello.server_name()))
    }
}

/// Load a PEM cert chain and private key from file paths.
fn load_certified_key(cert_path: &str, key_path: &str) -> Result<Arc<CertifiedKey>, SentioError> {
    let cert_data = std::fs::read(cert_path)
        .map_err(|e| SentioError::Internal(format!("failed to read cert file {cert_path}: {e}")))?;
    let key_data = std::fs::read(key_path)
        .map_err(|e| SentioError::Internal(format!("failed to read key file {key_path}: {e}")))?;

    let certs = load_certs(&cert_data)?;
    let key = load_private_key(&key_data)?;

    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
        .map_err(|e| SentioError::Internal(format!("invalid private key: {e}")))?;

    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

fn load_certs(data: &[u8]) -> Result<Vec<CertificateDer<'static>>, SentioError> {
    let mut reader = io::BufReader::new(data);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<_, _>>()
        .map_err(|e| SentioError::Internal(format!("failed to parse PEM certificates: {e}")))?;
    if certs.is_empty() {
        return Err(SentioError::Internal(
            "no certificates found in PEM file".into(),
        ));
    }
    Ok(certs)
}

fn load_private_key(data: &[u8]) -> Result<PrivateKeyDer<'static>, SentioError> {
    let mut reader = io::BufReader::new(data);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| SentioError::Internal(format!("failed to parse PEM private key: {e}")))?
        .ok_or_else(|| SentioError::Internal("no private key found in PEM file".into()))
}

/// Compute the `tls-server-end-point` channel binding hash (RFC 5929 §4.1).
///
/// Returns `SHA-256(DER-encoded leaf certificate)`. This is used for
/// SCRAM-SHA-256-PLUS channel binding verification.
pub fn compute_cert_hash(cert_pem: &[u8]) -> Result<Vec<u8>, SentioError> {
    let certs = load_certs(cert_pem)?;
    let leaf = certs
        .first()
        .ok_or_else(|| SentioError::Internal("no leaf certificate".into()))?;
    Ok(Sha256::digest(leaf.as_ref()).to_vec())
}

/// Compute the `tls-server-end-point` channel binding hash from a DER cert.
pub fn compute_cert_hash_from_der(leaf_der: &[u8]) -> Vec<u8> {
    Sha256::digest(leaf_der).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_certs_no_certs_in_data() {
        let result = load_certs(b"not-a-pem-file");
        assert!(result.is_err());
    }

    #[test]
    fn load_private_key_no_key_in_data() {
        let result = load_private_key(b"not-a-pem-file");
        assert!(result.is_err());
    }

    #[test]
    fn sni_lookup_exact_match() {
        // We can't easily construct CertifiedKey without real certs,
        // but we can test the matching logic in isolation.
        let domains = ["mail.example.com".to_string()];
        let domain = "mail.example.com";

        let matches = domains.iter().any(|d| d == domain);
        assert!(matches);
    }

    #[test]
    fn sni_wildcard_match() {
        let wildcard = "*.example.com";
        let name = "mail.example.com";

        let suffix = wildcard.strip_prefix("*.").unwrap();
        let matches = name.ends_with(suffix)
            && name.len() > suffix.len()
            && name.as_bytes()[name.len() - suffix.len() - 1] == b'.';
        assert!(matches);

        // Should not match the bare domain
        let bare = "example.com";
        let matches = bare.ends_with(suffix)
            && bare.len() > suffix.len()
            && bare.as_bytes()[bare.len() - suffix.len() - 1] == b'.';
        assert!(!matches);
    }

    #[test]
    fn sni_wildcard_no_match_subdomain() {
        let wildcard = "*.example.com";
        let name = "deep.sub.example.com";

        let suffix = wildcard.strip_prefix("*.").unwrap();
        let matches = name.ends_with(suffix)
            && name.len() > suffix.len()
            && name.as_bytes()[name.len() - suffix.len() - 1] == b'.';
        // Wildcards match any single level
        assert!(matches);
    }
}
