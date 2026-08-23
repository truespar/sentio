use hickory_resolver::config::{ResolverConfig, CLOUDFLARE, GOOGLE, QUAD9};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;
use mail_auth::MessageAuthenticator;
use sentio_core::error::SentioError;
use serde::{Deserialize, Serialize};

/// Which upstream DNS resolver the [`Authenticator`] should use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsResolverConfig {
    /// Use the operating-system resolver (typically `/etc/resolv.conf`).
    System,
    /// Cloudflare DNS-over-TLS (1.1.1.1).
    CloudflareTls,
    /// Google Public DNS (8.8.8.8 / 8.8.4.4).
    Google,
    /// Quad9 DNS-over-TLS (9.9.9.9).
    Quad9Tls,
}

impl DnsResolverConfig {
    /// Parse from a config string. Falls back to `Google` for unknown values.
    pub fn from_config_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "system" => Self::System,
            "cloudflare_tls" | "cloudflare" => Self::CloudflareTls,
            "google" => Self::Google,
            "quad9_tls" | "quad9" => Self::Quad9Tls,
            _ => {
                tracing::warn!(
                    value = s,
                    "unknown dns_resolver value, defaulting to google"
                );
                Self::Google
            }
        }
    }
}

/// Thin wrapper around [`mail_auth::MessageAuthenticator`] and a
/// [`hickory_resolver::TokioResolver`] so that downstream crates never
/// depend on `mail-auth` or `hickory-resolver` directly.
pub struct Authenticator {
    pub(crate) inner: MessageAuthenticator,
    pub(crate) resolver: TokioResolver,
}

impl Authenticator {
    /// Build an [`Authenticator`] for the given resolver configuration.
    pub fn new(config: DnsResolverConfig) -> Result<Self, SentioError> {
        let inner = match config {
            DnsResolverConfig::System => MessageAuthenticator::new_system_conf(),
            DnsResolverConfig::CloudflareTls => MessageAuthenticator::new_cloudflare_tls(),
            DnsResolverConfig::Google => MessageAuthenticator::new_google(),
            DnsResolverConfig::Quad9Tls => MessageAuthenticator::new_quad9_tls(),
        }
        .map_err(|e| SentioError::Auth(format!("failed to create DNS resolver: {e}")))?;

        let resolver = match config {
            DnsResolverConfig::System => TokioResolver::builder_tokio()
                .map_err(|e| {
                    SentioError::Auth(format!("failed to create system DNS resolver: {e}"))
                })?
                .build(),
            DnsResolverConfig::CloudflareTls => TokioResolver::builder_with_config(
                ResolverConfig::udp_and_tcp(&CLOUDFLARE),
                TokioRuntimeProvider::default(),
            )
            .build(),
            DnsResolverConfig::Google => TokioResolver::builder_with_config(
                ResolverConfig::udp_and_tcp(&GOOGLE),
                TokioRuntimeProvider::default(),
            )
            .build(),
            DnsResolverConfig::Quad9Tls => TokioResolver::builder_with_config(
                ResolverConfig::udp_and_tcp(&QUAD9),
                TokioRuntimeProvider::default(),
            )
            .build(),
        }
        .map_err(|e| SentioError::Auth(format!("failed to build DNS resolver: {e}")))?;

        Ok(Self { inner, resolver })
    }

    /// Convenience: build from the system resolver configuration.
    pub fn from_system_conf() -> Result<Self, SentioError> {
        Self::new(DnsResolverConfig::System)
    }

    /// Access the underlying hickory [`TokioResolver`] for MX/A/AAAA lookups.
    pub fn resolver(&self) -> &TokioResolver {
        &self.resolver
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_conf_creates_authenticator() {
        // System DNS should always be available on CI / dev machines.
        let auth = Authenticator::new(DnsResolverConfig::System);
        assert!(auth.is_ok());
    }

    #[test]
    fn cloudflare_tls_creates_authenticator() {
        let auth = Authenticator::new(DnsResolverConfig::CloudflareTls);
        assert!(auth.is_ok());
    }

    #[test]
    fn google_creates_authenticator() {
        let auth = Authenticator::new(DnsResolverConfig::Google);
        assert!(auth.is_ok());
    }

    #[test]
    fn quad9_tls_creates_authenticator() {
        let auth = Authenticator::new(DnsResolverConfig::Quad9Tls);
        assert!(auth.is_ok());
    }

    #[test]
    fn from_system_conf_shortcut() {
        let auth = Authenticator::from_system_conf();
        assert!(auth.is_ok());
    }

    #[test]
    fn dns_resolver_config_serde_roundtrip() {
        let cfg = DnsResolverConfig::CloudflareTls;
        let json = serde_json::to_string(&cfg).unwrap();
        assert_eq!(json, "\"cloudflare_tls\"");
        let parsed: DnsResolverConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, cfg);
    }
}
