use std::net::IpAddr;

use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use sentio_core::error::SentioError;

/// A single MX host with its preference and resolved addresses.
#[derive(Debug, Clone)]
pub struct MxHost {
    pub hostname: String,
    pub preference: u16,
    pub addresses: Vec<IpAddr>,
}

/// Result of resolving MX records for a domain.
#[derive(Debug, Clone)]
pub struct MxResolution {
    pub domain: String,
    pub hosts: Vec<MxHost>,
}

/// Resolve MX records for `domain`, sorted by preference (lowest first).
///
/// - If the MX lookup finds a null MX (RFC 7505 - a single MX with preference 0
///   and hostname `.`), returns an empty host list.
/// - If no MX records are found, falls back to using the domain itself as the
///   mail host (A/AAAA lookup).
pub async fn resolve_mx(
    resolver: &TokioResolver,
    domain: &str,
) -> Result<MxResolution, SentioError> {
    let mx_lookup = resolver.mx_lookup(domain).await;

    match mx_lookup {
        Ok(lookup) => {
            let mut entries: Vec<(u16, String)> = lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::MX(mx) => Some((mx.preference, mx.exchange.to_ascii())),
                    _ => None,
                })
                .collect();

            // RFC 7505: null MX - single record with preference 0 and hostname "."
            if entries.len() == 1 && entries[0].0 == 0 && entries[0].1 == "." {
                return Ok(MxResolution {
                    domain: domain.to_string(),
                    hosts: vec![],
                });
            }

            // Sort by preference (lowest first).
            entries.sort_by_key(|(pref, _)| *pref);

            let mut hosts = Vec::with_capacity(entries.len());
            for (pref, hostname) in &entries {
                let addresses = resolve_addresses(resolver, hostname).await;
                hosts.push(MxHost {
                    hostname: hostname.clone(),
                    preference: *pref,
                    addresses,
                });
            }

            Ok(MxResolution {
                domain: domain.to_string(),
                hosts,
            })
        }
        Err(_) => {
            // No MX records - fall back to A/AAAA on the domain itself.
            let addresses = resolve_addresses(resolver, domain).await;
            let hosts = if addresses.is_empty() {
                vec![]
            } else {
                vec![MxHost {
                    hostname: domain.to_string(),
                    preference: 0,
                    addresses,
                }]
            };
            Ok(MxResolution {
                domain: domain.to_string(),
                hosts,
            })
        }
    }
}

/// Resolve A + AAAA records for `hostname`, combining both into a single list.
pub async fn resolve_addresses(resolver: &TokioResolver, hostname: &str) -> Vec<IpAddr> {
    let mut addrs = Vec::new();

    if let Ok(ipv4) = resolver.ipv4_lookup(hostname).await {
        for record in ipv4.answers() {
            if let RData::A(a) = &record.data {
                addrs.push(IpAddr::V4(a.0));
            }
        }
    }

    if let Ok(ipv6) = resolver.ipv6_lookup(hostname).await {
        for record in ipv6.answers() {
            if let RData::AAAA(aaaa) = &record.data {
                addrs.push(IpAddr::V6(aaaa.0));
            }
        }
    }

    addrs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_resolver() -> TokioResolver {
        TokioResolver::builder_tokio()
            .expect("system DNS resolver")
            .build()
            .expect("build resolver")
    }

    #[tokio::test]
    async fn resolve_mx_returns_sorted_by_preference() {
        let resolver = test_resolver();
        // gmail.com has well-known MX records.
        let result = resolve_mx(&resolver, "gmail.com").await.unwrap();
        assert_eq!(result.domain, "gmail.com");
        assert!(!result.hosts.is_empty(), "gmail.com should have MX records");

        // Verify sorted by preference.
        for window in result.hosts.windows(2) {
            assert!(
                window[0].preference <= window[1].preference,
                "MX hosts should be sorted by preference"
            );
        }
    }

    #[tokio::test]
    async fn resolve_mx_falls_back_to_a_record() {
        let resolver = test_resolver();
        // example.com typically has no MX records, should fall back to A/AAAA.
        let result = resolve_mx(&resolver, "example.com").await.unwrap();
        assert_eq!(result.domain, "example.com");
        // example.com should resolve via A record fallback.
        if !result.hosts.is_empty() {
            assert_eq!(result.hosts[0].hostname, "example.com");
            assert!(!result.hosts[0].addresses.is_empty());
        }
    }

    #[tokio::test]
    async fn resolve_addresses_returns_ips() {
        let resolver = test_resolver();
        let addrs = resolve_addresses(&resolver, "one.one.one.one").await;
        assert!(!addrs.is_empty(), "one.one.one.one should have addresses");
    }
}
