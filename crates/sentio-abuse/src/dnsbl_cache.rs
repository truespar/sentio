use std::future::Future;
use std::net::IpAddr;

use sentio_core::config::AbuseConfig;

use crate::redis_conn::KvConn;

/// Abstraction over DNS A-record lookups, enabling mock DNS in tests.
///
/// `lookup_a` returns `Ok(true)` if listed, `Ok(false)` if not listed,
/// and `Err(message)` on DNS resolution failure (timeout, SERVFAIL, etc.).
///
/// DNSBL services return specific 127.x.x.x addresses to indicate listing status.
/// Spamhaus returns `127.255.255.254` (rate limited / public resolver) and
/// `127.255.255.255` (general error) which must NOT be treated as real listings.
/// Only responses in `127.0.0.x` range indicate actual listings.
pub trait DnsLookup: Send + Sync + 'static {
    fn lookup_a<'a>(
        &'a self,
        name: &'a str,
    ) -> impl Future<Output = Result<bool, String>> + Send + 'a;

    /// Perform a reverse DNS (PTR) lookup to verify an IP has a valid rDNS record.
    /// Returns `Ok(true)` if at least one PTR record exists.
    fn reverse_lookup<'a>(
        &'a self,
        ip: &'a IpAddr,
    ) -> impl Future<Output = Result<bool, String>> + Send + 'a;
}

/// Implement `DnsLookup` for the hickory async resolver.
impl DnsLookup for hickory_resolver::TokioResolver {
    fn lookup_a<'a>(
        &'a self,
        name: &'a str,
    ) -> impl Future<Output = Result<bool, String>> + Send + 'a {
        let name = name.to_string();
        async move {
            match self.lookup_ip(name.as_str()).await {
                Ok(response) => {
                    // Only treat 127.0.0.x responses as real DNSBL listings.
                    // 127.255.255.254 = rate limited / public resolver blocked
                    // 127.255.255.255 = general error from DNSBL provider
                    Ok(response.iter().any(|addr| {
                        if let std::net::IpAddr::V4(v4) = addr {
                            let octets = v4.octets();
                            octets[0] == 127 && octets[1] == 0 && octets[2] == 0
                        } else {
                            false
                        }
                    }))
                }
                Err(e) => {
                    if e.is_no_records_found() || e.is_nx_domain() {
                        Ok(false)
                    } else {
                        Err(e.to_string())
                    }
                }
            }
        }
    }

    async fn reverse_lookup(&self, ip: &IpAddr) -> Result<bool, String> {
        match self.reverse_lookup(*ip).await {
            Ok(response) => Ok(!response.answers().is_empty()),
            Err(e) => {
                if e.is_no_records_found() || e.is_nx_domain() {
                    Ok(false)
                } else {
                    Err(e.to_string())
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct DnsblResult {
    pub listed: bool,
    pub listings: Vec<String>,
}

pub struct DnsblChecker<R: KvConn, D: DnsLookup> {
    redis: R,
    resolver: D,
    lists: Vec<String>,
    cache_secs: u64,
}

impl<R: KvConn, D: DnsLookup> DnsblChecker<R, D> {
    pub fn new(redis: R, resolver: D, config: &AbuseConfig) -> Self {
        Self {
            redis,
            resolver,
            lists: config.dnsbl_lists.clone(),
            cache_secs: config.dnsbl_cache_secs,
        }
    }

    /// Expose the resolver for reverse DNS lookups.
    pub fn resolver(&self) -> &D {
        &self.resolver
    }

    /// Check an IP against all configured DNSBL lists.
    pub async fn check(&self, ip: &IpAddr) -> DnsblResult {
        let reversed = match reverse_ip(ip) {
            Some(r) => r,
            None => {
                return DnsblResult {
                    listed: false,
                    listings: vec![],
                }
            }
        };

        let mut listings = Vec::new();

        for list in &self.lists {
            if self.check_single_inner(ip, list, &reversed).await {
                listings.push(list.clone());
            }
        }

        DnsblResult {
            listed: !listings.is_empty(),
            listings,
        }
    }

    /// Check an IP against a single DNSBL list.
    pub async fn check_single(&self, ip: &IpAddr, list: &str) -> bool {
        let reversed = match reverse_ip(ip) {
            Some(r) => r,
            None => return false,
        };
        self.check_single_inner(ip, list, &reversed).await
    }

    async fn check_single_inner(&self, ip: &IpAddr, list: &str, reversed: &str) -> bool {
        let cache_key = format!("sentio:smtp:dnsbl:{list}:{ip}");

        // Check cache first
        if let Ok(Some(cached)) = self.redis.get_opt(&cache_key).await {
            return cached == "1";
        }

        // DNS lookup: reversed-IP.list → A record
        let query = format!("{reversed}.{list}");
        let listed = match self.resolver.lookup_a(&query).await {
            Ok(result) => result,
            Err(err) => {
                tracing::warn!(
                    list,
                    query = %query,
                    error = %err,
                    "DNSBL DNS lookup failed, failing open"
                );
                metrics::counter!("sentio_abuse_dnsbl_errors_total", "list" => list.to_string())
                    .increment(1);
                return false; // Fail open on DNS errors
            }
        };

        // Cache the result
        let value = if listed { "1" } else { "0" };
        let _ = self.redis.set_ex(&cache_key, value, self.cache_secs).await;

        if listed {
            metrics::counter!("sentio_abuse_dnsbl_hits_total", "list" => list.to_string())
                .increment(1);
        }

        listed
    }
}

/// Reverse the octets/nibbles of an IP address for DNSBL queries.
/// IPv4: reverses octets (1.2.3.4 → 4.3.2.1)
/// IPv6: expands to full nibble format and reverses
///   (::1 → 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0)
fn reverse_ip(ip: &IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(format!("{}.{}.{}.{}", o[3], o[2], o[1], o[0]))
        }
        IpAddr::V6(v6) => {
            let nibbles: String = v6
                .octets()
                .iter()
                .rev()
                .flat_map(|byte| {
                    // Low nibble first, then high nibble (after byte reversal)
                    [byte & 0x0f, (byte >> 4) & 0x0f]
                })
                .map(|n| format!("{n:x}"))
                .collect::<Vec<_>>()
                .join(".");
            Some(nibbles)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockRedis;

    struct MockDns {
        listed: bool,
    }

    impl DnsLookup for MockDns {
        fn lookup_a<'a>(
            &'a self,
            _name: &'a str,
        ) -> impl Future<Output = Result<bool, String>> + Send + 'a {
            std::future::ready(Ok(self.listed))
        }

        fn reverse_lookup<'a>(
            &'a self,
            _ip: &'a IpAddr,
        ) -> impl Future<Output = Result<bool, String>> + Send + 'a {
            std::future::ready(Ok(true))
        }
    }

    struct FailingDns;

    impl DnsLookup for FailingDns {
        fn lookup_a<'a>(
            &'a self,
            _name: &'a str,
        ) -> impl Future<Output = Result<bool, String>> + Send + 'a {
            std::future::ready(Err("DNS SERVFAIL".to_string()))
        }

        fn reverse_lookup<'a>(
            &'a self,
            _ip: &'a IpAddr,
        ) -> impl Future<Output = Result<bool, String>> + Send + 'a {
            std::future::ready(Err("DNS SERVFAIL".to_string()))
        }
    }

    fn default_config() -> AbuseConfig {
        AbuseConfig::default()
    }

    #[tokio::test]
    async fn listed_ip_detected() {
        let redis = MockRedis::new();
        let dns = MockDns { listed: true };
        let checker = DnsblChecker::new(redis, dns, &default_config());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        let result = checker.check(&ip).await;
        assert!(result.listed);
        assert!(!result.listings.is_empty());
    }

    #[tokio::test]
    async fn unlisted_ip_clean() {
        let redis = MockRedis::new();
        let dns = MockDns { listed: false };
        let checker = DnsblChecker::new(redis, dns, &default_config());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        let result = checker.check(&ip).await;
        assert!(!result.listed);
        assert!(result.listings.is_empty());
    }

    #[tokio::test]
    async fn cache_hit_uses_cached_value() {
        let redis = MockRedis::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        // Pre-populate cache with "not listed"
        let config = default_config();
        for list in &config.dnsbl_lists {
            redis.raw_set(&format!("sentio:smtp:dnsbl:{list}:{ip}"), "0");
        }

        // Even though DNS says "listed", cache says "not listed"
        let dns = MockDns { listed: true };
        let checker = DnsblChecker::new(redis, dns, &config);

        let result = checker.check(&ip).await;
        assert!(!result.listed);
    }

    #[tokio::test]
    async fn check_single_list() {
        let redis = MockRedis::new();
        let dns = MockDns { listed: true };
        let checker = DnsblChecker::new(redis, dns, &default_config());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        assert!(checker.check_single(&ip, "zen.spamhaus.org").await);
    }

    #[tokio::test]
    async fn ipv6_now_checked() {
        let redis = MockRedis::new();
        let dns = MockDns { listed: true };
        let checker = DnsblChecker::new(redis, dns, &default_config());
        let ip: IpAddr = "::1".parse().unwrap();

        let result = checker.check(&ip).await;
        assert!(result.listed, "IPv6 should now be checked against DNSBL");
    }

    #[tokio::test]
    async fn dns_failure_fails_open() {
        let redis = MockRedis::new();
        let checker = DnsblChecker::new(redis, FailingDns, &default_config());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        let result = checker.check(&ip).await;
        assert!(!result.listed, "DNS failures should fail open (not listed)");
    }

    #[test]
    fn reverse_ip_v4() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(reverse_ip(&ip), Some("4.3.2.1".to_string()));
    }

    #[test]
    fn reverse_ip_v6_loopback() {
        let ip: IpAddr = "::1".parse().unwrap();
        let reversed = reverse_ip(&ip).unwrap();
        assert_eq!(
            reversed,
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0"
        );
    }

    #[test]
    fn reverse_ip_v6_full() {
        let ip: IpAddr = "2001:0db8::1".parse().unwrap();
        let reversed = reverse_ip(&ip).unwrap();
        assert_eq!(
            reversed,
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
        );
    }
}
