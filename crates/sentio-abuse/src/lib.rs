pub mod auth_guard;
pub mod ban;
pub mod dnsbl_cache;
pub mod greylist;
pub mod ip_reputation;
pub mod rate_guard;
pub mod redis_conn;
pub mod whitelist;

#[cfg(any(test, feature = "test-support"))]
pub mod mock;

#[cfg(all(test, feature = "integration"))]
mod integration_tests;

use std::net::IpAddr;

use sentio_core::config::AbuseConfig;
use sentio_core::error::SentioError;

pub use auth_guard::AuthGuard;
pub use ban::BanChecker;
pub use dnsbl_cache::{DnsLookup, DnsblChecker, DnsblResult};
pub use greylist::{GreylistAction, Greylister};
pub use ip_reputation::{ReputationAction, ReputationTracker};
pub use rate_guard::RateGuard;
pub use redis_conn::KvConn;
pub use whitelist::Whitelist;

/// Facade composing all abuse-prevention modules.
///
/// Use `check_connection` for a quick pre-accept gate (whitelist → ban → rDNS →
/// rate → DNSBL → reputation). Individual modules are publicly accessible for
/// granular use (e.g., greylisting at RCPT TO, auth tracking on AUTH failure).
pub struct AbuseGuard<R: KvConn, D: DnsLookup> {
    pub bans: BanChecker<R>,
    pub rate: RateGuard<R>,
    pub auth: AuthGuard<R>,
    pub reputation: ReputationTracker<R>,
    pub dnsbl: DnsblChecker<R, D>,
    pub greylist: Greylister<R>,
    pub whitelist: Whitelist<R>,
    reverse_dns_required: bool,
}

impl<R: KvConn, D: DnsLookup> AbuseGuard<R, D> {
    pub fn new(redis: R, resolver: D, config: &AbuseConfig) -> Self {
        Self {
            bans: BanChecker::new(redis.clone(), config),
            rate: RateGuard::new(redis.clone(), config),
            auth: AuthGuard::new(redis.clone(), config),
            reputation: ReputationTracker::new(redis.clone(), config),
            dnsbl: DnsblChecker::new(redis.clone(), resolver, config),
            greylist: Greylister::new(redis.clone(), &config.greylist),
            whitelist: Whitelist::new(redis, config),
            reverse_dns_required: config.reverse_dns_required,
        }
    }

    /// Run whitelist, ban, rDNS, rate-limit, DNSBL, and reputation checks for
    /// an incoming connection. Returns `Ok(())` if the connection is allowed.
    pub async fn check_connection(&self, ip: &IpAddr) -> Result<(), SentioError> {
        // Whitelist check - bypass all other checks
        if self.whitelist.is_whitelisted(ip).await {
            metrics::counter!("sentio_abuse_whitelist_bypasses_total").increment(1);
            return Ok(());
        }

        // Ban check
        if self.bans.is_banned(ip).await {
            return Err(SentioError::RateLimit {
                key: format!("banned:{ip}"),
            });
        }

        // Reverse DNS enforcement
        if self.reverse_dns_required {
            match self.dnsbl.resolver().reverse_lookup(ip).await {
                Ok(true) => {} // Has rDNS, proceed
                Ok(false) => {
                    tracing::warn!(%ip, "reverse DNS check failed: no PTR record");
                    metrics::counter!("sentio_abuse_rdns_failures_total").increment(1);
                    return Err(SentioError::RateLimit {
                        key: format!("rdns:{ip}"),
                    });
                }
                Err(e) => {
                    tracing::warn!(%ip, error = %e, "reverse DNS lookup error, failing open");
                    metrics::counter!("sentio_abuse_rdns_failures_total").increment(1);
                    // Fail open on DNS errors
                }
            }
        }

        // Rate limit
        if let Err(e) = self.rate.check_rate(ip).await {
            metrics::counter!("sentio_abuse_rate_limit_hits_total").increment(1);
            return Err(e);
        }

        // DNSBL check
        let dnsbl_result = self.dnsbl.check(ip).await;
        if dnsbl_result.listed {
            tracing::warn!(%ip, lists = ?dnsbl_result.listings, "IP listed on DNSBL");
            return Err(SentioError::RateLimit {
                key: format!("dnsbl:{ip}"),
            });
        }

        // Graduated reputation check
        match self.reputation.evaluate(ip).await {
            ReputationAction::Allow => {}
            ReputationAction::Warn => {
                tracing::warn!(%ip, "IP has elevated reputation score");
                // Allow but logged
            }
            ReputationAction::Greylist => {
                return Err(SentioError::RateLimit {
                    key: format!("reputation:greylist:{ip}"),
                });
            }
            ReputationAction::Reject => {
                return Err(SentioError::RateLimit {
                    key: format!("reputation:reject:{ip}"),
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockRedis;

    struct MockDns;

    impl DnsLookup for MockDns {
        fn lookup_a<'a>(
            &'a self,
            _name: &'a str,
        ) -> impl std::future::Future<Output = Result<bool, String>> + Send + 'a {
            std::future::ready(Ok(false))
        }

        fn reverse_lookup<'a>(
            &'a self,
            _ip: &'a IpAddr,
        ) -> impl std::future::Future<Output = Result<bool, String>> + Send + 'a {
            std::future::ready(Ok(true))
        }
    }

    struct MockDnsNoRdns;

    impl DnsLookup for MockDnsNoRdns {
        fn lookup_a<'a>(
            &'a self,
            _name: &'a str,
        ) -> impl std::future::Future<Output = Result<bool, String>> + Send + 'a {
            std::future::ready(Ok(false))
        }

        fn reverse_lookup<'a>(
            &'a self,
            _ip: &'a IpAddr,
        ) -> impl std::future::Future<Output = Result<bool, String>> + Send + 'a {
            std::future::ready(Ok(false))
        }
    }

    fn default_config() -> AbuseConfig {
        AbuseConfig::default()
    }

    #[tokio::test]
    async fn clean_ip_passes_all_checks() {
        let redis = MockRedis::new();
        let guard = AbuseGuard::new(redis, MockDns, &default_config());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        assert!(guard.check_connection(&ip).await.is_ok());
    }

    #[tokio::test]
    async fn banned_ip_rejected() {
        let redis = MockRedis::new();
        let config = default_config();
        let guard = AbuseGuard::new(redis, MockDns, &config);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        guard.bans.ban(&ip, 3600).await;

        let result = guard.check_connection(&ip).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn suspicious_ip_rejected() {
        let redis = MockRedis::new();
        let config = AbuseConfig {
            reputation_reject_threshold: 10.0,
            ..Default::default()
        };
        let guard = AbuseGuard::new(redis, MockDns, &config);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        guard.reputation.record_infraction(&ip, 15.0).await;

        let result = guard.check_connection(&ip).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn whitelisted_ip_bypasses_all_checks() {
        let redis = MockRedis::new();
        let config = AbuseConfig {
            whitelist_ips: vec!["10.0.0.1".into()],
            ..Default::default()
        };
        let guard = AbuseGuard::new(redis, MockDns, &config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Even if banned, whitelist should bypass
        guard.bans.ban(&ip, 3600).await;
        assert!(guard.check_connection(&ip).await.is_ok());
    }

    #[tokio::test]
    async fn reverse_dns_required_rejects_no_rdns() {
        let redis = MockRedis::new();
        let config = AbuseConfig {
            reverse_dns_required: true,
            ..Default::default()
        };
        let guard = AbuseGuard::new(redis, MockDnsNoRdns, &config);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        let result = guard.check_connection(&ip).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn reverse_dns_not_required_allows_no_rdns() {
        let redis = MockRedis::new();
        let config = AbuseConfig {
            reverse_dns_required: false,
            ..Default::default()
        };
        let guard = AbuseGuard::new(redis, MockDnsNoRdns, &config);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        assert!(guard.check_connection(&ip).await.is_ok());
    }

    #[tokio::test]
    async fn graduated_reputation_greylist() {
        let redis = MockRedis::new();
        let config = AbuseConfig {
            reputation_warn_threshold: 5.0,
            reputation_greylist_threshold: 7.5,
            reputation_reject_threshold: 10.0,
            ..Default::default()
        };
        let guard = AbuseGuard::new(redis, MockDns, &config);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        // Score 8.0 → Greylist (tempfail)
        guard.reputation.record_infraction(&ip, 8.0).await;
        let result = guard.check_connection(&ip).await;
        assert!(result.is_err());
    }
}
