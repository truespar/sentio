use std::net::IpAddr;

use sentio_abuse::{DnsLookup, DnsblChecker, KvConn};
use sentio_core::config::AbuseConfig;
use sentio_core::traits::SpamRule;

/// DNSBL scorer that wraps `sentio_abuse::DnsblChecker` with Redis caching.
///
/// Each DNSBL listing produces a `SpamRule` with +3.0 score.
pub struct DnsblScorer<R: KvConn, D: DnsLookup> {
    checker: DnsblChecker<R, D>,
}

impl<R: KvConn, D: DnsLookup> DnsblScorer<R, D> {
    pub fn new(redis: R, resolver: D, config: &AbuseConfig) -> Self {
        Self {
            checker: DnsblChecker::new(redis, resolver, config),
        }
    }

    /// Check the peer IP against configured DNSBL zones.
    pub async fn check(&self, ip: &IpAddr) -> Vec<SpamRule> {
        let result = self.checker.check(ip).await;

        result
            .listings
            .into_iter()
            .map(|list| SpamRule {
                name: format!("DNSBL_{}", list.replace('.', "_").to_uppercase()),
                score: 3.0,
                description: format!("IP listed on {list}"),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentio_abuse::mock::MockRedis;
    use std::future::Future;
    use std::net::IpAddr;

    struct ListedDns;

    impl DnsLookup for ListedDns {
        fn lookup_a<'a>(
            &'a self,
            _name: &'a str,
        ) -> impl Future<Output = Result<bool, String>> + Send + 'a {
            std::future::ready(Ok(true))
        }

        fn reverse_lookup<'a>(
            &'a self,
            _ip: &'a IpAddr,
        ) -> impl Future<Output = Result<bool, String>> + Send + 'a {
            std::future::ready(Ok(true))
        }
    }

    struct CleanDns;

    impl DnsLookup for CleanDns {
        fn lookup_a<'a>(
            &'a self,
            _name: &'a str,
        ) -> impl Future<Output = Result<bool, String>> + Send + 'a {
            std::future::ready(Ok(false))
        }

        fn reverse_lookup<'a>(
            &'a self,
            _ip: &'a IpAddr,
        ) -> impl Future<Output = Result<bool, String>> + Send + 'a {
            std::future::ready(Ok(true))
        }
    }

    fn default_config() -> AbuseConfig {
        AbuseConfig::default()
    }

    #[tokio::test]
    async fn listed_ip_produces_rules() {
        let redis = MockRedis::new();
        let scorer = DnsblScorer::new(redis, ListedDns, &default_config());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        let rules = scorer.check(&ip).await;
        assert!(!rules.is_empty());
        for rule in &rules {
            assert!(rule.name.starts_with("DNSBL_"));
            assert_eq!(rule.score, 3.0);
        }
    }

    #[tokio::test]
    async fn clean_ip_no_rules() {
        let redis = MockRedis::new();
        let scorer = DnsblScorer::new(redis, CleanDns, &default_config());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        let rules = scorer.check(&ip).await;
        assert!(rules.is_empty());
    }

    #[tokio::test]
    async fn ipv6_returns_rules_when_listed() {
        let redis = MockRedis::new();
        let scorer = DnsblScorer::new(redis, ListedDns, &default_config());
        let ip: IpAddr = "::1".parse().unwrap();

        let rules = scorer.check(&ip).await;
        assert!(
            !rules.is_empty(),
            "IPv6 addresses should now be checked against DNSBL"
        );
    }
}
