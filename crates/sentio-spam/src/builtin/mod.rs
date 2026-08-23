pub mod bayes;
pub mod dnsbl;
pub mod headers;
pub mod heuristics;
pub mod uribl;

use std::net::IpAddr;

use sentio_abuse::{DnsLookup, KvConn};
use sentio_core::config::{AbuseConfig, SpamConfig};
use sentio_core::error::SentioError;
use sentio_core::traits::{SpamScore, SpamScorer};

use crate::aggregator::score_to_action;

use self::bayes::BayesFilter;
use self::dnsbl::DnsblScorer;
use self::headers::HeaderAnalyzer;
use self::heuristics::HeuristicScorer;
use self::uribl::UriblScorer;

/// Built-in spam scorer that orchestrates multiple sub-scorers:
/// header analysis, content heuristics, DNSBL, URIBL, and Bayesian classification.
pub struct BuiltinScorer<R: KvConn, D: DnsLookup + Clone> {
    dnsbl: DnsblScorer<R, D>,
    uribl: UriblScorer<D>,
    bayes: BayesFilter,
    config: SpamConfig,
    heuristics_enabled: bool,
    bayes_enabled: bool,
}

impl<R: KvConn, D: DnsLookup + Clone> BuiltinScorer<R, D> {
    pub fn new(
        redis: R,
        resolver: D,
        spam_config: &SpamConfig,
        abuse_config: &AbuseConfig,
    ) -> Self {
        // Build a custom AbuseConfig for the DNSBL scorer using the spam-specific list
        let dnsbl_abuse_config = AbuseConfig {
            dnsbl_lists: spam_config.builtin.dnsbl_lists.clone(),
            ..abuse_config.clone()
        };

        Self {
            dnsbl: DnsblScorer::new(redis, resolver.clone(), &dnsbl_abuse_config),
            uribl: UriblScorer::new(resolver, spam_config.builtin.uribl_lists.clone()),
            bayes: BayesFilter::new(),
            heuristics_enabled: spam_config.builtin.heuristics_enabled,
            bayes_enabled: spam_config.builtin.bayes_enabled,
            config: spam_config.clone(),
        }
    }

    /// Access the Bayesian filter for training.
    pub fn bayes(&self) -> &BayesFilter {
        &self.bayes
    }
}

impl<R: KvConn, D: DnsLookup + Clone> SpamScorer for BuiltinScorer<R, D> {
    async fn score(
        &self,
        raw_message: &[u8],
        _envelope_from: &str,
        _envelope_to: &[String],
        peer_ip: IpAddr,
    ) -> Result<SpamScore, SentioError> {
        let mut rules = Vec::new();

        // 1. Header analysis (always runs)
        rules.extend(HeaderAnalyzer::analyze(raw_message));

        // 2. Content heuristics
        if self.heuristics_enabled {
            rules.extend(HeuristicScorer::analyze(raw_message));
        }

        // 3. DNSBL check
        rules.extend(self.dnsbl.check(&peer_ip).await);

        // 4. URIBL check
        rules.extend(self.uribl.check(raw_message).await);

        // 5. Bayesian classification
        if self.bayes_enabled {
            if let Some(bayes_rule) = self.bayes.classify(raw_message) {
                rules.push(bayes_rule);
            }
        }

        // Sum all rule scores
        let score: f64 = rules.iter().map(|r| r.score).sum();
        let action = score_to_action(score, &self.config);

        Ok(SpamScore {
            score,
            action,
            rules,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentio_abuse::mock::MockRedis;
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};

    use sentio_core::traits::SpamAction;

    #[derive(Clone)]
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

    #[derive(Clone)]
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

    fn default_configs() -> (SpamConfig, AbuseConfig) {
        (SpamConfig::default(), AbuseConfig::default())
    }

    fn make_clean_message() -> Vec<u8> {
        concat!(
            "From: sender@example.com\r\n",
            "Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n",
            "Message-ID: <abc@example.com>\r\n",
            "Subject: Hello from a friend\r\n",
            "\r\n",
            "Hi there, just wanted to say hello and check in. Hope you are doing well."
        )
        .as_bytes()
        .to_vec()
    }

    fn make_spammy_message() -> Vec<u8> {
        concat!(
            "X-Mailer: PHPMailer bulk\r\n",
            "\r\n",
            "CLICK HERE IMMEDIATELY!!! VERIFY YOUR ACCOUNT NOW!!!! ",
            "ACT NOW!!!! YOU HAVE WON A PRIZE!!! ",
            "Visit https://bit.ly/scam123 to claim!!!"
        )
        .as_bytes()
        .to_vec()
    }

    #[tokio::test]
    async fn clean_message_low_score() {
        let (spam_cfg, abuse_cfg) = default_configs();
        let redis = MockRedis::new();
        let scorer = BuiltinScorer::new(redis, CleanDns, &spam_cfg, &abuse_cfg);

        let result = scorer
            .score(
                &make_clean_message(),
                "sender@example.com",
                &["rcpt@example.com".into()],
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            )
            .await
            .unwrap();

        assert_eq!(result.action, SpamAction::Accept);
        assert!(result.score < 4.0, "score was {}", result.score);
    }

    #[tokio::test]
    async fn spammy_message_high_score() {
        let (spam_cfg, abuse_cfg) = default_configs();
        let redis = MockRedis::new();
        let scorer = BuiltinScorer::new(redis, CleanDns, &spam_cfg, &abuse_cfg);

        let result = scorer
            .score(
                &make_spammy_message(),
                "spammer@evil.com",
                &["victim@example.com".into()],
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            )
            .await
            .unwrap();

        // Missing From, Date, Message-ID, Subject + caps + phishing + exclamation + short URL + x-mailer
        assert!(result.score > 4.0, "score was {}", result.score);
        assert!(!result.rules.is_empty());
    }

    #[tokio::test]
    async fn dnsbl_listed_ip_adds_score() {
        let (spam_cfg, abuse_cfg) = default_configs();
        let redis = MockRedis::new();
        let scorer = BuiltinScorer::new(redis, ListedDns, &spam_cfg, &abuse_cfg);

        let result = scorer
            .score(
                &make_clean_message(),
                "sender@example.com",
                &["rcpt@example.com".into()],
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            )
            .await
            .unwrap();

        let dnsbl_rules: Vec<_> = result
            .rules
            .iter()
            .filter(|r| r.name.starts_with("DNSBL_"))
            .collect();
        assert!(!dnsbl_rules.is_empty());
    }

    #[tokio::test]
    async fn heuristics_disabled_skips_content_checks() {
        let (mut spam_cfg, abuse_cfg) = default_configs();
        spam_cfg.builtin.heuristics_enabled = false;
        let redis = MockRedis::new();
        let scorer = BuiltinScorer::new(redis, CleanDns, &spam_cfg, &abuse_cfg);

        let result = scorer
            .score(
                &make_spammy_message(),
                "spammer@evil.com",
                &["victim@example.com".into()],
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            )
            .await
            .unwrap();

        // Should not have heuristic rules
        let heuristic_rules: Vec<_> = result
            .rules
            .iter()
            .filter(|r| {
                r.name == "PHISHING_PHRASES"
                    || r.name == "EXCESSIVE_EXCLAMATION"
                    || r.name == "BODY_ALL_CAPS_PCT"
                    || r.name == "SHORT_URL"
            })
            .collect();
        assert!(
            heuristic_rules.is_empty(),
            "should not have heuristic rules when disabled"
        );
    }

    #[tokio::test]
    async fn rules_have_valid_scores() {
        let (spam_cfg, abuse_cfg) = default_configs();
        let redis = MockRedis::new();
        let scorer = BuiltinScorer::new(redis, CleanDns, &spam_cfg, &abuse_cfg);

        let result = scorer
            .score(
                &make_spammy_message(),
                "spammer@evil.com",
                &["victim@example.com".into()],
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            )
            .await
            .unwrap();

        let sum: f64 = result.rules.iter().map(|r| r.score).sum();
        assert!(
            (result.score - sum).abs() < f64::EPSILON,
            "total score {} != sum of rules {}",
            result.score,
            sum
        );
    }
}
