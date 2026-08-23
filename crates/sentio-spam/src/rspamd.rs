use std::net::IpAddr;
use std::time::Duration;

use sentio_core::config::SpamConfig;
use sentio_core::error::SentioError;
use sentio_core::traits::{SpamRule, SpamScore, SpamScorer, SpamTrainer};

use crate::aggregator::score_to_action;

/// Rspamd HTTP client that scores messages via the `/checkv2` endpoint.
pub struct RspamdScorer {
    client: reqwest::Client,
    base_url: String,
    password: Option<String>,
    config: SpamConfig,
}

impl RspamdScorer {
    pub fn new(config: &SpamConfig) -> Result<Self, SentioError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.rspamd.timeout_secs))
            .build()
            .map_err(|e| {
                SentioError::Internal(format!("failed to build rspamd HTTP client: {e}"))
            })?;

        let password = if config.rspamd.password.is_empty() {
            None
        } else {
            Some(config.rspamd.password.clone())
        };

        Ok(Self {
            client,
            base_url: config.rspamd.url.trim_end_matches('/').to_string(),
            password,
            config: config.clone(),
        })
    }
}

impl SpamScorer for RspamdScorer {
    async fn score(
        &self,
        raw_message: &[u8],
        envelope_from: &str,
        envelope_to: &[String],
        peer_ip: IpAddr,
    ) -> Result<SpamScore, SentioError> {
        let url = format!("{}/checkv2", self.base_url);

        let mut req = self
            .client
            .post(&url)
            .header("IP", peer_ip.to_string())
            .header("From", envelope_from)
            .body(raw_message.to_vec());

        if let Some(first_rcpt) = envelope_to.first() {
            req = req.header("Rcpt", first_rcpt.as_str());
        }

        if let Some(ref pw) = self.password {
            req = req.header("Password", pw.as_str());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| SentioError::Internal(format!("rspamd request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(SentioError::Internal(format!(
                "rspamd returned HTTP {}",
                resp.status()
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SentioError::Internal(format!("rspamd response parse failed: {e}")))?;

        let score = body["score"].as_f64().unwrap_or(0.0);

        // Always use our own threshold logic for the action.
        // Rspamd has its own internal thresholds that may differ from ours,
        // so we only take the score and rules from rspamd.
        let action = score_to_action(score, &self.config);

        // Extract symbol rules from rspamd response
        let mut rules = Vec::new();
        if let Some(symbols) = body.get("symbols").and_then(|s| s.as_object()) {
            for (name, info) in symbols {
                let rule_score = info["score"].as_f64().unwrap_or(0.0);
                let description = info["description"].as_str().unwrap_or("").to_string();
                rules.push(SpamRule {
                    name: name.clone(),
                    score: rule_score,
                    description,
                });
            }
        }

        Ok(SpamScore {
            score,
            action,
            rules,
        })
    }
}

impl SpamTrainer for RspamdScorer {
    async fn learn_spam(&self, raw_message: &[u8]) -> Result<(), SentioError> {
        self.learn(raw_message, "learnspam").await
    }

    async fn learn_ham(&self, raw_message: &[u8]) -> Result<(), SentioError> {
        self.learn(raw_message, "learnham").await
    }
}

impl RspamdScorer {
    async fn learn(&self, raw_message: &[u8], endpoint: &str) -> Result<(), SentioError> {
        let url = format!("{}/{}", self.base_url, endpoint);

        let mut req = self.client.post(&url).body(raw_message.to_vec());

        if let Some(ref pw) = self.password {
            req = req.header("Password", pw.as_str());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| SentioError::Internal(format!("rspamd {endpoint} request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(SentioError::Internal(format!(
                "rspamd {endpoint} returned HTTP {}",
                resp.status()
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentio_core::traits::SpamAction;
    use std::net::Ipv4Addr;

    fn test_config(url: &str) -> SpamConfig {
        SpamConfig {
            rspamd: sentio_core::config::RspamdConfig {
                url: url.to_string(),
                timeout_secs: 5,
                password: String::new(),
            },
            ..Default::default()
        }
    }

    fn test_config_with_password(url: &str, password: &str) -> SpamConfig {
        SpamConfig {
            rspamd: sentio_core::config::RspamdConfig {
                url: url.to_string(),
                timeout_secs: 5,
                password: password.to_string(),
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn rspamd_accept_response() {
        let server = wiremock::MockServer::start().await;

        let response_body = serde_json::json!({
            "score": 1.5,
            "action": "no action",
            "symbols": {
                "DKIM_SIGNED": {
                    "score": -0.5,
                    "description": "DKIM signature present"
                }
            }
        });

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/checkv2"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&server)
            .await;

        let config = test_config(&server.uri());
        let scorer = RspamdScorer::new(&config).unwrap();

        let result = scorer
            .score(
                b"Subject: test\r\n\r\nHello",
                "sender@example.com",
                &["rcpt@example.com".into()],
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            )
            .await
            .unwrap();

        assert_eq!(result.action, SpamAction::Accept);
        assert!((result.score - 1.5).abs() < f64::EPSILON);
        assert_eq!(result.rules.len(), 1);
        assert_eq!(result.rules[0].name, "DKIM_SIGNED");
    }

    #[tokio::test]
    async fn rspamd_reject_response() {
        let server = wiremock::MockServer::start().await;

        let response_body = serde_json::json!({
            "score": 20.0,
            "action": "reject",
            "symbols": {
                "SPAM_CONTENT": {
                    "score": 15.0,
                    "description": "Spam content detected"
                },
                "MISSING_FROM": {
                    "score": 5.0,
                    "description": "Missing From header"
                }
            }
        });

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/checkv2"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&server)
            .await;

        let config = test_config(&server.uri());
        let scorer = RspamdScorer::new(&config).unwrap();

        let result = scorer
            .score(
                b"test",
                "sender@example.com",
                &["rcpt@example.com".into()],
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            )
            .await
            .unwrap();

        assert_eq!(result.action, SpamAction::Reject);
        assert_eq!(result.rules.len(), 2);
    }

    #[tokio::test]
    async fn rspamd_add_header_response() {
        let server = wiremock::MockServer::start().await;

        let response_body = serde_json::json!({
            "score": 7.5,
            "action": "add header",
            "symbols": {}
        });

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/checkv2"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&server)
            .await;

        let config = test_config(&server.uri());
        let scorer = RspamdScorer::new(&config).unwrap();

        let result = scorer
            .score(
                b"test",
                "sender@example.com",
                &["rcpt@example.com".into()],
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            )
            .await
            .unwrap();

        assert_eq!(result.action, SpamAction::AddHeader);
    }

    #[tokio::test]
    async fn rspamd_greylist_response() {
        let server = wiremock::MockServer::start().await;

        let response_body = serde_json::json!({
            "score": 4.5,
            "action": "greylist",
            "symbols": {}
        });

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/checkv2"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&server)
            .await;

        let config = test_config(&server.uri());
        let scorer = RspamdScorer::new(&config).unwrap();

        let result = scorer
            .score(
                b"test",
                "sender@example.com",
                &["rcpt@example.com".into()],
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            )
            .await
            .unwrap();

        assert_eq!(result.action, SpamAction::Greylist);
    }

    #[tokio::test]
    async fn rspamd_password_header_sent() {
        let server = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/checkv2"))
            .and(wiremock::matchers::header("Password", "secret123"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "score": 0.0,
                    "action": "no action",
                    "symbols": {}
                })),
            )
            .mount(&server)
            .await;

        let config = test_config_with_password(&server.uri(), "secret123");
        let scorer = RspamdScorer::new(&config).unwrap();

        let result = scorer
            .score(
                b"test",
                "sender@example.com",
                &["rcpt@example.com".into()],
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn rspamd_http_error_returns_internal() {
        let server = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/checkv2"))
            .respond_with(wiremock::ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let config = test_config(&server.uri());
        let scorer = RspamdScorer::new(&config).unwrap();

        let result = scorer
            .score(
                b"test",
                "sender@example.com",
                &["rcpt@example.com".into()],
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rspamd_action_ignored_our_thresholds_used() {
        let server = wiremock::MockServer::start().await;

        // rspamd says "no action" but score 20.0 exceeds our reject threshold
        let response_body = serde_json::json!({
            "score": 20.0,
            "action": "no action",
            "symbols": {}
        });

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/checkv2"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&server)
            .await;

        let config = test_config(&server.uri());
        let scorer = RspamdScorer::new(&config).unwrap();

        let result = scorer
            .score(
                b"test",
                "sender@example.com",
                &["rcpt@example.com".into()],
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            )
            .await
            .unwrap();

        // score 20.0 >= reject threshold 12.0 - our thresholds override rspamd action
        assert_eq!(result.action, SpamAction::Reject);
    }
}
