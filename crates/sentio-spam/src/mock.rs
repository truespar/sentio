use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use sentio_core::error::SentioError;
use sentio_core::traits::{SpamAction, SpamScore, SpamScorer};

/// Mock spam scorer for testing. Returns configurable results.
///
/// Available behind `cfg(test)` or the `test-support` feature.
#[derive(Clone)]
pub struct MockSpamScorer {
    result: Arc<Mutex<SpamScore>>,
}

impl MockSpamScorer {
    pub fn new() -> Self {
        Self {
            result: Arc::new(Mutex::new(SpamScore {
                score: 0.0,
                action: SpamAction::Accept,
                rules: vec![],
            })),
        }
    }

    /// Set the score that will be returned on the next `score()` call.
    pub fn set_score(&self, score: f64, action: SpamAction) {
        let mut r = self.result.lock().unwrap();
        r.score = score;
        r.action = action;
    }

    /// Set the full result that will be returned on the next `score()` call.
    pub fn set_result(&self, result: SpamScore) {
        *self.result.lock().unwrap() = result;
    }
}

impl Default for MockSpamScorer {
    fn default() -> Self {
        Self::new()
    }
}

impl SpamScorer for MockSpamScorer {
    async fn score(
        &self,
        _raw_message: &[u8],
        _envelope_from: &str,
        _envelope_to: &[String],
        _peer_ip: IpAddr,
    ) -> Result<SpamScore, SentioError> {
        Ok(self.result.lock().unwrap().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use sentio_core::traits::SpamRule;

    #[tokio::test]
    async fn mock_returns_default_accept() {
        let mock = MockSpamScorer::new();
        let result = mock
            .score(
                b"test",
                "from@example.com",
                &["to@example.com".into()],
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            )
            .await
            .unwrap();
        assert_eq!(result.action, SpamAction::Accept);
        assert_eq!(result.score, 0.0);
    }

    #[tokio::test]
    async fn mock_set_score() {
        let mock = MockSpamScorer::new();
        mock.set_score(15.0, SpamAction::Reject);
        let result = mock
            .score(
                b"test",
                "from@example.com",
                &["to@example.com".into()],
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            )
            .await
            .unwrap();
        assert_eq!(result.action, SpamAction::Reject);
        assert_eq!(result.score, 15.0);
    }

    #[tokio::test]
    async fn mock_set_result() {
        let mock = MockSpamScorer::new();
        mock.set_result(SpamScore {
            score: 5.0,
            action: SpamAction::Greylist,
            rules: vec![SpamRule {
                name: "TEST_RULE".into(),
                score: 5.0,
                description: "test rule".into(),
            }],
        });
        let result = mock
            .score(
                b"test",
                "from@example.com",
                &["to@example.com".into()],
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            )
            .await
            .unwrap();
        assert_eq!(result.action, SpamAction::Greylist);
        assert_eq!(result.rules.len(), 1);
        assert_eq!(result.rules[0].name, "TEST_RULE");
    }
}
