pub mod aggregator;
pub mod builtin;
pub mod rspamd;

#[cfg(any(test, feature = "test-support"))]
pub mod mock;

use std::net::IpAddr;

use sentio_abuse::{DnsLookup, KvConn};
use sentio_core::error::SentioError;
use sentio_core::traits::{SpamAction, SpamScore, SpamScorer, SpamTrainer};

pub use builtin::BuiltinScorer;
pub use rspamd::RspamdScorer;

/// Enum-based dispatch for spam scoring backends.
///
/// Uses enum dispatch instead of `dyn SpamScorer` because the `SpamScorer`
/// trait uses RPITIT (return-position `impl Trait` in traits), making it
/// non-object-safe.
pub enum SpamBackend<R: KvConn, D: DnsLookup + Clone> {
    Rspamd(RspamdScorer),
    Builtin(BuiltinScorer<R, D>),
    Noop(NoopSpamScorer),
}

impl<R: KvConn, D: DnsLookup + Clone> SpamScorer for SpamBackend<R, D> {
    async fn score(
        &self,
        raw_message: &[u8],
        envelope_from: &str,
        envelope_to: &[String],
        peer_ip: IpAddr,
    ) -> Result<SpamScore, SentioError> {
        match self {
            Self::Rspamd(s) => {
                s.score(raw_message, envelope_from, envelope_to, peer_ip)
                    .await
            }
            Self::Builtin(s) => {
                s.score(raw_message, envelope_from, envelope_to, peer_ip)
                    .await
            }
            Self::Noop(s) => {
                s.score(raw_message, envelope_from, envelope_to, peer_ip)
                    .await
            }
        }
    }
}

impl<R: KvConn, D: DnsLookup + Clone> SpamTrainer for SpamBackend<R, D> {
    async fn learn_spam(&self, raw_message: &[u8]) -> Result<(), SentioError> {
        match self {
            Self::Rspamd(s) => s.learn_spam(raw_message).await,
            Self::Builtin(_) | Self::Noop(_) => Ok(()),
        }
    }

    async fn learn_ham(&self, raw_message: &[u8]) -> Result<(), SentioError> {
        match self {
            Self::Rspamd(s) => s.learn_ham(raw_message).await,
            Self::Builtin(_) | Self::Noop(_) => Ok(()),
        }
    }
}

impl SpamTrainer for NoopSpamScorer {
    async fn learn_spam(&self, _raw_message: &[u8]) -> Result<(), SentioError> {
        Ok(())
    }

    async fn learn_ham(&self, _raw_message: &[u8]) -> Result<(), SentioError> {
        Ok(())
    }
}

/// No-op spam scorer that always returns score 0 / Accept.
#[derive(Debug, Clone)]
pub struct NoopSpamScorer;

impl SpamScorer for NoopSpamScorer {
    async fn score(
        &self,
        _raw_message: &[u8],
        _envelope_from: &str,
        _envelope_to: &[String],
        _peer_ip: IpAddr,
    ) -> Result<SpamScore, SentioError> {
        Ok(SpamScore {
            score: 0.0,
            action: SpamAction::Accept,
            rules: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn noop_scorer_returns_accept() {
        let scorer = NoopSpamScorer;
        let result = scorer
            .score(
                b"test message",
                "sender@example.com",
                &["rcpt@example.com".into()],
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            )
            .await
            .unwrap();
        assert_eq!(result.score, 0.0);
        assert_eq!(result.action, SpamAction::Accept);
        assert!(result.rules.is_empty());
    }

    #[tokio::test]
    async fn spam_backend_noop_variant() {
        use sentio_abuse::mock::MockRedis;

        #[derive(Clone)]
        struct MockDns;
        impl sentio_abuse::DnsLookup for MockDns {
            fn lookup_a<'a>(
                &'a self,
                _name: &'a str,
            ) -> impl std::future::Future<Output = Result<bool, String>> + Send + 'a {
                std::future::ready(Ok(false))
            }

            fn reverse_lookup<'a>(
                &'a self,
                _ip: &'a std::net::IpAddr,
            ) -> impl std::future::Future<Output = Result<bool, String>> + Send + 'a {
                std::future::ready(Ok(true))
            }
        }

        let backend: SpamBackend<MockRedis, MockDns> = SpamBackend::Noop(NoopSpamScorer);
        let result = backend
            .score(
                b"test",
                "from@example.com",
                &["to@example.com".into()],
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            )
            .await
            .unwrap();
        assert_eq!(result.action, SpamAction::Accept);
    }
}
