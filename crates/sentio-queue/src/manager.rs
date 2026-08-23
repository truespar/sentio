//! Facade owning the NATS client and JetStream context.

use std::time::Duration;

use async_nats::jetstream::Context as JsContext;
use async_nats::ConnectOptions;
use sentio_core::config::NatsConfig;

use crate::consumer::Consumer;
use crate::error::QueueError;
use crate::producer::Publisher;
use crate::retry::RetryPolicy;
use crate::topology::Topology;

/// Owns the NATS client + JetStream context and produces publishers/consumers.
#[derive(Clone)]
pub struct QueueManager {
    client: async_nats::Client,
    js: JsContext,
    config: NatsConfig,
}

impl QueueManager {
    /// Connect to NATS and declare the JetStream topology.
    pub async fn connect(cfg: &NatsConfig) -> Result<Self, QueueError> {
        let client = ConnectOptions::new()
            .name("sentio")
            .connection_timeout(Duration::from_secs(cfg.connection_timeout_secs))
            .connect(&cfg.url)
            .await?;

        tracing::info!(url = %cfg.url, "connected to NATS");

        let js = async_nats::jetstream::new(client.clone());
        Topology::declare_all(&js, cfg).await?;

        Ok(Self {
            client,
            js,
            config: cfg.clone(),
        })
    }

    pub fn client(&self) -> &async_nats::Client {
        &self.client
    }

    pub fn jetstream(&self) -> &JsContext {
        &self.js
    }

    pub fn config(&self) -> &NatsConfig {
        &self.config
    }

    /// Returns a connection status hint. NATS clients reconnect transparently,
    /// so this is currently always `true` once `connect` has returned.
    pub fn is_connected(&self) -> bool {
        true
    }

    /// Create a new `Publisher` backed by the shared JetStream context.
    pub async fn publisher(&self) -> Result<Publisher, QueueError> {
        Ok(Publisher::new(self.js.clone()))
    }

    /// Create a generic Consumer bound to the given stream/durable name.
    ///
    /// The returned [`Consumer`] is not yet running - call `run(handler)` on it
    /// to start the message loop.
    pub async fn consumer_on(
        &self,
        stream: &str,
        durable: &str,
        filter_subject: &str,
        prefetch: u16,
    ) -> Result<Consumer, QueueError> {
        Consumer::create(self, stream, durable, filter_subject, prefetch).await
    }

    /// Default retry policy used by the consumer message loop when no
    /// per-call policy is supplied. Pulled from `NatsConfig::max_retries`.
    pub fn default_retry_policy(&self) -> RetryPolicy {
        RetryPolicy {
            max_retries: self.config.max_retries,
            ..RetryPolicy::default()
        }
    }
}
