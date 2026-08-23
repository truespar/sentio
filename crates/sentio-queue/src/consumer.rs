//! Generic JetStream pull consumer.
//!
//! The consumer creates (idempotently) a durable pull consumer on a stream,
//! then runs a message loop that dispatches every incoming message to a
//! user-provided [`MessageHandler`]. The handler returns a [`HandlerResult`]
//! and the loop turns it into the appropriate JetStream ack:
//!
//! * `Ack`    → `message.ack()`
//! * `Retry`  → `message.ack_with(AckKind::Nak(Some(delay)))` if `info.delivered`
//!   is below the retry cap; otherwise the message is published to
//!   `sentio.dead.{original_subject}` and acked.
//! * `Reject` → publish to `sentio.dead.{original_subject}` and ack the original.
//!
//! Attempt count: derived from `msg.info()?.delivered` - JetStream-tracked.
//! We do not maintain our own `Sentio-Attempt` header because Nak retries the
//! *same* message (not a republish), so the header would be frozen at its
//! original value.

use std::time::Duration;

use async_nats::jetstream::consumer::{pull, AckPolicy, PullConsumer};
use async_nats::jetstream::message::AckKind;
use async_nats::HeaderMap;
use bytes::Bytes;
use futures::StreamExt;
use sentio_core::error::SentioError;

use crate::error::QueueError;
use crate::manager::QueueManager;
use crate::retry::RetryPolicy;
use crate::topology::{
    HEADER_ATTEMPT, HEADER_DEAD_REASON, HEADER_FIRST_QUEUED_AT, HEADER_MESSAGE_ID,
    HEADER_ORIGINAL_SUBJECT, HEADER_TENANT_ID, SUBJECT_DEAD_PREFIX,
};

const DEFAULT_ACK_WAIT_SECS: u64 = 60;

/// Parsed message delivered to the handler.
pub struct QueueMessage {
    pub body: Vec<u8>,
    pub headers: MessageHeaders,
}

/// Headers extracted from an incoming delivery.
#[derive(Debug, Clone, Default)]
pub struct MessageHeaders {
    pub message_id: Option<String>,
    pub tenant_id: Option<String>,
    /// Number of delivery attempts so far (1 = first delivery, 2 = first retry…).
    /// Sourced from `msg.info()?.delivered`.
    pub retry_count: u32,
    /// Old field name - populated from the `Sentio-Original-Subject` header
    /// when present. For consumers, this is informational.
    pub original_exchange: Option<String>,
    /// Original NATS subject (also populated from `Sentio-Original-Subject` /
    /// the message's own subject as fallback).
    pub original_routing_key: Option<String>,
    /// Unix timestamp (millis) when the message was first queued.
    pub first_queued_at: Option<u64>,
}

impl MessageHeaders {
    fn from_nats(nats_headers: Option<&HeaderMap>, subject: &str, delivered: u32) -> Self {
        let mut out = Self {
            retry_count: delivered.saturating_sub(1),
            original_routing_key: Some(subject.to_string()),
            ..Self::default()
        };

        if let Some(hm) = nats_headers {
            if let Some(v) = hm.get(HEADER_MESSAGE_ID) {
                out.message_id = Some(v.as_str().to_string());
            }
            if let Some(v) = hm.get(HEADER_TENANT_ID) {
                out.tenant_id = Some(v.as_str().to_string());
            }
            if let Some(v) = hm.get(HEADER_ATTEMPT) {
                if let Ok(n) = v.as_str().parse::<u32>() {
                    // Prefer the explicit header if present (legacy publishers).
                    out.retry_count = n;
                }
            }
            if let Some(v) = hm.get(HEADER_ORIGINAL_SUBJECT) {
                out.original_routing_key = Some(v.as_str().to_string());
            }
            if let Some(v) = hm.get(HEADER_FIRST_QUEUED_AT) {
                if let Ok(n) = v.as_str().parse::<u64>() {
                    out.first_queued_at = Some(n);
                }
            }
        }

        out
    }
}

/// Outcome of handling a single message.
pub enum HandlerResult {
    /// Message processed successfully.
    Ack,
    /// Transient failure - schedule a retry using the consumer's default
    /// `RetryPolicy::compute_delay_ms(delivered - 1)` backoff curve.
    Retry,
    /// Transient failure with a caller-supplied delay (e.g. per-domain
    /// backoff). The consumer Naks the message with this exact delay,
    /// overriding its internal policy curve.
    RetryAfter(Duration),
    /// Permanent failure - send to dead-letter stream.
    Reject,
}

/// Trait implemented by queue consumers to handle messages.
pub trait MessageHandler: Send + Sync + 'static {
    fn handle(
        &self,
        message: QueueMessage,
    ) -> impl std::future::Future<Output = HandlerResult> + Send;
}

/// Generic pull-consumer wrapper.
pub struct Consumer {
    js: async_nats::jetstream::Context,
    pull_consumer: PullConsumer,
    retry_policy: RetryPolicy,
}

impl Consumer {
    /// Create (or fetch) a durable pull consumer on `stream` filtered by
    /// `filter_subject`. The consumer is created with explicit acks,
    /// `max_ack_pending = prefetch`, and a 60s ack-wait window.
    pub async fn create(
        mgr: &QueueManager,
        stream: &str,
        durable: &str,
        filter_subject: &str,
        prefetch: u16,
    ) -> Result<Self, QueueError> {
        let js = mgr.jetstream().clone();
        let stream_handle = js.get_or_create_stream(stream).await?;

        let cfg = pull::Config {
            durable_name: Some(durable.to_string()),
            name: Some(durable.to_string()),
            description: Some(format!("Sentio consumer: {durable}")),
            filter_subject: filter_subject.to_string(),
            ack_policy: AckPolicy::Explicit,
            ack_wait: Duration::from_secs(DEFAULT_ACK_WAIT_SECS),
            max_ack_pending: prefetch.max(1) as i64,
            ..Default::default()
        };

        let pull_consumer = stream_handle.get_or_create_consumer(durable, cfg).await?;
        let retry_policy = mgr.default_retry_policy();

        Ok(Self {
            js,
            pull_consumer,
            retry_policy,
        })
    }

    /// Override the default retry policy (used for Nak-with-delay timing).
    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = policy;
        self
    }

    /// Run the message loop. Returns a `JoinHandle` so the caller can keep
    /// the consumer running in the background and shut it down on demand.
    pub async fn run<H: MessageHandler>(
        self,
        handler: H,
    ) -> Result<tokio::task::JoinHandle<()>, QueueError> {
        let mut messages = self.pull_consumer.messages().await?;
        let js = self.js.clone();
        let retry_policy = self.retry_policy.clone();

        let handle = tokio::spawn(async move {
            while let Some(msg_result) = messages.next().await {
                let msg = match msg_result {
                    Ok(m) => m,
                    Err(err) => {
                        tracing::error!(%err, "jetstream message stream error");
                        continue;
                    }
                };

                // Pull delivery metadata before we move the message into the
                // handler.
                let delivered_count = msg.info().ok().map(|i| i.delivered as u32).unwrap_or(1);

                let subject = msg.subject.to_string();
                let headers_obj =
                    MessageHeaders::from_nats(msg.headers.as_ref(), &subject, delivered_count);
                let original_subject = headers_obj
                    .original_routing_key
                    .clone()
                    .unwrap_or_else(|| subject.clone());

                // Preserve raw NATS headers so we can forward them to the
                // dead-letter stream untouched.
                let raw_headers = msg.headers.clone();

                let queue_msg = QueueMessage {
                    body: msg.payload.to_vec(),
                    headers: headers_obj,
                };

                let result = handler.handle(queue_msg).await;

                match result {
                    HandlerResult::Ack => {
                        if let Err(err) = msg.ack().await {
                            tracing::error!(%err, "ack failed");
                        }
                    }
                    HandlerResult::Retry | HandlerResult::RetryAfter(_) => {
                        // `delivered_count` is the number of times this
                        // message has been delivered to this consumer
                        // (including the current attempt).
                        if (delivered_count as u32) < retry_policy.max_retries {
                            let delay = match &result {
                                HandlerResult::RetryAfter(d) => *d,
                                _ => Duration::from_millis(
                                    retry_policy
                                        .compute_delay_ms(delivered_count.saturating_sub(1)),
                                ),
                            };
                            if let Err(err) = msg.ack_with(AckKind::Nak(Some(delay))).await {
                                tracing::error!(%err, "nak-with-delay failed");
                            }
                        } else {
                            tracing::warn!(
                                attempt = delivered_count,
                                max = retry_policy.max_retries,
                                "max retries exceeded - moving to dead-letter stream"
                            );
                            if let Err(err) = publish_to_dead(
                                &js,
                                &original_subject,
                                &msg.payload,
                                raw_headers.as_ref(),
                                "max_retries_exceeded",
                            )
                            .await
                            {
                                tracing::error!(%err, "publish to dead stream failed");
                            }
                            if let Err(err) = msg.ack().await {
                                tracing::error!(%err, "ack after dead-letter failed");
                            }
                        }
                    }
                    HandlerResult::Reject => {
                        if let Err(err) = publish_to_dead(
                            &js,
                            &original_subject,
                            &msg.payload,
                            raw_headers.as_ref(),
                            "rejected_by_handler",
                        )
                        .await
                        {
                            tracing::error!(%err, "publish to dead stream failed");
                        }
                        if let Err(err) = msg.ack().await {
                            tracing::error!(%err, "ack after reject failed");
                        }
                    }
                }
            }

            tracing::info!("consumer loop ended");
        });

        Ok(handle)
    }

    /// Alias for `run()` matching the old lapin-era API (`consume(queue_name,
    /// consumer_tag, handler)`). The `_queue_name` and `_consumer_tag` arguments
    /// are accepted for source compatibility and ignored - the stream/durable
    /// were already fixed in `create()`.
    pub async fn consume<H: MessageHandler>(
        self,
        _queue_name: &str,
        _consumer_tag: &str,
        handler: H,
    ) -> Result<tokio::task::JoinHandle<()>, SentioError> {
        self.run(handler)
            .await
            .map_err(|e| SentioError::Queue(e.to_string()))
    }
}

async fn publish_to_dead(
    js: &async_nats::jetstream::Context,
    original_subject: &str,
    payload: &Bytes,
    original_headers: Option<&HeaderMap>,
    reason: &str,
) -> Result<(), QueueError> {
    let subject = format!("{SUBJECT_DEAD_PREFIX}{original_subject}");

    let mut headers = original_headers.cloned().unwrap_or_else(HeaderMap::new);
    headers.insert(HEADER_ORIGINAL_SUBJECT, original_subject);
    headers.insert(HEADER_DEAD_REASON, reason);

    js.publish_with_headers(subject, headers, payload.clone())
        .await?
        .await?;
    Ok(())
}
