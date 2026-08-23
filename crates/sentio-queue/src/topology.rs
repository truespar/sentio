//! JetStream topology - streams and subject conventions.
//!
//! Three streams:
//!
//! | Stream          | Subjects                                      | Retention   |
//! |-----------------|-----------------------------------------------|-------------|
//! | sentio-submit   | sentio.submit.message.{outbound,inbound}.>    | WorkQueue   |
//! | sentio-events   | sentio.events.event.>                         | Limits      |
//! | sentio-dead     | sentio.dead.>                                 | Limits (30d)|
//!
//! Consumers live on top of these streams - see `Consumer::create`.

use std::time::Duration;

use async_nats::jetstream::stream::{
    Config as StreamConfig, DiscardPolicy, RetentionPolicy, StorageType,
};
use async_nats::jetstream::Context as JsContext;

use crate::error::QueueError;
use sentio_core::config::NatsConfig;

// ── Stream names ────────────────────────────────────────────────────────────

pub const STREAM_SUBMIT: &str = "sentio-submit";
pub const STREAM_EVENTS: &str = "sentio-events";
pub const STREAM_DEAD: &str = "sentio-dead";

// ── Subject prefixes ────────────────────────────────────────────────────────

pub const SUBJECT_SUBMIT_PREFIX: &str = "sentio.submit.";
pub const SUBJECT_EVENTS_PREFIX: &str = "sentio.events.";
pub const SUBJECT_DEAD_PREFIX: &str = "sentio.dead.";

// ── Submit subjects (full) ──────────────────────────────────────────────────

pub const SUBJECT_OUTBOUND_SEND: &str = "sentio.submit.message.outbound.send";
pub const SUBJECT_OUTBOUND_DELIVERY: &str = "sentio.submit.message.outbound.delivery";
pub const SUBJECT_INBOUND_RECEIVED: &str = "sentio.submit.message.inbound.received";

// ── Filter subjects used when creating consumers ───────────────────────────

pub const FILTER_OUTBOUND_ALL: &str = "sentio.submit.message.outbound.>";
pub const FILTER_INBOUND_ALL: &str = "sentio.submit.message.inbound.>";
pub const FILTER_EVENTS_ALL: &str = "sentio.events.event.>";

// ── Legacy aliases (deprecated - kept so external call sites compile) ──────
//
// Callers still publish via `Publisher::publish(exchange, routing_key, …)`
// with these `exchange` names. The publisher recognises them and
// translates the call into a NATS subject.

pub const EXCHANGE_SUBMIT: &str = "sentio.submit";
pub const EXCHANGE_EVENTS: &str = "sentio.events";
pub const EXCHANGE_DLX: &str = "sentio.dlx";

/// Legacy "wait queue" name. Code path: `publisher.publish("", QUEUE_RETRY_WAIT, …)`.
/// The NATS publisher recognises this and republishes back to the message's
/// `original_subject` header immediately (delay is dropped - see migration notes).
pub const QUEUE_RETRY_WAIT: &str = "sentio.retry.wait";
pub const QUEUE_RETRY_REQUEUE: &str = "sentio.retry.requeue";
pub const QUEUE_SUBMIT_DELIVERY: &str = "delivery";
pub const QUEUE_SUBMIT_INBOUND: &str = "inbound-routing";
pub const QUEUE_EVENTS_WEBHOOK: &str = "webhook";
pub const QUEUE_EVENTS_ANALYTICS: &str = "analytics";
pub const QUEUE_DEAD: &str = "sentio-dead";

// ── Header names (used by Publisher & Consumer) ────────────────────────────

pub const HEADER_TENANT_ID: &str = "Sentio-Tenant-Id";
pub const HEADER_MESSAGE_ID: &str = "Sentio-Message-Id";
pub const HEADER_ATTEMPT: &str = "Sentio-Attempt";
pub const HEADER_ORIGINAL_SUBJECT: &str = "Sentio-Original-Subject";
pub const HEADER_DEAD_REASON: &str = "Sentio-Dead-Reason";
pub const HEADER_FIRST_QUEUED_AT: &str = "Sentio-First-Queued-At";

// Legacy header names kept for source compatibility (no longer set by the
// NATS publisher).
pub const HEADER_ORIGINAL_EXCHANGE: &str = "x-original-exchange";
pub const HEADER_ORIGINAL_ROUTING_KEY: &str = "x-original-routing-key";
pub const HEADER_RETRY_COUNT: &str = "x-retry-count";

/// Declare the three JetStream streams idempotently.
pub struct Topology;

impl Topology {
    pub async fn declare_all(js: &JsContext, cfg: &NatsConfig) -> Result<(), QueueError> {
        let max_age = Duration::from_secs(cfg.stream_max_age_secs);
        let dead_max_age = Duration::from_secs(cfg.dead_stream_max_age_secs);

        // ── sentio-submit ──────────────────────────────────────────────
        js.get_or_create_stream(StreamConfig {
            name: STREAM_SUBMIT.to_string(),
            description: Some("Submitted SMTP messages awaiting delivery or routing".to_string()),
            subjects: vec![
                "sentio.submit.message.outbound.>".to_string(),
                "sentio.submit.message.inbound.>".to_string(),
            ],
            retention: RetentionPolicy::WorkQueue,
            storage: StorageType::File,
            max_age,
            discard: DiscardPolicy::Old,
            ..Default::default()
        })
        .await?;

        // ── sentio-events ──────────────────────────────────────────────
        js.get_or_create_stream(StreamConfig {
            name: STREAM_EVENTS.to_string(),
            description: Some(
                "Delivery / bounce / engagement events (webhook + analytics fan-out)".to_string(),
            ),
            subjects: vec!["sentio.events.event.>".to_string()],
            retention: RetentionPolicy::Limits,
            storage: StorageType::File,
            max_age,
            discard: DiscardPolicy::Old,
            ..Default::default()
        })
        .await?;

        // ── sentio-dead ────────────────────────────────────────────────
        js.get_or_create_stream(StreamConfig {
            name: STREAM_DEAD.to_string(),
            description: Some("Terminal dead-letter inspection (kept for 30d)".to_string()),
            subjects: vec!["sentio.dead.>".to_string()],
            retention: RetentionPolicy::Limits,
            storage: StorageType::File,
            max_age: dead_max_age,
            discard: DiscardPolicy::Old,
            ..Default::default()
        })
        .await?;

        tracing::info!(
            streams = 3,
            "JetStream topology declared (sentio-submit, sentio-events, sentio-dead)"
        );
        Ok(())
    }
}
