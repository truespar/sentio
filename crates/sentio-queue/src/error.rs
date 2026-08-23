//! Error type returned by the NATS / JetStream queue layer.
//!
//! All `async-nats` error variants are wrapped into a small, opaque
//! `QueueError` so that calling crates only need to handle one type. We
//! also provide a `From<QueueError> for SentioError` conversion so existing
//! call sites that expect `SentioError::Queue` keep working.

use sentio_core::error::SentioError;

#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("nats connect: {0}")]
    Connect(String),
    #[error("jetstream publish: {0}")]
    Publish(String),
    #[error("jetstream stream: {0}")]
    Stream(String),
    #[error("jetstream consumer: {0}")]
    Consumer(String),
    #[error("ack: {0}")]
    Ack(String),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("other: {0}")]
    Other(String),
}

impl From<QueueError> for SentioError {
    fn from(err: QueueError) -> Self {
        SentioError::Queue(err.to_string())
    }
}

// ── async-nats connection / client errors ───────────────────────────────────

impl From<async_nats::ConnectError> for QueueError {
    fn from(err: async_nats::ConnectError) -> Self {
        QueueError::Connect(err.to_string())
    }
}

// ── JetStream publish ──────────────────────────────────────────────────────

impl From<async_nats::jetstream::context::PublishError> for QueueError {
    fn from(err: async_nats::jetstream::context::PublishError) -> Self {
        QueueError::Publish(err.to_string())
    }
}

// ── JetStream stream / consumer creation ────────────────────────────────────

impl From<async_nats::jetstream::context::CreateStreamError> for QueueError {
    fn from(err: async_nats::jetstream::context::CreateStreamError) -> Self {
        QueueError::Stream(err.to_string())
    }
}

impl From<async_nats::jetstream::stream::ConsumerError> for QueueError {
    fn from(err: async_nats::jetstream::stream::ConsumerError) -> Self {
        QueueError::Consumer(err.to_string())
    }
}

impl From<async_nats::jetstream::consumer::StreamError> for QueueError {
    fn from(err: async_nats::jetstream::consumer::StreamError) -> Self {
        QueueError::Consumer(err.to_string())
    }
}

// ── Catch-all (boxed async_nats::Error) ─────────────────────────────────────

impl From<async_nats::Error> for QueueError {
    fn from(err: async_nats::Error) -> Self {
        QueueError::Other(err.to_string())
    }
}
