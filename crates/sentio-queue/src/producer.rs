//! JetStream publisher.
//!
//! The public `QueuePublisher` trait keeps the legacy `(exchange, routing_key,
//! payload, headers)` signature so that calling crates (sentio-api,
//! sentio-smtp-server, sentio-smtp-client) compile without changes. Internally
//! the implementation maps the old (exchange, routing_key) tuple onto a NATS
//! subject:
//!
//! * `("sentio.submit", "message.outbound.send")` → `sentio.submit.message.outbound.send`
//! * `("sentio.events", "event.delivery")`        → `sentio.events.event.delivery`
//! * `("sentio.dlx", "")`                         → `sentio.dead.{original_subject|unknown}`
//! * `("", "sentio.retry.wait")`                  → republished to `original_subject`
//!   from the headers (delay dropped - Nak-with-delay handles retry timing now).

use async_nats::jetstream::Context as JsContext;
use async_nats::HeaderMap;
use bytes::Bytes;
use sentio_core::error::SentioError;
use serde::Serialize;

use crate::error::QueueError;
use crate::topology::{
    EXCHANGE_DLX, EXCHANGE_EVENTS, EXCHANGE_SUBMIT, HEADER_ATTEMPT, HEADER_DEAD_REASON,
    HEADER_FIRST_QUEUED_AT, HEADER_MESSAGE_ID, HEADER_TENANT_ID, QUEUE_RETRY_WAIT,
    SUBJECT_DEAD_PREFIX, SUBJECT_EVENTS_PREFIX, SUBJECT_SUBMIT_PREFIX,
};

/// Headers attached to every published message.
#[derive(Debug, Clone, Default)]
pub struct PublishHeaders {
    pub message_id: Option<String>,
    pub tenant_id: Option<String>,
    pub retry_count: Option<u32>,
    /// Old field name - semantically "the subject this message originally
    /// targeted before being moved to a retry/dead-letter stream". With NATS
    /// there is no exchange, so `original_exchange` is informational only.
    pub original_exchange: Option<String>,
    /// In the NATS implementation this is treated as the *full* original
    /// subject when present. For legacy call sites that still pass a routing
    /// key fragment it is concatenated with `original_exchange`.
    pub original_routing_key: Option<String>,
    pub content_type: Option<String>,
    /// Per-message TTL in milliseconds. The NATS publisher ignores this
    /// field - retry delays are driven by `AckKind::Nak`.
    pub expiration: Option<String>,
    /// Unix timestamp (millis) when the message was first queued.
    pub first_queued_at: Option<u64>,
    /// Optional dead-letter reason - set when publishing to the dead stream.
    pub dead_reason: Option<String>,
}

impl PublishHeaders {
    fn into_nats(self) -> HeaderMap {
        let mut hm = HeaderMap::new();
        if let Some(v) = self.message_id {
            hm.insert(HEADER_MESSAGE_ID, v.as_str());
        }
        if let Some(v) = self.tenant_id {
            hm.insert(HEADER_TENANT_ID, v.as_str());
        }
        if let Some(v) = self.retry_count {
            hm.insert(HEADER_ATTEMPT, v.to_string().as_str());
        }
        if let Some(v) = self.first_queued_at {
            hm.insert(HEADER_FIRST_QUEUED_AT, v.to_string().as_str());
        }
        if let Some(v) = self.dead_reason {
            hm.insert(HEADER_DEAD_REASON, v.as_str());
        }
        // `original_subject`/`original_exchange`/`original_routing_key` are
        // not normally re-set on a republish - the consumer loop fills them
        // when sending to `sentio.dead.*`. We still propagate `original_subject`
        // if it was supplied explicitly (compatibility with code that sets
        // `original_exchange` + `original_routing_key`).
        // Nothing to do here for the legacy fields.
        hm
    }
}

/// Trait abstracting message publishing - kept identical to the lapin-era
/// version so existing callers compile unchanged.
pub trait QueuePublisher: Send + Sync {
    fn publish(
        &self,
        exchange: &str,
        routing_key: &str,
        payload: &[u8],
        headers: PublishHeaders,
    ) -> impl std::future::Future<Output = Result<(), SentioError>> + Send;
}

/// Map a legacy `(exchange, routing_key)` tuple to a NATS subject.
///
/// Returns `Some(subject)` for the standard cases. Returns `None` if the
/// publish call should be turned into a republish-to-original (legacy
/// `("", QUEUE_RETRY_WAIT)` flow) - the caller handles that path explicitly.
fn route_to_subject(exchange: &str, routing_key: &str, headers: &PublishHeaders) -> Option<String> {
    match exchange {
        EXCHANGE_SUBMIT => Some(format!("{SUBJECT_SUBMIT_PREFIX}{routing_key}")),
        EXCHANGE_EVENTS => Some(format!("{SUBJECT_EVENTS_PREFIX}{routing_key}")),
        EXCHANGE_DLX => {
            // Fanout dead-letter - derive a subject from the original.
            let orig = derive_original_subject(headers).unwrap_or_else(|| "unknown".to_string());
            Some(format!("{SUBJECT_DEAD_PREFIX}{orig}"))
        }
        "" if routing_key == QUEUE_RETRY_WAIT => {
            // Legacy retry-wait republish - handled by caller.
            None
        }
        "" => Some(routing_key.to_string()),
        _ => Some(format!("{exchange}.{routing_key}")),
    }
}

/// Best-effort reconstruction of the "original subject" from legacy header
/// fields. Returns `None` if nothing usable was supplied.
fn derive_original_subject(headers: &PublishHeaders) -> Option<String> {
    if let Some(rk) = &headers.original_routing_key {
        // If we also have an original_exchange that maps to a known prefix,
        // use the full mapped subject; otherwise return just the routing key
        // (already a full subject in newer callers).
        match headers.original_exchange.as_deref() {
            Some(EXCHANGE_SUBMIT) => Some(format!("{SUBJECT_SUBMIT_PREFIX}{rk}")),
            Some(EXCHANGE_EVENTS) => Some(format!("{SUBJECT_EVENTS_PREFIX}{rk}")),
            _ if rk.contains('.') => Some(rk.clone()),
            _ => Some(rk.clone()),
        }
    } else {
        None
    }
}

/// Real NATS / JetStream publisher.
#[derive(Clone)]
pub struct Publisher {
    js: JsContext,
}

impl Publisher {
    pub fn new(js: JsContext) -> Self {
        Self { js }
    }

    /// Publish a JSON-serialisable value to an explicit NATS subject.
    /// Returns the JetStream sequence number assigned to the message.
    pub async fn publish_json<T, S>(&self, subject: S, payload: &T) -> Result<u64, QueueError>
    where
        T: Serialize,
        S: async_nats::subject::ToSubject,
    {
        let bytes = serde_json::to_vec(payload)?;
        let ack = self.js.publish(subject, Bytes::from(bytes)).await?.await?;
        Ok(ack.sequence)
    }

    /// Publish JSON with a pre-built `HeaderMap`.
    pub async fn publish_json_with_headers<T, S>(
        &self,
        subject: S,
        payload: &T,
        headers: HeaderMap,
    ) -> Result<u64, QueueError>
    where
        T: Serialize,
        S: async_nats::subject::ToSubject,
    {
        let bytes = serde_json::to_vec(payload)?;
        let ack = self
            .js
            .publish_with_headers(subject, headers, Bytes::from(bytes))
            .await?
            .await?;
        Ok(ack.sequence)
    }

    /// Publish raw bytes to an explicit NATS subject.
    pub async fn publish_raw<S: async_nats::subject::ToSubject>(
        &self,
        subject: S,
        payload: Bytes,
        headers: HeaderMap,
    ) -> Result<u64, QueueError> {
        let ack = self
            .js
            .publish_with_headers(subject, headers, payload)
            .await?
            .await?;
        Ok(ack.sequence)
    }

    /// Convenience: publish into the `sentio-submit` stream.
    pub async fn publish_submit<T: Serialize>(
        &self,
        routing_key: &str,
        payload: &T,
        headers: PublishHeaders,
    ) -> Result<(), SentioError> {
        let body = serde_json::to_vec(payload)
            .map_err(|e| SentioError::Queue(format!("serialize: {e}")))?;
        self.publish(EXCHANGE_SUBMIT, routing_key, &body, headers)
            .await
    }

    /// Convenience: publish into the `sentio-events` stream.
    pub async fn publish_event<T: Serialize>(
        &self,
        routing_key: &str,
        payload: &T,
        headers: PublishHeaders,
    ) -> Result<(), SentioError> {
        let body = serde_json::to_vec(payload)
            .map_err(|e| SentioError::Queue(format!("serialize: {e}")))?;
        self.publish(EXCHANGE_EVENTS, routing_key, &body, headers)
            .await
    }
}

impl QueuePublisher for Publisher {
    async fn publish(
        &self,
        exchange: &str,
        routing_key: &str,
        payload: &[u8],
        headers: PublishHeaders,
    ) -> Result<(), SentioError> {
        // Legacy retry-wait path: republish straight back to original subject.
        // The original `expiration` header is silently dropped - Nak-with-delay
        // is the new retry mechanism (see migration notes in topology.rs).
        if exchange.is_empty() && routing_key == QUEUE_RETRY_WAIT {
            let orig_subject = derive_original_subject(&headers).ok_or_else(|| {
                SentioError::Queue(
                    "legacy retry-wait publish missing original_routing_key header".into(),
                )
            })?;
            let nats_headers = headers.into_nats();
            self.js
                .publish_with_headers(orig_subject, nats_headers, Bytes::copy_from_slice(payload))
                .await
                .map_err(|e| SentioError::Queue(format!("nats publish: {e}")))?
                .await
                .map_err(|e| SentioError::Queue(format!("nats publish ack: {e}")))?;
            return Ok(());
        }

        let subject = route_to_subject(exchange, routing_key, &headers).ok_or_else(|| {
            SentioError::Queue(format!(
                "no NATS subject mapping for ({exchange:?}, {routing_key:?})"
            ))
        })?;

        let nats_headers = headers.into_nats();
        self.js
            .publish_with_headers(subject, nats_headers, Bytes::copy_from_slice(payload))
            .await
            .map_err(|e| SentioError::Queue(format!("nats publish: {e}")))?
            .await
            .map_err(|e| SentioError::Queue(format!("nats publish ack: {e}")))?;
        Ok(())
    }
}

#[doc(hidden)]
pub fn _route_subject_for_test(
    exchange: &str,
    routing_key: &str,
    headers: &PublishHeaders,
) -> Option<String> {
    route_to_subject(exchange, routing_key, headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_submit_exchange() {
        let s = route_to_subject(
            EXCHANGE_SUBMIT,
            "message.outbound.send",
            &Default::default(),
        );
        assert_eq!(s.as_deref(), Some("sentio.submit.message.outbound.send"));
    }

    #[test]
    fn maps_events_exchange() {
        let s = route_to_subject(EXCHANGE_EVENTS, "event.delivery", &Default::default());
        assert_eq!(s.as_deref(), Some("sentio.events.event.delivery"));
    }

    #[test]
    fn maps_dlx_with_original_subject_from_headers() {
        let headers = PublishHeaders {
            original_exchange: Some(EXCHANGE_SUBMIT.to_string()),
            original_routing_key: Some("message.outbound.send".to_string()),
            ..Default::default()
        };
        let s = route_to_subject(EXCHANGE_DLX, "", &headers);
        assert_eq!(
            s.as_deref(),
            Some("sentio.dead.sentio.submit.message.outbound.send")
        );
    }

    #[test]
    fn retry_wait_returns_none() {
        let s = route_to_subject("", QUEUE_RETRY_WAIT, &Default::default());
        assert!(s.is_none());
    }
}
