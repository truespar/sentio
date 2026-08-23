//! Listmonk bounce bridge - forwards Sentio bounce events to Listmonk's
//! `/webhooks/bounce` endpoint so Listmonk can apply its subscriber
//! threshold rules (auto-blocklist on hard bounce, etc.).
//!
//! ## Why this lives here
//!
//! It's a plumbing shim, not a tenant feature: a single static destination URL +
//! Basic-auth creds defined in the `[listmonk]` config section. Sentio's existing
//! `sentio-webhooks` crate is for *tenant-configured* HMAC-signed event
//! dispatch to customer URLs - a different shape. The bridge sits next
//! to `bounce_handler.rs` because it's part of the same theme: Sentio
//! receives a bounce, Sentio fans the news out.
//!
//! ## Filtering
//!
//! For v1 we forward ALL bounce events to Listmonk. Listmonk's bounce
//! threshold rules only fire for emails it has subscribers for; bounces
//! for non-list traffic just create unattributed rows in Listmonk's
//! `bounces` table (or get silently dropped - depends on Listmonk's
//! handling). If pollution of Listmonk's bounce stats becomes a problem
//! we can:
//!   * tag list-traffic messages at SMTP submission time (e.g. via a
//!     dedicated SASL auth user like `listmonk@example.com`) and skip
//!     events for messages without the tag, OR
//!   * filter on sender domain.
//!
//! ## Retry semantics
//!
//! We map HTTP outcomes onto JetStream's [`HandlerResult`]:
//!   * 2xx                              → Ack (success)
//!   * 4xx                              → Ack (permanent - Listmonk says
//!     "I won't accept this", retrying won't help; logged but not Nak'd)
//!   * 5xx / network / timeout          → RetryAfter (Nak with backoff)
//!
//! The JetStream consumer's default retry policy controls the backoff
//! curve, capped by `nats.max_retries` after which the message goes to
//! the dead-letter stream and stops costing us delivery attempts.

use std::time::Duration;

use reqwest::StatusCode;
use serde::Deserialize;
use tracing::{debug, info, warn};

use sentio_core::config::ListmonkConfig;
use sentio_queue::consumer::{HandlerResult, MessageHandler, QueueMessage};

/// Listmonk bounce bridge consumer.
pub struct ListmonkBridge {
    config: ListmonkConfig,
    client: reqwest::Client,
}

impl ListmonkBridge {
    pub fn new(config: ListmonkConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { config, client }
    }
}

/// Shape of the Sentio bounce event published on
/// `sentio.events.event.bounce`. Mirrors the JSON emitted by both the
/// VERP handler in `pipeline.rs` and the outbound delivery engine in
/// `sentio-smtp-client::delivery::record_event`.
#[derive(Debug, Deserialize)]
struct SentioBounceEvent {
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    message_id: Option<String>,
    #[serde(default)]
    payload: BouncePayload,
}

#[derive(Debug, Default, Deserialize)]
struct BouncePayload {
    /// e.g. "verp_dsn" or "outbound_delivery"
    #[serde(default)]
    source: Option<String>,
    /// Sentio's BounceClass - "hard" | "soft" | "block".
    #[serde(default)]
    bounce_class: Option<String>,
    #[serde(default)]
    smtp_code: Option<String>,
    #[serde(default)]
    enhanced_status: Option<String>,
    #[serde(default)]
    diagnostic: Option<String>,
    /// The recipient whose mailbox bounced. Used as the `email` field
    /// in the Listmonk payload - Listmonk matches against its
    /// subscribers table.
    #[serde(default)]
    failed_recipient: Option<String>,
}

/// Map Sentio's BounceClass strings onto Listmonk's two-value enum.
/// Listmonk only accepts "hard" or "soft"; we collapse Sentio's "block"
/// onto "hard" since the user-visible action (auto-blocklist) is the
/// same as for an explicit hard bounce.
fn classify(sentio_class: Option<&str>) -> &'static str {
    match sentio_class.map(str::to_ascii_lowercase).as_deref() {
        Some("hard") | Some("block") => "hard",
        _ => "soft",
    }
}

impl MessageHandler for ListmonkBridge {
    async fn handle(&self, message: QueueMessage) -> HandlerResult {
        // 1. Decode the bounce event.
        let event: SentioBounceEvent = match serde_json::from_slice(&message.body) {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "listmonk bridge: failed to decode bounce event");
                // Malformed payload - retrying won't help.
                return HandlerResult::Ack;
            }
        };

        let Some(email) = event
            .payload
            .failed_recipient
            .as_deref()
            .filter(|s| !s.is_empty())
        else {
            debug!(
                message_id = ?event.message_id,
                "listmonk bridge: bounce event without failed_recipient, skipping"
            );
            return HandlerResult::Ack;
        };

        let bounce_type = classify(event.payload.bounce_class.as_deref());

        // 2. Build the Listmonk meta object - embedded as an escaped
        //    JSON string per Listmonk's webhook API spec.
        let meta = serde_json::json!({
            "sentio_message_id": event.message_id,
            "sentio_tenant_id":  event.tenant_id,
            "sentio_source":     event.payload.source,
            "smtp_code":         event.payload.smtp_code,
            "enhanced_status":   event.payload.enhanced_status,
            "diagnostic":        event.payload.diagnostic,
        });
        let meta_str = meta.to_string();

        let payload = serde_json::json!({
            "email":  email,
            "source": "sentio",
            "type":   bounce_type,
            "meta":   meta_str,
        });

        // 3. POST with Basic auth.
        let resp = self
            .client
            .post(&self.config.url)
            .basic_auth(&self.config.username, Some(&self.config.password))
            .json(&payload)
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    info!(
                        email,
                        bounce_type,
                        message_id = ?event.message_id,
                        "listmonk bridge: bounce forwarded"
                    );
                    HandlerResult::Ack
                } else if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                    // Misconfiguration - keep yelling about it, but
                    // don't pile up Nak'd messages. Ack so the consumer
                    // drains, then the operator fixes the config.
                    let body = r.text().await.unwrap_or_default();
                    warn!(
                        status = %status,
                        body = %body.chars().take(200).collect::<String>(),
                        "listmonk bridge: auth failed - check [listmonk] username/password"
                    );
                    HandlerResult::Ack
                } else if status.is_client_error() {
                    let body = r.text().await.unwrap_or_default();
                    warn!(
                        email,
                        status = %status,
                        body = %body.chars().take(200).collect::<String>(),
                        "listmonk bridge: 4xx response, treating as permanent"
                    );
                    HandlerResult::Ack
                } else {
                    let body = r.text().await.unwrap_or_default();
                    warn!(
                        email,
                        status = %status,
                        body = %body.chars().take(200).collect::<String>(),
                        "listmonk bridge: 5xx response, will retry"
                    );
                    HandlerResult::RetryAfter(Duration::from_secs(60))
                }
            }
            Err(e) => {
                warn!(error = %e, email, "listmonk bridge: network error, will retry");
                HandlerResult::RetryAfter(Duration::from_secs(60))
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_maps_block_to_hard() {
        assert_eq!(classify(Some("hard")), "hard");
        assert_eq!(classify(Some("Hard")), "hard");
        assert_eq!(classify(Some("block")), "hard");
        assert_eq!(classify(Some("BLOCK")), "hard");
    }

    #[test]
    fn classify_defaults_to_soft() {
        assert_eq!(classify(Some("soft")), "soft");
        assert_eq!(classify(Some("unknown")), "soft");
        assert_eq!(classify(None), "soft");
    }

    #[test]
    fn decode_matches_pipeline_emitted_envelope() {
        // The exact shape emitted by pipeline.rs:514 - if the producer
        // changes, this test catches it.
        let raw = serde_json::json!({
            "tenant_id":  "1c260631-5357-438e-a1e0-bd8e78829752",
            "event_type": "bounced",
            "message_id": "019eadeb-ba9a-7fa1-b43c-c6d708ddc529",
            "payload": {
                "source":           "verp_dsn",
                "bounce_class":     "hard",
                "smtp_code":        "550",
                "enhanced_status":  "5.1.1",
                "diagnostic":       "User unknown",
                "failed_recipient": "missing@example.com",
            },
            "occurred_at": "2026-06-13T10:00:00Z",
        });
        let body = serde_json::to_vec(&raw).unwrap();
        let event: SentioBounceEvent = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            event.tenant_id.as_deref(),
            Some("1c260631-5357-438e-a1e0-bd8e78829752")
        );
        assert_eq!(
            event.payload.failed_recipient.as_deref(),
            Some("missing@example.com")
        );
        assert_eq!(classify(event.payload.bounce_class.as_deref()), "hard");
    }
}
