use sentio_core::message::MessageId;
use sentio_core::tenant::TenantId;
use sentio_queue::consumer::{HandlerResult, MessageHandler, QueueMessage};
use serde::Deserialize;
use tracing::{debug, error};
use uuid::Uuid;

// ──────────────────────────────────────────────────────────────────────────────
// Event payload - matches the JSON published by delivery.rs record_outcome
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct AnalyticsEvent {
    pub tenant_id: String,
    pub event_type: String,
    #[serde(default)]
    pub message_id: Option<String>,
    #[serde(default)]
    pub payload: serde_json::Value,
    #[serde(default)]
    pub occurred_at: Option<String>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Analytics event handler - consumes from QUEUE_EVENTS_ANALYTICS
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct AnalyticsEventHandler;

impl AnalyticsEventHandler {
    pub fn new() -> Self {
        Self
    }
}

impl MessageHandler for AnalyticsEventHandler {
    async fn handle(&self, message: QueueMessage) -> HandlerResult {
        let event: AnalyticsEvent = match serde_json::from_slice(&message.body) {
            Ok(e) => e,
            Err(err) => {
                error!(error = %err, "invalid analytics event payload - rejecting");
                return HandlerResult::Reject;
            }
        };

        let tenant_id = match Uuid::parse_str(&event.tenant_id) {
            Ok(id) => TenantId(id),
            Err(e) => {
                error!(tenant = %event.tenant_id, error = %e, "invalid tenant_id in analytics event");
                return HandlerResult::Reject;
            }
        };

        let message_id = event
            .message_id
            .as_deref()
            .and_then(|id| Uuid::parse_str(id).ok().map(MessageId));

        // Emit Prometheus metrics for every event type.
        metrics::counter!(
            "sentio_events_total",
            "event_type" => event.event_type.clone(),
            "tenant_id" => tenant_id.to_string(),
        )
        .increment(1);

        match event.event_type.as_str() {
            "delivered" => {
                metrics::counter!("sentio_delivered_total", "tenant_id" => tenant_id.to_string())
                    .increment(1);
                debug!(
                    tenant_id = %tenant_id,
                    message_id = ?message_id,
                    "analytics: delivered event processed"
                );
            }
            "bounced" => {
                let bounce_class = event
                    .payload
                    .get("bounce_class")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                metrics::counter!(
                    "sentio_bounced_total",
                    "tenant_id" => tenant_id.to_string(),
                    "bounce_class" => bounce_class.to_string(),
                )
                .increment(1);
                debug!(
                    tenant_id = %tenant_id,
                    bounce_class,
                    "analytics: bounced event processed"
                );
            }
            "deferred" => {
                metrics::counter!("sentio_deferred_total", "tenant_id" => tenant_id.to_string())
                    .increment(1);
                debug!(tenant_id = %tenant_id, "analytics: deferred event processed");
            }
            "dropped" => {
                metrics::counter!("sentio_dropped_total", "tenant_id" => tenant_id.to_string())
                    .increment(1);
                debug!(tenant_id = %tenant_id, "analytics: dropped event processed");
            }
            "opened" | "clicked" | "unsubscribed" => {
                metrics::counter!(
                    "sentio_engagement_total",
                    "event_type" => event.event_type.clone(),
                    "tenant_id" => tenant_id.to_string(),
                )
                .increment(1);
                debug!(
                    tenant_id = %tenant_id,
                    event_type = %event.event_type,
                    "analytics: engagement event processed"
                );
            }
            other => {
                debug!(
                    tenant_id = %tenant_id,
                    event_type = other,
                    "analytics: unhandled event type"
                );
            }
        }

        HandlerResult::Ack
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analytics_event_deserialization() {
        let json = r#"{
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "event_type": "delivered",
            "message_id": "00000000-0000-0000-0000-000000000002",
            "payload": {"recipient": "user@example.com"},
            "occurred_at": "2024-01-01T00:00:00Z"
        }"#;

        let event: AnalyticsEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.event_type, "delivered");
        assert_eq!(
            event.message_id.as_deref(),
            Some("00000000-0000-0000-0000-000000000002")
        );
    }

    #[test]
    fn test_analytics_event_minimal() {
        let json = r#"{
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "event_type": "bounced"
        }"#;

        let event: AnalyticsEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.event_type, "bounced");
        assert!(event.message_id.is_none());
    }
}
