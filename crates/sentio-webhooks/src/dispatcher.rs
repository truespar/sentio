use std::sync::Arc;

use chrono::Utc;
use sentio_core::error::SentioError;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{
    NewWebhookDeliveryLog, WebhookDeliveryLogRepository, WebhookRecord, WebhookRepository,
};
use sentio_core::webhook::WebhookStatus;
use serde::{Deserialize, Serialize};

use crate::dead_letter::DeadLetterHandler;
use crate::delivery;
use crate::signing;

// ──────────────────────────────────────────────────────────────────────────────
// WebhookSender - abstracts the HTTP layer for testability
// ──────────────────────────────────────────────────────────────────────────────

/// Result of a single HTTP POST to a webhook endpoint.
#[derive(Debug, Clone)]
pub struct SendResult {
    pub status: u16,
    pub body: Option<String>,
}

/// Trait for sending webhook HTTP requests.
///
/// The production implementation wraps [`reqwest::Client`]; tests provide a
/// mock that captures requests and returns canned responses.
pub trait WebhookSender: Send + Sync {
    fn send(
        &self,
        url: &str,
        headers: Vec<(&str, String)>,
        body: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<SendResult, String>> + Send;
}

impl<T: WebhookSender> WebhookSender for Arc<T> {
    async fn send(
        &self,
        url: &str,
        headers: Vec<(&str, String)>,
        body: Vec<u8>,
    ) -> Result<SendResult, String> {
        (**self).send(url, headers, body).await
    }
}

/// Production sender backed by [`reqwest::Client`].
pub struct ReqwestSender {
    client: reqwest::Client,
}

impl ReqwestSender {
    pub fn new(timeout_secs: u64) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .build()
            .expect("failed to build HTTP client");
        Self { client }
    }
}

impl WebhookSender for ReqwestSender {
    async fn send(
        &self,
        url: &str,
        headers: Vec<(&str, String)>,
        body: Vec<u8>,
    ) -> Result<SendResult, String> {
        let mut req = self
            .client
            .post(url)
            .header("Content-Type", "application/json");

        for (name, value) in headers {
            req = req.header(name, value);
        }

        let response = req.body(body).send().await.map_err(|e| e.to_string())?;

        let status = response.status().as_u16();
        let body = response.text().await.ok();
        Ok(SendResult { status, body })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// WebhookEvent - payload deserialized from the queue
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub tenant_id: String,
    pub event_type: String,
    #[serde(default)]
    pub message_id: Option<String>,
    pub payload: serde_json::Value,
    #[serde(default)]
    pub occurred_at: Option<String>,
}

// ──────────────────────────────────────────────────────────────────────────────
// WebhookDispatcher
// ──────────────────────────────────────────────────────────────────────────────

/// Core webhook dispatcher.
///
/// Generic over:
/// - `S`: HTTP sender
/// - `W`: webhook repository
/// - `L`: delivery-log repository
pub struct WebhookDispatcher<S, W, L> {
    sender: S,
    webhook_repo: Arc<W>,
    delivery_log_repo: Arc<L>,
}

impl<S, W, L> WebhookDispatcher<S, W, L>
where
    S: WebhookSender,
    W: WebhookRepository,
    L: WebhookDeliveryLogRepository,
{
    pub fn new(sender: S, webhook_repo: Arc<W>, delivery_log_repo: Arc<L>) -> Self {
        Self {
            sender,
            webhook_repo,
            delivery_log_repo,
        }
    }

    /// Dispatch an event to all matching active webhooks for the tenant.
    pub async fn dispatch_event(&self, event: &WebhookEvent) -> Result<(), SentioError> {
        let tenant_id: TenantId = event.tenant_id.parse().map_err(|_| {
            SentioError::Validation(format!("invalid tenant_id: {}", event.tenant_id))
        })?;

        let webhooks = self.webhook_repo.list_by_tenant(tenant_id).await?;

        let mut any_failed = false;

        for webhook in &webhooks {
            if webhook.status != WebhookStatus::Active {
                continue;
            }

            // Filter: webhook must subscribe to this event type (or wildcard "*").
            if !webhook.event_types.contains(&event.event_type)
                && !webhook.event_types.contains(&"*".to_string())
            {
                continue;
            }

            if let Err(err) = self.deliver_to_webhook(webhook, event).await {
                tracing::warn!(
                    webhook_id = %webhook.id,
                    event_type = %event.event_type,
                    error = %err,
                    "webhook delivery failed after all retries"
                );
                any_failed = true;
            }
        }

        if any_failed {
            // Return an error so the queue handler can decide whether to retry
            // the entire event at the queue level.
            Err(SentioError::Internal(
                "one or more webhook deliveries failed".into(),
            ))
        } else {
            Ok(())
        }
    }

    /// Deliver an event to a single webhook with quick in-process retries.
    async fn deliver_to_webhook(
        &self,
        webhook: &WebhookRecord,
        event: &WebhookEvent,
    ) -> Result<(), SentioError> {
        let criticality = delivery::classify_event(&event.event_type);
        let max_attempts = delivery::quick_retry_attempts(criticality);

        let mut last_err = None;

        for attempt in 1..=max_attempts {
            match self.send_single(webhook, event, attempt).await {
                Ok(()) => {
                    self.webhook_repo.record_success(webhook.id).await?;
                    return Ok(());
                }
                Err(err) => {
                    last_err = Some(err);
                    if attempt < max_attempts {
                        let delay = delivery::quick_retry_delay(attempt);
                        tracing::debug!(
                            webhook_id = %webhook.id,
                            attempt,
                            delay_ms = delay.as_millis() as u64,
                            "retrying webhook delivery"
                        );
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        // All quick retries exhausted - record the failure.
        self.webhook_repo.increment_failure(webhook.id).await?;

        // Check if the webhook should be auto-disabled.
        let updated = self.webhook_repo.get(webhook.id).await?;
        DeadLetterHandler::handle_permanent_failure(
            &*self.webhook_repo,
            webhook.id,
            updated.failure_count,
        )
        .await;

        Err(last_err.unwrap_or_else(|| SentioError::Internal("delivery failed".into())))
    }

    /// Execute a single HTTP POST to the webhook endpoint.
    async fn send_single(
        &self,
        webhook: &WebhookRecord,
        event: &WebhookEvent,
        attempt: u32,
    ) -> Result<(), SentioError> {
        // Build webhook body by merging envelope fields into the payload.
        // This gives webhook consumers a flat, self-contained JSON object with
        // event_id, message_id, event_type, created_at alongside delivery details.
        let mut body_value = event.payload.clone();
        if let Some(obj) = body_value.as_object_mut() {
            obj.insert(
                "event_id".to_string(),
                serde_json::Value::String(uuid::Uuid::new_v4().to_string()),
            );
            if let Some(ref mid) = event.message_id {
                obj.insert(
                    "message_id".to_string(),
                    serde_json::Value::String(mid.clone()),
                );
            }
            obj.insert(
                "event_type".to_string(),
                serde_json::Value::String(event.event_type.clone()),
            );
            if let Some(ref ts) = event.occurred_at {
                obj.insert(
                    "created_at".to_string(),
                    serde_json::Value::String(ts.clone()),
                );
            }
        }
        let body = serde_json::to_vec(&body_value)
            .map_err(|e| SentioError::Internal(format!("serialize payload: {e}")))?;

        let sig = signing::build_signature(&webhook.signing_secret, &body);

        let headers = vec![
            (signing::HEADER_TIMESTAMP, sig.timestamp.to_string()),
            (signing::HEADER_NONCE, sig.nonce),
            (signing::HEADER_SIGNATURE, sig.signature),
            (signing::HEADER_EVENT, event.event_type.clone()),
        ];

        let tenant_id: TenantId = event
            .tenant_id
            .parse()
            .map_err(|_| SentioError::Validation("invalid tenant_id".into()))?;

        let result = self.sender.send(&webhook.url, headers, body).await;

        match result {
            Ok(sr) => {
                let status = sr.status as i32;
                if (200..300).contains(&(sr.status as usize)) {
                    self.log_delivery(
                        webhook,
                        event,
                        tenant_id,
                        attempt,
                        Some(status),
                        sr.body,
                        Some(Utc::now()),
                        None,
                        None,
                    )
                    .await;
                    Ok(())
                } else {
                    let err_msg = format!("HTTP {}", sr.status);
                    self.log_delivery(
                        webhook,
                        event,
                        tenant_id,
                        attempt,
                        Some(status),
                        sr.body,
                        None,
                        Some(Utc::now()),
                        Some(err_msg.clone()),
                    )
                    .await;
                    Err(SentioError::Internal(err_msg))
                }
            }
            Err(err_msg) => {
                self.log_delivery(
                    webhook,
                    event,
                    tenant_id,
                    attempt,
                    None,
                    None,
                    None,
                    Some(Utc::now()),
                    Some(err_msg.clone()),
                )
                .await;
                Err(SentioError::Internal(err_msg))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn log_delivery(
        &self,
        webhook: &WebhookRecord,
        event: &WebhookEvent,
        tenant_id: TenantId,
        attempt: u32,
        http_status: Option<i32>,
        response_body: Option<String>,
        delivered_at: Option<chrono::DateTime<Utc>>,
        failed_at: Option<chrono::DateTime<Utc>>,
        error_message: Option<String>,
    ) {
        let log = NewWebhookDeliveryLog {
            webhook_id: webhook.id,
            tenant_id,
            event_type: event.event_type.clone(),
            payload: event.payload.clone(),
            http_status,
            response_body,
            attempt_number: attempt as i32,
            delivered_at,
            failed_at,
            error_message,
        };

        if let Err(err) = self.delivery_log_repo.insert(log).await {
            tracing::error!(
                webhook_id = %webhook.id,
                error = %err,
                "failed to log webhook delivery"
            );
        }
    }
}
