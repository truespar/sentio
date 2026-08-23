use sentio_core::traits::WebhookRepository;
use sentio_core::webhook::{WebhookId, WebhookStatus};

/// Number of consecutive failures after which a webhook is automatically
/// disabled. The counter is reset on each successful delivery.
pub const AUTO_DISABLE_THRESHOLD: i32 = 50;

/// Handles permanently failed webhook deliveries.
///
/// After a webhook accumulates [`AUTO_DISABLE_THRESHOLD`] consecutive failures
/// its status is set to [`WebhookStatus::Disabled`] so that the dispatcher
/// stops attempting deliveries.
pub struct DeadLetterHandler;

impl DeadLetterHandler {
    /// Call this when a webhook has exhausted all retries for a single event.
    ///
    /// `current_failure_count` is the webhook's `failure_count` **after** the
    /// latest increment.
    pub async fn handle_permanent_failure<W: WebhookRepository>(
        repo: &W,
        webhook_id: WebhookId,
        current_failure_count: i32,
    ) {
        if current_failure_count >= AUTO_DISABLE_THRESHOLD {
            tracing::warn!(
                webhook_id = %webhook_id,
                failures = current_failure_count,
                "auto-disabling webhook after {} consecutive failures",
                current_failure_count,
            );
            if let Err(err) = repo
                .update_status(webhook_id, WebhookStatus::Disabled)
                .await
            {
                tracing::error!(
                    webhook_id = %webhook_id,
                    error = %err,
                    "failed to disable webhook"
                );
            }
        } else {
            tracing::warn!(
                webhook_id = %webhook_id,
                failures = current_failure_count,
                threshold = AUTO_DISABLE_THRESHOLD,
                "webhook delivery permanently failed"
            );
        }
    }
}
