use sqlx::PgPool;

use sentio_core::event::{ErrorCategory, ErrorComponent, ErrorSeverity};
use sentio_core::tenant::TenantId;
use sentio_core::traits::{ErrorEventRepository, NewErrorEvent};
use sentio_store::postgres::PgErrorEventRepository;

/// Fire-and-forget error capture. Spawns a background task to persist the error
/// event to PostgreSQL. Never blocks the caller or crashes the application.
pub fn capture_error(
    pool: PgPool,
    tenant_id: TenantId,
    severity: ErrorSeverity,
    component: ErrorComponent,
    error_type: ErrorCategory,
    message: String,
    message_id: Option<uuid::Uuid>,
    request_id: Option<String>,
    metadata: serde_json::Value,
) {
    tokio::spawn(async move {
        let repo = PgErrorEventRepository::new(pool);
        let event = NewErrorEvent {
            tenant_id,
            severity,
            component,
            error_type,
            message,
            stack_trace: None,
            message_id,
            request_id,
            metadata,
        };
        if let Err(e) = repo.insert(event).await {
            tracing::warn!(error = %e, "failed to persist error event");
        }
    });
}
