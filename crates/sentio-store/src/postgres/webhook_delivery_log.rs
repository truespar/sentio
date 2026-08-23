use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::error::SentioError;
use sentio_core::ids::WebhookDeliveryLogId;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{
    NewWebhookDeliveryLog, WebhookDeliveryLogRecord, WebhookDeliveryLogRepository,
};
use sentio_core::webhook::WebhookId;

pub struct PgWebhookDeliveryLogRepository {
    pool: PgPool,
}

impl PgWebhookDeliveryLogRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_delivery_log_row(
    id: Uuid,
    webhook_id: Uuid,
    tenant_id: Uuid,
    event_type: String,
    payload: serde_json::Value,
    http_status: Option<i32>,
    response_body: Option<String>,
    attempt_number: i32,
    delivered_at: Option<DateTime<Utc>>,
    failed_at: Option<DateTime<Utc>>,
    error_message: Option<String>,
    created_at: DateTime<Utc>,
) -> WebhookDeliveryLogRecord {
    WebhookDeliveryLogRecord {
        id: WebhookDeliveryLogId(id),
        webhook_id: WebhookId(webhook_id),
        tenant_id: TenantId(tenant_id),
        event_type,
        payload,
        http_status,
        response_body,
        attempt_number,
        delivered_at,
        failed_at,
        error_message,
        created_at,
    }
}

impl WebhookDeliveryLogRepository for PgWebhookDeliveryLogRepository {
    async fn insert(
        &self,
        log: NewWebhookDeliveryLog,
    ) -> Result<WebhookDeliveryLogId, SentioError> {
        let row = sqlx::query!(
            "INSERT INTO webhook_delivery_logs \
                (webhook_id, tenant_id, event_type, payload, http_status, \
                 response_body, attempt_number, delivered_at, failed_at, error_message) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id",
            log.webhook_id.0,
            log.tenant_id.0,
            log.event_type,
            log.payload,
            log.http_status,
            log.response_body,
            log.attempt_number,
            log.delivered_at,
            log.failed_at,
            log.error_message,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(WebhookDeliveryLogId(row.id))
    }

    async fn get(&self, id: WebhookDeliveryLogId) -> Result<WebhookDeliveryLogRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, webhook_id, tenant_id, event_type, payload, http_status, \
                    response_body, attempt_number, delivered_at, failed_at, error_message, \
                    created_at \
             FROM webhook_delivery_logs WHERE id = $1",
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "webhook_delivery_log",
            id: id.to_string(),
        })?;

        Ok(parse_delivery_log_row(
            row.id,
            row.webhook_id,
            row.tenant_id,
            row.event_type,
            row.payload,
            row.http_status,
            row.response_body,
            row.attempt_number,
            row.delivered_at,
            row.failed_at,
            row.error_message,
            row.created_at,
        ))
    }

    async fn list_by_webhook(
        &self,
        webhook_id: WebhookId,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<WebhookDeliveryLogRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, webhook_id, tenant_id, event_type, payload, http_status, \
                    response_body, attempt_number, delivered_at, failed_at, error_message, \
                    created_at \
             FROM webhook_delivery_logs WHERE webhook_id = $1 \
             ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            webhook_id.0,
            limit,
            offset,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| {
                parse_delivery_log_row(
                    r.id,
                    r.webhook_id,
                    r.tenant_id,
                    r.event_type,
                    r.payload,
                    r.http_status,
                    r.response_body,
                    r.attempt_number,
                    r.delivered_at,
                    r.failed_at,
                    r.error_message,
                    r.created_at,
                )
            })
            .collect())
    }

    async fn list_by_tenant(
        &self,
        tenant_id: TenantId,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<WebhookDeliveryLogRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, webhook_id, tenant_id, event_type, payload, http_status, \
                    response_body, attempt_number, delivered_at, failed_at, error_message, \
                    created_at \
             FROM webhook_delivery_logs WHERE tenant_id = $1 \
             ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            tenant_id.0,
            limit,
            offset,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| {
                parse_delivery_log_row(
                    r.id,
                    r.webhook_id,
                    r.tenant_id,
                    r.event_type,
                    r.payload,
                    r.http_status,
                    r.response_body,
                    r.attempt_number,
                    r.delivered_at,
                    r.failed_at,
                    r.error_message,
                    r.created_at,
                )
            })
            .collect())
    }
}
