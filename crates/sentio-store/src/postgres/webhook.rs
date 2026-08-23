use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::error::SentioError;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{NewWebhook, WebhookRecord, WebhookRepository, WebhookUpdate};
use sentio_core::webhook::{WebhookId, WebhookStatus};

pub struct PgWebhookRepository {
    pool: PgPool,
}

impl PgWebhookRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_webhook_row(
    id: Uuid,
    tenant_id: Uuid,
    url: String,
    event_types: Vec<String>,
    signing_secret: String,
    status: String,
    failure_count: i32,
    last_success_at: Option<DateTime<Utc>>,
    last_failure_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
) -> Result<WebhookRecord, SentioError> {
    Ok(WebhookRecord {
        id: WebhookId(id),
        tenant_id: TenantId(tenant_id),
        url,
        event_types,
        signing_secret,
        status: WebhookStatus::from_str(&status)
            .map_err(|_| SentioError::Database(format!("invalid webhook status: {status}")))?,
        failure_count,
        last_success_at,
        last_failure_at,
        created_at,
        updated_at,
    })
}

impl WebhookRepository for PgWebhookRepository {
    async fn create(&self, webhook: NewWebhook) -> Result<WebhookId, SentioError> {
        let row = sqlx::query!(
            "INSERT INTO webhooks (tenant_id, url, event_types, signing_secret) \
             VALUES ($1, $2, $3, $4) RETURNING id",
            webhook.tenant_id.0,
            webhook.url,
            &webhook.event_types,
            webhook.signing_secret,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(WebhookId(row.id))
    }

    async fn get(&self, id: WebhookId) -> Result<WebhookRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, tenant_id, url, event_types, signing_secret, status, \
                    failure_count, last_success_at, last_failure_at, created_at, updated_at \
             FROM webhooks WHERE id = $1",
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "webhook",
            id: id.to_string(),
        })?;

        parse_webhook_row(
            row.id,
            row.tenant_id,
            row.url,
            row.event_types,
            row.signing_secret,
            row.status,
            row.failure_count,
            row.last_success_at,
            row.last_failure_at,
            row.created_at,
            row.updated_at,
        )
    }

    async fn list_by_tenant(&self, tenant_id: TenantId) -> Result<Vec<WebhookRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, tenant_id, url, event_types, signing_secret, status, \
                    failure_count, last_success_at, last_failure_at, created_at, updated_at \
             FROM webhooks WHERE tenant_id = $1 ORDER BY created_at DESC",
            tenant_id.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|r| {
                parse_webhook_row(
                    r.id,
                    r.tenant_id,
                    r.url,
                    r.event_types,
                    r.signing_secret,
                    r.status,
                    r.failure_count,
                    r.last_success_at,
                    r.last_failure_at,
                    r.created_at,
                    r.updated_at,
                )
            })
            .collect()
    }

    async fn update(&self, id: WebhookId, update: WebhookUpdate) -> Result<(), SentioError> {
        let status_str = update.status.to_string();
        let result = sqlx::query!(
            "UPDATE webhooks SET url = $1, event_types = $2, status = $3 WHERE id = $4",
            update.url,
            &update.event_types,
            status_str,
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "webhook",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn update_status(&self, id: WebhookId, status: WebhookStatus) -> Result<(), SentioError> {
        let status_str = status.to_string();
        let result = sqlx::query!(
            "UPDATE webhooks SET status = $1 WHERE id = $2",
            status_str,
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "webhook",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn increment_failure(&self, id: WebhookId) -> Result<(), SentioError> {
        let result = sqlx::query!(
            "UPDATE webhooks SET failure_count = failure_count + 1, last_failure_at = now() \
             WHERE id = $1",
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "webhook",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn record_success(&self, id: WebhookId) -> Result<(), SentioError> {
        let result = sqlx::query!(
            "UPDATE webhooks SET failure_count = 0, last_success_at = now() WHERE id = $1",
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "webhook",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn delete(&self, id: WebhookId) -> Result<(), SentioError> {
        let result = sqlx::query!("DELETE FROM webhooks WHERE id = $1", id.0)
            .execute(&self.pool)
            .await
            .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "webhook",
                id: id.to_string(),
            });
        }
        Ok(())
    }
}
