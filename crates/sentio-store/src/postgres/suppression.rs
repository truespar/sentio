use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::error::SentioError;
use sentio_core::ids::{MessageEventId, SuppressionId};
use sentio_core::message::SuppressionReason;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{NewSuppression, SuppressionRecord, SuppressionRepository};

pub struct PgSuppressionRepository {
    pool: PgPool,
}

impl PgSuppressionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_suppression_row(
    id: Uuid,
    tenant_id: Uuid,
    email: String,
    reason: String,
    source_event_id: Option<Uuid>,
    created_at: DateTime<Utc>,
) -> Result<SuppressionRecord, SentioError> {
    Ok(SuppressionRecord {
        id: SuppressionId(id),
        tenant_id: TenantId(tenant_id),
        email,
        reason: SuppressionReason::from_str(&reason)
            .map_err(|_| SentioError::Database(format!("invalid suppression reason: {reason}")))?,
        source_event_id: source_event_id.map(MessageEventId),
        created_at,
    })
}

impl SuppressionRepository for PgSuppressionRepository {
    async fn add(&self, suppression: NewSuppression) -> Result<SuppressionId, SentioError> {
        let reason_str = suppression.reason.to_string();
        let row = sqlx::query!(
            "INSERT INTO suppressions (tenant_id, email, reason, source_event_id) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (tenant_id, email) DO NOTHING \
             RETURNING id",
            suppression.tenant_id.0,
            suppression.email,
            reason_str,
            suppression.source_event_id.map(|e| e.0),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        match row {
            Some(r) => Ok(SuppressionId(r.id)),
            None => {
                // Already suppressed - return the existing ID.
                let existing = sqlx::query!(
                    "SELECT id FROM suppressions WHERE tenant_id = $1 AND email = $2",
                    suppression.tenant_id.0,
                    suppression.email,
                )
                .fetch_one(&self.pool)
                .await
                .map_err(|e| SentioError::Database(e.to_string()))?;
                Ok(SuppressionId(existing.id))
            }
        }
    }

    async fn check(&self, tenant_id: TenantId, email: &str) -> Result<bool, SentioError> {
        let row = sqlx::query!(
            "SELECT 1 as exists_ FROM suppressions WHERE tenant_id = $1 AND email = $2",
            tenant_id.0,
            email,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(row.is_some())
    }

    async fn get(
        &self,
        tenant_id: TenantId,
        email: &str,
    ) -> Result<SuppressionRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, tenant_id, email, reason, source_event_id, created_at \
             FROM suppressions WHERE tenant_id = $1 AND email = $2",
            tenant_id.0,
            email,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "suppression",
            id: email.to_string(),
        })?;

        parse_suppression_row(
            row.id,
            row.tenant_id,
            row.email,
            row.reason,
            row.source_event_id,
            row.created_at,
        )
    }

    async fn list_by_tenant(
        &self,
        tenant_id: TenantId,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SuppressionRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, tenant_id, email, reason, source_event_id, created_at \
             FROM suppressions WHERE tenant_id = $1 \
             ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            tenant_id.0,
            limit,
            offset,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|r| {
                parse_suppression_row(
                    r.id,
                    r.tenant_id,
                    r.email,
                    r.reason,
                    r.source_event_id,
                    r.created_at,
                )
            })
            .collect()
    }

    async fn remove(&self, tenant_id: TenantId, email: &str) -> Result<(), SentioError> {
        let result = sqlx::query!(
            "DELETE FROM suppressions WHERE tenant_id = $1 AND email = $2",
            tenant_id.0,
            email,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "suppression",
                id: email.to_string(),
            });
        }
        Ok(())
    }
}
