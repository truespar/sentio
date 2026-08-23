use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::error::SentioError;
use sentio_core::ids::{InboundRouteDeliveryLogId, InboundRouteId};
use sentio_core::message::MessageId;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{
    InboundRouteDeliveryLogRecord, InboundRouteDeliveryLogRepository, NewInboundRouteDeliveryLog,
};

pub struct PgInboundRouteDeliveryLogRepository {
    pool: PgPool,
}

impl PgInboundRouteDeliveryLogRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_row(
    id: Uuid,
    inbound_route_id: Uuid,
    tenant_id: Uuid,
    message_id: Option<Uuid>,
    recipient: String,
    http_status: Option<i32>,
    response_body: Option<String>,
    attempt_number: i32,
    delivered_at: Option<DateTime<Utc>>,
    failed_at: Option<DateTime<Utc>>,
    error_message: Option<String>,
    created_at: DateTime<Utc>,
) -> InboundRouteDeliveryLogRecord {
    InboundRouteDeliveryLogRecord {
        id: InboundRouteDeliveryLogId(id),
        inbound_route_id: InboundRouteId(inbound_route_id),
        tenant_id: TenantId(tenant_id),
        message_id: message_id.map(MessageId),
        recipient,
        http_status,
        response_body,
        attempt_number,
        delivered_at,
        failed_at,
        error_message,
        created_at,
    }
}

impl InboundRouteDeliveryLogRepository for PgInboundRouteDeliveryLogRepository {
    async fn insert(
        &self,
        log: NewInboundRouteDeliveryLog,
    ) -> Result<InboundRouteDeliveryLogId, SentioError> {
        let row = sqlx::query!(
            "INSERT INTO inbound_route_delivery_logs \
                (inbound_route_id, tenant_id, message_id, recipient, http_status, \
                 response_body, attempt_number, delivered_at, failed_at, error_message) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id",
            log.inbound_route_id.0,
            log.tenant_id.0,
            log.message_id.map(|m| m.0),
            log.recipient,
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

        Ok(InboundRouteDeliveryLogId(row.id))
    }

    async fn list_by_route(
        &self,
        inbound_route_id: InboundRouteId,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<InboundRouteDeliveryLogRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, inbound_route_id, tenant_id, message_id, recipient, http_status, \
                    response_body, attempt_number, delivered_at, failed_at, error_message, \
                    created_at \
             FROM inbound_route_delivery_logs WHERE inbound_route_id = $1 \
             ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            inbound_route_id.0,
            limit,
            offset,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| {
                parse_row(
                    r.id,
                    r.inbound_route_id,
                    r.tenant_id,
                    r.message_id,
                    r.recipient,
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

    async fn has_prior_success(
        &self,
        inbound_route_id: InboundRouteId,
        message_id: MessageId,
        recipient: &str,
    ) -> Result<bool, SentioError> {
        let row = sqlx::query!(
            "SELECT 1 AS hit FROM inbound_route_delivery_logs \
             WHERE inbound_route_id = $1 \
               AND message_id = $2 \
               AND recipient = $3 \
               AND delivered_at IS NOT NULL \
             LIMIT 1",
            inbound_route_id.0,
            message_id.0,
            recipient,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;
        Ok(row.is_some())
    }

    async fn list_by_tenant(
        &self,
        tenant_id: TenantId,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<InboundRouteDeliveryLogRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, inbound_route_id, tenant_id, message_id, recipient, http_status, \
                    response_body, attempt_number, delivered_at, failed_at, error_message, \
                    created_at \
             FROM inbound_route_delivery_logs WHERE tenant_id = $1 \
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
                parse_row(
                    r.id,
                    r.inbound_route_id,
                    r.tenant_id,
                    r.message_id,
                    r.recipient,
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
