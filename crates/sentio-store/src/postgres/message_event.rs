use std::net::IpAddr;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::error::SentioError;
use sentio_core::event::{BounceClass, EventType};
use sentio_core::ids::MessageEventId;
use sentio_core::message::MessageId;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{
    EventFilter, MessageEventRecord, MessageEventRepository, NewMessageEvent,
};

pub struct PgMessageEventRepository {
    pool: PgPool,
}

impl PgMessageEventRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_bounce_class(s: Option<String>) -> Result<Option<BounceClass>, SentioError> {
    match s {
        Some(v) => Ok(Some(BounceClass::from_str(&v).map_err(|_| {
            SentioError::Database(format!("invalid bounce_class: {v}"))
        })?)),
        None => Ok(None),
    }
}

fn parse_ip(s: Option<ipnetwork::IpNetwork>) -> Option<IpAddr> {
    s.map(|n| n.ip())
}

fn parse_event_row(
    id: Uuid,
    message_id: Uuid,
    tenant_id: Uuid,
    event_type: String,
    smtp_response: Option<String>,
    remote_mta: Option<String>,
    diagnostic_code: Option<String>,
    bounce_class: Option<String>,
    retry_count: Option<i32>,
    next_retry_at: Option<DateTime<Utc>>,
    source_ip: Option<ipnetwork::IpNetwork>,
    destination_ip: Option<ipnetwork::IpNetwork>,
    tls_version: Option<String>,
    created_at: DateTime<Utc>,
) -> Result<MessageEventRecord, SentioError> {
    Ok(MessageEventRecord {
        id: MessageEventId(id),
        message_id: MessageId(message_id),
        tenant_id: TenantId(tenant_id),
        event_type: EventType::from_str(&event_type)
            .map_err(|_| SentioError::Database(format!("invalid event_type: {event_type}")))?,
        smtp_response,
        remote_mta,
        diagnostic_code,
        bounce_class: parse_bounce_class(bounce_class)?,
        retry_count,
        next_retry_at,
        source_ip: parse_ip(source_ip),
        destination_ip: parse_ip(destination_ip),
        tls_version,
        created_at,
    })
}

impl MessageEventRepository for PgMessageEventRepository {
    async fn insert(&self, event: NewMessageEvent) -> Result<MessageEventId, SentioError> {
        let id = MessageEventId::new();
        let event_type_str = event.event_type.to_string();
        let bounce_class_str = event.bounce_class.map(|b| b.to_string());
        let source_ip = event.source_ip.map(ipnetwork::IpNetwork::from);
        let destination_ip = event.destination_ip.map(ipnetwork::IpNetwork::from);

        sqlx::query!(
            "INSERT INTO message_events \
                (id, message_id, tenant_id, event_type, smtp_response, remote_mta, \
                 diagnostic_code, bounce_class, retry_count, next_retry_at, \
                 source_ip, destination_ip, tls_version) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
            id.0,
            event.message_id.0,
            event.tenant_id.0,
            event_type_str,
            event.smtp_response,
            event.remote_mta,
            event.diagnostic_code,
            bounce_class_str,
            event.retry_count,
            event.next_retry_at,
            source_ip,
            destination_ip,
            event.tls_version,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(id)
    }

    async fn list_by_message(
        &self,
        message_id: MessageId,
    ) -> Result<Vec<MessageEventRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, message_id, tenant_id, event_type, smtp_response, remote_mta, \
                    diagnostic_code, bounce_class, retry_count, next_retry_at, \
                    source_ip, destination_ip, tls_version, created_at \
             FROM message_events WHERE message_id = $1 ORDER BY created_at ASC",
            message_id.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|r| {
                parse_event_row(
                    r.id,
                    r.message_id,
                    r.tenant_id,
                    r.event_type,
                    r.smtp_response,
                    r.remote_mta,
                    r.diagnostic_code,
                    r.bounce_class,
                    r.retry_count,
                    r.next_retry_at,
                    r.source_ip,
                    r.destination_ip,
                    r.tls_version,
                    r.created_at,
                )
            })
            .collect()
    }

    async fn list_by_tenant(
        &self,
        tenant_id: TenantId,
        filter: EventFilter,
    ) -> Result<Vec<MessageEventRecord>, SentioError> {
        match filter.event_type {
            Some(et) => {
                let et_str = et.to_string();
                let rows = sqlx::query!(
                    "SELECT id, message_id, tenant_id, event_type, smtp_response, remote_mta, \
                            diagnostic_code, bounce_class, retry_count, next_retry_at, \
                            source_ip, destination_ip, tls_version, created_at \
                     FROM message_events \
                     WHERE tenant_id = $1 AND created_at >= $2 AND created_at < $3 \
                           AND event_type = $4 \
                     ORDER BY created_at DESC LIMIT $5 OFFSET $6",
                    tenant_id.0,
                    filter.from,
                    filter.to,
                    et_str,
                    filter.limit,
                    filter.offset,
                )
                .fetch_all(&self.pool)
                .await
                .map_err(|e| SentioError::Database(e.to_string()))?;

                rows.into_iter()
                    .map(|r| {
                        parse_event_row(
                            r.id,
                            r.message_id,
                            r.tenant_id,
                            r.event_type,
                            r.smtp_response,
                            r.remote_mta,
                            r.diagnostic_code,
                            r.bounce_class,
                            r.retry_count,
                            r.next_retry_at,
                            r.source_ip,
                            r.destination_ip,
                            r.tls_version,
                            r.created_at,
                        )
                    })
                    .collect()
            }
            None => {
                let rows = sqlx::query!(
                    "SELECT id, message_id, tenant_id, event_type, smtp_response, remote_mta, \
                            diagnostic_code, bounce_class, retry_count, next_retry_at, \
                            source_ip, destination_ip, tls_version, created_at \
                     FROM message_events \
                     WHERE tenant_id = $1 AND created_at >= $2 AND created_at < $3 \
                     ORDER BY created_at DESC LIMIT $4 OFFSET $5",
                    tenant_id.0,
                    filter.from,
                    filter.to,
                    filter.limit,
                    filter.offset,
                )
                .fetch_all(&self.pool)
                .await
                .map_err(|e| SentioError::Database(e.to_string()))?;

                rows.into_iter()
                    .map(|r| {
                        parse_event_row(
                            r.id,
                            r.message_id,
                            r.tenant_id,
                            r.event_type,
                            r.smtp_response,
                            r.remote_mta,
                            r.diagnostic_code,
                            r.bounce_class,
                            r.retry_count,
                            r.next_retry_at,
                            r.source_ip,
                            r.destination_ip,
                            r.tls_version,
                            r.created_at,
                        )
                    })
                    .collect()
            }
        }
    }
}
