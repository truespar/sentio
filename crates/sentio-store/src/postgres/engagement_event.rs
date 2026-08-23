use std::net::IpAddr;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::error::SentioError;
use sentio_core::event::{DeviceType, EngagementEventType};
use sentio_core::ids::EngagementEventId;
use sentio_core::message::MessageId;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{
    EngagementEventRecord, EngagementEventRepository, EngagementFilter, NewEngagementEvent,
};

pub struct PgEngagementEventRepository {
    pool: PgPool,
}

impl PgEngagementEventRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_device_type(s: Option<String>) -> Result<Option<DeviceType>, SentioError> {
    match s {
        Some(v) => Ok(Some(DeviceType::from_str(&v).map_err(|_| {
            SentioError::Database(format!("invalid device_type: {v}"))
        })?)),
        None => Ok(None),
    }
}

fn parse_ip(s: Option<ipnetwork::IpNetwork>) -> Option<IpAddr> {
    s.map(|n| n.ip())
}

fn parse_engagement_row(
    id: Uuid,
    message_id: Uuid,
    tenant_id: Uuid,
    event_type: String,
    ip_address: Option<ipnetwork::IpNetwork>,
    user_agent: Option<String>,
    url: Option<String>,
    referer: Option<String>,
    client_name: Option<String>,
    client_version: Option<String>,
    device_type: Option<String>,
    os_name: Option<String>,
    os_version: Option<String>,
    is_bot: bool,
    proxy_open: bool,
    country_code: Option<String>,
    region: Option<String>,
    city: Option<String>,
    created_at: DateTime<Utc>,
) -> Result<EngagementEventRecord, SentioError> {
    Ok(EngagementEventRecord {
        id: EngagementEventId(id),
        message_id: MessageId(message_id),
        tenant_id: TenantId(tenant_id),
        event_type: EngagementEventType::from_str(&event_type)
            .map_err(|_| SentioError::Database(format!("invalid event_type: {event_type}")))?,
        ip_address: parse_ip(ip_address),
        user_agent,
        url,
        referer,
        client_name,
        client_version,
        device_type: parse_device_type(device_type)?,
        os_name,
        os_version,
        is_bot,
        proxy_open,
        country_code,
        region,
        city,
        created_at,
    })
}

impl EngagementEventRepository for PgEngagementEventRepository {
    async fn insert(&self, event: NewEngagementEvent) -> Result<EngagementEventId, SentioError> {
        let id = EngagementEventId::new();
        let event_type_str = event.event_type.to_string();
        let device_type_str = event.device_type.map(|d| d.to_string());
        let ip_address = event.ip_address.map(ipnetwork::IpNetwork::from);

        sqlx::query!(
            "INSERT INTO engagement_events \
                (id, message_id, tenant_id, event_type, ip_address, user_agent, url, referer, \
                 client_name, client_version, device_type, os_name, os_version, \
                 is_bot, proxy_open, country_code, region, city) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)",
            id.0,
            event.message_id.0,
            event.tenant_id.0,
            event_type_str,
            ip_address,
            event.user_agent,
            event.url,
            event.referer,
            event.client_name,
            event.client_version,
            device_type_str,
            event.os_name,
            event.os_version,
            event.is_bot,
            event.proxy_open,
            event.country_code,
            event.region,
            event.city,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(id)
    }

    async fn list_by_message(
        &self,
        message_id: MessageId,
    ) -> Result<Vec<EngagementEventRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, message_id, tenant_id, event_type, ip_address, user_agent, \
                    url, referer, client_name, client_version, device_type, \
                    os_name, os_version, is_bot, proxy_open, \
                    country_code, region, city, created_at \
             FROM engagement_events WHERE message_id = $1 ORDER BY created_at ASC",
            message_id.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|r| {
                parse_engagement_row(
                    r.id,
                    r.message_id,
                    r.tenant_id,
                    r.event_type,
                    r.ip_address,
                    r.user_agent,
                    r.url,
                    r.referer,
                    r.client_name,
                    r.client_version,
                    r.device_type,
                    r.os_name,
                    r.os_version,
                    r.is_bot,
                    r.proxy_open,
                    r.country_code,
                    r.region,
                    r.city,
                    r.created_at,
                )
            })
            .collect()
    }

    async fn list_by_tenant(
        &self,
        tenant_id: TenantId,
        filter: EngagementFilter,
    ) -> Result<Vec<EngagementEventRecord>, SentioError> {
        match filter.event_type {
            Some(et) => {
                let et_str = et.to_string();
                let rows = sqlx::query!(
                    "SELECT id, message_id, tenant_id, event_type, ip_address, user_agent, \
                            url, referer, client_name, client_version, device_type, \
                            os_name, os_version, is_bot, proxy_open, \
                            country_code, region, city, created_at \
                     FROM engagement_events \
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
                        parse_engagement_row(
                            r.id,
                            r.message_id,
                            r.tenant_id,
                            r.event_type,
                            r.ip_address,
                            r.user_agent,
                            r.url,
                            r.referer,
                            r.client_name,
                            r.client_version,
                            r.device_type,
                            r.os_name,
                            r.os_version,
                            r.is_bot,
                            r.proxy_open,
                            r.country_code,
                            r.region,
                            r.city,
                            r.created_at,
                        )
                    })
                    .collect()
            }
            None => {
                let rows = sqlx::query!(
                    "SELECT id, message_id, tenant_id, event_type, ip_address, user_agent, \
                            url, referer, client_name, client_version, device_type, \
                            os_name, os_version, is_bot, proxy_open, \
                            country_code, region, city, created_at \
                     FROM engagement_events \
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
                        parse_engagement_row(
                            r.id,
                            r.message_id,
                            r.tenant_id,
                            r.event_type,
                            r.ip_address,
                            r.user_agent,
                            r.url,
                            r.referer,
                            r.client_name,
                            r.client_version,
                            r.device_type,
                            r.os_name,
                            r.os_version,
                            r.is_bot,
                            r.proxy_open,
                            r.country_code,
                            r.region,
                            r.city,
                            r.created_at,
                        )
                    })
                    .collect()
            }
        }
    }
}
