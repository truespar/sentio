use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::auth::DomainStatus;
use sentio_core::error::SentioError;
use sentio_core::ids::TrackingDomainId;
use sentio_core::message::DomainId;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{NewTrackingDomain, TrackingDomainRecord, TrackingDomainRepository};

pub struct PgTrackingDomainRepository {
    pool: PgPool,
}

impl PgTrackingDomainRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_tracking_domain_row(
    id: Uuid,
    tenant_id: Uuid,
    domain_id: Option<Uuid>,
    domain_name: String,
    cname_target: String,
    dns_status: String,
    dns_error: Option<String>,
    dns_checked_at: Option<DateTime<Utc>>,
    ssl_enabled: bool,
    track_opens: bool,
    track_clicks: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
) -> Result<TrackingDomainRecord, SentioError> {
    Ok(TrackingDomainRecord {
        id: TrackingDomainId(id),
        tenant_id: TenantId(tenant_id),
        domain_id: domain_id.map(DomainId),
        domain_name,
        cname_target,
        dns_status: DomainStatus::from_str(&dns_status)
            .map_err(|_| SentioError::Database(format!("invalid dns_status: {dns_status}")))?,
        dns_error,
        dns_checked_at,
        ssl_enabled,
        track_opens,
        track_clicks,
        created_at,
        updated_at,
    })
}

impl TrackingDomainRepository for PgTrackingDomainRepository {
    async fn create(&self, domain: NewTrackingDomain) -> Result<TrackingDomainId, SentioError> {
        let row = sqlx::query!(
            "INSERT INTO tracking_domains \
                (tenant_id, domain_id, domain_name, cname_target, \
                 ssl_enabled, track_opens, track_clicks) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
            domain.tenant_id.0,
            domain.domain_id.map(|d| d.0),
            domain.domain_name,
            domain.cname_target,
            domain.ssl_enabled,
            domain.track_opens,
            domain.track_clicks,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(TrackingDomainId(row.id))
    }

    async fn get(&self, id: TrackingDomainId) -> Result<TrackingDomainRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, tenant_id, domain_id, domain_name, cname_target, \
                    dns_status, dns_error, dns_checked_at, ssl_enabled, \
                    track_opens, track_clicks, created_at, updated_at \
             FROM tracking_domains WHERE id = $1",
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "tracking_domain",
            id: id.to_string(),
        })?;

        parse_tracking_domain_row(
            row.id,
            row.tenant_id,
            row.domain_id,
            row.domain_name,
            row.cname_target,
            row.dns_status,
            row.dns_error,
            row.dns_checked_at,
            row.ssl_enabled,
            row.track_opens,
            row.track_clicks,
            row.created_at,
            row.updated_at,
        )
    }

    async fn get_by_name(&self, domain_name: &str) -> Result<TrackingDomainRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, tenant_id, domain_id, domain_name, cname_target, \
                    dns_status, dns_error, dns_checked_at, ssl_enabled, \
                    track_opens, track_clicks, created_at, updated_at \
             FROM tracking_domains WHERE domain_name = $1",
            domain_name,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "tracking_domain",
            id: domain_name.to_string(),
        })?;

        parse_tracking_domain_row(
            row.id,
            row.tenant_id,
            row.domain_id,
            row.domain_name,
            row.cname_target,
            row.dns_status,
            row.dns_error,
            row.dns_checked_at,
            row.ssl_enabled,
            row.track_opens,
            row.track_clicks,
            row.created_at,
            row.updated_at,
        )
    }

    async fn list_by_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<TrackingDomainRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, tenant_id, domain_id, domain_name, cname_target, \
                    dns_status, dns_error, dns_checked_at, ssl_enabled, \
                    track_opens, track_clicks, created_at, updated_at \
             FROM tracking_domains WHERE tenant_id = $1 ORDER BY created_at DESC",
            tenant_id.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|r| {
                parse_tracking_domain_row(
                    r.id,
                    r.tenant_id,
                    r.domain_id,
                    r.domain_name,
                    r.cname_target,
                    r.dns_status,
                    r.dns_error,
                    r.dns_checked_at,
                    r.ssl_enabled,
                    r.track_opens,
                    r.track_clicks,
                    r.created_at,
                    r.updated_at,
                )
            })
            .collect()
    }

    async fn update_dns_status(
        &self,
        id: TrackingDomainId,
        dns_status: DomainStatus,
        dns_error: Option<&str>,
    ) -> Result<(), SentioError> {
        let dns_status_str = dns_status.to_string();
        let result = sqlx::query!(
            "UPDATE tracking_domains SET dns_status = $1, dns_error = $2, dns_checked_at = now() \
             WHERE id = $3",
            dns_status_str,
            dns_error,
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "tracking_domain",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn delete(&self, id: TrackingDomainId) -> Result<(), SentioError> {
        let result = sqlx::query!("DELETE FROM tracking_domains WHERE id = $1", id.0)
            .execute(&self.pool)
            .await
            .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "tracking_domain",
                id: id.to_string(),
            });
        }
        Ok(())
    }
}
