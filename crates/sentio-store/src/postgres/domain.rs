use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::auth::{DnsCheckStatus, DomainStatus};
use sentio_core::error::SentioError;
use sentio_core::message::DomainId;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{
    DnsCheckUpdate, DomainRecord, DomainRepository, DomainUpdate, NewDomain,
};

pub struct PgDomainRepository {
    pool: PgPool,
}

impl PgDomainRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_dns_check_status(s: &str) -> Result<DnsCheckStatus, SentioError> {
    DnsCheckStatus::from_str(s)
        .map_err(|_| SentioError::Database(format!("invalid dns_check_status: {s}")))
}

fn parse_domain_row(
    id: Uuid,
    tenant_id: Uuid,
    domain_name: String,
    use_for_sending: bool,
    use_for_receiving: bool,
    status: String,
    spf_status: String,
    spf_error: Option<String>,
    dkim_status: String,
    dkim_error: Option<String>,
    dmarc_status: String,
    dmarc_error: Option<String>,
    mx_status: String,
    mx_error: Option<String>,
    return_path_status: String,
    return_path_error: Option<String>,
    dns_checked_at: Option<DateTime<Utc>>,
    verification_token: String,
    verified_at: Option<DateTime<Utc>>,
    reject_unknown_recipients: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
) -> Result<DomainRecord, SentioError> {
    Ok(DomainRecord {
        id: DomainId(id),
        tenant_id: TenantId(tenant_id),
        domain_name,
        use_for_sending,
        use_for_receiving,
        status: DomainStatus::from_str(&status)
            .map_err(|_| SentioError::Database(format!("invalid domain status: {status}")))?,
        spf_status: parse_dns_check_status(&spf_status)?,
        spf_error,
        dkim_status: parse_dns_check_status(&dkim_status)?,
        dkim_error,
        dmarc_status: parse_dns_check_status(&dmarc_status)?,
        dmarc_error,
        mx_status: parse_dns_check_status(&mx_status)?,
        mx_error,
        return_path_status: parse_dns_check_status(&return_path_status)?,
        return_path_error,
        dns_checked_at,
        verification_token,
        verified_at,
        reject_unknown_recipients,
        created_at,
        updated_at,
    })
}

impl DomainRepository for PgDomainRepository {
    async fn create(&self, domain: NewDomain) -> Result<DomainRecord, SentioError> {
        let verification_token = format!("sentio-verify-{}", Uuid::new_v4());

        let row = sqlx::query!(
            "INSERT INTO domains (tenant_id, domain_name, use_for_sending, use_for_receiving, verification_token) \
             VALUES ($1, $2, $3, $4, $5) \
             RETURNING id, tenant_id, domain_name, use_for_sending, use_for_receiving, \
                       status, spf_status, spf_error, dkim_status, dkim_error, \
                       dmarc_status, dmarc_error, mx_status, mx_error, \
                       return_path_status, return_path_error, dns_checked_at, \
                       verification_token, verified_at, reject_unknown_recipients, \
                       created_at, updated_at",
            domain.tenant_id.0,
            domain.domain_name,
            domain.use_for_sending,
            domain.use_for_receiving,
            verification_token,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        parse_domain_row(
            row.id,
            row.tenant_id,
            row.domain_name,
            row.use_for_sending,
            row.use_for_receiving,
            row.status,
            row.spf_status,
            row.spf_error,
            row.dkim_status,
            row.dkim_error,
            row.dmarc_status,
            row.dmarc_error,
            row.mx_status,
            row.mx_error,
            row.return_path_status,
            row.return_path_error,
            row.dns_checked_at,
            row.verification_token,
            row.verified_at,
            row.reject_unknown_recipients,
            row.created_at,
            row.updated_at,
        )
    }

    async fn get(&self, id: DomainId) -> Result<DomainRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, tenant_id, domain_name, use_for_sending, use_for_receiving, \
                    status, spf_status, spf_error, dkim_status, dkim_error, \
                    dmarc_status, dmarc_error, mx_status, mx_error, \
                    return_path_status, return_path_error, dns_checked_at, \
                    verification_token, verified_at, reject_unknown_recipients, \
                    created_at, updated_at \
             FROM domains WHERE id = $1",
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "domain",
            id: id.to_string(),
        })?;

        parse_domain_row(
            row.id,
            row.tenant_id,
            row.domain_name,
            row.use_for_sending,
            row.use_for_receiving,
            row.status,
            row.spf_status,
            row.spf_error,
            row.dkim_status,
            row.dkim_error,
            row.dmarc_status,
            row.dmarc_error,
            row.mx_status,
            row.mx_error,
            row.return_path_status,
            row.return_path_error,
            row.dns_checked_at,
            row.verification_token,
            row.verified_at,
            row.reject_unknown_recipients,
            row.created_at,
            row.updated_at,
        )
    }

    async fn get_by_name(
        &self,
        tenant_id: TenantId,
        domain_name: &str,
    ) -> Result<DomainRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, tenant_id, domain_name, use_for_sending, use_for_receiving, \
                    status, spf_status, spf_error, dkim_status, dkim_error, \
                    dmarc_status, dmarc_error, mx_status, mx_error, \
                    return_path_status, return_path_error, dns_checked_at, \
                    verification_token, verified_at, reject_unknown_recipients, \
                    created_at, updated_at \
             FROM domains WHERE tenant_id = $1 AND domain_name = $2",
            tenant_id.0,
            domain_name,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "domain",
            id: domain_name.to_string(),
        })?;

        parse_domain_row(
            row.id,
            row.tenant_id,
            row.domain_name,
            row.use_for_sending,
            row.use_for_receiving,
            row.status,
            row.spf_status,
            row.spf_error,
            row.dkim_status,
            row.dkim_error,
            row.dmarc_status,
            row.dmarc_error,
            row.mx_status,
            row.mx_error,
            row.return_path_status,
            row.return_path_error,
            row.dns_checked_at,
            row.verification_token,
            row.verified_at,
            row.reject_unknown_recipients,
            row.created_at,
            row.updated_at,
        )
    }

    async fn list_by_tenant(&self, tenant_id: TenantId) -> Result<Vec<DomainRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, tenant_id, domain_name, use_for_sending, use_for_receiving, \
                    status, spf_status, spf_error, dkim_status, dkim_error, \
                    dmarc_status, dmarc_error, mx_status, mx_error, \
                    return_path_status, return_path_error, dns_checked_at, \
                    verification_token, verified_at, reject_unknown_recipients, \
                    created_at, updated_at \
             FROM domains WHERE tenant_id = $1 ORDER BY created_at DESC",
            tenant_id.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|r| {
                parse_domain_row(
                    r.id,
                    r.tenant_id,
                    r.domain_name,
                    r.use_for_sending,
                    r.use_for_receiving,
                    r.status,
                    r.spf_status,
                    r.spf_error,
                    r.dkim_status,
                    r.dkim_error,
                    r.dmarc_status,
                    r.dmarc_error,
                    r.mx_status,
                    r.mx_error,
                    r.return_path_status,
                    r.return_path_error,
                    r.dns_checked_at,
                    r.verification_token,
                    r.verified_at,
                    r.reject_unknown_recipients,
                    r.created_at,
                    r.updated_at,
                )
            })
            .collect()
    }

    async fn list_verified(&self) -> Result<Vec<DomainRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, tenant_id, domain_name, use_for_sending, use_for_receiving, \
                    status, spf_status, spf_error, dkim_status, dkim_error, \
                    dmarc_status, dmarc_error, mx_status, mx_error, \
                    return_path_status, return_path_error, dns_checked_at, \
                    verification_token, verified_at, reject_unknown_recipients, \
                    created_at, updated_at \
             FROM domains WHERE status = 'verified' ORDER BY created_at ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|r| {
                parse_domain_row(
                    r.id,
                    r.tenant_id,
                    r.domain_name,
                    r.use_for_sending,
                    r.use_for_receiving,
                    r.status,
                    r.spf_status,
                    r.spf_error,
                    r.dkim_status,
                    r.dkim_error,
                    r.dmarc_status,
                    r.dmarc_error,
                    r.mx_status,
                    r.mx_error,
                    r.return_path_status,
                    r.return_path_error,
                    r.dns_checked_at,
                    r.verification_token,
                    r.verified_at,
                    r.reject_unknown_recipients,
                    r.created_at,
                    r.updated_at,
                )
            })
            .collect()
    }

    async fn update_status(&self, id: DomainId, status: DomainStatus) -> Result<(), SentioError> {
        let status_str = status.to_string();
        let result = sqlx::query!(
            "UPDATE domains SET status = $1 WHERE id = $2",
            status_str,
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "domain",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn update_dns_checks(
        &self,
        id: DomainId,
        update: DnsCheckUpdate,
    ) -> Result<(), SentioError> {
        let result = sqlx::query!(
            "UPDATE domains SET \
                spf_status = $1, spf_error = $2, \
                dkim_status = $3, dkim_error = $4, \
                dmarc_status = $5, dmarc_error = $6, \
                mx_status = $7, mx_error = $8, \
                return_path_status = $9, return_path_error = $10, \
                dns_checked_at = now() \
             WHERE id = $11",
            update.spf_status.to_string(),
            update.spf_error,
            update.dkim_status.to_string(),
            update.dkim_error,
            update.dmarc_status.to_string(),
            update.dmarc_error,
            update.mx_status.to_string(),
            update.mx_error,
            update.return_path_status.to_string(),
            update.return_path_error,
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "domain",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn verify(&self, id: DomainId, token: &str) -> Result<(), SentioError> {
        let result = sqlx::query!(
            "UPDATE domains SET status = 'verified', verified_at = now() \
             WHERE id = $1 AND verification_token = $2 AND status = 'pending'",
            id.0,
            token,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::Validation(
                "domain not found, already verified, or token mismatch".into(),
            ));
        }
        Ok(())
    }

    async fn find_by_domain_name(
        &self,
        domain_name: &str,
    ) -> Result<Option<DomainRecord>, SentioError> {
        let row = sqlx::query!(
            "SELECT id, tenant_id, domain_name, use_for_sending, use_for_receiving, \
                    status, spf_status, spf_error, dkim_status, dkim_error, \
                    dmarc_status, dmarc_error, mx_status, mx_error, \
                    return_path_status, return_path_error, dns_checked_at, \
                    verification_token, verified_at, reject_unknown_recipients, \
                    created_at, updated_at \
             FROM domains WHERE domain_name = $1 AND use_for_receiving = true LIMIT 1",
            domain_name,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        match row {
            Some(r) => Ok(Some(parse_domain_row(
                r.id,
                r.tenant_id,
                r.domain_name,
                r.use_for_sending,
                r.use_for_receiving,
                r.status,
                r.spf_status,
                r.spf_error,
                r.dkim_status,
                r.dkim_error,
                r.dmarc_status,
                r.dmarc_error,
                r.mx_status,
                r.mx_error,
                r.return_path_status,
                r.return_path_error,
                r.dns_checked_at,
                r.verification_token,
                r.verified_at,
                r.reject_unknown_recipients,
                r.created_at,
                r.updated_at,
            )?)),
            None => Ok(None),
        }
    }

    async fn find_by_sending_domain(
        &self,
        domain_name: &str,
    ) -> Result<Option<DomainRecord>, SentioError> {
        let row = sqlx::query!(
            "SELECT id, tenant_id, domain_name, use_for_sending, use_for_receiving, \
                    status, spf_status, spf_error, dkim_status, dkim_error, \
                    dmarc_status, dmarc_error, mx_status, mx_error, \
                    return_path_status, return_path_error, dns_checked_at, \
                    verification_token, verified_at, reject_unknown_recipients, \
                    created_at, updated_at \
             FROM domains WHERE domain_name = $1 AND use_for_sending = true LIMIT 1",
            domain_name,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        match row {
            Some(r) => Ok(Some(parse_domain_row(
                r.id,
                r.tenant_id,
                r.domain_name,
                r.use_for_sending,
                r.use_for_receiving,
                r.status,
                r.spf_status,
                r.spf_error,
                r.dkim_status,
                r.dkim_error,
                r.dmarc_status,
                r.dmarc_error,
                r.mx_status,
                r.mx_error,
                r.return_path_status,
                r.return_path_error,
                r.dns_checked_at,
                r.verification_token,
                r.verified_at,
                r.reject_unknown_recipients,
                r.created_at,
                r.updated_at,
            )?)),
            None => Ok(None),
        }
    }

    async fn update(&self, id: DomainId, update: DomainUpdate) -> Result<(), SentioError> {
        let result = sqlx::query!(
            "UPDATE domains SET use_for_sending = $1, use_for_receiving = $2, \
             reject_unknown_recipients = $3 WHERE id = $4",
            update.use_for_sending,
            update.use_for_receiving,
            update.reject_unknown_recipients,
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "domain",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn delete(&self, id: DomainId) -> Result<(), SentioError> {
        let result = sqlx::query!("DELETE FROM domains WHERE id = $1", id.0)
            .execute(&self.pool)
            .await
            .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "domain",
                id: id.to_string(),
            });
        }
        Ok(())
    }
}
