use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::error::SentioError;
use sentio_core::ids::TlsrptReportId;
use sentio_core::message::{DomainId, MessageDirection};
use sentio_core::report::TlsrptPolicyType;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{NewTlsrptReport, TlsrptReportRecord, TlsrptReportRepository};

pub struct PgTlsrptReportRepository {
    pool: PgPool,
}

impl PgTlsrptReportRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_tlsrpt_report_row(
    id: Uuid,
    tenant_id: Uuid,
    domain_id: Uuid,
    direction: String,
    report_id: String,
    org_name: Option<String>,
    date_begin: DateTime<Utc>,
    date_end: DateTime<Utc>,
    policy_type: String,
    policy_domain: Option<String>,
    total_success: i32,
    total_failure: i32,
    failure_details: Option<serde_json::Value>,
    created_at: DateTime<Utc>,
) -> Result<TlsrptReportRecord, SentioError> {
    Ok(TlsrptReportRecord {
        id: TlsrptReportId(id),
        tenant_id: TenantId(tenant_id),
        domain_id: DomainId(domain_id),
        direction: MessageDirection::from_str(&direction)
            .map_err(|_| SentioError::Database(format!("invalid direction: {direction}")))?,
        report_id,
        org_name,
        date_begin,
        date_end,
        policy_type: TlsrptPolicyType::from_str(&policy_type)
            .map_err(|_| SentioError::Database(format!("invalid policy_type: {policy_type}")))?,
        policy_domain,
        total_success,
        total_failure,
        failure_details,
        created_at,
    })
}

impl TlsrptReportRepository for PgTlsrptReportRepository {
    async fn insert(&self, report: NewTlsrptReport) -> Result<TlsrptReportId, SentioError> {
        let direction_str = report.direction.to_string();
        let policy_type_str = report.policy_type.to_string();
        let row = sqlx::query!(
            "INSERT INTO tlsrpt_reports \
                (tenant_id, domain_id, direction, report_id, org_name, \
                 date_begin, date_end, policy_type, policy_domain, \
                 total_success, total_failure, failure_details) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id",
            report.tenant_id.0,
            report.domain_id.0,
            direction_str,
            report.report_id,
            report.org_name,
            report.date_begin,
            report.date_end,
            policy_type_str,
            report.policy_domain,
            report.total_success,
            report.total_failure,
            report.failure_details,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(TlsrptReportId(row.id))
    }

    async fn get(&self, id: TlsrptReportId) -> Result<TlsrptReportRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, tenant_id, domain_id, direction, report_id, org_name, \
                    date_begin, date_end, policy_type, policy_domain, \
                    total_success, total_failure, failure_details, created_at \
             FROM tlsrpt_reports WHERE id = $1",
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "tlsrpt_report",
            id: id.to_string(),
        })?;

        parse_tlsrpt_report_row(
            row.id,
            row.tenant_id,
            row.domain_id,
            row.direction,
            row.report_id,
            row.org_name,
            row.date_begin,
            row.date_end,
            row.policy_type,
            row.policy_domain,
            row.total_success,
            row.total_failure,
            row.failure_details,
            row.created_at,
        )
    }

    async fn list_by_domain(
        &self,
        domain_id: DomainId,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<TlsrptReportRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, tenant_id, domain_id, direction, report_id, org_name, \
                    date_begin, date_end, policy_type, policy_domain, \
                    total_success, total_failure, failure_details, created_at \
             FROM tlsrpt_reports WHERE domain_id = $1 \
             ORDER BY date_begin DESC LIMIT $2 OFFSET $3",
            domain_id.0,
            limit,
            offset,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|r| {
                parse_tlsrpt_report_row(
                    r.id,
                    r.tenant_id,
                    r.domain_id,
                    r.direction,
                    r.report_id,
                    r.org_name,
                    r.date_begin,
                    r.date_end,
                    r.policy_type,
                    r.policy_domain,
                    r.total_success,
                    r.total_failure,
                    r.failure_details,
                    r.created_at,
                )
            })
            .collect()
    }

    async fn list_by_tenant(
        &self,
        tenant_id: TenantId,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<TlsrptReportRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, tenant_id, domain_id, direction, report_id, org_name, \
                    date_begin, date_end, policy_type, policy_domain, \
                    total_success, total_failure, failure_details, created_at \
             FROM tlsrpt_reports WHERE tenant_id = $1 \
             ORDER BY date_begin DESC LIMIT $2 OFFSET $3",
            tenant_id.0,
            limit,
            offset,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|r| {
                parse_tlsrpt_report_row(
                    r.id,
                    r.tenant_id,
                    r.domain_id,
                    r.direction,
                    r.report_id,
                    r.org_name,
                    r.date_begin,
                    r.date_end,
                    r.policy_type,
                    r.policy_domain,
                    r.total_success,
                    r.total_failure,
                    r.failure_details,
                    r.created_at,
                )
            })
            .collect()
    }
}
