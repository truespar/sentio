use std::str::FromStr;

use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::error::SentioError;
use sentio_core::ids::DmarcReportId;
use sentio_core::message::{DomainId, MessageDirection};
use sentio_core::tenant::TenantId;
use sentio_core::traits::{DmarcReportRecord, DmarcReportRepository, NewDmarcReport};

pub struct PgDmarcReportRepository {
    pool: PgPool,
}

impl PgDmarcReportRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_dmarc_report_row(
    id: Uuid,
    tenant_id: Uuid,
    domain_id: Uuid,
    direction: String,
    report_id: String,
    org_name: Option<String>,
    date_begin: DateTime<Utc>,
    date_end: DateTime<Utc>,
    source_ip: Option<IpNetwork>,
    report_xml: Option<String>,
    total_count: i32,
    dkim_pass: i32,
    dkim_fail: i32,
    spf_pass: i32,
    spf_fail: i32,
    dmarc_pass: i32,
    dmarc_fail: i32,
    created_at: DateTime<Utc>,
) -> Result<DmarcReportRecord, SentioError> {
    Ok(DmarcReportRecord {
        id: DmarcReportId(id),
        tenant_id: TenantId(tenant_id),
        domain_id: DomainId(domain_id),
        direction: MessageDirection::from_str(&direction)
            .map_err(|_| SentioError::Database(format!("invalid direction: {direction}")))?,
        report_id,
        org_name,
        date_begin,
        date_end,
        source_ip: source_ip.map(|ip| ip.ip()),
        report_xml,
        total_count,
        dkim_pass,
        dkim_fail,
        spf_pass,
        spf_fail,
        dmarc_pass,
        dmarc_fail,
        created_at,
    })
}

impl DmarcReportRepository for PgDmarcReportRepository {
    async fn insert(&self, report: NewDmarcReport) -> Result<DmarcReportId, SentioError> {
        let direction_str = report.direction.to_string();
        let source_ip = report.source_ip.map(IpNetwork::from);
        let row = sqlx::query!(
            "INSERT INTO dmarc_reports \
                (tenant_id, domain_id, direction, report_id, org_name, \
                 date_begin, date_end, source_ip, report_xml, \
                 total_count, dkim_pass, dkim_fail, spf_pass, spf_fail, \
                 dmarc_pass, dmarc_fail) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) \
             RETURNING id",
            report.tenant_id.0,
            report.domain_id.0,
            direction_str,
            report.report_id,
            report.org_name,
            report.date_begin,
            report.date_end,
            source_ip,
            report.report_xml,
            report.total_count,
            report.dkim_pass,
            report.dkim_fail,
            report.spf_pass,
            report.spf_fail,
            report.dmarc_pass,
            report.dmarc_fail,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(DmarcReportId(row.id))
    }

    async fn get(&self, id: DmarcReportId) -> Result<DmarcReportRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, tenant_id, domain_id, direction, report_id, org_name, \
                    date_begin, date_end, source_ip, report_xml, \
                    total_count, dkim_pass, dkim_fail, spf_pass, spf_fail, \
                    dmarc_pass, dmarc_fail, created_at \
             FROM dmarc_reports WHERE id = $1",
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "dmarc_report",
            id: id.to_string(),
        })?;

        parse_dmarc_report_row(
            row.id,
            row.tenant_id,
            row.domain_id,
            row.direction,
            row.report_id,
            row.org_name,
            row.date_begin,
            row.date_end,
            row.source_ip,
            row.report_xml,
            row.total_count,
            row.dkim_pass,
            row.dkim_fail,
            row.spf_pass,
            row.spf_fail,
            row.dmarc_pass,
            row.dmarc_fail,
            row.created_at,
        )
    }

    async fn list_by_domain(
        &self,
        domain_id: DomainId,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DmarcReportRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, tenant_id, domain_id, direction, report_id, org_name, \
                    date_begin, date_end, source_ip, report_xml, \
                    total_count, dkim_pass, dkim_fail, spf_pass, spf_fail, \
                    dmarc_pass, dmarc_fail, created_at \
             FROM dmarc_reports WHERE domain_id = $1 \
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
                parse_dmarc_report_row(
                    r.id,
                    r.tenant_id,
                    r.domain_id,
                    r.direction,
                    r.report_id,
                    r.org_name,
                    r.date_begin,
                    r.date_end,
                    r.source_ip,
                    r.report_xml,
                    r.total_count,
                    r.dkim_pass,
                    r.dkim_fail,
                    r.spf_pass,
                    r.spf_fail,
                    r.dmarc_pass,
                    r.dmarc_fail,
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
    ) -> Result<Vec<DmarcReportRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, tenant_id, domain_id, direction, report_id, org_name, \
                    date_begin, date_end, source_ip, report_xml, \
                    total_count, dkim_pass, dkim_fail, spf_pass, spf_fail, \
                    dmarc_pass, dmarc_fail, created_at \
             FROM dmarc_reports WHERE tenant_id = $1 \
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
                parse_dmarc_report_row(
                    r.id,
                    r.tenant_id,
                    r.domain_id,
                    r.direction,
                    r.report_id,
                    r.org_name,
                    r.date_begin,
                    r.date_end,
                    r.source_ip,
                    r.report_xml,
                    r.total_count,
                    r.dkim_pass,
                    r.dkim_fail,
                    r.spf_pass,
                    r.spf_fail,
                    r.dmarc_pass,
                    r.dmarc_fail,
                    r.created_at,
                )
            })
            .collect()
    }
}
