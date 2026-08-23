use std::str::FromStr;

use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::error::SentioError;
use sentio_core::ids::FblReportId;
use sentio_core::message::MessageId;
use sentio_core::report::ComplaintType;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{FblReportRecord, FblReportRepository, NewFblReport};

pub struct PgFblReportRepository {
    pool: PgPool,
}

impl PgFblReportRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_fbl_report_row(
    id: Uuid,
    tenant_id: Uuid,
    original_message_id: Option<Uuid>,
    original_message_id_hdr: Option<String>,
    complained_recipient: String,
    complaint_type: String,
    feedback_type: Option<String>,
    source_ip: Option<IpNetwork>,
    arrival_date: Option<DateTime<Utc>>,
    report_raw: Option<String>,
    auto_suppressed: bool,
    processed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
) -> Result<FblReportRecord, SentioError> {
    Ok(FblReportRecord {
        id: FblReportId(id),
        tenant_id: TenantId(tenant_id),
        original_message_id: original_message_id.map(MessageId),
        original_message_id_hdr,
        complained_recipient,
        complaint_type: ComplaintType::from_str(&complaint_type).map_err(|_| {
            SentioError::Database(format!("invalid complaint_type: {complaint_type}"))
        })?,
        feedback_type,
        source_ip: source_ip.map(|ip| ip.ip()),
        arrival_date,
        report_raw,
        auto_suppressed,
        processed_at,
        created_at,
    })
}

impl FblReportRepository for PgFblReportRepository {
    async fn insert(&self, report: NewFblReport) -> Result<FblReportId, SentioError> {
        let complaint_type_str = report.complaint_type.to_string();
        let source_ip = report.source_ip.map(IpNetwork::from);
        let row = sqlx::query!(
            "INSERT INTO fbl_reports \
                (tenant_id, original_message_id, original_message_id_hdr, \
                 complained_recipient, complaint_type, feedback_type, \
                 source_ip, arrival_date, report_raw, auto_suppressed) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id",
            report.tenant_id.0,
            report.original_message_id.map(|m| m.0),
            report.original_message_id_hdr,
            report.complained_recipient,
            complaint_type_str,
            report.feedback_type,
            source_ip,
            report.arrival_date,
            report.report_raw,
            report.auto_suppressed,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(FblReportId(row.id))
    }

    async fn get(&self, id: FblReportId) -> Result<FblReportRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, tenant_id, original_message_id, original_message_id_hdr, \
                    complained_recipient, complaint_type, feedback_type, \
                    source_ip, arrival_date, report_raw, auto_suppressed, \
                    processed_at, created_at \
             FROM fbl_reports WHERE id = $1",
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "fbl_report",
            id: id.to_string(),
        })?;

        parse_fbl_report_row(
            row.id,
            row.tenant_id,
            row.original_message_id,
            row.original_message_id_hdr,
            row.complained_recipient,
            row.complaint_type,
            row.feedback_type,
            row.source_ip,
            row.arrival_date,
            row.report_raw,
            row.auto_suppressed,
            row.processed_at,
            row.created_at,
        )
    }

    async fn list_by_tenant(
        &self,
        tenant_id: TenantId,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<FblReportRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, tenant_id, original_message_id, original_message_id_hdr, \
                    complained_recipient, complaint_type, feedback_type, \
                    source_ip, arrival_date, report_raw, auto_suppressed, \
                    processed_at, created_at \
             FROM fbl_reports WHERE tenant_id = $1 \
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
                parse_fbl_report_row(
                    r.id,
                    r.tenant_id,
                    r.original_message_id,
                    r.original_message_id_hdr,
                    r.complained_recipient,
                    r.complaint_type,
                    r.feedback_type,
                    r.source_ip,
                    r.arrival_date,
                    r.report_raw,
                    r.auto_suppressed,
                    r.processed_at,
                    r.created_at,
                )
            })
            .collect()
    }

    async fn mark_processed(&self, id: FblReportId) -> Result<(), SentioError> {
        let result = sqlx::query!(
            "UPDATE fbl_reports SET processed_at = now() WHERE id = $1 AND processed_at IS NULL",
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "fbl_report",
                id: id.to_string(),
            });
        }
        Ok(())
    }
}
