use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::error::SentioError;
use sentio_core::ids::AttachmentId;
use sentio_core::message::{AttachmentDisposition, MessageId, ScanStatus};
use sentio_core::tenant::TenantId;
use sentio_core::traits::{AttachmentRecord, MessageAttachmentRepository, NewAttachment};

pub struct PgMessageAttachmentRepository {
    pool: PgPool,
}

impl PgMessageAttachmentRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_attachment_row(
    id: Uuid,
    message_id: Uuid,
    tenant_id: Uuid,
    filename: String,
    content_type: String,
    size: i64,
    content_id: Option<String>,
    disposition: String,
    blob_key: String,
    checksum_sha256: Option<String>,
    scan_status: String,
    scan_result: Option<String>,
    created_at: DateTime<Utc>,
) -> Result<AttachmentRecord, SentioError> {
    Ok(AttachmentRecord {
        id: AttachmentId(id),
        message_id: MessageId(message_id),
        tenant_id: TenantId(tenant_id),
        filename,
        content_type,
        size,
        content_id,
        disposition: AttachmentDisposition::from_str(&disposition)
            .map_err(|_| SentioError::Database(format!("invalid disposition: {disposition}")))?,
        // (live DB rename + .sqlx cache regen). Mapped to the new
        // `blob_key` field on the trait record.
        blob_key,
        checksum_sha256,
        scan_status: ScanStatus::from_str(&scan_status)
            .map_err(|_| SentioError::Database(format!("invalid scan_status: {scan_status}")))?,
        scan_result,
        created_at,
    })
}

impl MessageAttachmentRepository for PgMessageAttachmentRepository {
    async fn insert(&self, attachment: NewAttachment) -> Result<AttachmentId, SentioError> {
        let id = AttachmentId::new();
        let disposition_str = attachment.disposition.to_string();

        sqlx::query!(
            "INSERT INTO message_attachments \
                (id, message_id, tenant_id, filename, content_type, size, content_id, \
                 disposition, blob_key, checksum_sha256) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            id.0,
            attachment.message_id.0,
            attachment.tenant_id.0,
            attachment.filename,
            attachment.content_type,
            attachment.size,
            attachment.content_id,
            disposition_str,
            attachment.blob_key,
            attachment.checksum_sha256,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(id)
    }

    async fn list_by_message(
        &self,
        message_id: MessageId,
    ) -> Result<Vec<AttachmentRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, message_id, tenant_id, filename, content_type, size, content_id, \
                    disposition, blob_key, checksum_sha256, scan_status, scan_result, \
                    created_at \
             FROM message_attachments WHERE message_id = $1 ORDER BY created_at ASC",
            message_id.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|r| {
                parse_attachment_row(
                    r.id,
                    r.message_id,
                    r.tenant_id,
                    r.filename,
                    r.content_type,
                    r.size,
                    r.content_id,
                    r.disposition,
                    r.blob_key,
                    r.checksum_sha256,
                    r.scan_status,
                    r.scan_result,
                    r.created_at,
                )
            })
            .collect()
    }

    async fn update_scan_status(
        &self,
        id: AttachmentId,
        scan_status: ScanStatus,
        scan_result: Option<&str>,
    ) -> Result<(), SentioError> {
        let status_str = scan_status.to_string();
        let result = sqlx::query!(
            "UPDATE message_attachments SET scan_status = $1, scan_result = $2 WHERE id = $3",
            status_str,
            scan_result,
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "attachment",
                id: id.to_string(),
            });
        }
        Ok(())
    }
}
