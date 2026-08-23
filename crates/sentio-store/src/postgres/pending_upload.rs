use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::error::SentioError;
use sentio_core::ids::PendingUploadId;
use sentio_core::message::ScanStatus;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{NewPendingUpload, PendingUploadRecord, PendingUploadRepository};

pub struct PgPendingUploadRepository {
    pool: PgPool,
}

impl PgPendingUploadRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_pending_upload_row(
    id: Uuid,
    tenant_id: Uuid,
    blob_key: String,
    filename: String,
    content_type: String,
    size: i64,
    checksum_sha256: Option<String>,
    scan_status: String,
    scan_result: Option<String>,
    claimed: bool,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
) -> Result<PendingUploadRecord, SentioError> {
    Ok(PendingUploadRecord {
        id: PendingUploadId(id),
        tenant_id: TenantId(tenant_id),
        // (live DB rename + .sqlx cache regen). Mapped to the new
        // `blob_key` field on the trait record.
        blob_key,
        filename,
        content_type,
        size,
        checksum_sha256,
        scan_status: ScanStatus::from_str(&scan_status)
            .map_err(|_| SentioError::Database(format!("invalid scan_status: {scan_status}")))?,
        scan_result,
        claimed,
        expires_at,
        created_at,
    })
}

impl PendingUploadRepository for PgPendingUploadRepository {
    async fn create(&self, upload: NewPendingUpload) -> Result<PendingUploadId, SentioError> {
        let row = sqlx::query!(
            "INSERT INTO pending_uploads \
                (tenant_id, blob_key, filename, content_type, size, checksum_sha256) \
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
            upload.tenant_id.0,
            upload.blob_key,
            upload.filename,
            upload.content_type,
            upload.size,
            upload.checksum_sha256,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(PendingUploadId(row.id))
    }

    async fn get(&self, id: PendingUploadId) -> Result<PendingUploadRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, tenant_id, blob_key, filename, content_type, size, \
                    checksum_sha256, scan_status, scan_result, claimed, expires_at, created_at \
             FROM pending_uploads WHERE id = $1",
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "pending_upload",
            id: id.to_string(),
        })?;

        parse_pending_upload_row(
            row.id,
            row.tenant_id,
            row.blob_key,
            row.filename,
            row.content_type,
            row.size,
            row.checksum_sha256,
            row.scan_status,
            row.scan_result,
            row.claimed,
            row.expires_at,
            row.created_at,
        )
    }

    async fn claim(&self, id: PendingUploadId) -> Result<(), SentioError> {
        let result = sqlx::query!(
            "UPDATE pending_uploads SET claimed = true WHERE id = $1 AND claimed = false",
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::Validation(
                "pending upload not found or already claimed".into(),
            ));
        }
        Ok(())
    }

    async fn update_scan_status(
        &self,
        id: PendingUploadId,
        scan_status: ScanStatus,
        scan_result: Option<&str>,
    ) -> Result<(), SentioError> {
        let scan_status_str = scan_status.to_string();
        let result = sqlx::query!(
            "UPDATE pending_uploads SET scan_status = $1, scan_result = $2 WHERE id = $3",
            scan_status_str,
            scan_result,
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "pending_upload",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn delete_expired(&self) -> Result<u64, SentioError> {
        let result = sqlx::query!(
            "DELETE FROM pending_uploads WHERE expires_at < now() AND claimed = false"
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }

    async fn list_expired(&self, limit: i64) -> Result<Vec<PendingUploadRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, tenant_id, blob_key, filename, content_type, size, \
                    checksum_sha256, scan_status, scan_result, claimed, expires_at, created_at \
             FROM pending_uploads \
             WHERE expires_at < now() AND claimed = false \
             ORDER BY expires_at ASC \
             LIMIT $1",
            limit,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|row| {
                parse_pending_upload_row(
                    row.id,
                    row.tenant_id,
                    row.blob_key,
                    row.filename,
                    row.content_type,
                    row.size,
                    row.checksum_sha256,
                    row.scan_status,
                    row.scan_result,
                    row.claimed,
                    row.expires_at,
                    row.created_at,
                )
            })
            .collect()
    }
}
