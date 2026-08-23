use axum::extract::{Path, State};
use axum::http::header;
use axum::response::IntoResponse;
use chrono::{DateTime, Utc};
use serde::Serialize;

use sentio_core::ids::AttachmentId;
use sentio_core::message::{AttachmentDisposition, MessageId, ScanStatus};
use sentio_core::traits::{
    AttachmentRecord, BlobStore, MessageAttachmentRepository, MessageRepository,
};
use sentio_store::postgres::{PgMessageAttachmentRepository, PgMessageRepository};

use crate::auth::AuthContext;
use crate::errors::{ApiError, ErrorResponse};
use crate::response::{data, DataResponse};
use crate::state::AppState;

// ──────────────────────────────────────────────────────────────────────────────
// Response types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
struct AttachmentResponse {
    id: AttachmentId,
    message_id: MessageId,
    filename: String,
    content_type: String,
    size: i64,
    content_id: Option<String>,
    disposition: AttachmentDisposition,
    scan_status: ScanStatus,
    scan_result: Option<String>,
    created_at: DateTime<Utc>,
}

impl From<AttachmentRecord> for AttachmentResponse {
    fn from(r: AttachmentRecord) -> Self {
        Self {
            id: r.id,
            message_id: r.message_id,
            filename: r.filename,
            content_type: r.content_type,
            size: r.size,
            content_id: r.content_id,
            disposition: r.disposition,
            scan_status: r.scan_status,
            scan_result: r.scan_result,
            created_at: r.created_at,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/messages/:id/attachments
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/messages/{id}/attachments",
    tag = "Messages",
    security(("bearer" = [])),
    params(
        ("id" = uuid::Uuid, Path, description = "Message ID"),
    ),
    responses(
        (status = 200, body = DataResponse<Vec<AttachmentResponse>>),
    ),
)]
pub async fn list_attachments(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(message_id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("messages:read")?;

    // Verify message belongs to tenant
    let msg_repo = PgMessageRepository::new(state.pool.clone());
    msg_repo.get(auth.tenant_id, MessageId(message_id)).await?;

    // Fetch attachments
    let att_repo = PgMessageAttachmentRepository::new(state.pool.clone());
    let records = att_repo.list_by_message(MessageId(message_id)).await?;
    let attachments: Vec<AttachmentResponse> = records.into_iter().map(Into::into).collect();

    Ok(data(attachments))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/messages/:message_id/attachments/:attachment_id
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/messages/{message_id}/attachments/{attachment_id}",
    tag = "Messages",
    security(("bearer" = [])),
    params(
        ("message_id" = uuid::Uuid, Path,),
        ("attachment_id" = uuid::Uuid, Path,),
    ),
    responses(
        (status = 200, content_type = "application/octet-stream"),
        (status = 404, body = ErrorResponse),
    ),
)]
pub async fn download_attachment(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((message_id, attachment_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("messages:read")?;

    // Verify message belongs to tenant
    let msg_repo = PgMessageRepository::new(state.pool.clone());
    msg_repo.get(auth.tenant_id, MessageId(message_id)).await?;

    // Find the attachment
    let att_repo = PgMessageAttachmentRepository::new(state.pool.clone());
    let attachments = att_repo.list_by_message(MessageId(message_id)).await?;
    let attachment = attachments
        .into_iter()
        .find(|a| a.id == AttachmentId(attachment_id))
        .ok_or_else(|| ApiError::NotFound(format!("attachment not found: {attachment_id}")))?;

    // Download blob from the S3-compatible store
    let blob_data = state.blob_store.download(&attachment.blob_key).await?;

    Ok((
        [
            (header::CONTENT_TYPE, attachment.content_type),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", attachment.filename),
            ),
        ],
        blob_data,
    ))
}
