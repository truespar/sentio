use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use sentio_core::event::MailboxStatus;
use sentio_core::ids::MailboxId;
use sentio_core::message::DomainId;
use sentio_core::traits::{
    DomainRepository, MailboxRecord, MailboxRepository, MailboxUpdate, NewMailbox,
};
use sentio_store::postgres::{PgDomainRepository, PgMailboxRepository};

use crate::auth::AuthContext;
use crate::errors::{ApiError, ErrorResponse};
use crate::response::{data, DataResponse};
use crate::state::AppState;

// ──────────────────────────────────────────────────────────────────────────────
// Request / Response types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateMailboxRequest {
    pub address: String,
    pub display_name: Option<String>,
    #[serde(default)]
    pub forward_to: Vec<String>,
    #[serde(default)]
    pub auto_reply: bool,
    pub auto_reply_subject: Option<String>,
    pub auto_reply_body: Option<String>,
    #[schema(value_type = Object)]
    #[serde(default = "default_metadata")]
    pub metadata: serde_json::Value,
}

fn default_metadata() -> serde_json::Value {
    serde_json::json!({})
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateMailboxRequest {
    pub display_name: Option<String>,
    pub status: MailboxStatus,
    #[serde(default)]
    pub forward_to: Vec<String>,
    #[serde(default)]
    pub auto_reply: bool,
    pub auto_reply_subject: Option<String>,
    pub auto_reply_body: Option<String>,
    #[schema(value_type = Object)]
    #[serde(default = "default_metadata")]
    pub metadata: serde_json::Value,
}

#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct MailboxResponse {
    id: MailboxId,
    domain_id: DomainId,
    address: String,
    display_name: Option<String>,
    status: MailboxStatus,
    forward_to: Vec<String>,
    auto_reply: bool,
    auto_reply_subject: Option<String>,
    auto_reply_body: Option<String>,
    #[schema(value_type = Object)]
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<MailboxRecord> for MailboxResponse {
    fn from(r: MailboxRecord) -> Self {
        Self {
            id: r.id,
            domain_id: r.domain_id,
            address: r.address,
            display_name: r.display_name,
            status: r.status,
            forward_to: r.forward_to,
            auto_reply: r.auto_reply,
            auto_reply_subject: r.auto_reply_subject,
            auto_reply_body: r.auto_reply_body,
            metadata: r.metadata,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// Verify the domain belongs to the authenticated tenant.
async fn verify_domain_ownership(
    state: &AppState,
    auth: &AuthContext,
    domain_id: DomainId,
) -> Result<(), ApiError> {
    let repo = PgDomainRepository::new(state.pool.clone());
    let domain = repo.get(domain_id).await?;
    if domain.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("domain not found".into()));
    }
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/domains/{domain_id}/mailboxes
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/domains/{domain_id}/mailboxes",
    tag = "Mailboxes",
    security(("bearer" = [])),
    params(
        ("domain_id" = uuid::Uuid, Path,),
    ),
    responses(
        (status = 200, body = DataResponse<Vec<MailboxResponse>>),
        (status = 404, body = ErrorResponse),
    ),
)]
pub async fn list_mailboxes(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(domain_id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("domains:read")?;

    let did = DomainId(domain_id);
    verify_domain_ownership(&state, &auth, did).await?;

    let repo = PgMailboxRepository::new(state.pool.clone());
    let records = repo.list_by_domain(did).await?;
    let mailboxes: Vec<MailboxResponse> = records.into_iter().map(Into::into).collect();

    Ok(data(mailboxes))
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/domains/{domain_id}/mailboxes
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/domains/{domain_id}/mailboxes",
    tag = "Mailboxes",
    security(("bearer" = [])),
    params(
        ("domain_id" = uuid::Uuid, Path,),
    ),
    request_body = CreateMailboxRequest,
    responses(
        (status = 200, body = DataResponse<MailboxResponse>),
        (status = 422, body = ErrorResponse),
    ),
)]
pub async fn create_mailbox(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(domain_id): Path<uuid::Uuid>,
    Json(body): Json<CreateMailboxRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("domains:write")?;

    let did = DomainId(domain_id);
    verify_domain_ownership(&state, &auth, did).await?;

    if body.address.is_empty() {
        return Err(ApiError::Validation("address is required".into()));
    }

    let repo = PgMailboxRepository::new(state.pool.clone());
    let record = repo
        .create(NewMailbox {
            domain_id: did,
            tenant_id: auth.tenant_id,
            address: body.address,
            display_name: body.display_name,
            forward_to: body.forward_to,
            auto_reply: body.auto_reply,
            auto_reply_subject: body.auto_reply_subject,
            auto_reply_body: body.auto_reply_body,
            metadata: body.metadata,
        })
        .await?;

    Ok(data(MailboxResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/domains/{domain_id}/mailboxes/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/domains/{domain_id}/mailboxes/{id}",
    tag = "Mailboxes",
    security(("bearer" = [])),
    params(
        ("domain_id" = uuid::Uuid, Path,),
        ("id" = uuid::Uuid, Path,),
    ),
    responses(
        (status = 200, body = DataResponse<MailboxResponse>),
        (status = 404, body = ErrorResponse),
    ),
)]
pub async fn get_mailbox(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((domain_id, id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("domains:read")?;

    let did = DomainId(domain_id);
    verify_domain_ownership(&state, &auth, did).await?;

    let repo = PgMailboxRepository::new(state.pool.clone());
    let record = repo.get(MailboxId(id)).await?;

    if record.domain_id != did {
        return Err(ApiError::NotFound("mailbox not found".into()));
    }

    Ok(data(MailboxResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// PUT /v1/domains/{domain_id}/mailboxes/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    put,
    path = "/v1/domains/{domain_id}/mailboxes/{id}",
    tag = "Mailboxes",
    security(("bearer" = [])),
    params(
        ("domain_id" = uuid::Uuid, Path,),
        ("id" = uuid::Uuid, Path,),
    ),
    request_body = UpdateMailboxRequest,
    responses(
        (status = 200, body = DataResponse<MailboxResponse>),
        (status = 404, body = ErrorResponse),
    ),
)]
pub async fn update_mailbox(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((domain_id, id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(body): Json<UpdateMailboxRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("domains:write")?;

    let did = DomainId(domain_id);
    verify_domain_ownership(&state, &auth, did).await?;

    let repo = PgMailboxRepository::new(state.pool.clone());

    // Verify the mailbox belongs to this domain
    let existing = repo.get(MailboxId(id)).await?;
    if existing.domain_id != did {
        return Err(ApiError::NotFound("mailbox not found".into()));
    }

    repo.update(
        MailboxId(id),
        MailboxUpdate {
            display_name: body.display_name,
            status: body.status,
            forward_to: body.forward_to,
            auto_reply: body.auto_reply,
            auto_reply_subject: body.auto_reply_subject,
            auto_reply_body: body.auto_reply_body,
            metadata: body.metadata,
        },
    )
    .await?;

    let updated = repo.get(MailboxId(id)).await?;
    Ok(data(MailboxResponse::from(updated)))
}

// ──────────────────────────────────────────────────────────────────────────────
// DELETE /v1/domains/{domain_id}/mailboxes/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    delete,
    path = "/v1/domains/{domain_id}/mailboxes/{id}",
    tag = "Mailboxes",
    security(("bearer" = [])),
    params(
        ("domain_id" = uuid::Uuid, Path,),
        ("id" = uuid::Uuid, Path,),
    ),
    responses(
        (status = 204),
        (status = 404, body = ErrorResponse),
    ),
)]
pub async fn delete_mailbox(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((domain_id, id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("domains:write")?;

    let did = DomainId(domain_id);
    verify_domain_ownership(&state, &auth, did).await?;

    let repo = PgMailboxRepository::new(state.pool.clone());

    // Verify the mailbox belongs to this domain
    let existing = repo.get(MailboxId(id)).await?;
    if existing.domain_id != did {
        return Err(ApiError::NotFound("mailbox not found".into()));
    }

    repo.delete(MailboxId(id)).await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}
