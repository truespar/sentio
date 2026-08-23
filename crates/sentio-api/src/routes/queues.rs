use axum::extract::{Query, State};
use axum::response::IntoResponse;
use chrono::{Duration, Utc};
use sentio_abuse::KvConn;
use serde::{Deserialize, Serialize};

use sentio_core::message::MessageStatus;
use sentio_core::traits::{MessageFilter, MessageRecord, MessageRepository};
use sentio_store::postgres::PgMessageRepository;

use crate::auth::AuthContext;
use crate::errors::ApiError;
use crate::extract::PaginationParams;
use crate::response::{data, DataResponse};
use crate::state::AppState;

// ──────────────────────────────────────────────────────────────────────────────
// Response types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
struct StatusCountResponse {
    status: String,
    count: i64,
}

#[derive(Serialize, utoipa::ToSchema)]
struct QueueStatsResponse {
    counts: Vec<StatusCountResponse>,
    paused: bool,
}

#[derive(Serialize, utoipa::ToSchema)]
struct PauseResponse {
    paused: bool,
}

#[derive(Serialize, utoipa::ToSchema)]
struct DeferredMessageResponse {
    id: sentio_core::message::MessageId,
    envelope_from: String,
    envelope_to: Vec<String>,
    subject: Option<String>,
    status: MessageStatus,
    created_at: chrono::DateTime<Utc>,
}

impl From<MessageRecord> for DeferredMessageResponse {
    fn from(r: MessageRecord) -> Self {
        Self {
            id: r.id,
            envelope_from: r.envelope_from,
            envelope_to: r.envelope_to,
            subject: r.subject,
            status: r.status,
            created_at: r.created_at,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Query params for stats
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::IntoParams)]
pub struct StatsParams {
    pub from: Option<chrono::DateTime<Utc>>,
    pub to: Option<chrono::DateTime<Utc>>,
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/queues/stats
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/queues/stats",
    tag = "Queues",
    security(("bearer" = [])),
    params(StatsParams),
    responses(
        (status = 200, body = DataResponse<QueueStatsResponse>),
    ),
)]
pub async fn queue_stats(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<StatsParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("queues:read")?;

    let to = params.to.unwrap_or_else(Utc::now);
    let from = params.from.unwrap_or_else(|| to - Duration::hours(24));

    let msg_repo = PgMessageRepository::new(state.pool.clone());
    let counts = msg_repo.count_by_status(auth.tenant_id, from, to).await?;

    let counts_response: Vec<StatusCountResponse> = counts
        .into_iter()
        .map(|c| StatusCountResponse {
            status: c.status,
            count: c.count,
        })
        .collect();

    // Check if queue is paused
    let paused = is_paused(&state, auth.tenant_id).await;

    Ok(data(QueueStatsResponse {
        counts: counts_response,
        paused,
    }))
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/queues/pause
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/queues/pause",
    tag = "Queues",
    security(("bearer" = [])),
    responses(
        (status = 200, body = DataResponse<PauseResponse>),
    ),
)]
pub async fn pause_queue(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("queues:write")?;

    let kv = state
        .kv
        .as_ref()
        .ok_or_else(|| ApiError::Internal("KV backend not configured".into()))?;

    let key = pause_key(auth.tenant_id);
    // 0 secs = no expiry. Pause persists until explicit resume.
    kv.set_ex(&key, "1", 0)
        .await
        .map_err(|e| ApiError::Internal(format!("KV error: {e}")))?;

    tracing::info!(tenant_id = %auth.tenant_id, "queue paused");

    Ok(data(PauseResponse { paused: true }))
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/queues/resume
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/queues/resume",
    tag = "Queues",
    security(("bearer" = [])),
    responses(
        (status = 200, body = DataResponse<PauseResponse>),
    ),
)]
pub async fn resume_queue(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("queues:write")?;

    let kv = state
        .kv
        .as_ref()
        .ok_or_else(|| ApiError::Internal("KV backend not configured".into()))?;

    let key = pause_key(auth.tenant_id);
    kv.del(&key)
        .await
        .map_err(|e| ApiError::Internal(format!("KV error: {e}")))?;

    tracing::info!(tenant_id = %auth.tenant_id, "queue resumed");

    Ok(data(PauseResponse { paused: false }))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/queues/deferred
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/queues/deferred",
    tag = "Queues",
    security(("bearer" = [])),
    params(PaginationParams),
    responses(
        (status = 200, body = DataResponse<Vec<DeferredMessageResponse>>),
    ),
)]
pub async fn list_deferred(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<PaginationParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("queues:read")?;

    let params = params.validated();
    let to = Utc::now();
    let from = to - Duration::days(7);

    let filter = MessageFilter {
        status: Some(MessageStatus::Deferred),
        direction: None,
        from,
        to,
        limit: params.limit,
        offset: params.offset,
    };

    let msg_repo = PgMessageRepository::new(state.pool.clone());
    let records = msg_repo.list(auth.tenant_id, filter).await?;
    let deferred: Vec<DeferredMessageResponse> = records.into_iter().map(Into::into).collect();

    Ok(data(deferred))
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

fn pause_key(tenant_id: sentio_core::tenant::TenantId) -> String {
    format!("queue:pause:{}", tenant_id)
}

async fn is_paused(state: &AppState, tenant_id: sentio_core::tenant::TenantId) -> bool {
    let Some(kv) = &state.kv else {
        return false;
    };
    let key = pause_key(tenant_id);
    kv.exists(&key).await.unwrap_or(false)
}
