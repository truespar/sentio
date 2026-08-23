use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use sentio_core::ids::SuppressionId;
use sentio_core::message::SuppressionReason;
use sentio_core::traits::{NewSuppression, SuppressionRecord, SuppressionRepository};
use sentio_store::postgres::PgSuppressionRepository;

use crate::auth::AuthContext;
use crate::errors::{ApiError, ErrorResponse};
use crate::extract::PaginationParams;
use crate::response::{data, DataResponse};
use crate::state::AppState;

// ──────────────────────────────────────────────────────────────────────────────
// Request / Response types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
pub struct AddSuppressionRequest {
    pub email: String,
    pub reason: SuppressionReason,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CheckSuppressionRequest {
    pub email: String,
}

#[derive(Serialize, utoipa::ToSchema)]
struct SuppressionResponse {
    id: SuppressionId,
    email: String,
    reason: SuppressionReason,
    created_at: DateTime<Utc>,
}

impl From<SuppressionRecord> for SuppressionResponse {
    fn from(r: SuppressionRecord) -> Self {
        Self {
            id: r.id,
            email: r.email,
            reason: r.reason,
            created_at: r.created_at,
        }
    }
}

#[derive(Serialize, utoipa::ToSchema)]
struct CheckResponse {
    email: String,
    suppressed: bool,
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/suppressions
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/suppressions",
    tag = "Suppressions",
    security(("bearer" = [])),
    request_body = AddSuppressionRequest,
    responses(
        (status = 200, body = DataResponse<SuppressionResponse>),
    ),
)]
pub async fn add_suppression(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(body): Json<AddSuppressionRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("suppressions:write")?;

    if body.email.is_empty() {
        return Err(ApiError::Validation("email is required".into()));
    }

    let repo = PgSuppressionRepository::new(state.pool.clone());
    let _id = repo
        .add(NewSuppression {
            tenant_id: auth.tenant_id,
            email: body.email.clone(),
            reason: body.reason,
            source_event_id: None,
        })
        .await?;

    let record = repo.get(auth.tenant_id, &body.email).await?;
    Ok(data(SuppressionResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/suppressions
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/suppressions",
    tag = "Suppressions",
    security(("bearer" = [])),
    params(PaginationParams),
    responses(
        (status = 200, body = DataResponse<Vec<SuppressionResponse>>),
    ),
)]
pub async fn list_suppressions(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<PaginationParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("suppressions:read")?;

    let params = params.validated();
    let repo = PgSuppressionRepository::new(state.pool.clone());
    let records = repo
        .list_by_tenant(auth.tenant_id, params.limit, params.offset)
        .await?;
    let suppressions: Vec<SuppressionResponse> = records.into_iter().map(Into::into).collect();

    Ok(data(suppressions))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/suppressions/{email}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/suppressions/{email}",
    tag = "Suppressions",
    security(("bearer" = [])),
    params(("email" = String, Path,)),
    responses(
        (status = 200, body = DataResponse<SuppressionResponse>),
        (status = 404, body = ErrorResponse),
    ),
)]
pub async fn get_suppression(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(email): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("suppressions:read")?;

    let repo = PgSuppressionRepository::new(state.pool.clone());
    let record = repo.get(auth.tenant_id, &email).await?;

    Ok(data(SuppressionResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// DELETE /v1/suppressions/{email}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    delete,
    path = "/v1/suppressions/{email}",
    tag = "Suppressions",
    security(("bearer" = [])),
    params(("email" = String, Path,)),
    responses(
        (status = 204),
    ),
)]
pub async fn remove_suppression(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(email): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("suppressions:write")?;

    let repo = PgSuppressionRepository::new(state.pool.clone());
    repo.remove(auth.tenant_id, &email).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/suppressions/check
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/suppressions/check",
    tag = "Suppressions",
    security(("bearer" = [])),
    request_body = CheckSuppressionRequest,
    responses(
        (status = 200, body = DataResponse<CheckResponse>),
    ),
)]
pub async fn check_suppression(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(body): Json<CheckSuppressionRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("suppressions:read")?;

    let repo = PgSuppressionRepository::new(state.pool.clone());
    let suppressed = repo.check(auth.tenant_id, &body.email).await?;

    Ok(data(CheckResponse {
        email: body.email,
        suppressed,
    }))
}
