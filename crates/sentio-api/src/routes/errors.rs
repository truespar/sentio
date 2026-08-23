use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use sentio_core::ids::ErrorEventId;
use sentio_core::traits::{ErrorEventFilter, ErrorEventRecord, ErrorEventRepository};
use sentio_store::postgres::PgErrorEventRepository;

use crate::auth::AuthContext;
use crate::errors::{ApiError, ErrorResponse};
use crate::response::{data, DataResponse};
use crate::state::AppState;

// ──────────────────────────────────────────────────────────────────────────────
// Response types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
pub struct ErrorEventResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub severity: String,
    pub component: String,
    pub error_type: String,
    pub message: String,
    pub stack_trace: Option<String>,
    pub message_id: Option<Uuid>,
    pub request_id: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

impl From<ErrorEventRecord> for ErrorEventResponse {
    fn from(r: ErrorEventRecord) -> Self {
        Self {
            id: r.id.0,
            tenant_id: r.tenant_id.0,
            severity: r.severity.to_string(),
            component: r.component.to_string(),
            error_type: r.error_type.to_string(),
            message: r.message,
            stack_trace: r.stack_trace,
            message_id: r.message_id,
            request_id: r.request_id,
            metadata: r.metadata,
            created_at: r.created_at,
        }
    }
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct ErrorSummaryResponse {
    pub component: String,
    pub severity: String,
    pub count: i64,
}

// ──────────────────────────────────────────────────────────────────────────────
// Query params
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::IntoParams)]
pub struct ListErrorsParams {
    pub severity: Option<String>,
    pub component: Option<String>,
    pub error_type: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Deserialize, utoipa::IntoParams)]
pub struct SummaryParams {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Handlers
// ──────────────────────────────────────────────────────────────────────────────

/// GET /v1/admin/errors -- list error events.
#[utoipa::path(
    get,
    path = "/v1/admin/errors",
    tag = "Errors",
    security(("bearer" = [])),
    params(ListErrorsParams),
    responses(
        (status = 200, body = DataResponse<Vec<ErrorEventResponse>>),
        (status = 401, body = ErrorResponse),
    )
)]
pub async fn list_errors(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<ListErrorsParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:errors")?;

    let repo = PgErrorEventRepository::new(state.pool.clone());

    let filter = ErrorEventFilter {
        severity: params.severity.and_then(|s| s.parse().ok()),
        component: params.component.and_then(|c| c.parse().ok()),
        error_type: params.error_type.and_then(|e| e.parse().ok()),
        from: params.from,
        to: params.to,
        limit: params.limit.min(1000),
        offset: params.offset,
    };

    let records = repo.list(auth.tenant_id, filter).await?;
    let response: Vec<ErrorEventResponse> = records.into_iter().map(Into::into).collect();

    Ok(data(response))
}

/// GET /v1/admin/errors/summary -- error event summary grouped by component and severity.
#[utoipa::path(
    get,
    path = "/v1/admin/errors/summary",
    tag = "Errors",
    security(("bearer" = [])),
    params(SummaryParams),
    responses(
        (status = 200, body = DataResponse<Vec<ErrorSummaryResponse>>),
        (status = 401, body = ErrorResponse),
    )
)]
pub async fn error_summary(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<SummaryParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:errors")?;

    let repo = PgErrorEventRepository::new(state.pool.clone());

    let from = params
        .from
        .unwrap_or_else(|| Utc::now() - chrono::Duration::hours(24));
    let to = params.to.unwrap_or_else(Utc::now);

    let summaries = repo.summary(auth.tenant_id, from, to).await?;
    let response: Vec<ErrorSummaryResponse> = summaries
        .into_iter()
        .map(|s| ErrorSummaryResponse {
            component: s.component,
            severity: s.severity,
            count: s.count,
        })
        .collect();

    Ok(data(response))
}

/// GET /v1/admin/errors/{id} -- get a single error event.
#[utoipa::path(
    get,
    path = "/v1/admin/errors/{id}",
    tag = "Errors",
    security(("bearer" = [])),
    params(("id" = Uuid, Path,)),
    responses(
        (status = 200, body = DataResponse<ErrorEventResponse>),
        (status = 401, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
    )
)]
pub async fn get_error(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:errors")?;

    let repo = PgErrorEventRepository::new(state.pool.clone());
    let record = repo.get(ErrorEventId(id)).await?;

    Ok(data(ErrorEventResponse::from(record)))
}
