use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use sentio_core::tenant::{TenantId, TenantStatus, TenantTier};
use sentio_core::traits::{TenantRecord, TenantRepository, TenantUpdate};
use sentio_store::postgres::PgTenantRepository;

use crate::auth::AuthContext;
use crate::errors::{ApiError, ErrorResponse};
use crate::response::{data, DataResponse};
use crate::state::AppState;

// ──────────────────────────────────────────────────────────────────────────────
// Request / Response types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateTenantRequest {
    pub name: String,
    #[serde(default = "default_tier")]
    pub tier: TenantTier,
}

fn default_tier() -> TenantTier {
    TenantTier::SharedStandard
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateTenantStatusRequest {
    pub status: TenantStatus,
}

#[derive(Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
pub struct ListTenantsParams {
    pub status: Option<TenantStatus>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Serialize, utoipa::ToSchema)]
struct TenantResponse {
    id: TenantId,
    name: String,
    tier: TenantTier,
    status: TenantStatus,
    /// When `true`, outbound MAIL FROM is rewritten to a VERP bounce return
    /// path so DSN bounces route back to the message that generated them.
    verp_enabled: bool,
}

impl From<TenantRecord> for TenantResponse {
    fn from(r: TenantRecord) -> Self {
        Self {
            id: r.id,
            name: r.name,
            tier: r.tier,
            status: r.status,
            verp_enabled: r.verp_enabled,
        }
    }
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateTenantRequest {
    pub name: Option<String>,
    pub tier: Option<TenantTier>,
    /// Opt this tenant in/out of VERP bounce return-path rewriting.
    /// When `Some(true)`, the tenant must also publish `bounce.{domain}`
    /// MX/CNAME records pointing at this server - see the DNS-records API.
    pub verp_enabled: Option<bool>,
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/tenants
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/tenants",
    tag = "Tenants",
    security(("bearer" = [])),
    request_body = CreateTenantRequest,
    responses(
        (status = 200, body = DataResponse<TenantResponse>),
    ),
)]
pub async fn create_tenant(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(body): Json<CreateTenantRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:tenants:write")?;

    if body.name.is_empty() {
        return Err(ApiError::Validation("name is required".into()));
    }

    let repo = PgTenantRepository::new(state.pool.clone());
    let id = repo.create(&body.name, body.tier).await?;
    let record = repo.get(id).await?;

    Ok(data(TenantResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/tenants
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/tenants",
    tag = "Tenants",
    security(("bearer" = [])),
    params(ListTenantsParams),
    responses(
        (status = 200, body = DataResponse<Vec<TenantResponse>>),
    ),
)]
pub async fn list_tenants(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<ListTenantsParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:tenants:read")?;

    let limit = params.limit.clamp(1, 1000);
    let offset = params.offset.max(0);

    let repo = PgTenantRepository::new(state.pool.clone());
    let records = repo.list(params.status, limit, offset).await?;
    let tenants: Vec<TenantResponse> = records.into_iter().map(Into::into).collect();

    Ok(data(tenants))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/tenants/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/tenants/{id}",
    tag = "Tenants",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,)),
    responses(
        (status = 200, body = DataResponse<TenantResponse>),
        (status = 404, body = ErrorResponse),
    ),
)]
pub async fn get_tenant(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:tenants:read")?;

    let repo = PgTenantRepository::new(state.pool.clone());
    let record = repo.get(TenantId(id)).await?;

    Ok(data(TenantResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// PUT /v1/tenants/{id}/status
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    put,
    path = "/v1/tenants/{id}/status",
    tag = "Tenants",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,)),
    request_body = UpdateTenantStatusRequest,
    responses(
        (status = 200, body = DataResponse<TenantResponse>),
    ),
)]
pub async fn update_tenant_status(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<UpdateTenantStatusRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:tenants:write")?;

    let repo = PgTenantRepository::new(state.pool.clone());
    repo.update_status(TenantId(id), body.status).await?;

    let record = repo.get(TenantId(id)).await?;
    Ok(data(TenantResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// PUT /v1/tenants/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    put,
    path = "/v1/tenants/{id}",
    tag = "Tenants",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,)),
    request_body = UpdateTenantRequest,
    responses(
        (status = 200, body = DataResponse<TenantResponse>),
    ),
)]
pub async fn update_tenant(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<UpdateTenantRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:tenants:write")?;

    let repo = PgTenantRepository::new(state.pool.clone());
    repo.update(
        TenantId(id),
        TenantUpdate {
            name: body.name,
            tier: body.tier,
            verp_enabled: body.verp_enabled,
        },
    )
    .await?;

    let record = repo.get(TenantId(id)).await?;
    Ok(data(TenantResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// DELETE /v1/tenants/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    delete,
    path = "/v1/tenants/{id}",
    tag = "Tenants",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,)),
    responses(
        (status = 204),
    ),
)]
pub async fn delete_tenant(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:tenants:write")?;

    let repo = PgTenantRepository::new(state.pool.clone());
    repo.delete(TenantId(id)).await?;

    Ok(StatusCode::NO_CONTENT)
}
