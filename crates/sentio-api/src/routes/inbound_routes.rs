use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use sentio_core::ids::InboundRouteId;
use sentio_core::inbound::InboundRouteMatchType;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{
    InboundRouteRecord, InboundRouteRepository, InboundRouteUpdate, NewInboundRoute,
};
use sentio_store::postgres::PgInboundRouteRepository;

use crate::auth::AuthContext;
use crate::errors::{ApiError, ErrorResponse};
use crate::response::{data, DataResponse};
use crate::state::AppState;

// ──────────────────────────────────────────────────────────────────────────────
// Request / Response types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateInboundRouteRequest {
    pub pattern: String,
    pub match_type: InboundRouteMatchType,
    pub webhook_url: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub llm_classify: bool,
    #[serde(default)]
    pub auto_respond: bool,
    #[schema(value_type = Option<Object>)]
    pub auto_respond_config: Option<serde_json::Value>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateInboundRouteRequest {
    pub pattern: String,
    pub match_type: InboundRouteMatchType,
    pub webhook_url: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub llm_classify: bool,
    #[serde(default)]
    pub auto_respond: bool,
    #[schema(value_type = Option<Object>)]
    pub auto_respond_config: Option<serde_json::Value>,
}

#[derive(Serialize, utoipa::ToSchema)]
struct InboundRouteResponse {
    id: InboundRouteId,
    tenant_id: TenantId,
    pattern: String,
    match_type: InboundRouteMatchType,
    webhook_url: String,
    priority: i32,
    llm_classify: bool,
    auto_respond: bool,
    #[schema(value_type = Option<Object>)]
    auto_respond_config: Option<serde_json::Value>,
    created_at: DateTime<Utc>,
}

impl From<InboundRouteRecord> for InboundRouteResponse {
    fn from(r: InboundRouteRecord) -> Self {
        Self {
            id: r.id,
            tenant_id: r.tenant_id,
            pattern: r.pattern,
            match_type: r.match_type,
            webhook_url: r.webhook_url,
            priority: r.priority,
            llm_classify: r.llm_classify,
            auto_respond: r.auto_respond,
            auto_respond_config: r.auto_respond_config,
            created_at: r.created_at,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/tenants/{tenant_id}/inbound-routes
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/inbound-routes",
    tag = "Inbound Routes",
    security(("bearer" = [])),
    params(
        ("tenant_id" = uuid::Uuid, Path,),
    ),
    request_body = CreateInboundRouteRequest,
    responses(
        (status = 200, body = DataResponse<InboundRouteResponse>),
        (status = 401, body = ErrorResponse),
    ),
)]
pub async fn create_inbound_route(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(tenant_id): Path<uuid::Uuid>,
    Json(body): Json<CreateInboundRouteRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:inbound_routes:write")?;

    if body.pattern.is_empty() {
        return Err(ApiError::Validation("pattern is required".into()));
    }
    if body.webhook_url.is_empty() {
        return Err(ApiError::Validation("webhook_url is required".into()));
    }

    let repo = PgInboundRouteRepository::new(state.pool.clone());
    let id = repo
        .create(NewInboundRoute {
            tenant_id: TenantId(tenant_id),
            pattern: body.pattern,
            match_type: body.match_type,
            webhook_url: body.webhook_url,
            priority: body.priority,
            llm_classify: body.llm_classify,
            auto_respond: body.auto_respond,
            auto_respond_config: body.auto_respond_config,
        })
        .await?;

    let record = repo.get(id).await?;
    Ok(data(InboundRouteResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/tenants/{tenant_id}/inbound-routes
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/inbound-routes",
    tag = "Inbound Routes",
    security(("bearer" = [])),
    params(
        ("tenant_id" = uuid::Uuid, Path,),
    ),
    responses(
        (status = 200, body = DataResponse<Vec<InboundRouteResponse>>),
        (status = 401, body = ErrorResponse),
    ),
)]
pub async fn list_inbound_routes(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(tenant_id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:inbound_routes:read")?;

    let repo = PgInboundRouteRepository::new(state.pool.clone());
    let records = repo.list_by_tenant(TenantId(tenant_id)).await?;
    let routes: Vec<InboundRouteResponse> = records.into_iter().map(Into::into).collect();

    Ok(data(routes))
}

// ──────────────────────────────────────────────────────────────────────────────
// PUT /v1/tenants/{tenant_id}/inbound-routes/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/inbound-routes/{id}",
    tag = "Inbound Routes",
    security(("bearer" = [])),
    params(
        ("tenant_id" = uuid::Uuid, Path,),
        ("id" = uuid::Uuid, Path,),
    ),
    request_body = UpdateInboundRouteRequest,
    responses(
        (status = 200, body = DataResponse<InboundRouteResponse>),
        (status = 401, body = ErrorResponse),
    ),
)]
pub async fn update_inbound_route(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((_tenant_id, id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(body): Json<UpdateInboundRouteRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:inbound_routes:write")?;

    let repo = PgInboundRouteRepository::new(state.pool.clone());
    repo.update(
        InboundRouteId(id),
        InboundRouteUpdate {
            pattern: body.pattern,
            match_type: body.match_type,
            webhook_url: body.webhook_url,
            priority: body.priority,
            llm_classify: body.llm_classify,
            auto_respond: body.auto_respond,
            auto_respond_config: body.auto_respond_config,
        },
    )
    .await?;

    let record = repo.get(InboundRouteId(id)).await?;
    Ok(data(InboundRouteResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// DELETE /v1/tenants/{tenant_id}/inbound-routes/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/inbound-routes/{id}",
    tag = "Inbound Routes",
    security(("bearer" = [])),
    params(
        ("tenant_id" = uuid::Uuid, Path,),
        ("id" = uuid::Uuid, Path,),
    ),
    responses(
        (status = 204),
        (status = 401, body = ErrorResponse),
    ),
)]
pub async fn delete_inbound_route(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((_tenant_id, id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:inbound_routes:write")?;

    let repo = PgInboundRouteRepository::new(state.pool.clone());
    repo.delete(InboundRouteId(id)).await?;

    Ok(StatusCode::NO_CONTENT)
}
