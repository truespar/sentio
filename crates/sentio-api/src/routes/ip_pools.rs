use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use sentio_core::auth::{IpPoolStatus, IpPoolType};
use sentio_core::ids::IpPoolId;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{
    IpPoolRecord, IpPoolRepository, NewIpPool, TenantIpAssignmentRecord,
    TenantIpAssignmentRepository,
};
use sentio_store::postgres::{PgIpPoolRepository, PgTenantIpAssignmentRepository};

use crate::auth::AuthContext;
use crate::errors::ApiError;
use crate::response::{data, DataResponse};
use crate::state::AppState;

// ──────────────────────────────────────────────────────────────────────────────
// Request / Response types - IP Pools
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateIpPoolRequest {
    pub name: String,
    pub pool_type: IpPoolType,
    #[serde(default)]
    pub ips: Vec<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateIpPoolStatusRequest {
    pub status: IpPoolStatus,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct IpListRequest {
    pub ips: Vec<String>,
}

#[derive(Deserialize, utoipa::IntoParams)]
pub struct ListIpPoolsParams {
    pub status: Option<IpPoolStatus>,
}

#[derive(Serialize, utoipa::ToSchema)]
struct IpPoolResponse {
    id: IpPoolId,
    name: String,
    pool_type: IpPoolType,
    ips: Vec<String>,
    status: IpPoolStatus,
    created_at: DateTime<Utc>,
}

impl From<IpPoolRecord> for IpPoolResponse {
    fn from(r: IpPoolRecord) -> Self {
        Self {
            id: r.id,
            name: r.name,
            pool_type: r.pool_type,
            ips: r.ips.iter().map(|ip| ip.to_string()).collect(),
            status: r.status,
            created_at: r.created_at,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Request / Response types - Tenant IP Assignments
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
pub struct AssignIpPoolRequest {
    pub ip_pool_id: uuid::Uuid,
    #[serde(default = "default_priority")]
    pub priority: i32,
}

fn default_priority() -> i32 {
    100
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateAssignmentPriorityRequest {
    pub priority: i32,
}

#[derive(Serialize, utoipa::ToSchema)]
struct TenantIpAssignmentResponse {
    tenant_id: TenantId,
    ip_pool_id: IpPoolId,
    priority: i32,
    created_at: DateTime<Utc>,
}

impl From<TenantIpAssignmentRecord> for TenantIpAssignmentResponse {
    fn from(r: TenantIpAssignmentRecord) -> Self {
        Self {
            tenant_id: r.tenant_id,
            ip_pool_id: r.ip_pool_id,
            priority: r.priority,
            created_at: r.created_at,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

fn parse_ips(strings: &[String]) -> Result<Vec<IpNetwork>, ApiError> {
    strings
        .iter()
        .map(|s| {
            s.parse::<IpNetwork>()
                .map_err(|e| ApiError::Validation(format!("invalid IP/CIDR '{}': {e}", s)))
        })
        .collect()
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/ip-pools
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/ip-pools",
    tag = "IP Pools",
    security(("bearer" = [])),
    request_body = CreateIpPoolRequest,
    responses(
        (status = 200, body = DataResponse<IpPoolResponse>),
    ),
)]
pub async fn create_ip_pool(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(body): Json<CreateIpPoolRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:ip_pools:write")?;

    if body.name.is_empty() {
        return Err(ApiError::Validation("name is required".into()));
    }

    let ips = parse_ips(&body.ips)?;
    let repo = PgIpPoolRepository::new(state.pool.clone());
    let id = repo
        .create(NewIpPool {
            name: body.name,
            pool_type: body.pool_type,
            ips,
        })
        .await?;
    let record = repo.get(id).await?;

    Ok(data(IpPoolResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/ip-pools
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/ip-pools",
    tag = "IP Pools",
    security(("bearer" = [])),
    params(ListIpPoolsParams),
    responses(
        (status = 200, body = DataResponse<Vec<IpPoolResponse>>),
    ),
)]
pub async fn list_ip_pools(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<ListIpPoolsParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:ip_pools:read")?;

    let repo = PgIpPoolRepository::new(state.pool.clone());
    let records = repo.list(params.status).await?;
    let pools: Vec<IpPoolResponse> = records.into_iter().map(Into::into).collect();

    Ok(data(pools))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/ip-pools/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/ip-pools/{id}",
    tag = "IP Pools",
    security(("bearer" = [])),
    params(
        ("id" = uuid::Uuid, Path,),
    ),
    responses(
        (status = 200, body = DataResponse<IpPoolResponse>),
    ),
)]
pub async fn get_ip_pool(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:ip_pools:read")?;

    let repo = PgIpPoolRepository::new(state.pool.clone());
    let record = repo.get(IpPoolId(id)).await?;

    Ok(data(IpPoolResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// PUT /v1/ip-pools/{id}/status
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    put,
    path = "/v1/ip-pools/{id}/status",
    tag = "IP Pools",
    security(("bearer" = [])),
    params(
        ("id" = uuid::Uuid, Path,),
    ),
    request_body = UpdateIpPoolStatusRequest,
    responses(
        (status = 200, body = DataResponse<IpPoolResponse>),
    ),
)]
pub async fn update_ip_pool_status(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<UpdateIpPoolStatusRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:ip_pools:write")?;

    let repo = PgIpPoolRepository::new(state.pool.clone());
    repo.update_status(IpPoolId(id), body.status).await?;

    let record = repo.get(IpPoolId(id)).await?;
    Ok(data(IpPoolResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/ip-pools/{id}/ips
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/ip-pools/{id}/ips",
    tag = "IP Pools",
    security(("bearer" = [])),
    params(
        ("id" = uuid::Uuid, Path,),
    ),
    request_body = IpListRequest,
    responses(
        (status = 200, body = DataResponse<IpPoolResponse>),
    ),
)]
pub async fn add_ips(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<IpListRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:ip_pools:write")?;

    if body.ips.is_empty() {
        return Err(ApiError::Validation("ips list is required".into()));
    }

    let ips = parse_ips(&body.ips)?;
    let repo = PgIpPoolRepository::new(state.pool.clone());
    repo.add_ips(IpPoolId(id), &ips).await?;

    let record = repo.get(IpPoolId(id)).await?;
    Ok(data(IpPoolResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// DELETE /v1/ip-pools/{id}/ips
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    delete,
    path = "/v1/ip-pools/{id}/ips",
    tag = "IP Pools",
    security(("bearer" = [])),
    params(
        ("id" = uuid::Uuid, Path,),
    ),
    request_body = IpListRequest,
    responses(
        (status = 200, body = DataResponse<IpPoolResponse>),
    ),
)]
pub async fn remove_ips(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<IpListRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:ip_pools:write")?;

    if body.ips.is_empty() {
        return Err(ApiError::Validation("ips list is required".into()));
    }

    let ips = parse_ips(&body.ips)?;
    let repo = PgIpPoolRepository::new(state.pool.clone());
    repo.remove_ips(IpPoolId(id), &ips).await?;

    let record = repo.get(IpPoolId(id)).await?;
    Ok(data(IpPoolResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// DELETE /v1/ip-pools/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    delete,
    path = "/v1/ip-pools/{id}",
    tag = "IP Pools",
    security(("bearer" = [])),
    params(
        ("id" = uuid::Uuid, Path,),
    ),
    responses(
        (status = 204),
    ),
)]
pub async fn delete_ip_pool(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:ip_pools:write")?;

    let repo = PgIpPoolRepository::new(state.pool.clone());
    repo.delete(IpPoolId(id)).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/ip-pools/{id}/tenants
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/ip-pools/{id}/tenants",
    tag = "IP Pools",
    security(("bearer" = [])),
    params(
        ("id" = uuid::Uuid, Path,),
    ),
    responses(
        (status = 200, body = DataResponse<Vec<TenantIpAssignmentResponse>>),
    ),
)]
pub async fn list_pool_tenants(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:ip_pools:read")?;

    let repo = PgTenantIpAssignmentRepository::new(state.pool.clone());
    let records = repo.list_by_pool(IpPoolId(id)).await?;
    let assignments: Vec<TenantIpAssignmentResponse> =
        records.into_iter().map(Into::into).collect();

    Ok(data(assignments))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/tenants/{tenant_id}/ip-pools
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/ip-pools",
    tag = "IP Pools",
    security(("bearer" = [])),
    params(
        ("tenant_id" = uuid::Uuid, Path,),
    ),
    responses(
        (status = 200, body = DataResponse<Vec<TenantIpAssignmentResponse>>),
    ),
)]
pub async fn list_tenant_pools(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(tenant_id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:ip_pools:read")?;

    let repo = PgTenantIpAssignmentRepository::new(state.pool.clone());
    let records = repo.list_by_tenant(TenantId(tenant_id)).await?;
    let assignments: Vec<TenantIpAssignmentResponse> =
        records.into_iter().map(Into::into).collect();

    Ok(data(assignments))
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/tenants/{tenant_id}/ip-pools
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/ip-pools",
    tag = "IP Pools",
    security(("bearer" = [])),
    params(
        ("tenant_id" = uuid::Uuid, Path,),
    ),
    request_body = AssignIpPoolRequest,
    responses(
        (status = 200, body = DataResponse<Vec<TenantIpAssignmentResponse>>),
    ),
)]
pub async fn assign_ip_pool(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(tenant_id): Path<uuid::Uuid>,
    Json(body): Json<AssignIpPoolRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:ip_pools:write")?;

    let repo = PgTenantIpAssignmentRepository::new(state.pool.clone());
    repo.assign(
        TenantId(tenant_id),
        IpPoolId(body.ip_pool_id),
        body.priority,
    )
    .await?;

    let records = repo.list_by_tenant(TenantId(tenant_id)).await?;
    let assignments: Vec<TenantIpAssignmentResponse> =
        records.into_iter().map(Into::into).collect();

    Ok(data(assignments))
}

// ──────────────────────────────────────────────────────────────────────────────
// PUT /v1/tenants/{tenant_id}/ip-pools/{pool_id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/ip-pools/{pool_id}",
    tag = "IP Pools",
    security(("bearer" = [])),
    params(
        ("tenant_id" = uuid::Uuid, Path,),
        ("pool_id" = uuid::Uuid, Path,),
    ),
    request_body = UpdateAssignmentPriorityRequest,
    responses(
        (status = 200, body = DataResponse<Vec<TenantIpAssignmentResponse>>),
    ),
)]
pub async fn update_assignment_priority(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((tenant_id, pool_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(body): Json<UpdateAssignmentPriorityRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:ip_pools:write")?;

    let repo = PgTenantIpAssignmentRepository::new(state.pool.clone());
    repo.update_priority(TenantId(tenant_id), IpPoolId(pool_id), body.priority)
        .await?;

    let records = repo.list_by_tenant(TenantId(tenant_id)).await?;
    let assignments: Vec<TenantIpAssignmentResponse> =
        records.into_iter().map(Into::into).collect();

    Ok(data(assignments))
}

// ──────────────────────────────────────────────────────────────────────────────
// DELETE /v1/tenants/{tenant_id}/ip-pools/{pool_id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/ip-pools/{pool_id}",
    tag = "IP Pools",
    security(("bearer" = [])),
    params(
        ("tenant_id" = uuid::Uuid, Path,),
        ("pool_id" = uuid::Uuid, Path,),
    ),
    responses(
        (status = 204),
    ),
)]
pub async fn unassign_ip_pool(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((tenant_id, pool_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:ip_pools:write")?;

    let repo = PgTenantIpAssignmentRepository::new(state.pool.clone());
    repo.unassign(TenantId(tenant_id), IpPoolId(pool_id))
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
