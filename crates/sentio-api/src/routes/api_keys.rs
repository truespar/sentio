use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use sentio_core::ids::ApiKeyId;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{ApiKeyRecord, ApiKeyRepository};
use sentio_store::postgres::PgApiKeyRepository;

use crate::auth::AuthContext;
use crate::errors::{ApiError, ErrorResponse};
use crate::response::{data, DataResponse};
use crate::state::AppState;

// ──────────────────────────────────────────────────────────────────────────────
// Request / Response types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateApiKeyRequest {
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
struct ApiKeyCreatedResponse {
    id: ApiKeyId,
    raw_key: String,
}

#[derive(Serialize, utoipa::ToSchema)]
struct ApiKeyResponse {
    id: ApiKeyId,
    key_prefix: String,
    name: String,
    scopes: Vec<String>,
    created_at: DateTime<Utc>,
}

impl From<ApiKeyRecord> for ApiKeyResponse {
    fn from(r: ApiKeyRecord) -> Self {
        Self {
            id: r.id,
            key_prefix: r.key_prefix,
            name: r.name,
            scopes: r.scopes,
            created_at: r.created_at,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/tenants/{tenant_id}/api-keys
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/api-keys",
    tag = "API Keys",
    security(("bearer" = [])),
    params(
        ("tenant_id" = uuid::Uuid, Path,),
    ),
    request_body = CreateApiKeyRequest,
    responses(
        (status = 200, body = DataResponse<ApiKeyCreatedResponse>),
        (status = 401, body = ErrorResponse),
    ),
)]
pub async fn create_api_key(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(tenant_id): Path<uuid::Uuid>,
    Json(body): Json<CreateApiKeyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:api_keys:write")?;

    if body.name.is_empty() {
        return Err(ApiError::Validation("name is required".into()));
    }

    let repo = PgApiKeyRepository::new(state.pool.clone());
    let created = repo
        .create(TenantId(tenant_id), &body.name, &body.scopes)
        .await?;

    Ok(data(ApiKeyCreatedResponse {
        id: created.id,
        raw_key: created.raw_key,
    }))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/tenants/{tenant_id}/api-keys
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/api-keys",
    tag = "API Keys",
    security(("bearer" = [])),
    params(
        ("tenant_id" = uuid::Uuid, Path,),
    ),
    responses(
        (status = 200, body = DataResponse<Vec<ApiKeyResponse>>),
        (status = 401, body = ErrorResponse),
    ),
)]
pub async fn list_api_keys(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(tenant_id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:api_keys:read")?;

    let repo = PgApiKeyRepository::new(state.pool.clone());
    let records = repo.list_by_tenant(TenantId(tenant_id)).await?;
    let keys: Vec<ApiKeyResponse> = records.into_iter().map(Into::into).collect();

    Ok(data(keys))
}

// ──────────────────────────────────────────────────────────────────────────────
// DELETE /v1/tenants/{tenant_id}/api-keys/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/api-keys/{id}",
    tag = "API Keys",
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
pub async fn revoke_api_key(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((_tenant_id, id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:api_keys:write")?;

    let repo = PgApiKeyRepository::new(state.pool.clone());
    repo.revoke(ApiKeyId(id)).await?;

    Ok(StatusCode::NO_CONTENT)
}
