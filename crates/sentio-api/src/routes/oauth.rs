use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use sentio_core::ids::OAuthClientId;
use sentio_core::oauth::OAuthClientStatus;
use sentio_core::traits::{NewOAuthClient, OAuthClientRecord, OAuthClientRepository};
use sentio_store::postgres::PgOAuthClientRepository;

use crate::auth::AuthContext;
use crate::errors::{ApiError, ErrorResponse};
use crate::response::{data, DataResponse};
use crate::state::AppState;

// ──────────────────────────────────────────────────────────────────────────────
// Request / Response types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateOAuthClientRequest {
    pub name: String,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default = "default_grant_types")]
    pub grant_types: Vec<String>,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
}

fn default_grant_types() -> Vec<String> {
    vec!["authorization_code".into(), "client_credentials".into()]
}

fn default_scopes() -> Vec<String> {
    vec!["*".into()]
}

#[derive(Serialize, utoipa::ToSchema)]
struct OAuthClientResponse {
    id: OAuthClientId,
    client_id: String,
    name: String,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    scopes: Vec<String>,
    status: OAuthClientStatus,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<OAuthClientRecord> for OAuthClientResponse {
    fn from(r: OAuthClientRecord) -> Self {
        Self {
            id: r.id,
            client_id: r.client_id,
            name: r.name,
            redirect_uris: r.redirect_uris,
            grant_types: r.grant_types,
            scopes: r.scopes,
            status: r.status,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// Returned only on creation - includes the plaintext client secret.
#[derive(Serialize, utoipa::ToSchema)]
struct OAuthClientCreatedResponse {
    id: OAuthClientId,
    client_id: String,
    client_secret: String,
    name: String,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    scopes: Vec<String>,
    status: OAuthClientStatus,
    created_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/oauth/clients
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/oauth/clients",
    tag = "OAuth",
    security(("bearer" = [])),
    request_body = CreateOAuthClientRequest,
    responses(
        (status = 200, body = DataResponse<OAuthClientCreatedResponse>),
        (status = 401, body = ErrorResponse),
        (status = 422, body = ErrorResponse),
    )
)]
pub async fn create_oauth_client(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(body): Json<CreateOAuthClientRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("oauth:write")?;

    if body.name.is_empty() {
        return Err(ApiError::Validation("name is required".into()));
    }

    // Generate client_id and secret
    let client_id = format!("sentio_{}", uuid::Uuid::new_v4().simple());
    let client_secret = format!("sk_{}", uuid::Uuid::new_v4().simple());
    let secret_hash = {
        let mut hasher = Sha256::new();
        hasher.update(client_secret.as_bytes());
        hex::encode(hasher.finalize())
    };

    let repo = PgOAuthClientRepository::new(state.pool.clone());
    let id = repo
        .create(NewOAuthClient {
            tenant_id: auth.tenant_id,
            client_id: client_id.clone(),
            client_secret_hash: secret_hash,
            name: body.name.clone(),
            redirect_uris: body.redirect_uris.clone(),
            grant_types: body.grant_types.clone(),
            scopes: body.scopes.clone(),
        })
        .await?;

    let record = repo.get(id).await?;

    Ok(data(OAuthClientCreatedResponse {
        id: record.id,
        client_id: record.client_id,
        client_secret,
        name: record.name,
        redirect_uris: record.redirect_uris,
        grant_types: record.grant_types,
        scopes: record.scopes,
        status: record.status,
        created_at: record.created_at,
    }))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/oauth/clients
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/oauth/clients",
    tag = "OAuth",
    security(("bearer" = [])),
    responses(
        (status = 200, body = DataResponse<Vec<OAuthClientResponse>>),
        (status = 401, body = ErrorResponse),
    )
)]
pub async fn list_oauth_clients(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("oauth:read")?;

    let repo = PgOAuthClientRepository::new(state.pool.clone());
    let records = repo.list_by_tenant(auth.tenant_id).await?;
    let clients: Vec<OAuthClientResponse> = records.into_iter().map(Into::into).collect();

    Ok(data(clients))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/oauth/clients/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/oauth/clients/{id}",
    tag = "OAuth",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,)),
    responses(
        (status = 200, body = DataResponse<OAuthClientResponse>),
        (status = 404, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
    )
)]
pub async fn get_oauth_client(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("oauth:read")?;

    let repo = PgOAuthClientRepository::new(state.pool.clone());
    let record = repo.get(OAuthClientId(id)).await?;

    if record.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("oauth_client".into()));
    }

    Ok(data(OAuthClientResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/oauth/clients/{id}/revoke
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/oauth/clients/{id}/revoke",
    tag = "OAuth",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,)),
    responses(
        (status = 200, body = DataResponse<OAuthClientResponse>),
        (status = 404, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
    )
)]
pub async fn revoke_oauth_client(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("oauth:write")?;

    let repo = PgOAuthClientRepository::new(state.pool.clone());
    let record = repo.get(OAuthClientId(id)).await?;

    if record.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("oauth_client".into()));
    }

    repo.revoke(OAuthClientId(id)).await?;

    let updated = repo.get(OAuthClientId(id)).await?;
    Ok(data(OAuthClientResponse::from(updated)))
}

// ──────────────────────────────────────────────────────────────────────────────
// DELETE /v1/oauth/clients/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    delete,
    path = "/v1/oauth/clients/{id}",
    tag = "OAuth",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,)),
    responses(
        (status = 204, description = "OAuth client deleted"),
        (status = 404, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
    )
)]
pub async fn delete_oauth_client(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("oauth:write")?;

    let repo = PgOAuthClientRepository::new(state.pool.clone());
    let record = repo.get(OAuthClientId(id)).await?;

    if record.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("oauth_client".into()));
    }

    repo.delete(OAuthClientId(id)).await?;
    Ok(StatusCode::NO_CONTENT)
}
