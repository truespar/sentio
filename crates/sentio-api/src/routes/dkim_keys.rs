use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use sentio_core::auth::{DkimAlgorithm, DkimKeyStatus};
use sentio_core::ids::DkimKeyId;
use sentio_core::message::DomainId;
use sentio_core::traits::{DkimKeyRecord, DkimKeyRepository, DomainRepository, NewDkimKey};
use sentio_store::postgres::{PgDkimKeyRepository, PgDomainRepository};

use crate::auth::AuthContext;
use crate::errors::ApiError;
use crate::response::{data, DataResponse};
use crate::state::AppState;

// ──────────────────────────────────────────────────────────────────────────────
// Request / Response types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateDkimKeyRequest {
    pub selector: String,
    #[serde(default = "default_algorithm")]
    pub algorithm: DkimAlgorithm,
    /// RSA key size (only for RSA). Defaults to 2048.
    pub key_size: Option<i32>,
}

fn default_algorithm() -> DkimAlgorithm {
    DkimAlgorithm::Ed25519
}

#[derive(Serialize, utoipa::ToSchema)]
struct DkimKeyResponse {
    id: DkimKeyId,
    domain_id: DomainId,
    selector: String,
    algorithm: DkimAlgorithm,
    public_key: String,
    key_size: Option<i32>,
    status: DkimKeyStatus,
    activated_at: Option<DateTime<Utc>>,
    retired_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl From<DkimKeyRecord> for DkimKeyResponse {
    fn from(r: DkimKeyRecord) -> Self {
        Self {
            id: r.id,
            domain_id: r.domain_id,
            selector: r.selector,
            algorithm: r.algorithm,
            public_key: r.public_key,
            key_size: r.key_size,
            status: r.status,
            activated_at: r.activated_at,
            retired_at: r.retired_at,
            created_at: r.created_at,
        }
    }
}

#[derive(Serialize, utoipa::ToSchema)]
struct DnsRecordResponse {
    record_type: String,
    host: String,
    value: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Key generation helpers
// ──────────────────────────────────────────────────────────────────────────────

fn generate_ed25519_key() -> Result<(String, String), ApiError> {
    use base64::Engine;
    use ed25519_dalek::SigningKey;

    let signing_key = SigningKey::generate(&mut rand::rng());
    let verifying_key = signing_key.verifying_key();

    let b64 = base64::engine::general_purpose::STANDARD;
    let private_b64 = b64.encode(signing_key.to_bytes());
    let public_b64 = b64.encode(verifying_key.to_bytes());

    Ok((private_b64, public_b64))
}

fn generate_rsa_key(key_size: u32) -> Result<(String, String, i32), ApiError> {
    use base64::Engine;
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use rsa::rand_core::OsRng;
    use rsa::RsaPrivateKey;

    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, key_size as usize)
        .map_err(|e| ApiError::Internal(format!("RSA key generation failed: {e}")))?;

    let private_der = private_key
        .to_pkcs8_der()
        .map_err(|e| ApiError::Internal(format!("RSA private key encoding failed: {e}")))?;
    let public_der = private_key
        .to_public_key()
        .to_public_key_der()
        .map_err(|e| ApiError::Internal(format!("RSA public key encoding failed: {e}")))?;

    let b64 = base64::engine::general_purpose::STANDARD;
    Ok((
        b64.encode(private_der.as_bytes()),
        b64.encode(public_der.as_bytes()),
        key_size as i32,
    ))
}

/// Verify the caller owns the domain (admin scope bypasses).
async fn verify_domain_ownership(
    state: &AppState,
    auth: &AuthContext,
    domain_id: DomainId,
) -> Result<(), ApiError> {
    let domain_repo = PgDomainRepository::new(state.pool.clone());
    let domain = domain_repo.get(domain_id).await?;

    // Admin scope bypasses ownership check
    if auth
        .scopes
        .iter()
        .any(|s| s == "*" || s.starts_with("admin:"))
    {
        return Ok(());
    }

    if domain.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("domain not found".into()));
    }
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/domains/{domain_id}/dkim-keys
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/domains/{domain_id}/dkim-keys",
    tag = "DKIM Keys",
    security(("bearer" = [])),
    params(
        ("domain_id" = uuid::Uuid, Path,),
    ),
    request_body = CreateDkimKeyRequest,
    responses(
        (status = 200, body = DataResponse<DkimKeyResponse>),
    ),
)]
pub async fn create_dkim_key(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(domain_id): Path<uuid::Uuid>,
    Json(body): Json<CreateDkimKeyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:dkim_keys:write")?;

    let domain_id = DomainId(domain_id);
    verify_domain_ownership(&state, &auth, domain_id).await?;

    if body.selector.is_empty() {
        return Err(ApiError::Validation("selector is required".into()));
    }

    let new_key = match body.algorithm {
        DkimAlgorithm::Ed25519 => {
            let (private_key, public_key) = tokio::task::spawn_blocking(generate_ed25519_key)
                .await
                .map_err(|e| ApiError::Internal(format!("task join error: {e}")))??;
            NewDkimKey {
                domain_id,
                selector: body.selector,
                algorithm: DkimAlgorithm::Ed25519,
                private_key,
                public_key,
                key_size: None,
            }
        }
        DkimAlgorithm::Rsa => {
            let size = body.key_size.unwrap_or(2048);
            if !(1024..=4096).contains(&size) {
                return Err(ApiError::Validation(
                    "RSA key_size must be between 1024 and 4096".into(),
                ));
            }
            let size_u32 = size as u32;
            let (private_key, public_key, key_size) =
                tokio::task::spawn_blocking(move || generate_rsa_key(size_u32))
                    .await
                    .map_err(|e| ApiError::Internal(format!("task join error: {e}")))??;
            NewDkimKey {
                domain_id,
                selector: body.selector,
                algorithm: DkimAlgorithm::Rsa,
                private_key,
                public_key,
                key_size: Some(key_size),
            }
        }
    };

    let repo = PgDkimKeyRepository::new(state.pool.clone());
    let id = repo.create(new_key).await?;
    let record = repo.get(id).await?;

    Ok(data(DkimKeyResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/domains/{domain_id}/dkim-keys
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/domains/{domain_id}/dkim-keys",
    tag = "DKIM Keys",
    security(("bearer" = [])),
    params(
        ("domain_id" = uuid::Uuid, Path,),
    ),
    responses(
        (status = 200, body = DataResponse<Vec<DkimKeyResponse>>),
    ),
)]
pub async fn list_dkim_keys(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(domain_id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:dkim_keys:read")?;

    let domain_id = DomainId(domain_id);
    verify_domain_ownership(&state, &auth, domain_id).await?;

    let repo = PgDkimKeyRepository::new(state.pool.clone());
    let records = repo.list_by_domain(domain_id).await?;
    let keys: Vec<DkimKeyResponse> = records.into_iter().map(Into::into).collect();

    Ok(data(keys))
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/domains/{domain_id}/dkim-keys/rotate
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
pub struct RotateDkimKeyRequest {
    pub selector: String,
    #[serde(default = "default_algorithm")]
    pub algorithm: DkimAlgorithm,
    pub key_size: Option<i32>,
}

#[utoipa::path(
    post,
    path = "/v1/domains/{domain_id}/dkim-keys/rotate",
    tag = "DKIM Keys",
    security(("bearer" = [])),
    params(
        ("domain_id" = uuid::Uuid, Path,),
    ),
    request_body = RotateDkimKeyRequest,
    responses(
        (status = 200, body = DataResponse<DkimKeyResponse>),
    ),
)]
pub async fn rotate_dkim_key(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(domain_id): Path<uuid::Uuid>,
    Json(body): Json<RotateDkimKeyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:dkim_keys:write")?;

    let domain_id = DomainId(domain_id);
    verify_domain_ownership(&state, &auth, domain_id).await?;

    if body.selector.is_empty() {
        return Err(ApiError::Validation("selector is required".into()));
    }

    let new_key = match body.algorithm {
        DkimAlgorithm::Ed25519 => {
            let (private_key, public_key) = tokio::task::spawn_blocking(generate_ed25519_key)
                .await
                .map_err(|e| ApiError::Internal(format!("task join error: {e}")))??;
            NewDkimKey {
                domain_id,
                selector: body.selector,
                algorithm: DkimAlgorithm::Ed25519,
                private_key,
                public_key,
                key_size: None,
            }
        }
        DkimAlgorithm::Rsa => {
            let size = body.key_size.unwrap_or(2048);
            if !(1024..=4096).contains(&size) {
                return Err(ApiError::Validation(
                    "RSA key_size must be between 1024 and 4096".into(),
                ));
            }
            let size_u32 = size as u32;
            let (private_key, public_key, key_size) =
                tokio::task::spawn_blocking(move || generate_rsa_key(size_u32))
                    .await
                    .map_err(|e| ApiError::Internal(format!("task join error: {e}")))??;
            NewDkimKey {
                domain_id,
                selector: body.selector,
                algorithm: DkimAlgorithm::Rsa,
                private_key,
                public_key,
                key_size: Some(key_size),
            }
        }
    };

    let repo = PgDkimKeyRepository::new(state.pool.clone());
    let id = repo.rotate(domain_id, new_key).await?;
    let record = repo.get(id).await?;

    Ok(data(DkimKeyResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// DELETE /v1/domains/{domain_id}/dkim-keys/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    delete,
    path = "/v1/domains/{domain_id}/dkim-keys/{id}",
    tag = "DKIM Keys",
    security(("bearer" = [])),
    params(
        ("domain_id" = uuid::Uuid, Path,),
        ("id" = uuid::Uuid, Path,),
    ),
    responses(
        (status = 204),
    ),
)]
pub async fn retire_dkim_key(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((_domain_id, id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:dkim_keys:write")?;

    let repo = PgDkimKeyRepository::new(state.pool.clone());
    repo.retire(DkimKeyId(id)).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/domains/{domain_id}/dkim-keys/{id}/dns-record
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/domains/{domain_id}/dkim-keys/{id}/dns-record",
    tag = "DKIM Keys",
    security(("bearer" = [])),
    params(
        ("domain_id" = uuid::Uuid, Path,),
        ("id" = uuid::Uuid, Path,),
    ),
    responses(
        (status = 200, body = DataResponse<DnsRecordResponse>),
    ),
)]
pub async fn get_dkim_dns_record(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((domain_id, id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:dkim_keys:read")?;

    let domain_id = DomainId(domain_id);
    verify_domain_ownership(&state, &auth, domain_id).await?;

    let domain_repo = PgDomainRepository::new(state.pool.clone());
    let domain = domain_repo.get(domain_id).await?;

    let dkim_repo = PgDkimKeyRepository::new(state.pool.clone());
    let key = dkim_repo.get(DkimKeyId(id)).await?;

    let algorithm_label = match key.algorithm {
        DkimAlgorithm::Ed25519 => "ed25519",
        DkimAlgorithm::Rsa => "rsa",
    };

    let record = DnsRecordResponse {
        record_type: "TXT".into(),
        host: format!("{}._domainkey.{}", key.selector, domain.domain_name),
        value: format!("v=DKIM1; k={algorithm_label}; p={}", key.public_key),
    };

    Ok(data(record))
}
