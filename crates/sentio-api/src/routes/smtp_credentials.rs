use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use sentio_core::ids::SmtpCredentialId;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{NewSmtpCredential, SmtpCredentialRecord, SmtpCredentialRepository};
use sentio_store::postgres::PgSmtpCredentialRepository;

use crate::auth::AuthContext;
use crate::errors::{ApiError, ErrorResponse};
use crate::response::{data, DataResponse};
use crate::state::AppState;

// ──────────────────────────────────────────────────────────────────────────────
// Request / Response types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateSmtpCredentialRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateEnabledRequest {
    pub enabled: bool,
}

#[derive(Serialize, utoipa::ToSchema)]
struct SmtpCredentialResponse {
    id: SmtpCredentialId,
    username: String,
    mechanisms: Vec<String>,
    enabled: bool,
}

impl From<SmtpCredentialRecord> for SmtpCredentialResponse {
    fn from(r: SmtpCredentialRecord) -> Self {
        Self {
            id: r.id,
            username: r.username,
            mechanisms: r.mechanisms,
            enabled: r.enabled,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Password hashing helpers
// ──────────────────────────────────────────────────────────────────────────────

fn hash_password(password: &str) -> Result<String, ApiError> {
    use argon2::password_hash::SaltString;
    use argon2::PasswordHasher;

    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| ApiError::Internal(format!("password hashing failed: {e}")))
}

/// Derive SCRAM-SHA-256 keys for SMTP SCRAM authentication.
/// Returns (stored_key_b64, server_key_b64, salt_b64, iterations).
fn derive_scram_keys(password: &str) -> Result<(String, String, String, i32), ApiError> {
    use base64::Engine;
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Digest, Sha256};

    let iterations: u32 = 4096;
    let salt_bytes: [u8; 16] = rand::random();

    // SaltedPassword = PBKDF2(password, salt, iterations)
    let mut salted_password = [0u8; 32];
    pbkdf2::pbkdf2::<Hmac<Sha256>>(
        password.as_bytes(),
        &salt_bytes,
        iterations,
        &mut salted_password,
    )
    .map_err(|e| ApiError::Internal(format!("PBKDF2 derivation failed: {e}")))?;

    // ClientKey = HMAC(SaltedPassword, "Client Key")
    let mut client_mac =
        Hmac::<Sha256>::new_from_slice(&salted_password).expect("HMAC key size is valid");
    client_mac.update(b"Client Key");
    let client_key = client_mac.finalize().into_bytes();

    // StoredKey = SHA-256(ClientKey)
    let stored_key = Sha256::digest(client_key);

    // ServerKey = HMAC(SaltedPassword, "Server Key")
    let mut server_mac =
        Hmac::<Sha256>::new_from_slice(&salted_password).expect("HMAC key size is valid");
    server_mac.update(b"Server Key");
    let server_key = server_mac.finalize().into_bytes();

    let b64 = base64::engine::general_purpose::STANDARD;
    Ok((
        b64.encode(stored_key),
        b64.encode(server_key),
        b64.encode(salt_bytes),
        iterations as i32,
    ))
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/tenants/{tenant_id}/smtp-credentials
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/smtp-credentials",
    tag = "SMTP Credentials",
    security(("bearer" = [])),
    params(
        ("tenant_id" = uuid::Uuid, Path,),
    ),
    request_body = CreateSmtpCredentialRequest,
    responses(
        (status = 200, body = DataResponse<SmtpCredentialResponse>),
        (status = 401, body = ErrorResponse),
    ),
)]
pub async fn create_smtp_credential(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(tenant_id): Path<uuid::Uuid>,
    Json(body): Json<CreateSmtpCredentialRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:smtp_credentials:write")?;

    if body.username.is_empty() {
        return Err(ApiError::Validation("username is required".into()));
    }
    if body.password.is_empty() {
        return Err(ApiError::Validation("password is required".into()));
    }

    // Hash on blocking thread to avoid blocking async runtime
    let password = body.password.clone();
    let (password_hash, scram) = tokio::task::spawn_blocking(move || {
        let hash = hash_password(&password)?;
        let scram = derive_scram_keys(&password)?;
        Ok::<_, ApiError>((hash, scram))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("task join error: {e}")))??;

    let (stored_key, server_key, salt, iterations) = scram;

    let repo = PgSmtpCredentialRepository::new(state.pool.clone());
    let id = repo
        .create(NewSmtpCredential {
            tenant_id: TenantId(tenant_id),
            username: body.username,
            password_hash,
            mechanisms: vec!["PLAIN".into(), "LOGIN".into(), "SCRAM-SHA-256".into()],
            scram_stored_key: Some(stored_key),
            scram_server_key: Some(server_key),
            scram_salt: Some(salt),
            scram_iterations: Some(iterations),
        })
        .await?;

    // Fetch and return the created record (without sensitive fields)
    let records = repo.list_by_tenant(TenantId(tenant_id)).await?;
    let record = records
        .into_iter()
        .find(|r| r.id == id)
        .ok_or_else(|| ApiError::Internal("created credential not found".into()))?;

    Ok(data(SmtpCredentialResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/tenants/{tenant_id}/smtp-credentials
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/smtp-credentials",
    tag = "SMTP Credentials",
    security(("bearer" = [])),
    params(
        ("tenant_id" = uuid::Uuid, Path,),
    ),
    responses(
        (status = 200, body = DataResponse<Vec<SmtpCredentialResponse>>),
        (status = 401, body = ErrorResponse),
    ),
)]
pub async fn list_smtp_credentials(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(tenant_id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:smtp_credentials:read")?;

    let repo = PgSmtpCredentialRepository::new(state.pool.clone());
    let records = repo.list_by_tenant(TenantId(tenant_id)).await?;
    let creds: Vec<SmtpCredentialResponse> = records.into_iter().map(Into::into).collect();

    Ok(data(creds))
}

// ──────────────────────────────────────────────────────────────────────────────
// PUT /v1/tenants/{tenant_id}/smtp-credentials/{id}/enabled
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/smtp-credentials/{id}/enabled",
    tag = "SMTP Credentials",
    security(("bearer" = [])),
    params(
        ("tenant_id" = uuid::Uuid, Path,),
        ("id" = uuid::Uuid, Path,),
    ),
    request_body = UpdateEnabledRequest,
    responses(
        (status = 204),
        (status = 401, body = ErrorResponse),
    ),
)]
pub async fn update_smtp_credential_enabled(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((_tenant_id, id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(body): Json<UpdateEnabledRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:smtp_credentials:write")?;

    let repo = PgSmtpCredentialRepository::new(state.pool.clone());
    repo.update_enabled(SmtpCredentialId(id), body.enabled)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

// ──────────────────────────────────────────────────────────────────────────────
// DELETE /v1/tenants/{tenant_id}/smtp-credentials/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/smtp-credentials/{id}",
    tag = "SMTP Credentials",
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
pub async fn delete_smtp_credential(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((_tenant_id, id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:smtp_credentials:write")?;

    let repo = PgSmtpCredentialRepository::new(state.pool.clone());
    repo.delete(SmtpCredentialId(id)).await?;

    Ok(StatusCode::NO_CONTENT)
}
