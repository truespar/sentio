use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use sha2::{Digest, Sha256};

use sentio_core::tenant::TenantId;
use sentio_core::traits::{ApiKeyRepository, OAuthTokenRepository};
use sentio_store::postgres::{PgApiKeyRepository, PgOAuthTokenRepository};

use crate::errors::ApiError;
use crate::state::AppState;

// ──────────────────────────────────────────────────────────────────────────────
// Auth context - extracted from Authorization: Bearer <token>
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub tenant_id: TenantId,
    pub scopes: Vec<String>,
}

impl AuthContext {
    pub fn require_scope(&self, scope: &str) -> Result<(), ApiError> {
        if self.scopes.iter().any(|s| s == scope || s == "*") {
            Ok(())
        } else {
            Err(ApiError::Auth(format!("missing required scope: {scope}")))
        }
    }
}

impl FromRequestParts<AppState> for AuthContext {
    type Rejection = ApiError;

    fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let pool = state.pool.clone();
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        async move {
            let auth_header =
                auth_header.ok_or_else(|| ApiError::Auth("missing authorization header".into()))?;

            let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
                ApiError::Auth("invalid authorization format, expected Bearer token".into())
            })?;

            // SHA-256 hash the token for lookup
            let key_hash = {
                let mut hasher = Sha256::new();
                hasher.update(token.as_bytes());
                hex::encode(hasher.finalize())
            };

            // Try API key first
            let api_key_repo = PgApiKeyRepository::new(pool.clone());
            if let Ok(record) = api_key_repo.verify(&key_hash).await {
                return Ok(AuthContext {
                    tenant_id: record.tenant_id,
                    scopes: record.scopes,
                });
            }

            // Fall back to OAuth bearer token
            let oauth_repo = PgOAuthTokenRepository::new(pool);
            match oauth_repo.get_by_hash(&key_hash).await {
                Ok(record) => {
                    if record.revoked_at.is_some() {
                        return Err(ApiError::Auth("token has been revoked".into()));
                    }
                    if record.expires_at < chrono::Utc::now() {
                        return Err(ApiError::Auth("token has expired".into()));
                    }
                    Ok(AuthContext {
                        tenant_id: record.tenant_id,
                        scopes: record.scopes,
                    })
                }
                Err(_) => Err(ApiError::Auth("invalid or expired token".into())),
            }
        }
    }
}
