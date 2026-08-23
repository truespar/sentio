use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::error::SentioError;
use sentio_core::ids::{OAuthClientId, OAuthTokenId};
use sentio_core::oauth::OAuthTokenType;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{NewOAuthToken, OAuthTokenRecord, OAuthTokenRepository};

pub struct PgOAuthTokenRepository {
    pool: PgPool,
}

impl PgOAuthTokenRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_oauth_token_row(
    id: Uuid,
    client_id: Uuid,
    tenant_id: Uuid,
    token_hash: String,
    token_type: String,
    scopes: Vec<String>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
) -> Result<OAuthTokenRecord, SentioError> {
    Ok(OAuthTokenRecord {
        id: OAuthTokenId(id),
        client_id: OAuthClientId(client_id),
        tenant_id: TenantId(tenant_id),
        token_hash,
        token_type: OAuthTokenType::from_str(&token_type).map_err(|_| {
            SentioError::Database(format!("invalid oauth token type: {token_type}"))
        })?,
        scopes,
        expires_at,
        revoked_at,
        created_at,
    })
}

impl OAuthTokenRepository for PgOAuthTokenRepository {
    async fn create(&self, token: NewOAuthToken) -> Result<OAuthTokenId, SentioError> {
        let token_type_str = token.token_type.to_string();
        let row = sqlx::query!(
            "INSERT INTO oauth_tokens \
                (client_id, tenant_id, token_hash, token_type, scopes, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
            token.client_id.0,
            token.tenant_id.0,
            token.token_hash,
            token_type_str,
            &token.scopes,
            token.expires_at,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(OAuthTokenId(row.id))
    }

    async fn get_by_hash(&self, token_hash: &str) -> Result<OAuthTokenRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, client_id, tenant_id, token_hash, token_type, scopes, \
                    expires_at, revoked_at, created_at \
             FROM oauth_tokens WHERE token_hash = $1",
            token_hash,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "oauth_token",
            id: token_hash.to_string(),
        })?;

        parse_oauth_token_row(
            row.id,
            row.client_id,
            row.tenant_id,
            row.token_hash,
            row.token_type,
            row.scopes,
            row.expires_at,
            row.revoked_at,
            row.created_at,
        )
    }

    async fn revoke(&self, id: OAuthTokenId) -> Result<(), SentioError> {
        let result = sqlx::query!(
            "UPDATE oauth_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "oauth_token",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn revoke_by_client(&self, client_id: OAuthClientId) -> Result<u64, SentioError> {
        let result = sqlx::query!(
            "UPDATE oauth_tokens SET revoked_at = now() \
             WHERE client_id = $1 AND revoked_at IS NULL",
            client_id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }

    async fn delete_expired(&self) -> Result<u64, SentioError> {
        let result = sqlx::query!(
            "DELETE FROM oauth_tokens WHERE expires_at < now() AND revoked_at IS NOT NULL"
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }
}
