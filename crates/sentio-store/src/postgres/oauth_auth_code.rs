use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::error::SentioError;
use sentio_core::ids::OAuthClientId;
use sentio_core::oauth::CodeChallengeMethod;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{
    NewOAuthAuthorizationCode, OAuthAuthorizationCodeRecord, OAuthAuthorizationCodeRepository,
};

pub struct PgOAuthAuthorizationCodeRepository {
    pool: PgPool,
}

impl PgOAuthAuthorizationCodeRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_auth_code_row(
    code: String,
    client_id: Uuid,
    tenant_id: Uuid,
    redirect_uri: String,
    scopes: Vec<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
) -> Result<OAuthAuthorizationCodeRecord, SentioError> {
    let ccm = code_challenge_method
        .map(|s| {
            CodeChallengeMethod::from_str(&s)
                .map_err(|_| SentioError::Database(format!("invalid code_challenge_method: {s}")))
        })
        .transpose()?;

    Ok(OAuthAuthorizationCodeRecord {
        code,
        client_id: OAuthClientId(client_id),
        tenant_id: TenantId(tenant_id),
        redirect_uri,
        scopes,
        code_challenge,
        code_challenge_method: ccm,
        expires_at,
        created_at,
    })
}

impl OAuthAuthorizationCodeRepository for PgOAuthAuthorizationCodeRepository {
    async fn create(&self, auth_code: NewOAuthAuthorizationCode) -> Result<String, SentioError> {
        let ccm_str = auth_code.code_challenge_method.map(|m| m.to_string());
        sqlx::query!(
            "INSERT INTO oauth_authorization_codes \
                (code, client_id, tenant_id, redirect_uri, scopes, \
                 code_challenge, code_challenge_method, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            auth_code.code,
            auth_code.client_id.0,
            auth_code.tenant_id.0,
            auth_code.redirect_uri,
            &auth_code.scopes,
            auth_code.code_challenge,
            ccm_str,
            auth_code.expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(auth_code.code)
    }

    async fn get(&self, code: &str) -> Result<OAuthAuthorizationCodeRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT code, client_id, tenant_id, redirect_uri, scopes, \
                    code_challenge, code_challenge_method, expires_at, created_at \
             FROM oauth_authorization_codes WHERE code = $1",
            code,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "oauth_authorization_code",
            id: code.to_string(),
        })?;

        parse_auth_code_row(
            row.code,
            row.client_id,
            row.tenant_id,
            row.redirect_uri,
            row.scopes,
            row.code_challenge,
            row.code_challenge_method,
            row.expires_at,
            row.created_at,
        )
    }

    async fn consume(&self, code: &str) -> Result<OAuthAuthorizationCodeRecord, SentioError> {
        let row = sqlx::query!(
            "DELETE FROM oauth_authorization_codes WHERE code = $1 \
             RETURNING code, client_id, tenant_id, redirect_uri, scopes, \
                       code_challenge, code_challenge_method, expires_at, created_at",
            code,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "oauth_authorization_code",
            id: code.to_string(),
        })?;

        parse_auth_code_row(
            row.code,
            row.client_id,
            row.tenant_id,
            row.redirect_uri,
            row.scopes,
            row.code_challenge,
            row.code_challenge_method,
            row.expires_at,
            row.created_at,
        )
    }

    async fn delete_expired(&self) -> Result<u64, SentioError> {
        let result = sqlx::query!("DELETE FROM oauth_authorization_codes WHERE expires_at < now()")
            .execute(&self.pool)
            .await
            .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }
}
