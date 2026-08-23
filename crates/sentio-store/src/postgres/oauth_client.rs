use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::error::SentioError;
use sentio_core::ids::OAuthClientId;
use sentio_core::oauth::OAuthClientStatus;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{NewOAuthClient, OAuthClientRecord, OAuthClientRepository};

pub struct PgOAuthClientRepository {
    pool: PgPool,
}

impl PgOAuthClientRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_oauth_client_row(
    id: Uuid,
    tenant_id: Uuid,
    client_id: String,
    client_secret_hash: String,
    name: String,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    scopes: Vec<String>,
    status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
) -> Result<OAuthClientRecord, SentioError> {
    Ok(OAuthClientRecord {
        id: OAuthClientId(id),
        tenant_id: TenantId(tenant_id),
        client_id,
        client_secret_hash,
        name,
        redirect_uris,
        grant_types,
        scopes,
        status: OAuthClientStatus::from_str(&status)
            .map_err(|_| SentioError::Database(format!("invalid oauth client status: {status}")))?,
        created_at,
        updated_at,
    })
}

impl OAuthClientRepository for PgOAuthClientRepository {
    async fn create(&self, client: NewOAuthClient) -> Result<OAuthClientId, SentioError> {
        let row = sqlx::query!(
            "INSERT INTO oauth_clients \
                (tenant_id, client_id, client_secret_hash, name, redirect_uris, \
                 grant_types, scopes) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
            client.tenant_id.0,
            client.client_id,
            client.client_secret_hash,
            client.name,
            &client.redirect_uris,
            &client.grant_types,
            &client.scopes,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(OAuthClientId(row.id))
    }

    async fn get(&self, id: OAuthClientId) -> Result<OAuthClientRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, tenant_id, client_id, client_secret_hash, name, \
                    redirect_uris, grant_types, scopes, status, created_at, updated_at \
             FROM oauth_clients WHERE id = $1",
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "oauth_client",
            id: id.to_string(),
        })?;

        parse_oauth_client_row(
            row.id,
            row.tenant_id,
            row.client_id,
            row.client_secret_hash,
            row.name,
            row.redirect_uris,
            row.grant_types,
            row.scopes,
            row.status,
            row.created_at,
            row.updated_at,
        )
    }

    async fn get_by_client_id(&self, client_id: &str) -> Result<OAuthClientRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, tenant_id, client_id, client_secret_hash, name, \
                    redirect_uris, grant_types, scopes, status, created_at, updated_at \
             FROM oauth_clients WHERE client_id = $1",
            client_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "oauth_client",
            id: client_id.to_string(),
        })?;

        parse_oauth_client_row(
            row.id,
            row.tenant_id,
            row.client_id,
            row.client_secret_hash,
            row.name,
            row.redirect_uris,
            row.grant_types,
            row.scopes,
            row.status,
            row.created_at,
            row.updated_at,
        )
    }

    async fn list_by_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<OAuthClientRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, tenant_id, client_id, client_secret_hash, name, \
                    redirect_uris, grant_types, scopes, status, created_at, updated_at \
             FROM oauth_clients WHERE tenant_id = $1 ORDER BY created_at DESC",
            tenant_id.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|r| {
                parse_oauth_client_row(
                    r.id,
                    r.tenant_id,
                    r.client_id,
                    r.client_secret_hash,
                    r.name,
                    r.redirect_uris,
                    r.grant_types,
                    r.scopes,
                    r.status,
                    r.created_at,
                    r.updated_at,
                )
            })
            .collect()
    }

    async fn revoke(&self, id: OAuthClientId) -> Result<(), SentioError> {
        let result = sqlx::query!(
            "UPDATE oauth_clients SET status = 'revoked' WHERE id = $1",
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "oauth_client",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn delete(&self, id: OAuthClientId) -> Result<(), SentioError> {
        let result = sqlx::query!("DELETE FROM oauth_clients WHERE id = $1", id.0)
            .execute(&self.pool)
            .await
            .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "oauth_client",
                id: id.to_string(),
            });
        }
        Ok(())
    }
}
