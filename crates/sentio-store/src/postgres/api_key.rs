use base64::Engine;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::error::SentioError;
use sentio_core::ids::ApiKeyId;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{ApiKeyCreated, ApiKeyRecord, ApiKeyRepository};

pub struct PgApiKeyRepository {
    pool: PgPool,
}

impl PgApiKeyRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ApiKeyRepository for PgApiKeyRepository {
    async fn create(
        &self,
        tenant_id: TenantId,
        name: &str,
        scopes: &[String],
    ) -> Result<ApiKeyCreated, SentioError> {
        // Generate 256-bit random key from two UUIDv4s
        let mut key_bytes = [0u8; 32];
        key_bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        key_bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());

        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_bytes);
        let raw_key = format!("sentio_{encoded}");
        let key_prefix = raw_key[..12].to_string();

        // SHA-256 hash for storage
        let hash = Sha256::digest(raw_key.as_bytes());
        let key_hash: String = hash.iter().map(|b| format!("{b:02x}")).collect();

        let row = sqlx::query!(
            "INSERT INTO api_keys (tenant_id, key_hash, key_prefix, name, scopes) \
             VALUES ($1, $2, $3, $4, $5) RETURNING id",
            tenant_id.0,
            key_hash,
            key_prefix,
            name,
            scopes,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(ApiKeyCreated {
            id: ApiKeyId(row.id),
            raw_key,
        })
    }

    async fn verify(&self, key_hash: &str) -> Result<ApiKeyRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, tenant_id, key_prefix, name, scopes, created_at FROM api_keys \
             WHERE key_hash = $1 AND (expires_at IS NULL OR expires_at > now())",
            key_hash,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::Auth("invalid or expired API key".into()))?;

        Ok(ApiKeyRecord {
            id: ApiKeyId(row.id),
            tenant_id: TenantId(row.tenant_id),
            key_prefix: row.key_prefix,
            name: row.name,
            scopes: row.scopes,
            created_at: row.created_at,
        })
    }

    async fn list_by_tenant(&self, tenant_id: TenantId) -> Result<Vec<ApiKeyRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, tenant_id, key_prefix, name, scopes, created_at \
             FROM api_keys WHERE tenant_id = $1 ORDER BY created_at DESC",
            tenant_id.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| ApiKeyRecord {
                id: ApiKeyId(r.id),
                tenant_id: TenantId(r.tenant_id),
                key_prefix: r.key_prefix,
                name: r.name,
                scopes: r.scopes,
                created_at: r.created_at,
            })
            .collect())
    }

    async fn revoke(&self, id: ApiKeyId) -> Result<(), SentioError> {
        let result = sqlx::query!("DELETE FROM api_keys WHERE id = $1", id.0)
            .execute(&self.pool)
            .await
            .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "api_key",
                id: id.to_string(),
            });
        }
        Ok(())
    }
}
