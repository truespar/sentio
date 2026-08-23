use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::error::SentioError;
use sentio_core::ids::SmtpCredentialId;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{NewSmtpCredential, SmtpCredentialRecord, SmtpCredentialRepository};

pub struct PgSmtpCredentialRepository {
    pool: PgPool,
}

impl PgSmtpCredentialRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn row_to_record(
    id: Uuid,
    tenant_id: Uuid,
    username: String,
    password_hash: String,
    mechanisms: Vec<String>,
    scram_stored_key: Option<String>,
    scram_server_key: Option<String>,
    scram_salt: Option<String>,
    scram_iterations: Option<i32>,
    enabled: bool,
) -> SmtpCredentialRecord {
    SmtpCredentialRecord {
        id: SmtpCredentialId(id),
        tenant_id: TenantId(tenant_id),
        username,
        password_hash,
        mechanisms,
        scram_stored_key,
        scram_server_key,
        scram_salt,
        scram_iterations,
        enabled,
    }
}

impl SmtpCredentialRepository for PgSmtpCredentialRepository {
    async fn create(&self, cred: NewSmtpCredential) -> Result<SmtpCredentialId, SentioError> {
        let row = sqlx::query!(
            "INSERT INTO smtp_credentials \
             (tenant_id, username, password_hash, mechanisms, \
              scram_stored_key, scram_server_key, scram_salt, scram_iterations) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
            cred.tenant_id.0,
            cred.username,
            cred.password_hash,
            &cred.mechanisms,
            cred.scram_stored_key,
            cred.scram_server_key,
            cred.scram_salt,
            cred.scram_iterations,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(SmtpCredentialId(row.id))
    }

    async fn lookup(&self, username: &str) -> Result<SmtpCredentialRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, tenant_id, username, password_hash, mechanisms, \
                    scram_stored_key, scram_server_key, scram_salt, scram_iterations, enabled \
             FROM smtp_credentials WHERE username = $1 AND enabled = true",
            username,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "smtp_credential",
            id: username.to_string(),
        })?;

        Ok(row_to_record(
            row.id,
            row.tenant_id,
            row.username,
            row.password_hash,
            row.mechanisms,
            row.scram_stored_key,
            row.scram_server_key,
            row.scram_salt,
            row.scram_iterations,
            row.enabled,
        ))
    }

    async fn list_by_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<SmtpCredentialRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, tenant_id, username, password_hash, mechanisms, \
                    scram_stored_key, scram_server_key, scram_salt, scram_iterations, enabled \
             FROM smtp_credentials WHERE tenant_id = $1 ORDER BY created_at DESC",
            tenant_id.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| {
                row_to_record(
                    r.id,
                    r.tenant_id,
                    r.username,
                    r.password_hash,
                    r.mechanisms,
                    r.scram_stored_key,
                    r.scram_server_key,
                    r.scram_salt,
                    r.scram_iterations,
                    r.enabled,
                )
            })
            .collect())
    }

    async fn update_enabled(&self, id: SmtpCredentialId, enabled: bool) -> Result<(), SentioError> {
        let result = sqlx::query!(
            "UPDATE smtp_credentials SET enabled = $1 WHERE id = $2",
            enabled,
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "smtp_credential",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn delete(&self, id: SmtpCredentialId) -> Result<(), SentioError> {
        let result = sqlx::query!("DELETE FROM smtp_credentials WHERE id = $1", id.0)
            .execute(&self.pool)
            .await
            .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "smtp_credential",
                id: id.to_string(),
            });
        }
        Ok(())
    }
}
