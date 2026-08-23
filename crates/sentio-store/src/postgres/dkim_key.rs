use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::auth::{DkimAlgorithm, DkimKeyStatus};
use sentio_core::error::SentioError;
use sentio_core::ids::DkimKeyId;
use sentio_core::message::DomainId;
use sentio_core::traits::{DkimKeyRecord, DkimKeyRepository, NewDkimKey};

pub struct PgDkimKeyRepository {
    pool: PgPool,
}

impl PgDkimKeyRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_dkim_row(
    id: Uuid,
    domain_id: Uuid,
    selector: String,
    algorithm: String,
    private_key: String,
    public_key: String,
    key_size: Option<i32>,
    status: String,
    activated_at: Option<DateTime<Utc>>,
    retired_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
) -> Result<DkimKeyRecord, SentioError> {
    Ok(DkimKeyRecord {
        id: DkimKeyId(id),
        domain_id: DomainId(domain_id),
        selector,
        algorithm: DkimAlgorithm::from_str(&algorithm)
            .map_err(|_| SentioError::Database(format!("invalid dkim algorithm: {algorithm}")))?,
        private_key,
        public_key,
        key_size,
        status: DkimKeyStatus::from_str(&status)
            .map_err(|_| SentioError::Database(format!("invalid dkim key status: {status}")))?,
        activated_at,
        retired_at,
        created_at,
    })
}

impl DkimKeyRepository for PgDkimKeyRepository {
    async fn create(&self, key: NewDkimKey) -> Result<DkimKeyId, SentioError> {
        let algorithm_str = key.algorithm.to_string();
        let row = sqlx::query!(
            "INSERT INTO dkim_keys (domain_id, selector, algorithm, private_key, public_key, key_size, activated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, now()) RETURNING id",
            key.domain_id.0,
            key.selector,
            algorithm_str,
            key.private_key,
            key.public_key,
            key.key_size,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(DkimKeyId(row.id))
    }

    async fn get(&self, id: DkimKeyId) -> Result<DkimKeyRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, domain_id, selector, algorithm, private_key, public_key, \
                    key_size, status, activated_at, retired_at, created_at \
             FROM dkim_keys WHERE id = $1",
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "dkim_key",
            id: id.to_string(),
        })?;

        parse_dkim_row(
            row.id,
            row.domain_id,
            row.selector,
            row.algorithm,
            row.private_key,
            row.public_key,
            row.key_size,
            row.status,
            row.activated_at,
            row.retired_at,
            row.created_at,
        )
    }

    async fn get_active_for_domain(
        &self,
        domain_id: DomainId,
    ) -> Result<DkimKeyRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, domain_id, selector, algorithm, private_key, public_key, \
                    key_size, status, activated_at, retired_at, created_at \
             FROM dkim_keys WHERE domain_id = $1 AND status = 'active' \
             LIMIT 1",
            domain_id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "dkim_key",
            id: format!("active key for domain {domain_id}"),
        })?;

        parse_dkim_row(
            row.id,
            row.domain_id,
            row.selector,
            row.algorithm,
            row.private_key,
            row.public_key,
            row.key_size,
            row.status,
            row.activated_at,
            row.retired_at,
            row.created_at,
        )
    }

    async fn list_by_domain(&self, domain_id: DomainId) -> Result<Vec<DkimKeyRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, domain_id, selector, algorithm, private_key, public_key, \
                    key_size, status, activated_at, retired_at, created_at \
             FROM dkim_keys WHERE domain_id = $1 ORDER BY created_at DESC",
            domain_id.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|r| {
                parse_dkim_row(
                    r.id,
                    r.domain_id,
                    r.selector,
                    r.algorithm,
                    r.private_key,
                    r.public_key,
                    r.key_size,
                    r.status,
                    r.activated_at,
                    r.retired_at,
                    r.created_at,
                )
            })
            .collect()
    }

    async fn rotate(
        &self,
        domain_id: DomainId,
        new_key: NewDkimKey,
    ) -> Result<DkimKeyId, SentioError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SentioError::Database(e.to_string()))?;

        // Set current active key to rotating
        sqlx::query!(
            "UPDATE dkim_keys SET status = 'rotating' \
             WHERE domain_id = $1 AND status = 'active'",
            domain_id.0,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        // Insert new active key
        let algorithm_str = new_key.algorithm.to_string();
        let row = sqlx::query!(
            "INSERT INTO dkim_keys (domain_id, selector, algorithm, private_key, public_key, key_size, activated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, now()) RETURNING id",
            new_key.domain_id.0,
            new_key.selector,
            algorithm_str,
            new_key.private_key,
            new_key.public_key,
            new_key.key_size,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(DkimKeyId(row.id))
    }

    async fn retire(&self, id: DkimKeyId) -> Result<(), SentioError> {
        let result = sqlx::query!(
            "UPDATE dkim_keys SET status = 'retired', retired_at = now() WHERE id = $1",
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "dkim_key",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn delete(&self, id: DkimKeyId) -> Result<(), SentioError> {
        let result = sqlx::query!("DELETE FROM dkim_keys WHERE id = $1", id.0)
            .execute(&self.pool)
            .await
            .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "dkim_key",
                id: id.to_string(),
            });
        }
        Ok(())
    }
}
