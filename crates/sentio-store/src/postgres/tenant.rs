use std::str::FromStr;

use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::error::SentioError;
use sentio_core::tenant::{TenantId, TenantStatus, TenantTier};
use sentio_core::traits::{TenantRecord, TenantRepository, TenantUpdate};

pub struct PgTenantRepository {
    pool: PgPool,
}

impl PgTenantRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_tenant(
    id: Uuid,
    name: String,
    tier: String,
    status: String,
    verp_enabled: bool,
) -> Result<TenantRecord, SentioError> {
    Ok(TenantRecord {
        id: TenantId(id),
        name,
        tier: TenantTier::from_str(&tier)
            .map_err(|_| SentioError::Database(format!("invalid tier: {tier}")))?,
        status: TenantStatus::from_str(&status)
            .map_err(|_| SentioError::Database(format!("invalid status: {status}")))?,
        verp_enabled,
    })
}

impl TenantRepository for PgTenantRepository {
    async fn create(&self, name: &str, tier: TenantTier) -> Result<TenantId, SentioError> {
        let tier_str = tier.to_string();
        let row = sqlx::query!(
            "INSERT INTO tenants (name, tier) VALUES ($1, $2) RETURNING id",
            name,
            tier_str,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(TenantId(row.id))
    }

    async fn get(&self, id: TenantId) -> Result<TenantRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, name, tier, status, verp_enabled FROM tenants WHERE id = $1",
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "tenant",
            id: id.to_string(),
        })?;

        parse_tenant(row.id, row.name, row.tier, row.status, row.verp_enabled)
    }

    async fn update_status(&self, id: TenantId, status: TenantStatus) -> Result<(), SentioError> {
        let status_str = status.to_string();
        let result = sqlx::query!(
            "UPDATE tenants SET status = $1 WHERE id = $2",
            status_str,
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "tenant",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn list(
        &self,
        status: Option<TenantStatus>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<TenantRecord>, SentioError> {
        match status {
            Some(s) => {
                let status_str = s.to_string();
                let rows = sqlx::query!(
                    "SELECT id, name, tier, status, verp_enabled FROM tenants \
                     WHERE status = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                    status_str,
                    limit,
                    offset,
                )
                .fetch_all(&self.pool)
                .await
                .map_err(|e| SentioError::Database(e.to_string()))?;

                rows.into_iter()
                    .map(|r| parse_tenant(r.id, r.name, r.tier, r.status, r.verp_enabled))
                    .collect()
            }
            None => {
                let rows = sqlx::query!(
                    "SELECT id, name, tier, status, verp_enabled FROM tenants \
                     ORDER BY created_at DESC LIMIT $1 OFFSET $2",
                    limit,
                    offset,
                )
                .fetch_all(&self.pool)
                .await
                .map_err(|e| SentioError::Database(e.to_string()))?;

                rows.into_iter()
                    .map(|r| parse_tenant(r.id, r.name, r.tier, r.status, r.verp_enabled))
                    .collect()
            }
        }
    }

    async fn update(&self, id: TenantId, update: TenantUpdate) -> Result<(), SentioError> {
        let tier_str = update.tier.map(|t| t.to_string());

        let result = sqlx::query!(
            "UPDATE tenants SET \
                 name = COALESCE($1, name), \
                 tier = COALESCE($2, tier), \
                 verp_enabled = COALESCE($3, verp_enabled) \
             WHERE id = $4",
            update.name,
            tier_str,
            update.verp_enabled,
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "tenant",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn delete(&self, id: TenantId) -> Result<(), SentioError> {
        let result = sqlx::query!("DELETE FROM tenants WHERE id = $1", id.0)
            .execute(&self.pool)
            .await
            .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "tenant",
                id: id.to_string(),
            });
        }
        Ok(())
    }
}
