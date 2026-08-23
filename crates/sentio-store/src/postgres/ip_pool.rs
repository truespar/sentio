use std::str::FromStr;

use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::auth::{IpPoolStatus, IpPoolType};
use sentio_core::error::SentioError;
use sentio_core::ids::IpPoolId;
use sentio_core::traits::{IpPoolRecord, IpPoolRepository, NewIpPool};

pub struct PgIpPoolRepository {
    pool: PgPool,
}

impl PgIpPoolRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_ip_pool_row(
    id: Uuid,
    name: String,
    pool_type: String,
    ips: Vec<IpNetwork>,
    status: String,
    created_at: DateTime<Utc>,
) -> Result<IpPoolRecord, SentioError> {
    Ok(IpPoolRecord {
        id: IpPoolId(id),
        name,
        pool_type: IpPoolType::from_str(&pool_type)
            .map_err(|_| SentioError::Database(format!("invalid ip pool type: {pool_type}")))?,
        ips,
        status: IpPoolStatus::from_str(&status)
            .map_err(|_| SentioError::Database(format!("invalid ip pool status: {status}")))?,
        created_at,
    })
}

impl IpPoolRepository for PgIpPoolRepository {
    async fn create(&self, ip_pool: NewIpPool) -> Result<IpPoolId, SentioError> {
        let pool_type_str = ip_pool.pool_type.to_string();
        let ips: Vec<IpNetwork> = ip_pool.ips;
        let row = sqlx::query!(
            "INSERT INTO ip_pools (name, pool_type, ips) VALUES ($1, $2, $3) RETURNING id",
            ip_pool.name,
            pool_type_str,
            &ips as &[IpNetwork],
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(IpPoolId(row.id))
    }

    async fn get(&self, id: IpPoolId) -> Result<IpPoolRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, name, pool_type, ips, status, created_at \
             FROM ip_pools WHERE id = $1",
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "ip_pool",
            id: id.to_string(),
        })?;

        parse_ip_pool_row(
            row.id,
            row.name,
            row.pool_type,
            row.ips,
            row.status,
            row.created_at,
        )
    }

    async fn list(&self, status: Option<IpPoolStatus>) -> Result<Vec<IpPoolRecord>, SentioError> {
        match status {
            Some(s) => {
                let status_str = s.to_string();
                let rows = sqlx::query!(
                    "SELECT id, name, pool_type, ips, status, created_at \
                     FROM ip_pools WHERE status = $1 ORDER BY created_at DESC",
                    status_str,
                )
                .fetch_all(&self.pool)
                .await
                .map_err(|e| SentioError::Database(e.to_string()))?;

                rows.into_iter()
                    .map(|r| {
                        parse_ip_pool_row(r.id, r.name, r.pool_type, r.ips, r.status, r.created_at)
                    })
                    .collect()
            }
            None => {
                let rows = sqlx::query!(
                    "SELECT id, name, pool_type, ips, status, created_at \
                     FROM ip_pools ORDER BY created_at DESC",
                )
                .fetch_all(&self.pool)
                .await
                .map_err(|e| SentioError::Database(e.to_string()))?;

                rows.into_iter()
                    .map(|r| {
                        parse_ip_pool_row(r.id, r.name, r.pool_type, r.ips, r.status, r.created_at)
                    })
                    .collect()
            }
        }
    }

    async fn update_status(&self, id: IpPoolId, status: IpPoolStatus) -> Result<(), SentioError> {
        let status_str = status.to_string();
        let result = sqlx::query!(
            "UPDATE ip_pools SET status = $1 WHERE id = $2",
            status_str,
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "ip_pool",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn add_ips(&self, id: IpPoolId, ips: &[IpNetwork]) -> Result<(), SentioError> {
        let result = sqlx::query!(
            "UPDATE ip_pools SET ips = ips || $1 WHERE id = $2",
            ips as &[IpNetwork],
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "ip_pool",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn remove_ips(&self, id: IpPoolId, ips: &[IpNetwork]) -> Result<(), SentioError> {
        let result = sqlx::query!(
            "UPDATE ip_pools SET ips = ( \
                 SELECT COALESCE(array_agg(ip), '{}') \
                 FROM unnest(ips) AS ip \
                 WHERE ip != ALL($1) \
             ) WHERE id = $2",
            ips as &[IpNetwork],
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "ip_pool",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn delete(&self, id: IpPoolId) -> Result<(), SentioError> {
        let result = sqlx::query!("DELETE FROM ip_pools WHERE id = $1", id.0)
            .execute(&self.pool)
            .await
            .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "ip_pool",
                id: id.to_string(),
            });
        }
        Ok(())
    }
}
