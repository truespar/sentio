use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::error::SentioError;
use sentio_core::ids::IpPoolId;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{TenantIpAssignmentRecord, TenantIpAssignmentRepository};

pub struct PgTenantIpAssignmentRepository {
    pool: PgPool,
}

impl PgTenantIpAssignmentRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_assignment_row(
    tenant_id: Uuid,
    ip_pool_id: Uuid,
    priority: i32,
    created_at: DateTime<Utc>,
) -> TenantIpAssignmentRecord {
    TenantIpAssignmentRecord {
        tenant_id: TenantId(tenant_id),
        ip_pool_id: IpPoolId(ip_pool_id),
        priority,
        created_at,
    }
}

impl TenantIpAssignmentRepository for PgTenantIpAssignmentRepository {
    async fn assign(
        &self,
        tenant_id: TenantId,
        ip_pool_id: IpPoolId,
        priority: i32,
    ) -> Result<(), SentioError> {
        sqlx::query!(
            "INSERT INTO tenant_ip_assignments (tenant_id, ip_pool_id, priority) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (tenant_id, ip_pool_id) DO UPDATE SET priority = EXCLUDED.priority",
            tenant_id.0,
            ip_pool_id.0,
            priority,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(())
    }

    async fn unassign(&self, tenant_id: TenantId, ip_pool_id: IpPoolId) -> Result<(), SentioError> {
        let result = sqlx::query!(
            "DELETE FROM tenant_ip_assignments WHERE tenant_id = $1 AND ip_pool_id = $2",
            tenant_id.0,
            ip_pool_id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "tenant_ip_assignment",
                id: format!("({tenant_id}, {ip_pool_id})"),
            });
        }
        Ok(())
    }

    async fn list_by_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<TenantIpAssignmentRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT tenant_id, ip_pool_id, priority, created_at \
             FROM tenant_ip_assignments WHERE tenant_id = $1 ORDER BY priority DESC",
            tenant_id.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| parse_assignment_row(r.tenant_id, r.ip_pool_id, r.priority, r.created_at))
            .collect())
    }

    async fn list_by_pool(
        &self,
        ip_pool_id: IpPoolId,
    ) -> Result<Vec<TenantIpAssignmentRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT tenant_id, ip_pool_id, priority, created_at \
             FROM tenant_ip_assignments WHERE ip_pool_id = $1 ORDER BY priority DESC",
            ip_pool_id.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| parse_assignment_row(r.tenant_id, r.ip_pool_id, r.priority, r.created_at))
            .collect())
    }

    async fn update_priority(
        &self,
        tenant_id: TenantId,
        ip_pool_id: IpPoolId,
        priority: i32,
    ) -> Result<(), SentioError> {
        let result = sqlx::query!(
            "UPDATE tenant_ip_assignments SET priority = $1 \
             WHERE tenant_id = $2 AND ip_pool_id = $3",
            priority,
            tenant_id.0,
            ip_pool_id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "tenant_ip_assignment",
                id: format!("({tenant_id}, {ip_pool_id})"),
            });
        }
        Ok(())
    }
}
