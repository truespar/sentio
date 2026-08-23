use std::str::FromStr;

use chrono::{DateTime, NaiveDate, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::auth::WarmupStatus;
use sentio_core::error::SentioError;
use sentio_core::ids::{IpPoolId, WarmupScheduleId};
use sentio_core::tenant::TenantId;
use sentio_core::traits::{IpWarmupScheduleRepository, NewWarmupSchedule, WarmupScheduleRecord};

pub struct PgIpWarmupScheduleRepository {
    pool: PgPool,
}

impl PgIpWarmupScheduleRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_warmup_row(
    id: Uuid,
    ip_pool_id: Uuid,
    tenant_id: Uuid,
    start_date: NaiveDate,
    current_day: i32,
    daily_limit: i32,
    daily_increase_pct: f64,
    max_daily_limit: i32,
    isp_overrides: Option<serde_json::Value>,
    status: String,
    completed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
) -> Result<WarmupScheduleRecord, SentioError> {
    Ok(WarmupScheduleRecord {
        id: WarmupScheduleId(id),
        ip_pool_id: IpPoolId(ip_pool_id),
        tenant_id: TenantId(tenant_id),
        start_date,
        current_day,
        daily_limit,
        daily_increase_pct,
        max_daily_limit,
        isp_overrides,
        status: WarmupStatus::from_str(&status)
            .map_err(|_| SentioError::Database(format!("invalid warmup status: {status}")))?,
        completed_at,
        created_at,
        updated_at,
    })
}

impl IpWarmupScheduleRepository for PgIpWarmupScheduleRepository {
    async fn create(&self, schedule: NewWarmupSchedule) -> Result<WarmupScheduleId, SentioError> {
        // Use non-macro query because daily_increase_pct is DECIMAL in the DB
        // and sqlx::query! would require the bigdecimal feature for NUMERIC params.
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO ip_warmup_schedules \
                (ip_pool_id, tenant_id, start_date, daily_limit, daily_increase_pct, \
                 max_daily_limit, isp_overrides) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
        )
        .bind(schedule.ip_pool_id.0)
        .bind(schedule.tenant_id.0)
        .bind(schedule.start_date)
        .bind(schedule.daily_limit)
        .bind(schedule.daily_increase_pct)
        .bind(schedule.max_daily_limit)
        .bind(schedule.isp_overrides)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(WarmupScheduleId(id))
    }

    async fn get(&self, id: WarmupScheduleId) -> Result<WarmupScheduleRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, ip_pool_id, tenant_id, start_date, current_day, daily_limit, \
                    CAST(daily_increase_pct AS FLOAT8) as \"daily_increase_pct!\", \
                    max_daily_limit, isp_overrides, status, completed_at, created_at, updated_at \
             FROM ip_warmup_schedules WHERE id = $1",
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "ip_warmup_schedule",
            id: id.to_string(),
        })?;

        parse_warmup_row(
            row.id,
            row.ip_pool_id,
            row.tenant_id,
            row.start_date,
            row.current_day,
            row.daily_limit,
            row.daily_increase_pct,
            row.max_daily_limit,
            row.isp_overrides,
            row.status,
            row.completed_at,
            row.created_at,
            row.updated_at,
        )
    }

    async fn list_active(
        &self,
        tenant_id: Option<TenantId>,
    ) -> Result<Vec<WarmupScheduleRecord>, SentioError> {
        match tenant_id {
            Some(tid) => {
                let rows = sqlx::query!(
                    "SELECT id, ip_pool_id, tenant_id, start_date, current_day, daily_limit, \
                            CAST(daily_increase_pct AS FLOAT8) as \"daily_increase_pct!\", \
                            max_daily_limit, isp_overrides, status, completed_at, created_at, updated_at \
                     FROM ip_warmup_schedules \
                     WHERE status IN ('scheduled', 'in_progress') AND tenant_id = $1 \
                     ORDER BY created_at DESC",
                    tid.0,
                )
                .fetch_all(&self.pool)
                .await
                .map_err(|e| SentioError::Database(e.to_string()))?;

                rows.into_iter()
                    .map(|r| {
                        parse_warmup_row(
                            r.id,
                            r.ip_pool_id,
                            r.tenant_id,
                            r.start_date,
                            r.current_day,
                            r.daily_limit,
                            r.daily_increase_pct,
                            r.max_daily_limit,
                            r.isp_overrides,
                            r.status,
                            r.completed_at,
                            r.created_at,
                            r.updated_at,
                        )
                    })
                    .collect()
            }
            None => {
                let rows = sqlx::query!(
                    "SELECT id, ip_pool_id, tenant_id, start_date, current_day, daily_limit, \
                            CAST(daily_increase_pct AS FLOAT8) as \"daily_increase_pct!\", \
                            max_daily_limit, isp_overrides, status, completed_at, created_at, updated_at \
                     FROM ip_warmup_schedules \
                     WHERE status IN ('scheduled', 'in_progress') \
                     ORDER BY created_at DESC",
                )
                .fetch_all(&self.pool)
                .await
                .map_err(|e| SentioError::Database(e.to_string()))?;

                rows.into_iter()
                    .map(|r| {
                        parse_warmup_row(
                            r.id,
                            r.ip_pool_id,
                            r.tenant_id,
                            r.start_date,
                            r.current_day,
                            r.daily_limit,
                            r.daily_increase_pct,
                            r.max_daily_limit,
                            r.isp_overrides,
                            r.status,
                            r.completed_at,
                            r.created_at,
                            r.updated_at,
                        )
                    })
                    .collect()
            }
        }
    }

    async fn update_progress(
        &self,
        id: WarmupScheduleId,
        current_day: i32,
        daily_limit: i32,
    ) -> Result<(), SentioError> {
        let result = sqlx::query!(
            "UPDATE ip_warmup_schedules SET current_day = $1, daily_limit = $2 WHERE id = $3",
            current_day,
            daily_limit,
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "ip_warmup_schedule",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn update_status(
        &self,
        id: WarmupScheduleId,
        status: WarmupStatus,
    ) -> Result<(), SentioError> {
        let status_str = status.to_string();

        // Conditionally set completed_at when transitioning to completed
        let result = if status == WarmupStatus::Completed {
            sqlx::query!(
                "UPDATE ip_warmup_schedules SET status = $1, completed_at = now() WHERE id = $2",
                status_str,
                id.0,
            )
            .execute(&self.pool)
            .await
        } else {
            sqlx::query!(
                "UPDATE ip_warmup_schedules SET status = $1 WHERE id = $2",
                status_str,
                id.0,
            )
            .execute(&self.pool)
            .await
        }
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "ip_warmup_schedule",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn delete(&self, id: WarmupScheduleId) -> Result<(), SentioError> {
        let result = sqlx::query!("DELETE FROM ip_warmup_schedules WHERE id = $1", id.0,)
            .execute(&self.pool)
            .await
            .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "ip_warmup_schedule",
                id: id.to_string(),
            });
        }
        Ok(())
    }
}
