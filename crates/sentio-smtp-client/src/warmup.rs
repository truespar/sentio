use std::sync::Arc;

use chrono::Utc;
use sentio_core::auth::WarmupStatus;
use sentio_core::error::SentioError;
use sentio_core::kv::KvConn;
use sentio_core::tenant::TenantId;
use sentio_core::traits::IpWarmupScheduleRepository;
use sentio_store::RedisPool;
use tracing::{debug, info};

// ──────────────────────────────────────────────────────────────────────────────
// WarmupGuard
// ──────────────────────────────────────────────────────────────────────────────

pub struct WarmupGuard<W = sentio_store::postgres::PgIpWarmupScheduleRepository> {
    warmup_repo: Arc<W>,
    kv: RedisPool,
}

impl<W: IpWarmupScheduleRepository + 'static> WarmupGuard<W> {
    pub fn new(warmup_repo: Arc<W>, kv: RedisPool) -> Self {
        Self { warmup_repo, kv }
    }

    /// Check if sending is allowed under warmup limits for this tenant.
    /// If allowed, increments the daily counter. Returns `Err` if the limit
    /// has been reached.
    pub async fn check_and_increment(&self, tenant_id: TenantId) -> Result<(), SentioError> {
        let schedules = self.warmup_repo.list_active(Some(tenant_id)).await?;

        if schedules.is_empty() {
            // No active warmup - sending is unrestricted
            return Ok(());
        }

        let today = Utc::now().format("%Y-%m-%d").to_string();

        for schedule in &schedules {
            let key = format!("warmup:{}:{}", schedule.id.0, today);

            let count: i64 = self
                .kv
                .get_opt(&key)
                .await
                .ok()
                .flatten()
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);

            if count >= schedule.daily_limit as i64 {
                return Err(SentioError::RateLimit {
                    key: format!(
                        "warmup daily limit reached ({}/{})",
                        count, schedule.daily_limit
                    ),
                });
            }

            // Increment and set TTL (48h to cover timezone edge cases).
            let _ = self.kv.incr(&key).await;
            let _ = self.kv.expire(&key, 172800).await;

            debug!(
                schedule_id = %schedule.id.0,
                count = count + 1,
                limit = schedule.daily_limit,
                "warmup counter incremented"
            );
        }

        Ok(())
    }

    /// Advance daily warmup schedules: increase limits based on the configured
    /// daily increase percentage, and complete schedules that have reached their
    /// maximum daily limit.
    pub async fn advance_daily_schedules(&self) -> Result<(), SentioError> {
        let schedules = self.warmup_repo.list_active(None).await?;

        for schedule in &schedules {
            let days_elapsed = {
                let today = Utc::now().date_naive();
                (today - schedule.start_date).num_days().max(0) as i32
            };

            // Calculate new daily limit using compound growth
            let growth_factor = 1.0 + schedule.daily_increase_pct / 100.0;
            let new_limit = (schedule.daily_limit as f64 * growth_factor)
                .round()
                .min(schedule.max_daily_limit as f64) as i32;

            let new_day = days_elapsed;

            if new_limit >= schedule.max_daily_limit {
                // Schedule has reached max - mark as completed
                self.warmup_repo
                    .update_progress(schedule.id, new_day, schedule.max_daily_limit)
                    .await?;
                self.warmup_repo
                    .update_status(schedule.id, WarmupStatus::Completed)
                    .await?;
                info!(
                    schedule_id = %schedule.id.0,
                    max_limit = schedule.max_daily_limit,
                    "warmup schedule completed"
                );
            } else {
                self.warmup_repo
                    .update_progress(schedule.id, new_day, new_limit)
                    .await?;
                debug!(
                    schedule_id = %schedule.id.0,
                    day = new_day,
                    new_limit,
                    "warmup schedule advanced"
                );
            }
        }

        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #[test]
    fn test_advance_limit_calculation() {
        // With 20% daily increase, starting at 100
        let daily_limit: f64 = 100.0;
        let increase_pct: f64 = 20.0;
        let max_limit: i32 = 500;

        let growth: f64 = 1.0 + increase_pct / 100.0;
        let new_limit = (daily_limit * growth).round().min(max_limit as f64) as i32;
        assert_eq!(new_limit, 120);

        // After several days
        let mut limit: f64 = 100.0;
        for _ in 0..10 {
            limit = (limit * growth).min(max_limit as f64);
        }
        // 100 * 1.2^10 ≈ 619, capped at 500
        assert_eq!(limit.round() as i32, 500);
    }

    #[test]
    fn test_advance_completes_at_max() {
        let daily_limit: f64 = 490.0;
        let increase_pct: f64 = 10.0;
        let max_limit: i32 = 500;

        let growth: f64 = 1.0 + increase_pct / 100.0;
        let new_limit = (daily_limit * growth).round().min(max_limit as f64) as i32;
        // 490 * 1.1 = 539, capped at 500
        assert_eq!(new_limit, 500);
        assert!(new_limit >= max_limit);
    }
}
