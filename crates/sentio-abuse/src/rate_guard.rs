use std::net::IpAddr;

use sentio_core::config::AbuseConfig;
use sentio_core::error::SentioError;

use crate::redis_conn::KvConn;

pub struct RateGuard<R: KvConn> {
    redis: R,
    max_per_minute: u32,
}

impl<R: KvConn> RateGuard<R> {
    pub fn new(redis: R, config: &AbuseConfig) -> Self {
        Self {
            redis,
            max_per_minute: config.max_connections_per_minute,
        }
    }

    /// Check connection rate for an IP using a sliding-window algorithm
    /// (weighted average of current + previous fixed-window pair).
    ///
    /// Returns `Err(SentioError::RateLimit)` if the rate exceeds the configured
    /// maximum connections per minute.
    pub async fn check_rate(&self, ip: &IpAddr) -> Result<(), SentioError> {
        let now = chrono::Utc::now();
        let total_secs = now.timestamp();
        let current_minute = total_secs / 60;
        let elapsed_secs = total_secs % 60;
        let elapsed_fraction = elapsed_secs as f64 / 60.0;

        let current_key = format!("sentio:smtp:rate:conn:{ip}:{current_minute}");
        let prev_key = format!("sentio:smtp:rate:conn:{ip}:{}", current_minute - 1);

        // Increment current window counter
        let current_count = self.redis.incr(&current_key).await?;

        // Set TTL on first increment (covers current + next minute)
        if current_count == 1 {
            let _ = self.redis.expire(&current_key, 120).await;
        }

        // Read previous window count
        let prev_count: i64 = self
            .redis
            .get_opt(&prev_key)
            .await?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        // Weighted sliding window estimate
        let weighted = prev_count as f64 * (1.0 - elapsed_fraction) + current_count as f64;

        if weighted > self.max_per_minute as f64 {
            return Err(SentioError::RateLimit {
                key: format!("conn:{ip}"),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockRedis;

    fn config_with_limit(max: u32) -> AbuseConfig {
        AbuseConfig {
            max_connections_per_minute: max,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn under_limit_passes() {
        let redis = MockRedis::new();
        let guard = RateGuard::new(redis, &config_with_limit(10));
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        for _ in 0..9 {
            assert!(guard.check_rate(&ip).await.is_ok());
        }
    }

    #[tokio::test]
    async fn over_limit_rejects() {
        let redis = MockRedis::new();
        let guard = RateGuard::new(redis, &config_with_limit(5));
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        // First 5 calls should pass (counts 1..5, all <= 5)
        for _ in 0..5 {
            let _ = guard.check_rate(&ip).await;
        }

        // 6th call: count = 6, weighted > 5 → reject
        let result = guard.check_rate(&ip).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(SentioError::RateLimit { .. })));
    }

    #[tokio::test]
    async fn window_rotation_weighted() {
        let redis = MockRedis::new();
        let guard = RateGuard::new(redis.clone(), &config_with_limit(10));
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        // Simulate a previous window with 8 connections by directly setting the key.
        // Use a minute bucket that corresponds to the previous minute.
        let now = chrono::Utc::now().timestamp();
        let current_minute = now / 60;
        let prev_key = format!("sentio:smtp:rate:conn:{ip}:{}", current_minute - 1);
        redis.raw_set(&prev_key, "8");

        // First call in current window: current_count = 1
        // weighted = 8 * (1 - elapsed_fraction) + 1
        // At most: 8 * 1.0 + 1 = 9 (at second 0 of the minute) → passes (9 <= 10)
        assert!(guard.check_rate(&ip).await.is_ok());
    }

    #[tokio::test]
    async fn different_ips_independent() {
        let redis = MockRedis::new();
        let guard = RateGuard::new(redis, &config_with_limit(2));
        let ip1: IpAddr = "1.2.3.4".parse().unwrap();
        let ip2: IpAddr = "5.6.7.8".parse().unwrap();

        // Exhaust limit for ip1
        guard.check_rate(&ip1).await.unwrap();
        guard.check_rate(&ip1).await.unwrap();
        assert!(guard.check_rate(&ip1).await.is_err());

        // ip2 should still pass
        assert!(guard.check_rate(&ip2).await.is_ok());
    }
}
