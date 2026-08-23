use std::net::IpAddr;

use sentio_core::config::AbuseConfig;

use crate::redis_conn::KvConn;

pub struct AuthGuard<R: KvConn> {
    redis: R,
    max_failures: u32,
    ban_duration_secs: u64,
}

impl<R: KvConn> AuthGuard<R> {
    pub fn new(redis: R, config: &AbuseConfig) -> Self {
        Self {
            redis,
            max_failures: config.max_auth_failures_per_hour,
            ban_duration_secs: config.ban_duration_secs,
        }
    }

    /// Record an authentication failure. Returns `true` if the failure count
    /// has reached the threshold and the IP has been auto-banned.
    pub async fn record_failure(&self, ip: &IpAddr) -> bool {
        let hour_bucket = chrono::Utc::now().timestamp() / 3600;
        let key = format!("sentio:smtp:auth:fail:{ip}:{hour_bucket}");

        metrics::counter!("sentio_abuse_auth_failures_total").increment(1);

        let count = self.redis.incr(&key).await.unwrap_or(1);
        if count == 1 {
            let _ = self.redis.expire(&key, 7200).await;
        }

        if count as u32 >= self.max_failures {
            // Auto-ban: write the ban key directly (same format as BanChecker)
            let ban_key = format!("sentio:smtp:ban:{ip}");
            let _ = self
                .redis
                .set_ex(&ban_key, "1", self.ban_duration_secs)
                .await;
            tracing::warn!(%ip, count, "auto-banned IP due to auth failures");
            true
        } else {
            false
        }
    }

    /// Clear the failure counter for an IP (e.g., after successful auth).
    pub async fn reset(&self, ip: &IpAddr) {
        let hour_bucket = chrono::Utc::now().timestamp() / 3600;
        let key = format!("sentio:smtp:auth:fail:{ip}:{hour_bucket}");
        let _ = self.redis.del(&key).await;
    }

    /// Get the current failure count for an IP in the current hour window.
    pub async fn failure_count(&self, ip: &IpAddr) -> u32 {
        let hour_bucket = chrono::Utc::now().timestamp() / 3600;
        let key = format!("sentio:smtp:auth:fail:{ip}:{hour_bucket}");
        self.redis
            .get_opt(&key)
            .await
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ban::BanChecker;
    use crate::mock::MockRedis;

    #[tokio::test]
    async fn failure_accumulation() {
        let redis = MockRedis::new();
        let guard = AuthGuard::new(
            redis,
            &AbuseConfig {
                max_auth_failures_per_hour: 5,
                ..Default::default()
            },
        );
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        for _ in 0..4 {
            assert!(!guard.record_failure(&ip).await);
        }
        assert_eq!(guard.failure_count(&ip).await, 4);
    }

    #[tokio::test]
    async fn auto_ban_triggered() {
        let redis = MockRedis::new();
        let config = AbuseConfig {
            max_auth_failures_per_hour: 3,
            ..Default::default()
        };
        let guard = AuthGuard::new(redis.clone(), &config);
        let ban_checker = BanChecker::new(redis, &config);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        assert!(!guard.record_failure(&ip).await); // 1
        assert!(!guard.record_failure(&ip).await); // 2
        assert!(guard.record_failure(&ip).await); // 3 → triggers ban

        // Verify ban was set (BanChecker reads the same key format)
        assert!(ban_checker.is_banned(&ip).await);
    }

    #[tokio::test]
    async fn reset_clears_count() {
        let redis = MockRedis::new();
        let guard = AuthGuard::new(redis, &AbuseConfig::default());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        guard.record_failure(&ip).await;
        guard.record_failure(&ip).await;
        assert_eq!(guard.failure_count(&ip).await, 2);

        guard.reset(&ip).await;
        assert_eq!(guard.failure_count(&ip).await, 0);
    }
}
