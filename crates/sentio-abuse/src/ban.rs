use std::net::IpAddr;

use sentio_core::config::AbuseConfig;

use crate::redis_conn::KvConn;

pub struct BanChecker<R: KvConn> {
    redis: R,
    default_duration_secs: u64,
}

impl<R: KvConn> BanChecker<R> {
    pub fn new(redis: R, config: &AbuseConfig) -> Self {
        Self {
            redis,
            default_duration_secs: config.ban_duration_secs,
        }
    }

    pub async fn is_banned(&self, ip: &IpAddr) -> bool {
        let key = format!("sentio:smtp:ban:{ip}");
        self.redis.exists(&key).await.unwrap_or(false)
    }

    pub async fn ban(&self, ip: &IpAddr, duration_secs: u64) {
        let key = format!("sentio:smtp:ban:{ip}");
        if let Err(e) = self.redis.set_ex(&key, "1", duration_secs).await {
            tracing::error!(%ip, error = %e, "failed to set ban");
        }
    }

    pub async fn ban_default(&self, ip: &IpAddr) {
        self.ban(ip, self.default_duration_secs).await;
    }

    pub async fn unban(&self, ip: &IpAddr) {
        let key = format!("sentio:smtp:ban:{ip}");
        if let Err(e) = self.redis.del(&key).await {
            tracing::error!(%ip, error = %e, "failed to remove ban");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockRedis;

    fn config() -> AbuseConfig {
        AbuseConfig::default()
    }

    #[tokio::test]
    async fn ban_unban_cycle() {
        let redis = MockRedis::new();
        let checker = BanChecker::new(redis, &config());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        assert!(!checker.is_banned(&ip).await);

        checker.ban(&ip, 3600).await;
        assert!(checker.is_banned(&ip).await);

        checker.unban(&ip).await;
        assert!(!checker.is_banned(&ip).await);
    }

    #[tokio::test]
    async fn ban_default_uses_config_duration() {
        let redis = MockRedis::new();
        let checker = BanChecker::new(redis, &config());
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        checker.ban_default(&ip).await;
        assert!(checker.is_banned(&ip).await);
    }

    #[tokio::test]
    async fn different_ips_are_independent() {
        let redis = MockRedis::new();
        let checker = BanChecker::new(redis, &config());
        let ip1: IpAddr = "1.2.3.4".parse().unwrap();
        let ip2: IpAddr = "5.6.7.8".parse().unwrap();

        checker.ban(&ip1, 3600).await;

        assert!(checker.is_banned(&ip1).await);
        assert!(!checker.is_banned(&ip2).await);
    }
}
