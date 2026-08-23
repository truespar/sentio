use std::collections::HashSet;
use std::net::IpAddr;

use ipnet::IpNet;

use sentio_core::config::AbuseConfig;

use crate::redis_conn::KvConn;

/// IP whitelist combining static (config-based) and dynamic (Redis-based) checks.
pub struct Whitelist<R: KvConn> {
    redis: R,
    static_ips: HashSet<IpAddr>,
    static_cidrs: Vec<IpNet>,
}

impl<R: KvConn> Whitelist<R> {
    pub fn new(redis: R, config: &AbuseConfig) -> Self {
        let static_ips: HashSet<IpAddr> = config
            .whitelist_ips
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        let static_cidrs: Vec<IpNet> = config
            .whitelist_cidrs
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        if !static_ips.is_empty() || !static_cidrs.is_empty() {
            tracing::info!(
                ips = static_ips.len(),
                cidrs = static_cidrs.len(),
                "whitelist initialized"
            );
        }

        Self {
            redis,
            static_ips,
            static_cidrs,
        }
    }

    /// Check if an IP is whitelisted (static or dynamic).
    pub async fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        // Static IP match
        if self.static_ips.contains(ip) {
            return true;
        }

        // Static CIDR match
        for cidr in &self.static_cidrs {
            if cidr.contains(ip) {
                return true;
            }
        }

        // Dynamic Redis check
        let key = format!("sentio:smtp:whitelist:{ip}");
        self.redis.exists(&key).await.unwrap_or(false)
    }

    /// Add an IP to the dynamic whitelist in Redis.
    pub async fn add(&self, ip: &IpAddr) {
        let key = format!("sentio:smtp:whitelist:{ip}");
        // No expiry - permanent until removed
        if let Err(e) = self.redis.set_ex(&key, "1", 86400 * 365).await {
            tracing::error!(%ip, error = %e, "failed to add IP to whitelist");
        }
    }

    /// Remove an IP from the dynamic whitelist.
    pub async fn remove(&self, ip: &IpAddr) {
        let key = format!("sentio:smtp:whitelist:{ip}");
        if let Err(e) = self.redis.del(&key).await {
            tracing::error!(%ip, error = %e, "failed to remove IP from whitelist");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockRedis;

    fn config_with_whitelist() -> AbuseConfig {
        AbuseConfig {
            whitelist_ips: vec!["10.0.0.1".into(), "192.168.1.1".into()],
            whitelist_cidrs: vec!["172.16.0.0/12".into()],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn static_ip_whitelisted() {
        let redis = MockRedis::new();
        let wl = Whitelist::new(redis, &config_with_whitelist());
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(wl.is_whitelisted(&ip).await);
    }

    #[tokio::test]
    async fn static_cidr_whitelisted() {
        let redis = MockRedis::new();
        let wl = Whitelist::new(redis, &config_with_whitelist());

        let ip: IpAddr = "172.20.5.1".parse().unwrap();
        assert!(
            wl.is_whitelisted(&ip).await,
            "172.20.5.1 should be in 172.16.0.0/12"
        );
    }

    #[tokio::test]
    async fn non_whitelisted_ip() {
        let redis = MockRedis::new();
        let wl = Whitelist::new(redis, &config_with_whitelist());
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!wl.is_whitelisted(&ip).await);
    }

    #[tokio::test]
    async fn dynamic_whitelist_add_remove() {
        let redis = MockRedis::new();
        let wl = Whitelist::new(redis, &AbuseConfig::default());
        let ip: IpAddr = "5.5.5.5".parse().unwrap();

        assert!(!wl.is_whitelisted(&ip).await);

        wl.add(&ip).await;
        assert!(wl.is_whitelisted(&ip).await);

        wl.remove(&ip).await;
        assert!(!wl.is_whitelisted(&ip).await);
    }
}
