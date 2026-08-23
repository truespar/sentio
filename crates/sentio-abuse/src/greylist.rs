use std::net::IpAddr;

use sha2::{Digest, Sha256};

use sentio_core::config::GreylistConfig;

use crate::redis_conn::KvConn;

#[derive(Debug, PartialEq, Eq)]
pub enum GreylistAction {
    Accept,
    Defer,
    Disabled,
}

pub struct Greylister<R: KvConn> {
    redis: R,
    enabled: bool,
    min_delay_secs: u64,
    max_age_hours: u32,
}

impl<R: KvConn> Greylister<R> {
    pub fn new(redis: R, config: &GreylistConfig) -> Self {
        Self {
            redis,
            enabled: config.enabled,
            min_delay_secs: config.min_delay_secs,
            max_age_hours: config.max_age_hours,
        }
    }

    /// Evaluate a greylisting triplet (IP, envelope-from, envelope-to).
    ///
    /// - First time seeing this triplet → stores it and returns `Defer`
    /// - Seen before but too recent → returns `Defer`
    /// - Seen before and old enough → returns `Accept`
    /// - Greylisting disabled → returns `Disabled`
    pub async fn check(&self, ip: &IpAddr, from: &str, to: &str) -> GreylistAction {
        if !self.enabled {
            return GreylistAction::Disabled;
        }

        let hash = sha256_hex(&format!("{ip}|{from}|{to}"));
        let key = format!("sentio:smtp:grey:{hash}");
        let ttl = u64::from(self.max_age_hours) * 3600;

        match self.redis.get_opt(&key).await {
            Ok(Some(first_seen_str)) => {
                let first_seen: i64 = first_seen_str.parse().unwrap_or(0);
                let now = chrono::Utc::now().timestamp();
                let age = now - first_seen;

                if age >= self.min_delay_secs as i64 {
                    GreylistAction::Accept
                } else {
                    GreylistAction::Defer
                }
            }
            _ => {
                // New triplet - store first-seen timestamp
                let now = chrono::Utc::now().timestamp();
                let _ = self.redis.set_ex(&key, &now.to_string(), ttl).await;
                GreylistAction::Defer
            }
        }
    }
}

pub(crate) fn sha256_hex(input: &str) -> String {
    use std::fmt::Write;
    let result = Sha256::digest(input.as_bytes());
    let mut hex = String::with_capacity(64);
    for b in result.iter() {
        write!(hex, "{b:02x}").unwrap();
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockRedis;

    fn greylist_config(enabled: bool) -> GreylistConfig {
        GreylistConfig {
            enabled,
            min_delay_secs: 300,
            max_age_hours: 48,
        }
    }

    #[tokio::test]
    async fn new_triplet_defers() {
        let redis = MockRedis::new();
        let gl = Greylister::new(redis, &greylist_config(true));
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        let action = gl
            .check(&ip, "sender@example.com", "rcpt@example.com")
            .await;
        assert_eq!(action, GreylistAction::Defer);
    }

    #[tokio::test]
    async fn recent_triplet_still_defers() {
        let redis = MockRedis::new();
        let gl = Greylister::new(redis, &greylist_config(true));
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        // First call stores the triplet
        gl.check(&ip, "sender@example.com", "rcpt@example.com")
            .await;

        // Second call immediately - age < min_delay_secs → still Defer
        let action = gl
            .check(&ip, "sender@example.com", "rcpt@example.com")
            .await;
        assert_eq!(action, GreylistAction::Defer);
    }

    #[tokio::test]
    async fn aged_triplet_accepts() {
        let redis = MockRedis::new();
        let gl = Greylister::new(redis.clone(), &greylist_config(true));
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let from = "sender@example.com";
        let to = "rcpt@example.com";

        // First check creates the entry
        gl.check(&ip, from, to).await;

        // Manually backdate the first-seen timestamp to 10 minutes ago
        let triplet = format!("{ip}|{from}|{to}");
        let hash = sha256_hex(&triplet);
        let key = format!("sentio:smtp:grey:{hash}");
        let old_time = chrono::Utc::now().timestamp() - 600; // 600s > 300s min_delay
        redis.raw_set(&key, &old_time.to_string());

        let action = gl.check(&ip, from, to).await;
        assert_eq!(action, GreylistAction::Accept);
    }

    #[tokio::test]
    async fn disabled_returns_disabled() {
        let redis = MockRedis::new();
        let gl = Greylister::new(redis, &greylist_config(false));
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        let action = gl
            .check(&ip, "sender@example.com", "rcpt@example.com")
            .await;
        assert_eq!(action, GreylistAction::Disabled);
    }
}
