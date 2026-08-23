use std::net::IpAddr;

use sentio_core::config::AbuseConfig;

use crate::redis_conn::KvConn;

/// TTL for reputation keys (7 days). After this period of inactivity, the score
/// naturally drops to zero via Redis key expiry.
const REP_TTL_SECS: u64 = 86400 * 7;

/// Graduated response action based on reputation score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationAction {
    /// Score below warn threshold - allow freely.
    Allow,
    /// Score above warn but below greylist - allow with warning log.
    Warn,
    /// Score above greylist threshold - return tempfail.
    Greylist,
    /// Score above reject threshold - reject permanently.
    Reject,
}

pub struct ReputationTracker<R: KvConn> {
    redis: R,
    warn_threshold: f64,
    greylist_threshold: f64,
    reject_threshold: f64,
    decay_hours: f64,
}

impl<R: KvConn> ReputationTracker<R> {
    pub fn new(redis: R, config: &AbuseConfig) -> Self {
        Self {
            redis,
            warn_threshold: config.reputation_warn_threshold,
            greylist_threshold: config.reputation_greylist_threshold,
            reject_threshold: config.reputation_reject_threshold,
            decay_hours: config.reputation_decay_hours as f64,
        }
    }

    /// Get the effective reputation score for an IP, applying exponential
    /// time-based decay: `stored_score * 0.5^(hours_elapsed / decay_hours)`.
    pub async fn get_score(&self, ip: &IpAddr) -> f64 {
        let score_key = format!("sentio:smtp:rep:{ip}");
        let ts_key = format!("sentio:smtp:rep:ts:{ip}");

        let stored_score: f64 = self
            .redis
            .get_opt(&score_key)
            .await
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0.0);

        if stored_score == 0.0 {
            return 0.0;
        }

        let last_update: i64 = self
            .redis
            .get_opt(&ts_key)
            .await
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        if last_update == 0 {
            return stored_score;
        }

        let now = chrono::Utc::now().timestamp();
        let hours_elapsed = (now - last_update) as f64 / 3600.0;

        if hours_elapsed <= 0.0 {
            return stored_score;
        }

        // Exponential decay
        stored_score * (0.5_f64).powf(hours_elapsed / self.decay_hours)
    }

    /// Add penalty points to an IP's reputation score. The current score is
    /// first decayed, then the points are added. Returns the new effective score.
    pub async fn record_infraction(&self, ip: &IpAddr, points: f64) -> f64 {
        let score_key = format!("sentio:smtp:rep:{ip}");
        let ts_key = format!("sentio:smtp:rep:ts:{ip}");

        let current = self.get_score(ip).await;
        let new_score = current + points;

        let now = chrono::Utc::now().timestamp();

        let _ = self
            .redis
            .set_ex(&score_key, &new_score.to_string(), REP_TTL_SECS)
            .await;
        let _ = self
            .redis
            .set_ex(&ts_key, &now.to_string(), REP_TTL_SECS)
            .await;

        new_score
    }

    /// Reset an IP's reputation score to zero.
    pub async fn reset(&self, ip: &IpAddr) {
        let score_key = format!("sentio:smtp:rep:{ip}");
        let ts_key = format!("sentio:smtp:rep:ts:{ip}");
        let _ = self.redis.del(&score_key).await;
        let _ = self.redis.del(&ts_key).await;
    }

    /// Evaluate an IP and return a graduated `ReputationAction`.
    pub async fn evaluate(&self, ip: &IpAddr) -> ReputationAction {
        let score = self.get_score(ip).await;
        let action = if score > self.reject_threshold {
            ReputationAction::Reject
        } else if score > self.greylist_threshold {
            ReputationAction::Greylist
        } else if score > self.warn_threshold {
            ReputationAction::Warn
        } else {
            ReputationAction::Allow
        };

        if action != ReputationAction::Allow {
            metrics::counter!(
                "sentio_abuse_reputation_action_total",
                "action" => format!("{action:?}").to_lowercase()
            )
            .increment(1);
        }

        action
    }

    /// Returns true if the IP's effective score exceeds the reject threshold.
    /// Kept for backward compatibility.
    pub async fn is_suspicious(&self, ip: &IpAddr) -> bool {
        self.get_score(ip).await > self.reject_threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockRedis;

    #[tokio::test]
    async fn fresh_ip_has_zero_score() {
        let redis = MockRedis::new();
        let tracker = ReputationTracker::new(redis, &AbuseConfig::default());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        assert_eq!(tracker.get_score(&ip).await, 0.0);
    }

    #[tokio::test]
    async fn scoring_accumulates() {
        let redis = MockRedis::new();
        let tracker = ReputationTracker::new(redis, &AbuseConfig::default());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        let score = tracker.record_infraction(&ip, 5.0).await;
        assert!((score - 5.0).abs() < 0.01);

        let score = tracker.record_infraction(&ip, 3.0).await;
        assert!((score - 8.0).abs() < 0.1);
    }

    #[tokio::test]
    async fn decay_over_time() {
        let redis = MockRedis::new();
        let config = AbuseConfig {
            reputation_decay_hours: 24,
            ..Default::default()
        };
        let tracker = ReputationTracker::new(redis.clone(), &config);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        // Set score = 10.0 with a timestamp from 24 hours ago
        let old_time = chrono::Utc::now().timestamp() - 86400;
        redis.raw_set("sentio:smtp:rep:1.2.3.4", "10.0");
        redis.raw_set("sentio:smtp:rep:ts:1.2.3.4", &old_time.to_string());

        let score = tracker.get_score(&ip).await;
        // After exactly 1 half-life (24h decay, 24h elapsed): score ≈ 5.0
        assert!(
            (score - 5.0).abs() < 0.5,
            "expected ~5.0 after one half-life, got {score}"
        );
    }

    #[tokio::test]
    async fn threshold_check() {
        let redis = MockRedis::new();
        let config = AbuseConfig::default();
        let tracker = ReputationTracker::new(redis, &config);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        assert!(!tracker.is_suspicious(&ip).await);

        tracker.record_infraction(&ip, 11.0).await;
        assert!(tracker.is_suspicious(&ip).await);
    }

    #[tokio::test]
    async fn below_threshold_not_suspicious() {
        let redis = MockRedis::new();
        let config = AbuseConfig::default();
        let tracker = ReputationTracker::new(redis, &config);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        tracker.record_infraction(&ip, 4.0).await;
        assert!(!tracker.is_suspicious(&ip).await);
    }

    #[tokio::test]
    async fn evaluate_graduated_response() {
        let redis = MockRedis::new();
        let config = AbuseConfig {
            reputation_warn_threshold: 5.0,
            reputation_greylist_threshold: 7.5,
            reputation_reject_threshold: 10.0,
            ..Default::default()
        };
        let tracker = ReputationTracker::new(redis, &config);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        // Fresh IP → Allow
        assert_eq!(tracker.evaluate(&ip).await, ReputationAction::Allow);

        // Score 6.0 → Warn (above 5.0, below 7.5)
        tracker.record_infraction(&ip, 6.0).await;
        assert_eq!(tracker.evaluate(&ip).await, ReputationAction::Warn);

        // Score ~14.0 → Reject (above 10.0)
        tracker.record_infraction(&ip, 8.0).await;
        assert_eq!(tracker.evaluate(&ip).await, ReputationAction::Reject);
    }

    #[tokio::test]
    async fn evaluate_greylist_at_boundary() {
        let redis = MockRedis::new();
        let config = AbuseConfig {
            reputation_warn_threshold: 5.0,
            reputation_greylist_threshold: 7.5,
            reputation_reject_threshold: 10.0,
            ..Default::default()
        };
        let tracker = ReputationTracker::new(redis, &config);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        // Score 8.0 → Greylist (above 7.5, below 10.0)
        tracker.record_infraction(&ip, 8.0).await;
        assert_eq!(tracker.evaluate(&ip).await, ReputationAction::Greylist);
    }

    #[tokio::test]
    async fn reset_clears_score() {
        let redis = MockRedis::new();
        let tracker = ReputationTracker::new(redis, &AbuseConfig::default());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        tracker.record_infraction(&ip, 15.0).await;
        assert!(tracker.get_score(&ip).await > 0.0);

        tracker.reset(&ip).await;
        assert_eq!(tracker.get_score(&ip).await, 0.0);
    }
}
