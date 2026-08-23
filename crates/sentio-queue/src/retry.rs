use rand::RngExt as _;

use sentio_core::config::DeliveryConfig;
use sentio_core::event::BounceClass;

/// Fixed retry schedule for the first attempts (in milliseconds).
/// After these are exhausted, exponential backoff kicks in.
///
/// Schedule: 3m, 5m, 10m, 15m, 30m
const EARLY_RETRY_SCHEDULE_MS: &[u64] = &[
    3 * 60 * 1000,  // attempt 0 → 3 min
    5 * 60 * 1000,  // attempt 1 → 5 min
    10 * 60 * 1000, // attempt 2 → 10 min
    15 * 60 * 1000, // attempt 3 → 15 min
    30 * 60 * 1000, // attempt 4 → 30 min
];

/// Retry policy controlling exponential backoff with jitter.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts before moving to the dead-letter queue.
    pub max_retries: u32,
    /// Base delay in milliseconds for the first retry.
    pub base_delay_ms: u64,
    /// Maximum delay cap in milliseconds.
    pub max_delay_ms: u64,
    /// Random jitter factor (0.0–1.0). Delay is multiplied by `1 ± jitter`.
    pub jitter_factor: f64,
    /// Maximum queue lifetime in milliseconds. Messages older than this are
    /// treated as permanently failed regardless of retry count. Per RFC 5321
    /// §4.5.4.1 this SHOULD be at least 4–5 days.
    pub queue_lifetime_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 10,
            base_delay_ms: 30_000,
            max_delay_ms: 3_600_000,
            jitter_factor: 0.25,
            queue_lifetime_ms: 5 * 24 * 3600 * 1000, // 5 days
        }
    }
}

impl RetryPolicy {
    /// Construct a `RetryPolicy` from `DeliveryConfig`, mapping seconds to
    /// milliseconds and pulling `max_retries`.
    pub fn from_delivery_config(config: &DeliveryConfig) -> Self {
        Self {
            max_retries: config.max_retries,
            base_delay_ms: config.retry_base_secs * 1000,
            max_delay_ms: config.retry_max_secs * 1000,
            jitter_factor: 0.25,
            queue_lifetime_ms: u64::from(config.queue_lifetime_days) * 24 * 3600 * 1000,
        }
    }

    /// Construct a `RetryPolicy` for a specific destination domain, applying
    /// any per-domain overrides from `DeliveryConfig::domain_overrides`.
    pub fn from_delivery_config_for_domain(config: &DeliveryConfig, domain: &str) -> Self {
        let base = Self::from_delivery_config(config);
        match config.domain_overrides.get(domain) {
            Some(overrides) => Self {
                base_delay_ms: overrides
                    .retry_base_secs
                    .map(|s| s * 1000)
                    .unwrap_or(base.base_delay_ms),
                max_delay_ms: overrides
                    .retry_max_secs
                    .map(|s| s * 1000)
                    .unwrap_or(base.max_delay_ms),
                max_retries: overrides.max_retries.unwrap_or(base.max_retries),
                ..base
            },
            None => base,
        }
    }

    /// Compute the delay in milliseconds for the given attempt number (0-based).
    pub fn compute_delay_ms(&self, attempt: u32) -> u64 {
        self.compute_delay_ms_with_class(attempt, None)
    }

    /// Compute the delay in milliseconds with an optional bounce class multiplier.
    ///
    /// - `BounceClass::Block` (421 rate-limited): 2.0x multiplier - back off harder
    /// - `BounceClass::Soft` / other: 1.0x standard backoff
    pub fn compute_delay_ms_with_class(
        &self,
        attempt: u32,
        bounce_class: Option<BounceClass>,
    ) -> u64 {
        // Use the fixed early schedule for the first attempts, then
        // fall back to exponential backoff for later attempts.
        let base_delay = if (attempt as usize) < EARLY_RETRY_SCHEDULE_MS.len() {
            EARLY_RETRY_SCHEDULE_MS[attempt as usize]
        } else {
            let exp_attempt = attempt - EARLY_RETRY_SCHEDULE_MS.len() as u32;
            let shift = 1u64.checked_shl(exp_attempt).unwrap_or(u64::MAX);
            self.base_delay_ms.saturating_mul(shift)
        };
        let capped = base_delay.min(self.max_delay_ms);

        // Apply bounce-class multiplier
        let multiplied = match bounce_class {
            Some(BounceClass::Block) => {
                let doubled = capped.saturating_mul(2);
                doubled.min(self.max_delay_ms)
            }
            _ => capped,
        };

        if self.jitter_factor <= 0.0 {
            return multiplied;
        }

        let jitter_range = (multiplied as f64) * self.jitter_factor;
        let jitter = rand::rng().random_range(-jitter_range..=jitter_range);
        let with_jitter = (multiplied as f64) + jitter;

        (with_jitter.max(0.0) as u64).min(self.max_delay_ms)
    }

    /// Whether the message should be retried at the given attempt number.
    ///
    /// If `elapsed_ms` is provided, also checks that the message has not
    /// exceeded the queue lifetime (RFC 5321 §4.5.4.1: SHOULD be 4–5 days).
    pub fn should_retry(&self, attempt: u32, elapsed_ms: Option<u64>) -> bool {
        if attempt >= self.max_retries {
            return false;
        }
        if let Some(elapsed) = elapsed_ms {
            if elapsed >= self.queue_lifetime_ms {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_jitter_policy() -> RetryPolicy {
        RetryPolicy {
            jitter_factor: 0.0,
            ..Default::default()
        }
    }

    #[test]
    fn early_schedule_then_exponential() {
        let policy = no_jitter_policy();

        // Fixed early schedule
        assert_eq!(policy.compute_delay_ms(0), 180_000); // 3 min
        assert_eq!(policy.compute_delay_ms(1), 300_000); // 5 min
        assert_eq!(policy.compute_delay_ms(2), 600_000); // 10 min
        assert_eq!(policy.compute_delay_ms(3), 900_000); // 15 min
        assert_eq!(policy.compute_delay_ms(4), 1_800_000); // 30 min

        // Exponential backoff after schedule exhausted (base=30s, attempt offset from 0)
        assert_eq!(policy.compute_delay_ms(5), 30_000); // 30s × 2^0
        assert_eq!(policy.compute_delay_ms(6), 60_000); // 30s × 2^1
        assert_eq!(policy.compute_delay_ms(7), 120_000); // 30s × 2^2
    }

    #[test]
    fn delay_capped_at_max() {
        let policy = no_jitter_policy();

        // After early schedule, exponential should cap at max_delay_ms
        assert_eq!(policy.compute_delay_ms(12), 3_600_000); // capped
        assert_eq!(policy.compute_delay_ms(15), 3_600_000); // capped
    }

    #[test]
    fn jitter_stays_within_bounds() {
        let policy = RetryPolicy::default();

        for attempt in 0..policy.max_retries {
            for _ in 0..50 {
                let delay = policy.compute_delay_ms(attempt);
                assert!(delay <= policy.max_delay_ms);
            }
        }
    }

    #[test]
    fn should_retry_respects_max() {
        let policy = RetryPolicy {
            max_retries: 3,
            ..Default::default()
        };

        assert!(policy.should_retry(0, None));
        assert!(policy.should_retry(1, None));
        assert!(policy.should_retry(2, None));
        assert!(!policy.should_retry(3, None));
        assert!(!policy.should_retry(10, None));
    }

    #[test]
    fn should_retry_respects_queue_lifetime() {
        let policy = RetryPolicy {
            max_retries: 1000,
            queue_lifetime_ms: 5 * 24 * 3600 * 1000, // 5 days
            ..Default::default()
        };

        // Within lifetime - allowed
        let one_day_ms = 24 * 3600 * 1000;
        assert!(policy.should_retry(0, Some(one_day_ms)));
        assert!(policy.should_retry(10, Some(4 * one_day_ms)));

        // At or beyond lifetime - rejected
        assert!(!policy.should_retry(0, Some(5 * one_day_ms)));
        assert!(!policy.should_retry(0, Some(6 * one_day_ms)));
    }

    #[test]
    fn should_retry_checks_both_limits() {
        let policy = RetryPolicy {
            max_retries: 5,
            queue_lifetime_ms: 2 * 24 * 3600 * 1000, // 2 days
            ..Default::default()
        };

        // Under both limits
        assert!(policy.should_retry(3, Some(24 * 3600 * 1000)));

        // Over retry count, under lifetime
        assert!(!policy.should_retry(5, Some(24 * 3600 * 1000)));

        // Under retry count, over lifetime
        assert!(!policy.should_retry(3, Some(3 * 24 * 3600 * 1000)));

        // No elapsed_ms - only checks retry count
        assert!(policy.should_retry(3, None));
        assert!(!policy.should_retry(5, None));
    }

    #[test]
    fn overflow_does_not_panic() {
        let policy = no_jitter_policy();
        // Very high attempt - should saturate rather than panic
        let delay = policy.compute_delay_ms(63);
        assert_eq!(delay, policy.max_delay_ms);
    }

    #[test]
    fn from_delivery_config_maps_values() {
        let config = DeliveryConfig {
            retry_base_secs: 600,
            retry_max_secs: 7200,
            max_retries: 25,
            queue_lifetime_days: 7,
            ..Default::default()
        };
        let policy = RetryPolicy::from_delivery_config(&config);
        assert_eq!(policy.base_delay_ms, 600_000);
        assert_eq!(policy.max_delay_ms, 7_200_000);
        assert_eq!(policy.max_retries, 25);
        assert_eq!(policy.queue_lifetime_ms, 7 * 24 * 3600 * 1000);
        assert!((policy.jitter_factor - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn block_bounce_class_doubles_delay() {
        let policy = RetryPolicy {
            jitter_factor: 0.0,
            ..Default::default()
        };
        // attempt 0 uses early schedule → 180_000 (3 min)
        let normal = policy.compute_delay_ms_with_class(0, Some(BounceClass::Soft));
        let block = policy.compute_delay_ms_with_class(0, Some(BounceClass::Block));
        assert_eq!(normal, 180_000);
        assert_eq!(block, 360_000); // 2x for Block
    }

    #[test]
    fn block_delay_still_capped_at_max() {
        let policy = RetryPolicy {
            jitter_factor: 0.0,
            max_delay_ms: 200_000,
            ..Default::default()
        };
        // attempt 0 → 180_000 (early schedule), doubled → 360_000, but cap is 200_000
        let delay = policy.compute_delay_ms_with_class(0, Some(BounceClass::Block));
        assert_eq!(delay, 200_000);
    }

    #[test]
    fn domain_override_applies() {
        use sentio_core::config::DomainRetryOverride;
        use std::collections::HashMap;

        let mut overrides = HashMap::new();
        overrides.insert(
            "gmail.com".to_string(),
            DomainRetryOverride {
                retry_base_secs: Some(120),
                retry_max_secs: Some(14400),
                max_retries: Some(100),
            },
        );

        let config = DeliveryConfig {
            retry_base_secs: 30,
            retry_max_secs: 3600,
            max_retries: 50,
            domain_overrides: overrides,
            ..Default::default()
        };

        let policy = RetryPolicy::from_delivery_config_for_domain(&config, "gmail.com");
        assert_eq!(policy.base_delay_ms, 120_000);
        assert_eq!(policy.max_delay_ms, 14_400_000);
        assert_eq!(policy.max_retries, 100);
    }

    #[test]
    fn unknown_domain_uses_global() {
        let config = DeliveryConfig {
            retry_base_secs: 30,
            retry_max_secs: 3600,
            max_retries: 50,
            ..Default::default()
        };

        let policy = RetryPolicy::from_delivery_config_for_domain(&config, "unknown.com");
        assert_eq!(policy.base_delay_ms, 30_000);
        assert_eq!(policy.max_delay_ms, 3_600_000);
        assert_eq!(policy.max_retries, 50);
    }
}
