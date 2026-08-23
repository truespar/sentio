use std::time::Duration;

use sentio_core::config::WebhooksConfig;

/// Classification of event criticality for retry behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventCriticality {
    /// Delivery-affecting events (bounced, delivered, dropped) - more aggressive
    /// retries with shorter initial delays.
    Critical,
    /// Informational events (queued, processed, deferred, held, released) -
    /// standard retry behaviour.
    Normal,
}

/// Classify an event type string by its criticality.
pub fn classify_event(event_type: &str) -> EventCriticality {
    match event_type {
        "delivered" | "bounced" | "dropped" => EventCriticality::Critical,
        _ => EventCriticality::Normal,
    }
}

/// Maximum quick-retry attempts (in-process) for a single webhook delivery.
pub fn quick_retry_attempts(criticality: EventCriticality) -> u32 {
    match criticality {
        EventCriticality::Critical => 3,
        EventCriticality::Normal => 2,
    }
}

/// Delay before the Nth quick retry (1-indexed).
pub fn quick_retry_delay(attempt: u32) -> Duration {
    // 1s, 2s, 4s - capped at 4s
    let secs = 1u64 << attempt.saturating_sub(1).min(2);
    Duration::from_secs(secs)
}

/// Whether a background (queue-level) retry should be attempted.
pub fn should_background_retry(
    attempt: u32,
    criticality: EventCriticality,
    config: &WebhooksConfig,
) -> bool {
    let max = match criticality {
        EventCriticality::Critical => config.max_retries,
        EventCriticality::Normal => config.max_retries / 2,
    };
    attempt <= max
}

/// Compute the background retry delay using exponential backoff with jitter.
///
/// Critical events start at half the base delay for faster retries.
/// The delay is capped at 1 hour.
pub fn background_retry_delay(
    attempt: u32,
    criticality: EventCriticality,
    config: &WebhooksConfig,
) -> Duration {
    let base_secs = config.retry_backoff_base_secs as f64;
    let base = match criticality {
        EventCriticality::Critical => base_secs / 2.0,
        EventCriticality::Normal => base_secs,
    };

    let delay_secs = base * 2.0_f64.powi(attempt.saturating_sub(1) as i32);
    let capped = delay_secs.min(3600.0);

    // Add ±25% jitter.
    let jitter = 0.75 + rand::random::<f64>() * 0.5;
    Duration::from_secs_f64(capped * jitter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_critical_events() {
        assert_eq!(classify_event("delivered"), EventCriticality::Critical);
        assert_eq!(classify_event("bounced"), EventCriticality::Critical);
        assert_eq!(classify_event("dropped"), EventCriticality::Critical);
    }

    #[test]
    fn classify_normal_events() {
        assert_eq!(classify_event("queued"), EventCriticality::Normal);
        assert_eq!(classify_event("processed"), EventCriticality::Normal);
        assert_eq!(classify_event("deferred"), EventCriticality::Normal);
        assert_eq!(classify_event("held"), EventCriticality::Normal);
        assert_eq!(classify_event("released"), EventCriticality::Normal);
        assert_eq!(classify_event("unknown_event"), EventCriticality::Normal);
    }

    #[test]
    fn quick_retry_counts() {
        assert_eq!(quick_retry_attempts(EventCriticality::Critical), 3);
        assert_eq!(quick_retry_attempts(EventCriticality::Normal), 2);
    }

    #[test]
    fn quick_retry_delays() {
        assert_eq!(quick_retry_delay(1), Duration::from_secs(1));
        assert_eq!(quick_retry_delay(2), Duration::from_secs(2));
        assert_eq!(quick_retry_delay(3), Duration::from_secs(4));
        assert_eq!(quick_retry_delay(4), Duration::from_secs(4)); // capped
    }

    #[test]
    fn should_retry_respects_criticality() {
        let config = WebhooksConfig::default(); // max_retries = 10

        // Critical: up to 10
        assert!(should_background_retry(
            10,
            EventCriticality::Critical,
            &config
        ));
        assert!(!should_background_retry(
            11,
            EventCriticality::Critical,
            &config
        ));

        // Normal: up to 5 (10 / 2)
        assert!(should_background_retry(
            5,
            EventCriticality::Normal,
            &config
        ));
        assert!(!should_background_retry(
            6,
            EventCriticality::Normal,
            &config
        ));
    }

    #[test]
    fn background_delay_increases() {
        let config = WebhooksConfig::default(); // base = 60s

        let d1 = background_retry_delay(1, EventCriticality::Normal, &config);
        let d3 = background_retry_delay(3, EventCriticality::Normal, &config);

        // With jitter the exact values vary, but attempt 3 should be larger on
        // average. Allow generous tolerance.
        assert!(d3.as_secs_f64() > d1.as_secs_f64() * 1.5);
    }

    #[test]
    fn background_delay_capped_at_one_hour() {
        let config = WebhooksConfig::default();
        let d = background_retry_delay(20, EventCriticality::Normal, &config);
        // With +25% jitter on 3600s cap → max 4500s
        assert!(d.as_secs() <= 4500);
    }

    #[test]
    fn critical_events_get_shorter_base_delay() {
        let config = WebhooksConfig {
            retry_backoff_base_secs: 100,
            ..WebhooksConfig::default()
        };

        // Run a few times and check the average to smooth out jitter.
        let mut critical_total = 0.0;
        let mut normal_total = 0.0;
        let runs = 50;
        for _ in 0..runs {
            critical_total +=
                background_retry_delay(1, EventCriticality::Critical, &config).as_secs_f64();
            normal_total +=
                background_retry_delay(1, EventCriticality::Normal, &config).as_secs_f64();
        }
        // Critical should average ~50s, normal ~100s.
        let critical_avg = critical_total / runs as f64;
        let normal_avg = normal_total / runs as f64;
        assert!(critical_avg < normal_avg);
    }
}
