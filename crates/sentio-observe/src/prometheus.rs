use std::net::SocketAddr;

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use sentio_core::config::ObservabilityConfig;

/// Install the Prometheus metrics recorder globally and return a handle for
/// rendering metrics at the `/metrics` endpoint.
///
/// The handle's [`PrometheusHandle::render`] method returns Prometheus
/// exposition format text that can be served by the API layer.
pub fn install_recorder(config: &ObservabilityConfig) -> PrometheusHandle {
    let builder = PrometheusBuilder::new();

    let builder = if config.metrics_endpoint.is_empty() {
        builder
    } else if let Ok(addr) = config.metrics_endpoint.parse::<SocketAddr>() {
        builder.with_http_listener(addr)
    } else {
        tracing::warn!(
            endpoint = %config.metrics_endpoint,
            "invalid metrics_endpoint address, using default"
        );
        builder
    };

    builder
        .install_recorder()
        .expect("failed to install Prometheus metrics recorder")
}

/// Build a recorder + handle without installing globally. Useful for tests.
pub fn build_recorder() -> (
    metrics_exporter_prometheus::PrometheusRecorder,
    PrometheusHandle,
) {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    (recorder, handle)
}

/// Register well-known application metrics descriptors.
///
/// Calling this at startup pre-creates metric series so they appear in
/// Prometheus scrapes even before the first event.
pub fn register_descriptors() {
    // SMTP
    metrics::describe_counter!(
        "sentio_smtp_connections_total",
        "Total inbound SMTP connections accepted"
    );
    metrics::describe_counter!(
        "sentio_smtp_messages_received_total",
        "Total messages received via SMTP"
    );
    metrics::describe_counter!(
        "sentio_smtp_messages_rejected_total",
        "Total messages rejected at SMTP level"
    );
    metrics::describe_histogram!(
        "sentio_smtp_session_duration_seconds",
        "SMTP session duration in seconds"
    );

    // Delivery
    metrics::describe_counter!(
        "sentio_delivery_attempts_total",
        "Total outbound delivery attempts"
    );
    metrics::describe_counter!(
        "sentio_delivery_success_total",
        "Total successful deliveries"
    );
    metrics::describe_counter!(
        "sentio_delivery_bounce_total",
        "Total permanent delivery failures (bounces)"
    );
    metrics::describe_counter!(
        "sentio_delivery_deferred_total",
        "Total temporary delivery failures (deferred)"
    );
    metrics::describe_histogram!(
        "sentio_delivery_duration_seconds",
        "Outbound delivery attempt duration in seconds"
    );

    // Queue
    metrics::describe_gauge!(
        "sentio_queue_depth",
        "Current number of messages in the delivery queue"
    );

    // API
    metrics::describe_counter!("sentio_api_requests_total", "Total HTTP API requests");
    metrics::describe_histogram!(
        "sentio_api_request_duration_seconds",
        "HTTP API request duration in seconds"
    );

    // Abuse
    metrics::describe_counter!("sentio_abuse_bans_total", "Total IPs banned by abuse guard");
    metrics::describe_counter!("sentio_abuse_greylist_total", "Total greylisting events");
    metrics::describe_counter!(
        "sentio_abuse_rate_limit_hits_total",
        "Total rate limit rejections"
    );
    metrics::describe_counter!(
        "sentio_abuse_dnsbl_hits_total",
        "Total DNSBL listings detected (by list)"
    );
    metrics::describe_counter!(
        "sentio_abuse_dnsbl_errors_total",
        "Total DNSBL DNS lookup failures (by list)"
    );
    metrics::describe_counter!(
        "sentio_abuse_auth_failures_total",
        "Total authentication failures recorded"
    );
    metrics::describe_counter!(
        "sentio_abuse_rdns_failures_total",
        "Total reverse DNS check failures"
    );
    metrics::describe_counter!(
        "sentio_abuse_whitelist_bypasses_total",
        "Total connections that bypassed abuse checks via whitelist"
    );
    metrics::describe_counter!(
        "sentio_abuse_reputation_action_total",
        "Total reputation actions taken (by action type)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_recorder_produces_valid_handle() {
        let (_recorder, handle) = build_recorder();
        let output = handle.render();
        // Initially empty but valid Prometheus text
        assert!(output.is_empty() || output.starts_with('#'));
    }

    #[test]
    fn register_descriptors_does_not_panic() {
        // Install a recorder so descriptor registration works.
        let (recorder, _handle) = build_recorder();
        // Use a scoped recorder so we don't conflict with other tests.
        let _guard = metrics::set_default_local_recorder(&recorder);
        register_descriptors();
    }

    #[test]
    fn recorded_counter_appears_in_render() {
        let (recorder, handle) = build_recorder();
        let _guard = metrics::set_default_local_recorder(&recorder);

        metrics::counter!("sentio_test_counter", "env" => "test").increment(42);

        let output = handle.render();
        assert!(
            output.contains("sentio_test_counter"),
            "counter not found in output: {output}"
        );
    }

    #[test]
    fn recorded_gauge_appears_in_render() {
        let (recorder, handle) = build_recorder();
        let _guard = metrics::set_default_local_recorder(&recorder);

        metrics::gauge!("sentio_test_gauge").set(42.5);

        let output = handle.render();
        assert!(
            output.contains("sentio_test_gauge"),
            "gauge not found in output: {output}"
        );
    }

    #[test]
    fn recorded_histogram_appears_in_render() {
        let (recorder, handle) = build_recorder();
        let _guard = metrics::set_default_local_recorder(&recorder);

        metrics::histogram!("sentio_test_histogram").record(0.5);

        let output = handle.render();
        assert!(
            output.contains("sentio_test_histogram"),
            "histogram not found in output: {output}"
        );
    }
}
