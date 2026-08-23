use sentio_core::config::ObservabilityConfig;
use tracing::Subscriber;
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Registry};

/// Initialize the global tracing subscriber based on `ObservabilityConfig`.
///
/// - `RUST_LOG` env var takes precedence over config when set.
/// - `log_format = "json"` emits machine-readable JSON lines (production).
/// - `log_format = "text"` emits human-readable colored output (development).
pub fn init_logging(config: &ObservabilityConfig) {
    let subscriber = build_subscriber(config);
    tracing::subscriber::set_global_default(subscriber)
        .expect("global tracing subscriber already set");
}

/// Build a tracing subscriber from config without installing it globally.
///
/// Useful for testing - call `tracing::subscriber::with_default()` with the
/// returned subscriber instead of setting the global default.
pub fn build_subscriber(config: &ObservabilityConfig) -> Box<dyn Subscriber + Send + Sync> {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| build_filter_from_config(config));

    match config.log_format.as_str() {
        "json" => Box::new(
            Registry::default().with(env_filter).with(
                fmt::layer()
                    .json()
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_span_list(true),
            ),
        ),
        _ => Box::new(
            Registry::default()
                .with(env_filter)
                .with(fmt::layer().with_target(true).with_thread_ids(false)),
        ),
    }
}

/// Build an `EnvFilter` from the configured log level.
fn build_filter_from_config(config: &ObservabilityConfig) -> EnvFilter {
    let level = &config.log_level;
    let directive = format!("{level},hyper={level},tower={level}");
    EnvFilter::new(directive)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::subscriber::with_default;

    fn make_config(format: &str, level: &str) -> ObservabilityConfig {
        ObservabilityConfig {
            log_format: format.to_string(),
            log_level: level.to_string(),
            ..ObservabilityConfig::default()
        }
    }

    #[test]
    fn build_json_subscriber_does_not_panic() {
        let config = make_config("json", "info");
        let subscriber = build_subscriber(&config);
        with_default(subscriber, || {
            tracing::info!("json test message");
        });
    }

    #[test]
    fn build_text_subscriber_does_not_panic() {
        let config = make_config("text", "debug");
        let subscriber = build_subscriber(&config);
        with_default(subscriber, || {
            tracing::debug!("text test message");
        });
    }

    #[test]
    fn build_subscriber_with_all_levels() {
        for level in &["trace", "debug", "info", "warn", "error"] {
            let config = make_config("json", level);
            let _subscriber = build_subscriber(&config);
        }
    }

    #[test]
    fn json_output_contains_structured_fields() {
        let _config = make_config("json", "info");
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let buf_clone = buf.clone();

        // Build a JSON subscriber that writes to our buffer.
        let env_filter = EnvFilter::new("info");
        let subscriber = Registry::default().with(env_filter).with(
            fmt::layer()
                .json()
                .with_target(true)
                .with_thread_ids(true)
                .with_writer(move || -> Box<dyn std::io::Write> {
                    Box::new(BufWriter(buf_clone.clone()))
                }),
        );

        with_default(subscriber, || {
            tracing::info!(tenant_id = "t-123", "test structured field");
        });

        let output = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(
            output.contains("\"level\":\"INFO\""),
            "missing level: {output}"
        );
        assert!(
            output.contains("test structured field"),
            "missing message: {output}"
        );
        assert!(
            output.contains("tenant_id"),
            "missing structured field: {output}"
        );
    }

    /// Writer adapter that appends to a shared `Vec<u8>`.
    #[derive(Clone)]
    struct BufWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for BufWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
