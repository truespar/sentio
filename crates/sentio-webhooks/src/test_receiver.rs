//! In-process webhook receiver for integration testing.
//!
//! Spins up a lightweight Axum HTTP server on `127.0.0.1:0` that records
//! incoming webhook POSTs. Provides assertion helpers for verifying HMAC
//! signatures, event counts, and payload contents.
//!
//! Enabled via the `test-support` feature flag.
//!
//! # Example
//!
//! ```ignore
//! let receiver = WebhookReceiver::start(ReceiverConfig::default()).await;
//! // register receiver.url() as the webhook endpoint, then dispatch…
//! let events = receiver.wait_for_events(1, Duration::from_secs(5)).await.unwrap();
//! assert!(receiver.verify_signature(&events[0], "whsec_test"));
//! receiver.shutdown().await;
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use tokio::sync::{watch, Notify};

use crate::signing;

// ──────────────────────────────────────────────────────────────────────────────
// Configuration
// ──────────────────────────────────────────────────────────────────────────────

/// Configuration for the mock webhook receiver.
#[derive(Clone)]
pub struct ReceiverConfig {
    /// HTTP status code to return for every request.
    /// Use 200 for success, 500 to trigger retries, etc.
    pub response_status: u16,
}

impl Default for ReceiverConfig {
    fn default() -> Self {
        Self {
            response_status: 200,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Received event
// ──────────────────────────────────────────────────────────────────────────────

/// A webhook POST captured by the receiver.
#[derive(Debug, Clone)]
pub struct ReceivedWebhook {
    /// Raw request body bytes.
    pub body: Vec<u8>,
    /// Value of the `X-Sentio-Event` header.
    pub event_type: Option<String>,
    /// Value of the `X-Sentio-Timestamp` header.
    pub timestamp: Option<String>,
    /// Value of the `X-Sentio-Nonce` header.
    pub nonce: Option<String>,
    /// Value of the `X-Sentio-Signature` header.
    pub signature: Option<String>,
}

impl ReceivedWebhook {
    /// Parse the body as a JSON value.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("webhook body is not valid JSON")
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Shared state
// ──────────────────────────────────────────────────────────────────────────────

struct ReceiverState {
    events: std::sync::Mutex<Vec<ReceivedWebhook>>,
    response_status: StatusCode,
    notify: Notify,
}

// ──────────────────────────────────────────────────────────────────────────────
// WebhookReceiver
// ──────────────────────────────────────────────────────────────────────────────

/// An in-process HTTP server that captures webhook deliveries for testing.
pub struct WebhookReceiver {
    addr: SocketAddr,
    state: Arc<ReceiverState>,
    shutdown_tx: watch::Sender<bool>,
    join_handle: tokio::task::JoinHandle<()>,
}

impl WebhookReceiver {
    /// Start the receiver on a random port.
    pub async fn start(config: ReceiverConfig) -> Self {
        let state = Arc::new(ReceiverState {
            events: std::sync::Mutex::new(Vec::new()),
            response_status: StatusCode::from_u16(config.response_status).unwrap_or(StatusCode::OK),
            notify: Notify::new(),
        });

        let app = Router::new()
            .route("/webhook", post(handle_webhook))
            .with_state(Arc::clone(&state));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let join_handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.changed().await;
                })
                .await
                .ok();
        });

        Self {
            addr,
            state,
            shutdown_tx,
            join_handle,
        }
    }

    /// The full URL to POST webhooks to.
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}/webhook", self.addr.port())
    }

    /// Return all events received so far.
    pub fn received_events(&self) -> Vec<ReceivedWebhook> {
        self.state.events.lock().unwrap().clone()
    }

    /// Number of events received so far.
    pub fn received_count(&self) -> usize {
        self.state.events.lock().unwrap().len()
    }

    /// Block until at least `count` events have been received, or timeout.
    pub async fn wait_for_events(
        &self,
        count: usize,
        timeout: Duration,
    ) -> Result<Vec<ReceivedWebhook>, String> {
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            {
                let events = self.state.events.lock().unwrap();
                if events.len() >= count {
                    return Ok(events.clone());
                }
            }

            let remaining = deadline.duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                let got = self.state.events.lock().unwrap().len();
                return Err(format!(
                    "timed out waiting for {count} webhook events (got {got})"
                ));
            }

            tokio::select! {
                _ = self.state.notify.notified() => { /* check again */ }
                _ = tokio::time::sleep(remaining) => {
                    let got = self.state.events.lock().unwrap().len();
                    return Err(format!(
                        "timed out waiting for {count} webhook events (got {got})"
                    ));
                }
            }
        }
    }

    /// Verify the HMAC signature of a received event against a signing secret.
    pub fn verify_signature(&self, event: &ReceivedWebhook, secret: &str) -> bool {
        let (Some(ts_str), Some(nonce), Some(sig)) =
            (&event.timestamp, &event.nonce, &event.signature)
        else {
            return false;
        };

        let Ok(timestamp) = ts_str.parse::<i64>() else {
            return false;
        };

        // Use a generous tolerance (600s) since we're in-process.
        signing::verify_signature(secret, timestamp, nonce, &event.body, sig, 600)
    }

    /// Shut down the receiver.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.join_handle.await;
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Axum handler
// ──────────────────────────────────────────────────────────────────────────────

async fn handle_webhook(
    State(state): State<Arc<ReceiverState>>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let event = ReceivedWebhook {
        body: body.to_vec(),
        event_type: header_str(&headers, signing::HEADER_EVENT),
        timestamp: header_str(&headers, signing::HEADER_TIMESTAMP),
        nonce: header_str(&headers, signing::HEADER_NONCE),
        signature: header_str(&headers, signing::HEADER_SIGNATURE),
    };

    state.events.lock().unwrap().push(event);
    state.notify.notify_waiters();

    state.response_status
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}
