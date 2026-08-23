use std::net::SocketAddr;
use std::str::FromStr;

use sentio_core::error::SentioError;
use tokio::net::TcpListener;

use crate::routes;
use crate::state::AppState;

/// Start the HTTP API server.
pub async fn start(
    state: AppState,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), SentioError> {
    let listen_addr = &state.config.server.listen_api;

    let addr = SocketAddr::from_str(listen_addr).map_err(|e| {
        SentioError::Validation(format!("invalid listen_api address '{listen_addr}': {e}"))
    })?;

    let app = routes::router(state);

    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| SentioError::Internal(format!("failed to bind {addr}: {e}")))?;

    tracing::info!(%addr, "API server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.wait_for(|v| *v).await;
            tracing::info!("API server shutting down");
        })
        .await
        .map_err(|e| SentioError::Internal(format!("API server error: {e}")))?;

    tracing::info!("API server stopped");
    Ok(())
}
