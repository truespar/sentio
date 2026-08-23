pub mod bimi;
pub mod connection;
pub mod delivery;
pub mod dns;
pub mod headers;
pub mod pool;
pub mod tls;
pub mod tracking;
pub mod warmup;

#[cfg(any(test, feature = "test-support"))]
pub mod mock_server;

// Re-exports for convenience.
pub use connection::{
    dot_stuff, ConnectionConfig, ServerCapabilities, SmtpConnection, SmtpResponse,
};
pub use delivery::{DeliveryEngine, DeliveryOutcome, OutboundMessage};
pub use dns::{resolve_addresses, resolve_mx, MxHost, MxResolution};
pub use headers::{classify_bounce, generate_dsn, DsnParams};
pub use pool::{ConnectionPool, PoolConfig, PoolPermit};
pub use tls::{
    build_client_config, evaluate_tls_policy, starttls_upgrade, TlsPolicy, TlsRequirement,
};
pub use warmup::WarmupGuard;

/// Re-export VerpCodec so existing call sites (`sentio_smtp_client::VerpCodec`)
/// keep working - the codec itself lives in `sentio_core::verp`.
pub use sentio_core::verp::VerpCodec;
