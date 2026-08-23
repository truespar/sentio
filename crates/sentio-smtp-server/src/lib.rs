pub mod auth;
pub mod bounce_handler;
pub mod commands;
pub mod extensions;
pub mod listener;
pub mod listmonk_bridge;
pub mod mailbox_actions;
pub mod pipeline;
pub mod proxy_protocol;
pub mod response;
pub mod routing;
pub mod session;
pub mod tls;

#[cfg(any(test, feature = "test-support"))]
pub mod test_server;

pub mod validation;
pub mod xclient;

// Re-exports
pub use auth::{AuthResult, CredentialLookup};
pub use commands::SmtpCommand;
pub use extensions::Extensions;
pub use listener::SmtpListener;
pub use pipeline::{
    InboundMessage, InboundPipeline, MessageProcessor, ProcessingError, ProcessingOutcome,
};
pub use proxy_protocol::ProxyInfo;
pub use response::SmtpResponse;
pub use routing::InboundEngine;
pub use session::{
    DomainCheck, ListenerMode, Session, SessionConfig, SessionDeps, SessionOutcome, SessionState,
};
pub use tls::{
    build_acceptor, build_tls_config_from_pem, build_tls_config_from_resolver, SniResolver,
};
pub use xclient::XClientParams;

#[cfg(any(test, feature = "test-support"))]
pub use test_server::TestSmtpServer;
