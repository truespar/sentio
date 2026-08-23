use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::extensions::Extensions;
use crate::proxy_protocol;
use crate::response::SmtpResponse;
use crate::session::{ListenerMode, Session, SessionConfig, SessionDeps, SessionOutcome};

/// Boxed async predicate for connection-level abuse checking.
type ConnectionCheck =
    Arc<dyn Fn(IpAddr) -> Pin<Box<dyn Future<Output = Result<(), ()>> + Send>> + Send + Sync>;

/// TCP listener that accepts SMTP connections across three modes.
pub struct SmtpListener {
    config: Arc<SessionConfig>,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
    proxy_protocol: bool,
    deps: Arc<SessionDeps>,
    connection_check: ConnectionCheck,
    connection_semaphore: Arc<tokio::sync::Semaphore>,
}

impl SmtpListener {
    pub fn new(
        config: SessionConfig,
        tls_acceptor: Option<TlsAcceptor>,
        proxy_protocol: bool,
        deps: SessionDeps,
        connection_check: ConnectionCheck,
        max_connections: u32,
    ) -> Self {
        Self {
            config: Arc::new(config),
            tls_acceptor: tls_acceptor.map(Arc::new),
            proxy_protocol,
            deps: Arc::new(deps),
            connection_check,
            connection_semaphore: Arc::new(tokio::sync::Semaphore::new(max_connections as usize)),
        }
    }

    /// Create a listener with no TLS, no PROXY, no abuse checking (for tests).
    pub fn new_plain(config: SessionConfig) -> Self {
        Self {
            config: Arc::new(config),
            tls_acceptor: None,
            proxy_protocol: false,
            deps: Arc::new(SessionDeps::noop()),
            connection_check: Arc::new(|_ip| Box::pin(async { Ok(()) })),
            connection_semaphore: Arc::new(tokio::sync::Semaphore::new(10000)),
        }
    }

    /// Bind to addresses for each mode and accept connections until shutdown.
    ///
    /// Each address set can be empty to skip that mode.
    pub async fn run(
        &self,
        smtp_addrs: &[String],
        smtps_addrs: &[String],
        submission_addrs: &[String],
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), std::io::Error> {
        let mut handles = Vec::new();

        // Bind SMTP listeners (port 25)
        for addr in smtp_addrs {
            let listener = TcpListener::bind(addr).await?;
            info!(addr, mode = "smtp", "listener bound");
            handles.push(self.spawn_accept_loop(listener, ListenerMode::Smtp, shutdown_rx.clone()));
        }

        // Bind SMTPS listeners (port 465)
        for addr in smtps_addrs {
            if self.tls_acceptor.is_none() {
                warn!(
                    addr,
                    "SMTPS address configured but no TLS acceptor, skipping"
                );
                continue;
            }
            let listener = TcpListener::bind(addr).await?;
            info!(addr, mode = "smtps", "listener bound");
            handles.push(self.spawn_accept_loop(
                listener,
                ListenerMode::Smtps,
                shutdown_rx.clone(),
            ));
        }

        // Bind submission listeners (port 587)
        for addr in submission_addrs {
            let listener = TcpListener::bind(addr).await?;
            info!(addr, mode = "submission", "listener bound");
            handles.push(self.spawn_accept_loop(
                listener,
                ListenerMode::Submission,
                shutdown_rx.clone(),
            ));
        }

        // Wait for shutdown signal
        let _ = shutdown_rx.wait_for(|v| *v).await;
        info!("shutdown signal received, stopping listeners");

        for handle in handles {
            handle.abort();
        }

        Ok(())
    }

    fn spawn_accept_loop(
        &self,
        listener: TcpListener,
        mode: ListenerMode,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        let config = Arc::clone(&self.config);
        let tls_acceptor = self.tls_acceptor.clone();
        let proxy_protocol = self.proxy_protocol;
        let deps = Arc::clone(&self.deps);
        let connection_check = Arc::clone(&self.connection_check);
        let semaphore = Arc::clone(&self.connection_semaphore);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, addr)) => {
                                info!(%addr, ?mode, "new connection");
                                let config = Arc::clone(&config);
                                let tls = tls_acceptor.clone();
                                let deps = Arc::clone(&deps);
                                let check = Arc::clone(&connection_check);
                                let sem = Arc::clone(&semaphore);

                                tokio::spawn(async move {
                                    let _permit = match sem.acquire().await {
                                        Ok(p) => p,
                                        Err(_) => return, // semaphore closed
                                    };
                                    handle_connection(
                                        stream, addr.ip(), config, tls,
                                        proxy_protocol, mode, deps, check,
                                    ).await;
                                });
                            }
                            Err(e) => {
                                error!(error = %e, "accept failed");
                            }
                        }
                    }
                    _ = shutdown_rx.wait_for(|v| *v) => {
                        break;
                    }
                }
            }
        })
    }
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    mut peer_ip: IpAddr,
    config: Arc<SessionConfig>,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
    proxy_protocol: bool,
    mode: ListenerMode,
    deps: Arc<SessionDeps>,
    connection_check: ConnectionCheck,
) {
    // 1. PROXY protocol - extract real client IP
    if proxy_protocol {
        match proxy_protocol::read_proxy_header(&mut stream).await {
            Ok(info) => {
                peer_ip = info.src_addr.ip();
            }
            Err(e) => {
                warn!(error = %e, "PROXY protocol parse failed");
                return;
            }
        }
    }

    // 2. Abuse guard - reject banned/rate-limited IPs
    if (connection_check)(peer_ip).await.is_err() {
        info!(%peer_ip, "connection rejected by abuse guard");
        // Try to send 421 before dropping
        use tokio::io::AsyncWriteExt;
        let resp = SmtpResponse::connection_refused();
        let _ = stream.write_all(&resp.to_bytes()).await;
        return;
    }

    // 3. Mode-specific connection handling
    // We need to move deps out of Arc for the session. Create noop deps
    // since SessionDeps doesn't implement Clone; in production the deps
    // are created per-connection or shared via Arc callbacks.
    let session_deps = SessionDeps {
        credential_lookup: Arc::clone(&deps.credential_lookup),
        on_auth_failure: Arc::clone(&deps.on_auth_failure),
        on_auth_success: Arc::clone(&deps.on_auth_success),
        message_processor: deps.message_processor.clone(),
        domain_check: deps.domain_check.clone(),
    };

    // Set tls_available and extensions based on acceptor presence and listener mode
    let mut session_config = (*config).clone();
    session_config.tls_available = tls_acceptor.is_some();
    session_config.extensions = match mode {
        ListenerMode::Smtp => Extensions::default_smtp(),
        ListenerMode::Smtps => Extensions::default_smtps(),
        ListenerMode::Submission => Extensions::default_submission(),
    };

    match mode {
        ListenerMode::Smtps => {
            // Implicit TLS - handshake first
            let acceptor = match tls_acceptor {
                Some(a) => a,
                None => {
                    warn!("SMTPS mode but no TLS acceptor");
                    return;
                }
            };
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let mut session = Session::new(
                        tls_stream,
                        session_config,
                        peer_ip,
                        mode,
                        true,
                        session_deps,
                        None,
                    );
                    if let Err(e) = session.run().await {
                        info!(%peer_ip, error = %e, "SMTPS session ended with error");
                    }
                }
                Err(e) => {
                    info!(%peer_ip, error = %e, "TLS handshake failed");
                }
            }
        }
        ListenerMode::Smtp | ListenerMode::Submission => {
            // Plaintext initially - STARTTLS upgrades in-band
            let mut session = Session::new(
                stream,
                session_config,
                peer_ip,
                mode,
                false,
                session_deps,
                None,
            );
            match session.run().await {
                Ok(SessionOutcome::StartTls) => {
                    let (tcp_stream, _buf) = session.into_parts();

                    let acceptor = match tls_acceptor {
                        Some(a) => a,
                        None => {
                            warn!("STARTTLS requested but no TLS acceptor configured");
                            return;
                        }
                    };

                    match acceptor.accept(tcp_stream).await {
                        Ok(tls_stream) => {
                            let post_tls_deps = SessionDeps {
                                credential_lookup: Arc::clone(&deps.credential_lookup),
                                on_auth_failure: Arc::clone(&deps.on_auth_failure),
                                on_auth_success: Arc::clone(&deps.on_auth_success),
                                message_processor: deps.message_processor.clone(),
                                domain_check: deps.domain_check.clone(),
                            };
                            let mut post_tls_config = (*config).clone();
                            post_tls_config.tls_available = true;
                            post_tls_config.extensions = match mode {
                                ListenerMode::Smtp => Extensions::default_smtp(),
                                ListenerMode::Smtps => Extensions::default_smtps(),
                                ListenerMode::Submission => Extensions::default_submission(),
                            };
                            let mut tls_session = Session::new_after_starttls(
                                tls_stream,
                                post_tls_config,
                                peer_ip,
                                mode,
                                post_tls_deps,
                                None,
                            );
                            if let Err(e) = tls_session.run_after_starttls().await {
                                info!(%peer_ip, error = %e, "post-STARTTLS session error");
                            }
                        }
                        Err(e) => {
                            info!(%peer_ip, error = %e, "STARTTLS handshake failed");
                        }
                    }
                }
                Ok(SessionOutcome::Closed) => {}
                Err(e) => {
                    info!(%peer_ip, error = %e, "session ended with error");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn bind_and_get_greeting() {
        let config = SessionConfig::default();
        let listener = SmtpListener::new_plain(config);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        // Bind to port 0 (OS-assigned)
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        drop(tcp);

        let addr_str = addr.to_string();
        let handle = tokio::spawn(async move {
            listener
                .run(&[addr_str], &[], &[], shutdown_rx)
                .await
                .unwrap();
        });

        // Give the listener time to bind
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Connect and read greeting
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();

        let greeting = String::from_utf8_lossy(&buf[..n]);
        assert!(greeting.starts_with("220 "), "greeting: {greeting}");

        shutdown_tx.send(true).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
    }

    #[tokio::test]
    async fn multi_mode_binding() {
        let config = SessionConfig::default();
        let listener = SmtpListener::new_plain(config);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        // Bind SMTP and Submission to OS-assigned ports
        let tcp1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr1 = tcp1.local_addr().unwrap();
        drop(tcp1);

        let tcp2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr2 = tcp2.local_addr().unwrap();
        drop(tcp2);

        let addr1_str = addr1.to_string();
        let addr2_str = addr2.to_string();
        let handle = tokio::spawn(async move {
            listener
                .run(&[addr1_str], &[], &[addr2_str], shutdown_rx)
                .await
                .unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Connect to both and verify greetings
        for addr in [addr1, addr2] {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            let greeting = String::from_utf8_lossy(&buf[..n]);
            assert!(
                greeting.starts_with("220 "),
                "greeting on {addr}: {greeting}"
            );
        }

        shutdown_tx.send(true).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
    }
}
