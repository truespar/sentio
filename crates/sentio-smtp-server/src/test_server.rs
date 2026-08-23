//! Test helper: wraps the real SMTP session layer with message capture.
//!
//! Provides `TestSmtpServer` which starts a real SMTP server on a random port
//! using the full `Session` state machine, capturing received messages via a
//! `MessageProcessor` callback.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::pipeline::{InboundMessage, ProcessingOutcome};
use crate::session::{ListenerMode, Session, SessionConfig, SessionDeps};

/// An in-process SMTP server for integration tests, backed by the real
/// `Session` state machine.
pub struct TestSmtpServer {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<InboundMessage>>>,
    received_count: Arc<AtomicUsize>,
    total_bytes: Arc<AtomicUsize>,
    shutdown_tx: watch::Sender<bool>,
    join_handle: JoinHandle<()>,
}

impl TestSmtpServer {
    /// Start a plain-text SMTP server on `127.0.0.1:0`.
    pub async fn start() -> Self {
        Self::start_inner(None).await
    }

    /// Start an SMTP server with STARTTLS support.
    pub async fn start_with_tls(acceptor: TlsAcceptor) -> Self {
        Self::start_inner(Some(acceptor)).await
    }

    async fn start_inner(tls_acceptor: Option<TlsAcceptor>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let received: Arc<Mutex<Vec<InboundMessage>>> = Arc::new(Mutex::new(Vec::new()));
        let received_count = Arc::new(AtomicUsize::new(0));
        let total_bytes = Arc::new(AtomicUsize::new(0));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let recv = Arc::clone(&received);
        let count = Arc::clone(&received_count);
        let bytes = Arc::clone(&total_bytes);
        let tls = tls_acceptor.map(Arc::new);

        let join_handle = tokio::spawn(async move {
            accept_loop(listener, recv, count, bytes, tls, shutdown_rx).await;
        });

        Self {
            addr,
            received,
            received_count,
            total_bytes,
            shutdown_tx,
            join_handle,
        }
    }

    /// The address the server is listening on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Get all messages received so far (requires lock).
    pub async fn received(&self) -> Vec<InboundMessage> {
        self.received.lock().await.clone()
    }

    /// Lock-free count of received messages (for stress tests).
    pub fn received_count(&self) -> usize {
        self.received_count.load(Ordering::SeqCst)
    }

    /// Lock-free sum of raw message bytes received (for stress tests).
    pub fn total_bytes(&self) -> usize {
        self.total_bytes.load(Ordering::SeqCst)
    }

    /// Shut down the server gracefully.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.join_handle.await;
    }
}

async fn accept_loop(
    listener: TcpListener,
    received: Arc<Mutex<Vec<InboundMessage>>>,
    received_count: Arc<AtomicUsize>,
    total_bytes: Arc<AtomicUsize>,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, addr)) => {
                        let recv = Arc::clone(&received);
                        let count = Arc::clone(&received_count);
                        let bytes = Arc::clone(&total_bytes);
                        let tls = tls_acceptor.clone();

                        tokio::spawn(async move {
                            handle_connection(stream, addr.ip(), recv, count, bytes, tls).await;
                        });
                    }
                    Err(_) => break,
                }
            }
            _ = shutdown_rx.changed() => break,
        }
    }
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    peer_ip: std::net::IpAddr,
    received: Arc<Mutex<Vec<InboundMessage>>>,
    received_count: Arc<AtomicUsize>,
    total_bytes: Arc<AtomicUsize>,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
) {
    let has_tls = tls_acceptor.is_some();

    // Build a MessageProcessor that captures messages.
    let recv = Arc::clone(&received);
    let count = Arc::clone(&received_count);
    let bytes = Arc::clone(&total_bytes);

    let processor: crate::pipeline::MessageProcessor = Arc::new(move |msg: InboundMessage| {
        let recv = Arc::clone(&recv);
        let count = Arc::clone(&count);
        let bytes = Arc::clone(&bytes);
        Box::pin(async move {
            let data_len = msg.raw_data.len();
            recv.lock().await.push(msg);
            count.fetch_add(1, Ordering::SeqCst);
            bytes.fetch_add(data_len, Ordering::SeqCst);
            Ok(ProcessingOutcome {
                queue_id: format!("TEST-{:016X}", data_len as u64),
                message_id: sentio_core::message::MessageId::new(),
            })
        })
    });

    let mut config = SessionConfig::default();
    if has_tls {
        config.extensions = crate::extensions::Extensions::default_smtp(); // has STARTTLS
        config.tls_available = true;
    }

    let deps = SessionDeps {
        credential_lookup: Arc::new(|_username: &str| {
            Box::pin(async {
                Err(sentio_core::error::SentioError::NotFound {
                    entity: "credential",
                    id: "test".into(),
                })
            })
        }),
        on_auth_failure: Arc::new(|_ip| Box::pin(async {})),
        on_auth_success: Arc::new(|_ip| Box::pin(async {})),
        message_processor: Some(processor),
        domain_check: None,
    };

    let mut session = Session::new(
        stream,
        config.clone(),
        peer_ip,
        ListenerMode::Smtp,
        false,
        deps,
        None,
    );

    if let Ok(crate::session::SessionOutcome::StartTls) = session.run().await {
        // Upgrade to TLS
        let (tcp_stream, _buf) = session.into_parts();
        let acceptor = match tls_acceptor {
            Some(a) => a,
            None => return,
        };
        if let Ok(tls_stream) = acceptor.accept(tcp_stream).await {
            // Build fresh deps with a new processor clone for the TLS session
            let recv2 = Arc::clone(&received);
            let count2 = Arc::clone(&received_count);
            let bytes2 = Arc::clone(&total_bytes);
            let processor2: crate::pipeline::MessageProcessor =
                Arc::new(move |msg: InboundMessage| {
                    let recv = Arc::clone(&recv2);
                    let count = Arc::clone(&count2);
                    let bytes = Arc::clone(&bytes2);
                    Box::pin(async move {
                        let data_len = msg.raw_data.len();
                        recv.lock().await.push(msg);
                        count.fetch_add(1, Ordering::SeqCst);
                        bytes.fetch_add(data_len, Ordering::SeqCst);
                        Ok(ProcessingOutcome {
                            queue_id: format!("TEST-{:016X}", data_len as u64),
                            message_id: sentio_core::message::MessageId::new(),
                        })
                    })
                });

            let post_tls_deps = SessionDeps {
                credential_lookup: Arc::new(|_username: &str| {
                    Box::pin(async {
                        Err(sentio_core::error::SentioError::NotFound {
                            entity: "credential",
                            id: "test".into(),
                        })
                    })
                }),
                on_auth_failure: Arc::new(|_ip| Box::pin(async {})),
                on_auth_success: Arc::new(|_ip| Box::pin(async {})),
                message_processor: Some(processor2),
                domain_check: None,
            };

            let mut tls_session = Session::new_after_starttls(
                tls_stream,
                config,
                peer_ip,
                ListenerMode::Smtp,
                post_tls_deps,
                None,
            );
            let _ = tls_session.run_after_starttls().await;
        }
    }
}
