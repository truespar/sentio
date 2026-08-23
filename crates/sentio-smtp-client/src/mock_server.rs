//! Fault-injection SMTP mock for testing error handling paths.
//!
//! This server does NOT capture received messages - use
//! `sentio_smtp_server::TestSmtpServer` for happy-path / interoperability tests.
//! This mock exists solely to simulate SMTP error conditions:
//! - Rejected recipients (550)
//! - Deferred DATA (450)
//! - Bad greetings (421)
#![allow(dead_code)]

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Configuration for fault-injection behavior.
#[derive(Clone)]
pub struct FaultSmtpConfig {
    /// Hostname used in the greeting and EHLO response.
    pub hostname: String,
    /// Recipients that will be rejected with 550.
    pub reject_rcpt: Vec<String>,
    /// If true, DATA returns 450 instead of 250.
    pub defer_data: bool,
    /// Greeting response code (220 for normal, 421 for rejection).
    pub greeting_code: u16,
}

impl Default for FaultSmtpConfig {
    fn default() -> Self {
        Self {
            hostname: "fault.example.com".into(),
            reject_rcpt: Vec::new(),
            defer_data: false,
            greeting_code: 220,
        }
    }
}

/// A fault-injection SMTP server for testing error handling.
pub struct FaultSmtpServer {
    addr: SocketAddr,
    shutdown_tx: watch::Sender<bool>,
    join_handle: JoinHandle<()>,
}

impl FaultSmtpServer {
    /// Start the fault server on `127.0.0.1:0`.
    pub async fn start(config: FaultSmtpConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let join_handle = tokio::spawn(async move {
            accept_loop(listener, config, shutdown_rx).await;
        });

        Self {
            addr,
            shutdown_tx,
            join_handle,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.join_handle.await;
    }
}

/// Backward-compatible type aliases.
pub type MockSmtpServer = FaultSmtpServer;
pub type MockSmtpConfig = FaultSmtpConfig;

async fn accept_loop(
    listener: TcpListener,
    config: FaultSmtpConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        let config = config.clone();
                        tokio::spawn(async move {
                            handle_connection(stream, config).await;
                        });
                    }
                    Err(_) => break,
                }
            }
            _ = shutdown_rx.changed() => break,
        }
    }
}

async fn handle_connection(mut stream: tokio::net::TcpStream, config: FaultSmtpConfig) {
    // Send greeting
    if config.greeting_code != 220 {
        let greeting = format!(
            "{} {} Service not available\r\n",
            config.greeting_code, config.hostname
        );
        let _ = stream.write_all(greeting.as_bytes()).await;
        let _ = stream.flush().await;
        return;
    }

    let greeting = format!("220 {} ESMTP Fault Mock\r\n", config.hostname);
    let _ = stream.write_all(greeting.as_bytes()).await;
    let _ = stream.flush().await;

    let mut buf = vec![0u8; 4096];
    let mut line_buf = Vec::new();
    let mut in_data = false;

    loop {
        let n = match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
            .await
        {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => n,
            Ok(Err(_)) => break,
        };

        if in_data {
            line_buf.extend_from_slice(&buf[..n]);
            if line_buf.ends_with(b"\r\n.\r\n")
                || line_buf == b".\r\n"
                || contains_subsequence(&line_buf, b"\r\n.\r\n")
            {
                in_data = false;
                line_buf.clear();
                if config.defer_data {
                    let _ = stream.write_all(b"450 4.7.1 Try again later\r\n").await;
                } else {
                    let _ = stream.write_all(b"250 2.0.0 Message accepted\r\n").await;
                }
                let _ = stream.flush().await;
            }
            continue;
        }

        line_buf.extend_from_slice(&buf[..n]);

        while let Some(pos) = find_crlf(&line_buf) {
            let line_bytes = line_buf[..pos].to_vec();
            line_buf.drain(..pos + 2);
            let line = String::from_utf8_lossy(&line_bytes).to_uppercase();

            if line.starts_with("EHLO") || line.starts_with("HELO") {
                let resp = format!(
                    "250-{}\r\n250-SIZE 52428800\r\n250-PIPELINING\r\n250-8BITMIME\r\n250 OK\r\n",
                    config.hostname
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            } else if line.starts_with("MAIL FROM") {
                let _ = stream.write_all(b"250 2.1.0 OK\r\n").await;
            } else if line.starts_with("RCPT TO") {
                let path = extract_path(&String::from_utf8_lossy(&line_bytes), "RCPT TO:");
                if config.reject_rcpt.iter().any(|r| r == &path) {
                    let _ = stream.write_all(b"550 5.1.1 User unknown\r\n").await;
                } else {
                    let _ = stream.write_all(b"250 2.1.5 OK\r\n").await;
                }
            } else if line.starts_with("DATA") {
                let _ = stream
                    .write_all(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                    .await;
                in_data = true;
                if !line_buf.is_empty()
                    && (contains_subsequence(&line_buf, b"\r\n.\r\n") || line_buf == b".\r\n")
                {
                    in_data = false;
                    line_buf.clear();
                    if config.defer_data {
                        let _ = stream.write_all(b"450 4.7.1 Try again later\r\n").await;
                    } else {
                        let _ = stream.write_all(b"250 2.0.0 Message accepted\r\n").await;
                    }
                }
            } else if line.starts_with("RSET") {
                let _ = stream.write_all(b"250 2.0.0 OK\r\n").await;
            } else if line.starts_with("QUIT") {
                let _ = stream.write_all(b"221 2.0.0 Bye\r\n").await;
                let _ = stream.flush().await;
                return;
            } else if line.starts_with("NOOP") {
                let _ = stream.write_all(b"250 2.0.0 OK\r\n").await;
            } else {
                let _ = stream.write_all(b"500 Command not recognized\r\n").await;
            }

            let _ = stream.flush().await;
        }
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Extract the path from an SMTP command like `RCPT TO:<user@example.com>`.
fn extract_path(line: &str, prefix: &str) -> String {
    let upper_line = line.to_uppercase();
    let idx = upper_line.find(&prefix.to_uppercase()).unwrap_or(0);
    let after = line[idx + prefix.len()..].trim();
    if after.starts_with('<') {
        if let Some(end) = after.find('>') {
            return after[1..end].to_string();
        }
    }
    after.split_whitespace().next().unwrap_or("").to_string()
}
