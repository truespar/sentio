use std::time::Duration;

use bytes::BytesMut;
use memchr::memchr;
use sentio_core::error::{SentioError, SmtpError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Helper to create an SentioError::Smtp from a message string.
fn smtp_err(msg: impl Into<String>) -> SentioError {
    SentioError::Smtp(SmtpError {
        code: 0,
        enhanced: None,
        message: msg.into(),
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// SmtpResponse
// ──────────────────────────────────────────────────────────────────────────────

/// A parsed SMTP response from the remote server.
#[derive(Debug, Clone)]
pub struct SmtpResponse {
    /// 3-digit status code (e.g. 250, 421, 550).
    pub code: u16,
    /// Optional RFC 2034 enhanced status code (e.g. "2.1.0").
    pub enhanced: Option<String>,
    /// Individual response lines (text after the code).
    pub lines: Vec<String>,
}

impl SmtpResponse {
    /// 2xx response.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.code)
    }

    /// 4xx response (transient failure).
    pub fn is_transient(&self) -> bool {
        (400..500).contains(&self.code)
    }

    /// 5xx response (permanent failure).
    pub fn is_permanent(&self) -> bool {
        (500..600).contains(&self.code)
    }

    /// Reconstruct the full multi-line response text.
    pub fn full_text(&self) -> String {
        self.lines.join("\n")
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// ServerCapabilities
// ──────────────────────────────────────────────────────────────────────────────

/// Capabilities advertised by the remote server in the EHLO response.
#[derive(Debug, Clone, Default)]
pub struct ServerCapabilities {
    pub starttls: bool,
    pub size: Option<u64>,
    pub pipelining: bool,
    pub eight_bit_mime: bool,
    pub smtputf8: bool,
    pub chunking: bool,
    pub dsn: bool,
    pub auth_mechanisms: Vec<String>,
}

impl ServerCapabilities {
    fn parse_ehlo_lines(lines: &[String]) -> Self {
        let mut caps = Self::default();
        for line in lines {
            let upper = line.to_uppercase();
            let parts: Vec<&str> = upper.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }
            match parts[0] {
                "STARTTLS" => caps.starttls = true,
                "SIZE" => {
                    caps.size = parts.get(1).and_then(|s| s.parse().ok());
                }
                "PIPELINING" => caps.pipelining = true,
                "8BITMIME" => caps.eight_bit_mime = true,
                "SMTPUTF8" => caps.smtputf8 = true,
                "CHUNKING" => caps.chunking = true,
                "DSN" => caps.dsn = true,
                "AUTH" => {
                    caps.auth_mechanisms = parts[1..].iter().map(|s| s.to_string()).collect();
                }
                _ => {}
            }
        }
        caps
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// ConnectionConfig
// ──────────────────────────────────────────────────────────────────────────────

/// Timeout configuration for an outbound SMTP connection.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    pub connect_timeout: Duration,
    pub greeting_timeout: Duration,
    pub command_timeout: Duration,
    pub data_init_timeout: Duration,
    pub data_block_timeout: Duration,
    pub data_termination_timeout: Duration,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            greeting_timeout: Duration::from_secs(30),
            command_timeout: Duration::from_secs(60),
            data_init_timeout: Duration::from_secs(120),
            data_block_timeout: Duration::from_secs(180),
            data_termination_timeout: Duration::from_secs(300),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// SmtpConnection
// ──────────────────────────────────────────────────────────────────────────────

/// An SMTP client connection to a remote server.
pub struct SmtpConnection<S: AsyncRead + AsyncWrite + Unpin + Send> {
    stream: S,
    read_buf: BytesMut,
    config: ConnectionConfig,
    pub hostname: String,
    pub capabilities: Option<ServerCapabilities>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> SmtpConnection<S> {
    /// Create a new connection, reading the server greeting.
    pub async fn new(
        stream: S,
        config: ConnectionConfig,
        hostname: String,
    ) -> Result<(Self, SmtpResponse), SentioError> {
        let mut conn = Self {
            stream,
            read_buf: BytesMut::with_capacity(4096),
            config,
            hostname,
            capabilities: None,
        };
        let greeting = conn.read_response(conn.config.greeting_timeout).await?;
        if !greeting.is_success() {
            return Err(smtp_err(format!(
                "server rejected connection: {} {}",
                greeting.code,
                greeting.full_text()
            )));
        }
        Ok((conn, greeting))
    }

    /// Wrap an already-upgraded stream (e.g. after STARTTLS) without reading a greeting.
    /// Per RFC 3207, the server does not send a new greeting after TLS negotiation;
    /// the client should immediately issue EHLO.
    pub fn from_upgraded(
        stream: S,
        read_buf: BytesMut,
        config: ConnectionConfig,
        hostname: String,
    ) -> Self {
        Self {
            stream,
            read_buf,
            config,
            hostname,
            capabilities: None,
        }
    }

    /// Send EHLO and parse the server's capabilities.
    pub async fn ehlo(&mut self, my_hostname: &str) -> Result<SmtpResponse, SentioError> {
        let response = self.command(&format!("EHLO {my_hostname}")).await?;
        if response.is_success() {
            // First line is the server greeting; remaining lines are capabilities.
            let cap_lines = if response.lines.len() > 1 {
                response.lines[1..].to_vec()
            } else {
                vec![]
            };
            self.capabilities = Some(ServerCapabilities::parse_ehlo_lines(&cap_lines));
        }
        Ok(response)
    }

    /// Send MAIL FROM.
    pub async fn mail_from(
        &mut self,
        sender: &str,
        size: Option<u64>,
    ) -> Result<SmtpResponse, SentioError> {
        let cmd = if let Some(sz) = size {
            format!("MAIL FROM:<{sender}> SIZE={sz}")
        } else {
            format!("MAIL FROM:<{sender}>")
        };
        self.command(&cmd).await
    }

    /// Send RCPT TO.
    pub async fn rcpt_to(&mut self, recipient: &str) -> Result<SmtpResponse, SentioError> {
        self.command(&format!("RCPT TO:<{recipient}>")).await
    }

    /// Send MAIL FROM with optional RFC 3461 DSN parameters (RET, ENVID).
    /// Only emits DSN params when `dsn_ret` or `dsn_envid` is `Some`.
    pub async fn mail_from_with_dsn(
        &mut self,
        sender: &str,
        size: Option<u64>,
        ret: Option<&str>,
        envid: Option<&str>,
    ) -> Result<SmtpResponse, SentioError> {
        let mut cmd = if let Some(sz) = size {
            format!("MAIL FROM:<{sender}> SIZE={sz}")
        } else {
            format!("MAIL FROM:<{sender}>")
        };
        if let Some(ret) = ret {
            cmd.push_str(&format!(" RET={ret}"));
        }
        if let Some(envid) = envid {
            cmd.push_str(&format!(" ENVID={}", xtext_encode(envid)));
        }
        self.command(&cmd).await
    }

    /// Send RCPT TO with optional RFC 3461 DSN parameters (NOTIFY, ORCPT).
    pub async fn rcpt_to_with_dsn(
        &mut self,
        recipient: &str,
        notify: Option<&str>,
        orcpt: Option<&str>,
    ) -> Result<SmtpResponse, SentioError> {
        let mut cmd = format!("RCPT TO:<{recipient}>");
        if let Some(notify) = notify {
            cmd.push_str(&format!(" NOTIFY={notify}"));
        }
        if let Some(orcpt) = orcpt {
            cmd.push_str(&format!(" ORCPT={orcpt}"));
        }
        self.command(&cmd).await
    }

    /// Send DATA followed by the message body with dot-stuffing.
    pub async fn data(&mut self, message: &[u8]) -> Result<SmtpResponse, SentioError> {
        let init = self.command("DATA").await?;
        if init.code != 354 {
            return Ok(init);
        }

        let stuffed = dot_stuff(message);
        self.write_all(&stuffed, self.config.data_block_timeout)
            .await?;

        self.read_response(self.config.data_termination_timeout)
            .await
    }

    /// Send RSET.
    pub async fn rset(&mut self) -> Result<SmtpResponse, SentioError> {
        self.command("RSET").await
    }

    /// Send QUIT.
    pub async fn quit(&mut self) -> Result<SmtpResponse, SentioError> {
        self.command("QUIT").await
    }

    /// Send STARTTLS command (does not perform the actual TLS handshake).
    pub async fn starttls(&mut self) -> Result<SmtpResponse, SentioError> {
        self.command("STARTTLS").await
    }

    /// Consume the connection, returning the inner stream and read buffer.
    /// Used to perform TLS upgrade on the underlying stream.
    pub fn into_parts(self) -> (S, BytesMut, ConnectionConfig, String) {
        (self.stream, self.read_buf, self.config, self.hostname)
    }

    // ── Internal helpers ────────────────────────────────────────────────────

    /// Send a command and read the response.
    async fn command(&mut self, cmd: &str) -> Result<SmtpResponse, SentioError> {
        let line = format!("{cmd}\r\n");
        self.write_all(line.as_bytes(), self.config.command_timeout)
            .await?;
        self.read_response(self.config.command_timeout).await
    }

    /// Write all bytes to the stream with a timeout.
    async fn write_all(&mut self, data: &[u8], timeout: Duration) -> Result<(), SentioError> {
        tokio::time::timeout(timeout, self.stream.write_all(data))
            .await
            .map_err(|_| smtp_err("write timeout"))?
            .map_err(|e| smtp_err(format!("write error: {e}")))?;
        tokio::time::timeout(timeout, self.stream.flush())
            .await
            .map_err(|_| smtp_err("flush timeout"))?
            .map_err(|e| smtp_err(format!("flush error: {e}")))?;
        Ok(())
    }

    /// Read a complete SMTP response (possibly multi-line).
    ///
    /// Multi-line responses use `code-text` for continuation and `code text`
    /// (or `code\r\n`) for the final line.
    async fn read_response(&mut self, timeout: Duration) -> Result<SmtpResponse, SentioError> {
        let mut lines = Vec::new();
        let mut enhanced: Option<String> = None;

        let final_code = loop {
            let raw_line = self.read_line(timeout).await?;
            let line = raw_line.trim_end_matches('\r').trim_end_matches('\n');

            if line.len() < 3 {
                return Err(smtp_err(format!("invalid SMTP response line: {line}")));
            }

            let code: u16 = line[..3]
                .parse()
                .map_err(|_| smtp_err(format!("invalid response code: {line}")))?;

            let separator = line.as_bytes().get(3).copied();
            let text = if line.len() > 4 { &line[4..] } else { "" };

            // Extract enhanced status code from first line.
            if enhanced.is_none() && !text.is_empty() {
                let parts: Vec<&str> = text.splitn(2, ' ').collect();
                if parts[0].len() >= 5 && parts[0].chars().nth(1) == Some('.') {
                    enhanced = Some(parts[0].to_string());
                }
            }

            lines.push(text.to_string());

            // A space (or nothing) after the code means this is the last line.
            if separator != Some(b'-') {
                break code;
            }
        };

        Ok(SmtpResponse {
            code: final_code,
            enhanced,
            lines,
        })
    }

    /// Read a single CRLF-terminated line from the buffer/stream.
    async fn read_line(&mut self, timeout: Duration) -> Result<String, SentioError> {
        loop {
            // Check buffer first for a complete line.
            if let Some(pos) = memchr(b'\n', &self.read_buf) {
                let line_bytes = self.read_buf.split_to(pos + 1);
                let line = match String::from_utf8(line_bytes.to_vec()) {
                    Ok(s) => s,
                    Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
                };
                return Ok(line);
            }

            // Read more data from the stream.
            let mut tmp = [0u8; 4096];
            let n = tokio::time::timeout(timeout, self.stream.read(&mut tmp))
                .await
                .map_err(|_| smtp_err("read timeout"))?
                .map_err(|e| smtp_err(format!("read error: {e}")))?;

            if n == 0 {
                return Err(smtp_err("connection closed by remote"));
            }

            self.read_buf.extend_from_slice(&tmp[..n]);
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// xtext encoding (RFC 3461 §4)
// ──────────────────────────────────────────────────────────────────────────────

/// Encode a string using xtext encoding per RFC 3461 §4.
/// Characters outside the printable ASCII range (33-126) and `+` and `=`
/// are encoded as `+XX` where XX is the uppercase hex value.
pub fn xtext_encode(input: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte == b'+' || byte == b'=' || byte <= 32 || byte >= 127 {
            write!(out, "+{byte:02X}").unwrap();
        } else {
            out.push(byte as char);
        }
    }
    out
}

// ──────────────────────────────────────────────────────────────────────────────
// Dot-stuffing (RFC 5321 §4.5.2)
// ──────────────────────────────────────────────────────────────────────────────

/// Apply dot-stuffing to message data and append the terminating `\r\n.\r\n`.
///
/// Lines that begin with a `.` get an extra `.` prepended.
pub fn dot_stuff(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 64);
    let mut at_line_start = true;

    for &byte in data {
        if at_line_start && byte == b'.' {
            out.push(b'.');
        }
        out.push(byte);
        at_line_start = byte == b'\n';
    }

    // Ensure termination with CRLF.CRLF
    if !out.ends_with(b"\r\n") {
        if out.ends_with(b"\n") {
            // Replace bare LF at end with CRLF
            let len = out.len();
            out[len - 1] = b'\r';
            out.push(b'\n');
        } else {
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b".\r\n");

    out
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// Helper: create a connection from prepared server data.
    async fn connect_with_server_data(
        greeting: &[u8],
    ) -> (
        SmtpConnection<tokio::io::DuplexStream>,
        SmtpResponse,
        tokio::io::DuplexStream,
    ) {
        let (mut server, client) = duplex(8192);
        server.write_all(greeting).await.unwrap();
        server.flush().await.unwrap();

        let (conn, resp) =
            SmtpConnection::new(client, ConnectionConfig::default(), "test.local".into())
                .await
                .unwrap();
        (conn, resp, server)
    }

    #[tokio::test]
    async fn greeting_read() {
        let (_conn, greeting, _server) =
            connect_with_server_data(b"220 mail.example.com ESMTP ready\r\n").await;
        assert_eq!(greeting.code, 220);
        assert!(greeting.is_success());
        assert!(greeting.lines[0].contains("mail.example.com"));
    }

    #[tokio::test]
    async fn ehlo_parses_capabilities() {
        let (mut server, client) = duplex(8192);

        // Send greeting
        server
            .write_all(b"220 mail.example.com ESMTP\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        let (mut conn, _greeting) =
            SmtpConnection::new(client, ConnectionConfig::default(), "test.local".into())
                .await
                .unwrap();

        // Spawn a task to handle EHLO response
        let handle = tokio::spawn(async move {
            // Read the EHLO command
            let mut buf = [0u8; 1024];
            let n = server.read(&mut buf).await.unwrap();
            let cmd = String::from_utf8_lossy(&buf[..n]);
            assert!(cmd.starts_with("EHLO "));

            // Send EHLO response with capabilities
            server
                .write_all(
                    b"250-mail.example.com Hello\r\n\
                      250-STARTTLS\r\n\
                      250-SIZE 52428800\r\n\
                      250-PIPELINING\r\n\
                      250-8BITMIME\r\n\
                      250-SMTPUTF8\r\n\
                      250-CHUNKING\r\n\
                      250-DSN\r\n\
                      250-AUTH PLAIN LOGIN\r\n\
                      250 OK\r\n",
                )
                .await
                .unwrap();
            server.flush().await.unwrap();
            server
        });

        let response = conn.ehlo("client.example.com").await.unwrap();
        assert_eq!(response.code, 250);
        assert!(response.is_success());

        let caps = conn.capabilities.as_ref().unwrap();
        assert!(caps.starttls);
        assert_eq!(caps.size, Some(52428800));
        assert!(caps.pipelining);
        assert!(caps.eight_bit_mime);
        assert!(caps.smtputf8);
        assert!(caps.chunking);
        assert!(caps.dsn);
        assert_eq!(caps.auth_mechanisms, vec!["PLAIN", "LOGIN"]);

        let _ = handle.await;
    }

    #[tokio::test]
    async fn mail_from_rcpt_to_data_flow() {
        let (mut server, client) = duplex(65536);

        // Send greeting
        server
            .write_all(b"220 mx.example.com ESMTP\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        let (mut conn, _) =
            SmtpConnection::new(client, ConnectionConfig::default(), "test.local".into())
                .await
                .unwrap();

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];

            // EHLO
            let n = server.read(&mut buf).await.unwrap();
            let _ = String::from_utf8_lossy(&buf[..n]);
            server
                .write_all(b"250-mx.example.com\r\n250 OK\r\n")
                .await
                .unwrap();
            server.flush().await.unwrap();

            // MAIL FROM
            let n = server.read(&mut buf).await.unwrap();
            let cmd = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(cmd.contains("MAIL FROM:<sender@example.com>"));
            server.write_all(b"250 2.1.0 OK\r\n").await.unwrap();
            server.flush().await.unwrap();

            // RCPT TO
            let n = server.read(&mut buf).await.unwrap();
            let cmd = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(cmd.contains("RCPT TO:<recipient@example.com>"));
            server.write_all(b"250 2.1.5 OK\r\n").await.unwrap();
            server.flush().await.unwrap();

            // DATA
            let n = server.read(&mut buf).await.unwrap();
            let cmd = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(cmd.starts_with("DATA\r\n"));
            server.write_all(b"354 Start mail input\r\n").await.unwrap();
            server.flush().await.unwrap();

            // Read message body until CRLF.CRLF
            let mut body = Vec::new();
            loop {
                let n = server.read(&mut buf).await.unwrap();
                body.extend_from_slice(&buf[..n]);
                if body.windows(5).any(|w| w == b"\r\n.\r\n") {
                    break;
                }
            }
            server
                .write_all(b"250 2.0.0 Message accepted\r\n")
                .await
                .unwrap();
            server.flush().await.unwrap();

            server
        });

        let ehlo_resp = conn.ehlo("client.local").await.unwrap();
        assert!(ehlo_resp.is_success());

        let mail_resp = conn.mail_from("sender@example.com", None).await.unwrap();
        assert!(mail_resp.is_success());
        assert_eq!(mail_resp.enhanced, Some("2.1.0".into()));

        let rcpt_resp = conn.rcpt_to("recipient@example.com").await.unwrap();
        assert!(rcpt_resp.is_success());

        let data_resp = conn
            .data(b"From: sender@example.com\r\nTo: recipient@example.com\r\n\r\nHello!\r\n")
            .await
            .unwrap();
        assert!(data_resp.is_success());

        let _ = handle.await;
    }

    #[tokio::test]
    async fn multiline_response_parsing() {
        let (mut server, client) = duplex(8192);
        server
            .write_all(b"220 mx.example.com ESMTP\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        let (mut conn, _) =
            SmtpConnection::new(client, ConnectionConfig::default(), "test.local".into())
                .await
                .unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = server.read(&mut buf).await.unwrap();
            // Multi-line 421 response
            server
                .write_all(
                    b"421-Service not available,\r\n\
                      421-closing transmission channel.\r\n\
                      421 Try again later.\r\n",
                )
                .await
                .unwrap();
            server.flush().await.unwrap();
        });

        let resp = conn.command("EHLO test").await.unwrap();
        assert_eq!(resp.code, 421);
        assert!(resp.is_transient());
        assert_eq!(resp.lines.len(), 3);
    }

    #[test]
    fn dot_stuffing_basic() {
        let input = b"Hello\r\n.hidden\r\nWorld\r\n";
        let output = dot_stuff(input);
        let text = String::from_utf8_lossy(&output);
        assert!(text.contains("\r\n..hidden\r\n"));
        assert!(text.ends_with("\r\n.\r\n"));
    }

    #[test]
    fn dot_stuffing_no_trailing_crlf() {
        let input = b"Hello";
        let output = dot_stuff(input);
        assert!(output.ends_with(b"\r\n.\r\n"));
    }

    #[test]
    fn dot_stuffing_preserves_normal_lines() {
        let input = b"From: a@b.com\r\nTo: c@d.com\r\n\r\nBody text\r\n";
        let output = dot_stuff(input);
        let text = String::from_utf8_lossy(&output);
        assert!(text.contains("From: a@b.com\r\n"));
        assert!(text.ends_with("\r\n.\r\n"));
    }

    #[test]
    fn dot_stuffing_leading_dot_at_start() {
        let input = b".leading dot\r\n";
        let output = dot_stuff(input);
        let text = String::from_utf8_lossy(&output);
        assert!(text.starts_with("..leading dot"));
    }

    #[tokio::test]
    async fn timeout_on_slow_server() {
        let (_server, client) = duplex(8192);
        // Server never sends anything
        let config = ConnectionConfig {
            greeting_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let result = SmtpConnection::new(client, config, "test.local".into()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn permanent_failure_response() {
        let (mut server, client) = duplex(8192);
        server.write_all(b"220 mx.example.com\r\n").await.unwrap();
        server.flush().await.unwrap();

        let (mut conn, _) =
            SmtpConnection::new(client, ConnectionConfig::default(), "test.local".into())
                .await
                .unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = server.read(&mut buf).await.unwrap();
            server
                .write_all(b"550 5.1.1 User unknown\r\n")
                .await
                .unwrap();
            server.flush().await.unwrap();
        });

        let resp = conn.rcpt_to("nobody@example.com").await.unwrap();
        assert_eq!(resp.code, 550);
        assert!(resp.is_permanent());
        assert_eq!(resp.enhanced, Some("5.1.1".into()));
    }

    #[test]
    fn smtp_response_helpers() {
        let resp = SmtpResponse {
            code: 250,
            enhanced: Some("2.1.0".into()),
            lines: vec!["OK".into()],
        };
        assert!(resp.is_success());
        assert!(!resp.is_transient());
        assert!(!resp.is_permanent());
        assert_eq!(resp.full_text(), "OK");

        let resp_4xx = SmtpResponse {
            code: 450,
            enhanced: None,
            lines: vec!["Try again".into()],
        };
        assert!(resp_4xx.is_transient());

        let resp_5xx = SmtpResponse {
            code: 550,
            enhanced: None,
            lines: vec!["No such user".into(), "Check address".into()],
        };
        assert!(resp_5xx.is_permanent());
        assert_eq!(resp_5xx.full_text(), "No such user\nCheck address");
    }
}
