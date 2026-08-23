use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use memchr::memmem;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info, warn};

use std::collections::HashMap;

use crate::auth::{self, AuthProgress, AuthResult, AuthState, CredentialLookup};
use crate::commands::{self, MailFromParams, RcptToParams, SmtpCommand};
use crate::extensions::Extensions;
use crate::pipeline::{InboundMessage, MessageProcessor, ProcessingError};
use crate::response::SmtpResponse;
use crate::validation::{dot_unstuff, has_non_ascii, is_valid_ehlo_domain};
use crate::xclient::XClientParams;

/// Checks whether a tenant is allowed to send from a given domain.
/// Takes (tenant_id, domain_name) and returns Ok(()) or Err.
pub type DomainCheck = Arc<
    dyn Fn(
            sentio_core::tenant::TenantId,
            String,
        )
            -> Pin<Box<dyn Future<Output = Result<(), sentio_core::error::SentioError>> + Send>>
        + Send
        + Sync,
>;

// ──────────────────────────────────────────────────────────────────────────────
// Session state
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Connected,
    Greeted,
    MailFrom,
    RcptTo,
    Data,
    /// Receiving BDAT chunks (between first chunk and LAST).
    Bdat,
    Done,
}

/// What happened when the session loop exited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionOutcome {
    /// Session closed normally (QUIT or disconnect).
    Closed,
    /// Client issued STARTTLS - caller should upgrade the connection.
    StartTls,
}

/// Which listener port accepted this connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerMode {
    /// Port 25 - relay / MX delivery.
    Smtp,
    /// Port 465 - implicit TLS.
    Smtps,
    /// Port 587 - message submission.
    Submission,
}

// ──────────────────────────────────────────────────────────────────────────────
// Session dependencies (boxed closures to avoid generic propagation)
// ──────────────────────────────────────────────────────────────────────────────

/// Boxed async callback type.
type AsyncCallback = Arc<dyn Fn(IpAddr) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// External dependencies injected into the session.
pub struct SessionDeps {
    /// Look up SMTP credentials by username.
    pub credential_lookup: CredentialLookup,
    /// Called after each authentication failure (for abuse tracking).
    pub on_auth_failure: AsyncCallback,
    /// Called after successful authentication (to reset failure counters).
    pub on_auth_success: AsyncCallback,
    /// Optional message processor for the inbound pipeline.
    /// When `None`, DATA is accepted but discarded (stub behavior).
    pub message_processor: Option<MessageProcessor>,
    /// Optional domain check for sender domain enforcement.
    /// When set, MAIL FROM on submission/SMTPS ports validates that the
    /// authenticated tenant owns the sender domain.
    pub domain_check: Option<DomainCheck>,
}

impl SessionDeps {
    /// Create no-op deps for testing or when auth is not configured.
    pub fn noop() -> Self {
        Self {
            credential_lookup: Arc::new(|_username: &str| {
                Box::pin(async {
                    Err(sentio_core::error::SentioError::NotFound {
                        entity: "credential",
                        id: "not configured".into(),
                    })
                })
            }),
            on_auth_failure: Arc::new(|_ip| Box::pin(async {})),
            on_auth_success: Arc::new(|_ip| Box::pin(async {})),
            message_processor: None,
            domain_check: None,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Config (extracted from ServerConfig for the session)
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub hostname: String,
    pub extensions: Extensions,
    pub max_message_size: u64,
    pub max_recipients: u32,
    pub max_messages: u32,
    pub max_line_length: u32,
    pub max_received_headers: u32,
    pub max_auth_attempts: u32,
    pub max_commands_per_session: u32,
    pub strict_ehlo_validation: bool,
    /// Whether a TLS acceptor is available for STARTTLS upgrade.
    /// When `false` and STARTTLS is advertised, the server returns 454.
    pub tls_available: bool,
    pub greeting_timeout: Duration,
    pub command_timeout: Duration,
    pub data_initiation_timeout: Duration,
    pub data_block_timeout: Duration,
    pub data_termination_timeout: Duration,
    pub auth_mechanisms: String,
    /// SHA-256 hash of the leaf TLS certificate (DER). Used for
    /// `tls-server-end-point` channel binding (SCRAM-SHA-256-PLUS).
    pub tls_server_cert_hash: Option<Vec<u8>>,
    /// Whether XCLIENT is enabled (Postfix proxy convention).
    pub xclient_enabled: bool,
    /// IPs allowed to issue XCLIENT commands.
    pub xclient_allowed_ips: Vec<IpAddr>,
}

impl SessionConfig {
    pub fn from_server_config(cfg: &sentio_core::config::ServerConfig) -> Self {
        Self {
            hostname: cfg.hostname.clone(),
            extensions: Extensions::default_plain(),
            max_message_size: u64::from(cfg.inbound_limits.max_message_size_mb) * 1024 * 1024,
            max_recipients: cfg.inbound_limits.max_recipients_per_message,
            max_messages: cfg.inbound_limits.max_messages_per_session,
            max_line_length: cfg.inbound_limits.max_line_length,
            max_received_headers: cfg.inbound_limits.max_received_headers,
            max_auth_attempts: cfg.inbound_limits.max_auth_attempts,
            max_commands_per_session: cfg.inbound_limits.max_commands_per_session,
            strict_ehlo_validation: cfg.inbound_limits.strict_ehlo_validation,
            tls_available: false,
            greeting_timeout: Duration::from_secs(cfg.inbound_timeouts.greeting_secs),
            command_timeout: Duration::from_secs(cfg.inbound_timeouts.command_secs),
            data_initiation_timeout: Duration::from_secs(cfg.inbound_timeouts.data_initiation_secs),
            data_block_timeout: Duration::from_secs(cfg.inbound_timeouts.data_block_secs),
            data_termination_timeout: Duration::from_secs(
                cfg.inbound_timeouts.data_termination_secs,
            ),
            auth_mechanisms: "PLAIN LOGIN SCRAM-SHA-256".into(),
            tls_server_cert_hash: None,
            xclient_enabled: cfg.xclient_enabled,
            xclient_allowed_ips: cfg
                .xclient_allowed_ips
                .iter()
                .filter_map(|s| s.parse::<IpAddr>().ok())
                .collect(),
        }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        let server = sentio_core::config::ServerConfig::default();
        Self::from_server_config(&server)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Session
// ──────────────────────────────────────────────────────────────────────────────

pub struct Session<S> {
    stream: S,
    config: SessionConfig,
    state: SessionState,
    // Envelope state
    mail_from: Option<MailFromParams>,
    rcpt_to: Vec<RcptToParams>,
    // Counters
    message_count: u32,
    command_count: u32,
    // I/O buffer
    read_buf: BytesMut,
    // BDAT accumulator
    bdat_data: Vec<u8>,
    // TLS / auth state
    tls_active: bool,
    listener_mode: ListenerMode,
    authenticated: Option<AuthResult>,
    auth_state: Option<AuthState>,
    auth_attempts: u32,
    // Peer info
    peer_addr: IpAddr,
    client_domain: Option<String>,
    // Dependencies
    deps: SessionDeps,
    // Graceful shutdown signal
    shutdown: Option<tokio::sync::watch::Receiver<bool>>,
}

impl<S> Session<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub fn new(
        stream: S,
        config: SessionConfig,
        peer_addr: IpAddr,
        mode: ListenerMode,
        tls_active: bool,
        deps: SessionDeps,
        shutdown: Option<tokio::sync::watch::Receiver<bool>>,
    ) -> Self {
        Self {
            stream,
            config,
            state: SessionState::Connected,
            mail_from: None,
            rcpt_to: Vec::new(),
            message_count: 0,
            command_count: 0,
            read_buf: BytesMut::with_capacity(4096),
            bdat_data: Vec::new(),
            tls_active,
            listener_mode: mode,
            authenticated: None,
            auth_state: None,
            auth_attempts: 0,
            peer_addr,
            client_domain: None,
            deps,
            shutdown,
        }
    }

    /// Create a session after STARTTLS upgrade. Client must re-EHLO before
    /// any commands (RFC 3207 §4.2). No greeting is sent.
    pub fn new_after_starttls(
        stream: S,
        config: SessionConfig,
        peer_addr: IpAddr,
        mode: ListenerMode,
        deps: SessionDeps,
        shutdown: Option<tokio::sync::watch::Receiver<bool>>,
    ) -> Self {
        Self {
            stream,
            config,
            state: SessionState::Connected,
            mail_from: None,
            rcpt_to: Vec::new(),
            message_count: 0,
            command_count: 0,
            read_buf: BytesMut::new(), // discard pre-TLS buffer (RFC 3207 §6)
            bdat_data: Vec::new(),
            tls_active: true,
            listener_mode: mode,
            authenticated: None,
            auth_state: None,
            auth_attempts: 0,
            peer_addr,
            client_domain: None,
            deps,
            shutdown,
        }
    }

    /// Extract the underlying stream and buffer (for TLS upgrade).
    pub fn into_parts(self) -> (S, BytesMut) {
        (self.stream, self.read_buf)
    }

    /// Run the SMTP session to completion, sending the initial greeting.
    pub async fn run(&mut self) -> Result<SessionOutcome, std::io::Error> {
        // Send greeting
        let greeting = SmtpResponse::greeting(&self.config.hostname);
        self.write_response(&greeting).await?;
        self.state = SessionState::Connected;

        self.command_loop().await
    }

    /// Run the session after a STARTTLS upgrade (no greeting sent, client
    /// must re-EHLO per RFC 3207).
    pub async fn run_after_starttls(&mut self) -> Result<SessionOutcome, std::io::Error> {
        self.command_loop().await
    }

    async fn command_loop(&mut self) -> Result<SessionOutcome, std::io::Error> {
        loop {
            if self.state == SessionState::Done {
                return Ok(SessionOutcome::Closed);
            }

            // E7: Graceful shutdown - send 421 and close before reading next command
            if let Some(ref mut rx) = self.shutdown {
                if *rx.borrow() {
                    let _ = self
                        .write_response(&SmtpResponse::service_unavailable())
                        .await;
                    return Ok(SessionOutcome::Closed);
                }
            }

            let timeout = match self.state {
                SessionState::Data | SessionState::Bdat => self.config.data_initiation_timeout,
                _ => self.config.command_timeout,
            };

            let line = match self.read_line(timeout).await {
                Ok(Some(line)) => line,
                Ok(None) => {
                    debug!("client disconnected");
                    return Ok(SessionOutcome::Closed);
                }
                Err(ReadError::Timeout) => {
                    let _ = self.write_response(&SmtpResponse::timeout()).await;
                    return Ok(SessionOutcome::Closed);
                }
                Err(ReadError::LineTooLong) => {
                    self.write_response(&SmtpResponse::line_too_long()).await?;
                    continue;
                }
                Err(ReadError::Io(e)) => return Err(e),
            };

            // E10: Per-session command rate limit
            self.command_count += 1;
            if self.command_count > self.config.max_commands_per_session {
                let _ = self
                    .write_response(&SmtpResponse::service_unavailable())
                    .await;
                return Ok(SessionOutcome::Closed);
            }

            // If we're in the middle of a multi-step SASL exchange, route
            // the line to the auth handler instead of command parsing.
            if self.auth_state.is_some() {
                let response = self.handle_auth_data(&line).await;
                self.write_response(&response).await?;
                continue;
            }

            let response = match commands::parse(&line) {
                Ok(cmd) => {
                    let result = self.handle_command(cmd).await;
                    match result {
                        CommandResult::Response(r) => r,
                        CommandResult::StartTls => {
                            self.write_response(&SmtpResponse::ready_starttls()).await?;
                            return Ok(SessionOutcome::StartTls);
                        }
                    }
                }
                Err(resp) => resp,
            };

            self.write_response(&response).await?;
        }
    }

    // ── Command dispatch ─────────────────────────────────────────────────

    async fn handle_command(&mut self, cmd: SmtpCommand) -> CommandResult {
        match cmd {
            SmtpCommand::Ehlo(domain) => CommandResult::Response(self.handle_ehlo(&domain)),
            SmtpCommand::Helo(domain) => CommandResult::Response(self.handle_helo(&domain)),
            SmtpCommand::MailFrom(params) => {
                CommandResult::Response(self.handle_mail_from(params).await)
            }
            SmtpCommand::RcptTo(params) => CommandResult::Response(self.handle_rcpt_to(params)),
            SmtpCommand::Data => CommandResult::Response(self.handle_data().await),
            SmtpCommand::Bdat { size, last } => {
                CommandResult::Response(self.handle_bdat(size, last).await)
            }
            SmtpCommand::Quit => CommandResult::Response(self.handle_quit()),
            SmtpCommand::Rset => CommandResult::Response(self.handle_rset()),
            SmtpCommand::Noop => CommandResult::Response(SmtpResponse::ok()),
            SmtpCommand::Vrfy(_) => CommandResult::Response(SmtpResponse::new(
                252,
                Some("2.5.2"),
                "Cannot verify user, but will accept message",
            )),
            SmtpCommand::Help => CommandResult::Response(SmtpResponse::new(
                214,
                Some("2.0.0"),
                "See https://tools.ietf.org/html/rfc5321",
            )),
            SmtpCommand::StartTls => self.handle_starttls(),
            SmtpCommand::Auth(args) => CommandResult::Response(self.handle_auth_begin(&args).await),
            SmtpCommand::XClient(params) => CommandResult::Response(self.handle_xclient(params)),
            SmtpCommand::NotImplemented(_) => {
                CommandResult::Response(SmtpResponse::command_not_implemented())
            }
            SmtpCommand::Unknown(_) => {
                CommandResult::Response(SmtpResponse::command_not_recognized())
            }
        }
    }

    fn handle_ehlo(&mut self, domain: &str) -> SmtpResponse {
        if self.config.strict_ehlo_validation && !is_valid_ehlo_domain(domain) {
            return SmtpResponse::syntax_error();
        }
        info!(domain, "EHLO");
        self.reset_envelope();
        self.state = SessionState::Greeted;
        self.client_domain = Some(domain.to_string());

        // Build dynamic extensions based on current state
        let mut ext = self.config.extensions;

        // Remove STARTTLS if already on TLS
        if self.tls_active {
            ext.clear(Extensions::STARTTLS);
        }

        // Remove AUTH if TLS is required but not active
        // (on SMTPS port, TLS is implicit so AUTH is always available)
        if !self.tls_active && self.listener_mode != ListenerMode::Smtps {
            ext.clear(Extensions::AUTH);
        }

        // RFC 4954 §3: AUTH MUST NOT be advertised after successful authentication
        if self.authenticated.is_some() {
            ext.clear(Extensions::AUTH);
        }

        // Conditionally advertise XCLIENT to authorized proxies
        if self.config.xclient_enabled && self.config.xclient_allowed_ips.contains(&self.peer_addr)
        {
            ext.set(Extensions::XCLIENT);
        }

        // Dynamically add SCRAM-SHA-256-PLUS when TLS is active and cert hash is available
        let mechanisms = if self.tls_active
            && self.config.tls_server_cert_hash.is_some()
            && self.config.auth_mechanisms.contains("SCRAM-SHA-256")
            && !self.config.auth_mechanisms.contains("SCRAM-SHA-256-PLUS")
        {
            format!("{} SCRAM-SHA-256-PLUS", self.config.auth_mechanisms)
        } else {
            self.config.auth_mechanisms.clone()
        };

        let ext_lines = ext.ehlo_lines(self.config.max_message_size, &mechanisms);
        SmtpResponse::ehlo(&self.config.hostname, ext_lines)
    }

    fn handle_helo(&mut self, domain: &str) -> SmtpResponse {
        if self.config.strict_ehlo_validation && !is_valid_ehlo_domain(domain) {
            return SmtpResponse::syntax_error();
        }
        info!(domain, "HELO");
        self.reset_envelope();
        self.state = SessionState::Greeted;
        self.client_domain = Some(domain.to_string());
        SmtpResponse::helo(&self.config.hostname)
    }

    async fn handle_mail_from(&mut self, params: MailFromParams) -> SmtpResponse {
        if self.state != SessionState::Greeted {
            return SmtpResponse::bad_sequence();
        }
        if self.message_count >= self.config.max_messages {
            self.state = SessionState::Done;
            return SmtpResponse::too_many_messages();
        }
        // Check declared size against limit
        if let Some(declared) = params.size {
            if declared > self.config.max_message_size {
                return SmtpResponse::message_too_large();
            }
        }
        // E9: non-ASCII addresses require SMTPUTF8 parameter (RFC 6531)
        if has_non_ascii(&params.path) && !params.smtputf8 {
            return SmtpResponse::syntax_error();
        }

        // Sender domain enforcement on submission/SMTPS ports
        // Skip for port 25 relay, null sender <> (bounces/DSN), or when no check configured
        if self.listener_mode != ListenerMode::Smtp && !params.path.is_empty() {
            if let (Some(check), Some(auth_result)) =
                (self.deps.domain_check.as_ref(), self.authenticated.as_ref())
            {
                if let Some(domain) = params.path.rsplit_once('@').map(|(_, d)| d.to_string()) {
                    if let Err(_e) = check(auth_result.tenant_id, domain).await {
                        return SmtpResponse::new(
                            553,
                            Some("5.7.1"),
                            "Sender domain not authorized for this account",
                        );
                    }
                }
            }
        }

        info!(path = %params.path, "MAIL FROM");
        self.mail_from = Some(params);
        self.rcpt_to.clear();
        self.state = SessionState::MailFrom;
        SmtpResponse::mail_ok()
    }

    fn handle_rcpt_to(&mut self, mut params: RcptToParams) -> SmtpResponse {
        if self.state != SessionState::MailFrom && self.state != SessionState::RcptTo {
            return SmtpResponse::bad_sequence();
        }
        if self.rcpt_to.len() >= self.config.max_recipients as usize {
            return SmtpResponse::too_many_recipients();
        }
        // E9: non-ASCII recipients require SMTPUTF8 on the MAIL FROM (RFC 6531)
        if has_non_ascii(&params.path) {
            if let Some(ref mf) = self.mail_from {
                if !mf.smtputf8 {
                    return SmtpResponse::syntax_error();
                }
            }
        }
        // RFC 5321 §2.3.4: bare "postmaster" without domain must be accepted.
        if !params.path.contains('@') && params.path.eq_ignore_ascii_case("postmaster") {
            params.path = format!("postmaster@{}", self.config.hostname);
        }
        info!(path = %params.path, "RCPT TO");
        self.rcpt_to.push(params);
        self.state = SessionState::RcptTo;
        SmtpResponse::rcpt_ok()
    }

    async fn handle_data(&mut self) -> SmtpResponse {
        if self.state != SessionState::RcptTo {
            return SmtpResponse::bad_sequence();
        }

        self.state = SessionState::Data;
        if let Err(e) = self.write_response(&SmtpResponse::start_data()).await {
            warn!(error = %e, "failed to write 354");
            return SmtpResponse::service_unavailable();
        }

        match self.read_data().await {
            Ok(data) => {
                let response = if let Some(ref processor) = self.deps.message_processor {
                    // Extract DSN params from envelope
                    let dsn_ret = self.mail_from.as_ref().and_then(|m| m.ret);
                    let dsn_envid = self.mail_from.as_ref().and_then(|m| m.envid.clone());
                    let mut dsn_notify = HashMap::new();
                    let mut dsn_orcpt = HashMap::new();
                    for rcpt in &self.rcpt_to {
                        if let Some(notify) = rcpt.notify {
                            dsn_notify.insert(rcpt.path.clone(), notify);
                        }
                        if let Some(ref orcpt) = rcpt.orcpt {
                            dsn_orcpt.insert(rcpt.path.clone(), orcpt.clone());
                        }
                    }

                    let msg = InboundMessage {
                        raw_data: data,
                        envelope_from: self
                            .mail_from
                            .as_ref()
                            .map(|m| m.path.clone())
                            .unwrap_or_default(),
                        envelope_to: self.rcpt_to.iter().map(|r| r.path.clone()).collect(),
                        peer_addr: self.peer_addr,
                        client_domain: self.client_domain.clone(),
                        server_hostname: self.config.hostname.clone(),
                        authenticated_user: self.authenticated.as_ref().map(|a| a.username.clone()),
                        tls_active: self.tls_active,
                        max_received_headers: self.config.max_received_headers,
                        dsn_ret,
                        dsn_envid,
                        dsn_notify,
                        dsn_orcpt,
                    };
                    match processor(msg).await {
                        Ok(outcome) => SmtpResponse::data_ok(&outcome.queue_id),
                        Err(ProcessingError::Reject {
                            code,
                            enhanced,
                            message,
                        }) => SmtpResponse::processing_reject(code, &enhanced, &message),
                        Err(ProcessingError::TempFail {
                            code,
                            enhanced,
                            message,
                        }) => SmtpResponse::processing_tempfail(code, &enhanced, &message),
                    }
                } else {
                    // Stub behavior: accept but discard
                    let queue_id = format!("{:016X}", rand_queue_id());
                    info!(
                        queue_id,
                        bytes = data.len(),
                        recipients = self.rcpt_to.len(),
                        "message received"
                    );
                    SmtpResponse::data_ok(&queue_id)
                };
                self.message_count += 1;
                self.reset_envelope();
                self.state = SessionState::Greeted;
                response
            }
            Err(ReadError::Timeout) => {
                self.state = SessionState::Done;
                SmtpResponse::timeout()
            }
            Err(ReadError::LineTooLong) => {
                // Message exceeded size limit during DATA
                self.reset_envelope();
                self.state = SessionState::Greeted;
                SmtpResponse::message_too_large()
            }
            Err(ReadError::Io(e)) => {
                warn!(error = %e, "I/O error during DATA");
                self.state = SessionState::Done;
                SmtpResponse::service_unavailable()
            }
        }
    }

    async fn handle_bdat(&mut self, chunk_size: u64, last: bool) -> SmtpResponse {
        // BDAT allowed from RcptTo (first chunk) or Bdat (subsequent chunks)
        if self.state != SessionState::RcptTo && self.state != SessionState::Bdat {
            return SmtpResponse::bad_sequence();
        }

        // Check CHUNKING is enabled
        if !self.config.extensions.has(Extensions::CHUNKING) {
            return SmtpResponse::command_not_implemented();
        }

        // Check total accumulated size against limit
        let total = self.bdat_data.len() as u64 + chunk_size;
        if total > self.config.max_message_size {
            // Must still read the chunk bytes to stay in sync, then reject
            if self.read_exact_bytes(chunk_size as usize).await.is_err() {
                self.state = SessionState::Done;
                return SmtpResponse::service_unavailable();
            }
            self.reset_envelope();
            self.state = SessionState::Greeted;
            return SmtpResponse::message_too_large();
        }

        // Read exactly chunk_size bytes of binary data
        let chunk = match self.read_exact_bytes(chunk_size as usize).await {
            Ok(data) => data,
            Err(ReadError::Timeout) => {
                self.state = SessionState::Done;
                return SmtpResponse::timeout();
            }
            Err(ReadError::Io(e)) => {
                warn!(error = %e, "I/O error during BDAT");
                self.state = SessionState::Done;
                return SmtpResponse::service_unavailable();
            }
            Err(ReadError::LineTooLong) => {
                // Shouldn't happen for read_exact_bytes, but handle it
                self.state = SessionState::Done;
                return SmtpResponse::service_unavailable();
            }
        };

        self.bdat_data.extend_from_slice(&chunk);

        if !last {
            self.state = SessionState::Bdat;
            return SmtpResponse::ok();
        }

        // LAST chunk - process the complete message (same logic as handle_data)
        let data = std::mem::take(&mut self.bdat_data);
        let response = if let Some(ref processor) = self.deps.message_processor {
            let dsn_ret = self.mail_from.as_ref().and_then(|m| m.ret);
            let dsn_envid = self.mail_from.as_ref().and_then(|m| m.envid.clone());
            let mut dsn_notify = HashMap::new();
            let mut dsn_orcpt = HashMap::new();
            for rcpt in &self.rcpt_to {
                if let Some(notify) = rcpt.notify {
                    dsn_notify.insert(rcpt.path.clone(), notify);
                }
                if let Some(ref orcpt) = rcpt.orcpt {
                    dsn_orcpt.insert(rcpt.path.clone(), orcpt.clone());
                }
            }

            let msg = InboundMessage {
                raw_data: data,
                envelope_from: self
                    .mail_from
                    .as_ref()
                    .map(|m| m.path.clone())
                    .unwrap_or_default(),
                envelope_to: self.rcpt_to.iter().map(|r| r.path.clone()).collect(),
                peer_addr: self.peer_addr,
                client_domain: self.client_domain.clone(),
                server_hostname: self.config.hostname.clone(),
                authenticated_user: self.authenticated.as_ref().map(|a| a.username.clone()),
                tls_active: self.tls_active,
                max_received_headers: self.config.max_received_headers,
                dsn_ret,
                dsn_envid,
                dsn_notify,
                dsn_orcpt,
            };
            match processor(msg).await {
                Ok(outcome) => SmtpResponse::data_ok(&outcome.queue_id),
                Err(ProcessingError::Reject {
                    code,
                    enhanced,
                    message,
                }) => SmtpResponse::processing_reject(code, &enhanced, &message),
                Err(ProcessingError::TempFail {
                    code,
                    enhanced,
                    message,
                }) => SmtpResponse::processing_tempfail(code, &enhanced, &message),
            }
        } else {
            let queue_id = format!("{:016X}", rand_queue_id());
            info!(
                queue_id,
                bytes = self.bdat_data.len(),
                recipients = self.rcpt_to.len(),
                "message received (BDAT)"
            );
            SmtpResponse::data_ok(&queue_id)
        };

        self.message_count += 1;
        self.reset_envelope();
        self.state = SessionState::Greeted;
        response
    }

    /// Read exactly `count` bytes from the stream (for BDAT binary chunks).
    /// Drains from `read_buf` first, then reads from the stream directly.
    async fn read_exact_bytes(&mut self, count: usize) -> Result<Vec<u8>, ReadError> {
        let mut result = Vec::with_capacity(count);
        let mut remaining = count;

        // Drain from read_buf first
        let from_buf = remaining.min(self.read_buf.len());
        if from_buf > 0 {
            result.extend_from_slice(&self.read_buf[..from_buf]);
            let _ = self.read_buf.split_to(from_buf);
            remaining -= from_buf;
        }

        // Read the rest from the stream
        while remaining > 0 {
            let mut tmp = vec![0u8; remaining.min(8192)];
            let timeout = self.config.data_block_timeout;
            let n = match tokio::time::timeout(timeout, self.stream.read(&mut tmp)).await {
                Ok(Ok(0)) => return Err(ReadError::Io(std::io::ErrorKind::UnexpectedEof.into())),
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(ReadError::Io(e)),
                Err(_) => return Err(ReadError::Timeout),
            };
            let take = n.min(remaining);
            result.extend_from_slice(&tmp[..take]);
            remaining -= take;
            // If we read more than needed, put the excess back in read_buf
            if n > take {
                self.read_buf.extend_from_slice(&tmp[take..n]);
            }
        }

        Ok(result)
    }

    fn handle_quit(&mut self) -> SmtpResponse {
        self.state = SessionState::Done;
        SmtpResponse::bye()
    }

    fn handle_rset(&mut self) -> SmtpResponse {
        if self.state == SessionState::Connected {
            return SmtpResponse::ok();
        }
        self.reset_envelope();
        self.state = SessionState::Greeted;
        SmtpResponse::ok()
    }

    fn reset_envelope(&mut self) {
        self.mail_from = None;
        self.rcpt_to.clear();
        self.bdat_data.clear();
    }

    // ── XCLIENT ─────────────────────────────────────────────────────────

    fn handle_xclient(&mut self, params: XClientParams) -> SmtpResponse {
        if !self.config.xclient_enabled {
            return SmtpResponse::new(550, Some("5.5.0"), "XCLIENT not available");
        }
        if !self.config.xclient_allowed_ips.contains(&self.peer_addr) {
            return SmtpResponse::new(550, Some("5.7.1"), "Not authorized");
        }
        if self.state != SessionState::Greeted {
            return SmtpResponse::bad_sequence();
        }

        // Overwrite peer info with proxied values
        if let Some(addr) = params.addr {
            self.peer_addr = addr;
        }
        if let Some(ref name) = params.name {
            self.client_domain = Some(name.clone());
        }
        if let Some(ref helo) = params.helo {
            self.client_domain = Some(helo.clone());
        }

        // Per Postfix spec: XCLIENT resets session, client must re-EHLO
        self.reset_envelope();
        self.state = SessionState::Connected;

        SmtpResponse::new(220, Some("2.0.0"), "OK")
    }

    // ── STARTTLS ────────────────────────────────────────────────────────

    fn handle_starttls(&mut self) -> CommandResult {
        // Already on TLS
        if self.tls_active {
            return CommandResult::Response(SmtpResponse::command_not_recognized());
        }
        // STARTTLS not offered
        if !self.config.extensions.has(Extensions::STARTTLS) {
            return CommandResult::Response(SmtpResponse::command_not_recognized());
        }

        // RFC 3207 §3: STARTTLS SHOULD only be issued after EHLO
        if self.state != SessionState::Greeted {
            return CommandResult::Response(SmtpResponse::bad_sequence());
        }

        // TLS acceptor not available (temporary failure)
        if !self.config.tls_available {
            return CommandResult::Response(SmtpResponse::tls_not_available());
        }

        // Write 220 Ready and signal caller to upgrade
        // Note: the response is written by the caller after receiving StartTls
        CommandResult::StartTls
    }

    // ── AUTH ────────────────────────────────────────────────────────────

    async fn handle_auth_begin(&mut self, args: &str) -> SmtpResponse {
        // Already authenticated
        if self.authenticated.is_some() {
            return SmtpResponse::already_authenticated();
        }

        // RFC 4954 §3: AUTH MUST NOT be issued during a mail transaction
        if self.state == SessionState::MailFrom || self.state == SessionState::RcptTo {
            return SmtpResponse::bad_sequence();
        }

        // Require TLS on non-SMTPS ports
        if !self.tls_active && self.listener_mode != ListenerMode::Smtps {
            return SmtpResponse::encryption_required();
        }

        // Check AUTH is offered
        if !self.config.extensions.has(Extensions::AUTH) {
            return SmtpResponse::command_not_recognized();
        }

        // Rate limit
        if self.auth_attempts >= self.config.max_auth_attempts {
            return SmtpResponse::auth_too_many();
        }

        // Pass channel binding data when TLS is active
        let cb_data = if self.tls_active {
            self.config.tls_server_cert_hash.as_deref()
        } else {
            None
        };

        match auth::begin_auth(args, &self.deps.credential_lookup, cb_data).await {
            Ok(AuthProgress::Complete(result)) => {
                info!(username = %result.username, "AUTH successful");
                let ip = self.peer_addr;
                (self.deps.on_auth_success)(ip).await;
                self.authenticated = Some(result);
                SmtpResponse::auth_success()
            }
            Ok(AuthProgress::Challenge(state, response)) => {
                self.auth_state = Some(*state);
                response
            }
            Err(response) => self.handle_auth_failure(response).await,
        }
    }

    async fn handle_auth_data(&mut self, line: &[u8]) -> SmtpResponse {
        let state = self.auth_state.take().expect("auth_state should be Some");
        let cb_data = if self.tls_active {
            self.config.tls_server_cert_hash.as_deref()
        } else {
            None
        };

        match auth::continue_auth(state, line, &self.deps.credential_lookup, cb_data).await {
            Ok(AuthProgress::Complete(result)) => {
                info!(username = %result.username, "AUTH successful");
                let ip = self.peer_addr;
                (self.deps.on_auth_success)(ip).await;
                self.authenticated = Some(result);
                SmtpResponse::auth_success()
            }
            Ok(AuthProgress::Challenge(new_state, response)) => {
                self.auth_state = Some(*new_state);
                response
            }
            Err(response) => self.handle_auth_failure(response).await,
        }
    }

    /// Handle an auth failure response. Transient failures (4xx) do NOT count
    /// against the attempt limit - the user may have correct credentials but
    /// the backend is temporarily unavailable (RFC 4954 §5).
    async fn handle_auth_failure(&mut self, response: SmtpResponse) -> SmtpResponse {
        let is_transient = response.code >= 400 && response.code < 500;
        if !is_transient {
            self.auth_attempts += 1;
            let ip = self.peer_addr;
            (self.deps.on_auth_failure)(ip).await;
            if self.auth_attempts >= self.config.max_auth_attempts {
                self.state = SessionState::Done;
                return SmtpResponse::auth_too_many();
            }
        }
        response
    }

    // ── I/O ──────────────────────────────────────────────────────────────

    async fn write_response(&mut self, resp: &SmtpResponse) -> Result<(), std::io::Error> {
        let bytes = resp.to_bytes();
        self.stream.write_all(&bytes).await?;
        self.stream.flush().await
    }

    /// Read a single CRLF-terminated line from the stream (pipelining-aware).
    /// Returns the line content without CRLF.
    async fn read_line(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, ReadError> {
        loop {
            // Check buffer for a complete line first (pipelining)
            if let Some(pos) = memchr::memchr(b'\n', &self.read_buf) {
                let mut line = self.read_buf.split_to(pos + 1);
                // Strip CRLF or LF
                if line.ends_with(b"\r\n") {
                    line.truncate(line.len() - 2);
                } else {
                    line.truncate(line.len() - 1);
                }
                return Ok(Some(line.to_vec()));
            }

            // Check line length limit before reading more
            if self.read_buf.len() > self.config.max_line_length as usize {
                // Discard until we find a newline
                self.read_buf.clear();
                return Err(ReadError::LineTooLong);
            }

            // Read more data with timeout
            let mut tmp = [0u8; 4096];
            let n = match tokio::time::timeout(timeout, self.stream.read(&mut tmp)).await {
                Ok(Ok(0)) => return Ok(None), // EOF
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(ReadError::Io(e)),
                Err(_) => return Err(ReadError::Timeout),
            };

            self.read_buf.extend_from_slice(&tmp[..n]);
        }
    }

    /// Read dot-terminated DATA content. Performs dot-unstuffing and size enforcement.
    async fn read_data(&mut self) -> Result<Vec<u8>, ReadError> {
        let mut body = Vec::new();
        let terminator = b"\r\n.\r\n";
        let finder = memmem::Finder::new(terminator);

        loop {
            // Check if the terminator is in the buffer
            if let Some(pos) = finder.find(&self.read_buf) {
                // Append everything before the terminator
                body.extend_from_slice(&self.read_buf[..pos]);
                // Consume the data + terminator from the buffer
                let _ = self.read_buf.split_to(pos + terminator.len());
                break;
            }

            // Check for bare ".\r\n" at the very start (empty message body after 354)
            if self.read_buf.starts_with(b".\r\n") {
                let _ = self.read_buf.split_to(3);
                break;
            }

            // Move safe bytes to body (keep last 4 bytes to avoid splitting terminator)
            let safe = self.read_buf.len().saturating_sub(4);
            if safe > 0 {
                body.extend_from_slice(&self.read_buf[..safe]);
                let _ = self.read_buf.split_to(safe);
            }

            // Size check
            if body.len() as u64 > self.config.max_message_size {
                // Drain remaining data until terminator to stay in sync
                self.drain_until_dot_terminator().await;
                return Err(ReadError::LineTooLong);
            }

            // Read more data
            let timeout = self.config.data_block_timeout;
            let mut tmp = [0u8; 8192];
            let n = match tokio::time::timeout(timeout, self.stream.read(&mut tmp)).await {
                Ok(Ok(0)) => return Err(ReadError::Io(std::io::ErrorKind::UnexpectedEof.into())),
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(ReadError::Io(e)),
                Err(_) => return Err(ReadError::Timeout),
            };

            self.read_buf.extend_from_slice(&tmp[..n]);
        }

        // Final size check (covers case where terminator is found in first buffer read)
        if body.len() as u64 > self.config.max_message_size {
            return Err(ReadError::LineTooLong);
        }

        // Dot-unstuffing: lines starting with ".." become "."
        let unstuffed = dot_unstuff(&body);
        Ok(unstuffed)
    }

    /// Drain input until we find the dot terminator (used after size limit exceeded).
    async fn drain_until_dot_terminator(&mut self) {
        let terminator = b"\r\n.\r\n";
        let finder = memmem::Finder::new(terminator);

        loop {
            if finder.find(&self.read_buf).is_some() {
                self.read_buf.clear();
                return;
            }
            if self.read_buf.starts_with(b".\r\n") {
                self.read_buf.clear();
                return;
            }

            let safe = self.read_buf.len().saturating_sub(4);
            if safe > 0 {
                let _ = self.read_buf.split_to(safe);
            }

            let mut tmp = [0u8; 8192];
            let timeout = self.config.data_termination_timeout;
            match tokio::time::timeout(timeout, self.stream.read(&mut tmp)).await {
                Ok(Ok(0)) | Err(_) => return,
                Ok(Ok(n)) => self.read_buf.extend_from_slice(&tmp[..n]),
                Ok(Err(_)) => return,
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal result type for command handling
// ──────────────────────────────────────────────────────────────────────────────

enum CommandResult {
    Response(SmtpResponse),
    StartTls,
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
enum ReadError {
    Io(std::io::Error),
    Timeout,
    LineTooLong,
}

/// Generate a pseudo-random queue ID using system time + simple hash.
fn rand_queue_id() -> u64 {
    use std::time::SystemTime;
    let t = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    // Mix nanoseconds for uniqueness within the same second
    t.as_nanos() as u64 ^ (t.as_secs().wrapping_mul(6_364_136_223_846_793_005))
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::DuplexStream;

    fn test_config() -> SessionConfig {
        SessionConfig {
            hostname: "test.example.com".into(),
            extensions: Extensions::default_plain(),
            max_message_size: 1024 * 1024, // 1 MB
            max_recipients: 3,
            max_messages: 2,
            max_line_length: 998,
            max_received_headers: 100,
            max_auth_attempts: 3,
            max_commands_per_session: 1000,
            strict_ehlo_validation: false,
            tls_available: false,
            greeting_timeout: Duration::from_secs(5),
            command_timeout: Duration::from_secs(5),
            data_initiation_timeout: Duration::from_secs(5),
            data_block_timeout: Duration::from_secs(5),
            data_termination_timeout: Duration::from_secs(5),
            auth_mechanisms: "PLAIN LOGIN".into(),
            tls_server_cert_hash: None,
            xclient_enabled: false,
            xclient_allowed_ips: Vec::new(),
        }
    }

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    /// Create a session with a duplex stream pair. Returns (session_handle, client_stream).
    fn create_test_session() -> (tokio::task::JoinHandle<SessionOutcome>, DuplexStream) {
        let (server, client) = tokio::io::duplex(8192);
        let config = test_config();
        let handle = tokio::spawn(async move {
            let mut session = Session::new(
                server,
                config,
                localhost(),
                ListenerMode::Smtp,
                false,
                SessionDeps::noop(),
                None,
            );
            session.run().await.unwrap_or(SessionOutcome::Closed)
        });
        (handle, client)
    }

    async fn read_response(client: &mut DuplexStream) -> String {
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("timeout reading response")
            .expect("io error reading response");
        String::from_utf8_lossy(&buf[..n]).to_string()
    }

    async fn send_and_recv(client: &mut DuplexStream, cmd: &str) -> String {
        client.write_all(cmd.as_bytes()).await.unwrap();
        client.flush().await.unwrap();
        // Small delay to let the server process
        tokio::time::sleep(Duration::from_millis(20)).await;
        read_response(client).await
    }

    #[tokio::test]
    async fn full_transaction() {
        let (_handle, mut client) = create_test_session();

        // Read greeting
        let greeting = read_response(&mut client).await;
        assert!(greeting.starts_with("220 "), "greeting: {greeting}");

        // EHLO
        let resp = send_and_recv(&mut client, "EHLO test.local\r\n").await;
        assert!(resp.starts_with("250"), "ehlo: {resp}");

        // MAIL FROM
        let resp = send_and_recv(&mut client, "MAIL FROM:<sender@example.com>\r\n").await;
        assert!(resp.starts_with("250"), "mail: {resp}");

        // RCPT TO
        let resp = send_and_recv(&mut client, "RCPT TO:<rcpt@example.com>\r\n").await;
        assert!(resp.starts_with("250"), "rcpt: {resp}");

        // DATA
        let resp = send_and_recv(&mut client, "DATA\r\n").await;
        assert!(resp.starts_with("354"), "data: {resp}");

        // Send message body
        let resp = send_and_recv(&mut client, "Subject: Test\r\n\r\nHello World\r\n.\r\n").await;
        assert!(resp.starts_with("250"), "data-ok: {resp}");
        assert!(resp.contains("queued as"), "data-ok: {resp}");

        // QUIT
        let resp = send_and_recv(&mut client, "QUIT\r\n").await;
        assert!(resp.starts_with("221"), "quit: {resp}");
    }

    #[tokio::test]
    async fn bad_sequence_mail_before_ehlo() {
        let (_handle, mut client) = create_test_session();
        let _ = read_response(&mut client).await; // greeting

        let resp = send_and_recv(&mut client, "MAIL FROM:<a@b.com>\r\n").await;
        assert!(resp.starts_with("503"), "expected bad sequence: {resp}");
    }

    #[tokio::test]
    async fn bad_sequence_data_before_rcpt() {
        let (_handle, mut client) = create_test_session();
        let _ = read_response(&mut client).await;

        send_and_recv(&mut client, "EHLO test.local\r\n").await;
        send_and_recv(&mut client, "MAIL FROM:<a@b.com>\r\n").await;

        let resp = send_and_recv(&mut client, "DATA\r\n").await;
        assert!(resp.starts_with("503"), "expected bad sequence: {resp}");
    }

    #[tokio::test]
    async fn rset_returns_to_greeted() {
        let (_handle, mut client) = create_test_session();
        let _ = read_response(&mut client).await;

        send_and_recv(&mut client, "EHLO test.local\r\n").await;
        send_and_recv(&mut client, "MAIL FROM:<a@b.com>\r\n").await;
        send_and_recv(&mut client, "RCPT TO:<b@c.com>\r\n").await;

        let resp = send_and_recv(&mut client, "RSET\r\n").await;
        assert!(resp.starts_with("250"), "rset: {resp}");

        // DATA should fail now (no MAIL FROM/RCPT TO)
        let resp = send_and_recv(&mut client, "DATA\r\n").await;
        assert!(resp.starts_with("503"), "data after rset: {resp}");

        // But MAIL FROM should work
        let resp = send_and_recv(&mut client, "MAIL FROM:<x@y.com>\r\n").await;
        assert!(resp.starts_with("250"), "mail after rset: {resp}");
    }

    #[tokio::test]
    async fn max_recipients_enforced() {
        let (_handle, mut client) = create_test_session();
        let _ = read_response(&mut client).await;

        send_and_recv(&mut client, "EHLO test.local\r\n").await;
        send_and_recv(&mut client, "MAIL FROM:<a@b.com>\r\n").await;

        // Config allows 3 recipients
        for i in 0..3 {
            let resp =
                send_and_recv(&mut client, &format!("RCPT TO:<user{i}@example.com>\r\n")).await;
            assert!(resp.starts_with("250"), "rcpt {i}: {resp}");
        }

        // 4th should fail
        let resp = send_and_recv(&mut client, "RCPT TO:<user3@example.com>\r\n").await;
        assert!(resp.starts_with("452"), "too many rcpt: {resp}");
    }

    #[tokio::test]
    async fn max_messages_enforced() {
        let (_handle, mut client) = create_test_session();
        let _ = read_response(&mut client).await;

        send_and_recv(&mut client, "EHLO test.local\r\n").await;

        // Config allows 2 messages
        for _ in 0..2 {
            send_and_recv(&mut client, "MAIL FROM:<a@b.com>\r\n").await;
            send_and_recv(&mut client, "RCPT TO:<b@c.com>\r\n").await;
            send_and_recv(&mut client, "DATA\r\n").await;
            send_and_recv(&mut client, "test\r\n.\r\n").await;
        }

        // 3rd MAIL FROM should fail
        let resp = send_and_recv(&mut client, "MAIL FROM:<a@b.com>\r\n").await;
        assert!(resp.starts_with("421"), "too many messages: {resp}");
    }

    #[tokio::test]
    async fn message_size_limit() {
        let (server, mut client) = tokio::io::duplex(1024 * 1024 + 8192);
        let mut config = test_config();
        config.max_message_size = 100; // 100 bytes

        let handle = tokio::spawn(async move {
            let mut session = Session::new(
                server,
                config,
                localhost(),
                ListenerMode::Smtp,
                false,
                SessionDeps::noop(),
                None,
            );
            let _ = session.run().await;
        });

        let _ = read_response(&mut client).await;
        send_and_recv(&mut client, "EHLO test.local\r\n").await;
        send_and_recv(&mut client, "MAIL FROM:<a@b.com>\r\n").await;
        send_and_recv(&mut client, "RCPT TO:<b@c.com>\r\n").await;
        send_and_recv(&mut client, "DATA\r\n").await;

        // Send more than 100 bytes
        let big_body = "X".repeat(200);
        let resp = send_and_recv(&mut client, &format!("{big_body}\r\n.\r\n")).await;
        assert!(resp.starts_with("552"), "expected size limit: {resp}");

        drop(client);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn pipelining() {
        let (_handle, mut client) = create_test_session();
        let _ = read_response(&mut client).await;

        // Send multiple commands at once
        client
            .write_all(b"EHLO test.local\r\nMAIL FROM:<a@b.com>\r\nRCPT TO:<b@c.com>\r\n")
            .await
            .unwrap();
        client.flush().await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Read all responses
        let mut buf = vec![0u8; 8192];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]).to_string();

        // Should have responses for all three commands
        let lines: Vec<&str> = resp.split("\r\n").filter(|l| !l.is_empty()).collect();
        // EHLO produces multiline, then MAIL and RCPT each produce a line
        assert!(resp.contains("250"), "should contain success: {resp}");
        // Count the number of "250" response starts (terminal lines)
        let response_count = lines.iter().filter(|l| l.starts_with("250 ")).count();
        assert!(
            response_count >= 3,
            "expected at least 3 final 250 responses from pipelined commands, got {response_count}: {resp}"
        );
    }

    #[tokio::test]
    async fn quit_from_any_state() {
        // QUIT from Connected state (before EHLO)
        let (_handle, mut client) = create_test_session();
        let _ = read_response(&mut client).await;
        let resp = send_and_recv(&mut client, "QUIT\r\n").await;
        assert!(resp.starts_with("221"), "quit from connected: {resp}");
    }

    #[tokio::test]
    async fn ehlo_resets_transaction() {
        let (_handle, mut client) = create_test_session();
        let _ = read_response(&mut client).await;

        send_and_recv(&mut client, "EHLO test.local\r\n").await;
        send_and_recv(&mut client, "MAIL FROM:<a@b.com>\r\n").await;
        send_and_recv(&mut client, "RCPT TO:<b@c.com>\r\n").await;

        // Second EHLO resets the transaction
        send_and_recv(&mut client, "EHLO test.local\r\n").await;

        // DATA should fail (no MAIL FROM/RCPT TO after re-EHLO)
        let resp = send_and_recv(&mut client, "DATA\r\n").await;
        assert!(resp.starts_with("503"), "data after re-ehlo: {resp}");
    }

    #[tokio::test]
    async fn noop_always_ok() {
        let (_handle, mut client) = create_test_session();
        let _ = read_response(&mut client).await;

        let resp = send_and_recv(&mut client, "NOOP\r\n").await;
        assert!(resp.starts_with("250"), "noop: {resp}");
    }

    #[tokio::test]
    async fn unknown_command_rejected() {
        let (_handle, mut client) = create_test_session();
        let _ = read_response(&mut client).await;

        let resp = send_and_recv(&mut client, "XYZZY\r\n").await;
        assert!(resp.starts_with("500"), "unknown: {resp}");
    }

    #[tokio::test]
    async fn bare_postmaster_accepted() {
        let (_handle, mut client) = create_test_session();
        let _ = read_response(&mut client).await;

        send_and_recv(&mut client, "EHLO test.local\r\n").await;
        send_and_recv(&mut client, "MAIL FROM:<sender@example.com>\r\n").await;

        let resp = send_and_recv(&mut client, "RCPT TO:<postmaster>\r\n").await;
        assert!(
            resp.starts_with("250"),
            "bare postmaster should be accepted: {resp}"
        );
    }

    #[tokio::test]
    async fn expn_returns_502() {
        let (_handle, mut client) = create_test_session();
        let _ = read_response(&mut client).await;

        let resp = send_and_recv(&mut client, "EXPN list\r\n").await;
        assert!(resp.starts_with("502"), "expn should be 502: {resp}");
    }

    #[tokio::test]
    async fn declared_size_too_large() {
        let (server, mut client) = tokio::io::duplex(8192);
        let mut config = test_config();
        config.max_message_size = 1000;

        tokio::spawn(async move {
            let mut session = Session::new(
                server,
                config,
                localhost(),
                ListenerMode::Smtp,
                false,
                SessionDeps::noop(),
                None,
            );
            let _ = session.run().await;
        });

        let _ = read_response(&mut client).await;
        send_and_recv(&mut client, "EHLO test.local\r\n").await;

        let resp = send_and_recv(&mut client, "MAIL FROM:<a@b.com> SIZE=5000\r\n").await;
        assert!(resp.starts_with("552"), "declared size: {resp}");
    }

    // ── STARTTLS tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn starttls_returns_start_tls_outcome() {
        let (server, mut client) = tokio::io::duplex(8192);
        let mut config = test_config();
        config.extensions = Extensions::default_smtp(); // has STARTTLS
        config.tls_available = true;

        let handle = tokio::spawn(async move {
            let mut session = Session::new(
                server,
                config,
                localhost(),
                ListenerMode::Smtp,
                false,
                SessionDeps::noop(),
                None,
            );
            session.run().await.unwrap()
        });

        let _ = read_response(&mut client).await; // greeting
        send_and_recv(&mut client, "EHLO test.local\r\n").await;

        // Issue STARTTLS
        client.write_all(b"STARTTLS\r\n").await.unwrap();
        client.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Read 220 Ready
        let resp = read_response(&mut client).await;
        assert!(resp.starts_with("220"), "starttls response: {resp}");

        // Session should have returned StartTls
        drop(client);
        let outcome = handle.await.unwrap();
        assert_eq!(outcome, SessionOutcome::StartTls);
    }

    #[tokio::test]
    async fn starttls_rejected_when_already_tls() {
        let (server, mut client) = tokio::io::duplex(8192);
        let mut config = test_config();
        config.extensions = Extensions::default_smtp();

        tokio::spawn(async move {
            let mut session = Session::new(
                server,
                config,
                localhost(),
                ListenerMode::Smtps,
                true, // already TLS
                SessionDeps::noop(),
                None,
            );
            let _ = session.run().await;
        });

        let _ = read_response(&mut client).await;
        send_and_recv(&mut client, "EHLO test.local\r\n").await;
        let resp = send_and_recv(&mut client, "STARTTLS\r\n").await;
        assert!(resp.starts_with("500"), "starttls when already tls: {resp}");
    }

    // ── AUTH tests ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn auth_requires_tls_on_smtp() {
        let (_handle, mut client) = create_test_session();
        let _ = read_response(&mut client).await;
        send_and_recv(&mut client, "EHLO test.local\r\n").await;

        let resp = send_and_recv(&mut client, "AUTH PLAIN dGVzdA==\r\n").await;
        assert!(
            resp.starts_with("538") || resp.starts_with("500"),
            "auth without tls: {resp}"
        );
    }

    #[tokio::test]
    async fn auth_available_on_smtps() {
        let (server, mut client) = tokio::io::duplex(8192);
        let mut config = test_config();
        config.extensions = Extensions::default_smtps();

        tokio::spawn(async move {
            let mut session = Session::new(
                server,
                config,
                localhost(),
                ListenerMode::Smtps,
                true,
                SessionDeps::noop(),
                None,
            );
            let _ = session.run().await;
        });

        let _ = read_response(&mut client).await;
        send_and_recv(&mut client, "EHLO test.local\r\n").await;

        // AUTH should be accepted (but credentials will fail with noop lookup)
        let resp = send_and_recv(&mut client, "AUTH PLAIN dGVzdA==\r\n").await;
        assert!(
            resp.starts_with("535"),
            "auth should fail with bad creds: {resp}"
        );
    }

    #[tokio::test]
    async fn ehlo_shows_starttls_only_pre_tls() {
        let (server, mut client) = tokio::io::duplex(8192);
        let mut config = test_config();
        config.extensions = Extensions::default_submission();

        tokio::spawn(async move {
            let mut session = Session::new(
                server,
                config,
                localhost(),
                ListenerMode::Submission,
                false,
                SessionDeps::noop(),
                None,
            );
            let _ = session.run().await;
        });

        let _ = read_response(&mut client).await;
        let resp = send_and_recv(&mut client, "EHLO test.local\r\n").await;

        // Should have STARTTLS but not AUTH (no TLS yet on submission)
        assert!(resp.contains("STARTTLS"), "should offer STARTTLS: {resp}");
        assert!(
            !resp.contains("AUTH"),
            "should not offer AUTH pre-TLS: {resp}"
        );
    }

    #[tokio::test]
    async fn ehlo_shows_auth_after_tls() {
        let (server, mut client) = tokio::io::duplex(8192);
        let mut config = test_config();
        config.extensions = Extensions::default_submission();

        tokio::spawn(async move {
            let mut session = Session::new(
                server,
                config,
                localhost(),
                ListenerMode::Submission,
                true, // simulating post-TLS
                SessionDeps::noop(),
                None,
            );
            let _ = session.run().await;
        });

        let _ = read_response(&mut client).await;
        let resp = send_and_recv(&mut client, "EHLO test.local\r\n").await;

        // Should have AUTH but not STARTTLS (already on TLS)
        assert!(resp.contains("AUTH"), "should offer AUTH: {resp}");
        assert!(
            !resp.contains("STARTTLS"),
            "should not offer STARTTLS: {resp}"
        );
    }

    #[tokio::test]
    async fn auth_max_attempts() {
        let (server, mut client) = tokio::io::duplex(8192);
        let mut config = test_config();
        config.extensions = Extensions::default_smtps();
        config.max_auth_attempts = 2;

        tokio::spawn(async move {
            let mut session = Session::new(
                server,
                config,
                localhost(),
                ListenerMode::Smtps,
                true,
                SessionDeps::noop(),
                None,
            );
            let _ = session.run().await;
        });

        let _ = read_response(&mut client).await;
        send_and_recv(&mut client, "EHLO test.local\r\n").await;

        // First attempt fails (bad creds)
        let resp = send_and_recv(&mut client, "AUTH PLAIN dGVzdA==\r\n").await;
        assert!(resp.starts_with("535"), "first attempt: {resp}");

        // Second attempt should trigger too-many
        let resp = send_and_recv(&mut client, "AUTH PLAIN dGVzdA==\r\n").await;
        assert!(resp.starts_with("421"), "too many attempts: {resp}");
    }

    /// RFC 4954 §3 (3-5): AUTH MUST NOT be advertised in EHLO after successful auth.
    #[tokio::test]
    async fn ehlo_hides_auth_after_authenticated() {
        let (server, mut client) = tokio::io::duplex(8192);
        let mut config = test_config();
        config.extensions = Extensions::default_smtps();

        // Provide a credential lookup that accepts "testuser"/"secret"
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        let record = {
            use argon2::password_hash::SaltString;
            use argon2::PasswordHasher;
            let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
            let hash = argon2::Argon2::default()
                .hash_password(b"secret", &salt)
                .unwrap()
                .to_string();
            sentio_core::traits::SmtpCredentialRecord {
                id: sentio_core::ids::SmtpCredentialId(uuid::Uuid::new_v4()),
                tenant_id: sentio_core::tenant::TenantId(uuid::Uuid::new_v4()),
                username: "testuser".into(),
                password_hash: hash,
                mechanisms: vec!["PLAIN".into()],
                scram_stored_key: None,
                scram_server_key: None,
                scram_salt: None,
                scram_iterations: None,
                enabled: true,
            }
        };
        let deps = SessionDeps {
            credential_lookup: Arc::new(move |_username: &str| {
                let r = record.clone();
                Box::pin(async move { Ok(r) })
            }),
            on_auth_failure: Arc::new(|_ip| Box::pin(async {})),
            on_auth_success: Arc::new(|_ip| Box::pin(async {})),
            message_processor: None,
            domain_check: None,
        };

        tokio::spawn(async move {
            let mut session = Session::new(
                server,
                config,
                localhost(),
                ListenerMode::Smtps,
                true,
                deps,
                None,
            );
            let _ = session.run().await;
        });

        let _ = read_response(&mut client).await;
        let resp = send_and_recv(&mut client, "EHLO test.local\r\n").await;
        assert!(
            resp.contains("AUTH"),
            "should offer AUTH before auth: {resp}"
        );

        // Authenticate successfully
        let plain_data = B64.encode(b"\0testuser\0secret");
        let resp = send_and_recv(&mut client, &format!("AUTH PLAIN {plain_data}\r\n")).await;
        assert!(resp.starts_with("235"), "auth should succeed: {resp}");

        // Re-EHLO after successful auth
        let resp = send_and_recv(&mut client, "EHLO test.local\r\n").await;
        assert!(
            !resp.contains("AUTH"),
            "AUTH must not be advertised after auth: {resp}"
        );
    }

    /// RFC 4954 §3 (3-6): AUTH MUST NOT be issued during a mail transaction.
    #[tokio::test]
    async fn auth_rejected_during_mail_transaction() {
        let (server, mut client) = tokio::io::duplex(8192);
        let mut config = test_config();
        config.extensions = Extensions::default_smtps();

        tokio::spawn(async move {
            let mut session = Session::new(
                server,
                config,
                localhost(),
                ListenerMode::Smtps,
                true,
                SessionDeps::noop(),
                None,
            );
            let _ = session.run().await;
        });

        let _ = read_response(&mut client).await;
        send_and_recv(&mut client, "EHLO test.local\r\n").await;
        send_and_recv(&mut client, "MAIL FROM:<a@b.com>\r\n").await;

        // AUTH during MailFrom state should be rejected with 503
        let resp = send_and_recv(&mut client, "AUTH PLAIN dGVzdA==\r\n").await;
        assert!(
            resp.starts_with("503"),
            "AUTH during mail transaction: {resp}"
        );

        // Also after RCPT TO
        send_and_recv(&mut client, "RCPT TO:<b@c.com>\r\n").await;
        let resp = send_and_recv(&mut client, "AUTH PLAIN dGVzdA==\r\n").await;
        assert!(resp.starts_with("503"), "AUTH during rcpt state: {resp}");
    }

    // ── BDAT/CHUNKING tests ─────────────────────────────────────────

    #[tokio::test]
    async fn bdat_single_chunk() {
        let (_handle, mut client) = create_test_session();
        let _ = read_response(&mut client).await;

        send_and_recv(&mut client, "EHLO test.local\r\n").await;
        send_and_recv(&mut client, "MAIL FROM:<a@b.com>\r\n").await;
        send_and_recv(&mut client, "RCPT TO:<b@c.com>\r\n").await;

        // Send BDAT with LAST and the chunk data immediately following
        let body = b"Subject: Test\r\n\r\nHello BDAT\r\n";
        let cmd = format!("BDAT {} LAST\r\n", body.len());
        client.write_all(cmd.as_bytes()).await.unwrap();
        client.write_all(body).await.unwrap();
        client.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = read_response(&mut client).await;
        assert!(resp.starts_with("250"), "bdat single: {resp}");
        assert!(resp.contains("queued as"), "bdat single: {resp}");
    }

    #[tokio::test]
    async fn bdat_multi_chunk() {
        let (_handle, mut client) = create_test_session();
        let _ = read_response(&mut client).await;

        send_and_recv(&mut client, "EHLO test.local\r\n").await;
        send_and_recv(&mut client, "MAIL FROM:<a@b.com>\r\n").await;
        send_and_recv(&mut client, "RCPT TO:<b@c.com>\r\n").await;

        // First chunk (not LAST)
        let chunk1 = b"Subject: Test\r\n\r\n";
        let cmd1 = format!("BDAT {}\r\n", chunk1.len());
        client.write_all(cmd1.as_bytes()).await.unwrap();
        client.write_all(chunk1).await.unwrap();
        client.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let resp = read_response(&mut client).await;
        assert!(resp.starts_with("250"), "bdat chunk1: {resp}");

        // Second chunk (LAST)
        let chunk2 = b"Hello multi-chunk BDAT\r\n";
        let cmd2 = format!("BDAT {} LAST\r\n", chunk2.len());
        client.write_all(cmd2.as_bytes()).await.unwrap();
        client.write_all(chunk2).await.unwrap();
        client.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let resp = read_response(&mut client).await;
        assert!(resp.starts_with("250"), "bdat chunk2 last: {resp}");
        assert!(resp.contains("queued as"), "bdat chunk2 last: {resp}");
    }

    #[tokio::test]
    async fn bdat_before_rcpt_rejected() {
        let (_handle, mut client) = create_test_session();
        let _ = read_response(&mut client).await;

        send_and_recv(&mut client, "EHLO test.local\r\n").await;
        send_and_recv(&mut client, "MAIL FROM:<a@b.com>\r\n").await;

        // BDAT before RCPT TO should be rejected
        let resp = send_and_recv(&mut client, "BDAT 10 LAST\r\n").await;
        assert!(resp.starts_with("503"), "bdat before rcpt: {resp}");
    }

    #[tokio::test]
    async fn bdat_size_exceeded() {
        let (server, mut client) = tokio::io::duplex(1024 * 1024 + 8192);
        let mut config = test_config();
        config.max_message_size = 50;

        tokio::spawn(async move {
            let mut session = Session::new(
                server,
                config,
                localhost(),
                ListenerMode::Smtp,
                false,
                SessionDeps::noop(),
                None,
            );
            let _ = session.run().await;
        });

        let _ = read_response(&mut client).await;
        send_and_recv(&mut client, "EHLO test.local\r\n").await;
        send_and_recv(&mut client, "MAIL FROM:<a@b.com>\r\n").await;
        send_and_recv(&mut client, "RCPT TO:<b@c.com>\r\n").await;

        // Send chunk larger than limit
        let big_body = "X".repeat(100);
        let cmd = format!("BDAT {} LAST\r\n", big_body.len());
        client.write_all(cmd.as_bytes()).await.unwrap();
        client.write_all(big_body.as_bytes()).await.unwrap();
        client.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = read_response(&mut client).await;
        assert!(resp.starts_with("552"), "bdat size exceeded: {resp}");
    }

    #[tokio::test]
    async fn bdat_zero_last() {
        let (_handle, mut client) = create_test_session();
        let _ = read_response(&mut client).await;

        send_and_recv(&mut client, "EHLO test.local\r\n").await;
        send_and_recv(&mut client, "MAIL FROM:<a@b.com>\r\n").await;
        send_and_recv(&mut client, "RCPT TO:<b@c.com>\r\n").await;

        // First chunk with data
        let chunk1 = b"Subject: Test\r\n\r\nBody\r\n";
        let cmd1 = format!("BDAT {}\r\n", chunk1.len());
        client.write_all(cmd1.as_bytes()).await.unwrap();
        client.write_all(chunk1).await.unwrap();
        client.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let resp = read_response(&mut client).await;
        assert!(resp.starts_with("250"), "bdat chunk1: {resp}");

        // Zero-length LAST chunk to finalize
        let resp = send_and_recv(&mut client, "BDAT 0 LAST\r\n").await;
        assert!(resp.starts_with("250"), "bdat zero last: {resp}");
        assert!(resp.contains("queued as"), "bdat zero last: {resp}");
    }

    /// RFC 4954 §5: 454 transient auth failure does not count as an attempt.
    #[tokio::test]
    async fn auth_454_does_not_count_as_attempt() {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;

        let (server, mut client) = tokio::io::duplex(8192);
        let mut config = test_config();
        config.extensions = Extensions::default_smtps();
        config.max_auth_attempts = 2;

        // Lookup returns a transient database error
        let deps = SessionDeps {
            credential_lookup: Arc::new(|_username: &str| {
                Box::pin(async move {
                    Err(sentio_core::error::SentioError::Database(
                        "connection refused".into(),
                    ))
                })
            }),
            on_auth_failure: Arc::new(|_ip| Box::pin(async {})),
            on_auth_success: Arc::new(|_ip| Box::pin(async {})),
            message_processor: None,
            domain_check: None,
        };

        tokio::spawn(async move {
            let mut session = Session::new(
                server,
                config,
                localhost(),
                ListenerMode::Smtps,
                true,
                deps,
                None,
            );
            let _ = session.run().await;
        });

        let _ = read_response(&mut client).await;
        send_and_recv(&mut client, "EHLO test.local\r\n").await;

        // Use a properly formatted PLAIN blob so the lookup is actually called
        let plain_data = B64.encode(b"\0testuser\0password");

        // Multiple 454 responses should NOT trigger the too-many-attempts limit
        for _ in 0..5 {
            let resp = send_and_recv(&mut client, &format!("AUTH PLAIN {plain_data}\r\n")).await;
            assert!(
                resp.starts_with("454"),
                "expected 454 transient failure: {resp}"
            );
        }

        // Session should still be alive - NOOP should work
        let resp = send_and_recv(&mut client, "NOOP\r\n").await;
        assert!(
            resp.starts_with("250"),
            "session should still be alive: {resp}"
        );
    }

    /// RFC 3207 §3 (3-1b): STARTTLS SHOULD require prior EHLO.
    #[tokio::test]
    async fn starttls_rejected_before_ehlo() {
        let (server, mut client) = tokio::io::duplex(8192);
        let mut config = test_config();
        config.extensions = Extensions::default_smtp();
        config.tls_available = true;

        tokio::spawn(async move {
            let mut session = Session::new(
                server,
                config,
                localhost(),
                ListenerMode::Smtp,
                false,
                SessionDeps::noop(),
                None,
            );
            let _ = session.run().await;
        });

        let _ = read_response(&mut client).await; // greeting

        // STARTTLS before EHLO should be rejected with 503
        let resp = send_and_recv(&mut client, "STARTTLS\r\n").await;
        assert!(resp.starts_with("503"), "STARTTLS before EHLO: {resp}");
    }

    /// RFC 3207 §4 (4-9): 454 response when TLS is temporarily unavailable.
    #[tokio::test]
    async fn starttls_454_when_tls_unavailable() {
        let (server, mut client) = tokio::io::duplex(8192);
        let mut config = test_config();
        config.extensions = Extensions::default_smtp(); // advertises STARTTLS
        config.tls_available = false; // but no acceptor

        tokio::spawn(async move {
            let mut session = Session::new(
                server,
                config,
                localhost(),
                ListenerMode::Smtp,
                false,
                SessionDeps::noop(),
                None,
            );
            let _ = session.run().await;
        });

        let _ = read_response(&mut client).await;
        send_and_recv(&mut client, "EHLO test.local\r\n").await;

        // STARTTLS when advertised but TLS unavailable → 454
        let resp = send_and_recv(&mut client, "STARTTLS\r\n").await;
        assert!(resp.starts_with("454"), "TLS not available: {resp}");
    }

    // ── XCLIENT tests ─────────────────────────────────────────────────

    fn xclient_config() -> SessionConfig {
        let mut config = test_config();
        config.xclient_enabled = true;
        config.xclient_allowed_ips = vec![localhost()];
        config
    }

    #[tokio::test]
    async fn xclient_accepted_from_allowed_ip() {
        let (server, mut client) = tokio::io::duplex(8192);
        let config = xclient_config();

        tokio::spawn(async move {
            let mut session = Session::new(
                server,
                config,
                localhost(),
                ListenerMode::Smtp,
                false,
                SessionDeps::noop(),
                None,
            );
            let _ = session.run().await;
        });

        let _ = read_response(&mut client).await;
        send_and_recv(&mut client, "EHLO test.local\r\n").await;

        let resp = send_and_recv(
            &mut client,
            "XCLIENT ADDR=192.168.1.100 NAME=real-client.example.com\r\n",
        )
        .await;
        assert!(resp.starts_with("220"), "xclient accepted: {resp}");

        // Client must re-EHLO after XCLIENT (state was reset to Connected)
        let resp = send_and_recv(&mut client, "MAIL FROM:<a@b.com>\r\n").await;
        assert!(resp.starts_with("503"), "mail before re-ehlo: {resp}");

        // Re-EHLO should work
        let resp = send_and_recv(&mut client, "EHLO test.local\r\n").await;
        assert!(resp.starts_with("250"), "re-ehlo after xclient: {resp}");

        // Full transaction should work after re-EHLO
        let resp = send_and_recv(&mut client, "MAIL FROM:<a@b.com>\r\n").await;
        assert!(resp.starts_with("250"), "mail after re-ehlo: {resp}");
    }

    #[tokio::test]
    async fn xclient_rejected_from_non_allowed_ip() {
        let (server, mut client) = tokio::io::duplex(8192);
        let mut config = xclient_config();
        // Only allow 10.0.0.1, but session peer is 127.0.0.1
        config.xclient_allowed_ips = vec!["10.0.0.1".parse().unwrap()];

        tokio::spawn(async move {
            let mut session = Session::new(
                server,
                config,
                localhost(),
                ListenerMode::Smtp,
                false,
                SessionDeps::noop(),
                None,
            );
            let _ = session.run().await;
        });

        let _ = read_response(&mut client).await;
        send_and_recv(&mut client, "EHLO test.local\r\n").await;

        let resp = send_and_recv(&mut client, "XCLIENT ADDR=192.168.1.100\r\n").await;
        assert!(
            resp.starts_with("550"),
            "xclient rejected unauthorized: {resp}"
        );
        assert!(
            resp.contains("Not authorized"),
            "xclient rejected msg: {resp}"
        );
    }

    #[tokio::test]
    async fn xclient_rejected_when_disabled() {
        let (_handle, mut client) = create_test_session();
        let _ = read_response(&mut client).await;
        send_and_recv(&mut client, "EHLO test.local\r\n").await;

        let resp = send_and_recv(&mut client, "XCLIENT ADDR=192.168.1.100\r\n").await;
        assert!(resp.starts_with("550"), "xclient rejected disabled: {resp}");
        assert!(
            resp.contains("not available"),
            "xclient rejected msg: {resp}"
        );
    }

    #[tokio::test]
    async fn xclient_bad_sequence_before_ehlo() {
        let (server, mut client) = tokio::io::duplex(8192);
        let config = xclient_config();

        tokio::spawn(async move {
            let mut session = Session::new(
                server,
                config,
                localhost(),
                ListenerMode::Smtp,
                false,
                SessionDeps::noop(),
                None,
            );
            let _ = session.run().await;
        });

        let _ = read_response(&mut client).await;

        // XCLIENT before EHLO should be rejected with 503
        let resp = send_and_recv(&mut client, "XCLIENT ADDR=192.168.1.100\r\n").await;
        assert!(resp.starts_with("503"), "xclient before ehlo: {resp}");
    }

    #[tokio::test]
    async fn xclient_ehlo_advertised_to_allowed_ip() {
        let (server, mut client) = tokio::io::duplex(8192);
        let config = xclient_config();

        tokio::spawn(async move {
            let mut session = Session::new(
                server,
                config,
                localhost(),
                ListenerMode::Smtp,
                false,
                SessionDeps::noop(),
                None,
            );
            let _ = session.run().await;
        });

        let _ = read_response(&mut client).await;
        let resp = send_and_recv(&mut client, "EHLO test.local\r\n").await;
        assert!(
            resp.contains("XCLIENT"),
            "XCLIENT should be advertised to allowed IP: {resp}"
        );
    }

    #[tokio::test]
    async fn xclient_ehlo_not_advertised_to_non_allowed_ip() {
        let (server, mut client) = tokio::io::duplex(8192);
        let mut config = xclient_config();
        config.xclient_allowed_ips = vec!["10.0.0.1".parse().unwrap()];

        tokio::spawn(async move {
            let mut session = Session::new(
                server,
                config,
                localhost(),
                ListenerMode::Smtp,
                false,
                SessionDeps::noop(),
                None,
            );
            let _ = session.run().await;
        });

        let _ = read_response(&mut client).await;
        let resp = send_and_recv(&mut client, "EHLO test.local\r\n").await;
        assert!(
            !resp.contains("XCLIENT"),
            "XCLIENT should NOT be advertised to non-allowed IP: {resp}"
        );
    }

    #[tokio::test]
    async fn xclient_ehlo_not_advertised_when_disabled() {
        let (_handle, mut client) = create_test_session();
        let _ = read_response(&mut client).await;
        let resp = send_and_recv(&mut client, "EHLO test.local\r\n").await;
        assert!(
            !resp.contains("XCLIENT"),
            "XCLIENT should NOT be advertised when disabled: {resp}"
        );
    }
}
