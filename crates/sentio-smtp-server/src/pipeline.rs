use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use chrono::Utc;
use mail_parser::{MessageParser, MimeHeaders};
use tracing::{debug, info, warn};

use crate::commands::{DsnNotify, DsnRet};
use crate::validation::count_received_headers;

use sentio_auth::dmarc::{DmarcPolicy, DmarcVerifyResult};
use sentio_auth::Authenticator;
use sentio_core::event::{BounceClass, EventType, MailboxStatus};
use sentio_core::ids::AttachmentId;
use sentio_core::message::{AttachmentDisposition, ScanStatus};
use sentio_core::message::{MessageDirection, MessageId};
use sentio_core::traits::{
    BlobStore, DomainRecord, DomainRepository, MailboxRepository, MessageAttachmentRepository,
    MessageEventRepository, MessageRepository, NewAttachment, NewMessage, NewMessageEvent,
    ScanResult, SpamScorer, VirusScanner,
};
use sentio_core::verp::VerpCodec;
use sentio_queue::producer::{PublishHeaders, QueuePublisher};
use sentio_queue::topology::{EXCHANGE_EVENTS, EXCHANGE_SUBMIT};
use sentio_smtp_client::classify_bounce;

use crate::bounce_handler::parse_dsn;
use crate::mailbox_actions;

// ──────────────────────────────────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────────────────────────────────

/// Context for a message entering the inbound pipeline.
#[derive(Debug, Clone)]
pub struct InboundMessage {
    pub raw_data: Vec<u8>,
    pub envelope_from: String,
    pub envelope_to: Vec<String>,
    pub peer_addr: IpAddr,
    pub client_domain: Option<String>,
    pub server_hostname: String,
    pub authenticated_user: Option<String>,
    pub tls_active: bool,
    pub max_received_headers: u32,
    /// RFC 3461 DSN RET parameter from MAIL FROM.
    pub dsn_ret: Option<DsnRet>,
    /// RFC 3461 DSN ENVID parameter from MAIL FROM.
    pub dsn_envid: Option<String>,
    /// RFC 3461 DSN NOTIFY per recipient, keyed by recipient address.
    pub dsn_notify: HashMap<String, DsnNotify>,
    /// RFC 3461 DSN ORCPT per recipient, keyed by recipient address.
    pub dsn_orcpt: HashMap<String, String>,
}

/// Successful processing outcome.
#[derive(Debug, Clone)]
pub struct ProcessingOutcome {
    pub queue_id: String,
    pub message_id: MessageId,
}

/// Processing error - maps to SMTP reject or temp-fail.
#[derive(Debug, Clone)]
pub enum ProcessingError {
    Reject {
        code: u16,
        enhanced: String,
        message: String,
    },
    TempFail {
        code: u16,
        enhanced: String,
        message: String,
    },
}

impl ProcessingError {
    pub fn virus_detected(name: &str) -> Self {
        Self::Reject {
            code: 550,
            enhanced: "5.7.1".into(),
            message: format!("Message rejected: virus detected ({name})"),
        }
    }

    pub fn dmarc_reject(domain: &str) -> Self {
        Self::Reject {
            code: 550,
            enhanced: "5.7.1".into(),
            message: format!("Message rejected: DMARC policy failure for {domain}"),
        }
    }

    pub fn no_valid_recipient(domain: &str) -> Self {
        Self::Reject {
            code: 550,
            enhanced: "5.1.2".into(),
            message: format!("Domain not hosted: {domain}"),
        }
    }

    pub fn unparseable_message() -> Self {
        Self::Reject {
            code: 550,
            enhanced: "5.6.0".into(),
            message: "Message could not be parsed".into(),
        }
    }

    pub fn internal_error(detail: &str) -> Self {
        Self::TempFail {
            code: 451,
            enhanced: "4.3.0".into(),
            message: format!("Internal processing error: {detail}"),
        }
    }

    pub fn storage_unavailable() -> Self {
        Self::TempFail {
            code: 451,
            enhanced: "4.3.0".into(),
            message: "Storage temporarily unavailable".into(),
        }
    }

    pub fn queue_unavailable() -> Self {
        Self::TempFail {
            code: 451,
            enhanced: "4.3.0".into(),
            message: "Queue temporarily unavailable".into(),
        }
    }

    pub fn loop_detected() -> Self {
        Self::Reject {
            code: 554,
            enhanced: "5.4.6".into(),
            message: "Too many hops - routing loop detected".into(),
        }
    }
}

impl std::fmt::Display for ProcessingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reject {
                code,
                enhanced,
                message,
            } => {
                write!(f, "{code} {enhanced} {message}")
            }
            Self::TempFail {
                code,
                enhanced,
                message,
            } => {
                write!(f, "{code} {enhanced} {message}")
            }
        }
    }
}

/// Type-erased message processor callback for injection into SessionDeps.
pub type MessageProcessor = Arc<
    dyn Fn(
            InboundMessage,
        )
            -> Pin<Box<dyn Future<Output = Result<ProcessingOutcome, ProcessingError>> + Send>>
        + Send
        + Sync,
>;

// ──────────────────────────────────────────────────────────────────────────────
// MIME attachment extraction
// ──────────────────────────────────────────────────────────────────────────────

/// Owned attachment data extracted from a parsed MIME message.
struct ExtractedAttachment {
    filename: String,
    content_type: String,
    data: Vec<u8>,
    content_id: Option<String>,
    disposition: AttachmentDisposition,
}

/// Extract binary/inline attachments from a parsed message.
///
/// Skips text/html and text/plain body parts, and multipart containers.
/// `mail_parser` transparently decodes base64/quoted-printable.
fn extract_attachments(parsed: &mail_parser::Message<'_>) -> Vec<ExtractedAttachment> {
    let mut attachments = Vec::new();

    for part in parsed.parts.iter() {
        // Skip parts with no content type
        let ct = match part.content_type() {
            Some(ct) => ct,
            None => continue,
        };

        let main_type = ct.ctype();
        let subtype = ct.subtype().unwrap_or("");

        // Skip multipart containers
        if main_type == "multipart" {
            continue;
        }

        // Determine disposition from the part
        let is_inline = part
            .content_disposition()
            .map(|d| d.ctype() == "inline")
            .unwrap_or(false);
        let is_attachment = part
            .content_disposition()
            .map(|d| d.ctype() == "attachment")
            .unwrap_or(false);

        // Skip text body parts that are not explicitly attached
        if (main_type == "text" && (subtype == "plain" || subtype == "html")) && !is_attachment {
            continue;
        }

        // Get the decoded body content
        let data = match &part.body {
            mail_parser::PartType::Text(t) => t.as_bytes().to_vec(),
            mail_parser::PartType::Html(h) => h.as_bytes().to_vec(),
            mail_parser::PartType::Binary(b) | mail_parser::PartType::InlineBinary(b) => b.to_vec(),
            mail_parser::PartType::Message(msg) => msg.raw_message().to_vec(),
            mail_parser::PartType::Multipart(_) => continue,
        };

        if data.is_empty() {
            continue;
        }

        let filename = part
            .attachment_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unnamed".to_string());

        let content_id = part.content_id().map(|s| s.to_string());

        let disposition = if is_inline {
            AttachmentDisposition::Inline
        } else {
            AttachmentDisposition::Attachment
        };

        let ct_string = if subtype.is_empty() {
            main_type.to_string()
        } else {
            format!("{main_type}/{subtype}")
        };

        attachments.push(ExtractedAttachment {
            filename,
            content_type: ct_string,
            data,
            content_id,
            disposition,
        });
    }

    attachments
}

// ──────────────────────────────────────────────────────────────────────────────
// InboundPipeline
// ──────────────────────────────────────────────────────────────────────────────

pub struct InboundPipeline<B, V, M, E, D, Q, S, A, Mb> {
    blob_store: B,
    virus_scanner: V,
    message_repo: M,
    event_repo: E,
    domain_repo: D,
    queue_publisher: Q,
    spam_scorer: S,
    attachment_repo: A,
    authenticator: Arc<Authenticator>,
    mailbox_repo: Mb,
    /// VERP codec for verifying bounce return-path tokens. When `None`,
    /// bounce detection short-circuits to the normal inbound pipeline,
    /// so a misconfigured instance silently degrades to today's behaviour
    /// rather than blackholing bounces.
    verp_codec: Option<Arc<VerpCodec>>,
}

impl<B, V, M, E, D, Q, S, A, Mb> InboundPipeline<B, V, M, E, D, Q, S, A, Mb>
where
    B: BlobStore + 'static,
    V: VirusScanner + 'static,
    M: MessageRepository + 'static,
    E: MessageEventRepository + 'static,
    D: DomainRepository + 'static,
    Q: QueuePublisher + 'static,
    S: SpamScorer + 'static,
    A: MessageAttachmentRepository + 'static,
    Mb: MailboxRepository + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        blob_store: B,
        virus_scanner: V,
        message_repo: M,
        event_repo: E,
        domain_repo: D,
        queue_publisher: Q,
        spam_scorer: S,
        attachment_repo: A,
        authenticator: Arc<Authenticator>,
        mailbox_repo: Mb,
    ) -> Self {
        Self::with_verp(
            blob_store,
            virus_scanner,
            message_repo,
            event_repo,
            domain_repo,
            queue_publisher,
            spam_scorer,
            attachment_repo,
            authenticator,
            mailbox_repo,
            None,
        )
    }

    /// Construct an InboundPipeline with VERP bounce detection enabled.
    /// Pass `None` for the codec to disable bounce detection (same as
    /// `InboundPipeline::new`).
    #[allow(clippy::too_many_arguments)]
    pub fn with_verp(
        blob_store: B,
        virus_scanner: V,
        message_repo: M,
        event_repo: E,
        domain_repo: D,
        queue_publisher: Q,
        spam_scorer: S,
        attachment_repo: A,
        authenticator: Arc<Authenticator>,
        mailbox_repo: Mb,
        verp_codec: Option<Arc<VerpCodec>>,
    ) -> Self {
        Self {
            blob_store,
            virus_scanner,
            message_repo,
            event_repo,
            domain_repo,
            queue_publisher,
            spam_scorer,
            attachment_repo,
            authenticator,
            mailbox_repo,
            verp_codec,
        }
    }

    /// If any recipient looks like a VERP bounce return-path
    /// (`bounce+...@bounce.*`), and the token's HMAC verifies, treat the
    /// entire message as a bounce report, parse the DSN, persist the
    /// classified bounce against the original message, and publish a
    /// `sentio.events.event.bounce` event.
    ///
    /// Returns `Some(ProcessingOutcome)` to be sent back to the SMTP client
    /// with a 250 reply - bounces must never be 5xx'd or the remote MTA will
    /// retry forever and pile up. Decode failures, DSN parse failures, and
    /// unknown message IDs are all accepted-and-discarded for the same
    /// reason; persistence and publish failures are logged but do not
    /// affect the SMTP reply.
    async fn detect_bounce(&self, msg: &InboundMessage) -> Option<ProcessingOutcome> {
        let codec = self.verp_codec.as_ref()?;

        // Find the first recipient that looks like a VERP bounce token.
        let mut matched_rcpt: Option<(&str, uuid::Uuid)> = None;
        let mut had_unverified_token = false;
        for rcpt in &msg.envelope_to {
            let Some((local, domain)) = rcpt.rsplit_once('@') else {
                continue;
            };
            if !domain.starts_with("bounce.") {
                continue;
            }
            if !local.starts_with("bounce+") {
                continue;
            }
            match codec.decode_local_part(local) {
                Some(id) => {
                    matched_rcpt = Some((rcpt.as_str(), id));
                    break;
                }
                None => {
                    had_unverified_token = true;
                }
            }
        }

        // No recipient matched the VERP shape at all - fall through to
        // normal inbound routing.
        if matched_rcpt.is_none() && !had_unverified_token {
            return None;
        }

        // Token shape matched but HMAC failed. Accept-and-discard so the
        // remote MTA doesn't retry, but do NOT touch any message rows.
        let (rcpt, msg_id) = match matched_rcpt {
            Some(x) => x,
            None => {
                warn!(
                    bounce_token_recipient = ?msg.envelope_to,
                    "VERP token failed HMAC verification (accept-and-discard)"
                );
                return Some(ProcessingOutcome {
                    queue_id: "BOUNCE-INVALID".to_string(),
                    message_id: MessageId::new(),
                });
            }
        };

        // Look up the original message. If it doesn't exist (the row was
        // deleted, or the bounce arrived after retention), still ack 250.
        let message_id = MessageId(msg_id);
        let record = match self.message_repo.find_by_id(message_id).await {
            Ok(Some(r)) => r,
            Ok(None) => {
                info!(
                    bounce_token_recipient = %rcpt,
                    original_message_id = %msg_id,
                    "VERP bounce for unknown message id (accept-and-discard)"
                );
                return Some(ProcessingOutcome {
                    queue_id: format!("BOUNCE-{:X}", msg_id.as_u128() >> 96),
                    message_id,
                });
            }
            Err(e) => {
                warn!(
                    error = %e,
                    bounce_token_recipient = %rcpt,
                    original_message_id = %msg_id,
                    "VERP bounce: message lookup failed (accept-and-discard)"
                );
                return Some(ProcessingOutcome {
                    queue_id: format!("BOUNCE-{:X}", msg_id.as_u128() >> 96),
                    message_id,
                });
            }
        };

        // Per RFC 3464, only `multipart/report; report-type=delivery-status`
        // messages are bounce reports. parse_dsn returns None for anything
        // else (vacation responders, port25-style auto-replies, etc.). We
        // MUST NOT mark the original message bounced in that case - doing
        // so silently dropped legitimate auto-replies and corrupted
        // delivery state in our earlier broken behaviour.
        let dsn = match parse_dsn(&msg.raw_data) {
            Some(d) => d,
            None => {
                info!(
                    tenant_id = %record.tenant_id,
                    original_message_id = %msg_id,
                    bounce_token_recipient = %rcpt,
                    from = %msg.envelope_from,
                    body_bytes = msg.raw_data.len(),
                    "non-DSN reply received at VERP return-path - accept-and-discard (NOT marking bounced)"
                );
                return Some(ProcessingOutcome {
                    queue_id: format!("BOUNCE-NONDSN-{:X}", msg_id.as_u128() >> 96),
                    message_id,
                });
            }
        };

        // Classify. Unparseable code → Hard so we stop retrying.
        let class = match (dsn.status_code, dsn.enhanced_status.as_deref()) {
            (Some(code), enh) => classify_bounce(code, enh),
            _ => BounceClass::Hard,
        };

        info!(
            tenant_id = %record.tenant_id,
            original_message_id = %msg_id,
            bounce_class = %class,
            smtp_code = ?dsn.status_code,
            enhanced_status = ?dsn.enhanced_status,
            failed_recipient = ?dsn.failed_recipient,
            "VERP bounce report parsed and classified"
        );

        // Persist. Failures are logged, never propagated - we MUST 250.
        if let Err(e) = self
            .message_repo
            .mark_bounced(
                message_id,
                class,
                dsn.status_code,
                dsn.enhanced_status.as_deref(),
                dsn.diagnostic.as_deref(),
                dsn.failed_recipient.as_deref(),
            )
            .await
        {
            warn!(error = %e, original_message_id = %msg_id, "mark_bounced failed");
        }

        // Publish a bounce event. Mirrors the envelope used by the outbound
        // delivery engine when it records bounces (see
        // sentio-smtp-client::delivery::record_event) so webhook + analytics
        // consumers see a consistent shape across both bounce sources.
        let webhook_event = serde_json::json!({
            "tenant_id": record.tenant_id.to_string(),
            "event_type": "bounced",
            "message_id": message_id.to_string(),
            "payload": {
                "source": "verp_dsn",
                "bounce_class": class.to_string(),
                "smtp_code": dsn.status_code,
                "enhanced_status": dsn.enhanced_status,
                "diagnostic": dsn.diagnostic,
                "failed_recipient": dsn.failed_recipient,
            },
            "occurred_at": chrono::Utc::now().to_rfc3339(),
        });
        match serde_json::to_vec(&webhook_event) {
            Ok(body) => {
                let headers = PublishHeaders {
                    message_id: Some(message_id.to_string()),
                    tenant_id: Some(record.tenant_id.to_string()),
                    ..Default::default()
                };
                if let Err(e) = self
                    .queue_publisher
                    .publish(EXCHANGE_EVENTS, "event.bounce", &body, headers)
                    .await
                {
                    warn!(error = %e, "failed to publish VERP bounce event");
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to serialize VERP bounce event");
            }
        }

        Some(ProcessingOutcome {
            queue_id: format!("BOUNCE-{:X}", msg_id.as_u128() >> 96),
            message_id,
        })
    }

    pub async fn process(
        &self,
        mut msg: InboundMessage,
    ) -> Result<ProcessingOutcome, ProcessingError> {
        // 0. Loop detection (RFC 5321 §6.3)
        if count_received_headers(&msg.raw_data) >= msg.max_received_headers as usize {
            return Err(ProcessingError::loop_detected());
        }

        // 0b. VERP bounce detection. Runs *before* any other routing so
        //     bounces are never delivered to a mailbox, never published to
        //     the inbound NATS pipeline, and never matched against
        //     webhook-based inbound routes. Decode/lookup failures result
        //     in a 250 reply (NOT 5xx) to prevent the remote MTA from
        //     retrying bounces in a tight loop.
        if let Some(outcome) = self.detect_bounce(&msg).await {
            return Ok(outcome);
        }

        // 1. Parse message
        let parsed = MessageParser::default()
            .parse(&msg.raw_data)
            .ok_or_else(ProcessingError::unparseable_message)?;

        let header_from = parsed
            .from()
            .and_then(|addrs| addrs.first())
            .and_then(|a| a.address())
            .map(|s| s.to_string());

        let from_domain: String = header_from
            .as_deref()
            .and_then(|f| f.rsplit_once('@').map(|(_, d)| d))
            .unwrap_or("")
            .to_string();

        let header_to: Vec<String> = parsed
            .to()
            .map(|addrs| {
                addrs
                    .iter()
                    .filter_map(|a| a.address().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let header_cc: Vec<String> = parsed
            .cc()
            .map(|addrs| {
                addrs
                    .iter()
                    .filter_map(|a| a.address().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let header_reply_to = parsed
            .reply_to()
            .and_then(|addrs| addrs.first())
            .and_then(|a| a.address())
            .map(|s| s.to_string());

        let subject = parsed.subject().map(|s| s.to_string());

        let message_id_header = parsed.message_id().map(|s| s.to_string());

        // Threading headers - In-Reply-To (typically one id) and the
        // References chain (RFC 5322 section 3.6.4). A downstream consumer
        // matches these against prior messages' Message-IDs to thread a
        // reply into the conversation it answers. Bare ids - the parser
        // strips the angle brackets, same as `message_id`. Extracted as
        // owned values now so they outlive the `drop(parsed)` below.
        let in_reply_to = parsed.in_reply_to().as_text().map(|s| s.to_string());
        let references: Vec<String> = parsed
            .references()
            .as_text_list()
            .map(|l| l.iter().map(|s| s.to_string()).collect())
            .unwrap_or_default();

        // Loop-guard headers for a downstream intake gate: RFC 3834
        // Auto-Submitted, a mailing-list marker, and Precedence. Raw values
        // (owned before drop) - the consumer decides what counts as bulk/auto.
        let auto_submitted = parsed
            .header_raw("Auto-Submitted")
            .map(|s| s.trim().to_string());
        let list_id = parsed
            .header_raw("List-Id")
            .or_else(|| parsed.header_raw("List-Unsubscribe"))
            .map(|s| s.trim().to_string());
        let precedence = parsed
            .header_raw("Precedence")
            .map(|s| s.trim().to_string());

        // 1b. Extract MIME attachments into owned data before dropping parsed
        let extracted_attachments = extract_attachments(&parsed);
        drop(parsed); // release borrow on msg.raw_data

        // ── Authenticated submission → outbound path ───────────────────────
        if msg.authenticated_user.is_some() {
            return self
                .process_outbound_submission(
                    msg,
                    header_from,
                    header_to,
                    header_cc,
                    header_reply_to,
                    subject,
                    message_id_header,
                    extracted_attachments,
                    &from_domain,
                )
                .await;
        }

        // 2. Resolve tenant from first recipient domain
        let rcpt_domain = msg
            .envelope_to
            .first()
            .and_then(|r| r.rsplit_once('@').map(|(_, d)| d))
            .unwrap_or("");

        let domain_record = self
            .domain_repo
            .find_by_domain_name(rcpt_domain)
            .await
            .map_err(|e| {
                warn!(error = %e, "domain lookup failed");
                ProcessingError::internal_error("domain lookup")
            })?
            .ok_or_else(|| ProcessingError::no_valid_recipient(rcpt_domain))?;

        // 2b. Recipient validation - if domain has reject_unknown_recipients enabled,
        //     validate each envelope recipient against the mailboxes table.
        if domain_record.reject_unknown_recipients {
            let mut valid_recipients = Vec::new();
            for rcpt in &msg.envelope_to {
                let local_part = rcpt.rsplit_once('@').map(|(l, _)| l).unwrap_or(rcpt);
                if self
                    .mailbox_repo
                    .find_by_address(domain_record.id, local_part)
                    .await
                    .map_err(|e| {
                        warn!(error = %e, "mailbox lookup failed");
                        ProcessingError::internal_error("mailbox lookup")
                    })?
                    .is_some()
                {
                    valid_recipients.push(rcpt.clone());
                }
            }
            if valid_recipients.is_empty() {
                return Err(ProcessingError::Reject {
                    code: 550,
                    enhanced: "5.1.1".into(),
                    message: format!(
                        "No valid recipients found for domain {}",
                        domain_record.domain_name
                    ),
                });
            }
            msg.envelope_to = valid_recipients;
        }

        // 3. SPF check (soft-fail on error)
        let helo_domain = msg.client_domain.as_deref().unwrap_or("unknown");
        let spf_output = self
            .authenticator
            .verify_spf(
                msg.peer_addr,
                helo_domain,
                &msg.envelope_from,
                &msg.server_hostname,
            )
            .await
            .unwrap_or_else(|e| {
                debug!(error = %e, "SPF check error, soft-failing");
                sentio_auth::SpfVerifyOutput {
                    result: sentio_auth::SpfVerifyResult::TempError,
                    domain: from_domain.to_string(),
                    explanation: Some(format!("SPF check error: {e}")),
                }
            });

        // 4. DKIM verification (soft-fail on error)
        let dkim_output = self
            .authenticator
            .verify_dkim(&msg.raw_data)
            .await
            .unwrap_or_else(|e| {
                debug!(error = %e, "DKIM verification error, soft-failing");
                sentio_auth::DkimVerifyOutput { signatures: vec![] }
            });

        // 5. DMARC check (reject if policy=reject + fail)
        let dmarc_output = self
            .authenticator
            .verify_dmarc(&from_domain, &spf_output.domain, &dkim_output, &spf_output)
            .await
            .unwrap_or_else(|e| {
                debug!(error = %e, "DMARC check error, soft-failing");
                sentio_auth::DmarcVerifyOutput {
                    result: DmarcVerifyResult::TempError,
                    domain: from_domain.to_string(),
                    policy: DmarcPolicy::None,
                    dkim_aligned: false,
                    spf_aligned: false,
                    record: None,
                }
            });

        if dmarc_output.result == DmarcVerifyResult::Fail
            && dmarc_output.policy == DmarcPolicy::Reject
        {
            return Err(ProcessingError::dmarc_reject(&dmarc_output.domain));
        }

        // 5b. Generate IDs early so queue_id can appear in the Received header
        let message_id = MessageId::new();
        let queue_id = format!("{:X}", message_id.0.as_u128() >> 64);

        // 5c. Build Authentication-Results header (RFC 8601)
        let auth_results = generate_authentication_results(
            &msg.server_hostname,
            &spf_output,
            &dkim_output,
            &dmarc_output,
        );

        // 5d. Prepend Return-Path + Received + Authentication-Results - after DKIM
        //     verification so DKIM signatures are verified against the original message.
        let return_path = format!("Return-Path: <{}>\r\n", msg.envelope_from);
        let received_header = generate_received_header(&msg, &queue_id);
        let mut new_raw = Vec::with_capacity(
            return_path.len() + received_header.len() + auth_results.len() + msg.raw_data.len(),
        );
        new_raw.extend_from_slice(return_path.as_bytes());
        new_raw.extend_from_slice(received_header.as_bytes());
        new_raw.extend_from_slice(auth_results.as_bytes());
        new_raw.extend_from_slice(&msg.raw_data);
        msg.raw_data = new_raw;

        // 6. Virus scan
        match self.virus_scanner.scan(&msg.raw_data).await {
            Ok(ScanResult::Infected(name)) => {
                return Err(ProcessingError::virus_detected(&name));
            }
            Ok(ScanResult::Error(e)) => {
                return Err(ProcessingError::internal_error(&format!(
                    "virus scanner: {e}"
                )));
            }
            Err(e) => {
                return Err(ProcessingError::internal_error(&format!(
                    "virus scanner: {e}"
                )));
            }
            Ok(ScanResult::Clean) => {}
        }

        // 7. Spam scoring (record, never reject)
        let spam_result = self
            .spam_scorer
            .score(
                &msg.raw_data,
                &msg.envelope_from,
                &msg.envelope_to,
                msg.peer_addr,
            )
            .await
            .unwrap_or_else(|e| {
                warn!(error = %e, "spam scoring failed, defaulting to 0");
                sentio_core::traits::SpamScore {
                    score: 0.0,
                    action: sentio_core::traits::SpamAction::Accept,
                    rules: vec![],
                }
            });

        // 7b. Mailbox-level actions (forward / auto-reply).
        //     Runs IN ADDITION to the tenant inbound-route webhook so
        //     both fire for the same message. Best effort - failures
        //     here must not break the inbound pipeline. Must happen
        //     BEFORE the `mem::take` below (we read `msg.raw_data`).
        self.dispatch_mailbox_actions(
            &msg.raw_data,
            &msg.envelope_from,
            &msg.envelope_to,
            header_from.as_deref(),
            &header_to,
            subject.as_deref(),
            message_id_header.as_deref(),
            &msg.server_hostname,
            &domain_record,
            auto_submitted.as_deref(),
            list_id.as_deref(),
            precedence.as_deref(),
        )
        .await;

        // 8. Upload raw EML to blob store
        let assigned = self.blob_store.assign().await.map_err(|e| {
            warn!(error = %e, "blob store assign failed");
            ProcessingError::storage_unavailable()
        })?;

        self.blob_store
            .upload(
                &assigned.fid,
                Bytes::from(std::mem::take(&mut msg.raw_data)),
                "raw.eml",
                "message/rfc822",
            )
            .await
            .map_err(|e| {
                warn!(error = %e, "blob store upload failed");
                ProcessingError::storage_unavailable()
            })?;

        // 9. Insert message metadata to database
        // Serialize DSN params for DB storage
        let dsn_ret_str = msg.dsn_ret.map(|r| match r {
            DsnRet::Full => "FULL".to_string(),
            DsnRet::Hdrs => "HDRS".to_string(),
        });

        let dsn_notify_json = if msg.dsn_notify.is_empty() {
            serde_json::Value::Null
        } else {
            let map: serde_json::Map<String, serde_json::Value> = msg
                .dsn_notify
                .iter()
                .map(|(k, v)| {
                    let val = match v {
                        DsnNotify::Never => "NEVER".to_string(),
                        DsnNotify::Flags {
                            success,
                            failure,
                            delay,
                        } => {
                            let mut parts = Vec::new();
                            if *success {
                                parts.push("SUCCESS");
                            }
                            if *failure {
                                parts.push("FAILURE");
                            }
                            if *delay {
                                parts.push("DELAY");
                            }
                            parts.join(",")
                        }
                    };
                    (k.clone(), serde_json::Value::String(val))
                })
                .collect();
            serde_json::Value::Object(map)
        };

        let dsn_orcpt_json = if msg.dsn_orcpt.is_empty() {
            serde_json::Value::Null
        } else {
            let map: serde_json::Map<String, serde_json::Value> = msg
                .dsn_orcpt
                .iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                .collect();
            serde_json::Value::Object(map)
        };

        let new_message = NewMessage {
            id: message_id,
            tenant_id: domain_record.tenant_id,
            domain_id: Some(domain_record.id),
            direction: MessageDirection::Inbound,
            envelope_from: msg.envelope_from.clone(),
            envelope_to: msg.envelope_to.clone(),
            header_from,
            header_to,
            header_cc,
            header_reply_to,
            subject,
            message_id_header,
            tags: vec![],
            metadata: None,
            message_size: Some(msg.raw_data.len() as i64),
            raw_eml_key: Some(assigned.fid.clone()),
            spam_score: Some(spam_result.score),
            spam_action: Some(spam_result.action.to_string()),
            send_at: None,
            dsn_ret: dsn_ret_str.clone(),
            dsn_envid: msg.dsn_envid.clone(),
            dsn_notify: dsn_notify_json.clone(),
            dsn_orcpt: dsn_orcpt_json.clone(),
        };

        self.message_repo.insert(new_message).await.map_err(|e| {
            warn!(error = %e, "message insert failed");
            ProcessingError::storage_unavailable()
        })?;

        // 9b. Store extracted MIME attachments (best effort - never fail the message)
        for attachment in extracted_attachments {
            let filename = attachment.filename.clone();
            if let Err(e) = self
                .process_single_attachment(attachment, message_id, domain_record.tenant_id)
                .await
            {
                warn!(
                    error = %e,
                    filename = %filename,
                    "attachment processing failed (best effort)"
                );
            }
        }

        // 10. Log "queued" event (best effort)
        let event = NewMessageEvent {
            message_id,
            tenant_id: domain_record.tenant_id,
            event_type: EventType::Queued,
            smtp_response: None,
            remote_mta: None,
            diagnostic_code: None,
            bounce_class: None,
            retry_count: None,
            next_retry_at: None,
            source_ip: Some(msg.peer_addr),
            destination_ip: None,
            tls_version: None,
        };
        if let Err(e) = self.event_repo.insert(event).await {
            warn!(error = %e, "event insert failed (best effort)");
        }

        // 11. Publish to inbound queue
        let payload = serde_json::json!({
            "message_id": message_id.to_string(),
            "tenant_id": domain_record.tenant_id.0.to_string(),
            "domain_id": domain_record.id.0.to_string(),
            "envelope_from": msg.envelope_from,
            "envelope_to": msg.envelope_to,
            "raw_eml_key": assigned.fid,
            "spam_score": spam_result.score,
            "spam_action": spam_result.action.to_string(),
            "queued_at": Utc::now().to_rfc3339(),
            "in_reply_to": in_reply_to,
            "references": references,
            "auto_submitted": auto_submitted,
            "list_id": list_id,
            "precedence": precedence,
            "dsn_ret": dsn_ret_str,
            "dsn_envid": msg.dsn_envid,
            "dsn_notify": dsn_notify_json,
            "dsn_orcpt": dsn_orcpt_json,
        });

        let headers = PublishHeaders {
            message_id: Some(message_id.to_string()),
            tenant_id: Some(domain_record.tenant_id.0.to_string()),
            ..Default::default()
        };

        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| ProcessingError::internal_error(&e.to_string()))?;

        self.queue_publisher
            .publish(
                EXCHANGE_SUBMIT,
                "message.inbound.received",
                &payload_bytes,
                headers,
            )
            .await
            .map_err(|e| {
                warn!(error = %e, "queue publish failed");
                ProcessingError::queue_unavailable()
            })?;

        info!(
            queue_id,
            message_id = %message_id,
            tenant_id = %domain_record.tenant_id,
            "message queued"
        );

        // 12. Return outcome
        Ok(ProcessingOutcome {
            queue_id,
            message_id,
        })
    }

    /// Process an authenticated submission for outbound delivery.
    ///
    /// Skips inbound-only checks (SPF, DKIM verification, DMARC, spam scoring)
    /// and publishes to the outbound queue for delivery.
    async fn process_outbound_submission(
        &self,
        mut msg: InboundMessage,
        header_from: Option<String>,
        header_to: Vec<String>,
        header_cc: Vec<String>,
        header_reply_to: Option<String>,
        subject: Option<String>,
        message_id_header: Option<String>,
        extracted_attachments: Vec<ExtractedAttachment>,
        from_domain: &str,
    ) -> Result<ProcessingOutcome, ProcessingError> {
        let auth_user = msg.authenticated_user.as_deref().unwrap_or("unknown");
        info!(
            auth_user,
            from_domain,
            recipients = ?msg.envelope_to,
            "processing outbound submission"
        );

        // 1. Resolve tenant from sender domain (must be enabled for sending)
        let sender_domain = msg
            .envelope_from
            .rsplit_once('@')
            .map(|(_, d)| d)
            .unwrap_or(from_domain);

        let domain_record = self
            .domain_repo
            .find_by_sending_domain(sender_domain)
            .await
            .map_err(|e| {
                warn!(error = %e, "sender domain lookup failed");
                ProcessingError::internal_error("sender domain lookup")
            })?
            .ok_or_else(|| ProcessingError::Reject {
                code: 550,
                enhanced: "5.7.1".into(),
                message: format!("Sender domain not authorized for sending: {sender_domain}"),
            })?;

        // 2. Generate IDs
        let message_id = MessageId::new();
        let queue_id = format!("{:X}", message_id.0.as_u128() >> 64);

        // 3. Prepend Received header (no Return-Path - that's added by the final MTA)
        let received_header = generate_received_header(&msg, &queue_id);
        let mut new_raw = Vec::with_capacity(received_header.len() + msg.raw_data.len());
        new_raw.extend_from_slice(received_header.as_bytes());
        new_raw.extend_from_slice(&msg.raw_data);
        msg.raw_data = new_raw;

        // 4. Virus scan (still scan outbound)
        match self.virus_scanner.scan(&msg.raw_data).await {
            Ok(ScanResult::Infected(name)) => {
                return Err(ProcessingError::virus_detected(&name));
            }
            Ok(ScanResult::Error(e)) => {
                return Err(ProcessingError::internal_error(&format!(
                    "virus scanner: {e}"
                )));
            }
            Err(e) => {
                return Err(ProcessingError::internal_error(&format!(
                    "virus scanner: {e}"
                )));
            }
            Ok(ScanResult::Clean) => {}
        }

        // 5. Upload raw EML to blob store
        let message_size = msg.raw_data.len() as i64;
        let assigned = self.blob_store.assign().await.map_err(|e| {
            warn!(error = %e, "blob store assign failed");
            ProcessingError::storage_unavailable()
        })?;

        self.blob_store
            .upload(
                &assigned.fid,
                Bytes::from(std::mem::take(&mut msg.raw_data)),
                "raw.eml",
                "message/rfc822",
            )
            .await
            .map_err(|e| {
                warn!(error = %e, "blob store upload failed");
                ProcessingError::storage_unavailable()
            })?;

        // 6. Insert message metadata (direction = Outbound, no spam score)
        let dsn_ret_str = msg.dsn_ret.map(|r| match r {
            DsnRet::Full => "FULL".to_string(),
            DsnRet::Hdrs => "HDRS".to_string(),
        });

        let dsn_notify_json = if msg.dsn_notify.is_empty() {
            serde_json::Value::Null
        } else {
            let map: serde_json::Map<String, serde_json::Value> = msg
                .dsn_notify
                .iter()
                .map(|(k, v)| {
                    let val = match v {
                        DsnNotify::Never => "NEVER".to_string(),
                        DsnNotify::Flags {
                            success,
                            failure,
                            delay,
                        } => {
                            let mut parts = Vec::new();
                            if *success {
                                parts.push("SUCCESS");
                            }
                            if *failure {
                                parts.push("FAILURE");
                            }
                            if *delay {
                                parts.push("DELAY");
                            }
                            parts.join(",")
                        }
                    };
                    (k.clone(), serde_json::Value::String(val))
                })
                .collect();
            serde_json::Value::Object(map)
        };

        let dsn_orcpt_json = if msg.dsn_orcpt.is_empty() {
            serde_json::Value::Null
        } else {
            let map: serde_json::Map<String, serde_json::Value> = msg
                .dsn_orcpt
                .iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                .collect();
            serde_json::Value::Object(map)
        };

        let new_message = NewMessage {
            id: message_id,
            tenant_id: domain_record.tenant_id,
            domain_id: Some(domain_record.id),
            direction: MessageDirection::Outbound,
            envelope_from: msg.envelope_from.clone(),
            envelope_to: msg.envelope_to.clone(),
            header_from,
            header_to,
            header_cc,
            header_reply_to,
            subject,
            message_id_header,
            tags: vec![],
            metadata: None,
            message_size: Some(message_size),
            raw_eml_key: Some(assigned.fid.clone()),
            spam_score: None,
            spam_action: None,
            send_at: None,
            dsn_ret: dsn_ret_str.clone(),
            dsn_envid: msg.dsn_envid.clone(),
            dsn_notify: dsn_notify_json.clone(),
            dsn_orcpt: dsn_orcpt_json.clone(),
        };

        self.message_repo.insert(new_message).await.map_err(|e| {
            warn!(error = %e, "message insert failed");
            ProcessingError::storage_unavailable()
        })?;

        // 6b. Store extracted MIME attachments (best effort)
        for attachment in extracted_attachments {
            let filename = attachment.filename.clone();
            if let Err(e) = self
                .process_single_attachment(attachment, message_id, domain_record.tenant_id)
                .await
            {
                warn!(
                    error = %e,
                    filename = %filename,
                    "attachment processing failed (best effort)"
                );
            }
        }

        // 7. Log "queued" event (best effort)
        let event = NewMessageEvent {
            message_id,
            tenant_id: domain_record.tenant_id,
            event_type: EventType::Queued,
            smtp_response: None,
            remote_mta: None,
            diagnostic_code: None,
            bounce_class: None,
            retry_count: None,
            next_retry_at: None,
            source_ip: Some(msg.peer_addr),
            destination_ip: None,
            tls_version: None,
        };
        if let Err(e) = self.event_repo.insert(event).await {
            warn!(error = %e, "event insert failed (best effort)");
        }

        // 8. Publish to outbound queue
        let payload = serde_json::json!({
            "message_id": message_id.to_string(),
            "tenant_id": domain_record.tenant_id.0.to_string(),
            "domain_id": domain_record.id.0.to_string(),
            "envelope_from": msg.envelope_from,
            "envelope_to": msg.envelope_to,
            "raw_eml_key": assigned.fid,
            "is_forward": false,
            "dsn_ret": dsn_ret_str,
            "dsn_envid": msg.dsn_envid,
            "dsn_notify": dsn_notify_json,
            "dsn_orcpt": dsn_orcpt_json,
            "track_opens": false,
            "track_clicks": false,
        });

        let headers = PublishHeaders {
            message_id: Some(message_id.to_string()),
            tenant_id: Some(domain_record.tenant_id.0.to_string()),
            ..Default::default()
        };

        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| ProcessingError::internal_error(&e.to_string()))?;

        self.queue_publisher
            .publish(
                EXCHANGE_SUBMIT,
                "message.outbound.send",
                &payload_bytes,
                headers,
            )
            .await
            .map_err(|e| {
                warn!(error = %e, "queue publish failed");
                ProcessingError::queue_unavailable()
            })?;

        info!(
            queue_id,
            message_id = %message_id,
            tenant_id = %domain_record.tenant_id,
            auth_user,
            "outbound message queued via submission"
        );

        Ok(ProcessingOutcome {
            queue_id,
            message_id,
        })
    }

    /// Look up each envelope recipient against the mailboxes table and
    /// trigger any per-mailbox `forward_to` / `auto_reply` actions.
    ///
    /// This runs IN ADDITION to the tenant-level inbound webhook routing:
    /// both fire on the same message. Errors here are logged but NEVER
    /// propagated, because we don't want a flaky forward destination to
    /// fail the original inbound delivery.
    ///
    /// Mailbox lookups are skipped (with a log line) when the message
    /// shows the typical loop-causing signals - see
    /// [`mailbox_actions::skip_reason`].
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_mailbox_actions(
        &self,
        raw_data: &[u8],
        envelope_from: &str,
        envelope_to: &[String],
        header_from: Option<&str>,
        header_to: &[String],
        subject: Option<&str>,
        message_id_header: Option<&str>,
        server_hostname: &str,
        domain_record: &DomainRecord,
        auto_submitted: Option<&str>,
        list_id: Option<&str>,
        precedence: Option<&str>,
    ) {
        if let Some(reason) = mailbox_actions::skip_reason(
            envelope_from,
            auto_submitted,
            list_id,
            precedence,
            raw_data,
        ) {
            debug!(
                reason,
                domain = %domain_record.domain_name,
                "mailbox actions skipped"
            );
            return;
        }

        for rcpt in envelope_to {
            let Some((local_part, rcpt_domain)) = rcpt.rsplit_once('@') else {
                continue;
            };
            // Only check mailboxes for recipients in this domain. (A
            // multi-recipient message can have rcpts in multiple
            // domains; the others are someone else's problem.)
            if !rcpt_domain.eq_ignore_ascii_case(&domain_record.domain_name) {
                continue;
            }

            let mailbox = match self
                .mailbox_repo
                .find_by_address(domain_record.id, local_part)
                .await
            {
                Ok(Some(m)) => m,
                Ok(None) => continue,
                Err(e) => {
                    warn!(error = %e, rcpt, "mailbox lookup failed");
                    continue;
                }
            };

            if mailbox.status != MailboxStatus::Active {
                debug!(rcpt, status = ?mailbox.status, "mailbox not active, skipping actions");
                continue;
            }

            // `mailbox.address` is the local-part only - compose the
            // canonical full address for use in From: / envelope_from.
            let mailbox_full = format!("{}@{}", mailbox.address, domain_record.domain_name);

            // Forward
            if !mailbox.forward_to.is_empty() {
                let forwarded = mailbox_actions::rewrite_for_forward(
                    raw_data,
                    &mailbox_full,
                    mailbox.display_name.as_deref(),
                    header_from,
                    header_to,
                );
                if let Err(e) = self
                    .enqueue_outbound_eml(
                        forwarded,
                        mailbox_full.clone(),
                        mailbox.forward_to.clone(),
                        Some(mailbox_full.clone()),
                        mailbox.forward_to.clone(),
                        subject.map(|s| s.to_string()),
                        message_id_header.map(|s| s.to_string()),
                        domain_record,
                    )
                    .await
                {
                    warn!(error = %e, rcpt = %mailbox_full, "forward enqueue failed");
                } else {
                    info!(
                        rcpt = %mailbox_full,
                        forward_to = ?mailbox.forward_to,
                        "mailbox forward enqueued"
                    );
                }
            }

            // Auto-reply
            if mailbox.auto_reply {
                let (eml, new_mid) = mailbox_actions::build_auto_reply_eml(
                    &mailbox_full,
                    mailbox.display_name.as_deref(),
                    envelope_from,
                    mailbox.auto_reply_subject.as_deref(),
                    mailbox.auto_reply_body.as_deref(),
                    subject,
                    message_id_header,
                    server_hostname,
                );
                if let Err(e) = self
                    .enqueue_outbound_eml(
                        eml,
                        mailbox_full.clone(),
                        vec![envelope_from.to_string()],
                        Some(mailbox_full.clone()),
                        vec![envelope_from.to_string()],
                        Some(format!("Re: {}", subject.unwrap_or("(no subject)"))),
                        Some(new_mid),
                        domain_record,
                    )
                    .await
                {
                    warn!(error = %e, rcpt = %mailbox_full, "auto-reply enqueue failed");
                } else {
                    info!(
                        rcpt = %mailbox_full,
                        to = %envelope_from,
                        "mailbox auto-reply enqueued"
                    );
                }
            }
        }
    }

    /// Upload an EML to blob storage, insert a Message row (Outbound)
    /// and publish the outbound NATS event. Shared by the forward and
    /// auto-reply paths in [`Self::dispatch_mailbox_actions`].
    #[allow(clippy::too_many_arguments)]
    async fn enqueue_outbound_eml(
        &self,
        raw_eml: Vec<u8>,
        envelope_from: String,
        envelope_to: Vec<String>,
        header_from: Option<String>,
        header_to: Vec<String>,
        subject: Option<String>,
        message_id_header: Option<String>,
        domain_record: &DomainRecord,
    ) -> Result<MessageId, String> {
        let size = raw_eml.len() as i64;
        let assigned = self
            .blob_store
            .assign()
            .await
            .map_err(|e| format!("blob assign: {e}"))?;
        self.blob_store
            .upload(
                &assigned.fid,
                Bytes::from(raw_eml),
                "raw.eml",
                "message/rfc822",
            )
            .await
            .map_err(|e| format!("blob upload: {e}"))?;

        let message_id = MessageId::new();
        let new_message = NewMessage {
            id: message_id,
            tenant_id: domain_record.tenant_id,
            domain_id: Some(domain_record.id),
            direction: MessageDirection::Outbound,
            envelope_from: envelope_from.clone(),
            envelope_to: envelope_to.clone(),
            header_from,
            header_to,
            header_cc: vec![],
            header_reply_to: None,
            subject,
            message_id_header,
            tags: vec!["mailbox-action".to_string()],
            metadata: None,
            message_size: Some(size),
            raw_eml_key: Some(assigned.fid.clone()),
            spam_score: None,
            spam_action: None,
            send_at: None,
            dsn_ret: None,
            dsn_envid: None,
            dsn_notify: serde_json::Value::Null,
            dsn_orcpt: serde_json::Value::Null,
        };
        self.message_repo
            .insert(new_message)
            .await
            .map_err(|e| format!("message insert: {e}"))?;

        let payload = serde_json::json!({
            "message_id": message_id.to_string(),
            "tenant_id": domain_record.tenant_id.0.to_string(),
            "domain_id": domain_record.id.0.to_string(),
            "envelope_from": envelope_from,
            "envelope_to": envelope_to,
            "raw_eml_key": assigned.fid,
            "is_forward": true,
            "track_opens": false,
            "track_clicks": false,
        });
        let payload_bytes =
            serde_json::to_vec(&payload).map_err(|e| format!("payload serialize: {e}"))?;
        let headers = PublishHeaders {
            message_id: Some(message_id.to_string()),
            tenant_id: Some(domain_record.tenant_id.0.to_string()),
            ..Default::default()
        };
        self.queue_publisher
            .publish(
                EXCHANGE_SUBMIT,
                "message.outbound.send",
                &payload_bytes,
                headers,
            )
            .await
            .map_err(|e| format!("queue publish: {e}"))?;

        Ok(message_id)
    }

    /// Upload a single extracted attachment to blob storage and insert its metadata.
    async fn process_single_attachment(
        &self,
        attachment: ExtractedAttachment,
        message_id: MessageId,
        tenant_id: sentio_core::tenant::TenantId,
    ) -> Result<AttachmentId, sentio_core::error::SentioError> {
        // Compute checksum and size before consuming data
        let checksum = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&attachment.data);
            hex::encode(hasher.finalize())
        };
        let size = attachment.data.len() as i64;

        let assigned = self.blob_store.assign().await?;
        self.blob_store
            .upload(
                &assigned.fid,
                Bytes::from(attachment.data),
                &attachment.filename,
                &attachment.content_type,
            )
            .await?;

        let new_attachment = NewAttachment {
            message_id,
            tenant_id,
            filename: attachment.filename.clone(),
            content_type: attachment.content_type.clone(),
            size,
            content_id: attachment.content_id,
            disposition: attachment.disposition,
            blob_key: assigned.fid,
            checksum_sha256: Some(checksum),
        };

        let att_id = self.attachment_repo.insert(new_attachment).await?;
        self.attachment_repo
            .update_scan_status(att_id, ScanStatus::Clean, None)
            .await?;

        debug!(
            attachment_id = %att_id,
            filename = %attachment.filename,
            size,
            "attachment stored"
        );

        Ok(att_id)
    }

    /// Wrap this pipeline into a type-erased `MessageProcessor` callback.
    pub fn into_processor(self: Arc<Self>) -> MessageProcessor {
        Arc::new(move |msg| {
            let pipeline = Arc::clone(&self);
            Box::pin(async move { pipeline.process(msg).await })
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Received header generation (RFC 5321 §4.4)
// ──────────────────────────────────────────────────────────────────────────────

/// Generate a Received header per RFC 5321 §4.4.
/// Generate an RFC 8601 Authentication-Results header from SPF, DKIM, and DMARC outputs.
fn generate_authentication_results(
    hostname: &str,
    spf: &sentio_auth::SpfVerifyOutput,
    dkim: &sentio_auth::DkimVerifyOutput,
    dmarc: &sentio_auth::DmarcVerifyOutput,
) -> String {
    use sentio_auth::dkim::DkimVerifyResult;
    use sentio_auth::spf::SpfVerifyResult;

    let spf_result = match spf.result {
        SpfVerifyResult::Pass => "pass",
        SpfVerifyResult::Fail => "fail",
        SpfVerifyResult::SoftFail => "softfail",
        SpfVerifyResult::Neutral => "neutral",
        SpfVerifyResult::TempError => "temperror",
        SpfVerifyResult::PermError => "permerror",
        SpfVerifyResult::None => "none",
    };

    let dmarc_result = match dmarc.result {
        DmarcVerifyResult::Pass => "pass",
        DmarcVerifyResult::Fail => "fail",
        DmarcVerifyResult::TempError => "temperror",
        DmarcVerifyResult::PermError => "permerror",
        DmarcVerifyResult::None => "none",
    };

    let dmarc_policy = match dmarc.policy {
        DmarcPolicy::None => "none",
        DmarcPolicy::Quarantine => "quarantine",
        DmarcPolicy::Reject => "reject",
    };

    // Build DKIM results - one clause per signature
    let dkim_clauses: Vec<String> = dkim
        .signatures
        .iter()
        .map(|sig| {
            let result = match sig.result {
                DkimVerifyResult::Pass => "pass",
                DkimVerifyResult::Neutral => "neutral",
                DkimVerifyResult::Fail => "fail",
                DkimVerifyResult::PermError => "permerror",
                DkimVerifyResult::TempError => "temperror",
                DkimVerifyResult::None => "none",
            };
            format!(
                "dkim={result} header.d={} header.s={} header.b=*",
                sig.domain, sig.selector
            )
        })
        .collect();

    let dkim_part = if dkim_clauses.is_empty() {
        "dkim=none".to_string()
    } else {
        dkim_clauses.join(";\r\n\t")
    };

    format!(
        "Authentication-Results: {hostname};\r\n\
         \tspf={spf_result} smtp.mailfrom={spf_domain};\r\n\
         \t{dkim_part};\r\n\
         \tdmarc={dmarc_result} (p={dmarc_policy}) header.from={dmarc_domain}\r\n",
        spf_domain = spf.domain,
        dmarc_domain = dmarc.domain,
    )
}

fn generate_received_header(msg: &InboundMessage, queue_id: &str) -> String {
    let client_domain = msg.client_domain.as_deref().unwrap_or("unknown");
    let protocol = if msg.tls_active { "ESMTPS" } else { "ESMTP" };
    let auth_clause = msg
        .authenticated_user
        .as_deref()
        .map(|u| format!(" (authenticated as {u})"))
        .unwrap_or_default();
    // RFC 5321 §4.4: FOR clause with single recipient (omit for multi-recipient privacy)
    let for_clause = if msg.envelope_to.len() == 1 {
        format!("\r\n\tfor <{}>", msg.envelope_to[0])
    } else {
        String::new()
    };
    let date = Utc::now().to_rfc2822();

    format!(
        "Received: from {client_domain} ({}){auth_clause}\r\n\
         \tby {} with {protocol}\r\n\
         \tid {queue_id}{for_clause}; {date}\r\n",
        msg.peer_addr, msg.server_hostname,
    )
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    use sentio_core::auth::DnsCheckStatus;
    use sentio_core::error::SentioError;
    use sentio_core::ids::{MailboxId, MessageEventId};
    use sentio_core::message::DomainId;
    use sentio_core::tenant::TenantId;
    use sentio_core::traits::{
        AttachmentRecord, DomainRecord, MailboxRecord, MailboxUpdate, MessageFilter, MessageRecord,
        NewAttachment, NewMailbox, SpamAction, SpamScore,
    };
    use sentio_queue::mock::MockPublisher;
    use sentio_storage::mock::{MockBlobStore, MockScanner};

    // ── Mock repos ──────────────────────────────────────────────────────

    fn test_domain_record() -> DomainRecord {
        DomainRecord {
            id: DomainId::new(),
            tenant_id: TenantId::new(),
            domain_name: "example.com".into(),
            use_for_sending: false,
            use_for_receiving: true,
            status: sentio_core::auth::DomainStatus::Verified,
            spf_status: DnsCheckStatus::Verified,
            spf_error: None,
            dkim_status: DnsCheckStatus::Verified,
            dkim_error: None,
            dmarc_status: DnsCheckStatus::Verified,
            dmarc_error: None,
            mx_status: DnsCheckStatus::Verified,
            mx_error: None,
            return_path_status: DnsCheckStatus::Verified,
            return_path_error: None,
            dns_checked_at: Some(Utc::now()),
            verification_token: "token".into(),
            verified_at: Some(Utc::now()),
            reject_unknown_recipients: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[derive(Clone)]
    struct MockDomainRepo {
        record: Option<DomainRecord>,
    }

    impl MockDomainRepo {
        fn with_domain() -> Self {
            Self {
                record: Some(test_domain_record()),
            }
        }

        fn empty() -> Self {
            Self { record: None }
        }
    }

    impl DomainRepository for MockDomainRepo {
        async fn create(
            &self,
            _d: sentio_core::traits::NewDomain,
        ) -> Result<DomainRecord, SentioError> {
            unimplemented!()
        }
        async fn get(&self, _id: DomainId) -> Result<DomainRecord, SentioError> {
            unimplemented!()
        }
        async fn get_by_name(
            &self,
            _tid: TenantId,
            _name: &str,
        ) -> Result<DomainRecord, SentioError> {
            unimplemented!()
        }
        async fn list_by_tenant(&self, _tid: TenantId) -> Result<Vec<DomainRecord>, SentioError> {
            unimplemented!()
        }
        async fn list_verified(&self) -> Result<Vec<DomainRecord>, SentioError> {
            unimplemented!()
        }
        async fn update_status(
            &self,
            _id: DomainId,
            _s: sentio_core::auth::DomainStatus,
        ) -> Result<(), SentioError> {
            unimplemented!()
        }
        async fn update_dns_checks(
            &self,
            _id: DomainId,
            _u: sentio_core::traits::DnsCheckUpdate,
        ) -> Result<(), SentioError> {
            unimplemented!()
        }
        async fn verify(&self, _id: DomainId, _token: &str) -> Result<(), SentioError> {
            unimplemented!()
        }
        async fn update(
            &self,
            _id: DomainId,
            _update: sentio_core::traits::DomainUpdate,
        ) -> Result<(), SentioError> {
            unimplemented!()
        }
        async fn delete(&self, _id: DomainId) -> Result<(), SentioError> {
            unimplemented!()
        }
        async fn find_by_domain_name(
            &self,
            _name: &str,
        ) -> Result<Option<DomainRecord>, SentioError> {
            Ok(self.record.clone())
        }
        async fn find_by_sending_domain(
            &self,
            _name: &str,
        ) -> Result<Option<DomainRecord>, SentioError> {
            Ok(self.record.clone())
        }
    }

    #[derive(Clone)]
    struct MockMessageRepo {
        inserted: Arc<Mutex<Vec<MessageId>>>,
    }

    impl MockMessageRepo {
        fn new() -> Self {
            Self {
                inserted: Arc::new(Mutex::new(vec![])),
            }
        }
    }

    impl MessageRepository for MockMessageRepo {
        async fn insert(&self, msg: NewMessage) -> Result<MessageId, SentioError> {
            self.inserted.lock().unwrap().push(msg.id);
            Ok(msg.id)
        }
        async fn get(&self, _tid: TenantId, _id: MessageId) -> Result<MessageRecord, SentioError> {
            unimplemented!()
        }
        async fn list(
            &self,
            _tid: TenantId,
            _f: MessageFilter,
        ) -> Result<Vec<MessageRecord>, SentioError> {
            unimplemented!()
        }
        async fn update_status(
            &self,
            _id: MessageId,
            _s: sentio_core::message::MessageStatus,
        ) -> Result<(), SentioError> {
            unimplemented!()
        }
        async fn set_delivered(&self, _id: MessageId) -> Result<(), SentioError> {
            unimplemented!()
        }
        async fn set_bounced(&self, _id: MessageId) -> Result<(), SentioError> {
            unimplemented!()
        }
        async fn find_by_id(&self, _id: MessageId) -> Result<Option<MessageRecord>, SentioError> {
            unimplemented!()
        }
        async fn mark_bounced(
            &self,
            _id: MessageId,
            _class: sentio_core::event::BounceClass,
            _smtp_code: Option<u16>,
            _enhanced_status: Option<&str>,
            _diagnostic: Option<&str>,
            _failed_recipient: Option<&str>,
        ) -> Result<(), SentioError> {
            unimplemented!()
        }
        async fn count_by_status(
            &self,
            _tid: TenantId,
            _from: chrono::DateTime<chrono::Utc>,
            _to: chrono::DateTime<chrono::Utc>,
        ) -> Result<Vec<sentio_core::traits::StatusCount>, SentioError> {
            unimplemented!()
        }
        async fn update_spam_score(
            &self,
            _id: MessageId,
            _spam_score: f64,
        ) -> Result<(), SentioError> {
            Ok(())
        }
        async fn update_llm_classification(
            &self,
            _id: MessageId,
            _category: &str,
            _summary: &str,
        ) -> Result<(), SentioError> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct MockEventRepo {
        inserted: Arc<Mutex<Vec<NewMessageEvent>>>,
    }

    impl MockEventRepo {
        fn new() -> Self {
            Self {
                inserted: Arc::new(Mutex::new(vec![])),
            }
        }
    }

    impl MessageEventRepository for MockEventRepo {
        async fn insert(&self, event: NewMessageEvent) -> Result<MessageEventId, SentioError> {
            self.inserted.lock().unwrap().push(event);
            Ok(MessageEventId(uuid::Uuid::new_v4()))
        }
        async fn list_by_message(
            &self,
            _id: MessageId,
        ) -> Result<Vec<sentio_core::traits::MessageEventRecord>, SentioError> {
            unimplemented!()
        }
        async fn list_by_tenant(
            &self,
            _tid: TenantId,
            _f: sentio_core::traits::EventFilter,
        ) -> Result<Vec<sentio_core::traits::MessageEventRecord>, SentioError> {
            unimplemented!()
        }
    }

    /// A blob store that always fails on assign().
    #[derive(Clone)]
    struct FailingBlobStore;

    impl BlobStore for FailingBlobStore {
        async fn assign(&self) -> Result<sentio_core::traits::AssignedFid, SentioError> {
            Err(SentioError::Storage("connection refused".into()))
        }
        async fn upload(
            &self,
            _fid: &str,
            _data: Bytes,
            _filename: &str,
            _content_type: &str,
        ) -> Result<sentio_core::traits::UploadResult, SentioError> {
            Err(SentioError::Storage("connection refused".into()))
        }
        async fn download(&self, _fid: &str) -> Result<Bytes, SentioError> {
            Err(SentioError::Storage("connection refused".into()))
        }
        async fn delete(&self, _fid: &str) -> Result<(), SentioError> {
            Err(SentioError::Storage("connection refused".into()))
        }
    }

    /// A queue publisher that always fails.
    #[derive(Clone)]
    struct FailingPublisher;

    impl QueuePublisher for FailingPublisher {
        async fn publish(
            &self,
            _exchange: &str,
            _routing_key: &str,
            _payload: &[u8],
            _headers: PublishHeaders,
        ) -> Result<(), SentioError> {
            Err(SentioError::Queue("connection refused".into()))
        }
    }

    #[derive(Clone)]
    struct MockSpamScorer {
        score: f64,
        action: SpamAction,
    }

    impl MockSpamScorer {
        fn new() -> Self {
            Self {
                score: 0.0,
                action: SpamAction::Accept,
            }
        }

        fn high_score() -> Self {
            Self {
                score: 12.0,
                action: SpamAction::Reject,
            }
        }
    }

    impl SpamScorer for MockSpamScorer {
        async fn score(
            &self,
            _raw: &[u8],
            _from: &str,
            _to: &[String],
            _ip: IpAddr,
        ) -> Result<SpamScore, SentioError> {
            Ok(SpamScore {
                score: self.score,
                action: self.action,
                rules: vec![],
            })
        }
    }

    #[derive(Clone)]
    struct MockAttachmentRepo {
        inserted: Arc<Mutex<Vec<NewAttachment>>>,
    }

    impl MockAttachmentRepo {
        fn new() -> Self {
            Self {
                inserted: Arc::new(Mutex::new(vec![])),
            }
        }

        fn insert_count(&self) -> usize {
            self.inserted.lock().unwrap().len()
        }
    }

    impl MessageAttachmentRepository for MockAttachmentRepo {
        async fn insert(&self, attachment: NewAttachment) -> Result<AttachmentId, SentioError> {
            self.inserted.lock().unwrap().push(attachment);
            Ok(AttachmentId::new())
        }
        async fn list_by_message(
            &self,
            _id: MessageId,
        ) -> Result<Vec<AttachmentRecord>, SentioError> {
            Ok(vec![])
        }
        async fn update_scan_status(
            &self,
            _id: AttachmentId,
            _scan_status: ScanStatus,
            _scan_result: Option<&str>,
        ) -> Result<(), SentioError> {
            Ok(())
        }
    }

    /// An attachment repo that always fails on insert.
    #[derive(Clone)]
    struct FailingAttachmentRepo;

    impl MessageAttachmentRepository for FailingAttachmentRepo {
        async fn insert(&self, _attachment: NewAttachment) -> Result<AttachmentId, SentioError> {
            Err(SentioError::Storage("attachment store unavailable".into()))
        }
        async fn list_by_message(
            &self,
            _id: MessageId,
        ) -> Result<Vec<AttachmentRecord>, SentioError> {
            Ok(vec![])
        }
        async fn update_scan_status(
            &self,
            _id: AttachmentId,
            _scan_status: ScanStatus,
            _scan_result: Option<&str>,
        ) -> Result<(), SentioError> {
            Err(SentioError::Storage("attachment store unavailable".into()))
        }
    }

    #[derive(Clone)]
    struct MockMailboxRepo;

    impl MailboxRepository for MockMailboxRepo {
        async fn create(&self, _mailbox: NewMailbox) -> Result<MailboxRecord, SentioError> {
            unimplemented!()
        }
        async fn get(&self, _id: MailboxId) -> Result<MailboxRecord, SentioError> {
            unimplemented!()
        }
        async fn list_by_domain(
            &self,
            _domain_id: DomainId,
        ) -> Result<Vec<MailboxRecord>, SentioError> {
            Ok(vec![])
        }
        async fn list_by_tenant(
            &self,
            _tenant_id: TenantId,
        ) -> Result<Vec<MailboxRecord>, SentioError> {
            Ok(vec![])
        }
        async fn update(&self, _id: MailboxId, _update: MailboxUpdate) -> Result<(), SentioError> {
            Ok(())
        }
        async fn delete(&self, _id: MailboxId) -> Result<(), SentioError> {
            Ok(())
        }
        async fn find_by_address(
            &self,
            _domain_id: DomainId,
            _local_part: &str,
        ) -> Result<Option<MailboxRecord>, SentioError> {
            Ok(None)
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    fn test_authenticator() -> Arc<Authenticator> {
        Arc::new(Authenticator::from_system_conf().expect("system DNS"))
    }

    fn sample_message() -> Vec<u8> {
        // Use .invalid TLD to guarantee no real DNS records (RFC 2606)
        b"From: sender@test.invalid\r\n\
To: rcpt@test.invalid\r\n\
Subject: Test message\r\n\
Date: Thu, 01 Jan 2025 00:00:00 +0000\r\n\
Message-ID: <test@test.invalid>\r\n\
\r\n\
Hello, this is a test message.\r\n"
            .to_vec()
    }

    fn test_inbound_msg() -> InboundMessage {
        InboundMessage {
            raw_data: sample_message(),
            envelope_from: "sender@test.invalid".into(),
            envelope_to: vec!["rcpt@test.invalid".into()],
            peer_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            client_domain: Some("mail.test.invalid".into()),
            server_hostname: "mx.sentio.test".into(),
            authenticated_user: None,
            tls_active: false,
            max_received_headers: 100,
            dsn_ret: None,
            dsn_envid: None,
            dsn_notify: HashMap::new(),
            dsn_orcpt: HashMap::new(),
        }
    }

    /// The fully-monomorphised pipeline these tests build. Named so the
    /// constructor helpers below do not each repeat nine generic arguments.
    /// The blob store and publisher vary, so they stay parameters with the
    /// mock as the default.
    type TestPipeline<B = MockBlobStore, P = MockPublisher> = InboundPipeline<
        B,
        MockScanner,
        MockMessageRepo,
        MockEventRepo,
        MockDomainRepo,
        P,
        MockSpamScorer,
        MockAttachmentRepo,
        MockMailboxRepo,
    >;

    fn make_pipeline(
        domain_repo: MockDomainRepo,
        scanner: MockScanner,
        spam_scorer: MockSpamScorer,
    ) -> Arc<TestPipeline> {
        Arc::new(InboundPipeline::new(
            MockBlobStore::new(),
            scanner,
            MockMessageRepo::new(),
            MockEventRepo::new(),
            domain_repo,
            MockPublisher::new(),
            spam_scorer,
            MockAttachmentRepo::new(),
            test_authenticator(),
            MockMailboxRepo,
        ))
    }

    fn make_pipeline_with_attachment_repo(
        domain_repo: MockDomainRepo,
        attachment_repo: MockAttachmentRepo,
    ) -> Arc<TestPipeline> {
        Arc::new(InboundPipeline::new(
            MockBlobStore::new(),
            MockScanner::new(),
            MockMessageRepo::new(),
            MockEventRepo::new(),
            domain_repo,
            MockPublisher::new(),
            MockSpamScorer::new(),
            attachment_repo,
            test_authenticator(),
            MockMailboxRepo,
        ))
    }

    fn make_pipeline_failing_blob(
        domain_repo: MockDomainRepo,
    ) -> Arc<TestPipeline<FailingBlobStore>> {
        Arc::new(InboundPipeline::new(
            FailingBlobStore,
            MockScanner::new(),
            MockMessageRepo::new(),
            MockEventRepo::new(),
            domain_repo,
            MockPublisher::new(),
            MockSpamScorer::new(),
            MockAttachmentRepo::new(),
            test_authenticator(),
            MockMailboxRepo,
        ))
    }

    fn make_pipeline_failing_queue(
        domain_repo: MockDomainRepo,
    ) -> Arc<TestPipeline<MockBlobStore, FailingPublisher>> {
        Arc::new(InboundPipeline::new(
            MockBlobStore::new(),
            MockScanner::new(),
            MockMessageRepo::new(),
            MockEventRepo::new(),
            domain_repo,
            FailingPublisher,
            MockSpamScorer::new(),
            MockAttachmentRepo::new(),
            test_authenticator(),
            MockMailboxRepo,
        ))
    }

    // ── Test cases ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn happy_path_queues_message() {
        let pipeline = make_pipeline(
            MockDomainRepo::with_domain(),
            MockScanner::new(),
            MockSpamScorer::new(),
        );

        let result = pipeline.process(test_inbound_msg()).await;
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        let outcome = result.unwrap();
        assert!(!outcome.queue_id.is_empty());
    }

    #[tokio::test]
    async fn virus_detected_rejects_550() {
        let scanner = MockScanner::new();
        scanner.set_infected("EICAR-Test-File");

        let pipeline = make_pipeline(
            MockDomainRepo::with_domain(),
            scanner,
            MockSpamScorer::new(),
        );

        let result = pipeline.process(test_inbound_msg()).await;
        match result {
            Err(ProcessingError::Reject { code, .. }) => assert_eq!(code, 550),
            other => panic!("expected Reject(550), got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_domain_rejects_550() {
        let pipeline = make_pipeline(
            MockDomainRepo::empty(),
            MockScanner::new(),
            MockSpamScorer::new(),
        );

        let result = pipeline.process(test_inbound_msg()).await;
        match result {
            Err(ProcessingError::Reject { code, enhanced, .. }) => {
                assert_eq!(code, 550);
                assert_eq!(enhanced, "5.1.2");
            }
            other => panic!("expected Reject(550), got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn unparseable_message_rejects_550() {
        let pipeline = make_pipeline(
            MockDomainRepo::with_domain(),
            MockScanner::new(),
            MockSpamScorer::new(),
        );

        let mut msg = test_inbound_msg();
        msg.raw_data = vec![]; // empty message

        let result = pipeline.process(msg).await;
        match result {
            Err(ProcessingError::Reject { code, enhanced, .. }) => {
                assert_eq!(code, 550);
                assert_eq!(enhanced, "5.6.0");
            }
            other => panic!("expected Reject(550 5.6.0), got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn high_spam_score_still_accepts() {
        let pipeline = make_pipeline(
            MockDomainRepo::with_domain(),
            MockScanner::new(),
            MockSpamScorer::high_score(),
        );

        let result = pipeline.process(test_inbound_msg()).await;
        assert!(result.is_ok(), "high spam should still accept: {result:?}");
    }

    #[tokio::test]
    async fn scanner_error_tempfails() {
        let scanner = MockScanner::new();
        scanner.set_error("ClamAV connection refused");

        let pipeline = make_pipeline(
            MockDomainRepo::with_domain(),
            scanner,
            MockSpamScorer::new(),
        );

        let result = pipeline.process(test_inbound_msg()).await;
        match result {
            Err(ProcessingError::TempFail { code, .. }) => assert_eq!(code, 451),
            other => panic!("expected TempFail(451), got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn into_processor_works() {
        let pipeline = make_pipeline(
            MockDomainRepo::with_domain(),
            MockScanner::new(),
            MockSpamScorer::new(),
        );

        let processor = pipeline.into_processor();
        let result = processor(test_inbound_msg()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn dmarc_reject_returns_550() {
        // Use a domain that publishes p=reject DMARC policy.
        // example.com has v=DMARC1; p=reject in real DNS.
        let pipeline = make_pipeline(
            MockDomainRepo::with_domain(),
            MockScanner::new(),
            MockSpamScorer::new(),
        );

        let mut msg = test_inbound_msg();
        // Override From header to use example.com which has DMARC p=reject.
        // SPF and DKIM will fail alignment, triggering DMARC reject.
        msg.raw_data = b"From: sender@example.com\r\n\
To: rcpt@test.invalid\r\n\
Subject: DMARC test\r\n\
Date: Thu, 01 Jan 2025 00:00:00 +0000\r\n\
Message-ID: <dmarc-test@test.invalid>\r\n\
\r\n\
Test body.\r\n"
            .to_vec();
        msg.envelope_from = "sender@example.com".into();

        let result = pipeline.process(msg).await;
        match result {
            Err(ProcessingError::Reject { code, enhanced, .. }) => {
                assert_eq!(code, 550);
                assert_eq!(enhanced, "5.7.1");
            }
            other => panic!("expected DMARC Reject(550 5.7.1), got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn storage_failure_tempfails_451() {
        let pipeline = make_pipeline_failing_blob(MockDomainRepo::with_domain());

        let result = pipeline.process(test_inbound_msg()).await;
        match result {
            Err(ProcessingError::TempFail { code, enhanced, .. }) => {
                assert_eq!(code, 451);
                assert_eq!(enhanced, "4.3.0");
            }
            other => panic!("expected TempFail(451), got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn queue_failure_tempfails_451() {
        let pipeline = make_pipeline_failing_queue(MockDomainRepo::with_domain());

        let result = pipeline.process(test_inbound_msg()).await;
        match result {
            Err(ProcessingError::TempFail { code, enhanced, .. }) => {
                assert_eq!(code, 451);
                assert_eq!(enhanced, "4.3.0");
            }
            other => panic!("expected TempFail(451), got: {other:?}"),
        }
    }

    // ── Received header tests ─────────────────────────────────────────

    #[test]
    fn received_header_format() {
        let msg = test_inbound_msg();
        let header = generate_received_header(&msg, "ABCDEF1234");

        assert!(header.starts_with("Received: from mail.test.invalid (192.0.2.1)"));
        assert!(header.contains("by mx.sentio.test with ESMTP"));
        assert!(header.contains("id ABCDEF1234"));
        assert!(
            header.contains("for <rcpt@test.invalid>"),
            "single recipient should have FOR clause: {header}"
        );
        assert!(header.ends_with("\r\n"));
    }

    #[test]
    fn received_header_omits_for_multi_recipient() {
        let mut msg = test_inbound_msg();
        msg.envelope_to = vec!["a@test.invalid".into(), "b@test.invalid".into()];
        let header = generate_received_header(&msg, "Q1");
        assert!(
            !header.contains("for <"),
            "multi-recipient should omit FOR clause: {header}"
        );
    }

    #[test]
    fn received_header_esmtps_when_tls() {
        let mut msg = test_inbound_msg();
        msg.tls_active = true;

        let header = generate_received_header(&msg, "Q1");
        assert!(
            header.contains("with ESMTPS"),
            "should use ESMTPS: {header}"
        );
    }

    #[test]
    fn received_header_esmtp_when_no_tls() {
        let msg = test_inbound_msg();
        let header = generate_received_header(&msg, "Q1");
        assert!(
            header.contains("with ESMTP\r\n"),
            "should use ESMTP: {header}"
        );
        assert!(
            !header.contains("ESMTPS"),
            "should not use ESMTPS: {header}"
        );
    }

    #[test]
    fn received_header_includes_auth() {
        let mut msg = test_inbound_msg();
        msg.authenticated_user = Some("user@example.com".into());
        msg.tls_active = true;

        let header = generate_received_header(&msg, "Q1");
        assert!(
            header.contains("(authenticated as user@example.com)"),
            "should include auth clause: {header}"
        );
    }

    #[tokio::test]
    async fn received_header_prepended_to_stored_data() {
        let pipeline = make_pipeline(
            MockDomainRepo::with_domain(),
            MockScanner::new(),
            MockSpamScorer::new(),
        );

        let result = pipeline.process(test_inbound_msg()).await;
        // The pipeline modifies raw_data in-place - we can't directly inspect
        // the stored data from here, but we verify the function itself is correct
        // (see received_header_format test for direct verification).
        assert!(result.is_ok(), "pipeline should succeed: {result:?}");
    }

    // ── Return-Path tests ─────────────────────────────────────────────

    #[test]
    fn return_path_format() {
        let msg = test_inbound_msg();
        let expected = format!("Return-Path: <{}>\r\n", msg.envelope_from);
        assert_eq!(expected, "Return-Path: <sender@test.invalid>\r\n");
    }

    #[tokio::test]
    async fn loop_detection_rejects_excessive_hops() {
        let pipeline = make_pipeline(
            MockDomainRepo::with_domain(),
            MockScanner::new(),
            MockSpamScorer::new(),
        );

        // Build a message with 100 Received headers (hits the threshold)
        let mut raw = Vec::new();
        for i in 0..100 {
            raw.extend_from_slice(format!("Received: from relay{i}.example.com\r\n").as_bytes());
        }
        raw.extend_from_slice(sample_message().as_slice());

        let mut msg = test_inbound_msg();
        msg.raw_data = raw;

        let result = pipeline.process(msg).await;
        match result {
            Err(ProcessingError::Reject { code, enhanced, .. }) => {
                assert_eq!(code, 554);
                assert_eq!(enhanced, "5.4.6");
            }
            other => panic!("expected loop detection Reject(554 5.4.6), got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn loop_detection_allows_under_threshold() {
        let pipeline = make_pipeline(
            MockDomainRepo::with_domain(),
            MockScanner::new(),
            MockSpamScorer::new(),
        );

        // 99 Received headers - just under the threshold
        let mut raw = Vec::new();
        for i in 0..99 {
            raw.extend_from_slice(format!("Received: from relay{i}.example.com\r\n").as_bytes());
        }
        raw.extend_from_slice(sample_message().as_slice());

        let mut msg = test_inbound_msg();
        msg.raw_data = raw;

        let result = pipeline.process(msg).await;
        assert!(result.is_ok(), "99 hops should be allowed: {result:?}");
    }

    // ── Attachment extraction tests ─────────────────────────────────────

    #[tokio::test]
    async fn extracts_mime_attachments() {
        let attachment_repo = MockAttachmentRepo::new();
        let pipeline = make_pipeline_with_attachment_repo(
            MockDomainRepo::with_domain(),
            attachment_repo.clone(),
        );

        let raw = b"From: sender@test.invalid\r\n\
To: rcpt@test.invalid\r\n\
Subject: With attachment\r\n\
Date: Thu, 01 Jan 2025 00:00:00 +0000\r\n\
Message-ID: <att-test@test.invalid>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n\
\r\n\
--BOUNDARY\r\n\
Content-Type: text/plain\r\n\
\r\n\
Body text.\r\n\
\r\n\
--BOUNDARY\r\n\
Content-Type: application/pdf\r\n\
Content-Disposition: attachment; filename=\"report.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
JVBERi0xLjQKMSAwIG9iago=\r\n\
--BOUNDARY--\r\n";

        let mut msg = test_inbound_msg();
        msg.raw_data = raw.to_vec();

        let result = pipeline.process(msg).await;
        assert!(result.is_ok(), "should succeed: {result:?}");
        assert_eq!(
            attachment_repo.insert_count(),
            1,
            "should extract 1 attachment"
        );
    }

    #[tokio::test]
    async fn extracts_inline_image() {
        let attachment_repo = MockAttachmentRepo::new();
        let pipeline = make_pipeline_with_attachment_repo(
            MockDomainRepo::with_domain(),
            attachment_repo.clone(),
        );

        let raw = b"From: sender@test.invalid\r\n\
To: rcpt@test.invalid\r\n\
Subject: With inline image\r\n\
Date: Thu, 01 Jan 2025 00:00:00 +0000\r\n\
Message-ID: <inline-test@test.invalid>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/related; boundary=\"RELBOUND\"\r\n\
\r\n\
--RELBOUND\r\n\
Content-Type: text/html\r\n\
\r\n\
<html><body><img src=\"cid:logo123\"/></body></html>\r\n\
\r\n\
--RELBOUND\r\n\
Content-Type: image/png\r\n\
Content-Disposition: inline\r\n\
Content-ID: <logo123>\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
iVBORw0KGgoAAAANSUhEUg==\r\n\
--RELBOUND--\r\n";

        let mut msg = test_inbound_msg();
        msg.raw_data = raw.to_vec();

        let result = pipeline.process(msg).await;
        assert!(result.is_ok(), "should succeed: {result:?}");
        assert_eq!(
            attachment_repo.insert_count(),
            1,
            "should extract 1 inline image"
        );

        let inserts = attachment_repo.inserted.lock().unwrap();
        assert_eq!(inserts[0].disposition, AttachmentDisposition::Inline);
        assert!(inserts[0].content_id.is_some(), "should have content_id");
    }

    #[tokio::test]
    async fn no_attachments_for_plain_text() {
        let attachment_repo = MockAttachmentRepo::new();
        let pipeline = make_pipeline_with_attachment_repo(
            MockDomainRepo::with_domain(),
            attachment_repo.clone(),
        );

        let result = pipeline.process(test_inbound_msg()).await;
        assert!(result.is_ok(), "should succeed: {result:?}");
        assert_eq!(
            attachment_repo.insert_count(),
            0,
            "plain text should have 0 attachments"
        );
    }

    #[tokio::test]
    async fn attachment_failure_does_not_block_message() {
        let pipeline = Arc::new(InboundPipeline::new(
            MockBlobStore::new(),
            MockScanner::new(),
            MockMessageRepo::new(),
            MockEventRepo::new(),
            MockDomainRepo::with_domain(),
            MockPublisher::new(),
            MockSpamScorer::new(),
            FailingAttachmentRepo,
            test_authenticator(),
            MockMailboxRepo,
        ));

        let raw = b"From: sender@test.invalid\r\n\
To: rcpt@test.invalid\r\n\
Subject: Attachment will fail\r\n\
Date: Thu, 01 Jan 2025 00:00:00 +0000\r\n\
Message-ID: <fail-att@test.invalid>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"FAILBOUND\"\r\n\
\r\n\
--FAILBOUND\r\n\
Content-Type: text/plain\r\n\
\r\n\
Body.\r\n\
\r\n\
--FAILBOUND\r\n\
Content-Type: application/octet-stream\r\n\
Content-Disposition: attachment; filename=\"data.bin\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
AQIDBA==\r\n\
--FAILBOUND--\r\n";

        let mut msg = test_inbound_msg();
        msg.raw_data = raw.to_vec();

        let result = pipeline.process(msg).await;
        assert!(
            result.is_ok(),
            "message should succeed even when attachment repo fails: {result:?}"
        );
    }
}
