use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::Json;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use sentio_core::auth::DomainStatus;
use sentio_core::event::{BounceClass, EventType};
use sentio_core::ids::MessageEventId;
use sentio_core::message::DomainId;
use sentio_core::message::{AttachmentDisposition, MessageDirection, MessageId, MessageStatus};
use sentio_core::tenant::TenantId;
use sentio_core::traits::DomainRepository;
use sentio_core::traits::{
    BlobStore, MessageAttachmentRepository, MessageEventRecord, MessageEventRepository,
    MessageFilter, MessageRecord, MessageRepository, NewAttachment, NewMessage,
    SuppressionRepository,
};
use sentio_queue::{PublishHeaders, QueuePublisher, EXCHANGE_SUBMIT};
use sentio_store::postgres::{
    PgDomainRepository, PgMessageAttachmentRepository, PgMessageEventRepository,
    PgMessageRepository, PgSuppressionRepository,
};

use crate::auth::AuthContext;
use crate::errors::{ApiError, ErrorResponse};
use crate::extract::ListMessagesParams;
use crate::response::{data, DataResponse};
use crate::state::AppState;

// ──────────────────────────────────────────────────────────────────────────────
// Request / Response types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
pub struct AttachmentInput {
    pub filename: String,
    pub content_type: String,
    /// Base64-encoded binary content.
    pub data: String,
    /// Content-ID for inline attachments (e.g. `<img001>`).
    pub content_id: Option<String>,
    /// "attachment" (default) or "inline".
    #[serde(default = "default_disposition")]
    pub disposition: String,
}

fn default_disposition() -> String {
    "attachment".to_string()
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct SendMessageRequest {
    pub from: String,
    pub to: Vec<String>,
    #[serde(default)]
    pub cc: Vec<String>,
    #[serde(default)]
    pub bcc: Vec<String>,
    pub reply_to: Option<String>,
    pub subject: Option<String>,
    pub html: Option<String>,
    pub text: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[schema(value_type = Object)]
    pub metadata: Option<serde_json::Value>,
    pub send_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub attachments: Vec<AttachmentInput>,
    #[serde(default)]
    pub track_opens: bool,
    #[serde(default)]
    pub track_clicks: bool,
    /// RFC 5322 In-Reply-To - Message-ID this reply is responding to.
    /// Bare value or angle-bracketed; either way the builder normalises.
    /// Required for the reply to thread correctly in mail clients
    /// (Gmail, Apple Mail, Outlook all key threads off In-Reply-To).
    #[serde(default)]
    pub in_reply_to: Option<String>,
    /// RFC 5322 References - full chain of ancestor Message-IDs ordered
    /// oldest → newest. Standard reply-construction algorithm: take
    /// parent's References + append parent's Message-ID.
    #[serde(default)]
    pub references: Vec<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct SendRawRequest {
    pub from: String,
    pub to: Vec<String>,
    pub raw_eml: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SendResponse {
    id: MessageId,
    status: String,
    /// The RFC 5322 Message-ID stamped on the outbound message (bare
    /// `id@host`, no angle brackets). Lets the sender thread inbound
    /// replies against this id. Omitted when unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    message_id_header: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct MessageResponse {
    id: MessageId,
    direction: MessageDirection,
    envelope_from: String,
    envelope_to: Vec<String>,
    header_from: Option<String>,
    header_to: Vec<String>,
    header_cc: Vec<String>,
    header_reply_to: Option<String>,
    subject: Option<String>,
    message_id_header: Option<String>,
    status: MessageStatus,
    tags: Vec<String>,
    #[schema(value_type = Object)]
    metadata: serde_json::Value,
    message_size: Option<i64>,
    spam_score: Option<f64>,
    spam_action: Option<String>,
    send_at: Option<DateTime<Utc>>,
    llm_category: Option<String>,
    llm_summary: Option<String>,
    llm_classified_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    delivered_at: Option<DateTime<Utc>>,
    bounced_at: Option<DateTime<Utc>>,
}

impl From<MessageRecord> for MessageResponse {
    fn from(r: MessageRecord) -> Self {
        Self {
            id: r.id,
            direction: r.direction,
            envelope_from: r.envelope_from,
            envelope_to: r.envelope_to,
            header_from: r.header_from,
            header_to: r.header_to,
            header_cc: r.header_cc,
            header_reply_to: r.header_reply_to,
            subject: r.subject,
            message_id_header: r.message_id_header,
            status: r.status,
            tags: r.tags,
            metadata: r.metadata,
            message_size: r.message_size,
            spam_score: r.spam_score,
            spam_action: r.spam_action,
            send_at: r.send_at,
            llm_category: r.llm_category,
            llm_summary: r.llm_summary,
            llm_classified_at: r.llm_classified_at,
            created_at: r.created_at,
            delivered_at: r.delivered_at,
            bounced_at: r.bounced_at,
        }
    }
}

#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct EventResponse {
    id: MessageEventId,
    message_id: MessageId,
    event_type: EventType,
    smtp_response: Option<String>,
    remote_mta: Option<String>,
    diagnostic_code: Option<String>,
    bounce_class: Option<BounceClass>,
    retry_count: Option<i32>,
    next_retry_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl From<MessageEventRecord> for EventResponse {
    fn from(r: MessageEventRecord) -> Self {
        Self {
            id: r.id,
            message_id: r.message_id,
            event_type: r.event_type,
            smtp_response: r.smtp_response,
            remote_mta: r.remote_mta,
            diagnostic_code: r.diagnostic_code,
            bounce_class: r.bounce_class,
            retry_count: r.retry_count,
            next_retry_at: r.next_retry_at,
            created_at: r.created_at,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Queue payload - matches OutboundMessage in sentio-smtp-client
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct OutboundPayload {
    message_id: String,
    tenant_id: String,
    domain_id: Option<String>,
    envelope_from: String,
    envelope_to: Vec<String>,
    raw_eml_key: String,
    #[serde(default)]
    is_forward: bool,
    #[serde(default)]
    auth_results: Option<String>,
    #[serde(default)]
    track_opens: bool,
    #[serde(default)]
    track_clicks: bool,
}

// ──────────────────────────────────────────────────────────────────────────────
// EML builder - constructs a minimal RFC 5322 message from structured fields
// ──────────────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn build_eml(
    from: &str,
    to: &[String],
    cc: &[String],
    reply_to: Option<&str>,
    subject: Option<&str>,
    text: Option<&str>,
    html: Option<&str>,
    attachments: &[DecodedAttachment],
    hostname: &str,
    in_reply_to: Option<&str>,
    references: &[String],
) -> (Vec<u8>, String) {
    use mail_builder::headers::content_type::ContentType;
    use mail_builder::headers::message_id::MessageId;
    use mail_builder::mime::{BodyPart, MimePart};
    use mail_builder::MessageBuilder;

    let mut builder = MessageBuilder::new();
    // Explicit Message-ID so the right-hand side is our SMTP hostname,
    // not whatever `gethostname()` returns on the box. Without this,
    // mail-builder defaults to the OS hostname (e.g.
    // "Ubuntu-2404-noble-amd64-base") which leaks the deploy host name
    // into every outbound message and looks unprofessional in receivers'
    // headers.
    let message_id = format!("{}@{}", uuid::Uuid::new_v4().simple(), hostname);
    builder = builder.message_id(message_id.clone());
    // Parse mailbox-form (`"Display" <addr>`) into typed (name, addr)
    // so mail-builder emits the header correctly + RFC 2047-encodes any
    // non-ASCII display name. Passing the raw string to `.from()` makes
    // it treat the entire thing as a bare address and double-wrap it
    // in `<…>`, producing syntactically broken headers like
    // `From: <"Max" <addr>>` that downstream MTAs (Gmail in particular)
    // reject with `555 5.5.2 Syntax error`.
    builder = builder.from(parse_mailbox(from));
    // RFC 5322 §3.6.3: exactly one `To:` header per message. mail-builder's
    // `.to()` calls `.header("To", ...)` which *appends* a new header on
    // every invocation - so we must collect all recipients into a single
    // `Address::List` and pass it in one call. Calling `.to()` in a loop
    // produces multiple `To:` headers, which Gmail rejects with
    // `550 5.7.1 ... multiple To headers`. Same shape for `Cc:`.
    use mail_builder::headers::address::Address;
    if !to.is_empty() {
        let to_list: Vec<Address<'_>> =
            to.iter().map(|addr| parse_mailbox(addr.as_str())).collect();
        builder = builder.to(Address::new_list(to_list));
    }
    if !cc.is_empty() {
        let cc_list: Vec<Address<'_>> =
            cc.iter().map(|addr| parse_mailbox(addr.as_str())).collect();
        builder = builder.cc(Address::new_list(cc_list));
    }
    if let Some(rt) = reply_to {
        builder = builder.reply_to(parse_mailbox(rt));
    }
    if let Some(subj) = subject {
        builder = builder.subject(subj);
    }

    // Threading headers - strip surrounding angle brackets so we don't
    // double-wrap when mail_builder emits the header. mail_builder's
    // MessageId Display impl adds the brackets back.
    if let Some(irt) = in_reply_to
        .map(strip_msgid_brackets)
        .filter(|s| !s.is_empty())
    {
        builder = builder.in_reply_to(MessageId::new(irt.to_string()));
    }
    if !references.is_empty() {
        let cleaned: Vec<String> = references
            .iter()
            .map(|s| strip_msgid_brackets(s).to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !cleaned.is_empty() {
            builder = builder.references(MessageId::new_list(cleaned.into_iter()));
        }
    }

    match (text, html) {
        (Some(t), Some(h)) => {
            builder = builder.text_body(t);
            builder = builder.html_body(h);
        }
        (Some(t), None) => {
            builder = builder.text_body(t);
        }
        (None, Some(h)) => {
            builder = builder.html_body(h);
        }
        (None, None) => {
            builder = builder.text_body("");
        }
    }

    // Build attachment MimeParts directly so inline parts get BOTH a
    // filename= parameter AND the agent-supplied Content-ID. The
    // high-level MessageBuilder::inline(ct, cid, val) sugar would
    // (a) set no filename on the part - recipients see "noname" when
    //     they try to download/save the image, and
    // (b) treat its second arg as the cid, so passing the filename
    //     there clobbers the agent's `cid:` reference in the html body.
    // Setting headers explicitly keeps both semantics correct.
    for att in attachments {
        let mut part = MimePart::new(
            att.content_type.as_str(),
            BodyPart::Binary(att.data.as_slice().into()),
        );
        if att.disposition == "inline" {
            part = part.header(
                "Content-Disposition",
                ContentType::new("inline").attribute("filename", att.filename.as_str()),
            );
            let cid = att
                .content_id
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or(att.filename.as_str());
            part = part.cid(cid.to_string());
        } else {
            part = part.attachment(att.filename.as_str());
            if let Some(cid) = att.content_id.as_deref().filter(|s| !s.is_empty()) {
                part = part.cid(cid.to_string());
            }
        }
        builder.attachments.get_or_insert_with(Vec::new).push(part);
    }

    // Return the bare `id@host` (no angle brackets) so it matches what
    // mail_parser extracts on the inbound side - callers persist it as
    // `message_id_header` and surface it in the send response so the
    // sender can later thread inbound replies against it.
    (builder.write_to_vec().unwrap_or_default(), message_id)
}

/// Trim `<…>` wrapping off a Message-ID. RFC 5322 message-ids appear
/// angle-bracketed everywhere in the wire format, but the structured
/// constructors expect the bare id. Defensive: a caller might pass
/// either form.
fn strip_msgid_brackets(s: &str) -> &str {
    s.trim().trim_start_matches('<').trim_end_matches('>')
}

/// Parse an RFC 5322 mailbox into a typed mail-builder Address.
/// Validate a single email-address field at the API boundary. Catches:
///
/// - empty / whitespace-only input
/// - control characters (`\r`, `\n`, `\0`) - header-injection vector
/// - addr-spec without a single `@` or with empty local-part / domain
///
/// Returns `ApiError::Validation` (HTTP 422) with `{field}: {reason}`
/// so the caller sees the problem at request time rather than hours
/// later in a DMARC report / dead-letter row. Display-name + brackets
/// are unwrapped via `extract_addr_spec` before the per-character
/// checks, so `"Alice" <alice@example.com>` validates fine.
fn validate_email_field(field: &str, input: &str) -> Result<(), ApiError> {
    // Header injection check runs on the raw input - a CRLF inside a
    // quoted display name is still a CRLF on the wire and would let an
    // attacker inject extra headers.
    if input.chars().any(|c| c == '\r' || c == '\n' || c == '\0') {
        return Err(ApiError::Validation(format!(
            "{field}: contains forbidden control characters (CR/LF/NUL)"
        )));
    }
    let addr = extract_addr_spec(input);
    if addr.is_empty() {
        return Err(ApiError::Validation(format!("{field}: address is empty")));
    }
    // Whitespace inside the addr-spec is RFC-illegal (unless quoted,
    // which extract_addr_spec doesn't unwrap - but those should be rare).
    if addr.chars().any(|c| c.is_whitespace()) {
        return Err(ApiError::Validation(format!(
            "{field}: '{input}' contains whitespace inside the addr-spec"
        )));
    }
    // Must have exactly one '@' splitting non-empty local and domain.
    let mut parts = addr.splitn(2, '@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return Err(ApiError::Validation(format!(
            "{field}: '{input}' is not a valid email address"
        )));
    }
    Ok(())
}

/// Validate a list of email-address fields (e.g. `to`, `cc`, `bcc`).
/// Empty lists are allowed (the field-level required-or-not check
/// happens elsewhere); each present entry must validate.
fn validate_email_list(field: &str, inputs: &[String]) -> Result<(), ApiError> {
    for (i, input) in inputs.iter().enumerate() {
        validate_email_field(&format!("{field}[{i}]"), input)?;
    }
    Ok(())
}

/// Strip any RFC 5322 mailbox-form wrapping and return just the
/// addr-spec. Accepts:
///   `"Alice" <alice@example.com>`  →  `alice@example.com`
///   `<alice@example.com>`          →  `alice@example.com`
///   `alice@example.com`            →  `alice@example.com`
///
/// SMTP `MAIL FROM` and `RCPT TO` commands take only the addr-spec,
/// never the full mailbox. Passing a display-name form on the wire
/// produces `555 5.5.2 Syntax error` from strict receivers (Gmail) -
/// e.g. an API caller passing `"Alex · Team" <alex@example.com>` as the
/// `from` field. This helper is the canonical way to derive
/// envelope_from / envelope_to values from whatever the API caller wrote.
fn extract_addr_spec(input: &str) -> String {
    let trimmed = input.trim();
    if let Some(open) = trimmed.rfind('<') {
        let after = &trimmed[open + 1..];
        if let Some(close) = after.rfind('>') {
            let addr = after[..close].trim();
            if !addr.is_empty() {
                return addr.to_string();
            }
        }
    }
    trimmed.to_string()
}

/// Accepts either a bare address (`alice@example.com`) or the mailbox
/// form with display name (`"Alice" <alice@example.com>`). Returns a
/// `(name, email)` tuple address when a display name is present;
/// mail-builder serialises the result with proper quoting + RFC 2047
/// Q-encoding for any non-ASCII chars in the name.
fn parse_mailbox(input: &str) -> mail_builder::headers::address::Address<'_> {
    use mail_builder::headers::address::Address;
    let trimmed = input.trim();
    if let Some(open) = trimmed.rfind('<') {
        let after = &trimmed[open + 1..];
        let close = after.rfind('>').unwrap_or(after.len());
        let email = after[..close].trim();
        // Display-name portion: everything before the last `<`, with
        // surrounding quotes + whitespace stripped. mail-builder will
        // re-quote and encode as needed when emitting.
        let name = trimmed[..open].trim().trim_matches('"').trim().to_string();
        if !email.is_empty() {
            if name.is_empty() {
                return Address::new_address(None::<String>, email.to_string());
            }
            return Address::new_address(Some(name), email.to_string());
        }
    }
    Address::new_address(None::<String>, trimmed.to_string())
}

/// A pre-decoded attachment ready for EML building and blob upload.
struct DecodedAttachment {
    filename: String,
    content_type: String,
    data: Vec<u8>,
    content_id: Option<String>,
    disposition: String,
    checksum_sha256: String,
}

fn decode_attachments(inputs: &[AttachmentInput]) -> Result<Vec<DecodedAttachment>, ApiError> {
    use sha2::{Digest, Sha256};

    let mut decoded = Vec::with_capacity(inputs.len());
    for input in inputs {
        let data = base64::engine::general_purpose::STANDARD
            .decode(&input.data)
            .map_err(|e| {
                ApiError::Validation(format!(
                    "invalid base64 in attachment '{}': {e}",
                    input.filename
                ))
            })?;

        let digest = Sha256::digest(&data);
        let hash = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        decoded.push(DecodedAttachment {
            filename: input.filename.clone(),
            content_type: input.content_type.clone(),
            data,
            content_id: input.content_id.clone(),
            disposition: input.disposition.clone(),
            checksum_sha256: hash,
        });
    }
    Ok(decoded)
}

async fn upload_attachments<B: BlobStore>(
    blob_store: &B,
    attachment_repo: &PgMessageAttachmentRepository,
    message_id: MessageId,
    tenant_id: sentio_core::tenant::TenantId,
    attachments: &[DecodedAttachment],
) -> Result<(), ApiError> {
    for att in attachments {
        let assigned = blob_store.assign().await?;
        blob_store
            .upload(
                &assigned.fid,
                bytes::Bytes::copy_from_slice(&att.data),
                &att.filename,
                &att.content_type,
            )
            .await?;

        let disposition = if att.disposition == "inline" {
            AttachmentDisposition::Inline
        } else {
            AttachmentDisposition::Attachment
        };

        let new_att = NewAttachment {
            message_id,
            tenant_id,
            filename: att.filename.clone(),
            content_type: att.content_type.clone(),
            size: att.data.len() as i64,
            content_id: att.content_id.clone(),
            disposition,
            blob_key: assigned.fid,
            checksum_sha256: Some(att.checksum_sha256.clone()),
        };
        attachment_repo.insert(new_att).await?;
    }
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Sender domain validation
// ──────────────────────────────────────────────────────────────────────────────

async fn validate_sender_domain(
    pool: &sqlx::PgPool,
    tenant_id: TenantId,
    from: &str,
) -> Result<DomainId, ApiError> {
    let domain = parse_from_domain(from)
        .ok_or_else(|| ApiError::Validation("invalid from address: missing @".into()))?;

    let repo = PgDomainRepository::new(pool.clone());
    let record = repo.get_by_name(tenant_id, &domain).await.map_err(|_| {
        ApiError::Validation(format!(
            "sender domain '{domain}' not found for this tenant"
        ))
    })?;

    if record.status != DomainStatus::Verified {
        return Err(ApiError::Validation(format!(
            "sender domain '{domain}' is not verified"
        )));
    }
    if !record.use_for_sending {
        return Err(ApiError::Validation(format!(
            "domain '{domain}' is not enabled for sending"
        )));
    }
    Ok(record.id)
}

/// Extract the sending domain from a `from` field that may be either a
/// bare address (`alice@example.com`) or RFC 5322 mailbox form
/// (`"Alice" <alice@example.com>`). The naive `rsplit_once('@')`
/// returns `example.com>` for the bracketed form, which then fails
/// domain lookup with a confusing trailing `>`. This handles both.
fn parse_from_domain(from: &str) -> Option<String> {
    let trimmed = from.trim();
    // Mailbox form: extract between the LAST '<' and matching '>'.
    let addr = if let Some(open) = trimmed.rfind('<') {
        let after = &trimmed[open + 1..];
        let close = after.rfind('>').unwrap_or(after.len());
        &after[..close]
    } else {
        trimmed
    };
    let (_, domain) = addr.rsplit_once('@')?;
    let domain = domain.trim().trim_end_matches('>').trim();
    if domain.is_empty() {
        None
    } else {
        Some(domain.to_string())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/messages/send
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/messages/send",
    tag = "Messages",
    security(("bearer" = [])),
    request_body = SendMessageRequest,
    responses(
        (status = 200, body = DataResponse<SendResponse>),
        (status = 422, body = ErrorResponse),
    ),
)]
pub async fn send_message(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(body): Json<SendMessageRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("messages:send")?;

    // Validate
    if body.from.is_empty() {
        return Err(ApiError::Validation("from address is required".into()));
    }
    if body.to.is_empty() {
        return Err(ApiError::Validation(
            "at least one recipient is required".into(),
        ));
    }

    // Validate every address field at the API boundary so bad input
    // fails fast with a 422 instead of getting queued, dispatched
    // hours later, and bouncing into the audit trail.
    validate_email_field("from", &body.from)?;
    validate_email_list("to", &body.to)?;
    validate_email_list("cc", &body.cc)?;
    validate_email_list("bcc", &body.bcc)?;
    if let Some(rt) = body.reply_to.as_deref() {
        validate_email_field("reply_to", rt)?;
    }

    // Validate sender domain ownership
    let domain_id = validate_sender_domain(&state.pool, auth.tenant_id, &body.from).await?;

    // Build combined recipient list for envelope. extract_addr_spec on
    // ALL three lists - cc and bcc would otherwise leak display-name
    // forms into SMTP RCPT TO and Gmail-5.5.2 us.
    let mut envelope_to: Vec<String> = body.to.iter().map(|s| extract_addr_spec(s)).collect();
    envelope_to.extend(body.cc.iter().map(|s| extract_addr_spec(s)));
    envelope_to.extend(body.bcc.iter().map(|s| extract_addr_spec(s)));

    // Check suppression list for each recipient
    let suppression_repo = PgSuppressionRepository::new(state.pool.clone());
    let mut active_recipients = Vec::new();
    for rcpt in &envelope_to {
        let suppressed = suppression_repo.check(auth.tenant_id, rcpt).await?;
        if !suppressed {
            active_recipients.push(rcpt.clone());
        }
    }
    if active_recipients.is_empty() {
        return Err(ApiError::Validation("all recipients are suppressed".into()));
    }

    // Determine initial status
    let status_label = if body.send_at.is_some_and(|t| t > Utc::now()) {
        "scheduled"
    } else {
        "queued"
    };

    // Allocate message ID early - needed for tracking token generation
    let id = MessageId::new();

    // Decode attachments upfront (validates base64)
    let decoded_attachments = decode_attachments(&body.attachments)?;

    // Apply tracking rewrite to HTML body before MIME assembly (and DKIM signing)
    let html_body = if (body.track_opens || body.track_clicks) && body.html.is_some() {
        let rewritten = sentio_smtp_client::tracking::rewrite_html_tracking(
            body.html.as_deref().unwrap(),
            &state.config.server.api_base_url,
            &id.0.to_string(),
            &auth.tenant_id.0.to_string(),
            body.track_opens,
            body.track_clicks,
        );
        Some(rewritten)
    } else {
        body.html.clone()
    };

    // Build EML from structured fields (including attachments)
    let (raw_eml, message_id_header) = build_eml(
        &body.from,
        &body.to,
        &body.cc,
        body.reply_to.as_deref(),
        body.subject.as_deref(),
        body.text.as_deref(),
        html_body.as_deref(),
        &decoded_attachments,
        &state.config.server.hostname,
        body.in_reply_to.as_deref(),
        &body.references,
    );

    // Upload raw EML to blob store
    let assigned = state.blob_store.assign().await?;
    let upload_result = state
        .blob_store
        .upload(
            &assigned.fid,
            bytes::Bytes::from(raw_eml),
            "message.eml",
            "message/rfc822",
        )
        .await?;

    // Insert message record
    let msg_repo = PgMessageRepository::new(state.pool.clone());
    let new_msg = NewMessage {
        id,
        tenant_id: auth.tenant_id,
        domain_id: Some(domain_id),
        direction: MessageDirection::Outbound,
        envelope_from: extract_addr_spec(&body.from),
        envelope_to: active_recipients.clone(),
        header_from: Some(body.from.clone()),
        header_to: body.to,
        header_cc: body.cc,
        header_reply_to: body.reply_to,
        subject: body.subject,
        message_id_header: Some(message_id_header.clone()),
        tags: body.tags,
        metadata: body.metadata,
        message_size: Some(upload_result.size as i64),
        raw_eml_key: Some(upload_result.fid.clone()),
        spam_score: None,
        spam_action: None,
        send_at: body.send_at,
        dsn_ret: None,
        dsn_envid: None,
        dsn_notify: serde_json::json!({}),
        dsn_orcpt: serde_json::json!({}),
    };
    msg_repo.insert(new_msg).await?;

    // Upload individual attachments to blob store and record in DB
    if !decoded_attachments.is_empty() {
        let att_repo = PgMessageAttachmentRepository::new(state.pool.clone());
        upload_attachments(
            state.blob_store.as_ref(),
            &att_repo,
            id,
            auth.tenant_id,
            &decoded_attachments,
        )
        .await?;
    }

    // Update status to scheduled if send_at is in the future
    if status_label == "scheduled" {
        msg_repo.update_status(id, MessageStatus::Scheduled).await?;
    }

    // Publish to queue for delivery
    let track_opens = body.track_opens;
    let track_clicks = body.track_clicks;
    let payload = OutboundPayload {
        message_id: id.0.to_string(),
        tenant_id: auth.tenant_id.0.to_string(),
        domain_id: Some(domain_id.0.to_string()),
        envelope_from: extract_addr_spec(&body.from),
        envelope_to: active_recipients,
        raw_eml_key: upload_result.fid,
        is_forward: false,
        auth_results: None,
        track_opens,
        track_clicks,
    };
    let body_bytes = serde_json::to_vec(&payload).map_err(|e| ApiError::Internal(e.to_string()))?;
    let headers = PublishHeaders {
        message_id: Some(id.to_string()),
        tenant_id: Some(auth.tenant_id.to_string()),
        ..Default::default()
    };
    state
        .publisher
        .publish(
            EXCHANGE_SUBMIT,
            "message.outbound.delivery",
            &body_bytes,
            headers,
        )
        .await?;

    Ok(data(SendResponse {
        id,
        status: status_label.to_string(),
        message_id_header: Some(message_id_header),
    }))
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/messages/send-multipart
//
// Streaming send path for messages with non-trivial attachments. The
// JSON /send endpoint requires the entire message + attachments to be
// base64'd into the request body, which inflates the payload by 33%
// and forces both client and server to hold full bytes in memory.
// Multipart lets a client stream attachment bytes straight through
// to Sentio with zero base64,
// supporting attachments up to the upstream MTA cap (~25-50 MB).
//
// Wire format (multipart/form-data):
//   - Part name "message" with Content-Type: application/json,
//     body = SendMessageMultipartRequest (same shape as
//     SendMessageRequest, minus `attachments` - those are file parts)
//   - Zero or more file parts (any name) with:
//       Content-Disposition: form-data; name="…"; filename="<file>"
//       Content-Type: <mime>
//       Optional X-Sentio-Disposition: "attachment" (default) | "inline"
//       Optional X-Sentio-Content-Id: <id>  (required for inline images)
// ──────────────────────────────────────────────────────────────────────────────

/// Shape for the JSON "message" part of /send-multipart. Mirrors
/// SendMessageRequest except `attachments` is gone (file parts).
#[derive(Deserialize)]
pub struct SendMessageMultipartRequest {
    pub from: String,
    pub to: Vec<String>,
    #[serde(default)]
    pub cc: Vec<String>,
    #[serde(default)]
    pub bcc: Vec<String>,
    pub reply_to: Option<String>,
    pub subject: Option<String>,
    pub html: Option<String>,
    pub text: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub metadata: Option<serde_json::Value>,
    pub send_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub track_opens: bool,
    #[serde(default)]
    pub track_clicks: bool,
    #[serde(default)]
    pub in_reply_to: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
}

pub async fn send_multipart(
    State(state): State<AppState>,
    auth: AuthContext,
    mut multipart: axum::extract::Multipart,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("messages:send")?;

    // First pass: pull the "message" JSON part and accumulate file
    // parts. Files stream-collect into Vec<u8> (existing build_eml is
    // bytes-in-memory; future iteration can move EML assembly to
    // streaming once mail-builder supports it).
    let mut body: Option<SendMessageMultipartRequest> = None;
    let mut decoded: Vec<DecodedAttachment> = Vec::new();
    use sha2::{Digest, Sha256};

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::Validation(format!("multipart parse: {e}")))?
    {
        let name = field.name().unwrap_or("").to_string();
        let file_name = field.file_name().map(|s| s.to_string());
        let part_content_type = field
            .content_type()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "application/octet-stream".to_string());

        // Pull custom Sentio headers off the part before draining body.
        // axum::Multipart::Field exposes the raw headers via headers().
        let headers = field.headers().clone();
        let disposition = headers
            .get("x-sentio-disposition")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_lowercase())
            .filter(|s| s == "attachment" || s == "inline")
            .unwrap_or_else(|| "attachment".to_string());
        let content_id = headers
            .get("x-sentio-content-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let bytes = field
            .bytes()
            .await
            .map_err(|e| ApiError::Validation(format!("read field {name}: {e}")))?;

        if name == "message" {
            body = Some(
                serde_json::from_slice(&bytes)
                    .map_err(|e| ApiError::Validation(format!("message JSON: {e}")))?,
            );
            continue;
        }

        // Treat any other part with a filename as an attachment. Parts
        // without a filename are ignored (defensive: future fields
        // shouldn't break existing clients).
        let Some(filename) = file_name else {
            continue;
        };

        let digest = Sha256::digest(&bytes);
        let hash = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        decoded.push(DecodedAttachment {
            filename,
            content_type: part_content_type,
            data: bytes.to_vec(),
            content_id,
            disposition,
            checksum_sha256: hash,
        });
    }

    let body =
        body.ok_or_else(|| ApiError::Validation("missing required 'message' part".into()))?;

    // From here on, mirror the JSON /send path. The duplication is
    // intentional - a refactor to share would couple the two via a
    // wider signature than either needs.
    if body.from.is_empty() {
        return Err(ApiError::Validation("from address is required".into()));
    }
    if body.to.is_empty() {
        return Err(ApiError::Validation(
            "at least one recipient is required".into(),
        ));
    }

    validate_email_field("from", &body.from)?;
    validate_email_list("to", &body.to)?;
    validate_email_list("cc", &body.cc)?;
    validate_email_list("bcc", &body.bcc)?;
    if let Some(rt) = body.reply_to.as_deref() {
        validate_email_field("reply_to", rt)?;
    }

    let domain_id = validate_sender_domain(&state.pool, auth.tenant_id, &body.from).await?;

    let mut envelope_to: Vec<String> = body.to.iter().map(|s| extract_addr_spec(s)).collect();
    envelope_to.extend(body.cc.iter().map(|s| extract_addr_spec(s)));
    envelope_to.extend(body.bcc.iter().map(|s| extract_addr_spec(s)));
    let suppression_repo = PgSuppressionRepository::new(state.pool.clone());
    let mut active_recipients = Vec::new();
    for rcpt in &envelope_to {
        if !suppression_repo.check(auth.tenant_id, rcpt).await? {
            active_recipients.push(rcpt.clone());
        }
    }
    if active_recipients.is_empty() {
        return Err(ApiError::Validation("all recipients are suppressed".into()));
    }

    let status_label = if body.send_at.is_some_and(|t| t > Utc::now()) {
        "scheduled"
    } else {
        "queued"
    };
    let id = MessageId::new();

    let html_body = if (body.track_opens || body.track_clicks) && body.html.is_some() {
        let rewritten = sentio_smtp_client::tracking::rewrite_html_tracking(
            body.html.as_deref().unwrap(),
            &state.config.server.api_base_url,
            &id.0.to_string(),
            &auth.tenant_id.0.to_string(),
            body.track_opens,
            body.track_clicks,
        );
        Some(rewritten)
    } else {
        body.html.clone()
    };

    let (raw_eml, message_id_header) = build_eml(
        &body.from,
        &body.to,
        &body.cc,
        body.reply_to.as_deref(),
        body.subject.as_deref(),
        body.text.as_deref(),
        html_body.as_deref(),
        &decoded,
        &state.config.server.hostname,
        body.in_reply_to.as_deref(),
        &body.references,
    );

    let assigned = state.blob_store.assign().await?;
    let upload_result = state
        .blob_store
        .upload(
            &assigned.fid,
            bytes::Bytes::from(raw_eml),
            "message.eml",
            "message/rfc822",
        )
        .await?;

    let msg_repo = PgMessageRepository::new(state.pool.clone());
    let new_msg = NewMessage {
        id,
        tenant_id: auth.tenant_id,
        domain_id: Some(domain_id),
        direction: MessageDirection::Outbound,
        envelope_from: extract_addr_spec(&body.from),
        envelope_to: active_recipients.clone(),
        header_from: Some(body.from.clone()),
        header_to: body.to,
        header_cc: body.cc,
        header_reply_to: body.reply_to,
        subject: body.subject,
        message_id_header: Some(message_id_header.clone()),
        tags: body.tags,
        metadata: body.metadata,
        message_size: Some(upload_result.size as i64),
        raw_eml_key: Some(upload_result.fid.clone()),
        spam_score: None,
        spam_action: None,
        send_at: body.send_at,
        dsn_ret: None,
        dsn_envid: None,
        dsn_notify: serde_json::json!({}),
        dsn_orcpt: serde_json::json!({}),
    };
    msg_repo.insert(new_msg).await?;

    if !decoded.is_empty() {
        let att_repo = PgMessageAttachmentRepository::new(state.pool.clone());
        upload_attachments(
            state.blob_store.as_ref(),
            &att_repo,
            id,
            auth.tenant_id,
            &decoded,
        )
        .await?;
    }

    if status_label == "scheduled" {
        msg_repo.update_status(id, MessageStatus::Scheduled).await?;
    }

    let payload = OutboundPayload {
        message_id: id.0.to_string(),
        tenant_id: auth.tenant_id.0.to_string(),
        domain_id: Some(domain_id.0.to_string()),
        envelope_from: extract_addr_spec(&body.from),
        envelope_to: active_recipients,
        raw_eml_key: upload_result.fid,
        is_forward: false,
        auth_results: None,
        track_opens: body.track_opens,
        track_clicks: body.track_clicks,
    };
    let body_bytes = serde_json::to_vec(&payload).map_err(|e| ApiError::Internal(e.to_string()))?;
    let headers = PublishHeaders {
        message_id: Some(id.to_string()),
        tenant_id: Some(auth.tenant_id.to_string()),
        ..Default::default()
    };
    state
        .publisher
        .publish(
            EXCHANGE_SUBMIT,
            "message.outbound.delivery",
            &body_bytes,
            headers,
        )
        .await?;

    Ok(data(SendResponse {
        id,
        status: status_label.to_string(),
        message_id_header: Some(message_id_header),
    }))
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/messages/send-batch
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct BatchResultItem {
    id: Option<MessageId>,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[utoipa::path(
    post,
    path = "/v1/messages/send-batch",
    tag = "Messages",
    security(("bearer" = [])),
    request_body = Vec<SendMessageRequest>,
    responses(
        (status = 200, body = DataResponse<Vec<BatchResultItem>>),
        (status = 422, body = ErrorResponse),
    ),
)]
pub async fn send_batch(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(body): Json<Vec<SendMessageRequest>>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("messages:send")?;

    if body.len() > 1000 {
        return Err(ApiError::Validation(
            "batch size exceeds maximum of 1000".into(),
        ));
    }

    let mut results = Vec::with_capacity(body.len());

    for req in body {
        match send_single(&state, &auth, req).await {
            Ok((id, status)) => {
                results.push(BatchResultItem {
                    id: Some(id),
                    status,
                    error: None,
                });
            }
            Err(e) => {
                results.push(BatchResultItem {
                    id: None,
                    status: "failed".to_string(),
                    error: Some(format!("{e:?}")),
                });
            }
        }
    }

    Ok(data(results))
}

async fn send_single(
    state: &AppState,
    auth: &AuthContext,
    body: SendMessageRequest,
) -> Result<(MessageId, String), ApiError> {
    if body.from.is_empty() || body.to.is_empty() {
        return Err(ApiError::Validation("from and to are required".into()));
    }

    validate_email_field("from", &body.from)?;
    validate_email_list("to", &body.to)?;
    validate_email_list("cc", &body.cc)?;
    validate_email_list("bcc", &body.bcc)?;
    if let Some(rt) = body.reply_to.as_deref() {
        validate_email_field("reply_to", rt)?;
    }

    // Validate sender domain ownership
    let domain_id = validate_sender_domain(&state.pool, auth.tenant_id, &body.from).await?;

    let mut envelope_to: Vec<String> = body.to.iter().map(|s| extract_addr_spec(s)).collect();
    envelope_to.extend(body.cc.iter().map(|s| extract_addr_spec(s)));
    envelope_to.extend(body.bcc.iter().map(|s| extract_addr_spec(s)));

    let suppression_repo = PgSuppressionRepository::new(state.pool.clone());
    let mut active_recipients = Vec::new();
    for rcpt in &envelope_to {
        if !suppression_repo.check(auth.tenant_id, rcpt).await? {
            active_recipients.push(rcpt.clone());
        }
    }
    if active_recipients.is_empty() {
        return Err(ApiError::Validation("all recipients are suppressed".into()));
    }

    let status_label = if body.send_at.is_some_and(|t| t > Utc::now()) {
        "scheduled"
    } else {
        "queued"
    };

    // Allocate message ID early - needed for tracking token generation
    let id = MessageId::new();

    // Decode attachments upfront (validates base64)
    let decoded_attachments = decode_attachments(&body.attachments)?;

    // Apply tracking rewrite to HTML body before MIME assembly (and DKIM signing)
    let html_body = if (body.track_opens || body.track_clicks) && body.html.is_some() {
        let rewritten = sentio_smtp_client::tracking::rewrite_html_tracking(
            body.html.as_deref().unwrap(),
            &state.config.server.api_base_url,
            &id.0.to_string(),
            &auth.tenant_id.0.to_string(),
            body.track_opens,
            body.track_clicks,
        );
        Some(rewritten)
    } else {
        body.html.clone()
    };

    // Build EML from structured fields (including attachments)
    let (raw_eml, message_id_header) = build_eml(
        &body.from,
        &body.to,
        &body.cc,
        body.reply_to.as_deref(),
        body.subject.as_deref(),
        body.text.as_deref(),
        html_body.as_deref(),
        &decoded_attachments,
        &state.config.server.hostname,
        body.in_reply_to.as_deref(),
        &body.references,
    );

    // Upload raw EML to blob store
    let assigned = state.blob_store.assign().await?;
    let upload_result = state
        .blob_store
        .upload(
            &assigned.fid,
            bytes::Bytes::from(raw_eml),
            "message.eml",
            "message/rfc822",
        )
        .await?;

    let msg_repo = PgMessageRepository::new(state.pool.clone());
    let new_msg = NewMessage {
        id,
        tenant_id: auth.tenant_id,
        domain_id: Some(domain_id),
        direction: MessageDirection::Outbound,
        envelope_from: extract_addr_spec(&body.from),
        envelope_to: active_recipients.clone(),
        header_from: Some(body.from.clone()),
        header_to: body.to,
        header_cc: body.cc,
        header_reply_to: body.reply_to,
        subject: body.subject,
        message_id_header: Some(message_id_header.clone()),
        tags: body.tags,
        metadata: body.metadata,
        message_size: Some(upload_result.size as i64),
        raw_eml_key: Some(upload_result.fid.clone()),
        spam_score: None,
        spam_action: None,
        send_at: body.send_at,
        dsn_ret: None,
        dsn_envid: None,
        dsn_notify: serde_json::json!({}),
        dsn_orcpt: serde_json::json!({}),
    };
    msg_repo.insert(new_msg).await?;

    // Upload individual attachments to blob store and record in DB
    if !decoded_attachments.is_empty() {
        let att_repo = PgMessageAttachmentRepository::new(state.pool.clone());
        upload_attachments(
            state.blob_store.as_ref(),
            &att_repo,
            id,
            auth.tenant_id,
            &decoded_attachments,
        )
        .await?;
    }

    if status_label == "scheduled" {
        msg_repo.update_status(id, MessageStatus::Scheduled).await?;
    }

    let track_opens = body.track_opens;
    let track_clicks = body.track_clicks;
    let payload = OutboundPayload {
        message_id: id.0.to_string(),
        tenant_id: auth.tenant_id.0.to_string(),
        domain_id: Some(domain_id.0.to_string()),
        envelope_from: extract_addr_spec(&body.from),
        envelope_to: active_recipients,
        raw_eml_key: upload_result.fid,
        is_forward: false,
        auth_results: None,
        track_opens,
        track_clicks,
    };
    let body_bytes = serde_json::to_vec(&payload).map_err(|e| ApiError::Internal(e.to_string()))?;
    let headers = PublishHeaders {
        message_id: Some(id.to_string()),
        tenant_id: Some(auth.tenant_id.to_string()),
        ..Default::default()
    };
    state
        .publisher
        .publish(
            EXCHANGE_SUBMIT,
            "message.outbound.delivery",
            &body_bytes,
            headers,
        )
        .await?;

    Ok((id, status_label.to_string()))
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/messages/send-raw
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/messages/send-raw",
    tag = "Messages",
    security(("bearer" = [])),
    request_body = SendRawRequest,
    responses(
        (status = 200, body = DataResponse<SendResponse>),
        (status = 422, body = ErrorResponse),
    ),
)]
pub async fn send_raw(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(body): Json<SendRawRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("messages:send")?;

    if body.from.is_empty() || body.to.is_empty() {
        return Err(ApiError::Validation("from and to are required".into()));
    }

    validate_email_field("from", &body.from)?;
    validate_email_list("to", &body.to)?;

    // Validate sender domain ownership
    let domain_id = validate_sender_domain(&state.pool, auth.tenant_id, &body.from).await?;

    // Decode base64 raw EML
    let raw_eml = base64::engine::general_purpose::STANDARD
        .decode(&body.raw_eml)
        .map_err(|e| ApiError::Validation(format!("invalid base64 in raw_eml: {e}")))?;

    // Parse EML headers for DB metadata (best-effort - fall back to None/empty)
    let (header_from, header_to, header_cc, header_reply_to, subject, message_id_header) = {
        use mail_parser::MessageParser;
        if let Some(parsed) = MessageParser::default().parse(&raw_eml) {
            let hf = parsed
                .from()
                .and_then(|addrs| addrs.first())
                .and_then(|a| a.address())
                .map(|s| s.to_string());
            let ht: Vec<String> = parsed
                .to()
                .map(|addrs| {
                    addrs
                        .iter()
                        .filter_map(|a| a.address().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let hcc: Vec<String> = parsed
                .cc()
                .map(|addrs| {
                    addrs
                        .iter()
                        .filter_map(|a| a.address().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let hrt = parsed
                .reply_to()
                .and_then(|addrs| addrs.first())
                .and_then(|a| a.address())
                .map(|s| s.to_string());
            let subj = parsed.subject().map(|s| s.to_string());
            let mid = parsed.message_id().map(|s| s.to_string());
            (hf, ht, hcc, hrt, subj, mid)
        } else {
            (None, Vec::new(), Vec::new(), None, None, None)
        }
    };

    // Upload raw EML to blob store
    let assigned = state.blob_store.assign().await?;
    let upload_result = state
        .blob_store
        .upload(
            &assigned.fid,
            bytes::Bytes::from(raw_eml),
            "message.eml",
            "message/rfc822",
        )
        .await?;

    // Insert message record
    let msg_repo = PgMessageRepository::new(state.pool.clone());
    let id = MessageId::new();
    let new_msg = NewMessage {
        id,
        tenant_id: auth.tenant_id,
        domain_id: Some(domain_id),
        direction: MessageDirection::Outbound,
        envelope_from: extract_addr_spec(&body.from),
        envelope_to: body.to.iter().map(|s| extract_addr_spec(s)).collect(),
        header_from,
        header_to,
        header_cc,
        header_reply_to,
        subject,
        message_id_header: message_id_header.clone(),
        tags: Vec::new(),
        metadata: None,
        message_size: Some(upload_result.size as i64),
        raw_eml_key: Some(upload_result.fid.clone()),
        spam_score: None,
        spam_action: None,
        send_at: None,
        dsn_ret: None,
        dsn_envid: None,
        dsn_notify: serde_json::json!({}),
        dsn_orcpt: serde_json::json!({}),
    };
    msg_repo.insert(new_msg).await?;

    // Publish to queue
    let payload = OutboundPayload {
        message_id: id.0.to_string(),
        tenant_id: auth.tenant_id.0.to_string(),
        domain_id: Some(domain_id.0.to_string()),
        envelope_from: extract_addr_spec(&body.from),
        envelope_to: body.to.iter().map(|s| extract_addr_spec(s)).collect(),
        raw_eml_key: upload_result.fid,
        is_forward: false,
        auth_results: None,
        track_opens: false,
        track_clicks: false,
    };
    let body_bytes = serde_json::to_vec(&payload).map_err(|e| ApiError::Internal(e.to_string()))?;
    let headers = PublishHeaders {
        message_id: Some(id.to_string()),
        tenant_id: Some(auth.tenant_id.to_string()),
        ..Default::default()
    };
    state
        .publisher
        .publish(
            EXCHANGE_SUBMIT,
            "message.outbound.delivery",
            &body_bytes,
            headers,
        )
        .await?;

    Ok(data(SendResponse {
        id,
        status: "queued".to_string(),
        message_id_header,
    }))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/messages
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/messages",
    tag = "Messages",
    security(("bearer" = [])),
    params(ListMessagesParams),
    responses(
        (status = 200, body = DataResponse<Vec<MessageResponse>>),
    ),
)]
pub async fn list_messages(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<ListMessagesParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("messages:read")?;

    let to = params.to.unwrap_or_else(Utc::now);
    let from = params.from.unwrap_or_else(|| to - Duration::hours(24));
    let limit = params.limit.clamp(1, 1000);
    let offset = params.offset.max(0);

    let filter = MessageFilter {
        status: params.status,
        direction: params.direction,
        from,
        to,
        limit,
        offset,
    };

    let msg_repo = PgMessageRepository::new(state.pool.clone());
    let records = msg_repo.list(auth.tenant_id, filter).await?;
    let messages: Vec<MessageResponse> = records.into_iter().map(Into::into).collect();

    Ok(data(messages))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/messages/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/messages/{id}",
    tag = "Messages",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,)),
    responses(
        (status = 200, body = DataResponse<MessageResponse>),
        (status = 404, body = ErrorResponse),
    ),
)]
pub async fn get_message(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("messages:read")?;

    let msg_repo = PgMessageRepository::new(state.pool.clone());
    let record = msg_repo.get(auth.tenant_id, MessageId(id)).await?;

    Ok(data(MessageResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/messages/{id}/raw
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/messages/{id}/raw",
    tag = "Messages",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,)),
    responses(
        (status = 200, content_type = "message/rfc822"),
        (status = 404, body = ErrorResponse),
    ),
)]
pub async fn get_message_raw(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("messages:read")?;

    let msg_repo = PgMessageRepository::new(state.pool.clone());
    let record = msg_repo.get(auth.tenant_id, MessageId(id)).await?;

    let fid = record
        .raw_eml_key
        .ok_or_else(|| ApiError::NotFound("raw EML not available for this message".into()))?;

    let blob_data = state.blob_store.download(&fid).await?;

    Ok((
        [
            (
                axum::http::header::CONTENT_TYPE,
                "message/rfc822".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{id}.eml\""),
            ),
        ],
        blob_data,
    ))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/messages/{id}/events
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/messages/{id}/events",
    tag = "Messages",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,)),
    responses(
        (status = 200, body = DataResponse<Vec<EventResponse>>),
        (status = 404, body = ErrorResponse),
    ),
)]
pub async fn get_message_events(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("messages:read")?;

    // Verify message belongs to tenant
    let msg_repo = PgMessageRepository::new(state.pool.clone());
    msg_repo.get(auth.tenant_id, MessageId(id)).await?;

    // Fetch events
    let event_repo = PgMessageEventRepository::new(state.pool.clone());
    let records = event_repo.list_by_message(MessageId(id)).await?;
    let events: Vec<EventResponse> = records.into_iter().map(Into::into).collect();

    Ok(data(events))
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only helper: extract the String inside ApiError::Validation
    /// so test assertions can inspect the error message without needing
    /// a Display impl on ApiError (which deliberately doesn't have one
    /// to discourage logging raw error contents through user-facing
    /// channels).
    trait UnwrapErrMsg {
        fn unwrap_err_msg(self) -> String;
    }
    impl<T: std::fmt::Debug> UnwrapErrMsg for Result<T, ApiError> {
        fn unwrap_err_msg(self) -> String {
            match self.unwrap_err() {
                ApiError::Validation(msg) => msg,
                other => panic!("expected Validation, got {other:?}"),
            }
        }
    }

    // ── extract_addr_spec ────────────────────────────────────────────

    #[test]
    fn extract_bare_address() {
        assert_eq!(extract_addr_spec("alice@example.com"), "alice@example.com");
    }

    #[test]
    fn extract_angle_bracketed() {
        assert_eq!(
            extract_addr_spec("<alice@example.com>"),
            "alice@example.com"
        );
    }

    #[test]
    fn extract_quoted_display_name() {
        // A UTF-8 display name with the middle-dot character causes
        // Gmail to reject the MAIL FROM with 5.5.2 if the whole
        // mailbox string is sent on the wire. extract_addr_spec must
        // peel the wrapping cleanly.
        assert_eq!(
            extract_addr_spec(r#""Alex · Team" <alex@example.com>"#),
            "alex@example.com"
        );
    }

    #[test]
    fn extract_unquoted_display_name() {
        assert_eq!(
            extract_addr_spec("Alice <alice@example.com>"),
            "alice@example.com"
        );
    }

    #[test]
    fn extract_trims_outer_whitespace() {
        assert_eq!(
            extract_addr_spec("   alice@example.com   "),
            "alice@example.com"
        );
    }

    #[test]
    fn extract_picks_last_angle_when_display_name_has_brackets() {
        // rfind('<') anchors on the last opener so a display name like
        // `"<<weird>>" <real@example.com>` still resolves to real@.
        assert_eq!(
            extract_addr_spec(r#""<<weird>>" <real@example.com>"#),
            "real@example.com"
        );
    }

    #[test]
    fn extract_unterminated_angle_falls_through() {
        // No closing `>` - don't gamble, return the whole trimmed input
        // unchanged so validation downstream rejects it as malformed.
        assert_eq!(extract_addr_spec("<no-close-bracket"), "<no-close-bracket");
    }

    #[test]
    fn extract_empty_input() {
        assert_eq!(extract_addr_spec(""), "");
        assert_eq!(extract_addr_spec("   "), "");
    }

    // ── parse_mailbox ────────────────────────────────────────────────

    #[test]
    fn parse_mailbox_bare_address() {
        use mail_builder::headers::address::Address;
        let a = parse_mailbox("alice@example.com");
        match a {
            Address::Address(ea) => {
                assert_eq!(ea.email, "alice@example.com");
                assert!(ea.name.is_none());
            }
            _ => panic!("expected EmailAddress"),
        }
    }

    #[test]
    fn parse_mailbox_with_display_name() {
        use mail_builder::headers::address::Address;
        let a = parse_mailbox(r#""Alice Person" <alice@example.com>"#);
        match a {
            Address::Address(ea) => {
                assert_eq!(ea.email, "alice@example.com");
                assert_eq!(ea.name.as_deref(), Some("Alice Person"));
            }
            _ => panic!("expected EmailAddress with name"),
        }
    }

    #[test]
    fn parse_mailbox_unicode_display_name() {
        use mail_builder::headers::address::Address;
        let a = parse_mailbox(r#""Alex · Team" <alex@example.com>"#);
        match a {
            Address::Address(ea) => {
                assert_eq!(ea.email, "alex@example.com");
                assert_eq!(ea.name.as_deref(), Some("Alex · Team"));
            }
            _ => panic!("expected EmailAddress with unicode name"),
        }
    }

    // ── validate_email_field ─────────────────────────────────────────

    #[test]
    fn validate_accepts_bare_addr() {
        assert!(validate_email_field("from", "alice@example.com").is_ok());
    }

    #[test]
    fn validate_accepts_mailbox_form() {
        assert!(validate_email_field("from", r#""Alex · Team" <alex@example.com>"#).is_ok());
    }

    #[test]
    fn validate_rejects_empty() {
        let err = validate_email_field("from", "").unwrap_err_msg();
        assert!(err.contains("from"), "got: {err}");
        assert!(err.contains("empty"), "got: {err}");
    }

    #[test]
    fn validate_rejects_no_at() {
        let err = validate_email_field("from", "not-an-email").unwrap_err_msg();
        assert!(err.contains("not a valid email"), "got: {err}");
    }

    #[test]
    fn validate_rejects_at_only() {
        assert!(validate_email_field("from", "@").is_err());
        assert!(validate_email_field("from", "alice@").is_err());
        assert!(validate_email_field("from", "@example.com").is_err());
    }

    #[test]
    fn validate_rejects_double_at() {
        // 'a@b@c' parses as local='a', domain='b@c' which still has '@'
        let err = validate_email_field("from", "alice@a@b").unwrap_err_msg();
        assert!(err.contains("not a valid email"), "got: {err}");
    }

    #[test]
    fn validate_rejects_crlf_injection() {
        // The header-injection vector. Defensive even for a trusted
        // caller - never accept newlines in an address field.
        for evil in [
            "alice@example.com\r\nBcc: attacker@evil.com",
            "alice@example.com\nBcc: x",
            "alice@example.com\r",
            "alice@example.com\0null",
            "\"name\r\nBcc\" <a@b.com>",
        ] {
            let err = validate_email_field("from", evil).unwrap_err_msg();
            assert!(
                err.contains("control characters"),
                "expected CRLF-reject for {evil:?}, got: {err}"
            );
        }
    }

    #[test]
    fn validate_rejects_whitespace_in_addr_spec() {
        // The display-name wrapper handles outer whitespace; whitespace
        // inside the addr-spec itself is invalid per RFC 5321.
        assert!(validate_email_field("from", "ali ce@example.com").is_err());
        assert!(validate_email_field("from", "alice@ex ample.com").is_err());
    }

    #[test]
    fn validate_list_reports_index_of_bad_entry() {
        let bad = vec![
            "good@example.com".to_string(),
            "also-good@example.com".to_string(),
            "garbage".to_string(),
        ];
        let err = validate_email_list("to", &bad).unwrap_err_msg();
        assert!(err.contains("to[2]"), "expected to[2] in error, got: {err}");
    }

    #[test]
    fn validate_list_empty_ok() {
        assert!(validate_email_list("cc", &[]).is_ok());
    }
}
