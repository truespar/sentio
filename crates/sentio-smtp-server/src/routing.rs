use std::sync::Arc;

use sentio_core::config::LlmConfig;
use sentio_core::event::EventType;
use sentio_core::ids::InboundRouteId;
use sentio_core::inbound::InboundRouteMatchType;
use sentio_core::message::MessageId;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{
    BlobStore, InboundRouteDeliveryLogRepository, InboundRouteRecord, InboundRouteRepository,
    MessageEventRepository, MessageRepository, NewInboundRouteDeliveryLog, NewMessageEvent,
};
use sentio_llm::traits::LlmProvider;
use sentio_llm::LlmBackend;
use sentio_queue::consumer::{HandlerResult, MessageHandler, QueueMessage};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// ──────────────────────────────────────────────────────────────────────────────
// Inbound payload - matches the JSON published by pipeline.rs
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundPayload {
    pub message_id: String,
    pub tenant_id: String,
    pub domain_id: String,
    pub envelope_from: String,
    pub envelope_to: Vec<String>,
    pub raw_eml_key: String,
    pub spam_score: Option<f64>,
    pub spam_action: Option<String>,
    pub queued_at: Option<String>,
    #[serde(default)]
    pub dsn_ret: Option<String>,
    #[serde(default)]
    pub dsn_envid: Option<String>,
    #[serde(default)]
    pub dsn_notify: serde_json::Value,
    #[serde(default)]
    pub dsn_orcpt: serde_json::Value,
    #[serde(default)]
    pub llm_category: Option<String>,
    #[serde(default)]
    pub llm_summary: Option<String>,
    /// RFC 5322 In-Reply-To: the Message-ID this mail replies to (bare id,
    /// no angle brackets). Lets a consumer thread the reply against a prior
    /// message. `#[serde(default)]` keeps older queued payloads decoding.
    #[serde(default)]
    pub in_reply_to: Option<String>,
    /// RFC 5322 References: the ordered Message-ID chain for the thread
    /// (bare ids). Empty when absent.
    #[serde(default)]
    pub references: Vec<String>,
    /// Loop-guard headers (RFC 3834 Auto-Submitted, a mailing-list marker,
    /// Precedence). Raw values; a consumer's intake gate decides what counts
    /// as bulk/auto. `#[serde(default)]` keeps older payloads decoding.
    #[serde(default)]
    pub auto_submitted: Option<String>,
    #[serde(default)]
    pub list_id: Option<String>,
    #[serde(default)]
    pub precedence: Option<String>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Route matching
// ──────────────────────────────────────────────────────────────────────────────

/// Returns the first route that matches the given recipient address.
/// Routes are expected to be sorted by priority descending.
pub fn match_route<'a>(
    recipient: &str,
    routes: &'a [InboundRouteRecord],
) -> Option<&'a InboundRouteRecord> {
    let recipient_lower = recipient.to_lowercase();
    for route in routes {
        let matched = match route.match_type {
            InboundRouteMatchType::Exact => route.pattern.to_lowercase() == recipient_lower,
            InboundRouteMatchType::Domain => {
                let domain_part = recipient_lower
                    .rsplit_once('@')
                    .map(|(_, d)| d)
                    .unwrap_or("");
                route.pattern.to_lowercase() == domain_part
            }
            InboundRouteMatchType::Regex => match regex::Regex::new(&route.pattern) {
                Ok(re) => re.is_match(&recipient_lower),
                Err(e) => {
                    warn!(
                        pattern = %route.pattern,
                        error = %e,
                        "invalid regex pattern in inbound route, skipping"
                    );
                    false
                }
            },
            InboundRouteMatchType::CatchAll => true,
        };
        if matched {
            return Some(route);
        }
    }
    None
}

// ──────────────────────────────────────────────────────────────────────────────
// Inbound routing engine - implements MessageHandler
// ──────────────────────────────────────────────────────────────────────────────

pub struct InboundEngine<R, E, B, M, L> {
    route_repo: Arc<R>,
    event_repo: Arc<E>,
    blob_store: Arc<B>,
    message_repo: Arc<M>,
    delivery_log_repo: Arc<L>,
    llm_backend: Arc<LlmBackend>,
    llm_config: Arc<LlmConfig>,
    retry_policy: InboundWebhookRetryPolicy,
    http_client: reqwest::Client,
}

impl<R, E, B, M, L> InboundEngine<R, E, B, M, L>
where
    R: InboundRouteRepository + 'static,
    E: MessageEventRepository + 'static,
    B: BlobStore + 'static,
    M: MessageRepository + 'static,
    L: InboundRouteDeliveryLogRepository + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        route_repo: Arc<R>,
        event_repo: Arc<E>,
        blob_store: Arc<B>,
        message_repo: Arc<M>,
        delivery_log_repo: Arc<L>,
        llm_backend: Arc<LlmBackend>,
        llm_config: Arc<LlmConfig>,
    ) -> Self {
        Self::with_retry_policy(
            route_repo,
            event_repo,
            blob_store,
            message_repo,
            delivery_log_repo,
            llm_backend,
            llm_config,
            InboundWebhookRetryPolicy::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_retry_policy(
        route_repo: Arc<R>,
        event_repo: Arc<E>,
        blob_store: Arc<B>,
        message_repo: Arc<M>,
        delivery_log_repo: Arc<L>,
        llm_backend: Arc<LlmBackend>,
        llm_config: Arc<LlmConfig>,
        retry_policy: InboundWebhookRetryPolicy,
    ) -> Self {
        Self {
            route_repo,
            event_repo,
            blob_store,
            message_repo,
            delivery_log_repo,
            llm_backend,
            llm_config,
            retry_policy,
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    /// Dispatch one POST to `url` and persist exactly one
    /// `inbound_route_delivery_logs` row describing the outcome.
    ///
    /// This is *one* HTTP attempt - the retry loop lives in [`handle`],
    /// which uses JetStream `HandlerResult::RetryAfter(delay)` so the
    /// next attempt happens on a fresh consumer delivery (no in-process
    /// sleep, no consumer-thread starvation, survives sentio restarts).
    ///
    /// Classification of the outcome:
    /// - 2xx                          → `Success` (delivered_at = now)
    /// - 5xx / 408 / 429              → `TransientFail` (failed_at = now)
    /// - other 4xx                    → `PermanentFail` (failed_at = now)
    /// - network / timeout / DNS      → `TransientFail` (failed_at = now)
    ///
    /// Log-write failures are WARN-and-ignore - the audit trail can't
    /// be allowed to break dispatch.
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_webhook_once(
        &self,
        inbound_route_id: InboundRouteId,
        tenant_id: TenantId,
        message_id: Option<MessageId>,
        recipient: &str,
        url: &str,
        attempt_number: i32,
        payload: &InboundPayload,
    ) -> DispatchOutcome {
        const RESPONSE_BODY_CAP: usize = 4096;

        let send_result = self.http_client.post(url).json(payload).send().await;

        let (outcome, http_status, response_body, error_message, delivered_at, failed_at) =
            match send_result {
                Ok(resp) => {
                    let status = resp.status();
                    let s = status.as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    let body_capped = if body.len() > RESPONSE_BODY_CAP {
                        body[..RESPONSE_BODY_CAP].to_string()
                    } else {
                        body
                    };

                    if status.is_success() {
                        (
                            DispatchOutcome::Success,
                            Some(s as i32),
                            Some(body_capped),
                            None,
                            Some(chrono::Utc::now()),
                            None,
                        )
                    } else if s >= 500 || s == 408 || s == 429 {
                        let msg = format!("webhook returned {status}");
                        (
                            DispatchOutcome::TransientFail(msg.clone()),
                            Some(s as i32),
                            Some(body_capped),
                            Some(msg),
                            None,
                            Some(chrono::Utc::now()),
                        )
                    } else {
                        let msg = format!("webhook returned {status} (permanent, no retry)");
                        (
                            DispatchOutcome::PermanentFail(msg.clone()),
                            Some(s as i32),
                            Some(body_capped),
                            Some(msg),
                            None,
                            Some(chrono::Utc::now()),
                        )
                    }
                }
                Err(e) => {
                    let msg = format!("webhook request failed: {e}");
                    (
                        DispatchOutcome::TransientFail(msg.clone()),
                        None,
                        None,
                        Some(msg),
                        None,
                        Some(chrono::Utc::now()),
                    )
                }
            };

        self.write_log(NewInboundRouteDeliveryLog {
            inbound_route_id,
            tenant_id,
            message_id,
            recipient: recipient.to_string(),
            http_status,
            response_body,
            attempt_number,
            delivered_at,
            failed_at,
            error_message,
        })
        .await;

        outcome
    }

    async fn write_log(&self, log: NewInboundRouteDeliveryLog) {
        if let Err(e) = self.delivery_log_repo.insert(log).await {
            warn!(error = %e, "failed to persist inbound route delivery log");
        }
    }
}

/// Outcome of a single webhook POST attempt.
#[derive(Debug)]
enum DispatchOutcome {
    /// 2xx response - done.
    Success,
    /// 5xx / 408 / 429 / network / timeout - retry-eligible.
    TransientFail(String),
    /// Other 4xx - receiver config error, no retry.
    PermanentFail(String),
}

// ──────────────────────────────────────────────────────────────────────────────
// Retry policy for inbound-webhook dispatch
//
// Long-window exponential backoff with jitter, totalling a retry budget
// of several hours. Comparable to what Stripe, SendGrid, Mailgun and
// GitHub do. Anything shorter only survives a network blip, not an
// actual receiver outage.
//
// Implementation: when the InboundEngine handler hits a transient
// failure, it returns `HandlerResult::RetryAfter(delay)` and the
// JetStream consumer Naks the message with that delay. The next
// delivery is a fresh consumer dispatch - no in-process sleep, no
// consumer-thread starvation, and the retry survives a sentio restart
// because the message stays on the stream.
//
// Total max budget with defaults below: ~6h13m across 10 attempts
// (30s, 1m, 2m, 4m, 8m, 16m, 32m, 1h4m, 2h8m, +6h cap). Well within
// the sentio-submit stream's 24h MaxAge.
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct InboundWebhookRetryPolicy {
    /// Maximum number of attempts. attempt 1 is the initial delivery,
    /// attempts 2..=max_attempts are Nak-driven retries.
    pub max_attempts: u32,
    /// Base delay before the 2nd attempt (1st retry). Default 30s.
    pub base_delay_ms: u64,
    /// Hard cap on a single delay between attempts. Default 6h.
    pub max_delay_ms: u64,
    /// Fractional jitter applied to each computed delay
    /// (`delay * (1 ± jitter_pct)`). Default 0.15 (±15%).
    pub jitter_pct: f64,
}

impl Default for InboundWebhookRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 10,
            base_delay_ms: 30_000,             // 30s
            max_delay_ms: 6 * 60 * 60 * 1_000, // 6h
            jitter_pct: 0.15,
        }
    }
}

impl InboundWebhookRetryPolicy {
    /// Delay to wait before attempt N+1, given that attempt N just
    /// failed. N is the attempt that just ran (1-based), so on the
    /// first failure you pass 1 and get back the delay before attempt
    /// 2 (≈ `base_delay_ms` with jitter).
    pub fn delay_after_attempt(&self, attempt_just_completed: u32) -> std::time::Duration {
        // Exponential: base * 2^(attempt-1)
        let raw = self
            .base_delay_ms
            .saturating_mul(1u64 << attempt_just_completed.saturating_sub(1).min(30));
        let capped = raw.min(self.max_delay_ms);

        // Jitter: capped * (1 ± jitter_pct). rand 0..1 → -1..1 range.
        let factor: f64 = (rand::random::<f64>() * 2.0 - 1.0) * self.jitter_pct;
        let jittered = (capped as f64 * (1.0 + factor)).max(0.0) as u64;
        std::time::Duration::from_millis(jittered)
    }
}

impl<R, E, B, M, L> MessageHandler for InboundEngine<R, E, B, M, L>
where
    R: InboundRouteRepository + 'static,
    E: MessageEventRepository + 'static,
    B: BlobStore + 'static,
    M: MessageRepository + 'static,
    L: InboundRouteDeliveryLogRepository + 'static,
{
    async fn handle(&self, message: QueueMessage) -> HandlerResult {
        let mut payload: InboundPayload = match serde_json::from_slice(&message.body) {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, "failed to deserialize inbound payload");
                return HandlerResult::Reject;
            }
        };

        let tenant_id = match Uuid::parse_str(&payload.tenant_id) {
            Ok(id) => TenantId(id),
            Err(e) => {
                error!(tenant = %payload.tenant_id, error = %e, "invalid tenant_id in inbound payload");
                return HandlerResult::Reject;
            }
        };

        let message_id = match Uuid::parse_str(&payload.message_id) {
            Ok(id) => MessageId(id),
            Err(e) => {
                error!(message = %payload.message_id, error = %e, "invalid message_id in inbound payload");
                return HandlerResult::Reject;
            }
        };

        info!(
            message_id = %payload.message_id,
            recipients = ?payload.envelope_to,
            "processing inbound routing"
        );

        // Fetch routes for this tenant (sorted by priority DESC)
        let routes = match self.route_repo.list_by_tenant(tenant_id).await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "failed to fetch inbound routes, acking anyway");
                return HandlerResult::Ack;
            }
        };

        if routes.is_empty() {
            info!(tenant_id = %tenant_id, message_id = %payload.message_id, "no inbound routes configured, marking delivered (stored)");
            if let Err(e) = self.message_repo.set_delivered(message_id).await {
                warn!(error = %e, message_id = %payload.message_id, "failed to set message delivered (no routes)");
            }
            return HandlerResult::Ack;
        }

        // attempt counter: JetStream delivers the message once initially
        // (retry_count = 0) and increments on each Nak-driven redelivery.
        // attempt_number on the delivery_log row is 1-indexed for human
        // readability (the first attempt is "attempt 1", not "attempt 0").
        let attempt_number = (message.headers.retry_count + 1) as i32;
        let attempt_u32 = message.headers.retry_count + 1;

        // Tracks (route, recipient) tuples that hit a retry-eligible
        // transient failure on this delivery. Used at the end of
        // handle() to: (a) decide whether to Nak (any non-empty list),
        // (b) emit one dead-letter row per tuple when the retry
        // budget is exhausted. Permanent failures and successes are
        // NOT in this list - they don't drive a retry.
        let mut transient_failures: Vec<(InboundRouteId, String)> = Vec::new();

        // For each recipient, find matching route and execute action
        for recipient in &payload.envelope_to {
            let route = match match_route(recipient, &routes) {
                Some(r) => r,
                None => {
                    debug!(recipient, "no matching inbound route");
                    continue;
                }
            };

            let mut outcome_desc = String::new();

            // ── LLM content classification ─────────────────────────────
            // Runs before webhook so consumers receive enriched payload
            if route.llm_classify && self.llm_config.enabled && self.llm_config.classify_inbound {
                // Download raw EML and extract plain text for LLM
                let message_text = match self.blob_store.download(&payload.raw_eml_key).await {
                    Ok(eml_bytes) => {
                        let parsed = mail_parser::MessageParser::default().parse(&eml_bytes);
                        parsed
                            .and_then(|m| m.body_text(0).map(|t| t.to_string()))
                            .unwrap_or_default()
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to download EML for LLM classification, skipping");
                        String::new()
                    }
                };

                if !message_text.is_empty() {
                    let envelope_to_first = payload
                        .envelope_to
                        .first()
                        .map(|s| s.as_str())
                        .unwrap_or("");

                    match self
                        .llm_backend
                        .classify(&message_text, &payload.envelope_from, envelope_to_first)
                        .await
                    {
                        Ok(result) => {
                            info!(
                                message_id = %payload.message_id,
                                category = %result.category,
                                summary = %result.summary,
                                "LLM content classification complete"
                            );

                            // Enrich payload so webhook consumers get LLM results
                            payload.llm_category = Some(result.category.to_string());
                            payload.llm_summary = Some(result.summary.clone());

                            // Persist structured classification on the messages table
                            if let Err(e) = self
                                .message_repo
                                .update_llm_classification(
                                    message_id,
                                    &result.category.to_string(),
                                    &result.summary,
                                )
                                .await
                            {
                                warn!(error = %e, "failed to update LLM classification on message");
                            }

                            let llm_event = NewMessageEvent {
                                message_id,
                                tenant_id,
                                event_type: EventType::Processed,
                                smtp_response: Some(format!(
                                    "LLM classification: category={}",
                                    result.category
                                )),
                                remote_mta: None,
                                diagnostic_code: Some(format!(
                                    "category={}, summary={}",
                                    result.category, result.summary
                                )),
                                bounce_class: None,
                                retry_count: None,
                                next_retry_at: None,
                                source_ip: None,
                                destination_ip: None,
                                tls_version: None,
                            };
                            if let Err(e) = self.event_repo.insert(llm_event).await {
                                warn!(error = %e, "failed to record LLM classification event");
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "LLM content classification failed, continuing");
                        }
                    }
                }
            }

            // Dispatch webhook if configured (after LLM so payload includes classification).
            // Single attempt per consumer delivery - the retry loop is the
            // JetStream consumer's Nak(delay) (see the post-loop block at
            // the end of handle()).
            if !route.webhook_url.is_empty() {
                // On retries, skip recipients that already 2xx'd on a
                // prior attempt - otherwise a multi-recipient message
                // with one slow receiver would duplicate-deliver to
                // peers that already succeeded.
                let skip_already_delivered = attempt_number > 1
                    && matches!(
                        self.delivery_log_repo
                            .has_prior_success(route.id, message_id, recipient)
                            .await,
                        Ok(true)
                    );

                if skip_already_delivered {
                    debug!(
                        recipient,
                        attempt = attempt_number,
                        "skipping webhook dispatch - prior attempt already delivered to this recipient"
                    );
                    outcome_desc = format!(
                        "webhook idempotent-skip ({} already delivered on prior attempt)",
                        recipient
                    );
                } else {
                    match self
                        .dispatch_webhook_once(
                            route.id,
                            tenant_id,
                            Some(message_id),
                            recipient,
                            &route.webhook_url,
                            attempt_number,
                            &payload,
                        )
                        .await
                    {
                        DispatchOutcome::Success => {
                            info!(
                                recipient,
                                webhook_url = %route.webhook_url,
                                attempt = attempt_number,
                                "webhook dispatched successfully"
                            );
                            outcome_desc = format!("webhook dispatched to {}", route.webhook_url);
                        }
                        DispatchOutcome::PermanentFail(e) => {
                            warn!(
                                recipient,
                                webhook_url = %route.webhook_url,
                                attempt = attempt_number,
                                error = %e,
                                "webhook dispatch permanent failure - no retry"
                            );
                            outcome_desc = format!("webhook permanent failure: {e}");
                        }
                        DispatchOutcome::TransientFail(e) => {
                            warn!(
                                recipient,
                                webhook_url = %route.webhook_url,
                                attempt = attempt_number,
                                error = %e,
                                "webhook dispatch transient failure - will retry"
                            );
                            outcome_desc = format!("webhook transient failure: {e}");
                            transient_failures.push((route.id, recipient.clone()));
                        }
                    }
                }
            }

            // ── Auto-response ────────────────────────────────────────
            if route.auto_respond {
                // Download raw EML for auto-response if not already fetched
                let message_text = match self.blob_store.download(&payload.raw_eml_key).await {
                    Ok(eml_bytes) => {
                        let parsed = mail_parser::MessageParser::default().parse(&eml_bytes);
                        parsed
                            .and_then(|m| m.body_text(0).map(|t| t.to_string()))
                            .unwrap_or_default()
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to download EML for auto-response, skipping");
                        String::new()
                    }
                };

                if !message_text.is_empty() {
                    match sentio_llm::auto_response::generate_draft(
                        self.llm_backend.as_ref(),
                        &self.llm_config,
                        route.auto_respond,
                        route.auto_respond_config.as_ref(),
                        &message_text,
                    )
                    .await
                    {
                        Ok(Some(draft)) => {
                            info!(
                                message_id = %payload.message_id,
                                subject = %draft.subject,
                                body_len = draft.body.len(),
                                "auto-response draft generated"
                            );
                            // Log draft as event (actual sending is future work)
                            let draft_event = NewMessageEvent {
                                message_id,
                                tenant_id,
                                event_type: EventType::Processed,
                                smtp_response: Some(format!(
                                    "auto-response draft: subject={}",
                                    draft.subject
                                )),
                                remote_mta: None,
                                diagnostic_code: Some(draft.body),
                                bounce_class: None,
                                retry_count: None,
                                next_retry_at: None,
                                source_ip: None,
                                destination_ip: None,
                                tls_version: None,
                            };
                            if let Err(e) = self.event_repo.insert(draft_event).await {
                                warn!(error = %e, "failed to record auto-response event");
                            }
                        }
                        Ok(None) => {
                            debug!(message_id = %payload.message_id, "auto-response not generated (disabled or filtered)");
                        }
                        Err(e) => {
                            warn!(error = %e, "auto-response generation failed");
                        }
                    }
                }
            }

            // Record processed event
            if !outcome_desc.is_empty() {
                let event = NewMessageEvent {
                    message_id,
                    tenant_id,
                    event_type: EventType::Processed,
                    smtp_response: Some(outcome_desc),
                    remote_mta: None,
                    diagnostic_code: None,
                    bounce_class: None,
                    retry_count: None,
                    next_retry_at: None,
                    source_ip: None,
                    destination_ip: None,
                    tls_version: None,
                };
                if let Err(e) = self.event_repo.insert(event).await {
                    warn!(error = %e, "failed to record routing event");
                }
            }
        }

        // Mark message as delivered after routing completes. The DB
        // status reflects the *message-stored* state, not webhook
        // dispatch outcome - webhook dispatch has its own audit trail
        // in inbound_route_delivery_logs.
        if let Err(e) = self.message_repo.set_delivered(message_id).await {
            warn!(error = %e, message_id = %payload.message_id, "failed to set message delivered");
        }

        // Webhook retry decision: if any (route, recipient) tuple hit a
        // transient failure and we still have budget, Nak with
        // exponential backoff so JetStream redelivers and we try again
        // on a fresh dispatch (no in-process sleep, survives sentio
        // restarts). When budget is exhausted, emit one dead-letter row
        // per (route, recipient) so operators can find them, then Ack
        // - the message itself is already in PG, so no data is lost;
        // only the webhook delivery gave up.
        if !transient_failures.is_empty() {
            if attempt_u32 < self.retry_policy.max_attempts {
                let delay = self.retry_policy.delay_after_attempt(attempt_u32);
                info!(
                    message_id = %payload.message_id,
                    attempt = attempt_number,
                    next_attempt = attempt_number + 1,
                    delay_ms = delay.as_millis() as u64,
                    transient_failures = transient_failures.len(),
                    "inbound webhook transient failure - scheduling JetStream Nak retry"
                );
                return HandlerResult::RetryAfter(delay);
            }

            warn!(
                message_id = %payload.message_id,
                attempts = attempt_number,
                max_attempts = self.retry_policy.max_attempts,
                dead_letter_rows = transient_failures.len(),
                "inbound webhook retry budget exhausted - dead-lettering"
            );
            // One dead-letter row per (route, recipient) so operators
            // can find them with:
            //   SELECT * FROM inbound_route_delivery_logs
            //   WHERE error_message LIKE 'max retries exceeded%'
            for (route_id, recipient) in &transient_failures {
                self.write_log(NewInboundRouteDeliveryLog {
                    inbound_route_id: *route_id,
                    tenant_id,
                    message_id: Some(message_id),
                    recipient: recipient.clone(),
                    http_status: None,
                    response_body: None,
                    attempt_number,
                    delivered_at: None,
                    failed_at: Some(chrono::Utc::now()),
                    error_message: Some(format!(
                        "max retries exceeded ({} attempts)",
                        self.retry_policy.max_attempts
                    )),
                })
                .await;
            }
            // Fall through to Ack so JetStream removes the message.
        }

        HandlerResult::Ack
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sentio_core::ids::InboundRouteId;

    fn make_route(
        pattern: &str,
        match_type: InboundRouteMatchType,
        priority: i32,
        webhook_url: &str,
    ) -> InboundRouteRecord {
        InboundRouteRecord {
            id: InboundRouteId(Uuid::new_v4()),
            tenant_id: TenantId(Uuid::new_v4()),
            pattern: pattern.to_string(),
            match_type,
            webhook_url: webhook_url.to_string(),
            priority,
            llm_classify: false,
            auto_respond: false,
            auto_respond_config: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_match_exact() {
        let routes = vec![make_route(
            "admin@example.com",
            InboundRouteMatchType::Exact,
            100,
            "https://hook.example.com/inbound",
        )];
        assert!(match_route("admin@example.com", &routes).is_some());
        assert!(match_route("ADMIN@EXAMPLE.COM", &routes).is_some());
        assert!(match_route("other@example.com", &routes).is_none());
    }

    #[test]
    fn test_match_domain() {
        let routes = vec![make_route(
            "example.com",
            InboundRouteMatchType::Domain,
            100,
            "https://hook.example.com/inbound",
        )];
        assert!(match_route("anyone@example.com", &routes).is_some());
        assert!(match_route("boss@EXAMPLE.COM", &routes).is_some());
        assert!(match_route("user@other.com", &routes).is_none());
    }

    #[test]
    fn test_match_regex() {
        let routes = vec![make_route(
            r"^support\+.*@example\.com$",
            InboundRouteMatchType::Regex,
            100,
            "https://hook.example.com/inbound",
        )];
        assert!(match_route("support+ticket123@example.com", &routes).is_some());
        assert!(match_route("sales@example.com", &routes).is_none());
    }

    #[test]
    fn test_match_catchall() {
        let routes = vec![make_route(
            "",
            InboundRouteMatchType::CatchAll,
            1,
            "https://hook.example.com/catch-all",
        )];
        assert!(match_route("anything@anywhere.com", &routes).is_some());
    }

    #[test]
    fn test_priority_ordering() {
        // Routes come sorted by priority DESC from the repository.
        // Higher priority routes should match first.
        let routes = vec![
            make_route(
                "admin@example.com",
                InboundRouteMatchType::Exact,
                100,
                "https://hook.example.com/admin",
            ),
            make_route(
                "example.com",
                InboundRouteMatchType::Domain,
                50,
                "https://hook.example.com/domain",
            ),
            make_route(
                "",
                InboundRouteMatchType::CatchAll,
                1,
                "https://hook.example.com/catch-all",
            ),
        ];

        // Exact match wins over domain match
        let matched = match_route("admin@example.com", &routes).unwrap();
        assert_eq!(matched.webhook_url, "https://hook.example.com/admin");

        // Domain match wins over catch-all
        let matched = match_route("user@example.com", &routes).unwrap();
        assert_eq!(matched.webhook_url, "https://hook.example.com/domain");

        // Catch-all for unmatched domains
        let matched = match_route("user@other.com", &routes).unwrap();
        assert_eq!(matched.webhook_url, "https://hook.example.com/catch-all");
    }

    #[test]
    fn test_no_routes_returns_none() {
        let routes: Vec<InboundRouteRecord> = vec![];
        assert!(match_route("anything@example.com", &routes).is_none());
    }

    #[test]
    fn test_invalid_regex_skipped() {
        let routes = vec![
            make_route(
                "[invalid(",
                InboundRouteMatchType::Regex,
                100,
                "https://hook.example.com/bad",
            ),
            make_route(
                "",
                InboundRouteMatchType::CatchAll,
                1,
                "https://hook.example.com/fallback",
            ),
        ];
        // Invalid regex is skipped, falls through to catch-all
        let matched = match_route("test@example.com", &routes).unwrap();
        assert_eq!(matched.webhook_url, "https://hook.example.com/fallback");
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// InboundEngine handler tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod engine_tests {
    use super::*;
    use bytes::Bytes;
    use chrono::Utc;
    use sentio_core::config::LlmConfig;
    use sentio_core::error::SentioError;
    use sentio_core::ids::InboundRouteDeliveryLogId;
    use sentio_core::ids::{InboundRouteId, MessageEventId};
    use sentio_core::inbound::InboundRouteMatchType;
    use sentio_core::traits::{
        AssignedFid, BlobStore, EventFilter, InboundRouteDeliveryLogRecord,
        InboundRouteDeliveryLogRepository, InboundRouteRecord, InboundRouteRepository,
        InboundRouteUpdate, MessageEventRecord, MessageEventRepository, MessageFilter,
        MessageRecord, MessageRepository, NewInboundRoute, NewInboundRouteDeliveryLog, NewMessage,
        NewMessageEvent, StatusCount, UploadResult,
    };
    use sentio_llm::LlmBackend;
    use sentio_queue::consumer::{HandlerResult, MessageHandler, MessageHeaders, QueueMessage};
    use std::sync::{Arc, Mutex};

    // ── Mock InboundRouteRepository ──────────────────────────────────────

    #[derive(Clone)]
    struct MockRouteRepo {
        routes: Vec<InboundRouteRecord>,
    }

    impl MockRouteRepo {
        fn with_routes(routes: Vec<InboundRouteRecord>) -> Self {
            Self { routes }
        }

        fn empty() -> Self {
            Self { routes: vec![] }
        }
    }

    impl InboundRouteRepository for MockRouteRepo {
        async fn create(&self, _route: NewInboundRoute) -> Result<InboundRouteId, SentioError> {
            unimplemented!()
        }
        async fn get(&self, _id: InboundRouteId) -> Result<InboundRouteRecord, SentioError> {
            unimplemented!()
        }
        async fn list_by_tenant(
            &self,
            _tenant_id: TenantId,
        ) -> Result<Vec<InboundRouteRecord>, SentioError> {
            Ok(self.routes.clone())
        }
        async fn update(
            &self,
            _id: InboundRouteId,
            _update: InboundRouteUpdate,
        ) -> Result<(), SentioError> {
            unimplemented!()
        }
        async fn delete(&self, _id: InboundRouteId) -> Result<(), SentioError> {
            unimplemented!()
        }
    }

    // ── Mock MessageEventRepository ──────────────────────────────────────

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

        fn events(&self) -> Vec<NewMessageEvent> {
            self.inserted.lock().unwrap().clone()
        }
    }

    impl MessageEventRepository for MockEventRepo {
        async fn insert(&self, event: NewMessageEvent) -> Result<MessageEventId, SentioError> {
            self.inserted.lock().unwrap().push(event);
            Ok(MessageEventId(Uuid::new_v4()))
        }
        async fn list_by_message(
            &self,
            _id: MessageId,
        ) -> Result<Vec<MessageEventRecord>, SentioError> {
            unimplemented!()
        }
        async fn list_by_tenant(
            &self,
            _tid: TenantId,
            _f: EventFilter,
        ) -> Result<Vec<MessageEventRecord>, SentioError> {
            unimplemented!()
        }
    }

    // ── Mock BlobStore ───────────────────────────────────────────────────

    #[derive(Clone)]
    struct MockBlobStore {
        eml_data: Arc<Mutex<Option<Bytes>>>,
    }

    impl MockBlobStore {
        fn with_eml(eml: &[u8]) -> Self {
            Self {
                eml_data: Arc::new(Mutex::new(Some(Bytes::copy_from_slice(eml)))),
            }
        }

        fn failing() -> Self {
            Self {
                eml_data: Arc::new(Mutex::new(None)),
            }
        }
    }

    impl BlobStore for MockBlobStore {
        async fn assign(&self) -> Result<AssignedFid, SentioError> {
            unimplemented!()
        }
        async fn upload(
            &self,
            _fid: &str,
            _data: Bytes,
            _filename: &str,
            _content_type: &str,
        ) -> Result<UploadResult, SentioError> {
            unimplemented!()
        }
        async fn download(&self, _fid: &str) -> Result<Bytes, SentioError> {
            match &*self.eml_data.lock().unwrap() {
                Some(data) => Ok(data.clone()),
                None => Err(SentioError::Storage("blob not found".into())),
            }
        }
        async fn delete(&self, _fid: &str) -> Result<(), SentioError> {
            unimplemented!()
        }
    }

    // ── Mock MessageRepository ──────────────────────────────────────────

    #[derive(Clone)]
    struct MockMessageRepo {
        classifications: Arc<Mutex<Vec<(MessageId, String, String)>>>,
    }

    impl MockMessageRepo {
        fn new() -> Self {
            Self {
                classifications: Arc::new(Mutex::new(vec![])),
            }
        }

        fn classifications(&self) -> Vec<(MessageId, String, String)> {
            self.classifications.lock().unwrap().clone()
        }
    }

    impl MessageRepository for MockMessageRepo {
        async fn insert(&self, _msg: NewMessage) -> Result<MessageId, SentioError> {
            unimplemented!()
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
            Ok(())
        }
        async fn set_bounced(&self, _id: MessageId) -> Result<(), SentioError> {
            Ok(())
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
        ) -> Result<Vec<StatusCount>, SentioError> {
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
            id: MessageId,
            category: &str,
            summary: &str,
        ) -> Result<(), SentioError> {
            self.classifications.lock().unwrap().push((
                id,
                category.to_string(),
                summary.to_string(),
            ));
            Ok(())
        }
    }

    // ── Mock InboundRouteDeliveryLogRepository ───────────────────────────

    #[derive(Clone, Default)]
    struct MockDeliveryLogRepo;

    impl MockDeliveryLogRepo {
        fn new() -> Self {
            Self
        }
    }

    impl InboundRouteDeliveryLogRepository for MockDeliveryLogRepo {
        async fn insert(
            &self,
            _log: NewInboundRouteDeliveryLog,
        ) -> Result<InboundRouteDeliveryLogId, SentioError> {
            Ok(InboundRouteDeliveryLogId(Uuid::new_v4()))
        }

        async fn list_by_route(
            &self,
            _inbound_route_id: InboundRouteId,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<InboundRouteDeliveryLogRecord>, SentioError> {
            Ok(vec![])
        }

        async fn list_by_tenant(
            &self,
            _tenant_id: TenantId,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<InboundRouteDeliveryLogRecord>, SentioError> {
            Ok(vec![])
        }

        async fn has_prior_success(
            &self,
            _inbound_route_id: InboundRouteId,
            _message_id: MessageId,
            _recipient: &str,
        ) -> Result<bool, SentioError> {
            Ok(false)
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    fn test_tenant_id() -> TenantId {
        TenantId(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap())
    }

    fn test_message_id() -> MessageId {
        MessageId(Uuid::now_v7())
    }

    fn make_route_record(llm_classify: bool, auto_respond: bool) -> InboundRouteRecord {
        InboundRouteRecord {
            id: InboundRouteId(Uuid::new_v4()),
            tenant_id: test_tenant_id(),
            pattern: "example.com".to_string(),
            match_type: InboundRouteMatchType::Domain,
            webhook_url: String::new(),
            priority: 100,
            llm_classify,
            auto_respond,
            auto_respond_config: None,
            created_at: Utc::now(),
        }
    }

    fn llm_config(enabled: bool, classify_inbound: bool) -> LlmConfig {
        LlmConfig {
            enabled,
            classify_inbound,
            ..Default::default()
        }
    }

    fn sample_eml() -> Vec<u8> {
        b"From: sender@example.com\r\n\
To: rcpt@example.com\r\n\
Subject: Test\r\n\
Date: Thu, 01 Jan 2025 00:00:00 +0000\r\n\
Message-ID: <test@example.com>\r\n\
\r\n\
Hello, this is a test message.\r\n"
            .to_vec()
    }

    fn make_payload(message_id: MessageId) -> InboundPayload {
        InboundPayload {
            message_id: message_id.0.to_string(),
            tenant_id: test_tenant_id().0.to_string(),
            domain_id: Uuid::new_v4().to_string(),
            envelope_from: "sender@example.com".to_string(),
            envelope_to: vec!["rcpt@example.com".to_string()],
            raw_eml_key: "1,abc123".to_string(),
            spam_score: Some(3.5),
            spam_action: Some("accept".to_string()),
            queued_at: None,
            dsn_ret: None,
            dsn_envid: None,
            dsn_notify: serde_json::Value::Null,
            dsn_orcpt: serde_json::Value::Null,
            llm_category: None,
            llm_summary: None,
            in_reply_to: None,
            references: Vec::new(),
            auto_submitted: None,
            list_id: None,
            precedence: None,
        }
    }

    fn queue_message(payload: &InboundPayload) -> QueueMessage {
        QueueMessage {
            body: serde_json::to_vec(payload).unwrap(),
            headers: MessageHeaders::default(),
        }
    }

    fn make_engine(
        route_repo: MockRouteRepo,
        event_repo: MockEventRepo,
        blob_store: MockBlobStore,
        llm_config: LlmConfig,
    ) -> InboundEngine<
        MockRouteRepo,
        MockEventRepo,
        MockBlobStore,
        MockMessageRepo,
        MockDeliveryLogRepo,
    > {
        InboundEngine::new(
            Arc::new(route_repo),
            Arc::new(event_repo),
            Arc::new(blob_store),
            Arc::new(MockMessageRepo::new()),
            Arc::new(MockDeliveryLogRepo::new()),
            Arc::new(LlmBackend::Noop(sentio_llm::NoopLlmProvider)),
            Arc::new(llm_config),
        )
    }

    // ── Test cases ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn no_routes_acks_message() {
        let event_repo = MockEventRepo::new();
        let engine = make_engine(
            MockRouteRepo::empty(),
            event_repo.clone(),
            MockBlobStore::failing(),
            llm_config(false, false),
        );

        let payload = make_payload(test_message_id());
        let result = engine.handle(queue_message(&payload)).await;
        assert!(matches!(result, HandlerResult::Ack));
        assert!(event_repo.events().is_empty());
    }

    #[tokio::test]
    async fn llm_classify_runs_when_enabled() {
        let event_repo = MockEventRepo::new();
        let message_repo = MockMessageRepo::new();
        let route_repo = MockRouteRepo::with_routes(vec![make_route_record(true, false)]);
        let blob_store = MockBlobStore::with_eml(&sample_eml());

        let engine = InboundEngine::new(
            Arc::new(route_repo),
            Arc::new(event_repo.clone()),
            Arc::new(blob_store),
            Arc::new(message_repo.clone()),
            Arc::new(MockDeliveryLogRepo::new()),
            Arc::new(LlmBackend::Noop(sentio_llm::NoopLlmProvider)),
            Arc::new(llm_config(true, true)),
        );

        let payload = make_payload(test_message_id());
        let result = engine.handle(queue_message(&payload)).await;
        assert!(matches!(result, HandlerResult::Ack));

        // Noop provider returns Other - should still log a classification event
        let events = event_repo.events();
        assert_eq!(events.len(), 1, "expected 1 classification event");
        let evt = &events[0];
        assert!(
            evt.smtp_response
                .as_ref()
                .unwrap()
                .contains("LLM classification"),
            "event should describe LLM classification"
        );
        assert!(
            evt.diagnostic_code.as_ref().unwrap().contains("category="),
            "diagnostic should contain category"
        );

        // Verify classification was also written to messages table
        let classifications = message_repo.classifications();
        assert_eq!(
            classifications.len(),
            1,
            "expected 1 classification update on message"
        );
        assert!(
            !classifications[0].1.is_empty(),
            "category should not be empty"
        );
    }

    #[tokio::test]
    async fn llm_classify_skipped_when_config_disabled() {
        let event_repo = MockEventRepo::new();
        let route_repo = MockRouteRepo::with_routes(vec![make_route_record(true, false)]);
        let blob_store = MockBlobStore::with_eml(&sample_eml());

        // llm_config.enabled = false
        let engine = make_engine(
            route_repo,
            event_repo.clone(),
            blob_store,
            llm_config(false, true),
        );

        let payload = make_payload(test_message_id());
        let result = engine.handle(queue_message(&payload)).await;
        assert!(matches!(result, HandlerResult::Ack));
        assert!(
            event_repo.events().is_empty(),
            "no events when LLM disabled"
        );
    }

    #[tokio::test]
    async fn llm_classify_skipped_when_classify_inbound_false() {
        let event_repo = MockEventRepo::new();
        let route_repo = MockRouteRepo::with_routes(vec![make_route_record(true, false)]);
        let blob_store = MockBlobStore::with_eml(&sample_eml());

        // llm_config.classify_inbound = false
        let engine = make_engine(
            route_repo,
            event_repo.clone(),
            blob_store,
            llm_config(true, false),
        );

        let payload = make_payload(test_message_id());
        let result = engine.handle(queue_message(&payload)).await;
        assert!(matches!(result, HandlerResult::Ack));
        assert!(
            event_repo.events().is_empty(),
            "no events when classify_inbound=false"
        );
    }

    #[tokio::test]
    async fn llm_classify_skipped_when_route_flag_false() {
        let event_repo = MockEventRepo::new();
        // route.llm_classify = false
        let route_repo = MockRouteRepo::with_routes(vec![make_route_record(false, false)]);
        let blob_store = MockBlobStore::with_eml(&sample_eml());

        let engine = make_engine(
            route_repo,
            event_repo.clone(),
            blob_store,
            llm_config(true, true),
        );

        let payload = make_payload(test_message_id());
        let result = engine.handle(queue_message(&payload)).await;
        assert!(matches!(result, HandlerResult::Ack));
        assert!(
            event_repo.events().is_empty(),
            "no events when route.llm_classify=false"
        );
    }

    #[tokio::test]
    async fn llm_classify_graceful_on_blob_failure() {
        let event_repo = MockEventRepo::new();
        let route_repo = MockRouteRepo::with_routes(vec![make_route_record(true, false)]);
        let blob_store = MockBlobStore::failing();

        let engine = InboundEngine::new(
            Arc::new(route_repo),
            Arc::new(event_repo.clone()),
            Arc::new(blob_store),
            Arc::new(MockMessageRepo::new()),
            Arc::new(MockDeliveryLogRepo::new()),
            Arc::new(LlmBackend::Noop(sentio_llm::NoopLlmProvider)),
            Arc::new(llm_config(true, true)),
        );

        let payload = make_payload(test_message_id());
        let result = engine.handle(queue_message(&payload)).await;
        assert!(
            matches!(result, HandlerResult::Ack),
            "should ack even when blob download fails"
        );
        assert!(
            event_repo.events().is_empty(),
            "no classification event when EML download fails"
        );
    }

    #[tokio::test]
    async fn classification_does_not_modify_spam_score() {
        // This is the key behavioral test: the LLM classification event
        // should log category/reasoning but never touch spam_score.
        let event_repo = MockEventRepo::new();
        let route_repo = MockRouteRepo::with_routes(vec![make_route_record(true, false)]);
        let blob_store = MockBlobStore::with_eml(&sample_eml());

        let engine = InboundEngine::new(
            Arc::new(route_repo),
            Arc::new(event_repo.clone()),
            Arc::new(blob_store),
            Arc::new(MockMessageRepo::new()),
            Arc::new(MockDeliveryLogRepo::new()),
            Arc::new(LlmBackend::Noop(sentio_llm::NoopLlmProvider)),
            Arc::new(llm_config(true, true)),
        );

        let payload = make_payload(test_message_id());
        let result = engine.handle(queue_message(&payload)).await;
        assert!(matches!(result, HandlerResult::Ack));

        // Verify the event describes content classification, not score adjustment
        let events = event_repo.events();
        assert_eq!(events.len(), 1);
        let evt = &events[0];
        let resp = evt.smtp_response.as_ref().unwrap();
        assert!(
            !resp.contains("score"),
            "classification event should not mention score adjustment: {resp}"
        );
        assert!(
            resp.contains("category="),
            "classification event should describe category: {resp}"
        );
    }

    #[tokio::test]
    async fn invalid_payload_rejects() {
        let engine = make_engine(
            MockRouteRepo::empty(),
            MockEventRepo::new(),
            MockBlobStore::failing(),
            llm_config(false, false),
        );

        let msg = QueueMessage {
            body: b"not valid json".to_vec(),
            headers: MessageHeaders::default(),
        };
        let result = engine.handle(msg).await;
        assert!(matches!(result, HandlerResult::Reject));
    }
}
