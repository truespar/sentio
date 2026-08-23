use std::sync::Arc;

use chrono::Utc;
use sentio_auth::{dkim_sign, select_signing_key, Authenticator};
use sentio_core::config::DeliveryConfig;
use sentio_core::error::{SentioError, SmtpError};
use sentio_core::event::{BounceClass, EventType};
use sentio_core::message::{
    DomainId, MessageDirection, MessageId, MessageStatus, SuppressionReason,
};
use sentio_core::tenant::TenantId;
use sentio_core::traits::{
    BlobStore, DkimKeyRepository, DomainRepository, MessageEventRepository, MessageRepository,
    NewMessage, NewMessageEvent, NewSuppression, SuppressionRepository, TenantRepository,
};

/// Helper to create an SentioError::Smtp from a message string.
fn smtp_err(msg: impl Into<String>) -> SentioError {
    SentioError::Smtp(SmtpError {
        code: 0,
        enhanced: None,
        message: msg.into(),
    })
}
use sentio_queue::consumer::{HandlerResult, MessageHandler, QueueMessage};
use sentio_queue::producer::{PublishHeaders, QueuePublisher};
use sentio_queue::retry::RetryPolicy;
use sentio_queue::topology::EXCHANGE_SUBMIT;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::connection::{ConnectionConfig, SmtpConnection, SmtpResponse};
use crate::dns::{resolve_mx, MxHost};
use crate::headers::{classify_bounce, generate_dsn, DsnParams};
use crate::pool::ConnectionPool;
use crate::tls::{build_client_config, evaluate_tls_policy, starttls_upgrade, TlsPolicy};
use sentio_core::verp::VerpCodec;

// ──────────────────────────────────────────────────────────────────────────────
// Delivery outcome
// ──────────────────────────────────────────────────────────────────────────────

/// Outcome of a single delivery attempt.
#[derive(Debug, Clone)]
pub enum DeliveryOutcome {
    Delivered {
        response: String,
        remote_mta: String,
    },
    Deferred {
        response: String,
        remote_mta: String,
        bounce_class: BounceClass,
        retry_count: u32,
        next_retry_at: chrono::DateTime<Utc>,
    },
    Bounced {
        response: String,
        remote_mta: String,
        bounce_class: BounceClass,
    },
    Suppressed {
        reason: String,
    },
}

// ──────────────────────────────────────────────────────────────────────────────
// Outbound message (deserialized from queue)
// ──────────────────────────────────────────────────────────────────────────────

/// A message deserialized from the outbound queue for delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundMessage {
    pub message_id: String,
    pub tenant_id: String,
    pub domain_id: Option<String>,
    pub envelope_from: String,
    pub envelope_to: Vec<String>,
    pub raw_eml_key: String,
    /// True when this message is being forwarded/relayed (triggers ARC sealing).
    #[serde(default)]
    pub is_forward: bool,
    /// Authentication-Results header from the receiving hop, used for ARC sealing.
    #[serde(default)]
    pub auth_results: Option<String>,
    /// RFC 3461 DSN RET parameter ("FULL" or "HDRS").
    #[serde(default)]
    pub dsn_ret: Option<String>,
    /// RFC 3461 DSN ENVID parameter.
    #[serde(default)]
    pub dsn_envid: Option<String>,
    /// RFC 3461 DSN NOTIFY per recipient: {"rcpt@example.com": "SUCCESS,FAILURE"}.
    #[serde(default)]
    pub dsn_notify: serde_json::Value,
    /// RFC 3461 DSN ORCPT per recipient: {"rcpt@example.com": "rfc822;orig@example.com"}.
    #[serde(default)]
    pub dsn_orcpt: serde_json::Value,
    /// Whether to inject open tracking pixel.
    #[serde(default)]
    pub track_opens: bool,
    /// Whether to rewrite links for click tracking.
    #[serde(default)]
    pub track_clicks: bool,
}

// ──────────────────────────────────────────────────────────────────────────────
// Delivery engine
// ──────────────────────────────────────────────────────────────────────────────

/// The outbound delivery engine that orchestrates sending messages.
pub struct DeliveryEngine<B, M, E, S, D, DR, P, T> {
    blob_store: Arc<B>,
    message_repo: Arc<M>,
    event_repo: Arc<E>,
    suppression_repo: Arc<S>,
    dkim_repo: Arc<D>,
    domain_repo: Arc<DR>,
    tenant_repo: Arc<T>,
    authenticator: Arc<Authenticator>,
    pool: Arc<ConnectionPool>,
    publisher: Arc<P>,
    config: DeliveryConfig,
    hostname: String,
    dane_enabled: bool,
    arc_sign_forward: bool,
    warmup_guard: Option<Arc<crate::warmup::WarmupGuard>>,
    /// VERP codec for rewriting MAIL FROM to a bounce return-path. When
    /// `None`, VERP is disabled instance-wide and `tenant_verp_enabled`
    /// is ignored.
    verp_codec: Option<Arc<VerpCodec>>,
}

impl<B, M, E, S, D, DR, P, T> DeliveryEngine<B, M, E, S, D, DR, P, T>
where
    B: BlobStore + 'static,
    M: MessageRepository + 'static,
    E: MessageEventRepository + 'static,
    S: SuppressionRepository + 'static,
    D: DkimKeyRepository + 'static,
    DR: DomainRepository + 'static,
    P: QueuePublisher + 'static,
    T: TenantRepository + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        blob_store: Arc<B>,
        message_repo: Arc<M>,
        event_repo: Arc<E>,
        suppression_repo: Arc<S>,
        dkim_repo: Arc<D>,
        domain_repo: Arc<DR>,
        tenant_repo: Arc<T>,
        authenticator: Arc<Authenticator>,
        pool: Arc<ConnectionPool>,
        publisher: Arc<P>,
        config: DeliveryConfig,
        hostname: String,
        dane_enabled: bool,
        arc_sign_forward: bool,
        warmup_guard: Option<Arc<crate::warmup::WarmupGuard>>,
        verp_codec: Option<Arc<VerpCodec>>,
    ) -> Self {
        Self {
            blob_store,
            message_repo,
            event_repo,
            suppression_repo,
            dkim_repo,
            domain_repo,
            tenant_repo,
            authenticator,
            pool,
            publisher,
            config,
            hostname,
            dane_enabled,
            arc_sign_forward,
            warmup_guard,
            verp_codec,
        }
    }

    /// Look up whether VERP should rewrite this tenant's MAIL FROM.
    /// Returns false on any error (best-effort - never block delivery).
    async fn tenant_verp_enabled(&self, tenant_id: TenantId) -> bool {
        if self.verp_codec.is_none() {
            return false;
        }
        match self.tenant_repo.get(tenant_id).await {
            Ok(rec) => rec.verp_enabled,
            Err(e) => {
                warn!(
                    tenant = %tenant_id,
                    error = %e,
                    "tenant lookup for VERP failed, defaulting to disabled"
                );
                false
            }
        }
    }

    /// Compute the effective MAIL FROM value for this message.
    /// When VERP is enabled for the tenant and a codec is configured,
    /// returns the rewritten `bounce+{token}@bounce.{domain}` form;
    /// otherwise returns `envelope_from` unchanged.
    fn verp_rewrite(
        &self,
        message_id: MessageId,
        envelope_from: &str,
        tenant_verp_enabled: bool,
    ) -> String {
        // Null sender (used for DSN bounce notifications themselves) is
        // preserved verbatim - re-VERP-ing a bounce would create loops.
        if envelope_from.is_empty() {
            return String::new();
        }
        match (&self.verp_codec, tenant_verp_enabled) {
            (Some(codec), true) => {
                let from_domain = envelope_from
                    .rsplit_once('@')
                    .map(|(_, d)| d)
                    .unwrap_or(&self.hostname);
                codec.encode_address(message_id.0, from_domain)
            }
            _ => envelope_from.to_string(),
        }
    }

    /// Process a single outbound message.
    /// Attempt delivery of one outbound message. Returns one
    /// `(representative_recipient, outcome)` tuple per delivery decision -
    /// per-domain-group for Delivered / Deferred / Bounced (the
    /// representative is the first recipient of that domain group), and
    /// per-recipient for Suppressed (which is decided pre-SMTP).
    /// The recipient string is what callers use to derive the per-domain
    /// retry policy when scheduling a Nak-with-delay redelivery.
    pub async fn deliver(
        &self,
        msg: &OutboundMessage,
        retry_count: u32,
        first_queued_at: Option<u64>,
    ) -> Vec<(String, DeliveryOutcome)> {
        let placeholder_rcpt = msg.envelope_to.first().cloned().unwrap_or_default();
        let tenant_id = match Uuid::parse_str(&msg.tenant_id) {
            Ok(id) => TenantId(id),
            Err(e) => {
                error!(tenant = %msg.tenant_id, error = %e, "invalid tenant_id");
                return vec![(
                    placeholder_rcpt,
                    DeliveryOutcome::Bounced {
                        response: "Invalid tenant ID".into(),
                        remote_mta: String::new(),
                        bounce_class: BounceClass::Hard,
                    },
                )];
            }
        };
        let message_id = match Uuid::parse_str(&msg.message_id) {
            Ok(id) => MessageId(id),
            Err(e) => {
                error!(message = %msg.message_id, error = %e, "invalid message_id");
                return vec![(
                    placeholder_rcpt,
                    DeliveryOutcome::Bounced {
                        response: "Invalid message ID".into(),
                        remote_mta: String::new(),
                        bounce_class: BounceClass::Hard,
                    },
                )];
            }
        };

        // 0. Warmup check - enforce daily sending limits.
        if let Some(ref guard) = self.warmup_guard {
            if let Err(e) = guard.check_and_increment(tenant_id).await {
                warn!(error = %e, "warmup limit reached, deferring message");
                return vec![(
                    placeholder_rcpt.clone(),
                    DeliveryOutcome::Deferred {
                        response: format!("Warmup limit reached: {e}"),
                        remote_mta: String::new(),
                        bounce_class: BounceClass::Soft,
                        retry_count,
                        next_retry_at: Utc::now() + chrono::Duration::minutes(30),
                    },
                )];
            }
        }

        // 1. Download raw EML from blob store.
        let raw_eml = match self.blob_store.download(&msg.raw_eml_key).await {
            Ok(data) => data,
            Err(e) => {
                error!(fid = %msg.raw_eml_key, error = %e, "failed to download EML");
                return vec![(
                    placeholder_rcpt.clone(),
                    DeliveryOutcome::Bounced {
                        response: format!("Failed to retrieve message: {e}"),
                        remote_mta: String::new(),
                        bounce_class: BounceClass::Hard,
                    },
                )];
            }
        };

        // 1b. Tracking rewrite (open pixel / click redirect) is handled at message
        //     composition time in the API layer, before DKIM signing.  The delivery
        //     pipeline operates on the already-signed EML and must not modify it.
        let raw_eml = raw_eml.to_vec();

        // 2. ARC seal if this is a forwarded message.
        let arc_eml = if msg.is_forward && self.arc_sign_forward {
            if let Some(ref domain_id_str) = msg.domain_id {
                if let Ok(domain_id_uuid) = Uuid::parse_str(domain_id_str) {
                    let domain_id = DomainId(domain_id_uuid);
                    match self
                        .arc_seal_message(&raw_eml, domain_id, msg.auth_results.as_deref())
                        .await
                    {
                        Ok(sealed) => {
                            info!(
                                message_id = %msg.message_id,
                                "ARC sealed forwarded message"
                            );
                            sealed
                        }
                        Err(e) => {
                            warn!(error = %e, "ARC sealing failed, continuing without ARC");
                            raw_eml.clone()
                        }
                    }
                } else {
                    raw_eml.clone()
                }
            } else {
                raw_eml.clone()
            }
        } else {
            raw_eml
        };

        // 3. DKIM sign if domain_id is set.
        let signed_eml = if let Some(ref domain_id_str) = msg.domain_id {
            if let Ok(domain_id_uuid) = Uuid::parse_str(domain_id_str) {
                let domain_id = DomainId(domain_id_uuid);
                match self.dkim_sign_message(&arc_eml, domain_id).await {
                    Ok(signed) => signed,
                    Err(e) => {
                        warn!(error = %e, "DKIM signing failed, sending unsigned");
                        arc_eml
                    }
                }
            } else {
                arc_eml
            }
        } else {
            arc_eml
        };

        // 4. Group recipients by destination domain.
        let grouped = group_by_domain(&msg.envelope_to);

        // 4b. Resolve VERP-rewritten envelope sender once per message.
        //     When the tenant has VERP enabled and we have a codec, this
        //     becomes `bounce+{token}@bounce.{from_domain}`; otherwise it
        //     is the original envelope_from. Note that the original sender
        //     is *not* mutated - it's still passed to record_outcome /
        //     queue_dsn so retries and bounce notifications target the
        //     real submitter, not the bounce return-path.
        let tenant_verp_enabled = self.tenant_verp_enabled(tenant_id).await;
        let mail_from = self.verp_rewrite(message_id, &msg.envelope_from, tenant_verp_enabled);
        if mail_from != msg.envelope_from {
            debug!(
                message_id = %message_id,
                original = %msg.envelope_from,
                rewritten = %mail_from,
                "VERP rewrote MAIL FROM"
            );
        }

        let mut outcomes = Vec::new();

        // 5. Per destination domain.
        for (domain, recipients) in &grouped {
            // Check suppression for each recipient.
            let mut active_rcpts = Vec::new();
            for rcpt in recipients {
                match self.suppression_repo.check(tenant_id, rcpt).await {
                    Ok(true) => {
                        debug!(rcpt, "recipient suppressed, skipping");
                        outcomes.push((
                            rcpt.clone(),
                            DeliveryOutcome::Suppressed {
                                reason: format!("{rcpt} is suppressed"),
                            },
                        ));
                    }
                    Ok(false) => active_rcpts.push(rcpt.as_str()),
                    Err(e) => {
                        warn!(rcpt, error = %e, "suppression check failed, delivering anyway");
                        active_rcpts.push(rcpt.as_str());
                    }
                }
            }

            if active_rcpts.is_empty() {
                continue;
            }

            // Deliver to this domain. NOTE: `mail_from` is the VERP-rewritten
            // envelope sender used on the SMTP wire; `msg.envelope_from` is
            // the original (used for retries, bounce DSN routing, and event
            // bookkeeping).
            let outcome = self
                .deliver_to_domain(
                    domain,
                    &mail_from,
                    &active_rcpts,
                    &signed_eml,
                    retry_count,
                    msg.dsn_ret.as_deref(),
                    msg.dsn_envid.as_deref(),
                    &msg.dsn_notify,
                    &msg.dsn_orcpt,
                )
                .await;

            // Record events and update state.
            for rcpt in &active_rcpts {
                self.record_outcome(
                    tenant_id,
                    message_id,
                    rcpt,
                    &outcome,
                    retry_count,
                    &msg.envelope_from,
                    first_queued_at,
                    msg.dsn_ret.as_deref(),
                    msg.dsn_envid.as_deref(),
                    &msg.dsn_orcpt,
                    msg,
                )
                .await;
            }

            let rep_rcpt = recipients
                .first()
                .map(|s| s.to_string())
                .unwrap_or_else(|| domain.clone());
            outcomes.push((rep_rcpt, outcome));
        }

        // Update message status based on outcomes.
        let final_status = if outcomes
            .iter()
            .all(|(_, o)| matches!(o, DeliveryOutcome::Delivered { .. }))
        {
            Some(MessageStatus::Delivered)
        } else if outcomes
            .iter()
            .any(|(_, o)| matches!(o, DeliveryOutcome::Bounced { .. }))
        {
            Some(MessageStatus::Bounced)
        } else if outcomes
            .iter()
            .any(|(_, o)| matches!(o, DeliveryOutcome::Deferred { .. }))
        {
            Some(MessageStatus::Deferred)
        } else {
            None
        };

        if let Some(status) = final_status {
            match status {
                MessageStatus::Delivered => {
                    if let Err(e) = self.message_repo.set_delivered(message_id).await {
                        error!(error = %e, "failed to set message delivered");
                    }
                }
                MessageStatus::Bounced => {
                    if let Err(e) = self.message_repo.set_bounced(message_id).await {
                        error!(error = %e, "failed to set message bounced");
                    }
                }
                _ => {
                    if let Err(e) = self.message_repo.update_status(message_id, status).await {
                        error!(error = %e, "failed to update message status");
                    }
                }
            }
        }

        outcomes
    }

    /// Deliver to all MX hosts for a given destination domain.
    async fn deliver_to_domain(
        &self,
        domain: &str,
        sender: &str,
        recipients: &[&str],
        message: &[u8],
        retry_count: u32,
        dsn_ret: Option<&str>,
        dsn_envid: Option<&str>,
        dsn_notify: &serde_json::Value,
        dsn_orcpt: &serde_json::Value,
    ) -> DeliveryOutcome {
        // If relay mode is enabled, deliver via the configured relay host.
        if self.config.relay.enabled {
            return self
                .deliver_via_relay(
                    sender,
                    recipients,
                    message,
                    retry_count,
                    dsn_ret,
                    dsn_envid,
                    dsn_notify,
                    dsn_orcpt,
                )
                .await;
        }

        // Resolve MX.
        let resolver = self.authenticator.resolver();
        let mx_result = match resolve_mx(resolver, domain).await {
            Ok(r) => r,
            Err(e) => {
                return DeliveryOutcome::Deferred {
                    response: format!("DNS resolution failed: {e}"),
                    remote_mta: String::new(),
                    bounce_class: BounceClass::Soft,
                    retry_count,
                    next_retry_at: compute_next_retry(retry_count, &self.config),
                };
            }
        };

        if mx_result.hosts.is_empty() {
            return DeliveryOutcome::Bounced {
                response: format!("No MX records for {domain}"),
                remote_mta: String::new(),
                bounce_class: BounceClass::Hard,
            };
        }

        // Evaluate TLS policy.
        let tls_req = match evaluate_tls_policy(
            &self.authenticator,
            &mx_result.hosts[0].hostname,
            domain,
            self.dane_enabled,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "TLS policy evaluation failed, using opportunistic");
                crate::tls::TlsRequirement {
                    policy: TlsPolicy::Opportunistic,
                    dane_records: vec![],
                    mta_sts_mx_patterns: vec![],
                }
            }
        };

        // Try each MX host in preference order.
        let mut last_error = None;

        for mx_host in &mx_result.hosts {
            match self
                .try_mx_host(
                    mx_host, sender, recipients, message, &tls_req, dsn_ret, dsn_envid, dsn_notify,
                    dsn_orcpt,
                )
                .await
            {
                Ok(outcome) => return outcome,
                Err(e) => {
                    warn!(
                        mx = %mx_host.hostname,
                        error = %e,
                        "MX host delivery failed, trying next"
                    );
                    last_error = Some(e.to_string());
                }
            }
        }

        // All MX hosts failed - defer.
        DeliveryOutcome::Deferred {
            response: last_error.unwrap_or_else(|| "all MX hosts unreachable".into()),
            remote_mta: mx_result
                .hosts
                .last()
                .map(|h| h.hostname.clone())
                .unwrap_or_default(),
            bounce_class: BounceClass::Soft,
            retry_count,
            next_retry_at: compute_next_retry(retry_count, &self.config),
        }
    }

    /// Deliver via a configured relay host instead of MX resolution.
    async fn deliver_via_relay(
        &self,
        sender: &str,
        recipients: &[&str],
        message: &[u8],
        retry_count: u32,
        dsn_ret: Option<&str>,
        dsn_envid: Option<&str>,
        dsn_notify: &serde_json::Value,
        dsn_orcpt: &serde_json::Value,
    ) -> DeliveryOutcome {
        let relay = &self.config.relay;
        let host = match relay.host.as_deref() {
            Some(h) => h,
            None => {
                return DeliveryOutcome::Bounced {
                    response: "Relay enabled but no host configured".into(),
                    remote_mta: String::new(),
                    bounce_class: BounceClass::Hard,
                };
            }
        };
        let port = relay.port.unwrap_or(25);
        let tls_mode = relay.tls_mode.as_deref().unwrap_or("opportunistic");

        // Resolve relay host address.
        let addr = match tokio::net::lookup_host(format!("{host}:{port}")).await {
            Ok(mut addrs) => match addrs.next() {
                Some(a) => a,
                None => {
                    return DeliveryOutcome::Deferred {
                        response: format!("No addresses found for relay host {host}"),
                        remote_mta: host.to_string(),
                        bounce_class: BounceClass::Soft,
                        retry_count,
                        next_retry_at: compute_next_retry(retry_count, &self.config),
                    };
                }
            },
            Err(e) => {
                return DeliveryOutcome::Deferred {
                    response: format!("Failed to resolve relay host {host}: {e}"),
                    remote_mta: host.to_string(),
                    bounce_class: BounceClass::Soft,
                    retry_count,
                    next_retry_at: compute_next_retry(retry_count, &self.config),
                };
            }
        };

        // Acquire pool permit.
        let _permit = self.pool.acquire_permit(host).await;

        // TCP connect with timeout.
        let conn_config = ConnectionConfig::default();
        let tcp = match tokio::time::timeout(
            conn_config.connect_timeout,
            tokio::net::TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                return DeliveryOutcome::Deferred {
                    response: format!("Relay connect error: {e}"),
                    remote_mta: host.to_string(),
                    bounce_class: BounceClass::Soft,
                    retry_count,
                    next_retry_at: compute_next_retry(retry_count, &self.config),
                };
            }
            Err(_) => {
                return DeliveryOutcome::Deferred {
                    response: "Relay connect timeout".into(),
                    remote_mta: host.to_string(),
                    bounce_class: BounceClass::Soft,
                    retry_count,
                    next_retry_at: compute_next_retry(retry_count, &self.config),
                };
            }
        };

        // Create SMTP connection.
        let (mut conn, _greeting) =
            match SmtpConnection::new(tcp, conn_config, host.to_string()).await {
                Ok(c) => c,
                Err(e) => {
                    return DeliveryOutcome::Deferred {
                        response: format!("Relay connection failed: {e}"),
                        remote_mta: host.to_string(),
                        bounce_class: BounceClass::Soft,
                        retry_count,
                        next_retry_at: compute_next_retry(retry_count, &self.config),
                    };
                }
            };

        // EHLO.
        let ehlo_resp = match conn.ehlo(&self.hostname).await {
            Ok(r) => r,
            Err(e) => {
                return DeliveryOutcome::Deferred {
                    response: format!("Relay EHLO failed: {e}"),
                    remote_mta: host.to_string(),
                    bounce_class: BounceClass::Soft,
                    retry_count,
                    next_retry_at: compute_next_retry(retry_count, &self.config),
                };
            }
        };
        if !ehlo_resp.is_success() {
            return DeliveryOutcome::Deferred {
                response: format!(
                    "Relay EHLO rejected: {} {}",
                    ehlo_resp.code,
                    ehlo_resp.full_text()
                ),
                remote_mta: host.to_string(),
                bounce_class: BounceClass::Soft,
                retry_count,
                next_retry_at: compute_next_retry(retry_count, &self.config),
            };
        }

        // STARTTLS upgrade if requested and server supports it.
        if tls_mode == "starttls" {
            let caps = conn.capabilities.clone().unwrap_or_default();
            if caps.starttls {
                let starttls_resp = match conn.starttls().await {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(error = %e, "relay STARTTLS command failed");
                        return DeliveryOutcome::Deferred {
                            response: format!("Relay STARTTLS failed: {e}"),
                            remote_mta: host.to_string(),
                            bounce_class: BounceClass::Soft,
                            retry_count,
                            next_retry_at: compute_next_retry(retry_count, &self.config),
                        };
                    }
                };
                if starttls_resp.is_success() {
                    let tls_req = crate::tls::TlsRequirement {
                        policy: TlsPolicy::Opportunistic,
                        dane_records: vec![],
                        mta_sts_mx_patterns: vec![],
                    };
                    let tls_config = match build_client_config(&tls_req) {
                        Ok(c) => c,
                        Err(e) => {
                            return DeliveryOutcome::Deferred {
                                response: format!("Relay TLS config error: {e}"),
                                remote_mta: host.to_string(),
                                bounce_class: BounceClass::Soft,
                                retry_count,
                                next_retry_at: compute_next_retry(retry_count, &self.config),
                            };
                        }
                    };
                    let (stream, _buf, conn_config, hostname) = conn.into_parts();
                    match starttls_upgrade(stream, Arc::new(tls_config), &hostname).await {
                        Ok((tls_stream, _version)) => {
                            let (mut tls_conn, _) = match SmtpConnection::new(
                                tls_stream,
                                conn_config,
                                hostname,
                            )
                            .await
                            {
                                Ok(c) => c,
                                Err(e) => {
                                    return DeliveryOutcome::Deferred {
                                        response: format!("Relay TLS connection failed: {e}"),
                                        remote_mta: host.to_string(),
                                        bounce_class: BounceClass::Soft,
                                        retry_count,
                                        next_retry_at: compute_next_retry(
                                            retry_count,
                                            &self.config,
                                        ),
                                    };
                                }
                            };
                            let ehlo_resp = match tls_conn.ehlo(&self.hostname).await {
                                Ok(r) => r,
                                Err(e) => {
                                    return DeliveryOutcome::Deferred {
                                        response: format!("Relay post-TLS EHLO failed: {e}"),
                                        remote_mta: host.to_string(),
                                        bounce_class: BounceClass::Soft,
                                        retry_count,
                                        next_retry_at: compute_next_retry(
                                            retry_count,
                                            &self.config,
                                        ),
                                    };
                                }
                            };
                            if !ehlo_resp.is_success() {
                                return DeliveryOutcome::Deferred {
                                    response: "Relay post-TLS EHLO rejected".into(),
                                    remote_mta: host.to_string(),
                                    bounce_class: BounceClass::Soft,
                                    retry_count,
                                    next_retry_at: compute_next_retry(retry_count, &self.config),
                                };
                            }
                            // Send over TLS connection.
                            return match self
                                .send_message(
                                    &mut tls_conn,
                                    sender,
                                    recipients,
                                    message,
                                    host,
                                    dsn_ret,
                                    dsn_envid,
                                    dsn_notify,
                                    dsn_orcpt,
                                )
                                .await
                            {
                                Ok(outcome) => outcome,
                                Err(e) => DeliveryOutcome::Deferred {
                                    response: format!("Relay TLS send failed: {e}"),
                                    remote_mta: host.to_string(),
                                    bounce_class: BounceClass::Soft,
                                    retry_count,
                                    next_retry_at: compute_next_retry(retry_count, &self.config),
                                },
                            };
                        }
                        Err(e) => {
                            return DeliveryOutcome::Deferred {
                                response: format!("Relay STARTTLS upgrade failed: {e}"),
                                remote_mta: host.to_string(),
                                bounce_class: BounceClass::Soft,
                                retry_count,
                                next_retry_at: compute_next_retry(retry_count, &self.config),
                            };
                        }
                    }
                }
                // STARTTLS response not success - fall through to send without TLS.
            }
            // Server doesn't support STARTTLS - fall through to send without TLS.
        }

        // Send without TLS (tls_mode == "none" or STARTTLS unavailable).
        match self
            .send_message(
                &mut conn, sender, recipients, message, host, dsn_ret, dsn_envid, dsn_notify,
                dsn_orcpt,
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(e) => DeliveryOutcome::Deferred {
                response: format!("Relay send failed: {e}"),
                remote_mta: host.to_string(),
                bounce_class: BounceClass::Soft,
                retry_count,
                next_retry_at: compute_next_retry(retry_count, &self.config),
            },
        }
    }

    /// Try delivering to a single MX host.
    async fn try_mx_host(
        &self,
        mx_host: &MxHost,
        sender: &str,
        recipients: &[&str],
        message: &[u8],
        tls_req: &crate::tls::TlsRequirement,
        dsn_ret: Option<&str>,
        dsn_envid: Option<&str>,
        dsn_notify: &serde_json::Value,
        dsn_orcpt: &serde_json::Value,
    ) -> Result<DeliveryOutcome, SentioError> {
        if mx_host.addresses.is_empty() {
            return Err(smtp_err(format!(
                "no addresses for MX host {}",
                mx_host.hostname
            )));
        }

        let addr = mx_host.addresses[0];
        let socket_addr = std::net::SocketAddr::new(addr, 25);

        debug!(
            mx = %mx_host.hostname,
            addr = %socket_addr,
            all_addrs = ?mx_host.addresses,
            "connecting to MX host"
        );

        // Acquire pool permit.
        let _permit = self.pool.acquire_permit(&mx_host.hostname).await;

        // TCP connect with timeout.
        let conn_config = ConnectionConfig::default();
        let tcp = tokio::time::timeout(
            conn_config.connect_timeout,
            tokio::net::TcpStream::connect(socket_addr),
        )
        .await
        .map_err(|_| smtp_err("connect timeout"))?
        .map_err(|e| smtp_err(format!("connect error: {e}")))?;

        debug!(mx = %mx_host.hostname, "TCP connected, reading greeting");

        // Create SMTP connection.
        let (mut conn, _greeting) =
            SmtpConnection::new(tcp, conn_config, mx_host.hostname.clone()).await?;

        debug!(mx = %mx_host.hostname, greeting = %_greeting.code, "greeting received");

        // EHLO.
        let ehlo_resp = conn.ehlo(&self.hostname).await?;
        if !ehlo_resp.is_success() {
            return Err(smtp_err(format!(
                "EHLO rejected: {} {}",
                ehlo_resp.code,
                ehlo_resp.full_text()
            )));
        }

        // STARTTLS if server supports it.
        let caps = conn.capabilities.clone().unwrap_or_default();
        if caps.starttls {
            let starttls_resp = conn.starttls().await?;
            if starttls_resp.is_success() {
                let tls_config = build_client_config(tls_req)
                    .map_err(|e| smtp_err(format!("TLS config error: {e}")))?;
                let (stream, read_buf, conn_config, hostname) = conn.into_parts();

                match starttls_upgrade(stream, Arc::new(tls_config), &hostname).await {
                    Ok((tls_stream, _version)) => {
                        // RFC 3207: after STARTTLS, the server does NOT send a new greeting.
                        // Use from_upgraded to skip greeting read.
                        let mut tls_conn = SmtpConnection::from_upgraded(
                            tls_stream,
                            read_buf,
                            conn_config,
                            hostname,
                        );
                        let ehlo_resp = tls_conn.ehlo(&self.hostname).await?;
                        if !ehlo_resp.is_success() {
                            return Err(smtp_err("EHLO after TLS rejected"));
                        }

                        return self
                            .send_message(
                                &mut tls_conn,
                                sender,
                                recipients,
                                message,
                                &mx_host.hostname,
                                dsn_ret,
                                dsn_envid,
                                dsn_notify,
                                dsn_orcpt,
                            )
                            .await;
                    }
                    Err(e) => {
                        if tls_req.policy == TlsPolicy::Required
                            || tls_req.policy == TlsPolicy::Dane
                        {
                            return Err(e);
                        }
                        // Opportunistic: TLS handshake failed (bad cipher, protocol
                        // mismatch, etc.).  The TCP stream is now unusable - try
                        // the next MX host rather than deferring the message.
                        warn!(
                            mx = mx_host.hostname,
                            error = %e,
                            "opportunistic TLS handshake failed, skipping MX host"
                        );
                        return Err(e);
                    }
                }
            } else if tls_req.policy == TlsPolicy::Required || tls_req.policy == TlsPolicy::Dane {
                return Err(smtp_err("STARTTLS required but server rejected it"));
            }
        } else if tls_req.policy == TlsPolicy::Required || tls_req.policy == TlsPolicy::Dane {
            return Err(smtp_err(
                "TLS required but server does not support STARTTLS",
            ));
        }

        // Send without TLS (opportunistic mode, STARTTLS unavailable).
        self.send_message(
            &mut conn,
            sender,
            recipients,
            message,
            &mx_host.hostname,
            dsn_ret,
            dsn_envid,
            dsn_notify,
            dsn_orcpt,
        )
        .await
    }

    /// Send the message over an established connection.
    /// When the remote server advertises DSN support, RFC 3461 params are forwarded.
    async fn send_message<ST: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send>(
        &self,
        conn: &mut SmtpConnection<ST>,
        sender: &str,
        recipients: &[&str],
        message: &[u8],
        remote_mta: &str,
        dsn_ret: Option<&str>,
        dsn_envid: Option<&str>,
        dsn_notify: &serde_json::Value,
        dsn_orcpt: &serde_json::Value,
    ) -> Result<DeliveryOutcome, SentioError> {
        let server_dsn = conn.capabilities.as_ref().is_some_and(|c| c.dsn);

        // MAIL FROM - include DSN params if the server supports DSN.
        let mail_resp = if server_dsn && (dsn_ret.is_some() || dsn_envid.is_some()) {
            conn.mail_from_with_dsn(sender, Some(message.len() as u64), dsn_ret, dsn_envid)
                .await?
        } else {
            conn.mail_from(sender, Some(message.len() as u64)).await?
        };
        if !mail_resp.is_success() {
            return Ok(classify_response(&mail_resp, remote_mta));
        }

        // RCPT TO - include per-recipient DSN params if the server supports DSN.
        for rcpt in recipients {
            let rcpt_resp = if server_dsn {
                let notify = dsn_notify.get(*rcpt).and_then(|v| v.as_str());
                let orcpt = dsn_orcpt.get(*rcpt).and_then(|v| v.as_str());
                if notify.is_some() || orcpt.is_some() {
                    conn.rcpt_to_with_dsn(rcpt, notify, orcpt).await?
                } else {
                    conn.rcpt_to(rcpt).await?
                }
            } else {
                conn.rcpt_to(rcpt).await?
            };
            if !rcpt_resp.is_success() {
                // If RCPT TO fails, classify and return.
                let _ = conn.rset().await;
                return Ok(classify_response(&rcpt_resp, remote_mta));
            }
        }

        // DATA.
        let data_resp = conn.data(message).await?;
        let _ = conn.quit().await;

        Ok(classify_response(&data_resp, remote_mta))
    }

    /// DKIM sign a message with all active keys (dual signing).
    async fn dkim_sign_message(
        &self,
        raw_eml: &[u8],
        domain_id: DomainId,
    ) -> Result<Vec<u8>, SentioError> {
        // Look up domain name for DKIM.
        let domain_record = self.domain_repo.get(domain_id).await?;
        let domain_name = &domain_record.domain_name;

        // Get all active DKIM keys.
        let keys = self.dkim_repo.list_by_domain(domain_id).await?;
        let active_keys: Vec<&_> = keys
            .iter()
            .filter(|k| k.status == sentio_core::auth::DkimKeyStatus::Active)
            .collect();

        if active_keys.is_empty() {
            return Err(SentioError::Auth("no active DKIM key found".into()));
        }

        let headers = &[
            "From",
            "To",
            "Subject",
            "Date",
            "Message-ID",
            "MIME-Version",
        ];

        // Sign with every active key (dual/multi signing).
        // Prepend signatures in reverse so the preferred key (Ed25519) ends up first.
        let mut sig_headers = Vec::new();
        for key in active_keys.iter().rev() {
            let output = dkim_sign(key, domain_name, raw_eml, headers)?;
            sig_headers.push(output.header);
        }
        sig_headers.reverse();

        let total_len: usize = sig_headers.iter().map(|h| h.len()).sum::<usize>() + raw_eml.len();
        let mut signed = Vec::with_capacity(total_len);
        for hdr in &sig_headers {
            signed.extend_from_slice(hdr.as_bytes());
        }
        signed.extend_from_slice(raw_eml);
        Ok(signed)
    }

    /// ARC seal a forwarded message.
    async fn arc_seal_message(
        &self,
        raw_eml: &[u8],
        domain_id: DomainId,
        auth_results: Option<&str>,
    ) -> Result<Vec<u8>, SentioError> {
        let domain_record = self.domain_repo.get(domain_id).await?;
        let domain_name = &domain_record.domain_name;

        let keys = self.dkim_repo.list_by_domain(domain_id).await?;
        let signing_key = select_signing_key(&keys)
            .ok_or_else(|| SentioError::Auth("no active DKIM key for ARC sealing".into()))?;

        let ar_header = auth_results.unwrap_or(&self.hostname);

        let headers = &[
            "From",
            "To",
            "Subject",
            "Date",
            "Message-ID",
            "MIME-Version",
        ];
        let header_refs: Vec<&str> = headers.to_vec();

        let arc_output = self
            .authenticator
            .seal_arc(raw_eml, signing_key, domain_name, ar_header, &header_refs)
            .await?;

        let mut sealed = Vec::with_capacity(arc_output.headers.len() + raw_eml.len());
        sealed.extend_from_slice(arc_output.headers.as_bytes());
        sealed.extend_from_slice(raw_eml);
        Ok(sealed)
    }

    /// Record the outcome as a message event.
    async fn record_outcome(
        &self,
        tenant_id: TenantId,
        message_id: MessageId,
        recipient: &str,
        outcome: &DeliveryOutcome,
        retry_count: u32,
        sender: &str,
        first_queued_at: Option<u64>,
        dsn_ret: Option<&str>,
        dsn_envid: Option<&str>,
        dsn_orcpt: &serde_json::Value,
        outbound_msg: &OutboundMessage,
    ) {
        let (event_type, smtp_response, remote_mta, bounce_class, next_retry) = match outcome {
            DeliveryOutcome::Delivered {
                response,
                remote_mta,
            } => (
                EventType::Delivered,
                Some(response.clone()),
                Some(remote_mta.clone()),
                None,
                None,
            ),
            DeliveryOutcome::Deferred {
                response,
                remote_mta,
                bounce_class,
                next_retry_at,
                ..
            } => (
                EventType::Deferred,
                Some(response.clone()),
                Some(remote_mta.clone()),
                Some(*bounce_class),
                Some(*next_retry_at),
            ),
            DeliveryOutcome::Bounced {
                response,
                remote_mta,
                bounce_class,
            } => (
                EventType::Bounced,
                Some(response.clone()),
                Some(remote_mta.clone()),
                Some(*bounce_class),
                None,
            ),
            DeliveryOutcome::Suppressed { reason } => {
                (EventType::Dropped, Some(reason.clone()), None, None, None)
            }
        };

        // Clone strings before moving into the event struct (needed for webhook payload below).
        let smtp_response_str = smtp_response.clone();
        let remote_mta_str = remote_mta.clone();

        let event = NewMessageEvent {
            message_id,
            tenant_id,
            event_type,
            smtp_response,
            remote_mta,
            diagnostic_code: None,
            bounce_class,
            retry_count: Some(retry_count as i32),
            next_retry_at: next_retry,
            source_ip: None,
            destination_ip: None,
            tls_version: None,
        };

        if let Err(e) = self.event_repo.insert(event).await {
            error!(error = %e, "failed to record delivery event");
        }

        // Publish event to the events exchange for webhook + analytics consumers.
        let webhook_event = serde_json::json!({
            "tenant_id": tenant_id.to_string(),
            "event_type": event_type.to_string(),
            "message_id": message_id.to_string(),
            "payload": {
                "recipient": recipient,
                "envelope_to": [recipient],
                "smtp_response": smtp_response_str,
                "remote_mta": remote_mta_str,
                "bounce_class": bounce_class.map(|b| b.to_string()),
                "diagnostic_code": serde_json::Value::Null,
                "retry_count": retry_count,
            },
            "occurred_at": chrono::Utc::now().to_rfc3339(),
        });
        let routing_key = format!("event.{event_type}");
        if let Ok(body) = serde_json::to_vec(&webhook_event) {
            let headers = PublishHeaders {
                message_id: Some(message_id.to_string()),
                tenant_id: Some(tenant_id.to_string()),
                ..Default::default()
            };
            if let Err(e) = self
                .publisher
                .publish(sentio_queue::EXCHANGE_EVENTS, &routing_key, &body, headers)
                .await
            {
                warn!(error = %e, "failed to publish event to events exchange");
            }
        }

        // Handle bounce: add suppression for hard bounces.
        if let DeliveryOutcome::Bounced { bounce_class, .. } = outcome {
            if *bounce_class == BounceClass::Hard {
                let suppression = NewSuppression {
                    tenant_id,
                    email: recipient.to_string(),
                    reason: SuppressionReason::HardBounce,
                    source_event_id: None,
                };
                if let Err(e) = self.suppression_repo.add(suppression).await {
                    error!(error = %e, rcpt = recipient, "failed to add suppression");
                }

                // Generate and queue DSN - only for non-null senders to prevent loops
                // (RFC 3464 §3: DSNs for null-sender messages must not be generated).
                if !sender.is_empty() {
                    // Build per-recipient ORCPT map for this bounce.
                    let mut orcpt_map = std::collections::HashMap::new();
                    if let Some(orcpt_val) = dsn_orcpt.get(recipient).and_then(|v| v.as_str()) {
                        orcpt_map.insert(recipient.to_string(), orcpt_val.to_string());
                    }
                    let dsn_params = DsnParams {
                        original_from: sender.to_string(),
                        original_to: vec![recipient.to_string()],
                        reporting_mta: self.hostname.clone(),
                        remote_response: match outcome {
                            DeliveryOutcome::Bounced { response, .. } => response.clone(),
                            _ => String::new(),
                        },
                        remote_mta: match outcome {
                            DeliveryOutcome::Bounced { remote_mta, .. } => Some(remote_mta.clone()),
                            _ => None,
                        },
                        bounce_class: *bounce_class,
                        arrival_date: Utc::now(),
                        original_message_id: None,
                        original_envid: dsn_envid.map(|s| s.to_string()),
                        original_ret: dsn_ret.map(|s| s.to_string()),
                        original_orcpt: orcpt_map,
                    };
                    let dsn_bytes = generate_dsn(&dsn_params);
                    self.queue_dsn(tenant_id, sender, &dsn_bytes).await;
                } else {
                    debug!(
                        rcpt = recipient,
                        "skipping DSN for null sender (loop prevention)"
                    );
                }
            }
        }

        // Deferral is handled at the handler level (see `MessageHandler::handle`)
        // by returning `HandlerResult::RetryAfter(delay)` and letting JetStream
        // Nak-with-delay redeliver the same message. We do NOT republish here:
        // doing so creates duplicate copies in the consumer's pending window
        // and causes the recipient to receive the message multiple times once
        // the transient failure resolves.
        let _ = (retry_count, first_queued_at, outbound_msg);
    }

    /// Upload a DSN to blob store and publish it as a new outbound message.
    /// The envelope sender is set to empty string (null sender per RFC 3464).
    async fn queue_dsn(&self, tenant_id: TenantId, original_sender: &str, dsn_bytes: &[u8]) {
        // 1. Upload DSN to blob store
        let assigned = match self.blob_store.assign().await {
            Ok(a) => a,
            Err(e) => {
                error!(error = %e, "failed to assign blob FID for DSN");
                return;
            }
        };

        let upload_result = match self
            .blob_store
            .upload(
                &assigned.fid,
                bytes::Bytes::copy_from_slice(dsn_bytes),
                "dsn.eml",
                "message/rfc822",
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                error!(error = %e, "failed to upload DSN to blob store");
                return;
            }
        };

        // 2. Insert message record so delivery status updates can find it.
        let dsn_id = MessageId::new();
        let new_msg = NewMessage {
            id: dsn_id,
            tenant_id,
            domain_id: None,
            direction: MessageDirection::Outbound,
            envelope_from: String::new(),
            envelope_to: vec![original_sender.to_string()],
            header_from: None,
            header_to: vec![original_sender.to_string()],
            header_cc: vec![],
            header_reply_to: None,
            subject: Some("Delivery Status Notification".to_string()),
            message_id_header: None,
            tags: vec!["dsn".to_string()],
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

        if let Err(e) = self.message_repo.insert(new_msg).await {
            error!(error = %e, "failed to insert DSN message record");
            return;
        }

        // 3. Build outbound message with null sender (MAIL FROM:<>)
        //    DSN bounce messages carry no DSN params themselves (prevents loops).
        let dsn_msg = OutboundMessage {
            message_id: dsn_id.0.to_string(),
            tenant_id: tenant_id.0.to_string(),
            domain_id: None,
            envelope_from: String::new(), // null sender
            envelope_to: vec![original_sender.to_string()],
            raw_eml_key: upload_result.fid,
            is_forward: false,
            auth_results: None,
            dsn_ret: None,
            dsn_envid: None,
            dsn_notify: serde_json::json!({}),
            dsn_orcpt: serde_json::json!({}),
            track_opens: false,
            track_clicks: false,
        };

        // 4. Publish to queue
        let body = match serde_json::to_vec(&dsn_msg) {
            Ok(b) => b,
            Err(e) => {
                error!(error = %e, "failed to serialize DSN outbound message");
                return;
            }
        };

        let headers = PublishHeaders {
            message_id: Some(dsn_msg.message_id.clone()),
            tenant_id: Some(tenant_id.0.to_string()),
            ..Default::default()
        };

        if let Err(e) = self
            .publisher
            .publish(EXCHANGE_SUBMIT, "message.outbound.send", &body, headers)
            .await
        {
            error!(error = %e, "failed to publish DSN to queue");
        } else {
            debug!(
                to = original_sender,
                dsn_id = %dsn_id,
                "DSN queued for delivery"
            );
        }
    }

    /// Re-publish a deferred message for retry. Respects `max_retries` and
    /// `queue_lifetime_days` from config (with per-domain overrides) - when
    /// exhausted, the message is treated as a hard bounce.
    /// Compute the retry delay across a set of outcomes, using each
    /// recipient's per-domain policy. Returns the longest delay among
    /// deferred recipients (so no domain is retried sooner than its
    /// policy allows). Returns `None` if there are no deferred outcomes.
    fn deferred_retry_delay(
        &self,
        outcomes: &[(String, DeliveryOutcome)],
        retry_count: u32,
    ) -> Option<std::time::Duration> {
        let mut longest_ms: Option<u64> = None;
        for (recipient, outcome) in outcomes {
            if let DeliveryOutcome::Deferred { bounce_class, .. } = outcome {
                let domain = recipient.rsplit('@').next().unwrap_or("");
                let policy = RetryPolicy::from_delivery_config_for_domain(&self.config, domain);
                let delay_ms = policy.compute_delay_ms_with_class(retry_count, Some(*bounce_class));
                longest_ms = Some(longest_ms.map_or(delay_ms, |cur| cur.max(delay_ms)));
            }
        }
        longest_ms.map(std::time::Duration::from_millis)
    }

    /// Check whether retry budget (max attempts + queue lifetime) is exhausted
    /// for the longest-suffering deferred recipient. Returns true if every
    /// deferred outcome would be denied another retry under its own policy.
    fn retry_budget_exhausted(
        &self,
        outcomes: &[(String, DeliveryOutcome)],
        retry_count: u32,
        first_queued_at: Option<u64>,
    ) -> bool {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let queued_at = first_queued_at.unwrap_or(now_ms);
        let elapsed_ms = now_ms.saturating_sub(queued_at);

        let mut any_deferred = false;
        for (recipient, outcome) in outcomes {
            if matches!(outcome, DeliveryOutcome::Deferred { .. }) {
                any_deferred = true;
                let domain = recipient.rsplit('@').next().unwrap_or("");
                let policy = RetryPolicy::from_delivery_config_for_domain(&self.config, domain);
                if policy.should_retry(retry_count, Some(elapsed_ms)) {
                    return false; // at least one recipient can still be retried
                }
            }
        }
        any_deferred
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// MessageHandler implementation
// ──────────────────────────────────────────────────────────────────────────────

impl<B, M, E, S, D, DR, P, T> MessageHandler for DeliveryEngine<B, M, E, S, D, DR, P, T>
where
    B: BlobStore + 'static,
    M: MessageRepository + 'static,
    E: MessageEventRepository + 'static,
    S: SuppressionRepository + 'static,
    D: DkimKeyRepository + 'static,
    DR: DomainRepository + 'static,
    P: QueuePublisher + 'static,
    T: TenantRepository + 'static,
{
    async fn handle(&self, message: QueueMessage) -> HandlerResult {
        let msg: OutboundMessage = match serde_json::from_slice(&message.body) {
            Ok(m) => m,
            Err(e) => {
                error!(error = %e, "failed to deserialize outbound message");
                return HandlerResult::Reject;
            }
        };

        let retry_count = message.headers.retry_count;
        let first_queued_at = message.headers.first_queued_at;

        info!(
            message_id = %msg.message_id,
            to = ?msg.envelope_to,
            "processing outbound delivery"
        );

        let outcomes = self.deliver(&msg, retry_count, first_queued_at).await;

        for (_, outcome) in &outcomes {
            match outcome {
                DeliveryOutcome::Delivered { response, .. } => {
                    info!(message_id = %msg.message_id, response, "delivered");
                }
                DeliveryOutcome::Deferred { response, .. } => {
                    warn!(message_id = %msg.message_id, response, "deferred");
                }
                DeliveryOutcome::Bounced { response, .. } => {
                    warn!(message_id = %msg.message_id, response, "bounced");
                }
                DeliveryOutcome::Suppressed { reason } => {
                    debug!(message_id = %msg.message_id, reason, "suppressed");
                }
            }
        }

        // Retry decision:
        // - No deferred outcomes  → Ack (we're done with this message).
        // - Deferred + budget left → RetryAfter(longest-per-domain delay) so
        //   JetStream Nak-with-delay redelivers exactly this message after
        //   the per-domain backoff, with no republish (avoids the duplicate-
        //   delivery loop that the legacy retry-wait path produced).
        // - Deferred + budget exhausted → set_bounced, Ack (matches the
        //   semantics of the old `schedule_retry` exhaustion branch).
        let any_deferred = outcomes
            .iter()
            .any(|(_, o)| matches!(o, DeliveryOutcome::Deferred { .. }));

        if !any_deferred {
            return HandlerResult::Ack;
        }

        let message_id = match Uuid::parse_str(&msg.message_id) {
            Ok(id) => MessageId(id),
            Err(_) => return HandlerResult::Ack,
        };

        if self.retry_budget_exhausted(&outcomes, retry_count, first_queued_at) {
            warn!(
                %message_id,
                retry_count,
                "retry budget exhausted across all deferred recipients"
            );
            if let Err(e) = self.message_repo.set_bounced(message_id).await {
                error!(error = %e, "failed to set message bounced after max retries");
            }
            return HandlerResult::Ack;
        }

        match self.deferred_retry_delay(&outcomes, retry_count) {
            Some(delay) => {
                info!(
                    %message_id,
                    retry_count = retry_count + 1,
                    delay_ms = delay.as_millis() as u64,
                    "scheduling retry via JetStream Nak"
                );
                HandlerResult::RetryAfter(delay)
            }
            None => HandlerResult::Ack,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Classify an SMTP response into a delivery outcome.
fn classify_response(resp: &SmtpResponse, remote_mta: &str) -> DeliveryOutcome {
    let response_text = format!("{} {}", resp.code, resp.full_text());
    if resp.is_success() {
        DeliveryOutcome::Delivered {
            response: response_text,
            remote_mta: remote_mta.to_string(),
        }
    } else if resp.is_transient() {
        let bounce_class = classify_bounce(resp.code, resp.enhanced.as_deref());
        DeliveryOutcome::Deferred {
            response: response_text,
            remote_mta: remote_mta.to_string(),
            bounce_class,
            retry_count: 0,
            next_retry_at: Utc::now(),
        }
    } else {
        let bounce_class = classify_bounce(resp.code, resp.enhanced.as_deref());
        DeliveryOutcome::Bounced {
            response: response_text,
            remote_mta: remote_mta.to_string(),
            bounce_class,
        }
    }
}

/// Group recipient addresses by their domain.
fn group_by_domain(recipients: &[String]) -> Vec<(String, Vec<String>)> {
    use std::collections::HashMap;
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for rcpt in recipients {
        let domain = rcpt
            .rsplit_once('@')
            .map(|(_, d)| d.to_lowercase())
            .unwrap_or_else(|| "unknown".to_string());
        map.entry(domain).or_default().push(rcpt.clone());
    }
    map.into_iter().collect()
}

/// Compute the next retry time using the unified `RetryPolicy`.
fn compute_next_retry(retry_count: u32, config: &DeliveryConfig) -> chrono::DateTime<Utc> {
    let policy = RetryPolicy::from_delivery_config(config);
    let delay_ms = policy.compute_delay_ms(retry_count);
    Utc::now() + chrono::Duration::milliseconds(delay_ms as i64)
}

/// Compute retry delay in milliseconds with exponential backoff and jitter.
#[cfg(test)]
fn compute_delay_ms(retry_count: u32, config: &DeliveryConfig) -> u64 {
    RetryPolicy::from_delivery_config(config).compute_delay_ms(retry_count)
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::SmtpResponse;

    #[test]
    fn group_by_domain_groups_correctly() {
        let recipients = vec![
            "alice@example.com".into(),
            "bob@example.com".into(),
            "charlie@other.org".into(),
        ];
        let grouped = group_by_domain(&recipients);
        assert_eq!(grouped.len(), 2);

        let example: &(String, Vec<String>) =
            grouped.iter().find(|(d, _)| d == "example.com").unwrap();
        assert_eq!(example.1.len(), 2);

        let other: &(String, Vec<String>) = grouped.iter().find(|(d, _)| d == "other.org").unwrap();
        assert_eq!(other.1.len(), 1);
    }

    #[test]
    fn classify_response_2xx_is_delivered() {
        let resp = SmtpResponse {
            code: 250,
            enhanced: Some("2.0.0".into()),
            lines: vec!["Message accepted".into()],
        };
        let outcome = classify_response(&resp, "mx.example.com");
        assert!(matches!(outcome, DeliveryOutcome::Delivered { .. }));
    }

    #[test]
    fn classify_response_4xx_is_deferred() {
        let resp = SmtpResponse {
            code: 450,
            enhanced: Some("4.7.1".into()),
            lines: vec!["Try again later".into()],
        };
        let outcome = classify_response(&resp, "mx.example.com");
        assert!(matches!(outcome, DeliveryOutcome::Deferred { .. }));
    }

    #[test]
    fn classify_response_5xx_is_bounced() {
        let resp = SmtpResponse {
            code: 550,
            enhanced: Some("5.1.1".into()),
            lines: vec!["User unknown".into()],
        };
        let outcome = classify_response(&resp, "mx.example.com");
        assert!(matches!(outcome, DeliveryOutcome::Bounced { .. }));
    }

    #[test]
    fn compute_delay_increases_exponentially() {
        let config = DeliveryConfig::default();
        let d0 = compute_delay_ms(0, &config);
        let d1 = compute_delay_ms(1, &config);
        let d2 = compute_delay_ms(2, &config);

        // With exponential backoff, each subsequent delay should roughly double.
        // But jitter makes it fuzzy, so just check the general trend.
        // base is 300s = 300_000ms.
        assert!(d0 > 0);
        assert!(d1 > d0 / 2); // With jitter, d1 should generally be larger.
        assert!(d2 > d1 / 2);
    }

    #[test]
    fn compute_delay_capped_at_max() {
        let config = DeliveryConfig {
            retry_base_secs: 300,
            retry_max_secs: 4000,
            ..Default::default()
        };
        // Very high retry count should hit the cap.
        let delay = compute_delay_ms(20, &config);
        // Max is 4000s = 4_000_000ms. With jitter ±25%, range is 3M-5M.
        assert!(delay <= 5_000_000);
    }

    #[test]
    fn outbound_message_serde() {
        let msg = OutboundMessage {
            message_id: Uuid::new_v4().to_string(),
            tenant_id: Uuid::new_v4().to_string(),
            domain_id: Some(Uuid::new_v4().to_string()),
            envelope_from: "sender@example.com".into(),
            envelope_to: vec!["rcpt@example.org".into()],
            raw_eml_key: "1,00000001".into(),
            is_forward: false,
            auth_results: None,
            dsn_ret: Some("FULL".into()),
            dsn_envid: Some("abc123".into()),
            dsn_notify: serde_json::json!({"rcpt@example.org": "SUCCESS,FAILURE"}),
            dsn_orcpt: serde_json::json!({"rcpt@example.org": "rfc822;orig@example.org"}),
            track_opens: false,
            track_clicks: false,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: OutboundMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.message_id, msg.message_id);
        assert_eq!(parsed.envelope_from, msg.envelope_from);
        assert_eq!(parsed.dsn_ret, Some("FULL".into()));
        assert_eq!(parsed.dsn_envid, Some("abc123".into()));
    }

    #[test]
    fn outbound_message_serde_without_dsn() {
        // Verify backward compat: JSON without DSN fields deserializes fine.
        let json = r#"{
            "message_id": "00000000-0000-0000-0000-000000000001",
            "tenant_id": "00000000-0000-0000-0000-000000000002",
            "envelope_from": "a@b.com",
            "envelope_to": ["c@d.com"],
            "raw_eml_key": "1,00000001"
        }"#;
        let parsed: OutboundMessage = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.dsn_ret, None);
        assert_eq!(parsed.dsn_envid, None);
        assert_eq!(parsed.dsn_notify, serde_json::json!(null));
        assert_eq!(parsed.dsn_orcpt, serde_json::json!(null));
    }

    #[test]
    fn group_by_domain_handles_no_at_sign() {
        let recipients = vec!["localpart".into()];
        let grouped = group_by_domain(&recipients);
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].0, "unknown");
    }
}
