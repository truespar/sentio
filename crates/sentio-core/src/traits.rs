use std::future::Future;
use std::net::IpAddr;

use chrono::{DateTime, NaiveDate, Utc};
use ipnetwork::IpNetwork;

use crate::auth::{
    DkimAlgorithm, DkimKeyStatus, DnsCheckStatus, DomainStatus, IpPoolStatus, IpPoolType,
    WarmupStatus,
};
use crate::error::SentioError;
use crate::event::{BounceClass, DeviceType, EngagementEventType, EventType, MailboxStatus};
use crate::event::{ErrorCategory, ErrorComponent, ErrorSeverity};
use crate::ids::{
    ApiKeyId, AttachmentId, DkimKeyId, DmarcReportId, EngagementEventId, ErrorEventId, FblReportId,
    InboundRouteDeliveryLogId, InboundRouteId, IpPoolId, MailboxId, MessageEventId, OAuthClientId,
    OAuthTokenId, PendingUploadId, SmtpCredentialId, SuppressionId, TlsrptReportId,
    TrackingCertificateId, TrackingDomainId, WarmupScheduleId, WebhookDeliveryLogId,
};
use crate::inbound::InboundRouteMatchType;
use crate::message::{
    AttachmentDisposition, DomainId, MessageDirection, MessageId, MessageStatus, ScanStatus,
    SuppressionReason,
};
use crate::oauth::{CodeChallengeMethod, OAuthClientStatus, OAuthTokenType};
use crate::report::{ComplaintType, TlsrptPolicyType};
use crate::tenant::{TenantId, TenantStatus, TenantTier};
use crate::webhook::{WebhookId, WebhookStatus};

// ──────────────────────────────────────────────────────────────────────────────
// TenantRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait TenantRepository: Send + Sync {
    fn create(
        &self,
        name: &str,
        tier: TenantTier,
    ) -> impl Future<Output = Result<TenantId, SentioError>> + Send;

    fn get(&self, id: TenantId) -> impl Future<Output = Result<TenantRecord, SentioError>> + Send;

    fn update_status(
        &self,
        id: TenantId,
        status: TenantStatus,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn list(
        &self,
        status: Option<TenantStatus>,
        limit: i64,
        offset: i64,
    ) -> impl Future<Output = Result<Vec<TenantRecord>, SentioError>> + Send;

    fn update(
        &self,
        id: TenantId,
        update: TenantUpdate,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn delete(&self, id: TenantId) -> impl Future<Output = Result<(), SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct TenantUpdate {
    pub name: Option<String>,
    pub tier: Option<TenantTier>,
    /// Toggle VERP (Variable Envelope Return Path) outbound rewriting for
    /// this tenant. When `None`, the existing value is kept.
    pub verp_enabled: Option<bool>,
}

/// Lightweight row returned by tenant queries.
/// Full struct lives in sentio-store; this is the shared contract.
#[derive(Debug, Clone)]
pub struct TenantRecord {
    pub id: TenantId,
    pub name: String,
    pub tier: TenantTier,
    pub status: TenantStatus,
    /// When `true`, outbound MAIL FROM is rewritten to a bounce return path
    /// at `bounce.{from_domain}` so DSN bounces route back to this server.
    /// Default is `false` so the feature is strictly opt-in per tenant.
    pub verp_enabled: bool,
}

// ──────────────────────────────────────────────────────────────────────────────
// DomainRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait DomainRepository: Send + Sync {
    fn create(
        &self,
        domain: NewDomain,
    ) -> impl Future<Output = Result<DomainRecord, SentioError>> + Send;

    fn get(&self, id: DomainId) -> impl Future<Output = Result<DomainRecord, SentioError>> + Send;

    fn get_by_name(
        &self,
        tenant_id: TenantId,
        domain_name: &str,
    ) -> impl Future<Output = Result<DomainRecord, SentioError>> + Send;

    fn list_by_tenant(
        &self,
        tenant_id: TenantId,
    ) -> impl Future<Output = Result<Vec<DomainRecord>, SentioError>> + Send;

    /// List all domains across all tenants whose `status = verified`.
    /// Used by the background DNS verification sweep.
    fn list_verified(&self) -> impl Future<Output = Result<Vec<DomainRecord>, SentioError>> + Send;

    fn update_status(
        &self,
        id: DomainId,
        status: DomainStatus,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn update_dns_checks(
        &self,
        id: DomainId,
        update: DnsCheckUpdate,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn verify(
        &self,
        id: DomainId,
        token: &str,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn update(
        &self,
        id: DomainId,
        update: DomainUpdate,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn delete(&self, id: DomainId) -> impl Future<Output = Result<(), SentioError>> + Send;

    /// Look up a domain by name that is configured for receiving mail.
    /// Returns `None` if the domain does not exist or is not enabled for receiving.
    fn find_by_domain_name(
        &self,
        domain_name: &str,
    ) -> impl Future<Output = Result<Option<DomainRecord>, SentioError>> + Send;

    /// Look up a domain by name that is configured for sending mail.
    /// Returns `None` if the domain does not exist or is not enabled for sending.
    fn find_by_sending_domain(
        &self,
        domain_name: &str,
    ) -> impl Future<Output = Result<Option<DomainRecord>, SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewDomain {
    pub tenant_id: TenantId,
    pub domain_name: String,
    pub use_for_sending: bool,
    pub use_for_receiving: bool,
}

#[derive(Debug, Clone)]
pub struct DomainUpdate {
    pub use_for_sending: bool,
    pub use_for_receiving: bool,
    pub reject_unknown_recipients: bool,
}

#[derive(Debug, Clone)]
pub struct DnsCheckUpdate {
    pub spf_status: DnsCheckStatus,
    pub spf_error: Option<String>,
    pub dkim_status: DnsCheckStatus,
    pub dkim_error: Option<String>,
    pub dmarc_status: DnsCheckStatus,
    pub dmarc_error: Option<String>,
    pub mx_status: DnsCheckStatus,
    pub mx_error: Option<String>,
    pub return_path_status: DnsCheckStatus,
    pub return_path_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DomainRecord {
    pub id: DomainId,
    pub tenant_id: TenantId,
    pub domain_name: String,
    pub use_for_sending: bool,
    pub use_for_receiving: bool,
    pub status: DomainStatus,
    pub spf_status: DnsCheckStatus,
    pub spf_error: Option<String>,
    pub dkim_status: DnsCheckStatus,
    pub dkim_error: Option<String>,
    pub dmarc_status: DnsCheckStatus,
    pub dmarc_error: Option<String>,
    pub mx_status: DnsCheckStatus,
    pub mx_error: Option<String>,
    pub return_path_status: DnsCheckStatus,
    pub return_path_error: Option<String>,
    pub dns_checked_at: Option<DateTime<Utc>>,
    pub verification_token: String,
    pub verified_at: Option<DateTime<Utc>>,
    pub reject_unknown_recipients: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// MailboxRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait MailboxRepository: Send + Sync {
    fn create(
        &self,
        mailbox: NewMailbox,
    ) -> impl Future<Output = Result<MailboxRecord, SentioError>> + Send;

    fn get(&self, id: MailboxId)
        -> impl Future<Output = Result<MailboxRecord, SentioError>> + Send;

    fn list_by_domain(
        &self,
        domain_id: DomainId,
    ) -> impl Future<Output = Result<Vec<MailboxRecord>, SentioError>> + Send;

    fn list_by_tenant(
        &self,
        tenant_id: TenantId,
    ) -> impl Future<Output = Result<Vec<MailboxRecord>, SentioError>> + Send;

    fn update(
        &self,
        id: MailboxId,
        update: MailboxUpdate,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn delete(&self, id: MailboxId) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn find_by_address(
        &self,
        domain_id: DomainId,
        local_part: &str,
    ) -> impl Future<Output = Result<Option<MailboxRecord>, SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewMailbox {
    pub domain_id: DomainId,
    pub tenant_id: TenantId,
    pub address: String,
    pub display_name: Option<String>,
    pub forward_to: Vec<String>,
    pub auto_reply: bool,
    pub auto_reply_subject: Option<String>,
    pub auto_reply_body: Option<String>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct MailboxRecord {
    pub id: MailboxId,
    pub domain_id: DomainId,
    pub tenant_id: TenantId,
    pub address: String,
    pub display_name: Option<String>,
    pub status: MailboxStatus,
    pub forward_to: Vec<String>,
    pub auto_reply: bool,
    pub auto_reply_subject: Option<String>,
    pub auto_reply_body: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct MailboxUpdate {
    pub display_name: Option<String>,
    pub status: MailboxStatus,
    pub forward_to: Vec<String>,
    pub auto_reply: bool,
    pub auto_reply_subject: Option<String>,
    pub auto_reply_body: Option<String>,
    pub metadata: serde_json::Value,
}

// ──────────────────────────────────────────────────────────────────────────────
// DkimKeyRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait DkimKeyRepository: Send + Sync {
    fn create(
        &self,
        key: NewDkimKey,
    ) -> impl Future<Output = Result<DkimKeyId, SentioError>> + Send;

    fn get(&self, id: DkimKeyId)
        -> impl Future<Output = Result<DkimKeyRecord, SentioError>> + Send;

    fn get_active_for_domain(
        &self,
        domain_id: DomainId,
    ) -> impl Future<Output = Result<DkimKeyRecord, SentioError>> + Send;

    fn list_by_domain(
        &self,
        domain_id: DomainId,
    ) -> impl Future<Output = Result<Vec<DkimKeyRecord>, SentioError>> + Send;

    /// Atomically: set current active key to rotating, insert new active key.
    fn rotate(
        &self,
        domain_id: DomainId,
        new_key: NewDkimKey,
    ) -> impl Future<Output = Result<DkimKeyId, SentioError>> + Send;

    fn retire(&self, id: DkimKeyId) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn delete(&self, id: DkimKeyId) -> impl Future<Output = Result<(), SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewDkimKey {
    pub domain_id: DomainId,
    pub selector: String,
    pub algorithm: DkimAlgorithm,
    pub private_key: String,
    pub public_key: String,
    pub key_size: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct DkimKeyRecord {
    pub id: DkimKeyId,
    pub domain_id: DomainId,
    pub selector: String,
    pub algorithm: DkimAlgorithm,
    pub private_key: String,
    pub public_key: String,
    pub key_size: Option<i32>,
    pub status: DkimKeyStatus,
    pub activated_at: Option<DateTime<Utc>>,
    pub retired_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// IpPoolRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait IpPoolRepository: Send + Sync {
    fn create(&self, pool: NewIpPool)
        -> impl Future<Output = Result<IpPoolId, SentioError>> + Send;

    fn get(&self, id: IpPoolId) -> impl Future<Output = Result<IpPoolRecord, SentioError>> + Send;

    fn list(
        &self,
        status: Option<IpPoolStatus>,
    ) -> impl Future<Output = Result<Vec<IpPoolRecord>, SentioError>> + Send;

    fn update_status(
        &self,
        id: IpPoolId,
        status: IpPoolStatus,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn add_ips(
        &self,
        id: IpPoolId,
        ips: &[IpNetwork],
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn remove_ips(
        &self,
        id: IpPoolId,
        ips: &[IpNetwork],
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn delete(&self, id: IpPoolId) -> impl Future<Output = Result<(), SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewIpPool {
    pub name: String,
    pub pool_type: IpPoolType,
    pub ips: Vec<IpNetwork>,
}

#[derive(Debug, Clone)]
pub struct IpPoolRecord {
    pub id: IpPoolId,
    pub name: String,
    pub pool_type: IpPoolType,
    pub ips: Vec<IpNetwork>,
    pub status: IpPoolStatus,
    pub created_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// TenantIpAssignmentRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait TenantIpAssignmentRepository: Send + Sync {
    fn assign(
        &self,
        tenant_id: TenantId,
        ip_pool_id: IpPoolId,
        priority: i32,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn unassign(
        &self,
        tenant_id: TenantId,
        ip_pool_id: IpPoolId,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn list_by_tenant(
        &self,
        tenant_id: TenantId,
    ) -> impl Future<Output = Result<Vec<TenantIpAssignmentRecord>, SentioError>> + Send;

    fn list_by_pool(
        &self,
        ip_pool_id: IpPoolId,
    ) -> impl Future<Output = Result<Vec<TenantIpAssignmentRecord>, SentioError>> + Send;

    fn update_priority(
        &self,
        tenant_id: TenantId,
        ip_pool_id: IpPoolId,
        priority: i32,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct TenantIpAssignmentRecord {
    pub tenant_id: TenantId,
    pub ip_pool_id: IpPoolId,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// IpWarmupScheduleRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait IpWarmupScheduleRepository: Send + Sync {
    fn create(
        &self,
        schedule: NewWarmupSchedule,
    ) -> impl Future<Output = Result<WarmupScheduleId, SentioError>> + Send;

    fn get(
        &self,
        id: WarmupScheduleId,
    ) -> impl Future<Output = Result<WarmupScheduleRecord, SentioError>> + Send;

    fn list_active(
        &self,
        tenant_id: Option<TenantId>,
    ) -> impl Future<Output = Result<Vec<WarmupScheduleRecord>, SentioError>> + Send;

    fn update_progress(
        &self,
        id: WarmupScheduleId,
        current_day: i32,
        daily_limit: i32,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn update_status(
        &self,
        id: WarmupScheduleId,
        status: WarmupStatus,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn delete(&self, id: WarmupScheduleId) -> impl Future<Output = Result<(), SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewWarmupSchedule {
    pub ip_pool_id: IpPoolId,
    pub tenant_id: TenantId,
    pub start_date: NaiveDate,
    pub daily_limit: i32,
    pub daily_increase_pct: f64,
    pub max_daily_limit: i32,
    pub isp_overrides: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct WarmupScheduleRecord {
    pub id: WarmupScheduleId,
    pub ip_pool_id: IpPoolId,
    pub tenant_id: TenantId,
    pub start_date: NaiveDate,
    pub current_day: i32,
    pub daily_limit: i32,
    pub daily_increase_pct: f64,
    pub max_daily_limit: i32,
    pub isp_overrides: Option<serde_json::Value>,
    pub status: WarmupStatus,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// MessageRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait MessageRepository: Send + Sync {
    fn insert(
        &self,
        msg: NewMessage,
    ) -> impl Future<Output = Result<MessageId, SentioError>> + Send;

    fn get(
        &self,
        tenant_id: TenantId,
        id: MessageId,
    ) -> impl Future<Output = Result<MessageRecord, SentioError>> + Send;

    fn list(
        &self,
        tenant_id: TenantId,
        filter: MessageFilter,
    ) -> impl Future<Output = Result<Vec<MessageRecord>, SentioError>> + Send;

    fn update_status(
        &self,
        id: MessageId,
        status: MessageStatus,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn set_delivered(&self, id: MessageId) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn set_bounced(&self, id: MessageId) -> impl Future<Output = Result<(), SentioError>> + Send;

    /// Look up a message by id without requiring a tenant_id. Used by the
    /// inbound VERP bounce handler, which only knows the message id after
    /// decoding the bounce token. Returns `None` when no such message
    /// exists.
    fn find_by_id(
        &self,
        id: MessageId,
    ) -> impl Future<Output = Result<Option<MessageRecord>, SentioError>> + Send;

    /// Record a DSN bounce report against a message. Updates
    /// `status = 'bounced'`, sets `bounced_at = now()`, and stores the
    /// parsed bounce details (class, smtp code, enhanced status,
    /// diagnostic text, failed recipient) on the messages row.
    ///
    /// Used by the inbound VERP bounce handler. Must NOT 5xx the SMTP
    /// reply on failure - callers ignore the result and still ack 250.
    #[allow(clippy::too_many_arguments)]
    fn mark_bounced<'a>(
        &'a self,
        id: MessageId,
        class: BounceClass,
        smtp_code: Option<u16>,
        enhanced_status: Option<&'a str>,
        diagnostic: Option<&'a str>,
        failed_recipient: Option<&'a str>,
    ) -> impl Future<Output = Result<(), SentioError>> + Send + 'a;

    fn count_by_status(
        &self,
        tenant_id: TenantId,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> impl Future<Output = Result<Vec<StatusCount>, SentioError>> + Send;

    fn update_spam_score(
        &self,
        id: MessageId,
        spam_score: f64,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn update_llm_classification(
        &self,
        id: MessageId,
        category: &str,
        summary: &str,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct StatusCount {
    pub status: String,
    pub count: i64,
}

#[derive(Debug, Clone)]
pub struct NewMessage {
    pub id: MessageId,
    pub tenant_id: TenantId,
    pub domain_id: Option<DomainId>,
    pub direction: MessageDirection,
    pub envelope_from: String,
    pub envelope_to: Vec<String>,
    pub header_from: Option<String>,
    pub header_to: Vec<String>,
    pub header_cc: Vec<String>,
    pub header_reply_to: Option<String>,
    pub subject: Option<String>,
    pub message_id_header: Option<String>,
    pub tags: Vec<String>,
    pub metadata: Option<serde_json::Value>,
    pub message_size: Option<i64>,
    pub raw_eml_key: Option<String>,
    pub spam_score: Option<f64>,
    pub spam_action: Option<String>,
    pub send_at: Option<DateTime<Utc>>,
    /// RFC 3461 DSN RET parameter ("FULL" or "HDRS").
    pub dsn_ret: Option<String>,
    /// RFC 3461 DSN ENVID parameter.
    pub dsn_envid: Option<String>,
    /// RFC 3461 DSN NOTIFY per recipient: {"rcpt@example.com": "SUCCESS,FAILURE"}.
    pub dsn_notify: serde_json::Value,
    /// RFC 3461 DSN ORCPT per recipient: {"rcpt@example.com": "rfc822;orig@example.com"}.
    pub dsn_orcpt: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct MessageRecord {
    pub id: MessageId,
    pub tenant_id: TenantId,
    pub domain_id: Option<DomainId>,
    pub direction: MessageDirection,
    pub envelope_from: String,
    pub envelope_to: Vec<String>,
    pub header_from: Option<String>,
    pub header_to: Vec<String>,
    pub header_cc: Vec<String>,
    pub header_reply_to: Option<String>,
    pub subject: Option<String>,
    pub message_id_header: Option<String>,
    pub status: MessageStatus,
    pub tags: Vec<String>,
    pub metadata: serde_json::Value,
    pub message_size: Option<i64>,
    pub raw_eml_key: Option<String>,
    pub spam_score: Option<f64>,
    pub spam_action: Option<String>,
    pub send_at: Option<DateTime<Utc>>,
    /// RFC 3461 DSN RET parameter ("FULL" or "HDRS").
    pub dsn_ret: Option<String>,
    /// RFC 3461 DSN ENVID parameter.
    pub dsn_envid: Option<String>,
    /// RFC 3461 DSN NOTIFY per recipient: {"rcpt@example.com": "SUCCESS,FAILURE"}.
    pub dsn_notify: serde_json::Value,
    /// RFC 3461 DSN ORCPT per recipient: {"rcpt@example.com": "rfc822;orig@example.com"}.
    pub dsn_orcpt: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub bounced_at: Option<DateTime<Utc>>,
    pub llm_category: Option<String>,
    pub llm_summary: Option<String>,
    pub llm_classified_at: Option<DateTime<Utc>>,
}

/// Filter for listing messages. `from` and `to` dates are required for
/// partition pruning on the monthly-partitioned messages table.
#[derive(Debug, Clone)]
pub struct MessageFilter {
    pub status: Option<MessageStatus>,
    pub direction: Option<MessageDirection>,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub limit: i64,
    pub offset: i64,
}

// ──────────────────────────────────────────────────────────────────────────────
// MessageEventRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait MessageEventRepository: Send + Sync {
    fn insert(
        &self,
        event: NewMessageEvent,
    ) -> impl Future<Output = Result<MessageEventId, SentioError>> + Send;

    fn list_by_message(
        &self,
        message_id: MessageId,
    ) -> impl Future<Output = Result<Vec<MessageEventRecord>, SentioError>> + Send;

    fn list_by_tenant(
        &self,
        tenant_id: TenantId,
        filter: EventFilter,
    ) -> impl Future<Output = Result<Vec<MessageEventRecord>, SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewMessageEvent {
    pub message_id: MessageId,
    pub tenant_id: TenantId,
    pub event_type: EventType,
    pub smtp_response: Option<String>,
    pub remote_mta: Option<String>,
    pub diagnostic_code: Option<String>,
    pub bounce_class: Option<BounceClass>,
    pub retry_count: Option<i32>,
    pub next_retry_at: Option<DateTime<Utc>>,
    pub source_ip: Option<IpAddr>,
    pub destination_ip: Option<IpAddr>,
    pub tls_version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MessageEventRecord {
    pub id: MessageEventId,
    pub message_id: MessageId,
    pub tenant_id: TenantId,
    pub event_type: EventType,
    pub smtp_response: Option<String>,
    pub remote_mta: Option<String>,
    pub diagnostic_code: Option<String>,
    pub bounce_class: Option<BounceClass>,
    pub retry_count: Option<i32>,
    pub next_retry_at: Option<DateTime<Utc>>,
    pub source_ip: Option<IpAddr>,
    pub destination_ip: Option<IpAddr>,
    pub tls_version: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Filter for listing message events. Date range required for partition pruning.
#[derive(Debug, Clone)]
pub struct EventFilter {
    pub event_type: Option<EventType>,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub limit: i64,
    pub offset: i64,
}

// ──────────────────────────────────────────────────────────────────────────────
// EngagementEventRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait EngagementEventRepository: Send + Sync {
    fn insert(
        &self,
        event: NewEngagementEvent,
    ) -> impl Future<Output = Result<EngagementEventId, SentioError>> + Send;

    fn list_by_message(
        &self,
        message_id: MessageId,
    ) -> impl Future<Output = Result<Vec<EngagementEventRecord>, SentioError>> + Send;

    fn list_by_tenant(
        &self,
        tenant_id: TenantId,
        filter: EngagementFilter,
    ) -> impl Future<Output = Result<Vec<EngagementEventRecord>, SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewEngagementEvent {
    pub message_id: MessageId,
    pub tenant_id: TenantId,
    pub event_type: EngagementEventType,
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub url: Option<String>,
    pub referer: Option<String>,
    pub client_name: Option<String>,
    pub client_version: Option<String>,
    pub device_type: Option<DeviceType>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub is_bot: bool,
    pub proxy_open: bool,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EngagementEventRecord {
    pub id: EngagementEventId,
    pub message_id: MessageId,
    pub tenant_id: TenantId,
    pub event_type: EngagementEventType,
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub url: Option<String>,
    pub referer: Option<String>,
    pub client_name: Option<String>,
    pub client_version: Option<String>,
    pub device_type: Option<DeviceType>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub is_bot: bool,
    pub proxy_open: bool,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Filter for listing engagement events. Date range required for partition pruning.
#[derive(Debug, Clone)]
pub struct EngagementFilter {
    pub event_type: Option<EngagementEventType>,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub limit: i64,
    pub offset: i64,
}

// ──────────────────────────────────────────────────────────────────────────────
// MessageAttachmentRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait MessageAttachmentRepository: Send + Sync {
    fn insert(
        &self,
        attachment: NewAttachment,
    ) -> impl Future<Output = Result<AttachmentId, SentioError>> + Send;

    fn list_by_message(
        &self,
        message_id: MessageId,
    ) -> impl Future<Output = Result<Vec<AttachmentRecord>, SentioError>> + Send;

    fn update_scan_status(
        &self,
        id: AttachmentId,
        scan_status: ScanStatus,
        scan_result: Option<&str>,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewAttachment {
    pub message_id: MessageId,
    pub tenant_id: TenantId,
    pub filename: String,
    pub content_type: String,
    pub size: i64,
    pub content_id: Option<String>,
    pub disposition: AttachmentDisposition,
    pub blob_key: String,
    pub checksum_sha256: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AttachmentRecord {
    pub id: AttachmentId,
    pub message_id: MessageId,
    pub tenant_id: TenantId,
    pub filename: String,
    pub content_type: String,
    pub size: i64,
    pub content_id: Option<String>,
    pub disposition: AttachmentDisposition,
    pub blob_key: String,
    pub checksum_sha256: Option<String>,
    pub scan_status: ScanStatus,
    pub scan_result: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// ApiKeyRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait ApiKeyRepository: Send + Sync {
    fn create(
        &self,
        tenant_id: TenantId,
        name: &str,
        scopes: &[String],
    ) -> impl Future<Output = Result<ApiKeyCreated, SentioError>> + Send;

    fn verify(
        &self,
        key_hash: &str,
    ) -> impl Future<Output = Result<ApiKeyRecord, SentioError>> + Send;

    fn list_by_tenant(
        &self,
        tenant_id: TenantId,
    ) -> impl Future<Output = Result<Vec<ApiKeyRecord>, SentioError>> + Send;

    fn revoke(&self, id: ApiKeyId) -> impl Future<Output = Result<(), SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct ApiKeyCreated {
    pub id: ApiKeyId,
    pub raw_key: String,
}

#[derive(Debug, Clone)]
pub struct ApiKeyRecord {
    pub id: ApiKeyId,
    pub tenant_id: TenantId,
    pub key_prefix: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// SmtpCredentialRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait SmtpCredentialRepository: Send + Sync {
    fn create(
        &self,
        credential: NewSmtpCredential,
    ) -> impl Future<Output = Result<SmtpCredentialId, SentioError>> + Send;

    /// Look up an enabled credential by username (used during SMTP AUTH).
    fn lookup(
        &self,
        username: &str,
    ) -> impl Future<Output = Result<SmtpCredentialRecord, SentioError>> + Send;

    fn list_by_tenant(
        &self,
        tenant_id: TenantId,
    ) -> impl Future<Output = Result<Vec<SmtpCredentialRecord>, SentioError>> + Send;

    fn update_enabled(
        &self,
        id: SmtpCredentialId,
        enabled: bool,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn delete(&self, id: SmtpCredentialId) -> impl Future<Output = Result<(), SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewSmtpCredential {
    pub tenant_id: TenantId,
    pub username: String,
    pub password_hash: String,
    pub mechanisms: Vec<String>,
    pub scram_stored_key: Option<String>,
    pub scram_server_key: Option<String>,
    pub scram_salt: Option<String>,
    pub scram_iterations: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct SmtpCredentialRecord {
    pub id: SmtpCredentialId,
    pub tenant_id: TenantId,
    pub username: String,
    pub password_hash: String,
    pub mechanisms: Vec<String>,
    pub scram_stored_key: Option<String>,
    pub scram_server_key: Option<String>,
    pub scram_salt: Option<String>,
    pub scram_iterations: Option<i32>,
    pub enabled: bool,
}

// ──────────────────────────────────────────────────────────────────────────────
// SuppressionRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait SuppressionRepository: Send + Sync {
    fn add(
        &self,
        suppression: NewSuppression,
    ) -> impl Future<Output = Result<SuppressionId, SentioError>> + Send;

    fn check(
        &self,
        tenant_id: TenantId,
        email: &str,
    ) -> impl Future<Output = Result<bool, SentioError>> + Send;

    fn get(
        &self,
        tenant_id: TenantId,
        email: &str,
    ) -> impl Future<Output = Result<SuppressionRecord, SentioError>> + Send;

    fn list_by_tenant(
        &self,
        tenant_id: TenantId,
        limit: i64,
        offset: i64,
    ) -> impl Future<Output = Result<Vec<SuppressionRecord>, SentioError>> + Send;

    fn remove(
        &self,
        tenant_id: TenantId,
        email: &str,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewSuppression {
    pub tenant_id: TenantId,
    pub email: String,
    pub reason: SuppressionReason,
    pub source_event_id: Option<MessageEventId>,
}

#[derive(Debug, Clone)]
pub struct SuppressionRecord {
    pub id: SuppressionId,
    pub tenant_id: TenantId,
    pub email: String,
    pub reason: SuppressionReason,
    pub source_event_id: Option<MessageEventId>,
    pub created_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// WebhookRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait WebhookRepository: Send + Sync {
    fn create(
        &self,
        webhook: NewWebhook,
    ) -> impl Future<Output = Result<WebhookId, SentioError>> + Send;

    fn get(&self, id: WebhookId)
        -> impl Future<Output = Result<WebhookRecord, SentioError>> + Send;

    fn list_by_tenant(
        &self,
        tenant_id: TenantId,
    ) -> impl Future<Output = Result<Vec<WebhookRecord>, SentioError>> + Send;

    fn update_status(
        &self,
        id: WebhookId,
        status: WebhookStatus,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn update(
        &self,
        id: WebhookId,
        update: WebhookUpdate,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn increment_failure(
        &self,
        id: WebhookId,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn record_success(&self, id: WebhookId)
        -> impl Future<Output = Result<(), SentioError>> + Send;

    fn delete(&self, id: WebhookId) -> impl Future<Output = Result<(), SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewWebhook {
    pub tenant_id: TenantId,
    pub url: String,
    pub event_types: Vec<String>,
    pub signing_secret: String,
}

#[derive(Debug, Clone)]
pub struct WebhookUpdate {
    pub url: String,
    pub event_types: Vec<String>,
    pub status: WebhookStatus,
}

#[derive(Debug, Clone)]
pub struct WebhookRecord {
    pub id: WebhookId,
    pub tenant_id: TenantId,
    pub url: String,
    pub event_types: Vec<String>,
    pub signing_secret: String,
    pub status: WebhookStatus,
    pub failure_count: i32,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_failure_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// WebhookDeliveryLogRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait WebhookDeliveryLogRepository: Send + Sync {
    fn insert(
        &self,
        log: NewWebhookDeliveryLog,
    ) -> impl Future<Output = Result<WebhookDeliveryLogId, SentioError>> + Send;

    fn get(
        &self,
        id: WebhookDeliveryLogId,
    ) -> impl Future<Output = Result<WebhookDeliveryLogRecord, SentioError>> + Send;

    fn list_by_webhook(
        &self,
        webhook_id: WebhookId,
        limit: i64,
        offset: i64,
    ) -> impl Future<Output = Result<Vec<WebhookDeliveryLogRecord>, SentioError>> + Send;

    fn list_by_tenant(
        &self,
        tenant_id: TenantId,
        limit: i64,
        offset: i64,
    ) -> impl Future<Output = Result<Vec<WebhookDeliveryLogRecord>, SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewWebhookDeliveryLog {
    pub webhook_id: WebhookId,
    pub tenant_id: TenantId,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub http_status: Option<i32>,
    pub response_body: Option<String>,
    pub attempt_number: i32,
    pub delivered_at: Option<DateTime<Utc>>,
    pub failed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WebhookDeliveryLogRecord {
    pub id: WebhookDeliveryLogId,
    pub webhook_id: WebhookId,
    pub tenant_id: TenantId,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub http_status: Option<i32>,
    pub response_body: Option<String>,
    pub attempt_number: i32,
    pub delivered_at: Option<DateTime<Utc>>,
    pub failed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// InboundRouteDeliveryLogRepository
//
// Per-attempt audit log for InboundEngine's webhook dispatch loop. Mirrors
// `WebhookDeliveryLogRepository` (engagement-event side) but scoped to
// inbound routes - separate dispatch path, separate operator view, no
// payload column (raw EML is in blob storage, parsed payload on the message row).
// ──────────────────────────────────────────────────────────────────────────────

pub trait InboundRouteDeliveryLogRepository: Send + Sync {
    fn insert(
        &self,
        log: NewInboundRouteDeliveryLog,
    ) -> impl Future<Output = Result<InboundRouteDeliveryLogId, SentioError>> + Send;

    fn list_by_route(
        &self,
        inbound_route_id: InboundRouteId,
        limit: i64,
        offset: i64,
    ) -> impl Future<Output = Result<Vec<InboundRouteDeliveryLogRecord>, SentioError>> + Send;

    fn list_by_tenant(
        &self,
        tenant_id: TenantId,
        limit: i64,
        offset: i64,
    ) -> impl Future<Output = Result<Vec<InboundRouteDeliveryLogRecord>, SentioError>> + Send;

    /// Idempotency check for the retry loop: has this (route, message, recipient)
    /// triple ever logged a 2xx? If yes, callers skip re-dispatch on
    /// retry so a single transient-failed recipient on a multi-recipient
    /// message doesn't duplicate-deliver to peers that already 2xx'd.
    fn has_prior_success(
        &self,
        inbound_route_id: InboundRouteId,
        message_id: MessageId,
        recipient: &str,
    ) -> impl Future<Output = Result<bool, SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewInboundRouteDeliveryLog {
    pub inbound_route_id: InboundRouteId,
    pub tenant_id: TenantId,
    pub message_id: Option<MessageId>,
    pub recipient: String,
    pub http_status: Option<i32>,
    pub response_body: Option<String>,
    pub attempt_number: i32,
    pub delivered_at: Option<DateTime<Utc>>,
    pub failed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct InboundRouteDeliveryLogRecord {
    pub id: InboundRouteDeliveryLogId,
    pub inbound_route_id: InboundRouteId,
    pub tenant_id: TenantId,
    pub message_id: Option<MessageId>,
    pub recipient: String,
    pub http_status: Option<i32>,
    pub response_body: Option<String>,
    pub attempt_number: i32,
    pub delivered_at: Option<DateTime<Utc>>,
    pub failed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// InboundRouteRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait InboundRouteRepository: Send + Sync {
    fn create(
        &self,
        route: NewInboundRoute,
    ) -> impl Future<Output = Result<InboundRouteId, SentioError>> + Send;

    fn get(
        &self,
        id: InboundRouteId,
    ) -> impl Future<Output = Result<InboundRouteRecord, SentioError>> + Send;

    fn list_by_tenant(
        &self,
        tenant_id: TenantId,
    ) -> impl Future<Output = Result<Vec<InboundRouteRecord>, SentioError>> + Send;

    fn update(
        &self,
        id: InboundRouteId,
        update: InboundRouteUpdate,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn delete(&self, id: InboundRouteId) -> impl Future<Output = Result<(), SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewInboundRoute {
    pub tenant_id: TenantId,
    pub pattern: String,
    pub match_type: InboundRouteMatchType,
    pub webhook_url: String,
    pub priority: i32,
    pub llm_classify: bool,
    pub auto_respond: bool,
    pub auto_respond_config: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct InboundRouteUpdate {
    pub pattern: String,
    pub match_type: InboundRouteMatchType,
    pub webhook_url: String,
    pub priority: i32,
    pub llm_classify: bool,
    pub auto_respond: bool,
    pub auto_respond_config: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct InboundRouteRecord {
    pub id: InboundRouteId,
    pub tenant_id: TenantId,
    pub pattern: String,
    pub match_type: InboundRouteMatchType,
    pub webhook_url: String,
    pub priority: i32,
    pub llm_classify: bool,
    pub auto_respond: bool,
    pub auto_respond_config: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// OAuthClientRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait OAuthClientRepository: Send + Sync {
    fn create(
        &self,
        client: NewOAuthClient,
    ) -> impl Future<Output = Result<OAuthClientId, SentioError>> + Send;

    fn get(
        &self,
        id: OAuthClientId,
    ) -> impl Future<Output = Result<OAuthClientRecord, SentioError>> + Send;

    fn get_by_client_id(
        &self,
        client_id: &str,
    ) -> impl Future<Output = Result<OAuthClientRecord, SentioError>> + Send;

    fn list_by_tenant(
        &self,
        tenant_id: TenantId,
    ) -> impl Future<Output = Result<Vec<OAuthClientRecord>, SentioError>> + Send;

    fn revoke(&self, id: OAuthClientId) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn delete(&self, id: OAuthClientId) -> impl Future<Output = Result<(), SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewOAuthClient {
    pub tenant_id: TenantId,
    pub client_id: String,
    pub client_secret_hash: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct OAuthClientRecord {
    pub id: OAuthClientId,
    pub tenant_id: TenantId,
    pub client_id: String,
    pub client_secret_hash: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    pub status: OAuthClientStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// OAuthAuthorizationCodeRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait OAuthAuthorizationCodeRepository: Send + Sync {
    fn create(
        &self,
        auth_code: NewOAuthAuthorizationCode,
    ) -> impl Future<Output = Result<String, SentioError>> + Send;

    fn get(
        &self,
        code: &str,
    ) -> impl Future<Output = Result<OAuthAuthorizationCodeRecord, SentioError>> + Send;

    fn consume(
        &self,
        code: &str,
    ) -> impl Future<Output = Result<OAuthAuthorizationCodeRecord, SentioError>> + Send;

    fn delete_expired(&self) -> impl Future<Output = Result<u64, SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewOAuthAuthorizationCode {
    pub code: String,
    pub client_id: OAuthClientId,
    pub tenant_id: TenantId,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<CodeChallengeMethod>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct OAuthAuthorizationCodeRecord {
    pub code: String,
    pub client_id: OAuthClientId,
    pub tenant_id: TenantId,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<CodeChallengeMethod>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// OAuthTokenRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait OAuthTokenRepository: Send + Sync {
    fn create(
        &self,
        token: NewOAuthToken,
    ) -> impl Future<Output = Result<OAuthTokenId, SentioError>> + Send;

    fn get_by_hash(
        &self,
        token_hash: &str,
    ) -> impl Future<Output = Result<OAuthTokenRecord, SentioError>> + Send;

    fn revoke(&self, id: OAuthTokenId) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn revoke_by_client(
        &self,
        client_id: OAuthClientId,
    ) -> impl Future<Output = Result<u64, SentioError>> + Send;

    fn delete_expired(&self) -> impl Future<Output = Result<u64, SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewOAuthToken {
    pub client_id: OAuthClientId,
    pub tenant_id: TenantId,
    pub token_hash: String,
    pub token_type: OAuthTokenType,
    pub scopes: Vec<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct OAuthTokenRecord {
    pub id: OAuthTokenId,
    pub client_id: OAuthClientId,
    pub tenant_id: TenantId,
    pub token_hash: String,
    pub token_type: OAuthTokenType,
    pub scopes: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// DmarcReportRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait DmarcReportRepository: Send + Sync {
    fn insert(
        &self,
        report: NewDmarcReport,
    ) -> impl Future<Output = Result<DmarcReportId, SentioError>> + Send;

    fn get(
        &self,
        id: DmarcReportId,
    ) -> impl Future<Output = Result<DmarcReportRecord, SentioError>> + Send;

    fn list_by_domain(
        &self,
        domain_id: DomainId,
        limit: i64,
        offset: i64,
    ) -> impl Future<Output = Result<Vec<DmarcReportRecord>, SentioError>> + Send;

    fn list_by_tenant(
        &self,
        tenant_id: TenantId,
        limit: i64,
        offset: i64,
    ) -> impl Future<Output = Result<Vec<DmarcReportRecord>, SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewDmarcReport {
    pub tenant_id: TenantId,
    pub domain_id: DomainId,
    pub direction: MessageDirection,
    pub report_id: String,
    pub org_name: Option<String>,
    pub date_begin: DateTime<Utc>,
    pub date_end: DateTime<Utc>,
    pub source_ip: Option<IpAddr>,
    pub report_xml: Option<String>,
    pub total_count: i32,
    pub dkim_pass: i32,
    pub dkim_fail: i32,
    pub spf_pass: i32,
    pub spf_fail: i32,
    pub dmarc_pass: i32,
    pub dmarc_fail: i32,
}

#[derive(Debug, Clone)]
pub struct DmarcReportRecord {
    pub id: DmarcReportId,
    pub tenant_id: TenantId,
    pub domain_id: DomainId,
    pub direction: MessageDirection,
    pub report_id: String,
    pub org_name: Option<String>,
    pub date_begin: DateTime<Utc>,
    pub date_end: DateTime<Utc>,
    pub source_ip: Option<IpAddr>,
    pub report_xml: Option<String>,
    pub total_count: i32,
    pub dkim_pass: i32,
    pub dkim_fail: i32,
    pub spf_pass: i32,
    pub spf_fail: i32,
    pub dmarc_pass: i32,
    pub dmarc_fail: i32,
    pub created_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// FblReportRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait FblReportRepository: Send + Sync {
    fn insert(
        &self,
        report: NewFblReport,
    ) -> impl Future<Output = Result<FblReportId, SentioError>> + Send;

    fn get(
        &self,
        id: FblReportId,
    ) -> impl Future<Output = Result<FblReportRecord, SentioError>> + Send;

    fn list_by_tenant(
        &self,
        tenant_id: TenantId,
        limit: i64,
        offset: i64,
    ) -> impl Future<Output = Result<Vec<FblReportRecord>, SentioError>> + Send;

    fn mark_processed(
        &self,
        id: FblReportId,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewFblReport {
    pub tenant_id: TenantId,
    pub original_message_id: Option<MessageId>,
    pub original_message_id_hdr: Option<String>,
    pub complained_recipient: String,
    pub complaint_type: ComplaintType,
    pub feedback_type: Option<String>,
    pub source_ip: Option<IpAddr>,
    pub arrival_date: Option<DateTime<Utc>>,
    pub report_raw: Option<String>,
    pub auto_suppressed: bool,
}

#[derive(Debug, Clone)]
pub struct FblReportRecord {
    pub id: FblReportId,
    pub tenant_id: TenantId,
    pub original_message_id: Option<MessageId>,
    pub original_message_id_hdr: Option<String>,
    pub complained_recipient: String,
    pub complaint_type: ComplaintType,
    pub feedback_type: Option<String>,
    pub source_ip: Option<IpAddr>,
    pub arrival_date: Option<DateTime<Utc>>,
    pub report_raw: Option<String>,
    pub auto_suppressed: bool,
    pub processed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// PendingUploadRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait PendingUploadRepository: Send + Sync {
    fn create(
        &self,
        upload: NewPendingUpload,
    ) -> impl Future<Output = Result<PendingUploadId, SentioError>> + Send;

    fn get(
        &self,
        id: PendingUploadId,
    ) -> impl Future<Output = Result<PendingUploadRecord, SentioError>> + Send;

    fn claim(&self, id: PendingUploadId) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn update_scan_status(
        &self,
        id: PendingUploadId,
        scan_status: ScanStatus,
        scan_result: Option<&str>,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn delete_expired(&self) -> impl Future<Output = Result<u64, SentioError>> + Send;

    fn list_expired(
        &self,
        limit: i64,
    ) -> impl Future<Output = Result<Vec<PendingUploadRecord>, SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewPendingUpload {
    pub tenant_id: TenantId,
    pub blob_key: String,
    pub filename: String,
    pub content_type: String,
    pub size: i64,
    pub checksum_sha256: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PendingUploadRecord {
    pub id: PendingUploadId,
    pub tenant_id: TenantId,
    pub blob_key: String,
    pub filename: String,
    pub content_type: String,
    pub size: i64,
    pub checksum_sha256: Option<String>,
    pub scan_status: ScanStatus,
    pub scan_result: Option<String>,
    pub claimed: bool,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// TlsrptReportRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait TlsrptReportRepository: Send + Sync {
    fn insert(
        &self,
        report: NewTlsrptReport,
    ) -> impl Future<Output = Result<TlsrptReportId, SentioError>> + Send;

    fn get(
        &self,
        id: TlsrptReportId,
    ) -> impl Future<Output = Result<TlsrptReportRecord, SentioError>> + Send;

    fn list_by_domain(
        &self,
        domain_id: DomainId,
        limit: i64,
        offset: i64,
    ) -> impl Future<Output = Result<Vec<TlsrptReportRecord>, SentioError>> + Send;

    fn list_by_tenant(
        &self,
        tenant_id: TenantId,
        limit: i64,
        offset: i64,
    ) -> impl Future<Output = Result<Vec<TlsrptReportRecord>, SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewTlsrptReport {
    pub tenant_id: TenantId,
    pub domain_id: DomainId,
    pub direction: MessageDirection,
    pub report_id: String,
    pub org_name: Option<String>,
    pub date_begin: DateTime<Utc>,
    pub date_end: DateTime<Utc>,
    pub policy_type: TlsrptPolicyType,
    pub policy_domain: Option<String>,
    pub total_success: i32,
    pub total_failure: i32,
    pub failure_details: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct TlsrptReportRecord {
    pub id: TlsrptReportId,
    pub tenant_id: TenantId,
    pub domain_id: DomainId,
    pub direction: MessageDirection,
    pub report_id: String,
    pub org_name: Option<String>,
    pub date_begin: DateTime<Utc>,
    pub date_end: DateTime<Utc>,
    pub policy_type: TlsrptPolicyType,
    pub policy_domain: Option<String>,
    pub total_success: i32,
    pub total_failure: i32,
    pub failure_details: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// TrackingDomainRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait TrackingDomainRepository: Send + Sync {
    fn create(
        &self,
        domain: NewTrackingDomain,
    ) -> impl Future<Output = Result<TrackingDomainId, SentioError>> + Send;

    fn get(
        &self,
        id: TrackingDomainId,
    ) -> impl Future<Output = Result<TrackingDomainRecord, SentioError>> + Send;

    fn get_by_name(
        &self,
        domain_name: &str,
    ) -> impl Future<Output = Result<TrackingDomainRecord, SentioError>> + Send;

    fn list_by_tenant(
        &self,
        tenant_id: TenantId,
    ) -> impl Future<Output = Result<Vec<TrackingDomainRecord>, SentioError>> + Send;

    fn update_dns_status(
        &self,
        id: TrackingDomainId,
        dns_status: DomainStatus,
        dns_error: Option<&str>,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn delete(&self, id: TrackingDomainId) -> impl Future<Output = Result<(), SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewTrackingDomain {
    pub tenant_id: TenantId,
    pub domain_id: Option<DomainId>,
    pub domain_name: String,
    pub cname_target: String,
    pub ssl_enabled: bool,
    pub track_opens: bool,
    pub track_clicks: bool,
}

#[derive(Debug, Clone)]
pub struct TrackingDomainRecord {
    pub id: TrackingDomainId,
    pub tenant_id: TenantId,
    pub domain_id: Option<DomainId>,
    pub domain_name: String,
    pub cname_target: String,
    pub dns_status: DomainStatus,
    pub dns_error: Option<String>,
    pub dns_checked_at: Option<DateTime<Utc>>,
    pub ssl_enabled: bool,
    pub track_opens: bool,
    pub track_clicks: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// TrackingCertificateRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait TrackingCertificateRepository: Send + Sync {
    fn create(
        &self,
        cert: NewTrackingCertificate,
    ) -> impl Future<Output = Result<TrackingCertificateId, SentioError>> + Send;

    fn get(
        &self,
        id: TrackingCertificateId,
    ) -> impl Future<Output = Result<TrackingCertificateRecord, SentioError>> + Send;

    fn get_active_for_domain(
        &self,
        tracking_domain_id: TrackingDomainId,
    ) -> impl Future<Output = Result<TrackingCertificateRecord, SentioError>> + Send;

    fn list_due_for_renewal(
        &self,
    ) -> impl Future<Output = Result<Vec<TrackingCertificateRecord>, SentioError>> + Send;

    fn delete(
        &self,
        id: TrackingCertificateId,
    ) -> impl Future<Output = Result<(), SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewTrackingCertificate {
    pub tracking_domain_id: TrackingDomainId,
    pub certificate: String,
    pub intermediaries: Option<String>,
    pub private_key: String,
    pub expires_at: DateTime<Utc>,
    pub renew_after: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct TrackingCertificateRecord {
    pub id: TrackingCertificateId,
    pub tracking_domain_id: TrackingDomainId,
    pub certificate: String,
    pub intermediaries: Option<String>,
    pub private_key: String,
    pub expires_at: DateTime<Utc>,
    pub renew_after: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// BlobStore
// ──────────────────────────────────────────────────────────────────────────────

pub trait BlobStore: Send + Sync {
    fn assign(&self) -> impl Future<Output = Result<AssignedFid, SentioError>> + Send;

    fn upload(
        &self,
        fid: &str,
        data: bytes::Bytes,
        filename: &str,
        content_type: &str,
    ) -> impl Future<Output = Result<UploadResult, SentioError>> + Send;

    fn download(&self, fid: &str)
        -> impl Future<Output = Result<bytes::Bytes, SentioError>> + Send;

    fn delete(&self, fid: &str) -> impl Future<Output = Result<(), SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct AssignedFid {
    pub fid: String,
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct UploadResult {
    pub fid: String,
    pub size: u64,
    pub checksum_sha256: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// VirusScanner
// ──────────────────────────────────────────────────────────────────────────────

pub trait VirusScanner: Send + Sync {
    fn scan(&self, data: &[u8]) -> impl Future<Output = Result<ScanResult, SentioError>> + Send;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanResult {
    Clean,
    Infected(String),
    Error(String),
}

// ──────────────────────────────────────────────────────────────────────────────
// SpamScorer
// ──────────────────────────────────────────────────────────────────────────────

pub trait SpamScorer: Send + Sync {
    fn score(
        &self,
        raw_message: &[u8],
        envelope_from: &str,
        envelope_to: &[String],
        peer_ip: IpAddr,
    ) -> impl Future<Output = Result<SpamScore, SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct SpamScore {
    pub score: f64,
    pub action: SpamAction,
    pub rules: Vec<SpamRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpamAction {
    Accept,
    AddHeader,
    Greylist,
    Reject,
}

impl std::fmt::Display for SpamAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accept => write!(f, "accept"),
            Self::AddHeader => write!(f, "add_header"),
            Self::Greylist => write!(f, "greylist"),
            Self::Reject => write!(f, "reject"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SpamRule {
    pub name: String,
    pub score: f64,
    pub description: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// SpamTrainer - teach spam/ham to backend (rspamd learn endpoints)
// ──────────────────────────────────────────────────────────────────────────────

pub trait SpamTrainer: Send + Sync {
    fn learn_spam(
        &self,
        raw_message: &[u8],
    ) -> impl Future<Output = Result<(), SentioError>> + Send;

    fn learn_ham(&self, raw_message: &[u8])
        -> impl Future<Output = Result<(), SentioError>> + Send;
}

// ──────────────────────────────────────────────────────────────────────────────
// ErrorEventRepository
// ──────────────────────────────────────────────────────────────────────────────

pub trait ErrorEventRepository: Send + Sync {
    fn insert(
        &self,
        event: NewErrorEvent,
    ) -> impl Future<Output = Result<ErrorEventId, SentioError>> + Send;

    fn get(
        &self,
        id: ErrorEventId,
    ) -> impl Future<Output = Result<ErrorEventRecord, SentioError>> + Send;

    fn list(
        &self,
        tenant_id: TenantId,
        filter: ErrorEventFilter,
    ) -> impl Future<Output = Result<Vec<ErrorEventRecord>, SentioError>> + Send;

    fn summary(
        &self,
        tenant_id: TenantId,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> impl Future<Output = Result<Vec<ErrorEventSummary>, SentioError>> + Send;

    fn delete_before(
        &self,
        before: DateTime<Utc>,
    ) -> impl Future<Output = Result<u64, SentioError>> + Send;
}

#[derive(Debug, Clone)]
pub struct NewErrorEvent {
    pub tenant_id: TenantId,
    pub severity: ErrorSeverity,
    pub component: ErrorComponent,
    pub error_type: ErrorCategory,
    pub message: String,
    pub stack_trace: Option<String>,
    pub message_id: Option<uuid::Uuid>,
    pub request_id: Option<String>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct ErrorEventRecord {
    pub id: ErrorEventId,
    pub tenant_id: TenantId,
    pub severity: ErrorSeverity,
    pub component: ErrorComponent,
    pub error_type: ErrorCategory,
    pub message: String,
    pub stack_trace: Option<String>,
    pub message_id: Option<uuid::Uuid>,
    pub request_id: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ErrorEventFilter {
    pub severity: Option<ErrorSeverity>,
    pub component: Option<ErrorComponent>,
    pub error_type: Option<ErrorCategory>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Clone)]
pub struct ErrorEventSummary {
    pub component: String,
    pub severity: String,
    pub count: i64,
}
