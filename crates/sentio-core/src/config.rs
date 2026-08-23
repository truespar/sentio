use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

// ──────────────────────────────────────────────────────────────────────────────
// Top-level config
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SentioConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub kv: KvConfig,
    #[serde(default)]
    pub redis: RedisConfig,
    #[serde(default)]
    pub nats: NatsConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub scanning: ScanningConfig,
    #[serde(default)]
    pub abuse: AbuseConfig,
    #[serde(default)]
    pub spam: SpamConfig,
    #[serde(default)]
    pub delivery: DeliveryConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub deliverability: DeliverabilityConfig,
    #[serde(default)]
    pub tracking: TrackingConfig,
    #[serde(default)]
    pub webhooks: WebhooksConfig,
    #[serde(default)]
    pub llm: LlmConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
    #[serde(default)]
    pub analytics: AnalyticsConfig,
    #[serde(default)]
    pub error_events: ErrorEventsConfig,
    #[serde(default)]
    pub listmonk: ListmonkConfig,
}

// ──────────────────────────────────────────────────────────────────────────────
// Server
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub hostname: String,
    /// Base URL for the API server (used for tracking pixels/links).
    #[serde(default = "default_api_base_url")]
    pub api_base_url: String,
    /// DNS resolver for MX lookups and email authentication.
    /// Options: "system", "google", "cloudflare_tls", "quad9_tls".
    #[serde(default = "default_dns_resolver")]
    pub dns_resolver: String,
    #[serde(default)]
    pub listen_smtp: Vec<String>,
    #[serde(default)]
    pub listen_smtps: Vec<String>,
    #[serde(default)]
    pub listen_submission: Vec<String>,
    pub listen_api: String,
    pub workers: usize,
    pub max_connections: u32,
    pub proxy_protocol: bool,
    pub xclient_enabled: bool,
    #[serde(default)]
    pub xclient_allowed_ips: Vec<String>,
    pub shutdown_drain_secs: u64,
    pub shutdown_force_secs: u64,
    /// Maximum API request body size in megabytes.
    #[serde(default = "default_max_api_body_size_mb")]
    pub max_api_body_size_mb: u32,
    #[serde(default)]
    pub inbound_timeouts: InboundTimeoutsConfig,
    #[serde(default)]
    pub inbound_limits: InboundLimitsConfig,
    /// Per-instance secret used to HMAC-sign VERP bounce tokens.
    ///
    /// MUST be set when any tenant has `verp_enabled = true`; the server
    /// refuses to start otherwise (see `main.rs`). Rotating the secret
    /// invalidates all in-flight bounce tokens - bounces generated before
    /// the rotation will fail HMAC verification and be silently discarded.
    #[serde(default)]
    pub verp_secret: Option<String>,
}

fn default_api_base_url() -> String {
    "https://mail.example.com".to_string()
}

fn default_dns_resolver() -> String {
    "google".to_string()
}

fn default_max_api_body_size_mb() -> u32 {
    50
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            hostname: "mail.example.com".to_string(),
            api_base_url: "https://mail.example.com".to_string(),
            dns_resolver: "google".to_string(),
            listen_smtp: vec!["0.0.0.0:25".into(), "[::]:25".into()],
            listen_smtps: vec!["0.0.0.0:465".into(), "[::]:465".into()],
            listen_submission: vec!["0.0.0.0:587".into(), "[::]:587".into()],
            listen_api: "0.0.0.0:8080".to_string(),
            workers: 0,
            max_connections: 10000,
            proxy_protocol: false,
            xclient_enabled: false,
            xclient_allowed_ips: Vec::new(),
            shutdown_drain_secs: 30,
            shutdown_force_secs: 60,
            max_api_body_size_mb: 50,
            inbound_timeouts: InboundTimeoutsConfig::default(),
            inbound_limits: InboundLimitsConfig::default(),
            verp_secret: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundTimeoutsConfig {
    pub greeting_secs: u64,
    pub command_secs: u64,
    pub data_initiation_secs: u64,
    pub data_block_secs: u64,
    pub data_termination_secs: u64,
}

impl Default for InboundTimeoutsConfig {
    fn default() -> Self {
        Self {
            greeting_secs: 300,
            command_secs: 300,
            data_initiation_secs: 120,
            data_block_secs: 180,
            data_termination_secs: 600,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundLimitsConfig {
    pub max_recipients_per_message: u32,
    pub max_messages_per_session: u32,
    pub max_message_size_mb: u32,
    pub max_received_headers: u32,
    pub max_line_length: u32,
    pub max_auth_attempts: u32,
    pub max_commands_per_session: u32,
    pub strict_ehlo_validation: bool,
}

impl Default for InboundLimitsConfig {
    fn default() -> Self {
        Self {
            max_recipients_per_message: 100,
            max_messages_per_session: 50,
            max_message_size_mb: 50,
            max_received_headers: 50,
            max_line_length: 998,
            max_auth_attempts: 3,
            max_commands_per_session: 1000,
            strict_ehlo_validation: false,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// TLS
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub min_version: String,
    pub sni_enabled: bool,
    #[serde(default)]
    pub sni_certs: Vec<SniCertConfig>,
    #[serde(default)]
    pub acme: AcmeConfig,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_path: "/etc/sentio/cert.pem".to_string(),
            key_path: "/etc/sentio/key.pem".to_string(),
            min_version: "1.2".to_string(),
            sni_enabled: true,
            sni_certs: Vec::new(),
            acme: AcmeConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SniCertConfig {
    pub domains: Vec<String>,
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    pub enabled: bool,
    pub email: String,
    pub directory_url: String,
    #[serde(default)]
    pub domains: Vec<String>,
    pub storage_path: String,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            email: "admin@example.com".to_string(),
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".to_string(),
            domains: vec!["mail.example.com".into()],
            storage_path: "/etc/sentio/acme".to_string(),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Database
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "postgres://sentio:sentio@localhost:5432/sentio".to_string(),
            max_connections: 50,
            min_connections: 5,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// KV store
// ──────────────────────────────────────────────────────────────────────────────

/// Selector for which KV backend Sentio should use. Backends share the
/// `KvConn` surface; connection settings live in the matching section
/// (`[redis]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvConfig {
    /// Which KV backend to use. This build ships `"redis"` only.
    #[serde(default = "default_kv_backend")]
    pub backend: String,
}

fn default_kv_backend() -> String {
    "redis".to_string()
}

impl Default for KvConfig {
    fn default() -> Self {
        Self {
            backend: default_kv_backend(),
        }
    }
}

// ── Redis backend ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    /// Redis connection URL, e.g. `redis://127.0.0.1:6379/0` or
    /// `rediss://user:pass@host:6380/0` for TLS.
    pub url: String,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: "redis://127.0.0.1:6379/0".to_string(),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// NATS (JetStream)
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsConfig {
    /// NATS server URL, e.g. "nats://127.0.0.1:4222".
    pub url: String,
    /// Maximum number of un-acknowledged messages in flight per consumer.
    /// Used as the JetStream consumer `max_ack_pending`.
    pub prefetch_count: u16,
    /// Same as `prefetch_count` but for LLM-bound consumers.
    pub llm_prefetch_count: u16,
    /// Retained for backwards compatibility with TOML files; JetStream `publish`
    /// always awaits an ack server-side, so the value is effectively ignored.
    pub publisher_confirms: bool,
    /// Initial NATS connection timeout in seconds.
    pub connection_timeout_secs: u64,
    /// Maximum number of `Nak`-with-delay retries before a message is sent to
    /// the dead-letter stream.
    #[serde(default = "default_nats_max_retries")]
    pub max_retries: u32,
    /// Max age, in seconds, of messages in the work/event streams (safety net).
    #[serde(default = "default_nats_stream_max_age_secs")]
    pub stream_max_age_secs: u64,
    /// Max age, in seconds, of messages in the dead-letter stream.
    #[serde(default = "default_nats_dead_stream_max_age_secs")]
    pub dead_stream_max_age_secs: u64,
}

fn default_nats_max_retries() -> u32 {
    5
}
fn default_nats_stream_max_age_secs() -> u64 {
    86_400
}
fn default_nats_dead_stream_max_age_secs() -> u64 {
    2_592_000
}

impl Default for NatsConfig {
    fn default() -> Self {
        Self {
            url: "nats://127.0.0.1:4222".to_string(),
            prefetch_count: 50,
            llm_prefetch_count: 1,
            publisher_confirms: true,
            connection_timeout_secs: 30,
            max_retries: default_nats_max_retries(),
            stream_max_age_secs: default_nats_stream_max_age_secs(),
            dead_stream_max_age_secs: default_nats_dead_stream_max_age_secs(),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Storage
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// S3-compatible endpoint URL. Works with any S3-compatible
    /// backend - AWS S3 (`https://s3.<region>.amazonaws.com`),
    /// Cloudflare R2, Backblaze B2, MinIO, SeaweedFS, Ceph RGW, Garage,
    /// etc. Accepts the legacy `endpoint_url` key.
    #[serde(alias = "endpoint_url")]
    pub endpoint_url: String,

    /// S3 access key.
    #[serde(default)]
    pub access_key: String,

    /// S3 secret key.
    #[serde(default)]
    pub secret_key: String,

    /// Bucket used for raw EMLs and attachments. Auto-created at
    /// startup if missing.
    #[serde(default = "default_bucket")]
    pub bucket: String,

    /// Force path-style addressing. Required for most self-hosted
    /// backends (MinIO, SeaweedFS, Ceph RGW); AWS S3 supports both
    /// vhost- and path-style; R2 requires vhost-style (set to false).
    #[serde(default = "default_true")]
    pub path_style: bool,

    /// Region. Required by the AWS SDK; many self-hosted backends
    /// ignore the value but the SDK still needs one set.
    #[serde(default = "default_region")]
    pub region: String,

    pub store_raw_eml: bool,
    pub orphan_cleanup_interval_hours: u32,
    pub orphan_max_age_hours: u32,
}

fn default_true() -> bool {
    true
}

fn default_region() -> String {
    "us-east-1".to_string()
}

fn default_bucket() -> String {
    "sentio-eml".to_string()
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            endpoint_url: "http://127.0.0.1:8333".to_string(),
            access_key: "sentio".to_string(),
            secret_key: "CHANGE_ME".to_string(),
            bucket: default_bucket(),
            path_style: true,
            region: default_region(),
            store_raw_eml: true,
            orphan_cleanup_interval_hours: 6,
            orphan_max_age_hours: 24,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Scanning
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanningConfig {
    pub enabled: bool,
    pub clamd_host: String,
    pub clamd_timeout_secs: u64,
    pub max_attachment_size_mb: u32,
    pub max_message_size_mb: u32,
    #[serde(default)]
    pub per_tenant_defaults: ScanningPerTenantDefaults,
}

impl Default for ScanningConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            clamd_host: "127.0.0.1:3310".to_string(),
            clamd_timeout_secs: 30,
            max_attachment_size_mb: 25,
            max_message_size_mb: 50,
            per_tenant_defaults: ScanningPerTenantDefaults::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanningPerTenantDefaults {
    pub scan_inbound: bool,
    pub scan_outbound: bool,
    pub reject_on_virus: bool,
}

impl Default for ScanningPerTenantDefaults {
    fn default() -> Self {
        Self {
            scan_inbound: true,
            scan_outbound: false,
            reject_on_virus: true,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Abuse
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbuseConfig {
    pub max_connections_per_minute: u32,
    pub max_auth_failures_per_hour: u32,
    pub ban_duration_secs: u64,
    /// Score above which a warning is logged (but connection proceeds).
    pub reputation_warn_threshold: f64,
    /// Score above which the connection is greylisted (tempfail).
    pub reputation_greylist_threshold: f64,
    /// Score above which the connection is rejected permanently.
    pub reputation_reject_threshold: f64,
    pub reputation_decay_hours: u32,
    pub reverse_dns_required: bool,
    #[serde(default)]
    pub dnsbl_lists: Vec<String>,
    pub dnsbl_cache_secs: u64,
    #[serde(default)]
    pub whitelist_ips: Vec<String>,
    #[serde(default)]
    pub whitelist_cidrs: Vec<String>,
    #[serde(default)]
    pub greylist: GreylistConfig,
}

impl Default for AbuseConfig {
    fn default() -> Self {
        Self {
            max_connections_per_minute: 50,
            max_auth_failures_per_hour: 10,
            ban_duration_secs: 3600,
            reputation_warn_threshold: 5.0,
            reputation_greylist_threshold: 7.5,
            reputation_reject_threshold: 10.0,
            reputation_decay_hours: 24,
            reverse_dns_required: false,
            dnsbl_lists: vec!["zen.spamhaus.org".into(), "b.barracudacentral.org".into()],
            dnsbl_cache_secs: 3600,
            whitelist_ips: Vec::new(),
            whitelist_cidrs: Vec::new(),
            greylist: GreylistConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GreylistConfig {
    pub enabled: bool,
    pub min_delay_secs: u64,
    pub max_age_hours: u32,
}

impl Default for GreylistConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_delay_secs: 300,
            max_age_hours: 48,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Spam
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpamConfig {
    pub backend: String,
    pub score_reject: f64,
    pub score_add_header: f64,
    pub score_greylist: f64,
    pub score_llm_review_min: f64,
    pub score_llm_review_max: f64,
    #[serde(default)]
    pub rspamd: RspamdConfig,
    #[serde(default)]
    pub builtin: BuiltinSpamConfig,
}

impl Default for SpamConfig {
    fn default() -> Self {
        Self {
            backend: "rspamd".to_string(),
            score_reject: 12.0,
            score_add_header: 6.0,
            score_greylist: 4.0,
            score_llm_review_min: 4.0,
            score_llm_review_max: 6.0,
            rspamd: RspamdConfig::default(),
            builtin: BuiltinSpamConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RspamdConfig {
    pub url: String,
    pub timeout_secs: u64,
    pub password: String,
}

impl Default for RspamdConfig {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:11333".to_string(),
            timeout_secs: 10,
            password: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuiltinSpamConfig {
    #[serde(default)]
    pub dnsbl_lists: Vec<String>,
    #[serde(default)]
    pub uribl_lists: Vec<String>,
    pub bayes_enabled: bool,
    pub heuristics_enabled: bool,
}

impl Default for BuiltinSpamConfig {
    fn default() -> Self {
        Self {
            dnsbl_lists: vec!["zen.spamhaus.org".into(), "b.barracudacentral.org".into()],
            uribl_lists: vec!["multi.uribl.com".into(), "dbl.spamhaus.org".into()],
            bayes_enabled: true,
            heuristics_enabled: true,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Delivery
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryConfig {
    pub max_connections: u32,
    pub max_connections_per_dest: u32,
    pub idle_timeout_secs: u64,
    pub retry_base_secs: u64,
    pub retry_max_secs: u64,
    pub max_retries: u32,
    pub queue_lifetime_days: u32,
    pub batch_size: u32,
    pub max_schedule_hours: u32,
    #[serde(default)]
    pub rate_limits: DeliveryRateLimitsConfig,
    #[serde(default)]
    pub relay: RelayConfig,
    #[serde(default)]
    pub domain_overrides: HashMap<String, DomainRetryOverride>,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            max_connections: 1000,
            max_connections_per_dest: 20,
            idle_timeout_secs: 300,
            retry_base_secs: 300,
            retry_max_secs: 4000,
            max_retries: 50,
            queue_lifetime_days: 5,
            batch_size: 100,
            max_schedule_hours: 72,
            rate_limits: DeliveryRateLimitsConfig::default(),
            relay: RelayConfig::default(),
            domain_overrides: HashMap::new(),
        }
    }
}

/// Per-domain retry overrides. Any `None` field falls back to the global config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRetryOverride {
    pub retry_base_secs: Option<u64>,
    pub retry_max_secs: Option<u64>,
    pub max_retries: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryRateLimitsConfig {
    pub default_per_minute: u32,
    pub gmail_per_minute: u32,
    pub microsoft_per_minute: u32,
}

impl Default for DeliveryRateLimitsConfig {
    fn default() -> Self {
        Self {
            default_per_minute: 100,
            gmail_per_minute: 50,
            microsoft_per_minute: 80,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RelayConfig {
    pub enabled: bool,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub auth_username: Option<String>,
    pub auth_password_env: Option<String>,
    pub tls_mode: Option<String>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Auth
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub dkim_default_selector: String,
    pub dkim_algorithm: String,
    pub dkim_rsa_key_bits: u32,
    pub spf_check_inbound: bool,
    pub dmarc_check_inbound: bool,
    pub arc_sign_forward: bool,
    pub mta_sts_cache_secs: u64,
    pub dane_enabled: bool,
    pub bimi_check_inbound: bool,
    pub bimi_vmc_required: bool,
    #[serde(default)]
    pub fbl: FblConfig,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            dkim_default_selector: "sentio".to_string(),
            dkim_algorithm: "ed25519".to_string(),
            dkim_rsa_key_bits: 2048,
            spf_check_inbound: true,
            dmarc_check_inbound: true,
            arc_sign_forward: true,
            mta_sts_cache_secs: 86400,
            dane_enabled: true,
            bimi_check_inbound: true,
            bimi_vmc_required: false,
            fbl: FblConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FblConfig {
    pub enabled: bool,
    pub fbl_address: String,
    pub auto_suppress: bool,
}

impl Default for FblConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            fbl_address: "fbl@mail.example.com".to_string(),
            auto_suppress: true,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Deliverability
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliverabilityConfig {
    pub list_unsubscribe_enabled: bool,
    pub batv_enabled: bool,
    pub batv_key: String,
    pub batv_tag_lifetime_days: u32,
    #[serde(default)]
    pub required_addresses: Vec<String>,
    /// How often the background DNS verification task re-checks all
    /// verified domains (SPF / DKIM / DMARC / MX / Return-Path).
    #[serde(default = "default_dns_check_interval_hours")]
    pub dns_check_interval_hours: u32,
}

fn default_dns_check_interval_hours() -> u32 {
    6
}

impl Default for DeliverabilityConfig {
    fn default() -> Self {
        Self {
            list_unsubscribe_enabled: true,
            batv_enabled: true,
            batv_key: String::new(),
            batv_tag_lifetime_days: 7,
            required_addresses: vec!["postmaster".into(), "abuse".into()],
            dns_check_interval_hours: default_dns_check_interval_hours(),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tracking
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrackingConfig {
    pub open_tracking: bool,
    pub click_tracking: bool,
    pub tracking_domain: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Webhooks
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhooksConfig {
    pub max_retries: u32,
    pub retry_backoff_base_secs: u64,
    pub signing_algorithm: String,
    pub delivery_timeout_secs: u64,
    pub max_concurrent_per_endpoint: u32,
    pub max_per_second_per_endpoint: u32,
}

impl Default for WebhooksConfig {
    fn default() -> Self {
        Self {
            max_retries: 10,
            retry_backoff_base_secs: 60,
            signing_algorithm: "hmac-sha256".to_string(),
            delivery_timeout_secs: 30,
            max_concurrent_per_endpoint: 10,
            max_per_second_per_endpoint: 100,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// LLM
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    pub enabled: bool,
    pub provider: String,
    pub model: String,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub api_key_env: String,
    pub temperature: f64,
    pub max_input_tokens: u32,
    pub classify_inbound: bool,
    pub classify_outbound: bool,
    pub auto_respond: bool,
    /// Which OpenAI-compatible API surface to call on the openai
    /// provider: `"chat_completions"` (legacy `/v1/chat/completions`,
    /// the default) or `"responses"` (2025 `/v1/responses` with a
    /// structured reasoning channel). Only consulted when `provider =
    /// "openai"`. Anthropic and Ollama providers ignore this field.
    #[serde(default = "default_openai_api")]
    pub openai_api: String,
    #[serde(default)]
    pub ollama: OllamaConfig,
}

fn default_openai_api() -> String {
    "chat_completions".to_string()
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: "anthropic".to_string(),
            model: "claude-sonnet-5".to_string(),
            base_url: None,
            api_key_env: String::new(),
            temperature: 0.3,
            max_input_tokens: 2000,
            classify_inbound: true,
            classify_outbound: false,
            auto_respond: false,
            openai_api: default_openai_api(),
            ollama: OllamaConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OllamaConfig {
    pub base_url: String,
    pub model: String,
}

impl Default for OllamaConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:11434".to_string(),
            model: "llama3".to_string(),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Observability
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    pub log_format: String,
    pub log_level: String,
    pub metrics_endpoint: String,
    pub otlp_endpoint: String,
    pub tracing_sample_rate: f64,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            log_format: "json".to_string(),
            log_level: "info".to_string(),
            metrics_endpoint: "0.0.0.0:9090".to_string(),
            otlp_endpoint: String::new(),
            tracing_sample_rate: 0.1,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Analytics
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsConfig {
    pub backend: String,
    pub clickhouse_url: String,
    pub clickhouse_database: String,
}

impl Default for AnalyticsConfig {
    fn default() -> Self {
        Self {
            backend: "none".to_string(),
            clickhouse_url: "http://localhost:8123".to_string(),
            clickhouse_database: "sentio".to_string(),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Error Events
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorEventsConfig {
    pub retention_days: u32,
}

impl Default for ErrorEventsConfig {
    fn default() -> Self {
        Self { retention_days: 30 }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Listmonk bounce bridge
// ──────────────────────────────────────────────────────────────────────────────
//
// Forwards Sentio bounce events to Listmonk's `/webhooks/bounce` endpoint
// so Listmonk can apply its subscriber threshold rules. See
// `sentio-smtp-server::listmonk_bridge` for the actual consumer.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListmonkConfig {
    pub enabled: bool,
    /// Full URL including scheme + path, e.g. `https://lists.example.com/webhooks/bounce`.
    pub url: String,
    /// Listmonk API username (HTTP Basic).
    pub username: String,
    /// Listmonk API access token (HTTP Basic password).
    pub password: String,
    /// Per-request timeout. Defaults to 10s - Listmonk's `/webhooks/bounce`
    /// is a simple DB insert and should respond in well under a second; a
    /// 10s ceiling protects the consumer from a hung receiver.
    pub timeout_secs: u64,
}

impl Default for ListmonkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            username: String::new(),
            password: String::new(),
            timeout_secs: 10,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Loading
// ──────────────────────────────────────────────────────────────────────────────

pub fn load_config(path: &Path) -> Result<SentioConfig, ConfigError> {
    let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;

    let mut config: SentioConfig = toml::from_str(&contents)?;

    apply_env_overrides(&mut config)?;

    config.validate()?;

    tracing::info!(path = %path.display(), "configuration loaded successfully");
    Ok(config)
}

// ──────────────────────────────────────────────────────────────────────────────
// Environment variable overrides
// ──────────────────────────────────────────────────────────────────────────────

fn apply_env_overrides(config: &mut SentioConfig) -> Result<(), ConfigError> {
    apply_env_overrides_from(config, std::env::vars())
}

fn apply_env_overrides_from(
    config: &mut SentioConfig,
    vars: impl Iterator<Item = (String, String)>,
) -> Result<(), ConfigError> {
    for (key, value) in vars {
        let Some(rest) = key.strip_prefix("SENTIO__") else {
            continue;
        };
        let parts: Vec<&str> = rest.split("__").collect();
        apply_single_override(config, &key, &parts, &value)?;
    }
    Ok(())
}

fn parse_env<T: FromStr>(key: &str, value: &str) -> Result<T, ConfigError>
where
    T::Err: std::fmt::Display,
{
    value.parse::<T>().map_err(|e| ConfigError::EnvOverride {
        key: key.to_string(),
        message: format!("failed to parse '{}': {}", value, e),
    })
}

fn parse_csv(value: &str) -> Vec<String> {
    if value.is_empty() {
        Vec::new()
    } else {
        value.split(',').map(|s| s.trim().to_string()).collect()
    }
}

fn parse_optional_string(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn parse_optional_env<T: FromStr>(key: &str, value: &str) -> Result<Option<T>, ConfigError>
where
    T::Err: std::fmt::Display,
{
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(parse_env(key, value)?))
    }
}

#[allow(clippy::too_many_lines)]
fn apply_single_override(
    config: &mut SentioConfig,
    full_key: &str,
    parts: &[&str],
    value: &str,
) -> Result<(), ConfigError> {
    match parts {
        // ── Server ──────────────────────────────────────────────────────
        ["SERVER", "HOSTNAME"] => config.server.hostname = value.to_string(),
        ["SERVER", "API_BASE_URL"] => config.server.api_base_url = value.to_string(),
        ["SERVER", "LISTEN_SMTP"] => config.server.listen_smtp = parse_csv(value),
        ["SERVER", "LISTEN_SMTPS"] => config.server.listen_smtps = parse_csv(value),
        ["SERVER", "LISTEN_SUBMISSION"] => config.server.listen_submission = parse_csv(value),
        ["SERVER", "LISTEN_API"] => config.server.listen_api = value.to_string(),
        ["SERVER", "WORKERS"] => config.server.workers = parse_env(full_key, value)?,
        ["SERVER", "MAX_CONNECTIONS"] => {
            config.server.max_connections = parse_env(full_key, value)?;
        }
        ["SERVER", "PROXY_PROTOCOL"] => config.server.proxy_protocol = parse_env(full_key, value)?,
        ["SERVER", "XCLIENT_ENABLED"] => {
            config.server.xclient_enabled = parse_env(full_key, value)?;
        }
        ["SERVER", "XCLIENT_ALLOWED_IPS"] => {
            config.server.xclient_allowed_ips = parse_csv(value);
        }
        ["SERVER", "SHUTDOWN_DRAIN_SECS"] => {
            config.server.shutdown_drain_secs = parse_env(full_key, value)?;
        }
        ["SERVER", "SHUTDOWN_FORCE_SECS"] => {
            config.server.shutdown_force_secs = parse_env(full_key, value)?;
        }
        // Server → inbound_timeouts
        ["SERVER", "INBOUND_TIMEOUTS", "GREETING_SECS"] => {
            config.server.inbound_timeouts.greeting_secs = parse_env(full_key, value)?;
        }
        ["SERVER", "INBOUND_TIMEOUTS", "COMMAND_SECS"] => {
            config.server.inbound_timeouts.command_secs = parse_env(full_key, value)?;
        }
        ["SERVER", "INBOUND_TIMEOUTS", "DATA_INITIATION_SECS"] => {
            config.server.inbound_timeouts.data_initiation_secs = parse_env(full_key, value)?;
        }
        ["SERVER", "INBOUND_TIMEOUTS", "DATA_BLOCK_SECS"] => {
            config.server.inbound_timeouts.data_block_secs = parse_env(full_key, value)?;
        }
        ["SERVER", "INBOUND_TIMEOUTS", "DATA_TERMINATION_SECS"] => {
            config.server.inbound_timeouts.data_termination_secs = parse_env(full_key, value)?;
        }
        // Server → inbound_limits
        ["SERVER", "INBOUND_LIMITS", "MAX_RECIPIENTS_PER_MESSAGE"] => {
            config.server.inbound_limits.max_recipients_per_message = parse_env(full_key, value)?;
        }
        ["SERVER", "INBOUND_LIMITS", "MAX_MESSAGES_PER_SESSION"] => {
            config.server.inbound_limits.max_messages_per_session = parse_env(full_key, value)?;
        }
        ["SERVER", "INBOUND_LIMITS", "MAX_MESSAGE_SIZE_MB"] => {
            config.server.inbound_limits.max_message_size_mb = parse_env(full_key, value)?;
        }
        ["SERVER", "INBOUND_LIMITS", "MAX_RECEIVED_HEADERS"] => {
            config.server.inbound_limits.max_received_headers = parse_env(full_key, value)?;
        }
        ["SERVER", "INBOUND_LIMITS", "MAX_LINE_LENGTH"] => {
            config.server.inbound_limits.max_line_length = parse_env(full_key, value)?;
        }
        ["SERVER", "INBOUND_LIMITS", "MAX_AUTH_ATTEMPTS"] => {
            config.server.inbound_limits.max_auth_attempts = parse_env(full_key, value)?;
        }
        ["SERVER", "INBOUND_LIMITS", "MAX_COMMANDS_PER_SESSION"] => {
            config.server.inbound_limits.max_commands_per_session = parse_env(full_key, value)?;
        }
        ["SERVER", "INBOUND_LIMITS", "STRICT_EHLO_VALIDATION"] => {
            config.server.inbound_limits.strict_ehlo_validation = parse_env(full_key, value)?;
        }
        ["SERVER", "VERP_SECRET"] => {
            config.server.verp_secret = parse_optional_string(value);
        }

        // ── TLS ─────────────────────────────────────────────────────────
        ["TLS", "CERT_PATH"] => config.tls.cert_path = value.to_string(),
        ["TLS", "KEY_PATH"] => config.tls.key_path = value.to_string(),
        ["TLS", "MIN_VERSION"] => config.tls.min_version = value.to_string(),
        ["TLS", "SNI_ENABLED"] => config.tls.sni_enabled = parse_env(full_key, value)?,
        // TLS → ACME
        ["TLS", "ACME", "ENABLED"] => config.tls.acme.enabled = parse_env(full_key, value)?,
        ["TLS", "ACME", "EMAIL"] => config.tls.acme.email = value.to_string(),
        ["TLS", "ACME", "DIRECTORY_URL"] => config.tls.acme.directory_url = value.to_string(),
        ["TLS", "ACME", "DOMAINS"] => config.tls.acme.domains = parse_csv(value),
        ["TLS", "ACME", "STORAGE_PATH"] => config.tls.acme.storage_path = value.to_string(),

        // ── Database ────────────────────────────────────────────────────
        ["DATABASE", "URL"] => config.database.url = value.to_string(),
        ["DATABASE", "MAX_CONNECTIONS"] => {
            config.database.max_connections = parse_env(full_key, value)?;
        }
        ["DATABASE", "MIN_CONNECTIONS"] => {
            config.database.min_connections = parse_env(full_key, value)?;
        }

        // ── KV backend selector ─────────────────────────────────────────
        ["KV", "BACKEND"] => config.kv.backend = value.to_string(),

        // ── Redis ───────────────────────────────────────────────────────
        ["REDIS", "URL"] => config.redis.url = value.to_string(),

        // ── NATS / JetStream ────────────────────────────────────────────
        ["NATS", "URL"] => config.nats.url = value.to_string(),
        ["NATS", "PREFETCH_COUNT"] => {
            config.nats.prefetch_count = parse_env(full_key, value)?;
        }
        ["NATS", "LLM_PREFETCH_COUNT"] => {
            config.nats.llm_prefetch_count = parse_env(full_key, value)?;
        }
        ["NATS", "PUBLISHER_CONFIRMS"] => {
            config.nats.publisher_confirms = parse_env(full_key, value)?;
        }
        ["NATS", "CONNECTION_TIMEOUT_SECS"] => {
            config.nats.connection_timeout_secs = parse_env(full_key, value)?;
        }
        ["NATS", "MAX_RETRIES"] => {
            config.nats.max_retries = parse_env(full_key, value)?;
        }
        ["NATS", "STREAM_MAX_AGE_SECS"] => {
            config.nats.stream_max_age_secs = parse_env(full_key, value)?;
        }
        ["NATS", "DEAD_STREAM_MAX_AGE_SECS"] => {
            config.nats.dead_stream_max_age_secs = parse_env(full_key, value)?;
        }

        // ── Storage ─────────────────────────────────────────────────────
        ["STORAGE", "ENDPOINT_URL"] => {
            config.storage.endpoint_url = value.to_string();
        }
        ["STORAGE", "ACCESS_KEY"] => {
            config.storage.access_key = value.to_string();
        }
        ["STORAGE", "SECRET_KEY"] => {
            config.storage.secret_key = value.to_string();
        }
        ["STORAGE", "BUCKET"] => {
            config.storage.bucket = value.to_string();
        }
        ["STORAGE", "PATH_STYLE"] => {
            config.storage.path_style = parse_env(full_key, value)?;
        }
        ["STORAGE", "REGION"] => {
            config.storage.region = value.to_string();
        }
        ["STORAGE", "STORE_RAW_EML"] => {
            config.storage.store_raw_eml = parse_env(full_key, value)?;
        }
        ["STORAGE", "ORPHAN_CLEANUP_INTERVAL_HOURS"] => {
            config.storage.orphan_cleanup_interval_hours = parse_env(full_key, value)?;
        }
        ["STORAGE", "ORPHAN_MAX_AGE_HOURS"] => {
            config.storage.orphan_max_age_hours = parse_env(full_key, value)?;
        }

        // ── Scanning ────────────────────────────────────────────────────
        ["SCANNING", "ENABLED"] => config.scanning.enabled = parse_env(full_key, value)?,
        ["SCANNING", "CLAMD_HOST"] => config.scanning.clamd_host = value.to_string(),
        ["SCANNING", "CLAMD_TIMEOUT_SECS"] => {
            config.scanning.clamd_timeout_secs = parse_env(full_key, value)?;
        }
        ["SCANNING", "MAX_ATTACHMENT_SIZE_MB"] => {
            config.scanning.max_attachment_size_mb = parse_env(full_key, value)?;
        }
        ["SCANNING", "MAX_MESSAGE_SIZE_MB"] => {
            config.scanning.max_message_size_mb = parse_env(full_key, value)?;
        }
        ["SCANNING", "PER_TENANT_DEFAULTS", "SCAN_INBOUND"] => {
            config.scanning.per_tenant_defaults.scan_inbound = parse_env(full_key, value)?;
        }
        ["SCANNING", "PER_TENANT_DEFAULTS", "SCAN_OUTBOUND"] => {
            config.scanning.per_tenant_defaults.scan_outbound = parse_env(full_key, value)?;
        }
        ["SCANNING", "PER_TENANT_DEFAULTS", "REJECT_ON_VIRUS"] => {
            config.scanning.per_tenant_defaults.reject_on_virus = parse_env(full_key, value)?;
        }

        // ── Abuse ───────────────────────────────────────────────────────
        ["ABUSE", "MAX_CONNECTIONS_PER_MINUTE"] => {
            config.abuse.max_connections_per_minute = parse_env(full_key, value)?;
        }
        ["ABUSE", "MAX_AUTH_FAILURES_PER_HOUR"] => {
            config.abuse.max_auth_failures_per_hour = parse_env(full_key, value)?;
        }
        ["ABUSE", "BAN_DURATION_SECS"] => {
            config.abuse.ban_duration_secs = parse_env(full_key, value)?;
        }
        ["ABUSE", "REPUTATION_WARN_THRESHOLD"] => {
            config.abuse.reputation_warn_threshold = parse_env(full_key, value)?;
        }
        ["ABUSE", "REPUTATION_GREYLIST_THRESHOLD"] => {
            config.abuse.reputation_greylist_threshold = parse_env(full_key, value)?;
        }
        ["ABUSE", "REPUTATION_REJECT_THRESHOLD"] => {
            config.abuse.reputation_reject_threshold = parse_env(full_key, value)?;
        }
        ["ABUSE", "REPUTATION_DECAY_HOURS"] => {
            config.abuse.reputation_decay_hours = parse_env(full_key, value)?;
        }
        ["ABUSE", "REVERSE_DNS_REQUIRED"] => {
            config.abuse.reverse_dns_required = parse_env(full_key, value)?;
        }
        ["ABUSE", "DNSBL_LISTS"] => config.abuse.dnsbl_lists = parse_csv(value),
        ["ABUSE", "WHITELIST_IPS"] => config.abuse.whitelist_ips = parse_csv(value),
        ["ABUSE", "WHITELIST_CIDRS"] => config.abuse.whitelist_cidrs = parse_csv(value),
        ["ABUSE", "DNSBL_CACHE_SECS"] => {
            config.abuse.dnsbl_cache_secs = parse_env(full_key, value)?;
        }
        ["ABUSE", "GREYLIST", "ENABLED"] => {
            config.abuse.greylist.enabled = parse_env(full_key, value)?;
        }
        ["ABUSE", "GREYLIST", "MIN_DELAY_SECS"] => {
            config.abuse.greylist.min_delay_secs = parse_env(full_key, value)?;
        }
        ["ABUSE", "GREYLIST", "MAX_AGE_HOURS"] => {
            config.abuse.greylist.max_age_hours = parse_env(full_key, value)?;
        }

        // ── Spam ────────────────────────────────────────────────────────
        ["SPAM", "BACKEND"] => config.spam.backend = value.to_string(),
        ["SPAM", "SCORE_REJECT"] => config.spam.score_reject = parse_env(full_key, value)?,
        ["SPAM", "SCORE_ADD_HEADER"] => {
            config.spam.score_add_header = parse_env(full_key, value)?;
        }
        ["SPAM", "SCORE_GREYLIST"] => config.spam.score_greylist = parse_env(full_key, value)?,
        ["SPAM", "SCORE_LLM_REVIEW_MIN"] => {
            config.spam.score_llm_review_min = parse_env(full_key, value)?;
        }
        ["SPAM", "SCORE_LLM_REVIEW_MAX"] => {
            config.spam.score_llm_review_max = parse_env(full_key, value)?;
        }
        ["SPAM", "RSPAMD", "URL"] => config.spam.rspamd.url = value.to_string(),
        ["SPAM", "RSPAMD", "TIMEOUT_SECS"] => {
            config.spam.rspamd.timeout_secs = parse_env(full_key, value)?;
        }
        ["SPAM", "RSPAMD", "PASSWORD"] => config.spam.rspamd.password = value.to_string(),
        ["SPAM", "BUILTIN", "DNSBL_LISTS"] => {
            config.spam.builtin.dnsbl_lists = parse_csv(value);
        }
        ["SPAM", "BUILTIN", "URIBL_LISTS"] => {
            config.spam.builtin.uribl_lists = parse_csv(value);
        }
        ["SPAM", "BUILTIN", "BAYES_ENABLED"] => {
            config.spam.builtin.bayes_enabled = parse_env(full_key, value)?;
        }
        ["SPAM", "BUILTIN", "HEURISTICS_ENABLED"] => {
            config.spam.builtin.heuristics_enabled = parse_env(full_key, value)?;
        }

        // ── Delivery ────────────────────────────────────────────────────
        ["DELIVERY", "MAX_CONNECTIONS"] => {
            config.delivery.max_connections = parse_env(full_key, value)?;
        }
        ["DELIVERY", "MAX_CONNECTIONS_PER_DEST"] => {
            config.delivery.max_connections_per_dest = parse_env(full_key, value)?;
        }
        ["DELIVERY", "IDLE_TIMEOUT_SECS"] => {
            config.delivery.idle_timeout_secs = parse_env(full_key, value)?;
        }
        ["DELIVERY", "RETRY_BASE_SECS"] => {
            config.delivery.retry_base_secs = parse_env(full_key, value)?;
        }
        ["DELIVERY", "RETRY_MAX_SECS"] => {
            config.delivery.retry_max_secs = parse_env(full_key, value)?;
        }
        ["DELIVERY", "MAX_RETRIES"] => {
            config.delivery.max_retries = parse_env(full_key, value)?;
        }
        ["DELIVERY", "QUEUE_LIFETIME_DAYS"] => {
            config.delivery.queue_lifetime_days = parse_env(full_key, value)?;
        }
        ["DELIVERY", "BATCH_SIZE"] => {
            config.delivery.batch_size = parse_env(full_key, value)?;
        }
        ["DELIVERY", "MAX_SCHEDULE_HOURS"] => {
            config.delivery.max_schedule_hours = parse_env(full_key, value)?;
        }
        ["DELIVERY", "RATE_LIMITS", "DEFAULT_PER_MINUTE"] => {
            config.delivery.rate_limits.default_per_minute = parse_env(full_key, value)?;
        }
        ["DELIVERY", "RATE_LIMITS", "GMAIL_PER_MINUTE"] => {
            config.delivery.rate_limits.gmail_per_minute = parse_env(full_key, value)?;
        }
        ["DELIVERY", "RATE_LIMITS", "MICROSOFT_PER_MINUTE"] => {
            config.delivery.rate_limits.microsoft_per_minute = parse_env(full_key, value)?;
        }
        ["DELIVERY", "RELAY", "ENABLED"] => {
            config.delivery.relay.enabled = parse_env(full_key, value)?;
        }
        ["DELIVERY", "RELAY", "HOST"] => {
            config.delivery.relay.host = parse_optional_string(value);
        }
        ["DELIVERY", "RELAY", "PORT"] => {
            config.delivery.relay.port = parse_optional_env(full_key, value)?;
        }
        ["DELIVERY", "RELAY", "AUTH_USERNAME"] => {
            config.delivery.relay.auth_username = parse_optional_string(value);
        }
        ["DELIVERY", "RELAY", "AUTH_PASSWORD_ENV"] => {
            config.delivery.relay.auth_password_env = parse_optional_string(value);
        }
        ["DELIVERY", "RELAY", "TLS_MODE"] => {
            config.delivery.relay.tls_mode = parse_optional_string(value);
        }

        // ── Auth ────────────────────────────────────────────────────────
        ["AUTH", "DKIM_DEFAULT_SELECTOR"] => {
            config.auth.dkim_default_selector = value.to_string();
        }
        ["AUTH", "DKIM_ALGORITHM"] => config.auth.dkim_algorithm = value.to_string(),
        ["AUTH", "DKIM_RSA_KEY_BITS"] => {
            config.auth.dkim_rsa_key_bits = parse_env(full_key, value)?;
        }
        ["AUTH", "SPF_CHECK_INBOUND"] => {
            config.auth.spf_check_inbound = parse_env(full_key, value)?;
        }
        ["AUTH", "DMARC_CHECK_INBOUND"] => {
            config.auth.dmarc_check_inbound = parse_env(full_key, value)?;
        }
        ["AUTH", "ARC_SIGN_FORWARD"] => {
            config.auth.arc_sign_forward = parse_env(full_key, value)?;
        }
        ["AUTH", "MTA_STS_CACHE_SECS"] => {
            config.auth.mta_sts_cache_secs = parse_env(full_key, value)?;
        }
        ["AUTH", "DANE_ENABLED"] => config.auth.dane_enabled = parse_env(full_key, value)?,
        ["AUTH", "BIMI_CHECK_INBOUND"] => {
            config.auth.bimi_check_inbound = parse_env(full_key, value)?;
        }
        ["AUTH", "BIMI_VMC_REQUIRED"] => {
            config.auth.bimi_vmc_required = parse_env(full_key, value)?;
        }
        ["AUTH", "FBL", "ENABLED"] => config.auth.fbl.enabled = parse_env(full_key, value)?,
        ["AUTH", "FBL", "FBL_ADDRESS"] => config.auth.fbl.fbl_address = value.to_string(),
        ["AUTH", "FBL", "AUTO_SUPPRESS"] => {
            config.auth.fbl.auto_suppress = parse_env(full_key, value)?;
        }

        // ── Deliverability ──────────────────────────────────────────────
        ["DELIVERABILITY", "LIST_UNSUBSCRIBE_ENABLED"] => {
            config.deliverability.list_unsubscribe_enabled = parse_env(full_key, value)?;
        }
        ["DELIVERABILITY", "BATV_ENABLED"] => {
            config.deliverability.batv_enabled = parse_env(full_key, value)?;
        }
        ["DELIVERABILITY", "BATV_KEY"] => config.deliverability.batv_key = value.to_string(),
        ["DELIVERABILITY", "BATV_TAG_LIFETIME_DAYS"] => {
            config.deliverability.batv_tag_lifetime_days = parse_env(full_key, value)?;
        }
        ["DELIVERABILITY", "REQUIRED_ADDRESSES"] => {
            config.deliverability.required_addresses = parse_csv(value);
        }
        ["DELIVERABILITY", "DNS_CHECK_INTERVAL_HOURS"] => {
            config.deliverability.dns_check_interval_hours = parse_env(full_key, value)?;
        }

        // ── Tracking ────────────────────────────────────────────────────
        ["TRACKING", "OPEN_TRACKING"] => {
            config.tracking.open_tracking = parse_env(full_key, value)?;
        }
        ["TRACKING", "CLICK_TRACKING"] => {
            config.tracking.click_tracking = parse_env(full_key, value)?;
        }
        ["TRACKING", "TRACKING_DOMAIN"] => config.tracking.tracking_domain = value.to_string(),

        // ── Webhooks ────────────────────────────────────────────────────
        ["WEBHOOKS", "MAX_RETRIES"] => {
            config.webhooks.max_retries = parse_env(full_key, value)?;
        }
        ["WEBHOOKS", "RETRY_BACKOFF_BASE_SECS"] => {
            config.webhooks.retry_backoff_base_secs = parse_env(full_key, value)?;
        }
        ["WEBHOOKS", "SIGNING_ALGORITHM"] => {
            config.webhooks.signing_algorithm = value.to_string();
        }
        ["WEBHOOKS", "DELIVERY_TIMEOUT_SECS"] => {
            config.webhooks.delivery_timeout_secs = parse_env(full_key, value)?;
        }
        ["WEBHOOKS", "MAX_CONCURRENT_PER_ENDPOINT"] => {
            config.webhooks.max_concurrent_per_endpoint = parse_env(full_key, value)?;
        }
        ["WEBHOOKS", "MAX_PER_SECOND_PER_ENDPOINT"] => {
            config.webhooks.max_per_second_per_endpoint = parse_env(full_key, value)?;
        }

        // ── LLM ─────────────────────────────────────────────────────────
        ["LLM", "ENABLED"] => config.llm.enabled = parse_env(full_key, value)?,
        ["LLM", "PROVIDER"] => config.llm.provider = value.to_string(),
        ["LLM", "MODEL"] => config.llm.model = value.to_string(),
        ["LLM", "API_KEY_ENV"] => config.llm.api_key_env = value.to_string(),
        ["LLM", "TEMPERATURE"] => config.llm.temperature = parse_env(full_key, value)?,
        ["LLM", "MAX_INPUT_TOKENS"] => {
            config.llm.max_input_tokens = parse_env(full_key, value)?;
        }
        ["LLM", "CLASSIFY_INBOUND"] => {
            config.llm.classify_inbound = parse_env(full_key, value)?;
        }
        ["LLM", "CLASSIFY_OUTBOUND"] => {
            config.llm.classify_outbound = parse_env(full_key, value)?;
        }
        ["LLM", "AUTO_RESPOND"] => config.llm.auto_respond = parse_env(full_key, value)?,
        ["LLM", "OLLAMA", "BASE_URL"] => config.llm.ollama.base_url = value.to_string(),
        ["LLM", "OLLAMA", "MODEL"] => config.llm.ollama.model = value.to_string(),

        // ── Observability ───────────────────────────────────────────────
        ["OBSERVABILITY", "LOG_FORMAT"] => config.observability.log_format = value.to_string(),
        ["OBSERVABILITY", "LOG_LEVEL"] => config.observability.log_level = value.to_string(),
        ["OBSERVABILITY", "METRICS_ENDPOINT"] => {
            config.observability.metrics_endpoint = value.to_string();
        }
        ["OBSERVABILITY", "OTLP_ENDPOINT"] => {
            config.observability.otlp_endpoint = value.to_string();
        }
        ["OBSERVABILITY", "TRACING_SAMPLE_RATE"] => {
            config.observability.tracing_sample_rate = parse_env(full_key, value)?;
        }

        // ── Analytics ───────────────────────────────────────────────────
        ["ANALYTICS", "BACKEND"] => config.analytics.backend = value.to_string(),
        ["ANALYTICS", "CLICKHOUSE_URL"] => config.analytics.clickhouse_url = value.to_string(),
        ["ANALYTICS", "CLICKHOUSE_DATABASE"] => {
            config.analytics.clickhouse_database = value.to_string();
        }

        // ── Error Events ──────────────────────────────────────────────
        ["ERROR_EVENTS", "RETENTION_DAYS"] => {
            config.error_events.retention_days = parse_env(full_key, value)?;
        }

        _ => {
            tracing::warn!(key = %full_key, "unknown environment variable override, ignoring");
        }
    }
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Validation
// ──────────────────────────────────────────────────────────────────────────────

impl SentioConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut errors = Vec::new();

        // Required non-empty strings
        if self.server.hostname.is_empty() {
            errors.push("server.hostname must not be empty".into());
        }
        if self.database.url.is_empty() {
            errors.push("database.url must not be empty".into());
        }
        if self.redis.url.is_empty() {
            errors.push("redis.url must not be empty".into());
        }
        if self.nats.url.is_empty() {
            errors.push("nats.url must not be empty".into());
        }

        // At least one SMTP listener
        if self.server.listen_smtp.is_empty()
            && self.server.listen_smtps.is_empty()
            && self.server.listen_submission.is_empty()
        {
            errors.push("at least one SMTP listener must be configured (listen_smtp, listen_smtps, or listen_submission)".into());
        }

        // Socket address format for all listeners
        let listener_sets: &[(&str, &[String])] = &[
            ("server.listen_smtp", &self.server.listen_smtp),
            ("server.listen_smtps", &self.server.listen_smtps),
            ("server.listen_submission", &self.server.listen_submission),
        ];
        for (name, addrs) in listener_sets {
            for addr in *addrs {
                if SocketAddr::from_str(addr).is_err() {
                    errors.push(format!("{name}: '{addr}' is not a valid socket address"));
                }
            }
        }
        if !self.server.listen_api.is_empty()
            && SocketAddr::from_str(&self.server.listen_api).is_err()
        {
            errors.push(format!(
                "server.listen_api: '{}' is not a valid socket address",
                self.server.listen_api
            ));
        }

        // TLS min_version
        if !matches!(self.tls.min_version.as_str(), "1.2" | "1.3") {
            errors.push(format!(
                "tls.min_version must be \"1.2\" or \"1.3\", got \"{}\"",
                self.tls.min_version
            ));
        }

        // ACME: email + domains required when enabled
        if self.tls.acme.enabled {
            if self.tls.acme.email.is_empty() {
                errors.push("tls.acme.email must not be empty when ACME is enabled".into());
            }
            if self.tls.acme.domains.is_empty() {
                errors.push("tls.acme.domains must not be empty when ACME is enabled".into());
            }
        }

        // database.min_connections <= max_connections
        if self.database.min_connections > self.database.max_connections {
            errors.push(format!(
                "database.min_connections ({}) must be <= database.max_connections ({})",
                self.database.min_connections, self.database.max_connections
            ));
        }

        // Spam score ordering: greylist < add_header < reject
        if self.spam.score_greylist >= self.spam.score_add_header {
            errors.push(format!(
                "spam.score_greylist ({}) must be < spam.score_add_header ({})",
                self.spam.score_greylist, self.spam.score_add_header
            ));
        }
        if self.spam.score_add_header >= self.spam.score_reject {
            errors.push(format!(
                "spam.score_add_header ({}) must be < spam.score_reject ({})",
                self.spam.score_add_header, self.spam.score_reject
            ));
        }

        // LLM review band: min < max
        if self.spam.score_llm_review_min >= self.spam.score_llm_review_max {
            errors.push(format!(
                "spam.score_llm_review_min ({}) must be < spam.score_llm_review_max ({})",
                self.spam.score_llm_review_min, self.spam.score_llm_review_max
            ));
        }

        // Delivery retry: base > 0, base <= max
        if self.delivery.retry_base_secs == 0 {
            errors.push("delivery.retry_base_secs must be > 0".into());
        }
        if self.delivery.retry_base_secs > self.delivery.retry_max_secs {
            errors.push(format!(
                "delivery.retry_base_secs ({}) must be <= delivery.retry_max_secs ({})",
                self.delivery.retry_base_secs, self.delivery.retry_max_secs
            ));
        }

        // Relay: host required when enabled, tls_mode validation
        if self.delivery.relay.enabled {
            if self
                .delivery
                .relay
                .host
                .as_ref()
                .map_or(true, String::is_empty)
            {
                errors.push("delivery.relay.host is required when relay is enabled".into());
            }
            if let Some(ref mode) = self.delivery.relay.tls_mode {
                if !matches!(mode.as_str(), "starttls" | "implicit" | "none") {
                    errors.push(format!(
                        "delivery.relay.tls_mode must be \"starttls\", \"implicit\", or \"none\", got \"{mode}\""
                    ));
                }
            }
        }

        // Enum-like string fields
        if !matches!(self.spam.backend.as_str(), "rspamd" | "builtin") {
            errors.push(format!(
                "spam.backend must be \"rspamd\" or \"builtin\", got \"{}\"",
                self.spam.backend
            ));
        }
        if !matches!(self.auth.dkim_algorithm.as_str(), "ed25519" | "rsa") {
            errors.push(format!(
                "auth.dkim_algorithm must be \"ed25519\" or \"rsa\", got \"{}\"",
                self.auth.dkim_algorithm
            ));
        }
        if !matches!(self.observability.log_format.as_str(), "json" | "text") {
            errors.push(format!(
                "observability.log_format must be \"json\" or \"text\", got \"{}\"",
                self.observability.log_format
            ));
        }
        if !matches!(
            self.observability.log_level.as_str(),
            "trace" | "debug" | "info" | "warn" | "error"
        ) {
            errors.push(format!(
                "observability.log_level must be one of trace/debug/info/warn/error, got \"{}\"",
                self.observability.log_level
            ));
        }
        if !matches!(self.analytics.backend.as_str(), "none" | "clickhouse") {
            errors.push(format!(
                "analytics.backend must be \"none\" or \"clickhouse\", got \"{}\"",
                self.analytics.backend
            ));
        }

        // Tracing sample rate
        if !(0.0..=1.0).contains(&self.observability.tracing_sample_rate) {
            errors.push(format!(
                "observability.tracing_sample_rate must be between 0.0 and 1.0, got {}",
                self.observability.tracing_sample_rate
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::ValidationBatch { errors })
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn default_toml_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/default.toml")
    }

    #[test]
    fn parse_default_toml() {
        let config = load_config(&default_toml_path()).unwrap();
        assert_eq!(config.server.hostname, "mail.example.com");
        assert_eq!(
            config.database.url,
            "postgres://sentio:sentio@localhost:5432/sentio"
        );
        assert_eq!(config.server.listen_smtp.len(), 1);
        assert_eq!(config.server.inbound_timeouts.greeting_secs, 300);
        assert_eq!(config.spam.backend, "rspamd");
        // Shipped defaults must not enable an LLM or point at a host.
        assert!(!config.llm.enabled);
        assert_eq!(config.llm.base_url.as_deref(), Some(""));
    }

    #[test]
    fn empty_toml_produces_valid_defaults() {
        let config: SentioConfig = toml::from_str("").unwrap();
        assert_eq!(config.server.hostname, "mail.example.com");
        assert_eq!(config.server.workers, 0);
        assert_eq!(config.database.max_connections, 50);
        assert_eq!(config.tls.min_version, "1.2");
        config.validate().unwrap();
    }

    #[test]
    fn default_config_passes_validation() {
        let config = SentioConfig::default();
        config.validate().unwrap();
    }

    #[test]
    fn env_override_string() {
        let mut config = SentioConfig::default();
        let vars = vec![(
            "SENTIO__SERVER__HOSTNAME".to_string(),
            "custom.host.com".to_string(),
        )];
        apply_env_overrides_from(&mut config, vars.into_iter()).unwrap();
        assert_eq!(config.server.hostname, "custom.host.com");
    }

    #[test]
    fn env_override_integer() {
        let mut config = SentioConfig::default();
        let vars = vec![(
            "SENTIO__DATABASE__MAX_CONNECTIONS".to_string(),
            "200".to_string(),
        )];
        apply_env_overrides_from(&mut config, vars.into_iter()).unwrap();
        assert_eq!(config.database.max_connections, 200);
    }

    #[test]
    fn env_override_bool() {
        let mut config = SentioConfig::default();
        let vars = vec![(
            "SENTIO__SERVER__PROXY_PROTOCOL".to_string(),
            "true".to_string(),
        )];
        apply_env_overrides_from(&mut config, vars.into_iter()).unwrap();
        assert!(config.server.proxy_protocol);
    }

    #[test]
    fn env_override_vec_csv() {
        let mut config = SentioConfig::default();
        let vars = vec![(
            "SENTIO__SERVER__LISTEN_SMTP".to_string(),
            "0.0.0.0:25, [::]:25, 0.0.0.0:2525".to_string(),
        )];
        apply_env_overrides_from(&mut config, vars.into_iter()).unwrap();
        assert_eq!(config.server.listen_smtp.len(), 3);
        assert_eq!(config.server.listen_smtp[2], "0.0.0.0:2525");
    }

    #[test]
    fn env_override_option_set() {
        let mut config = SentioConfig::default();
        let vars = vec![(
            "SENTIO__DELIVERY__RELAY__HOST".to_string(),
            "relay.example.com".to_string(),
        )];
        apply_env_overrides_from(&mut config, vars.into_iter()).unwrap();
        assert_eq!(
            config.delivery.relay.host,
            Some("relay.example.com".to_string())
        );
    }

    #[test]
    fn env_override_option_empty_clears() {
        let mut config = SentioConfig::default();
        config.delivery.relay.host = Some("old.host.com".to_string());
        let vars = vec![("SENTIO__DELIVERY__RELAY__HOST".to_string(), String::new())];
        apply_env_overrides_from(&mut config, vars.into_iter()).unwrap();
        assert_eq!(config.delivery.relay.host, None);
    }

    #[test]
    fn env_override_nested() {
        let mut config = SentioConfig::default();
        let vars = vec![(
            "SENTIO__SERVER__INBOUND_TIMEOUTS__GREETING_SECS".to_string(),
            "60".to_string(),
        )];
        apply_env_overrides_from(&mut config, vars.into_iter()).unwrap();
        assert_eq!(config.server.inbound_timeouts.greeting_secs, 60);
    }

    #[test]
    fn env_override_bad_parse_returns_error() {
        let mut config = SentioConfig::default();
        let vars = vec![(
            "SENTIO__DATABASE__MAX_CONNECTIONS".to_string(),
            "not_a_number".to_string(),
        )];
        let err = apply_env_overrides_from(&mut config, vars.into_iter()).unwrap_err();
        assert!(matches!(err, ConfigError::EnvOverride { .. }));
    }

    #[test]
    fn validation_catches_empty_hostname() {
        let mut config = SentioConfig::default();
        config.server.hostname = String::new();
        let err = config.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("hostname must not be empty"), "{msg}");
    }

    #[test]
    fn validation_catches_no_listeners() {
        let mut config = SentioConfig::default();
        config.server.listen_smtp.clear();
        config.server.listen_smtps.clear();
        config.server.listen_submission.clear();
        let err = config.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("at least one SMTP listener"), "{msg}");
    }

    #[test]
    fn validation_catches_bad_socket_address() {
        let mut config = SentioConfig::default();
        config.server.listen_smtp = vec!["not_an_address".into()];
        let err = config.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not a valid socket address"), "{msg}");
    }

    #[test]
    fn validation_catches_bad_tls_version() {
        let mut config = SentioConfig::default();
        config.tls.min_version = "1.1".to_string();
        let err = config.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("tls.min_version"), "{msg}");
    }

    #[test]
    fn validation_catches_spam_score_ordering() {
        let mut config = SentioConfig::default();
        config.spam.score_greylist = 10.0;
        config.spam.score_add_header = 5.0;
        let err = config.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("score_greylist"), "{msg}");
    }

    #[test]
    fn validation_catches_db_connections_mismatch() {
        let mut config = SentioConfig::default();
        config.database.min_connections = 100;
        config.database.max_connections = 10;
        let err = config.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("min_connections"), "{msg}");
    }

    #[test]
    fn validation_catches_retry_base_zero() {
        let mut config = SentioConfig::default();
        config.delivery.retry_base_secs = 0;
        let err = config.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("retry_base_secs must be > 0"), "{msg}");
    }

    #[test]
    fn validation_catches_relay_missing_host() {
        let mut config = SentioConfig::default();
        config.delivery.relay.enabled = true;
        let err = config.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("relay.host is required"), "{msg}");
    }

    #[test]
    fn validation_catches_bad_sample_rate() {
        let mut config = SentioConfig::default();
        config.observability.tracing_sample_rate = 1.5;
        let err = config.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("tracing_sample_rate"), "{msg}");
    }

    #[test]
    fn validation_catches_bad_log_level() {
        let mut config = SentioConfig::default();
        config.observability.log_level = "verbose".to_string();
        let err = config.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("log_level"), "{msg}");
    }

    #[test]
    fn validation_batch_collects_multiple_errors() {
        let mut config = SentioConfig::default();
        config.server.hostname = String::new();
        config.database.url = String::new();
        config.tls.min_version = "1.0".to_string();
        let err = config.validate().unwrap_err();
        match err {
            ConfigError::ValidationBatch { ref errors } => {
                assert!(
                    errors.len() >= 3,
                    "expected at least 3 errors, got {errors:?}"
                );
            }
            _ => panic!("expected ValidationBatch"),
        }
    }

    #[test]
    fn validation_catches_llm_review_band() {
        let mut config = SentioConfig::default();
        config.spam.score_llm_review_min = 6.0;
        config.spam.score_llm_review_max = 4.0;
        let err = config.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("score_llm_review_min"), "{msg}");
    }

    #[test]
    fn validation_catches_acme_missing_email() {
        let mut config = SentioConfig::default();
        config.tls.acme.enabled = true;
        config.tls.acme.email = String::new();
        let err = config.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("acme.email"), "{msg}");
    }
}
