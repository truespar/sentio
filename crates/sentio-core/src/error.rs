use std::fmt;
use std::path::PathBuf;

// ──────────────────────────────────────────────────────────────────────────────
// ConfigError
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read configuration file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to parse TOML configuration: {0}")]
    ParseToml(#[from] toml::de::Error),

    #[error("invalid environment variable override SENTIO__{key}: {message}")]
    EnvOverride { key: String, message: String },

    #[error("configuration validation failed:\n{}", format_validation_errors(.errors))]
    ValidationBatch { errors: Vec<String> },
}

fn format_validation_errors(errors: &[String]) -> String {
    errors
        .iter()
        .enumerate()
        .map(|(i, e)| format!("  {}. {}", i + 1, e))
        .collect::<Vec<_>>()
        .join("\n")
}

// ──────────────────────────────────────────────────────────────────────────────
// SmtpError
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SmtpError {
    pub code: u16,
    pub enhanced: Option<String>,
    pub message: String,
}

impl fmt::Display for SmtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref enh) = self.enhanced {
            write!(f, "{} {} {}", self.code, enh, self.message)
        } else {
            write!(f, "{} {}", self.code, self.message)
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// SentioError - shared error type used by all crates
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum SentioError {
    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error("database error: {0}")]
    Database(String),

    #[error("redis error: {0}")]
    Redis(String),

    #[error("KV error: {0}")]
    Kv(String),

    #[error("queue error: {0}")]
    Queue(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("SMTP error: {0}")]
    Smtp(SmtpError),

    #[error("auth error: {0}")]
    Auth(String),

    #[error("rate limit exceeded for key: {key}")]
    RateLimit { key: String },

    #[error("{entity} not found: {id}")]
    NotFound { entity: &'static str, id: String },

    #[error("validation error: {0}")]
    Validation(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl SentioError {
    /// Returns the error category string matching the DB CHECK constraint.
    pub fn error_category(&self) -> &'static str {
        match self {
            SentioError::Config(_) => "config",
            SentioError::Database(_) => "database",
            SentioError::Redis(_) => "redis",
            SentioError::Kv(_) => "kv",
            SentioError::Queue(_) => "queue",
            SentioError::Storage(_) => "storage",
            SentioError::Smtp(_) => "smtp",
            SentioError::Auth(_) => "auth",
            SentioError::RateLimit { .. } => "rate_limit",
            SentioError::NotFound { .. } => "not_found",
            SentioError::Validation(_) => "validation",
            SentioError::Internal(_) => "internal",
        }
    }
}
