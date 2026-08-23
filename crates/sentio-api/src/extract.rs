use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;

use sentio_core::message::{MessageDirection, MessageStatus};

// ──────────────────────────────────────────────────────────────────────────────
// Pagination
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct PaginationParams {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

impl PaginationParams {
    pub fn validated(self) -> Self {
        Self {
            limit: self.limit.clamp(1, 1000),
            offset: self.offset.max(0),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Date range (required for partition-aware queries)
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct DateRangeParams {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}

impl DateRangeParams {
    /// Returns (from, to) with defaults: last 24 hours if not specified.
    pub fn validated(self) -> (DateTime<Utc>, DateTime<Utc>) {
        let to = self.to.unwrap_or_else(Utc::now);
        let from = self.from.unwrap_or_else(|| to - Duration::hours(24));
        (from, to)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Combined message list query params
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListMessagesParams {
    pub status: Option<MessageStatus>,
    pub direction: Option<MessageDirection>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}
