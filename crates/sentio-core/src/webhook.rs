use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ──────────────────────────────────────────────────────────────────────────────
// WebhookId
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(transparent)]
pub struct WebhookId(pub Uuid);

impl WebhookId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for WebhookId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for WebhookId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for WebhookId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// WebhookStatus  (CHECK: active, paused, disabled)
// ──────────────────────────────────────────────────────────────────────────────

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    strum::Display,
    strum::EnumString,
    utoipa::ToSchema,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum WebhookStatus {
    Active,
    Paused,
    Disabled,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_id_roundtrip() {
        let id = WebhookId::new();
        let s = id.to_string();
        let parsed: WebhookId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn webhook_status_display() {
        assert_eq!(WebhookStatus::Active.to_string(), "active");
        assert_eq!(WebhookStatus::Paused.to_string(), "paused");
        assert_eq!(WebhookStatus::Disabled.to_string(), "disabled");
    }

    #[test]
    fn webhook_status_serde_roundtrip() {
        let status = WebhookStatus::Paused;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"paused\"");
        let parsed: WebhookStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, status);
    }
}
