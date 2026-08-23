use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ──────────────────────────────────────────────────────────────────────────────
// TenantId
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(transparent)]
pub struct TenantId(pub Uuid);

impl TenantId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for TenantId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for TenantId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// TenantTier  (CHECK: dedicated, shared_premium, shared_standard)
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
pub enum TenantTier {
    Dedicated,
    SharedPremium,
    SharedStandard,
}

// ──────────────────────────────────────────────────────────────────────────────
// TenantStatus  (CHECK: active, suspended, deleted)
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
pub enum TenantStatus {
    Active,
    Suspended,
    Deleted,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_id_roundtrip() {
        let id = TenantId::new();
        let s = id.to_string();
        let parsed: TenantId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn tenant_id_serde_roundtrip() {
        let id = TenantId::new();
        let json = serde_json::to_string(&id).unwrap();
        let parsed: TenantId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn tenant_tier_display() {
        assert_eq!(TenantTier::Dedicated.to_string(), "dedicated");
        assert_eq!(TenantTier::SharedPremium.to_string(), "shared_premium");
        assert_eq!(TenantTier::SharedStandard.to_string(), "shared_standard");
    }

    #[test]
    fn tenant_tier_from_str() {
        assert_eq!(
            "dedicated".parse::<TenantTier>().unwrap(),
            TenantTier::Dedicated
        );
        assert_eq!(
            "shared_premium".parse::<TenantTier>().unwrap(),
            TenantTier::SharedPremium
        );
        assert_eq!(
            "shared_standard".parse::<TenantTier>().unwrap(),
            TenantTier::SharedStandard
        );
        assert!("invalid".parse::<TenantTier>().is_err());
    }

    #[test]
    fn tenant_tier_serde_roundtrip() {
        let tier = TenantTier::SharedPremium;
        let json = serde_json::to_string(&tier).unwrap();
        assert_eq!(json, "\"shared_premium\"");
        let parsed: TenantTier = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, tier);
    }

    #[test]
    fn tenant_status_display() {
        assert_eq!(TenantStatus::Active.to_string(), "active");
        assert_eq!(TenantStatus::Suspended.to_string(), "suspended");
        assert_eq!(TenantStatus::Deleted.to_string(), "deleted");
    }

    #[test]
    fn tenant_status_serde_roundtrip() {
        let status = TenantStatus::Suspended;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"suspended\"");
        let parsed: TenantStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, status);
    }
}
