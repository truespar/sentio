use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────────────────────────────────────
// DkimAlgorithm  (CHECK: ed25519, rsa)
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
pub enum DkimAlgorithm {
    #[strum(serialize = "ed25519")]
    #[serde(rename = "ed25519")]
    Ed25519,
    #[strum(serialize = "rsa")]
    #[serde(rename = "rsa")]
    Rsa,
}

// ──────────────────────────────────────────────────────────────────────────────
// DkimKeyStatus  (CHECK: active, rotating, retired)
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
pub enum DkimKeyStatus {
    Active,
    Rotating,
    Retired,
}

// ──────────────────────────────────────────────────────────────────────────────
// DomainStatus  (CHECK: pending, verified, failed)
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
pub enum DomainStatus {
    Pending,
    Verified,
    Failed,
}

// ──────────────────────────────────────────────────────────────────────────────
// DnsCheckStatus  (CHECK: pending, verified, failed, not_applicable)
// Used for mx_status, return_path_status, spf_status, dkim_status, dmarc_status
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
pub enum DnsCheckStatus {
    Pending,
    Verified,
    Failed,
    NotApplicable,
}

// ──────────────────────────────────────────────────────────────────────────────
// IpPoolType  (CHECK: shared, dedicated)
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
pub enum IpPoolType {
    Shared,
    Dedicated,
}

// ──────────────────────────────────────────────────────────────────────────────
// IpPoolStatus  (CHECK: active, draining, inactive)
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
pub enum IpPoolStatus {
    Active,
    Draining,
    Inactive,
}

// ──────────────────────────────────────────────────────────────────────────────
// WarmupStatus  (CHECK: scheduled, in_progress, paused, completed)
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
pub enum WarmupStatus {
    Scheduled,
    InProgress,
    Paused,
    Completed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dkim_algorithm_display() {
        assert_eq!(DkimAlgorithm::Ed25519.to_string(), "ed25519");
        assert_eq!(DkimAlgorithm::Rsa.to_string(), "rsa");
    }

    #[test]
    fn dkim_algorithm_from_str() {
        assert_eq!(
            "ed25519".parse::<DkimAlgorithm>().unwrap(),
            DkimAlgorithm::Ed25519
        );
        assert_eq!("rsa".parse::<DkimAlgorithm>().unwrap(), DkimAlgorithm::Rsa);
        assert!("invalid".parse::<DkimAlgorithm>().is_err());
    }

    #[test]
    fn dkim_algorithm_serde_roundtrip() {
        let alg = DkimAlgorithm::Ed25519;
        let json = serde_json::to_string(&alg).unwrap();
        assert_eq!(json, "\"ed25519\"");
        let parsed: DkimAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, alg);
    }

    #[test]
    fn dkim_key_status_display() {
        assert_eq!(DkimKeyStatus::Active.to_string(), "active");
        assert_eq!(DkimKeyStatus::Rotating.to_string(), "rotating");
        assert_eq!(DkimKeyStatus::Retired.to_string(), "retired");
    }

    #[test]
    fn domain_status_display() {
        assert_eq!(DomainStatus::Pending.to_string(), "pending");
        assert_eq!(DomainStatus::Verified.to_string(), "verified");
        assert_eq!(DomainStatus::Failed.to_string(), "failed");
    }

    #[test]
    fn dns_check_status_display() {
        assert_eq!(DnsCheckStatus::Pending.to_string(), "pending");
        assert_eq!(DnsCheckStatus::Verified.to_string(), "verified");
        assert_eq!(DnsCheckStatus::Failed.to_string(), "failed");
        assert_eq!(DnsCheckStatus::NotApplicable.to_string(), "not_applicable");
    }

    #[test]
    fn dns_check_status_from_str() {
        assert_eq!(
            "not_applicable".parse::<DnsCheckStatus>().unwrap(),
            DnsCheckStatus::NotApplicable,
        );
    }

    #[test]
    fn dns_check_status_serde_roundtrip() {
        let status = DnsCheckStatus::NotApplicable;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"not_applicable\"");
        let parsed: DnsCheckStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, status);
    }

    #[test]
    fn ip_pool_type_display() {
        assert_eq!(IpPoolType::Shared.to_string(), "shared");
        assert_eq!(IpPoolType::Dedicated.to_string(), "dedicated");
    }

    #[test]
    fn ip_pool_type_from_str() {
        assert_eq!("shared".parse::<IpPoolType>().unwrap(), IpPoolType::Shared);
        assert_eq!(
            "dedicated".parse::<IpPoolType>().unwrap(),
            IpPoolType::Dedicated
        );
        assert!("invalid".parse::<IpPoolType>().is_err());
    }

    #[test]
    fn ip_pool_type_serde_roundtrip() {
        let pt = IpPoolType::Dedicated;
        let json = serde_json::to_string(&pt).unwrap();
        assert_eq!(json, "\"dedicated\"");
        let parsed: IpPoolType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, pt);
    }

    #[test]
    fn ip_pool_status_display() {
        assert_eq!(IpPoolStatus::Active.to_string(), "active");
        assert_eq!(IpPoolStatus::Draining.to_string(), "draining");
        assert_eq!(IpPoolStatus::Inactive.to_string(), "inactive");
    }

    #[test]
    fn ip_pool_status_from_str() {
        assert_eq!(
            "draining".parse::<IpPoolStatus>().unwrap(),
            IpPoolStatus::Draining
        );
        assert!("invalid".parse::<IpPoolStatus>().is_err());
    }

    #[test]
    fn ip_pool_status_serde_roundtrip() {
        let s = IpPoolStatus::Draining;
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"draining\"");
        let parsed: IpPoolStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, s);
    }

    #[test]
    fn warmup_status_display() {
        assert_eq!(WarmupStatus::Scheduled.to_string(), "scheduled");
        assert_eq!(WarmupStatus::InProgress.to_string(), "in_progress");
        assert_eq!(WarmupStatus::Paused.to_string(), "paused");
        assert_eq!(WarmupStatus::Completed.to_string(), "completed");
    }

    #[test]
    fn warmup_status_from_str() {
        assert_eq!(
            "in_progress".parse::<WarmupStatus>().unwrap(),
            WarmupStatus::InProgress
        );
        assert_eq!(
            "completed".parse::<WarmupStatus>().unwrap(),
            WarmupStatus::Completed
        );
        assert!("invalid".parse::<WarmupStatus>().is_err());
    }

    #[test]
    fn warmup_status_serde_roundtrip() {
        let s = WarmupStatus::InProgress;
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"in_progress\"");
        let parsed: WarmupStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, s);
    }
}
