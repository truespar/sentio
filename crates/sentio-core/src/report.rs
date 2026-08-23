use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────────────────────────────────────
// ComplaintType  (CHECK: abuse, fraud, virus, other, not-spam)
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
pub enum ComplaintType {
    #[strum(serialize = "abuse")]
    #[serde(rename = "abuse")]
    Abuse,
    #[strum(serialize = "fraud")]
    #[serde(rename = "fraud")]
    Fraud,
    #[strum(serialize = "virus")]
    #[serde(rename = "virus")]
    Virus,
    #[strum(serialize = "other")]
    #[serde(rename = "other")]
    Other,
    #[strum(serialize = "not-spam")]
    #[serde(rename = "not-spam")]
    NotSpam,
}

// ──────────────────────────────────────────────────────────────────────────────
// TlsrptPolicyType  (CHECK: tlsa, sts, no-policy-found)
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
pub enum TlsrptPolicyType {
    #[strum(serialize = "tlsa")]
    #[serde(rename = "tlsa")]
    Tlsa,
    #[strum(serialize = "sts")]
    #[serde(rename = "sts")]
    Sts,
    #[strum(serialize = "no-policy-found")]
    #[serde(rename = "no-policy-found")]
    NoPolicyFound,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complaint_type_display() {
        assert_eq!(ComplaintType::Abuse.to_string(), "abuse");
        assert_eq!(ComplaintType::Fraud.to_string(), "fraud");
        assert_eq!(ComplaintType::Virus.to_string(), "virus");
        assert_eq!(ComplaintType::Other.to_string(), "other");
        assert_eq!(ComplaintType::NotSpam.to_string(), "not-spam");
    }

    #[test]
    fn complaint_type_from_str() {
        assert_eq!(
            "not-spam".parse::<ComplaintType>().unwrap(),
            ComplaintType::NotSpam
        );
        assert_eq!(
            "abuse".parse::<ComplaintType>().unwrap(),
            ComplaintType::Abuse
        );
        assert!("notspam".parse::<ComplaintType>().is_err());
    }

    #[test]
    fn tlsrpt_policy_type_display() {
        assert_eq!(TlsrptPolicyType::Tlsa.to_string(), "tlsa");
        assert_eq!(TlsrptPolicyType::Sts.to_string(), "sts");
        assert_eq!(
            TlsrptPolicyType::NoPolicyFound.to_string(),
            "no-policy-found"
        );
    }

    #[test]
    fn tlsrpt_policy_type_from_str() {
        assert_eq!(
            "no-policy-found".parse::<TlsrptPolicyType>().unwrap(),
            TlsrptPolicyType::NoPolicyFound
        );
        assert_eq!(
            "tlsa".parse::<TlsrptPolicyType>().unwrap(),
            TlsrptPolicyType::Tlsa
        );
        assert!("nopolicyfound".parse::<TlsrptPolicyType>().is_err());
    }
}
