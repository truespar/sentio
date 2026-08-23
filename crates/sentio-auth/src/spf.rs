use std::net::IpAddr;

use mail_auth::spf::verify::SpfParameters;
use mail_auth::{SpfOutput, SpfResult};
use serde::{Deserialize, Serialize};

use sentio_core::error::SentioError;

use crate::dns::Authenticator;

// ──────────────────────────────────────────────────────────────────────────────
// Sentio-owned SPF result types
// ──────────────────────────────────────────────────────────────────────────────

/// Outcome of an SPF check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpfVerifyResult {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    TempError,
    PermError,
    None,
}

impl SpfVerifyResult {
    fn from_mail_auth(r: &SpfResult) -> Self {
        match r {
            SpfResult::Pass => Self::Pass,
            SpfResult::Fail => Self::Fail,
            SpfResult::SoftFail => Self::SoftFail,
            SpfResult::Neutral => Self::Neutral,
            SpfResult::TempError => Self::TempError,
            SpfResult::PermError => Self::PermError,
            SpfResult::None => Self::None,
        }
    }
}

/// Full SPF verification output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpfVerifyOutput {
    pub result: SpfVerifyResult,
    pub domain: String,
    pub explanation: Option<String>,
}

fn map_spf_output(output: SpfOutput) -> SpfVerifyOutput {
    SpfVerifyOutput {
        result: SpfVerifyResult::from_mail_auth(&output.result()),
        domain: output.domain().to_string(),
        explanation: output.explanation().map(|s| s.to_string()),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Verification
// ──────────────────────────────────────────────────────────────────────────────

impl Authenticator {
    /// Full SPF check using the MAIL FROM identity.
    ///
    /// * `sender_ip`   - IP address of the sending MTA
    /// * `helo_domain` - domain from the EHLO/HELO command
    /// * `mail_from`   - envelope sender (e.g. `user@example.com`)
    /// * `host_domain` - our receiving host domain
    pub async fn verify_spf(
        &self,
        sender_ip: IpAddr,
        helo_domain: &str,
        mail_from: &str,
        host_domain: &str,
    ) -> Result<SpfVerifyOutput, SentioError> {
        let params =
            SpfParameters::verify_mail_from(sender_ip, helo_domain, host_domain, mail_from);

        let output: SpfOutput = self.inner.verify_spf(params).await;
        Ok(map_spf_output(output))
    }

    /// HELO-only SPF check (no MAIL FROM identity).
    ///
    /// * `sender_ip`   - IP address of the sending MTA
    /// * `helo_domain` - domain from the EHLO/HELO command
    /// * `host_domain` - our receiving host domain
    pub async fn verify_spf_helo(
        &self,
        sender_ip: IpAddr,
        helo_domain: &str,
        host_domain: &str,
    ) -> Result<SpfVerifyOutput, SentioError> {
        let params = SpfParameters::verify_ehlo(sender_ip, helo_domain, host_domain);

        let output: SpfOutput = self.inner.verify_spf(params).await;
        Ok(map_spf_output(output))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spf_result_maps_all_variants() {
        assert_eq!(
            SpfVerifyResult::from_mail_auth(&SpfResult::Pass),
            SpfVerifyResult::Pass
        );
        assert_eq!(
            SpfVerifyResult::from_mail_auth(&SpfResult::Fail),
            SpfVerifyResult::Fail
        );
        assert_eq!(
            SpfVerifyResult::from_mail_auth(&SpfResult::SoftFail),
            SpfVerifyResult::SoftFail
        );
        assert_eq!(
            SpfVerifyResult::from_mail_auth(&SpfResult::Neutral),
            SpfVerifyResult::Neutral
        );
        assert_eq!(
            SpfVerifyResult::from_mail_auth(&SpfResult::TempError),
            SpfVerifyResult::TempError
        );
        assert_eq!(
            SpfVerifyResult::from_mail_auth(&SpfResult::PermError),
            SpfVerifyResult::PermError
        );
        assert_eq!(
            SpfVerifyResult::from_mail_auth(&SpfResult::None),
            SpfVerifyResult::None
        );
    }

    #[test]
    fn spf_verify_result_serde_roundtrip() {
        let result = SpfVerifyResult::SoftFail;
        let json = serde_json::to_string(&result).unwrap();
        assert_eq!(json, "\"soft_fail\"");
        let parsed: SpfVerifyResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, result);
    }

    #[test]
    fn spf_verify_output_construction() {
        let output = SpfVerifyOutput {
            result: SpfVerifyResult::Pass,
            domain: "example.com".to_string(),
            explanation: None,
        };
        assert_eq!(output.result, SpfVerifyResult::Pass);
        assert_eq!(output.domain, "example.com");
        assert!(output.explanation.is_none());
    }
}
