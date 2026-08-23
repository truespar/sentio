use hickory_resolver::proto::rr::RData;
use sentio_core::error::SentioError;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::dns::Authenticator;

// ──────────────────────────────────────────────────────────────────────────────
// MTA-STS types
// ──────────────────────────────────────────────────────────────────────────────

/// MTA-STS enforcement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MtaStsMode {
    /// Senders MUST use TLS and validate the certificate.
    Enforce,
    /// Senders SHOULD report failures but not reject mail.
    Testing,
    /// No MTA-STS policy is in effect.
    None,
}

/// A parsed MTA-STS policy (from `/.well-known/mta-sts.txt`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtaStsPolicy {
    pub version: String,
    pub mode: MtaStsMode,
    /// MX host patterns, e.g. `["mail.example.com", "*.example.com"]`.
    pub mx: Vec<String>,
    /// Maximum age in seconds the policy may be cached.
    pub max_age: u64,
}

/// Result of looking up and fetching the MTA-STS policy for a domain.
#[derive(Debug, Clone)]
pub struct MtaStsLookupOutput {
    /// The TXT record id (from `_mta-sts.{domain}`).
    pub policy_id: Option<String>,
    /// The fetched and parsed policy, if available.
    pub policy: Option<MtaStsPolicy>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Policy parsing
// ──────────────────────────────────────────────────────────────────────────────

/// Parse the MTA-STS policy text (RFC 8461 §3.2).
///
/// Example input:
/// ```text
/// version: STSv1
/// mode: enforce
/// mx: mail.example.com
/// mx: *.example.com
/// max_age: 604800
/// ```
pub fn parse_mta_sts_policy(text: &str) -> Result<MtaStsPolicy, SentioError> {
    let mut version = None;
    let mut mode = None;
    let mut mx = Vec::new();
    let mut max_age = None;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| SentioError::Auth(format!("invalid MTA-STS policy line: {line}")))?;
        let key = key.trim().to_lowercase();
        let value = value.trim();

        match key.as_str() {
            "version" => {
                if value != "STSv1" {
                    return Err(SentioError::Auth(format!(
                        "unsupported MTA-STS version: {value}"
                    )));
                }
                version = Some(value.to_string());
            }
            "mode" => {
                mode = Some(match value.to_lowercase().as_str() {
                    "enforce" => MtaStsMode::Enforce,
                    "testing" => MtaStsMode::Testing,
                    "none" => MtaStsMode::None,
                    _ => {
                        return Err(SentioError::Auth(format!("invalid MTA-STS mode: {value}")));
                    }
                });
            }
            "mx" => {
                mx.push(value.to_string());
            }
            "max_age" => {
                max_age =
                    Some(value.parse::<u64>().map_err(|_| {
                        SentioError::Auth(format!("invalid MTA-STS max_age: {value}"))
                    })?);
            }
            _ => { /* ignore unknown keys per RFC 8461 §3.2 */ }
        }
    }

    let version =
        version.ok_or_else(|| SentioError::Auth("MTA-STS policy missing version".into()))?;
    let mode = mode.ok_or_else(|| SentioError::Auth("MTA-STS policy missing mode".into()))?;
    let max_age =
        max_age.ok_or_else(|| SentioError::Auth("MTA-STS policy missing max_age".into()))?;

    Ok(MtaStsPolicy {
        version,
        mode,
        mx,
        max_age,
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// MX matching
// ──────────────────────────────────────────────────────────────────────────────

impl MtaStsPolicy {
    /// Check whether the given MX hostname matches any of the policy's MX
    /// patterns.  Supports wildcard matching (`*.example.com`).
    pub fn matches_mx(&self, mx_host: &str) -> bool {
        let mx_lower = mx_host.to_lowercase();
        self.mx.iter().any(|pattern| {
            let pat = pattern.to_lowercase();
            if let Some(suffix) = pat.strip_prefix("*.") {
                // Wildcard: host must end with `.{suffix}` (at least one label before it).
                mx_lower.ends_with(&format!(".{suffix}")) || mx_lower == suffix
            } else {
                mx_lower == pat
            }
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// DNS + HTTP fetch
// ──────────────────────────────────────────────────────────────────────────────

/// Parse the `_mta-sts.{domain}` TXT record to extract the policy ID.
///
/// Expected format: `v=STSv1; id=20190429T010101;`
fn parse_mta_sts_txt(txt: &str) -> Option<String> {
    let txt = txt.trim();
    if !txt.contains("v=STSv1") {
        return None;
    }
    for part in txt.split(';') {
        let part = part.trim();
        if let Some(id) = part.strip_prefix("id=") {
            return Some(id.trim().to_string());
        }
    }
    None
}

impl Authenticator {
    /// Fetch the MTA-STS policy for a domain.
    ///
    /// 1. Look up `_mta-sts.{domain}` TXT record for the policy ID.
    /// 2. Fetch `https://mta-sts.{domain}/.well-known/mta-sts.txt`.
    /// 3. Parse and return the policy.
    pub async fn fetch_mta_sts(&self, domain: &str) -> Result<MtaStsLookupOutput, SentioError> {
        // 1. DNS TXT lookup for the policy ID.
        let query = format!("_mta-sts.{domain}");
        let policy_id = match self.resolver.txt_lookup(&query).await {
            Ok(lookup) => {
                let mut id = None;
                for record in lookup.answers() {
                    let RData::TXT(txt) = &record.data else {
                        continue;
                    };
                    if let Some(parsed_id) = parse_mta_sts_txt(&txt.to_string()) {
                        id = Some(parsed_id);
                        break;
                    }
                }
                id
            }
            Err(e) => {
                debug!(domain, error = %e, "MTA-STS TXT lookup failed");
                return Ok(MtaStsLookupOutput {
                    policy_id: None,
                    policy: None,
                });
            }
        };

        let Some(policy_id) = policy_id else {
            return Ok(MtaStsLookupOutput {
                policy_id: None,
                policy: None,
            });
        };

        // 2. HTTPS fetch of the policy file.
        let url = format!("https://mta-sts.{domain}/.well-known/mta-sts.txt");
        let response = reqwest::get(&url).await.map_err(|e| {
            SentioError::Auth(format!("MTA-STS policy fetch failed for {domain}: {e}"))
        })?;

        if !response.status().is_success() {
            debug!(domain, status = %response.status(), "MTA-STS policy fetch returned non-200");
            return Ok(MtaStsLookupOutput {
                policy_id: Some(policy_id),
                policy: None,
            });
        }

        let body = response
            .text()
            .await
            .map_err(|e| SentioError::Auth(format!("failed to read MTA-STS policy body: {e}")))?;

        match parse_mta_sts_policy(&body) {
            Ok(policy) => Ok(MtaStsLookupOutput {
                policy_id: Some(policy_id),
                policy: Some(policy),
            }),
            Err(e) => {
                debug!(domain, error = %e, "failed to parse MTA-STS policy");
                Ok(MtaStsLookupOutput {
                    policy_id: Some(policy_id),
                    policy: None,
                })
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Policy parsing ──────────────────────────────────────────────────────

    #[test]
    fn parse_valid_policy() {
        let text = "\
version: STSv1
mode: enforce
mx: mail.example.com
mx: *.example.com
max_age: 604800
";
        let policy = parse_mta_sts_policy(text).unwrap();
        assert_eq!(policy.version, "STSv1");
        assert_eq!(policy.mode, MtaStsMode::Enforce);
        assert_eq!(policy.mx, vec!["mail.example.com", "*.example.com"]);
        assert_eq!(policy.max_age, 604800);
    }

    #[test]
    fn parse_testing_mode() {
        let text = "version: STSv1\nmode: testing\nmax_age: 86400\n";
        let policy = parse_mta_sts_policy(text).unwrap();
        assert_eq!(policy.mode, MtaStsMode::Testing);
        assert!(policy.mx.is_empty());
    }

    #[test]
    fn parse_none_mode() {
        let text = "version: STSv1\nmode: none\nmax_age: 0\n";
        let policy = parse_mta_sts_policy(text).unwrap();
        assert_eq!(policy.mode, MtaStsMode::None);
    }

    #[test]
    fn parse_missing_version_errors() {
        assert!(parse_mta_sts_policy("mode: enforce\nmax_age: 100\n").is_err());
    }

    #[test]
    fn parse_missing_mode_errors() {
        assert!(parse_mta_sts_policy("version: STSv1\nmax_age: 100\n").is_err());
    }

    #[test]
    fn parse_invalid_max_age_errors() {
        let text = "version: STSv1\nmode: enforce\nmax_age: notanumber\n";
        assert!(parse_mta_sts_policy(text).is_err());
    }

    // ── MX matching ─────────────────────────────────────────────────────────

    #[test]
    fn matches_exact_mx() {
        let policy = MtaStsPolicy {
            version: "STSv1".into(),
            mode: MtaStsMode::Enforce,
            mx: vec!["mail.example.com".into()],
            max_age: 86400,
        };
        assert!(policy.matches_mx("mail.example.com"));
        assert!(!policy.matches_mx("other.example.com"));
    }

    #[test]
    fn matches_wildcard_mx() {
        let policy = MtaStsPolicy {
            version: "STSv1".into(),
            mode: MtaStsMode::Enforce,
            mx: vec!["*.example.com".into()],
            max_age: 86400,
        };
        assert!(policy.matches_mx("mail.example.com"));
        assert!(policy.matches_mx("mx1.example.com"));
        assert!(!policy.matches_mx("mail.other.com"));
    }

    #[test]
    fn matches_mx_case_insensitive() {
        let policy = MtaStsPolicy {
            version: "STSv1".into(),
            mode: MtaStsMode::Enforce,
            mx: vec!["MAIL.EXAMPLE.COM".into()],
            max_age: 86400,
        };
        assert!(policy.matches_mx("mail.example.com"));
    }

    // ── TXT record parsing ──────────────────────────────────────────────────

    #[test]
    fn parse_txt_record_valid() {
        let id = parse_mta_sts_txt("v=STSv1; id=20190429T010101;");
        assert_eq!(id, Some("20190429T010101".into()));
    }

    #[test]
    fn parse_txt_record_no_sts() {
        assert!(parse_mta_sts_txt("v=spf1 include:example.com ~all").is_none());
    }

    #[test]
    fn parse_txt_record_missing_id() {
        assert!(parse_mta_sts_txt("v=STSv1;").is_none());
    }

    // ── Serde ───────────────────────────────────────────────────────────────

    #[test]
    fn mta_sts_mode_serde_roundtrip() {
        let mode = MtaStsMode::Enforce;
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(json, "\"enforce\"");
        let parsed: MtaStsMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, mode);
    }
}
