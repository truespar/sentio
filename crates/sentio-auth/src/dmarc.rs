use hickory_resolver::proto::rr::RData;
use sentio_core::error::SentioError;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::dkim::DkimVerifyOutput;
use crate::dns::Authenticator;
use crate::spf::SpfVerifyOutput;

// ──────────────────────────────────────────────────────────────────────────────
// Sentio-owned DMARC result types
// ──────────────────────────────────────────────────────────────────────────────

/// Outcome of a DMARC alignment check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DmarcVerifyResult {
    Pass,
    Fail,
    TempError,
    PermError,
    None,
}

/// DMARC policy declared by the domain owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DmarcPolicy {
    None,
    Quarantine,
    Reject,
}

/// DMARC alignment mode (applies to both DKIM and SPF).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DmarcAlignment {
    Relaxed,
    Strict,
}

/// A parsed DMARC DNS record.
#[derive(Debug, Clone)]
pub struct DmarcRecord {
    pub policy: DmarcPolicy,
    pub subdomain_policy: Option<DmarcPolicy>,
    pub dkim_alignment: DmarcAlignment,
    pub spf_alignment: DmarcAlignment,
    pub pct: u8,
    pub rua: Vec<String>,
    pub ruf: Vec<String>,
}

/// Full DMARC verification output.
#[derive(Debug, Clone)]
pub struct DmarcVerifyOutput {
    pub result: DmarcVerifyResult,
    pub domain: String,
    pub policy: DmarcPolicy,
    pub dkim_aligned: bool,
    pub spf_aligned: bool,
    pub record: Option<DmarcRecord>,
}

// ──────────────────────────────────────────────────────────────────────────────
// DMARC record parsing
// ──────────────────────────────────────────────────────────────────────────────

/// Parse a DMARC TXT record value into a [`DmarcRecord`].
///
/// Expected format: `v=DMARC1; p=reject; adkim=r; aspf=r; pct=100; ...`
pub fn parse_dmarc_record(txt: &str) -> Result<DmarcRecord, SentioError> {
    let txt = txt.trim();

    let mut policy = None;
    let mut subdomain_policy = None;
    let mut dkim_alignment = DmarcAlignment::Relaxed;
    let mut spf_alignment = DmarcAlignment::Relaxed;
    let mut pct = 100u8;
    let mut rua = Vec::new();
    let mut ruf = Vec::new();
    let mut has_version = false;

    for part in txt.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| SentioError::Auth(format!("invalid DMARC tag: {part}")))?;
        let key = key.trim().to_lowercase();
        let value = value.trim();

        match key.as_str() {
            "v" => {
                if value != "DMARC1" {
                    return Err(SentioError::Auth(format!(
                        "unsupported DMARC version: {value}"
                    )));
                }
                has_version = true;
            }
            "p" => {
                policy = Some(parse_policy(value)?);
            }
            "sp" => {
                subdomain_policy = Some(parse_policy(value)?);
            }
            "adkim" => {
                dkim_alignment = parse_alignment(value)?;
            }
            "aspf" => {
                spf_alignment = parse_alignment(value)?;
            }
            "pct" => {
                pct = value
                    .parse()
                    .map_err(|_| SentioError::Auth(format!("invalid DMARC pct: {value}")))?;
            }
            "rua" => {
                rua = value.split(',').map(|s| s.trim().to_string()).collect();
            }
            "ruf" => {
                ruf = value.split(',').map(|s| s.trim().to_string()).collect();
            }
            _ => { /* ignore unknown tags per RFC 7489 §6.3 */ }
        }
    }

    if !has_version {
        return Err(SentioError::Auth("DMARC record missing v=DMARC1".into()));
    }
    let policy =
        policy.ok_or_else(|| SentioError::Auth("DMARC record missing required p= tag".into()))?;

    Ok(DmarcRecord {
        policy,
        subdomain_policy,
        dkim_alignment,
        spf_alignment,
        pct,
        rua,
        ruf,
    })
}

fn parse_policy(value: &str) -> Result<DmarcPolicy, SentioError> {
    match value.to_lowercase().as_str() {
        "none" => Ok(DmarcPolicy::None),
        "quarantine" => Ok(DmarcPolicy::Quarantine),
        "reject" => Ok(DmarcPolicy::Reject),
        _ => Err(SentioError::Auth(format!("invalid DMARC policy: {value}"))),
    }
}

fn parse_alignment(value: &str) -> Result<DmarcAlignment, SentioError> {
    match value.to_lowercase().as_str() {
        "r" => Ok(DmarcAlignment::Relaxed),
        "s" => Ok(DmarcAlignment::Strict),
        _ => Err(SentioError::Auth(format!(
            "invalid DMARC alignment: {value}"
        ))),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Domain alignment helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Return the organizational domain (last two labels) as a simple heuristic.
///
/// For production, integrate a proper public suffix list (PSL) crate.
/// This handles common cases like `mail.example.com` → `example.com`
/// but does not handle multi-label TLDs (e.g. `.co.uk`).
fn org_domain(domain: &str) -> &str {
    // Find the second-to-last dot to get the last two labels.
    match domain.rmatch_indices('.').nth(1) {
        Some((pos, _)) => &domain[pos + 1..],
        None => domain, // already two labels or fewer
    }
}

fn domains_aligned(d1: &str, d2: &str, alignment: DmarcAlignment) -> bool {
    let d1 = d1.to_lowercase();
    let d2 = d2.to_lowercase();
    match alignment {
        DmarcAlignment::Strict => d1 == d2,
        DmarcAlignment::Relaxed => org_domain(&d1) == org_domain(&d2),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Pure alignment evaluation (testable without DNS)
// ──────────────────────────────────────────────────────────────────────────────

/// Evaluate DMARC alignment from pre-computed DKIM, SPF, and DMARC record data.
///
/// This is the pure logic extracted from `verify_dmarc()` - no DNS lookups.
/// Available in tests and with the `test-support` feature.
#[cfg(any(test, feature = "test-support"))]
pub fn evaluate_dmarc_alignment(
    from_domain: &str,
    spf_domain: &str,
    dkim_output: &DkimVerifyOutput,
    spf_output: &SpfVerifyOutput,
    record: Option<&DmarcRecord>,
) -> DmarcVerifyOutput {
    evaluate_alignment_inner(from_domain, spf_domain, dkim_output, spf_output, record)
}

/// Inner alignment logic shared by `verify_dmarc()` and `evaluate_dmarc_alignment()`.
fn evaluate_alignment_inner(
    from_domain: &str,
    spf_domain: &str,
    dkim_output: &DkimVerifyOutput,
    spf_output: &SpfVerifyOutput,
    record: Option<&DmarcRecord>,
) -> DmarcVerifyOutput {
    let Some(record) = record else {
        return DmarcVerifyOutput {
            result: DmarcVerifyResult::None,
            domain: from_domain.to_string(),
            policy: DmarcPolicy::None,
            dkim_aligned: false,
            spf_aligned: false,
            record: None,
        };
    };

    // Check DKIM alignment
    let dkim_aligned = dkim_output.signatures.iter().any(|sig| {
        sig.result == crate::dkim::DkimVerifyResult::Pass
            && domains_aligned(&sig.domain, from_domain, record.dkim_alignment)
    });

    // Check SPF alignment
    let spf_aligned = spf_output.result == crate::spf::SpfVerifyResult::Pass
        && domains_aligned(spf_domain, from_domain, record.spf_alignment);

    let result = if dkim_aligned || spf_aligned {
        DmarcVerifyResult::Pass
    } else {
        DmarcVerifyResult::Fail
    };

    let policy = record.policy;

    DmarcVerifyOutput {
        result,
        domain: from_domain.to_string(),
        policy,
        dkim_aligned,
        spf_aligned,
        record: Some(record.clone()),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Verification
// ──────────────────────────────────────────────────────────────────────────────

impl Authenticator {
    /// Perform a DMARC check using pre-computed DKIM and SPF results.
    ///
    /// * `from_domain` - the domain from the RFC 5322 From header
    /// * `spf_domain`  - the domain authenticated by SPF (MAIL FROM or HELO)
    /// * `dkim_output` - result of [`Authenticator::verify_dkim()`]
    /// * `spf_output`  - result of [`Authenticator::verify_spf()`]
    pub async fn verify_dmarc(
        &self,
        from_domain: &str,
        spf_domain: &str,
        dkim_output: &DkimVerifyOutput,
        spf_output: &SpfVerifyOutput,
    ) -> Result<DmarcVerifyOutput, SentioError> {
        // 1. Look up the DMARC record via DNS.
        let record = self.lookup_dmarc_record(from_domain).await?;

        if record.is_none() {
            debug!(domain = from_domain, "no DMARC record found");
        }

        // 2. Evaluate alignment using the shared pure function.
        Ok(evaluate_alignment_inner(
            from_domain,
            spf_domain,
            dkim_output,
            spf_output,
            record.as_ref(),
        ))
    }

    /// Look up the DMARC TXT record for a domain, walking up the domain tree
    /// per RFC 7489 §6.6.3 (organizational domain fallback).
    async fn lookup_dmarc_record(&self, domain: &str) -> Result<Option<DmarcRecord>, SentioError> {
        // Try exact domain first: _dmarc.{domain}
        let query = format!("_dmarc.{domain}");
        if let Some(record) = self.try_parse_dmarc_txt(&query).await? {
            return Ok(Some(record));
        }

        // Fall back to organizational domain: _dmarc.{org_domain}
        let org = org_domain(domain);
        if org != domain {
            let query = format!("_dmarc.{org}");
            if let Some(record) = self.try_parse_dmarc_txt(&query).await? {
                return Ok(Some(record));
            }
        }

        Ok(None)
    }

    /// Query DNS for a TXT record and attempt to parse it as DMARC.
    async fn try_parse_dmarc_txt(&self, name: &str) -> Result<Option<DmarcRecord>, SentioError> {
        match self.resolver.txt_lookup(name).await {
            Ok(lookup) => {
                for record in lookup.answers() {
                    let RData::TXT(txt) = &record.data else {
                        continue;
                    };
                    let value = txt.to_string();
                    if value.starts_with("v=DMARC1") {
                        match parse_dmarc_record(&value) {
                            Ok(record) => return Ok(Some(record)),
                            Err(e) => {
                                debug!(name, error = %e, "failed to parse DMARC record");
                            }
                        }
                    }
                }
                Ok(None)
            }
            Err(e) => {
                // NXDOMAIN / no record is not an error - just means no DMARC.
                debug!(name, error = %e, "DMARC DNS lookup failed");
                Ok(None)
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

    // ── Record parsing ──────────────────────────────────────────────────────

    #[test]
    fn parse_minimal_record() {
        let r = parse_dmarc_record("v=DMARC1; p=none").unwrap();
        assert_eq!(r.policy, DmarcPolicy::None);
        assert_eq!(r.dkim_alignment, DmarcAlignment::Relaxed);
        assert_eq!(r.spf_alignment, DmarcAlignment::Relaxed);
        assert_eq!(r.pct, 100);
    }

    #[test]
    fn parse_full_record() {
        let txt = "v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=s; pct=50; \
                   rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com";
        let r = parse_dmarc_record(txt).unwrap();
        assert_eq!(r.policy, DmarcPolicy::Reject);
        assert_eq!(r.subdomain_policy, Some(DmarcPolicy::Quarantine));
        assert_eq!(r.dkim_alignment, DmarcAlignment::Strict);
        assert_eq!(r.spf_alignment, DmarcAlignment::Strict);
        assert_eq!(r.pct, 50);
        assert_eq!(r.rua, vec!["mailto:dmarc@example.com"]);
        assert_eq!(r.ruf, vec!["mailto:forensic@example.com"]);
    }

    #[test]
    fn parse_missing_version_errors() {
        assert!(parse_dmarc_record("p=none").is_err());
    }

    #[test]
    fn parse_missing_policy_errors() {
        assert!(parse_dmarc_record("v=DMARC1").is_err());
    }

    #[test]
    fn parse_invalid_policy_errors() {
        assert!(parse_dmarc_record("v=DMARC1; p=explode").is_err());
    }

    #[test]
    fn parse_unknown_tags_ignored() {
        let r = parse_dmarc_record("v=DMARC1; p=none; foo=bar").unwrap();
        assert_eq!(r.policy, DmarcPolicy::None);
    }

    // ── Organizational domain ───────────────────────────────────────────────

    #[test]
    fn org_domain_two_labels() {
        assert_eq!(org_domain("example.com"), "example.com");
    }

    #[test]
    fn org_domain_three_labels() {
        assert_eq!(org_domain("mail.example.com"), "example.com");
    }

    #[test]
    fn org_domain_four_labels() {
        assert_eq!(org_domain("a.b.example.com"), "example.com");
    }

    #[test]
    fn org_domain_single_label() {
        assert_eq!(org_domain("localhost"), "localhost");
    }

    // ── Alignment checks ────────────────────────────────────────────────────

    #[test]
    fn strict_alignment_exact_match() {
        assert!(domains_aligned(
            "example.com",
            "example.com",
            DmarcAlignment::Strict
        ));
    }

    #[test]
    fn strict_alignment_subdomain_fails() {
        assert!(!domains_aligned(
            "mail.example.com",
            "example.com",
            DmarcAlignment::Strict
        ));
    }

    #[test]
    fn relaxed_alignment_subdomain_passes() {
        assert!(domains_aligned(
            "mail.example.com",
            "example.com",
            DmarcAlignment::Relaxed
        ));
    }

    #[test]
    fn relaxed_alignment_different_domains_fails() {
        assert!(!domains_aligned(
            "example.com",
            "other.com",
            DmarcAlignment::Relaxed
        ));
    }

    #[test]
    fn alignment_case_insensitive() {
        assert!(domains_aligned(
            "EXAMPLE.COM",
            "example.com",
            DmarcAlignment::Strict
        ));
    }

    // ── Serde ───────────────────────────────────────────────────────────────

    #[test]
    fn dmarc_result_serde_roundtrip() {
        let result = DmarcVerifyResult::Fail;
        let json = serde_json::to_string(&result).unwrap();
        assert_eq!(json, "\"fail\"");
        let parsed: DmarcVerifyResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, result);
    }

    #[test]
    fn dmarc_policy_serde_roundtrip() {
        let policy = DmarcPolicy::Quarantine;
        let json = serde_json::to_string(&policy).unwrap();
        assert_eq!(json, "\"quarantine\"");
        let parsed: DmarcPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, policy);
    }

    // ── DMARC alignment evaluation ─────────────────────────────────────

    use crate::dkim::{DkimSignatureResult, DkimVerifyOutput, DkimVerifyResult};
    use crate::spf::{SpfVerifyOutput, SpfVerifyResult};

    fn make_dkim_pass(domain: &str) -> DkimVerifyOutput {
        DkimVerifyOutput {
            signatures: vec![DkimSignatureResult {
                result: DkimVerifyResult::Pass,
                domain: domain.to_string(),
                selector: "s1".into(),
                algorithm: "rsa-sha256".into(),
            }],
        }
    }

    fn make_dkim_fail(domain: &str) -> DkimVerifyOutput {
        DkimVerifyOutput {
            signatures: vec![DkimSignatureResult {
                result: DkimVerifyResult::Fail,
                domain: domain.to_string(),
                selector: "s1".into(),
                algorithm: "rsa-sha256".into(),
            }],
        }
    }

    fn make_spf_pass(domain: &str) -> SpfVerifyOutput {
        SpfVerifyOutput {
            result: SpfVerifyResult::Pass,
            domain: domain.to_string(),
            explanation: None,
        }
    }

    fn make_spf_fail(domain: &str) -> SpfVerifyOutput {
        SpfVerifyOutput {
            result: SpfVerifyResult::Fail,
            domain: domain.to_string(),
            explanation: None,
        }
    }

    fn make_record(policy: DmarcPolicy) -> DmarcRecord {
        DmarcRecord {
            policy,
            subdomain_policy: None,
            dkim_alignment: DmarcAlignment::Relaxed,
            spf_alignment: DmarcAlignment::Relaxed,
            pct: 100,
            rua: vec![],
            ruf: vec![],
        }
    }

    #[test]
    fn evaluate_dmarc_pass_dkim_aligned() {
        let record = make_record(DmarcPolicy::Reject);
        let result = super::evaluate_dmarc_alignment(
            "example.com",
            "other.com",
            &make_dkim_pass("example.com"),
            &make_spf_fail("other.com"),
            Some(&record),
        );
        assert_eq!(result.result, DmarcVerifyResult::Pass);
        assert!(result.dkim_aligned);
        assert!(!result.spf_aligned);
    }

    #[test]
    fn evaluate_dmarc_pass_spf_aligned() {
        let record = make_record(DmarcPolicy::Reject);
        let result = super::evaluate_dmarc_alignment(
            "example.com",
            "example.com",
            &make_dkim_fail("example.com"),
            &make_spf_pass("example.com"),
            Some(&record),
        );
        assert_eq!(result.result, DmarcVerifyResult::Pass);
        assert!(!result.dkim_aligned);
        assert!(result.spf_aligned);
    }

    #[test]
    fn evaluate_dmarc_fail_no_alignment() {
        let record = make_record(DmarcPolicy::Reject);
        let result = super::evaluate_dmarc_alignment(
            "example.com",
            "other.com",
            &make_dkim_pass("different.com"),
            &make_spf_fail("other.com"),
            Some(&record),
        );
        assert_eq!(result.result, DmarcVerifyResult::Fail);
        assert!(!result.dkim_aligned);
        assert!(!result.spf_aligned);
    }

    #[test]
    fn evaluate_dmarc_fail_strict_subdomain() {
        let mut record = make_record(DmarcPolicy::Reject);
        record.dkim_alignment = DmarcAlignment::Strict;
        let result = super::evaluate_dmarc_alignment(
            "example.com",
            "other.com",
            &make_dkim_pass("sub.example.com"),
            &make_spf_fail("other.com"),
            Some(&record),
        );
        assert_eq!(result.result, DmarcVerifyResult::Fail);
        assert!(!result.dkim_aligned);
    }

    #[test]
    fn evaluate_dmarc_pass_relaxed_subdomain() {
        let record = make_record(DmarcPolicy::Reject);
        // Default is Relaxed alignment
        let result = super::evaluate_dmarc_alignment(
            "example.com",
            "other.com",
            &make_dkim_pass("sub.example.com"),
            &make_spf_fail("other.com"),
            Some(&record),
        );
        assert_eq!(result.result, DmarcVerifyResult::Pass);
        assert!(result.dkim_aligned);
    }

    #[test]
    fn evaluate_dmarc_none_no_record() {
        let result = super::evaluate_dmarc_alignment(
            "example.com",
            "example.com",
            &make_dkim_pass("example.com"),
            &make_spf_pass("example.com"),
            None,
        );
        assert_eq!(result.result, DmarcVerifyResult::None);
        assert!(result.record.is_none());
    }
}
