use hickory_resolver::proto::rr::RData;
use sentio_core::error::SentioError;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::dns::Authenticator;

// ──────────────────────────────────────────────────────────────────────────────
// BIMI types (RFC 9495)
// ──────────────────────────────────────────────────────────────────────────────

/// A parsed BIMI DNS record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BimiRecord {
    /// Logo location URL (the `l=` tag).  Must be an HTTPS URL to an SVG.
    pub logo_url: Option<String>,
    /// Authority evidence location (the `a=` tag).  URL to a VMC/CMC
    /// certificate.
    pub authority_url: Option<String>,
    /// BIMI selector used for the lookup (default: `default`).
    pub selector: String,
}

/// Result of a BIMI lookup.
#[derive(Debug, Clone)]
pub struct BimiLookupOutput {
    /// The parsed BIMI record, if found.
    pub record: Option<BimiRecord>,
    /// The domain that was queried.
    pub domain: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Record parsing
// ──────────────────────────────────────────────────────────────────────────────

/// Parse a BIMI TXT record value.
///
/// Expected format: `v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem`
pub fn parse_bimi_record(txt: &str, selector: &str) -> Result<BimiRecord, SentioError> {
    let txt = txt.trim();
    let mut has_version = false;
    let mut logo_url = None;
    let mut authority_url = None;

    for part in txt.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| SentioError::Auth(format!("invalid BIMI tag: {part}")))?;
        let key = key.trim().to_lowercase();
        let value = value.trim();

        match key.as_str() {
            "v" => {
                if value != "BIMI1" {
                    return Err(SentioError::Auth(format!(
                        "unsupported BIMI version: {value}"
                    )));
                }
                has_version = true;
            }
            "l" if !value.is_empty() => {
                logo_url = Some(value.to_string());
            }
            "a" if !value.is_empty() => {
                authority_url = Some(value.to_string());
            }
            _ => { /* ignore unknown tags */ }
        }
    }

    if !has_version {
        return Err(SentioError::Auth("BIMI record missing v=BIMI1".into()));
    }

    Ok(BimiRecord {
        logo_url,
        authority_url,
        selector: selector.to_string(),
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// DNS lookup
// ──────────────────────────────────────────────────────────────────────────────

impl Authenticator {
    /// Look up the BIMI record for a domain.
    ///
    /// Queries `{selector}._bimi.{domain}` (default selector: `default`).
    pub async fn lookup_bimi(
        &self,
        domain: &str,
        selector: Option<&str>,
    ) -> Result<BimiLookupOutput, SentioError> {
        let selector = selector.unwrap_or("default");
        let query = format!("{selector}._bimi.{domain}");

        match self.resolver.txt_lookup(&query).await {
            Ok(lookup) => {
                for record in lookup.answers() {
                    let RData::TXT(txt) = &record.data else {
                        continue;
                    };
                    let value = txt.to_string();
                    if value.starts_with("v=BIMI1") {
                        match parse_bimi_record(&value, selector) {
                            Ok(record) => {
                                return Ok(BimiLookupOutput {
                                    record: Some(record),
                                    domain: domain.to_string(),
                                });
                            }
                            Err(e) => {
                                debug!(domain, error = %e, "failed to parse BIMI record");
                            }
                        }
                    }
                }
                Ok(BimiLookupOutput {
                    record: None,
                    domain: domain.to_string(),
                })
            }
            Err(e) => {
                debug!(domain, error = %e, "BIMI DNS lookup failed");
                Ok(BimiLookupOutput {
                    record: None,
                    domain: domain.to_string(),
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

    #[test]
    fn parse_full_bimi_record() {
        let txt = "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem";
        let record = parse_bimi_record(txt, "default").unwrap();
        assert_eq!(record.logo_url, Some("https://example.com/logo.svg".into()));
        assert_eq!(
            record.authority_url,
            Some("https://example.com/vmc.pem".into())
        );
        assert_eq!(record.selector, "default");
    }

    #[test]
    fn parse_logo_only() {
        let txt = "v=BIMI1; l=https://example.com/brand.svg;";
        let record = parse_bimi_record(txt, "default").unwrap();
        assert_eq!(
            record.logo_url,
            Some("https://example.com/brand.svg".into())
        );
        assert!(record.authority_url.is_none());
    }

    #[test]
    fn parse_empty_values() {
        let txt = "v=BIMI1; l=; a=";
        let record = parse_bimi_record(txt, "default").unwrap();
        assert!(record.logo_url.is_none());
        assert!(record.authority_url.is_none());
    }

    #[test]
    fn parse_missing_version_errors() {
        assert!(parse_bimi_record("l=https://example.com/logo.svg", "default").is_err());
    }

    #[test]
    fn parse_wrong_version_errors() {
        assert!(parse_bimi_record("v=BIMI2; l=https://example.com/logo.svg", "default").is_err());
    }

    #[test]
    fn parse_unknown_tags_ignored() {
        let txt = "v=BIMI1; l=https://example.com/logo.svg; foo=bar";
        let record = parse_bimi_record(txt, "s1").unwrap();
        assert!(record.logo_url.is_some());
        assert_eq!(record.selector, "s1");
    }

    // ── Serde ───────────────────────────────────────────────────────────────

    #[test]
    fn bimi_record_serde_roundtrip() {
        let record = BimiRecord {
            logo_url: Some("https://example.com/logo.svg".into()),
            authority_url: None,
            selector: "default".into(),
        };
        let json = serde_json::to_string(&record).unwrap();
        let parsed: BimiRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, record);
    }
}
