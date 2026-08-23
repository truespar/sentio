use hickory_resolver::proto::rr::{RData, RecordType};
use sentio_core::error::SentioError;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::dns::Authenticator;

// ──────────────────────────────────────────────────────────────────────────────
// DANE / TLSA types (RFC 6698, RFC 7671)
// ──────────────────────────────────────────────────────────────────────────────

/// TLSA Certificate Usage field (RFC 6698 §2.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsaUsage {
    /// 0 - PKIX-TA: CA constraint (PKIX trust anchor).
    PkixTa,
    /// 1 - PKIX-EE: Service certificate constraint (must chain to PKIX CA).
    PkixEe,
    /// 2 - DANE-TA: Trust anchor assertion (CA, no PKIX validation needed).
    DaneTa,
    /// 3 - DANE-EE: Domain-issued certificate (exact match, no chain validation).
    DaneEe,
}

impl TlsaUsage {
    pub fn from_u8(v: u8) -> Result<Self, SentioError> {
        match v {
            0 => Ok(Self::PkixTa),
            1 => Ok(Self::PkixEe),
            2 => Ok(Self::DaneTa),
            3 => Ok(Self::DaneEe),
            _ => Err(SentioError::Auth(format!("unknown TLSA usage: {v}"))),
        }
    }
}

/// TLSA Selector field (RFC 6698 §2.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsaSelector {
    /// 0 - Full certificate (DER).
    FullCert,
    /// 1 - SubjectPublicKeyInfo (DER).
    SubjectPublicKeyInfo,
}

impl TlsaSelector {
    pub fn from_u8(v: u8) -> Result<Self, SentioError> {
        match v {
            0 => Ok(Self::FullCert),
            1 => Ok(Self::SubjectPublicKeyInfo),
            _ => Err(SentioError::Auth(format!("unknown TLSA selector: {v}"))),
        }
    }
}

/// TLSA Matching Type field (RFC 6698 §2.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsaMatchingType {
    /// 0 - Exact match (no hashing).
    Full,
    /// 1 - SHA-256 hash.
    Sha256,
    /// 2 - SHA-512 hash.
    Sha512,
}

impl TlsaMatchingType {
    pub fn from_u8(v: u8) -> Result<Self, SentioError> {
        match v {
            0 => Ok(Self::Full),
            1 => Ok(Self::Sha256),
            2 => Ok(Self::Sha512),
            _ => Err(SentioError::Auth(format!(
                "unknown TLSA matching type: {v}"
            ))),
        }
    }
}

/// A parsed TLSA record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsaRecord {
    pub usage: TlsaUsage,
    pub selector: TlsaSelector,
    pub matching_type: TlsaMatchingType,
    /// The certificate association data (raw bytes).
    pub data: Vec<u8>,
}

/// Result of looking up DANE/TLSA records for an MX host.
#[derive(Debug, Clone)]
pub struct DaneLookupOutput {
    /// Whether any TLSA records were found.
    pub has_tlsa: bool,
    /// Parsed TLSA records (may be empty).
    pub records: Vec<TlsaRecord>,
}

// ──────────────────────────────────────────────────────────────────────────────
// TLSA record parsing
// ──────────────────────────────────────────────────────────────────────────────

/// Parse a raw TLSA record from its wire format (usage, selector, matching_type
/// + certificate association data).
///
/// The wire format is: `[usage:1][selector:1][matching_type:1][data:N]`
pub fn parse_tlsa_rdata(rdata: &[u8]) -> Result<TlsaRecord, SentioError> {
    if rdata.len() < 4 {
        return Err(SentioError::Auth(format!(
            "TLSA rdata too short: {} bytes",
            rdata.len()
        )));
    }

    Ok(TlsaRecord {
        usage: TlsaUsage::from_u8(rdata[0])?,
        selector: TlsaSelector::from_u8(rdata[1])?,
        matching_type: TlsaMatchingType::from_u8(rdata[2])?,
        data: rdata[3..].to_vec(),
    })
}

/// Build the TLSA DNS query name for a given MX host and port.
///
/// Returns e.g. `_25._tcp.mail.example.com` for port 25.
pub fn tlsa_query_name(mx_host: &str, port: u16) -> String {
    format!("_{port}._tcp.{mx_host}")
}

// ──────────────────────────────────────────────────────────────────────────────
// Conversion from hickory-proto TLSA
// ──────────────────────────────────────────────────────────────────────────────

fn convert_hickory_tlsa(
    tlsa: &hickory_resolver::proto::rr::rdata::tlsa::TLSA,
) -> Result<TlsaRecord, SentioError> {
    let usage = TlsaUsage::from_u8(u8::from(tlsa.cert_usage))?;
    let selector = TlsaSelector::from_u8(u8::from(tlsa.selector))?;
    let matching_type = TlsaMatchingType::from_u8(u8::from(tlsa.matching))?;
    Ok(TlsaRecord {
        usage,
        selector,
        matching_type,
        data: tlsa.cert_data.clone(),
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// DNS lookup
// ──────────────────────────────────────────────────────────────────────────────

impl Authenticator {
    /// Look up TLSA records for an MX host and port.
    ///
    /// Queries `_PORT._tcp.{mx_host}` for TLSA records.
    ///
    /// **Note:** DANE requires DNSSEC-validated responses to be trustworthy.
    /// The resolver must be configured with DNSSEC validation enabled for
    /// production use.
    pub async fn lookup_tlsa(
        &self,
        mx_host: &str,
        port: u16,
    ) -> Result<DaneLookupOutput, SentioError> {
        let query = tlsa_query_name(mx_host, port);

        match self.resolver.lookup(&query, RecordType::TLSA).await {
            Ok(lookup) => {
                let mut records = Vec::new();
                for record in lookup.answers() {
                    if let RData::TLSA(ref tlsa) = &record.data {
                        match convert_hickory_tlsa(tlsa) {
                            Ok(parsed) => records.push(parsed),
                            Err(e) => {
                                debug!(query, error = %e, "failed to convert TLSA record");
                            }
                        }
                    }
                }
                Ok(DaneLookupOutput {
                    has_tlsa: !records.is_empty(),
                    records,
                })
            }
            Err(e) => {
                debug!(query, error = %e, "TLSA DNS lookup failed");
                Ok(DaneLookupOutput {
                    has_tlsa: false,
                    records: vec![],
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
    fn parse_tlsa_dane_ee_sha256() {
        // Usage=3 (DANE-EE), Selector=1 (SPKI), MatchType=1 (SHA-256)
        // followed by 32 bytes of hash data.
        let mut rdata = vec![3, 1, 1];
        rdata.extend_from_slice(&[0xAA; 32]);

        let record = parse_tlsa_rdata(&rdata).unwrap();
        assert_eq!(record.usage, TlsaUsage::DaneEe);
        assert_eq!(record.selector, TlsaSelector::SubjectPublicKeyInfo);
        assert_eq!(record.matching_type, TlsaMatchingType::Sha256);
        assert_eq!(record.data.len(), 32);
    }

    #[test]
    fn parse_tlsa_pkix_ta_full() {
        let mut rdata = vec![0, 0, 0];
        rdata.extend_from_slice(b"certificate-data-here");

        let record = parse_tlsa_rdata(&rdata).unwrap();
        assert_eq!(record.usage, TlsaUsage::PkixTa);
        assert_eq!(record.selector, TlsaSelector::FullCert);
        assert_eq!(record.matching_type, TlsaMatchingType::Full);
    }

    #[test]
    fn parse_tlsa_too_short() {
        assert!(parse_tlsa_rdata(&[3, 1]).is_err());
    }

    #[test]
    fn parse_tlsa_unknown_usage() {
        let rdata = vec![99, 1, 1, 0xAA];
        assert!(parse_tlsa_rdata(&rdata).is_err());
    }

    #[test]
    fn tlsa_query_name_port_25() {
        assert_eq!(
            tlsa_query_name("mail.example.com", 25),
            "_25._tcp.mail.example.com"
        );
    }

    #[test]
    fn tlsa_query_name_port_465() {
        assert_eq!(
            tlsa_query_name("smtp.example.com", 465),
            "_465._tcp.smtp.example.com"
        );
    }

    // ── Serde ───────────────────────────────────────────────────────────────

    #[test]
    fn tlsa_usage_serde_roundtrip() {
        let usage = TlsaUsage::DaneEe;
        let json = serde_json::to_string(&usage).unwrap();
        assert_eq!(json, "\"dane_ee\"");
        let parsed: TlsaUsage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, usage);
    }

    #[test]
    fn tlsa_selector_serde_roundtrip() {
        let sel = TlsaSelector::SubjectPublicKeyInfo;
        let json = serde_json::to_string(&sel).unwrap();
        assert_eq!(json, "\"subject_public_key_info\"");
        let parsed: TlsaSelector = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, sel);
    }

    #[test]
    fn tlsa_matching_type_serde_roundtrip() {
        let mt = TlsaMatchingType::Sha512;
        let json = serde_json::to_string(&mt).unwrap();
        assert_eq!(json, "\"sha512\"");
        let parsed: TlsaMatchingType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, mt);
    }
}
