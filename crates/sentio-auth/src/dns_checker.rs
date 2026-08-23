//! DNS verification for tenant domains.
//!
//! Runs SPF / DKIM / DMARC / MX / Return-Path lookups against the live
//! authoritative DNS for a domain and reports per-record status so
//! `domains.{spf,dkim,dmarc,mx,return_path}_status` can be updated.
//!
//! Errors from individual checks are captured as `(Failed, Some(msg))`
//! rather than propagated, so a partial success is still useful to the
//! caller.

use hickory_resolver::config::{ResolverConfig, GOOGLE};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;

use sentio_core::auth::{DkimKeyStatus, DnsCheckStatus};
use sentio_core::error::SentioError;
use sentio_core::message::DomainId;
use sentio_core::traits::{DkimKeyRepository, DomainRecord};

/// Result of running all DNS checks for one domain.
#[derive(Debug, Clone)]
pub struct DnsCheckOutcome {
    pub spf: (DnsCheckStatus, Option<String>),
    pub dkim: (DnsCheckStatus, Option<String>),
    pub dmarc: (DnsCheckStatus, Option<String>),
    pub mx: (DnsCheckStatus, Option<String>),
    pub return_path: (DnsCheckStatus, Option<String>),
}

/// Performs SPF / DKIM / DMARC / MX / Return-Path lookups for a domain.
pub struct DnsChecker {
    resolver: TokioResolver,
    hostname: String,
}

impl DnsChecker {
    /// Build a checker using a Google-public-DNS resolver.
    ///
    /// We don't use the system resolver because Sentio typically runs on
    /// the SMTP server itself, where the local resolver may have
    /// recursion disabled or special split-horizon entries that would
    /// hide the public answers we actually care about.
    pub fn new(hostname: String) -> Result<Self, SentioError> {
        let resolver = TokioResolver::builder_with_config(
            ResolverConfig::udp_and_tcp(&GOOGLE),
            TokioRuntimeProvider::default(),
        )
        .build()
        .map_err(|e| SentioError::Auth(format!("failed to build DNS resolver: {e}")))?;

        Ok(Self { resolver, hostname })
    }

    /// Run all checks for a single domain.
    ///
    /// `tenant_verp_enabled` controls whether `bounce.{domain}` is also
    /// verified. When false, `return_path` is reported as `NotApplicable`
    /// so the field doesn't sit at "pending" forever for tenants that have
    /// not opted into VERP.
    pub async fn check<K>(
        &self,
        domain: &DomainRecord,
        dkim_repo: &K,
        tenant_verp_enabled: bool,
    ) -> DnsCheckOutcome
    where
        K: DkimKeyRepository + ?Sized,
    {
        let spf = self.check_spf(&domain.domain_name).await;
        let dkim = self
            .check_dkim(domain.id, &domain.domain_name, dkim_repo)
            .await;
        let dmarc = self.check_dmarc(&domain.domain_name).await;
        let mx = if domain.use_for_receiving {
            self.check_mx(&domain.domain_name).await
        } else {
            // Send-only domains do not need an MX record pointing at us.
            (DnsCheckStatus::NotApplicable, None)
        };
        let return_path = if tenant_verp_enabled {
            self.check_return_path(&domain.domain_name).await
        } else {
            (DnsCheckStatus::NotApplicable, None)
        };

        DnsCheckOutcome {
            spf,
            dkim,
            dmarc,
            mx,
            return_path,
        }
    }

    /// Verify that `bounce.{domain}` resolves to one of this SMTP server's
    /// public IPs. CNAME chains are followed automatically by hickory's
    /// `lookup_ip`. Both A and AAAA records are considered.
    ///
    /// We compare against the addresses that `self.hostname` itself
    /// resolves to (rather than reading a config field) so the check
    /// remains correct even when the server is in the middle of an IP
    /// rotation - DNS is the authoritative source.
    pub async fn check_return_path(&self, domain: &str) -> (DnsCheckStatus, Option<String>) {
        let host = format!("bounce.{domain}");
        let bounce_ips = match self.resolver.lookup_ip(&host).await {
            Ok(rsp) => rsp.iter().collect::<Vec<_>>(),
            Err(_) => {
                return (
                    DnsCheckStatus::Failed,
                    Some(format!("{host} does not resolve")),
                );
            }
        };

        let target = self.hostname.trim_end_matches('.').to_lowercase();
        let my_ips = match self.resolver.lookup_ip(&target).await {
            Ok(rsp) => rsp.iter().collect::<Vec<_>>(),
            Err(e) => {
                return (
                    DnsCheckStatus::Failed,
                    Some(format!("could not resolve smtp host {target}: {e}")),
                );
            }
        };

        let mine: std::collections::HashSet<_> = my_ips.iter().copied().collect();
        if bounce_ips.iter().any(|ip| mine.contains(ip)) {
            (DnsCheckStatus::Verified, None)
        } else {
            (
                DnsCheckStatus::Failed,
                Some(format!(
                    "{host} resolves to {:?} but smtp host {target} resolves to {:?}",
                    bounce_ips, my_ips
                )),
            )
        }
    }

    // ── per-check implementations ────────────────────────────────────────

    async fn check_spf(&self, domain: &str) -> (DnsCheckStatus, Option<String>) {
        match self.resolver.txt_lookup(domain).await {
            Ok(rsp) => {
                let mut spf_records: Vec<String> = rsp
                    .answers()
                    .iter()
                    .filter_map(|r| match &r.data {
                        RData::TXT(txt) => Some(txt.to_string()),
                        _ => None,
                    })
                    .filter(|s| s.starts_with("v=spf1"))
                    .collect();
                match spf_records.len() {
                    0 => (
                        DnsCheckStatus::Failed,
                        Some(format!("no v=spf1 TXT record on {domain}")),
                    ),
                    1 => {
                        let rec = spf_records.pop().unwrap();
                        let expected = format!("include:{}", self.hostname);
                        if rec.contains(&expected) || rec.contains("ip4:") || rec.contains("a:") {
                            (DnsCheckStatus::Verified, None)
                        } else {
                            (
                                DnsCheckStatus::Failed,
                                Some(format!(
                                    "SPF record does not include {} (got: {rec})",
                                    self.hostname
                                )),
                            )
                        }
                    }
                    n => (
                        DnsCheckStatus::Failed,
                        Some(format!(
                            "multiple v=spf1 TXT records on {domain} ({n} found); only one is permitted"
                        )),
                    ),
                }
            }
            Err(e) if e.is_no_records_found() => (
                DnsCheckStatus::Failed,
                Some(format!("no TXT records on {domain}")),
            ),
            Err(e) => (
                DnsCheckStatus::Failed,
                Some(format!("SPF lookup error: {e}")),
            ),
        }
    }

    async fn check_dkim<K: DkimKeyRepository + ?Sized>(
        &self,
        domain_id: DomainId,
        domain: &str,
        dkim_repo: &K,
    ) -> (DnsCheckStatus, Option<String>) {
        let keys = match dkim_repo.list_by_domain(domain_id).await {
            Ok(k) => k,
            Err(e) => {
                return (
                    DnsCheckStatus::Failed,
                    Some(format!("dkim key fetch failed: {e}")),
                )
            }
        };
        let active: Vec<_> = keys
            .into_iter()
            .filter(|k| k.status == DkimKeyStatus::Active)
            .collect();
        if active.is_empty() {
            return (
                DnsCheckStatus::Failed,
                Some("no active DKIM key for this domain".into()),
            );
        }
        let mut missing = Vec::new();
        for key in &active {
            let host = format!("{}._domainkey.{}", key.selector, domain);
            match self.resolver.txt_lookup(&host).await {
                Ok(rsp) => {
                    let recs: Vec<String> = rsp
                        .answers()
                        .iter()
                        .filter_map(|r| match &r.data {
                            RData::TXT(txt) => Some(txt.to_string()),
                            _ => None,
                        })
                        .collect();
                    let pubkey_marker = format!("p={}", key.public_key);
                    let has_pubkey = recs.iter().any(|r| r.contains(&pubkey_marker));
                    if !has_pubkey {
                        let prefix_len = key.public_key.len().min(12);
                        missing.push(format!(
                            "{host} present but does not contain expected p={}…",
                            &key.public_key[..prefix_len]
                        ));
                    }
                }
                Err(_) => missing.push(format!("{host} not found")),
            }
        }
        if missing.is_empty() {
            (DnsCheckStatus::Verified, None)
        } else {
            (DnsCheckStatus::Failed, Some(missing.join("; ")))
        }
    }

    async fn check_dmarc(&self, domain: &str) -> (DnsCheckStatus, Option<String>) {
        let host = format!("_dmarc.{domain}");
        match self.resolver.txt_lookup(&host).await {
            Ok(rsp) => {
                let recs: Vec<String> = rsp
                    .answers()
                    .iter()
                    .filter_map(|r| match &r.data {
                        RData::TXT(txt) => Some(txt.to_string()),
                        _ => None,
                    })
                    .filter(|s| s.starts_with("v=DMARC1"))
                    .collect();
                if recs.is_empty() {
                    (
                        DnsCheckStatus::Failed,
                        Some(format!("no v=DMARC1 TXT record at {host}")),
                    )
                } else {
                    (DnsCheckStatus::Verified, None)
                }
            }
            Err(_) => (
                DnsCheckStatus::Failed,
                Some(format!("no TXT records at {host}")),
            ),
        }
    }

    async fn check_mx(&self, domain: &str) -> (DnsCheckStatus, Option<String>) {
        match self.resolver.mx_lookup(domain).await {
            Ok(rsp) => {
                let target = self.hostname.trim_end_matches('.').to_lowercase();
                let mut targets: Vec<String> = rsp
                    .answers()
                    .iter()
                    .filter_map(|r| match &r.data {
                        RData::MX(mx) => {
                            Some(mx.exchange.to_string().trim_end_matches('.').to_lowercase())
                        }
                        _ => None,
                    })
                    .collect();
                targets.sort();
                if targets.iter().any(|t| t == &target) {
                    (DnsCheckStatus::Verified, None)
                } else {
                    (
                        DnsCheckStatus::Failed,
                        Some(format!(
                            "MX records on {domain} do not include {target} (got: {})",
                            targets.join(", ")
                        )),
                    )
                }
            }
            Err(_) => (
                DnsCheckStatus::Failed,
                Some(format!("no MX records on {domain}")),
            ),
        }
    }
}
