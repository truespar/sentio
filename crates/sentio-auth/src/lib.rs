pub mod arc;
pub mod bimi;
pub mod dane;
pub mod dkim;
pub mod dmarc;
pub mod dns;
pub mod dns_checker;
pub mod mta_sts;
pub mod spf;

// Re-export key types for ergonomic use by downstream crates.
pub use dns::{Authenticator, DnsResolverConfig};
pub use dns_checker::{DnsCheckOutcome, DnsChecker};

pub use dkim::{
    dkim_sign, select_signing_key, DkimSignOutput, DkimSignatureResult, DkimVerifyOutput,
    DkimVerifyResult,
};

pub use spf::{SpfVerifyOutput, SpfVerifyResult};

pub use dmarc::{
    parse_dmarc_record, DmarcAlignment, DmarcPolicy, DmarcRecord, DmarcVerifyOutput,
    DmarcVerifyResult,
};

pub use arc::{ArcSealOutput, ArcVerifyOutput, ArcVerifyResult};

pub use bimi::{parse_bimi_record, BimiLookupOutput, BimiRecord};

pub use mta_sts::{parse_mta_sts_policy, MtaStsLookupOutput, MtaStsMode, MtaStsPolicy};

pub use dane::{
    parse_tlsa_rdata, tlsa_query_name, DaneLookupOutput, TlsaMatchingType, TlsaRecord,
    TlsaSelector, TlsaUsage,
};
