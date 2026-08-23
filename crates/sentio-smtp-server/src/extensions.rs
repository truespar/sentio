/// ESMTP extension capabilities as a compact bitflag set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extensions(u32);

impl Extensions {
    pub const SIZE: u32 = 1 << 0;
    pub const EIGHT_BIT_MIME: u32 = 1 << 1;
    pub const PIPELINING: u32 = 1 << 2;
    pub const SMTPUTF8: u32 = 1 << 3;
    /// Reserved for outbound client use only; BDAT is routed to NotImplemented on the server.
    pub const CHUNKING: u32 = 1 << 4;
    pub const STARTTLS: u32 = 1 << 5;
    pub const AUTH: u32 = 1 << 6;
    pub const ENHANCED_STATUS_CODES: u32 = 1 << 7;
    /// DSN extension (RFC 3461). Included in all default sets.
    pub const DSN: u32 = 1 << 8;
    /// XCLIENT extension (Postfix proxy convention). Not in any default set.
    pub const XCLIENT: u32 = 1 << 9;

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn has(self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    pub fn set(&mut self, flag: u32) {
        self.0 |= flag;
    }

    pub fn clear(&mut self, flag: u32) {
        self.0 &= !flag;
    }

    /// Common base extensions shared by all modes.
    fn base() -> Self {
        Self(
            Self::SIZE
                | Self::EIGHT_BIT_MIME
                | Self::PIPELINING
                | Self::SMTPUTF8
                | Self::CHUNKING
                | Self::ENHANCED_STATUS_CODES
                | Self::DSN,
        )
    }

    /// Default extensions for a plaintext session (no TLS, no AUTH).
    pub fn default_plain() -> Self {
        Self::base()
    }

    /// Port 25 SMTP: base + STARTTLS (no AUTH until TLS).
    pub fn default_smtp() -> Self {
        let mut ext = Self::base();
        ext.set(Self::STARTTLS);
        ext
    }

    /// Port 465 implicit TLS (SMTPS): base + AUTH (no STARTTLS needed).
    pub fn default_smtps() -> Self {
        let mut ext = Self::base();
        ext.set(Self::AUTH);
        ext
    }

    /// Port 587 submission: base + STARTTLS + AUTH.
    pub fn default_submission() -> Self {
        let mut ext = Self::base();
        ext.set(Self::STARTTLS);
        ext.set(Self::AUTH);
        ext
    }

    /// Generate EHLO extension advertisement lines.
    ///
    /// `auth_mechanisms` is the space-separated list of supported SASL
    /// mechanisms (e.g., `"PLAIN LOGIN SCRAM-SHA-256"`). Only used when
    /// the AUTH extension flag is set.
    pub fn ehlo_lines(&self, max_message_size: u64, auth_mechanisms: &str) -> Vec<String> {
        let mut lines = Vec::new();

        if self.has(Self::SIZE) {
            lines.push(format!("SIZE {max_message_size}"));
        }
        if self.has(Self::EIGHT_BIT_MIME) {
            lines.push("8BITMIME".into());
        }
        if self.has(Self::PIPELINING) {
            lines.push("PIPELINING".into());
        }
        if self.has(Self::SMTPUTF8) {
            lines.push("SMTPUTF8".into());
        }
        if self.has(Self::CHUNKING) {
            lines.push("CHUNKING".into());
        }
        if self.has(Self::STARTTLS) {
            lines.push("STARTTLS".into());
        }
        if self.has(Self::AUTH) && !auth_mechanisms.is_empty() {
            lines.push(format!("AUTH {auth_mechanisms}"));
        }
        if self.has(Self::ENHANCED_STATUS_CODES) {
            lines.push("ENHANCEDSTATUSCODES".into());
        }
        if self.has(Self::DSN) {
            lines.push("DSN".into());
        }
        if self.has(Self::XCLIENT) {
            lines.push("XCLIENT ADDR NAME HELO LOGIN PORT".into());
        }

        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_plain_flags() {
        let ext = Extensions::default_plain();
        assert!(ext.has(Extensions::SIZE));
        assert!(ext.has(Extensions::EIGHT_BIT_MIME));
        assert!(ext.has(Extensions::PIPELINING));
        assert!(ext.has(Extensions::SMTPUTF8));
        assert!(ext.has(Extensions::CHUNKING));
        assert!(ext.has(Extensions::ENHANCED_STATUS_CODES));
        assert!(ext.has(Extensions::DSN));
        assert!(!ext.has(Extensions::STARTTLS));
        assert!(!ext.has(Extensions::AUTH));
    }

    #[test]
    fn set_and_clear() {
        let mut ext = Extensions::empty();
        assert!(!ext.has(Extensions::SIZE));
        ext.set(Extensions::SIZE);
        assert!(ext.has(Extensions::SIZE));
        ext.clear(Extensions::SIZE);
        assert!(!ext.has(Extensions::SIZE));
    }

    #[test]
    fn ehlo_lines_default_plain() {
        let ext = Extensions::default_plain();
        let lines = ext.ehlo_lines(52_428_800, "");
        assert!(lines.contains(&"SIZE 52428800".to_string()));
        assert!(lines.contains(&"8BITMIME".to_string()));
        assert!(lines.contains(&"PIPELINING".to_string()));
        assert!(lines.contains(&"SMTPUTF8".to_string()));
        assert!(lines.contains(&"ENHANCEDSTATUSCODES".to_string()));
        assert!(!lines.iter().any(|l| l.starts_with("STARTTLS")));
        assert!(!lines.iter().any(|l| l.starts_with("AUTH")));
    }

    #[test]
    fn ehlo_lines_with_starttls_and_auth() {
        let mut ext = Extensions::default_plain();
        ext.set(Extensions::STARTTLS);
        ext.set(Extensions::AUTH);
        let lines = ext.ehlo_lines(10_000_000, "PLAIN LOGIN SCRAM-SHA-256");
        assert!(lines.contains(&"STARTTLS".to_string()));
        assert!(lines.contains(&"AUTH PLAIN LOGIN SCRAM-SHA-256".to_string()));
    }

    #[test]
    fn empty_has_nothing() {
        let ext = Extensions::empty();
        assert!(!ext.has(Extensions::SIZE));
        assert!(!ext.has(Extensions::PIPELINING));
        assert!(ext.ehlo_lines(0, "").is_empty());
    }

    #[test]
    fn default_smtp_has_starttls() {
        let ext = Extensions::default_smtp();
        assert!(ext.has(Extensions::STARTTLS));
        assert!(!ext.has(Extensions::AUTH));
    }

    #[test]
    fn default_smtps_has_auth_no_starttls() {
        let ext = Extensions::default_smtps();
        assert!(ext.has(Extensions::AUTH));
        assert!(!ext.has(Extensions::STARTTLS));
    }

    #[test]
    fn default_submission_has_both() {
        let ext = Extensions::default_submission();
        assert!(ext.has(Extensions::STARTTLS));
        assert!(ext.has(Extensions::AUTH));
    }

    #[test]
    fn auth_line_omitted_when_mechanisms_empty() {
        let ext = Extensions::default_smtps();
        let lines = ext.ehlo_lines(10_000_000, "");
        assert!(!lines.iter().any(|l| l.starts_with("AUTH")));
    }

    #[test]
    fn dsn_in_defaults() {
        assert!(Extensions::default_plain().has(Extensions::DSN));
        assert!(Extensions::default_smtp().has(Extensions::DSN));
        assert!(Extensions::default_smtps().has(Extensions::DSN));
        assert!(Extensions::default_submission().has(Extensions::DSN));
    }

    #[test]
    fn dsn_ehlo_advertisement() {
        let mut ext = Extensions::default_plain();
        ext.set(Extensions::DSN);
        let lines = ext.ehlo_lines(10_000_000, "");
        assert!(lines.contains(&"DSN".to_string()));
    }
}
