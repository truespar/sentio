//! Mailbox-level inbound actions: forwarding and auto-reply.
//!
//! These complement (do not replace) the tenant-level `inbound_routes`
//! webhook system. A message can both fire a webhook to a downstream
//! application AND trigger a per-mailbox forward/auto-reply - the
//! webhook tells the application the mail arrived, the mailbox actions
//! produce additional outbound mail.
//!
//! ## Loop safety
//!
//! Forwards and auto-replies CAN cause mail loops. Mailbox actions are
//! skipped when any of the following indicate the message is itself
//! automated:
//!
//!   * empty MAIL FROM (null sender - already a bounce/DSN)
//!   * RFC 3834 `Auto-Submitted:` header with any value other than `no`
//!   * RFC 2369 `List-*` / `List-Id` (mailing-list traffic)
//!   * `Precedence: bulk|list|junk` (the de-facto legacy marker)
//!   * `>= MAX_FORWARD_HOPS` Received headers (too many hops already)
//!
//! ## DMARC
//!
//! Forwarded mail rewrites `From:` to the mailbox address (e.g.
//! `info@example.com`) and moves the original sender to `Reply-To:`.
//! This makes DMARC pass at the forward destination because the
//! From-domain matches the mailbox domain and the outbound DKIM signs
//! with that domain's selector. The original DKIM signature is
//! unavoidably invalidated by the `From:` rewrite - that's expected;
//! it is discarded explicitly to avoid noise in the headers.

use chrono::Utc;
use mail_builder::headers::address::Address;
use mail_builder::headers::message_id::MessageId as MbMessageId;
use mail_builder::headers::raw::Raw;
use mail_builder::MessageBuilder;
use uuid::Uuid;

use crate::validation::count_received_headers;

/// Maximum allowed Received-header count before we refuse to forward.
/// Set conservatively - a normal hop chain is 2–4 Received headers.
pub const MAX_FORWARD_HOPS: usize = 10;

// ──────────────────────────────────────────────────────────────────────────────
// Loop guard
// ──────────────────────────────────────────────────────────────────────────────

/// Decide whether mailbox-level actions (forward / auto-reply) should
/// fire for this inbound message. Returns `Some(reason)` to skip, or
/// `None` to proceed. The reason string is for log lines.
pub fn skip_reason(
    envelope_from: &str,
    auto_submitted: Option<&str>,
    list_id: Option<&str>,
    precedence: Option<&str>,
    raw: &[u8],
) -> Option<&'static str> {
    if envelope_from.is_empty() {
        return Some("null sender (likely DSN/bounce)");
    }
    if let Some(v) = auto_submitted {
        // RFC 3834: any value other than "no" means automated.
        if !v.eq_ignore_ascii_case("no") {
            return Some("Auto-Submitted header present");
        }
    }
    if list_id.is_some() {
        return Some("List-Id / List-Unsubscribe present");
    }
    if let Some(p) = precedence {
        let t = p.trim();
        if t.eq_ignore_ascii_case("bulk")
            || t.eq_ignore_ascii_case("list")
            || t.eq_ignore_ascii_case("junk")
        {
            return Some("Precedence: bulk/list/junk");
        }
    }
    if count_received_headers(raw) >= MAX_FORWARD_HOPS {
        return Some("too many Received hops");
    }
    None
}

// ──────────────────────────────────────────────────────────────────────────────
// Forward - header rewrite of the original raw EML
// ──────────────────────────────────────────────────────────────────────────────

/// Names of headers we replace/drop from the original message when
/// constructing a forwarded copy. Comparison is case-insensitive.
///
/// We drop the original DKIM signature because rewriting From: breaks
/// it; outbound DKIM will re-sign with the mailbox-domain selector.
/// We drop Return-Path because the SMTP server prepends a fresh one
/// at final delivery.
const HEADERS_TO_REPLACE: &[&str] = &[
    "from",
    "reply-to",
    "return-path",
    "dkim-signature",
    "arc-seal",
    "arc-message-signature",
    "arc-authentication-results",
    // The original Authentication-Results header refers to the previous
    // hop's authentication of the sender domain. After the From: rewrite
    // that AR is misleading (it names the original sender's domain while
    // the new From: is the mailbox's own domain), and a strict downstream
    // verifier could flag the inconsistency. Drop it; the outbound
    // delivery path emits a fresh AR after re-signing.
    "authentication-results",
];

/// Rewrite the headers of a raw RFC 5322 message for forwarding:
///   * prepend new `From:` (the mailbox address)
///   * prepend `Reply-To:` (the original From, so the recipient can
///     reply directly to the original sender)
///   * prepend `Resent-From`, `Resent-To`, `Resent-Date` per RFC 5322
///     §3.6.6 so the forward is properly attributed
///   * drop the original From/Reply-To/Return-Path/DKIM/ARC headers
///   * keep the body bytes verbatim (no MIME re-encoding)
///
/// Returns the new raw bytes. Always emits CRLF line endings.
pub fn rewrite_for_forward(
    raw: &[u8],
    mailbox_addr: &str,
    mailbox_display_name: Option<&str>,
    original_from: Option<&str>,
    original_to: &[String],
) -> Vec<u8> {
    let (headers_end, body_start) = find_headers_body_boundary(raw);
    let header_section = &raw[..headers_end];
    let body_section = &raw[body_start..];

    let mut out: Vec<u8> = Vec::with_capacity(raw.len() + 512);

    // Prepend new headers (these win over any in the original). For
    // `From:` prefer the `"Display" <addr>` form when the mailbox has
    // a display name set, falling back to bare addr-spec. We never
    // emit `<addr>` alone (no display-name + angle brackets) - Gmail
    // rejects that as RFC 5322 non-compliant despite the grammar
    // technically allowing it.
    let now = Utc::now().to_rfc2822();
    let from_value = match mailbox_display_name.filter(|s| !s.trim().is_empty()) {
        Some(name) => format!("\"{}\" <{}>", escape_quoted_string(name), mailbox_addr),
        None => mailbox_addr.to_string(),
    };
    write_header(&mut out, "From", &from_value);
    if let Some(orig) = original_from.filter(|s| !s.is_empty()) {
        write_header(&mut out, "Reply-To", orig);
        write_header(&mut out, "Resent-From", orig);
    }
    if !original_to.is_empty() {
        let joined = original_to.join(", ");
        write_header(&mut out, "Resent-To", &joined);
    }
    write_header(&mut out, "Resent-Date", &now);

    // Copy original headers, skipping any in HEADERS_TO_REPLACE.
    for logical in iter_logical_headers(header_section) {
        if header_in_replace_set(logical) {
            continue;
        }
        out.extend_from_slice(logical);
        // Ensure every preserved header ends with CRLF (the last header
        // line in some malformed messages omits it).
        if !logical.ends_with(b"\r\n") {
            if logical.ends_with(b"\n") {
                // bare LF - normalise to CRLF
                out.pop();
                out.extend_from_slice(b"\r\n");
            } else {
                out.extend_from_slice(b"\r\n");
            }
        }
    }

    // Headers/body separator + body verbatim.
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body_section);
    out
}

fn write_header(buf: &mut Vec<u8>, name: &str, value: &str) {
    buf.extend_from_slice(name.as_bytes());
    buf.extend_from_slice(b": ");
    buf.extend_from_slice(value.as_bytes());
    buf.extend_from_slice(b"\r\n");
}

/// Escape `"` and `\` inside an RFC 5322 quoted-string so a display name
/// like `John "the boss" Smith` does not terminate the quoted-string
/// early. Strips CR and LF since those would break header folding.
fn escape_quoted_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '\r' | '\n' => {}
            _ => out.push(c),
        }
    }
    out
}

fn find_headers_body_boundary(raw: &[u8]) -> (usize, usize) {
    if let Some(p) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        return (p + 2, p + 4); // include trailing CRLF of last header
    }
    if let Some(p) = raw.windows(2).position(|w| w == b"\n\n") {
        return (p + 1, p + 2);
    }
    (raw.len(), raw.len())
}

/// Iterator over logical headers in a header section. A logical
/// header may span multiple raw lines via RFC 5322 §2.2.3 folding
/// (continuation lines start with SP or HTAB). Each yielded slice
/// covers the full logical header *including* its trailing CRLF.
fn iter_logical_headers(section: &[u8]) -> LogicalHeaderIter<'_> {
    LogicalHeaderIter {
        bytes: section,
        pos: 0,
    }
}

struct LogicalHeaderIter<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for LogicalHeaderIter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        if self.pos >= self.bytes.len() {
            return None;
        }
        let start = self.pos;
        loop {
            let line_end = next_line_end(&self.bytes[self.pos..]) + self.pos;
            self.pos = line_end;
            // Peek next byte; if it's WSP, the next line is a continuation
            // of this logical header.
            match self.bytes.get(self.pos) {
                Some(b' ') | Some(b'\t') => continue,
                _ => break,
            }
        }
        Some(&self.bytes[start..self.pos])
    }
}

fn next_line_end(slice: &[u8]) -> usize {
    let mut i = 0;
    while i < slice.len() {
        if slice[i] == b'\n' {
            return i + 1;
        }
        i += 1;
    }
    slice.len()
}

fn header_in_replace_set(line: &[u8]) -> bool {
    let Some(colon_pos) = line.iter().position(|&b| b == b':') else {
        return false;
    };
    let name = &line[..colon_pos];
    HEADERS_TO_REPLACE
        .iter()
        .any(|h| name.eq_ignore_ascii_case(h.as_bytes()))
}

// ──────────────────────────────────────────────────────────────────────────────
// Auto-reply - fresh EML built via mail-builder
// ──────────────────────────────────────────────────────────────────────────────

/// Build a fresh auto-reply EML responding to an inbound message.
///
/// * `Subject:` becomes `Re: {original_subject}` (or the configured
///   subject template if non-empty).
/// * `Auto-Submitted: auto-replied` per RFC 3834 - receiving auto-
///   responders MUST honour this to break loops.
/// * `In-Reply-To` and `References` point at the original Message-ID
///   so the reply threads in the user's client.
///
/// Returns `(raw_eml_bytes, new_message_id_bare)`. The Message-ID is
/// the bare `id@host` form (no angle brackets) for persistence.
pub fn build_auto_reply_eml(
    mailbox_addr: &str,
    mailbox_display_name: Option<&str>,
    to_addr: &str,
    subject_template: Option<&str>,
    body_template: Option<&str>,
    original_subject: Option<&str>,
    original_message_id_bare: Option<&str>,
    hostname: &str,
) -> (Vec<u8>, String) {
    let subject = match subject_template {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => format!("Re: {}", original_subject.unwrap_or("(no subject)")),
    };
    let body = body_template.unwrap_or("");

    let new_message_id = format!("{}@{}", Uuid::new_v4().simple(), hostname);

    let from_address: Address = match mailbox_display_name {
        Some(n) if !n.is_empty() => {
            Address::new_address(Some(n.to_string()), mailbox_addr.to_string())
        }
        _ => Address::new_address(None::<String>, mailbox_addr.to_string()),
    };
    let to_address: Address = Address::new_address(None::<String>, to_addr.to_string());

    let mut builder = MessageBuilder::new()
        .from(from_address)
        .to(to_address)
        .subject(subject)
        .message_id(new_message_id.clone())
        .date(Utc::now().timestamp())
        .text_body(body.to_string())
        // RFC 3834 §5: auto-responders MUST set this so other auto-
        // responders down the chain don't reply to our reply.
        .header("Auto-Submitted", Raw::new("auto-replied"));

    if let Some(orig) = original_message_id_bare {
        // mail-builder writes In-Reply-To / References as the angle-
        // bracketed form when given via MessageId.
        builder = builder
            .header("In-Reply-To", MbMessageId::new(orig.to_string()))
            .header("References", MbMessageId::new(orig.to_string()));
    }

    let raw = builder.write_to_vec().unwrap_or_default();
    (raw, new_message_id)
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: explicit `\x20` on the continuation line because Rust's
    // `\` line-continuation in string literals strips leading
    // whitespace, which would have destroyed the RFC 5322 fold.
    const SAMPLE_EML: &[u8] = b"From: \"Alice\" <alice@example.com>\r\n\
To: info@example.com\r\n\
Subject: Hello\r\n\
Date: Mon, 1 Jan 2024 12:00:00 +0000\r\n\
Message-ID: <abc@example.com>\r\n\
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel; b=\r\n\
\x20multilinesignaturedata==\r\n\
Reply-To: alice-noreply@example.com\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Hello there.\r\n\
This is the body.\r\n";

    #[test]
    fn forward_replaces_from_and_drops_dkim() {
        let out = rewrite_for_forward(
            SAMPLE_EML,
            "info@example.com",
            None,
            Some("alice@example.com"),
            &["info@example.com".to_string()],
        );
        let out_str = std::str::from_utf8(&out).expect("utf-8");

        // New From: at top, bare addr-spec (no display name supplied).
        assert!(
            out_str.starts_with("From: info@example.com\r\n"),
            "From: must lead, got:\n{}",
            out_str
        );
        // Original DKIM-Signature must be gone.
        assert!(!out_str.to_ascii_lowercase().contains("dkim-signature:"));
        // Reply-To rewritten (bare addr-spec).
        let lower = out_str.to_ascii_lowercase();
        assert!(lower.contains("reply-to: alice@example.com\r\n"));
        // Resent-* attribution.
        assert!(lower.contains("resent-from: alice@example.com\r\n"));
        assert!(lower.contains("resent-to: info@example.com\r\n"));
        assert!(lower.contains("resent-date:"));
        // Original subject + body preserved.
        assert!(out_str.contains("Subject: Hello\r\n"));
        assert!(out_str.contains("\r\n\r\nHello there.\r\nThis is the body.\r\n"));
        // Original Reply-To stripped (we replaced it).
        assert!(!lower.contains("reply-to: alice-noreply@example.com"));
    }

    #[test]
    fn forward_handles_folded_continuation_headers() {
        // The DKIM-Signature in SAMPLE_EML is folded across two lines.
        // It must be removed as a single logical header - the continuation
        // line must NOT leak through as a stray top-level header.
        let out = rewrite_for_forward(
            SAMPLE_EML,
            "info@example.com",
            None,
            Some("alice@example.com"),
            &[],
        );
        let out_str = std::str::from_utf8(&out).expect("utf-8");
        assert!(
            !out_str.contains("multilinesignaturedata"),
            "continuation leaked:\n{}",
            out_str
        );
    }

    #[test]
    fn forward_with_display_name_uses_quoted_form() {
        let out = rewrite_for_forward(
            SAMPLE_EML,
            "info@example.com",
            Some("John"),
            Some("alice@example.com"),
            &[],
        );
        let out_str = std::str::from_utf8(&out).expect("utf-8");
        assert!(
            out_str.starts_with("From: \"John\" <info@example.com>\r\n"),
            "got:\n{}",
            out_str
        );
    }

    #[test]
    fn forward_escapes_quotes_in_display_name() {
        let out = rewrite_for_forward(
            SAMPLE_EML,
            "info@example.com",
            Some("John \"the boss\" Smith"),
            Some("alice@example.com"),
            &[],
        );
        let out_str = std::str::from_utf8(&out).expect("utf-8");
        assert!(
            out_str.starts_with("From: \"John \\\"the boss\\\" Smith\" <info@example.com>\r\n"),
            "got:\n{}",
            out_str
        );
    }

    #[test]
    fn forward_drops_authentication_results() {
        let raw = b"Authentication-Results: smtp.example.com;\r\n\
\tspf=pass smtp.mailfrom=example.org\r\n\
From: \"Alice\" <alice@example.com>\r\n\
To: info@example.com\r\n\
Subject: Hello\r\n\
\r\n\
Body";
        let out = rewrite_for_forward(
            raw,
            "info@example.com",
            None,
            Some("alice@example.com"),
            &[],
        );
        let s = std::str::from_utf8(&out).expect("utf-8");
        assert!(!s.to_ascii_lowercase().contains("authentication-results:"));
        // continuation line must not leak as a header
        assert!(!s.contains("spf=pass"));
    }

    #[test]
    fn forward_preserves_body_verbatim() {
        let out = rewrite_for_forward(SAMPLE_EML, "info@example.com", None, None, &[]);
        // Find body in output and confirm byte-for-byte equality.
        let sep = out.windows(4).position(|w| w == b"\r\n\r\n").expect("sep");
        let body = &out[sep + 4..];
        assert_eq!(body, b"Hello there.\r\nThis is the body.\r\n");
    }

    #[test]
    fn auto_reply_threads_via_in_reply_to() {
        let (eml, mid) = build_auto_reply_eml(
            "info@example.com",
            Some("Info Desk"),
            "alice@example.com",
            None,
            Some("Thanks for your message - we'll reply within 24h."),
            Some("Original Subject"),
            Some("abc@example.com"),
            "smtp.example.com",
        );
        let eml_str = std::str::from_utf8(&eml).expect("utf-8");

        assert!(eml_str.contains("From:"));
        assert!(eml_str.contains("info@example.com"));
        assert!(eml_str.contains("To:"));
        assert!(eml_str.contains("alice@example.com"));
        assert!(eml_str.contains("Subject: Re: Original Subject"));
        assert!(eml_str.contains("Auto-Submitted: auto-replied"));
        assert!(eml_str.contains("In-Reply-To: <abc@example.com>"));
        assert!(eml_str.contains("References: <abc@example.com>"));
        assert!(eml_str.contains("Thanks for your message"));
        assert!(mid.ends_with("@smtp.example.com"));
    }

    #[test]
    fn auto_reply_subject_falls_back_to_re_original() {
        let (eml, _) = build_auto_reply_eml(
            "info@example.com",
            None,
            "a@b.com",
            Some("  "),
            Some("body"),
            Some("X"),
            None,
            "smtp.example.com",
        );
        let s = std::str::from_utf8(&eml).expect("utf-8");
        assert!(s.contains("Subject: Re: X"));
    }

    #[test]
    fn skip_reason_null_sender() {
        let r = skip_reason("", None, None, None, b"From: x\r\n\r\nbody");
        assert_eq!(r, Some("null sender (likely DSN/bounce)"));
    }

    #[test]
    fn skip_reason_auto_submitted() {
        let r = skip_reason(
            "x@y",
            Some("auto-replied"),
            None,
            None,
            b"From: x\r\n\r\nbody",
        );
        assert_eq!(r, Some("Auto-Submitted header present"));
        // "no" is the only value that allows passage.
        let r2 = skip_reason("x@y", Some("no"), None, None, b"From: x\r\n\r\nbody");
        assert!(r2.is_none());
    }

    #[test]
    fn skip_reason_list_marker() {
        let r = skip_reason(
            "x@y",
            None,
            Some("<list.example.com>"),
            None,
            b"From: x\r\n\r\nbody",
        );
        assert_eq!(r, Some("List-Id / List-Unsubscribe present"));
    }

    #[test]
    fn skip_reason_precedence_bulk() {
        let r = skip_reason("x@y", None, None, Some("bulk"), b"From: x\r\n\r\nbody");
        assert_eq!(r, Some("Precedence: bulk/list/junk"));
        // Unrelated precedence value passes.
        let r2 = skip_reason("x@y", None, None, Some("urgent"), b"From: x\r\n\r\nbody");
        assert!(r2.is_none());
    }

    #[test]
    fn skip_reason_too_many_received() {
        // Build a header section with MAX_FORWARD_HOPS Received: lines.
        let mut raw = Vec::new();
        for i in 0..MAX_FORWARD_HOPS {
            raw.extend_from_slice(format!("Received: from hop{}\r\n", i).as_bytes());
        }
        raw.extend_from_slice(b"From: x@y\r\n\r\nbody");
        let r = skip_reason("x@y", None, None, None, &raw);
        assert_eq!(r, Some("too many Received hops"));
    }

    #[test]
    fn skip_reason_clean_passes() {
        let r = skip_reason(
            "x@y",
            None,
            None,
            None,
            b"Received: from a\r\nFrom: x@y\r\n\r\nbody",
        );
        assert!(r.is_none());
    }
}
