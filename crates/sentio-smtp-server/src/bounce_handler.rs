//! Inbound DSN (RFC 3464) parsing for VERP bounce reports.
//!
//! When the inbound pipeline detects a recipient at `bounce.{domain}` whose
//! local-part decodes to a valid VERP token (see
//! `sentio_core::verp::VerpCodec`), the entire SMTP DATA payload is treated
//! as a DSN (Delivery Status Notification) and routed here for parsing.
//!
//! Only the fields needed for downstream bounce classification and
//! suppression are extracted; richer per-recipient breakdowns are out of
//! scope for the current handler.
//!
//! Parsing is best-effort: any failure (malformed MIME, missing report
//! sub-part, unparseable status code) returns `None` so the caller can
//! still record an "unclassified bounce" without 5xx'ing the upstream MTA.

use mail_parser::{MessageParser, MimeHeaders};

/// Subset of an RFC 3464 DSN that's useful for classifying a bounce and
/// updating message state. Each field is optional because real-world DSNs
/// from misconfigured MTAs frequently omit them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedDsn {
    /// SMTP basic status code (e.g. 550).
    pub status_code: Option<u16>,
    /// Extended status code (e.g. "5.1.1").
    pub enhanced_status: Option<String>,
    /// Free-form diagnostic, typically from the `Diagnostic-Code` field
    /// (which embeds the remote SMTP response).
    pub diagnostic: Option<String>,
    /// Final-Recipient address (without the `rfc822;` type prefix).
    pub failed_recipient: Option<String>,
}

/// Parse an RFC 3464 DSN from a raw RFC 5322 message body.
///
/// Returns `None` if:
/// * The message is not parseable as MIME at all.
/// * No `multipart/report` part with `report-type=delivery-status` exists.
/// * The `message/delivery-status` sub-part is absent.
///
/// Otherwise returns a `ParsedDsn` with whatever fields could be
/// extracted; missing individual fields are `None`, not an error.
pub fn parse_dsn(body: &[u8]) -> Option<ParsedDsn> {
    let parsed = MessageParser::default().parse(body)?;

    // Find the per-recipient delivery-status text. RFC 3464 says the
    // `multipart/report` body has 2-3 parts; the second is
    // `message/delivery-status`, an RFC-822-headers-style document with
    // per-message and per-recipient field groups separated by blank
    // lines. Different MTAs differ in whether they include a leading
    // per-message group or jump straight to the recipient group, so the
    // safest approach is to scan every text part for the recognised
    // field names.
    //
    // We accept any text part whose content-type is `message/delivery-status`
    // or whose body contains a recognisable field set. This is more
    // forgiving than strict RFC 3464 walks and survives the
    // bracketed-Content-Type formats some MTAs emit.
    let mut delivery_status_body: Option<String> = None;
    for part in parsed.parts.iter() {
        let ctype = part
            .content_type()
            .map(|c| c.ctype().to_ascii_lowercase())
            .unwrap_or_default();
        let csub = part
            .content_type()
            .and_then(|c| c.subtype().map(|s| s.to_ascii_lowercase()))
            .unwrap_or_default();

        if ctype == "message" && csub == "delivery-status" {
            if let Some(text) = part.text_contents() {
                delivery_status_body = Some(text.to_string());
                break;
            }
            // Some parsers expose the raw bytes only.
            let raw = part.contents();
            if let Ok(s) = std::str::from_utf8(raw) {
                delivery_status_body = Some(s.to_string());
                break;
            }
        }
    }

    // Fallback: scan all text parts for the per-recipient field block.
    // This catches DSNs where the parser didn't classify the delivery-status
    // part by content-type (e.g. nested forwards or odd MIME nesting).
    if delivery_status_body.is_none() {
        for part in parsed.parts.iter() {
            if let Some(text) = part.text_contents() {
                if text.contains("Final-Recipient:") || text.contains("Status:") {
                    delivery_status_body = Some(text.to_string());
                    break;
                }
            }
        }
    }

    let ds = delivery_status_body?;
    Some(extract_fields(&ds))
}

/// Extract the relevant RFC 3464 fields from the text body of a
/// `message/delivery-status` part. Lines are scanned linearly so we tolerate
/// missing per-message field groups, mixed CRLF/LF line endings, and
/// continuation lines (lines starting with whitespace are appended to the
/// previous field).
fn extract_fields(ds: &str) -> ParsedDsn {
    let mut out = ParsedDsn::default();

    // Flatten continuation lines so a wrapped Diagnostic-Code value parses
    // as one field. RFC 3464 follows RFC 822-style header folding.
    let mut unfolded: Vec<String> = Vec::new();
    for raw_line in ds.split('\n') {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() {
            unfolded.push(String::new());
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = unfolded.last_mut() {
                last.push(' ');
                last.push_str(line.trim_start());
                continue;
            }
        }
        unfolded.push(line.to_string());
    }

    for line in unfolded.iter().filter(|l| !l.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name_lc = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name_lc.as_str() {
            "final-recipient" => {
                // Format: "rfc822; user@example.com"
                let addr = value
                    .split_once(';')
                    .map(|(_, v)| v.trim())
                    .unwrap_or(value);
                if !addr.is_empty() && out.failed_recipient.is_none() {
                    out.failed_recipient = Some(addr.to_string());
                }
            }
            "status" if out.enhanced_status.is_none() && !value.is_empty() => {
                out.enhanced_status = Some(value.to_string());
            }
            "diagnostic-code" => {
                // Format: "smtp; 550 5.1.1 User unknown"
                let body = value
                    .split_once(';')
                    .map(|(_, v)| v.trim())
                    .unwrap_or(value);
                if out.diagnostic.is_none() && !body.is_empty() {
                    out.diagnostic = Some(body.to_string());
                }
                // Pull the first 3-digit basic SMTP code out of the
                // diagnostic body.
                if out.status_code.is_none() {
                    out.status_code = first_smtp_code(body);
                }
            }
            _ => {}
        }
    }

    out
}

/// Find the first three consecutive ASCII digits (2xx/4xx/5xx) in a free-form
/// diagnostic string and return them as a u16. Anything outside the standard
/// SMTP code range (200-599) is rejected.
fn first_smtp_code(s: &str) -> Option<u16> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        if bytes[i].is_ascii_digit()
            && bytes[i + 1].is_ascii_digit()
            && bytes[i + 2].is_ascii_digit()
        {
            // Must be at a word boundary (start of string or preceded by
            // non-digit) so we don't pull "1234" out of an order id.
            let at_boundary = i == 0 || !bytes[i - 1].is_ascii_digit();
            let not_followed_by_digit = i + 3 == bytes.len() || !bytes[i + 3].is_ascii_digit();
            if at_boundary && not_followed_by_digit {
                let n = (bytes[i] - b'0') as u16 * 100
                    + (bytes[i + 1] - b'0') as u16 * 10
                    + (bytes[i + 2] - b'0') as u16;
                if (200..=599).contains(&n) {
                    return Some(n);
                }
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a canonical RFC 3464 DSN with the given recipient + status.
    fn sample_dsn(rcpt: &str, status: &str, smtp_line: &str) -> Vec<u8> {
        format!(
            "From: postmaster@example.com\r\n\
             To: bounce+abc@bounce.example.com\r\n\
             Subject: Undeliverable\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: multipart/report; report-type=delivery-status; boundary=\"BX\"\r\n\
             \r\n\
             --BX\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             This is an automatic delivery failure notice.\r\n\
             \r\n\
             --BX\r\n\
             Content-Type: message/delivery-status\r\n\
             \r\n\
             Reporting-MTA: dns; mta.example.com\r\n\
             \r\n\
             Final-Recipient: rfc822; {rcpt}\r\n\
             Action: failed\r\n\
             Status: {status}\r\n\
             Diagnostic-Code: smtp; {smtp_line}\r\n\
             \r\n\
             --BX--\r\n",
        )
        .into_bytes()
    }

    #[test]
    fn parses_standard_dsn() {
        let body = sample_dsn("user@example.com", "5.1.1", "550 5.1.1 User unknown");
        let dsn = parse_dsn(&body).expect("DSN parses");
        assert_eq!(dsn.failed_recipient.as_deref(), Some("user@example.com"));
        assert_eq!(dsn.enhanced_status.as_deref(), Some("5.1.1"));
        assert_eq!(dsn.status_code, Some(550));
        assert_eq!(dsn.diagnostic.as_deref(), Some("550 5.1.1 User unknown"));
    }

    #[test]
    fn handles_soft_bounce_status() {
        let body = sample_dsn(
            "queued@example.com",
            "4.2.1",
            "451 4.2.1 mailbox temporarily disabled",
        );
        let dsn = parse_dsn(&body).expect("DSN parses");
        assert_eq!(dsn.status_code, Some(451));
        assert_eq!(dsn.enhanced_status.as_deref(), Some("4.2.1"));
    }

    #[test]
    fn returns_none_for_unparseable_input() {
        // Random bytes - not even close to MIME.
        let body = b"\x00\x01\x02not an email at all";
        assert_eq!(parse_dsn(body), None);
    }

    #[test]
    fn returns_none_when_no_delivery_status_part() {
        let body = b"From: x@y\r\nSubject: hi\r\n\r\nhello\r\n";
        assert_eq!(parse_dsn(body), None);
    }

    #[test]
    fn first_smtp_code_handles_common_patterns() {
        assert_eq!(first_smtp_code("550 5.1.1 user unknown"), Some(550));
        assert_eq!(first_smtp_code("smtp; 451 4.2.1 deferred"), Some(451));
        assert_eq!(first_smtp_code("no code here"), None);
        // 600 is out of range.
        assert_eq!(first_smtp_code("600 not valid"), None);
        // Embedded inside a longer number should not match.
        assert_eq!(first_smtp_code("ref=12345"), None);
    }

    #[test]
    fn extract_fields_unfolds_continuation_lines() {
        // Direct test of the field extractor with an RFC-822-folded
        // Diagnostic-Code value. The end-to-end MIME walk relies on
        // mail-parser's own folding behaviour, which already strips
        // continuation whitespace, so this test exercises the codepath
        // that handles DSNs where the part is fed in raw.
        let ds = "Final-Recipient: rfc822; folded@example.com\r\n\
                  Status: 5.7.1\r\n\
                  Diagnostic-Code: smtp; 550 5.7.1 rejected because\r\n\
                  \tthe message looks like spam\r\n";
        let dsn = extract_fields(ds);
        assert_eq!(dsn.status_code, Some(550));
        assert_eq!(dsn.enhanced_status.as_deref(), Some("5.7.1"));
        assert!(dsn
            .diagnostic
            .as_deref()
            .unwrap()
            .contains("looks like spam"));
    }
}
