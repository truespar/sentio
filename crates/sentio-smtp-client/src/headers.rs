use std::collections::HashMap;

use chrono::{DateTime, Utc};
use sentio_core::event::BounceClass;

// ──────────────────────────────────────────────────────────────────────────────
// DSN types
// ──────────────────────────────────────────────────────────────────────────────

/// Parameters for generating a Delivery Status Notification (RFC 3464).
#[derive(Debug, Clone)]
pub struct DsnParams {
    /// Original envelope sender (MAIL FROM).
    pub original_from: String,
    /// Original envelope recipients that bounced/deferred.
    pub original_to: Vec<String>,
    /// Our reporting MTA hostname.
    pub reporting_mta: String,
    /// The remote server's SMTP response.
    pub remote_response: String,
    /// Remote MTA hostname.
    pub remote_mta: Option<String>,
    /// Bounce classification.
    pub bounce_class: BounceClass,
    /// Original message arrival date.
    pub arrival_date: DateTime<Utc>,
    /// The original Message-ID header, if known.
    pub original_message_id: Option<String>,
    /// RFC 3461 Original-Envelope-Id (from MAIL FROM ENVID param).
    pub original_envid: Option<String>,
    /// RFC 3461 RET param ("FULL" or "HDRS") - controls whether the DSN
    /// includes the full original message or only headers.
    pub original_ret: Option<String>,
    /// RFC 3461 Original-Recipient per recipient address.
    /// Key = final recipient, Value = ORCPT value (e.g. "rfc822;user@example.com").
    pub original_orcpt: HashMap<String, String>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Bounce classification
// ──────────────────────────────────────────────────────────────────────────────

/// Classify a bounce from the SMTP response code.
pub fn classify_bounce(code: u16, enhanced: Option<&str>) -> BounceClass {
    // Check enhanced status code first.
    if let Some(esc) = enhanced {
        if esc.starts_with("5.1.") {
            return BounceClass::Hard; // Bad address
        }
        if esc.starts_with("5.7.") {
            return BounceClass::Block; // Policy rejection
        }
        if esc.starts_with("4.") {
            return BounceClass::Soft;
        }
    }

    match code {
        550..=554 => BounceClass::Hard,
        421 | 450 | 451 | 452 => BounceClass::Soft,
        500..=599 => BounceClass::Block,
        _ => BounceClass::Soft,
    }
}

/// Map a [`BounceClass`] to an RFC 3464 DSN action value.
fn dsn_action(bounce_class: BounceClass) -> &'static str {
    match bounce_class {
        BounceClass::Hard | BounceClass::Block => "failed",
        BounceClass::Soft => "delayed",
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// DSN generation
// ──────────────────────────────────────────────────────────────────────────────

/// Generate a DSN message per RFC 3464.
///
/// Returns the complete MIME message as a byte vector, with:
/// - A human-readable `text/plain` part.
/// - A `message/delivery-status` part with per-message and per-recipient fields.
pub fn generate_dsn(params: &DsnParams) -> Vec<u8> {
    let boundary = format!(
        "sentio-dsn-{}",
        uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let action = dsn_action(params.bounce_class);
    let arrival = params.arrival_date.to_rfc2822();
    let date_now = Utc::now().to_rfc2822();

    let mut msg = String::with_capacity(2048);

    // Headers
    msg.push_str(&format!("Date: {date_now}\r\n"));
    msg.push_str(&format!(
        "From: Mail Delivery System <mailer-daemon@{}>\r\n",
        params.reporting_mta
    ));
    msg.push_str(&format!("To: <{}>\r\n", params.original_from));
    msg.push_str("Subject: Delivery Status Notification\r\n");
    if let Some(ref mid) = params.original_message_id {
        msg.push_str(&format!("In-Reply-To: {mid}\r\n"));
    }
    msg.push_str("MIME-Version: 1.0\r\n");
    msg.push_str(&format!(
        "Content-Type: multipart/report; report-type=delivery-status;\r\n boundary=\"{boundary}\"\r\n"
    ));
    msg.push_str("\r\n");

    // Part 1: human-readable explanation
    msg.push_str(&format!("--{boundary}\r\n"));
    msg.push_str("Content-Type: text/plain; charset=utf-8\r\n\r\n");

    match params.bounce_class {
        BounceClass::Soft => {
            msg.push_str("This is a temporary delivery failure notification.\r\n\r\n");
            msg.push_str("Delivery of your message has been delayed. The system will continue\r\n");
            msg.push_str("trying to deliver it for you.\r\n\r\n");
        }
        _ => {
            msg.push_str("This is a permanent delivery failure notification.\r\n\r\n");
            msg.push_str(
                "Your message could not be delivered to the following recipients:\r\n\r\n",
            );
        }
    }

    for rcpt in &params.original_to {
        msg.push_str(&format!("  <{rcpt}>: {}\r\n", params.remote_response));
    }
    msg.push_str("\r\n");

    // Part 2: message/delivery-status (RFC 3464 §2)
    msg.push_str(&format!("--{boundary}\r\n"));
    msg.push_str("Content-Type: message/delivery-status\r\n\r\n");

    // Per-message fields
    msg.push_str(&format!("Reporting-MTA: dns; {}\r\n", params.reporting_mta));
    if let Some(ref envid) = params.original_envid {
        msg.push_str(&format!("Original-Envelope-Id: {envid}\r\n"));
    }
    msg.push_str(&format!("Arrival-Date: {arrival}\r\n"));
    msg.push_str("\r\n");

    // Per-recipient fields
    for rcpt in &params.original_to {
        if let Some(orcpt) = params.original_orcpt.get(rcpt) {
            msg.push_str(&format!("Original-Recipient: {orcpt}\r\n"));
        }
        msg.push_str(&format!("Final-Recipient: rfc822; {rcpt}\r\n"));
        msg.push_str(&format!("Action: {action}\r\n"));
        msg.push_str(&format!(
            "Status: {}\r\n",
            dsn_status_code(params.bounce_class)
        ));
        if let Some(ref mta) = params.remote_mta {
            msg.push_str(&format!("Remote-MTA: dns; {mta}\r\n"));
        }
        msg.push_str(&format!(
            "Diagnostic-Code: smtp; {}\r\n",
            params.remote_response
        ));
        msg.push_str("\r\n");
    }

    // Closing boundary
    msg.push_str(&format!("--{boundary}--\r\n"));

    msg.into_bytes()
}

/// Map a BounceClass to a DSN status code.
fn dsn_status_code(bounce_class: BounceClass) -> &'static str {
    match bounce_class {
        BounceClass::Hard => "5.0.0",
        BounceClass::Block => "5.7.1",
        BounceClass::Soft => "4.0.0",
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> DsnParams {
        DsnParams {
            original_from: "sender@example.com".into(),
            original_to: vec!["recipient@example.org".into()],
            reporting_mta: "mail.example.com".into(),
            remote_response: "550 5.1.1 User unknown".into(),
            remote_mta: Some("mx.example.org".into()),
            bounce_class: BounceClass::Hard,
            arrival_date: Utc::now(),
            original_message_id: Some("<test@example.com>".into()),
            original_envid: None,
            original_ret: None,
            original_orcpt: HashMap::new(),
        }
    }

    #[test]
    fn dsn_contains_required_fields() {
        let dsn = generate_dsn(&test_params());
        let text = String::from_utf8(dsn).unwrap();

        assert!(text.contains("Content-Type: multipart/report"));
        assert!(text.contains("report-type=delivery-status"));
        assert!(text.contains("Reporting-MTA: dns; mail.example.com"));
        assert!(text.contains("Final-Recipient: rfc822; recipient@example.org"));
        assert!(text.contains("Action: failed"));
        assert!(text.contains("Status: 5.0.0"));
        assert!(text.contains("Remote-MTA: dns; mx.example.org"));
        assert!(text.contains("Diagnostic-Code: smtp; 550 5.1.1 User unknown"));
    }

    #[test]
    fn dsn_multipart_structure() {
        let dsn = generate_dsn(&test_params());
        let text = String::from_utf8(dsn).unwrap();

        assert!(text.contains("Content-Type: text/plain"));
        assert!(text.contains("Content-Type: message/delivery-status"));
        // Should have opening and closing boundaries.
        let boundary_count = text.matches("--sentio-dsn-").count();
        assert!(
            boundary_count >= 3,
            "should have at least 3 boundaries (2 parts + closing)"
        );
    }

    #[test]
    fn dsn_delayed_action_for_soft_bounce() {
        let mut params = test_params();
        params.bounce_class = BounceClass::Soft;
        params.remote_response = "450 Try again later".into();

        let dsn = generate_dsn(&params);
        let text = String::from_utf8(dsn).unwrap();

        assert!(text.contains("Action: delayed"));
        assert!(text.contains("Status: 4.0.0"));
        assert!(text.contains("temporary delivery failure"));
    }

    #[test]
    fn dsn_block_bounce_action_is_failed() {
        let mut params = test_params();
        params.bounce_class = BounceClass::Block;

        let dsn = generate_dsn(&params);
        let text = String::from_utf8(dsn).unwrap();

        assert!(text.contains("Action: failed"));
        assert!(text.contains("Status: 5.7.1"));
    }

    #[test]
    fn classify_bounce_hard() {
        assert_eq!(classify_bounce(550, None), BounceClass::Hard);
        assert_eq!(classify_bounce(550, Some("5.1.1")), BounceClass::Hard);
    }

    #[test]
    fn classify_bounce_soft() {
        assert_eq!(classify_bounce(450, None), BounceClass::Soft);
        assert_eq!(classify_bounce(421, Some("4.7.0")), BounceClass::Soft);
    }

    #[test]
    fn classify_bounce_block() {
        assert_eq!(classify_bounce(550, Some("5.7.1")), BounceClass::Block);
    }

    #[test]
    fn dsn_multiple_recipients() {
        let mut params = test_params();
        params.original_to = vec!["alice@example.org".into(), "bob@example.org".into()];

        let dsn = generate_dsn(&params);
        let text = String::from_utf8(dsn).unwrap();

        assert!(text.contains("Final-Recipient: rfc822; alice@example.org"));
        assert!(text.contains("Final-Recipient: rfc822; bob@example.org"));
    }

    #[test]
    fn dsn_in_reply_to_header() {
        let dsn = generate_dsn(&test_params());
        let text = String::from_utf8(dsn).unwrap();
        assert!(text.contains("In-Reply-To: <test@example.com>"));
    }
}
