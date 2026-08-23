use bytes::BytesMut;

/// An SMTP response with reply code, optional enhanced status code, and one or more text lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpResponse {
    pub code: u16,
    pub enhanced: Option<String>,
    pub lines: Vec<String>,
}

impl SmtpResponse {
    pub fn new(code: u16, enhanced: Option<&str>, message: &str) -> Self {
        Self {
            code,
            enhanced: enhanced.map(String::from),
            lines: vec![message.to_string()],
        }
    }

    fn multi(code: u16, enhanced: Option<&str>, lines: Vec<String>) -> Self {
        Self {
            code,
            enhanced: enhanced.map(String::from),
            lines,
        }
    }

    // ── Greeting & EHLO ──────────────────────────────────────────────────

    pub fn greeting(hostname: &str) -> Self {
        Self::new(220, None, &format!("{hostname} ESMTP AI-SMTP"))
    }

    /// EHLO response with extension lines appended by the caller.
    pub fn ehlo(hostname: &str, ext_lines: Vec<String>) -> Self {
        let mut lines = vec![format!("{hostname} greets you")];
        lines.extend(ext_lines);
        Self::multi(250, None, lines)
    }

    pub fn helo(hostname: &str) -> Self {
        Self::new(250, None, &format!("{hostname} greets you"))
    }

    // ── Success ──────────────────────────────────────────────────────────

    pub fn ok() -> Self {
        Self::new(250, Some("2.0.0"), "OK")
    }

    pub fn mail_ok() -> Self {
        Self::new(250, Some("2.1.0"), "OK")
    }

    pub fn rcpt_ok() -> Self {
        Self::new(250, Some("2.1.5"), "OK")
    }

    pub fn start_data() -> Self {
        Self::new(354, None, "Start mail input; end with <CRLF>.<CRLF>")
    }

    pub fn data_ok(queue_id: &str) -> Self {
        Self::new(250, Some("2.0.0"), &format!("OK queued as {queue_id}"))
    }

    pub fn bye() -> Self {
        Self::new(221, Some("2.0.0"), "Bye")
    }

    // ── Client errors ────────────────────────────────────────────────────

    pub fn command_not_recognized() -> Self {
        Self::new(500, Some("5.5.1"), "Command not recognized")
    }

    pub fn command_not_implemented() -> Self {
        Self::new(502, Some("5.5.1"), "Command not implemented")
    }

    pub fn syntax_error() -> Self {
        Self::new(
            501,
            Some("5.5.4"),
            "Syntax error in parameters or arguments",
        )
    }

    pub fn bad_sequence() -> Self {
        Self::new(503, Some("5.5.1"), "Bad sequence of commands")
    }

    pub fn too_many_recipients() -> Self {
        Self::new(452, Some("4.5.3"), "Too many recipients")
    }

    pub fn message_too_large() -> Self {
        Self::new(
            552,
            Some("5.3.4"),
            "Message size exceeds fixed maximum message size",
        )
    }

    pub fn line_too_long() -> Self {
        Self::new(500, Some("5.5.2"), "Line too long")
    }

    // ── STARTTLS ────────────────────────────────────────────────────────

    pub fn ready_starttls() -> Self {
        Self::new(220, Some("2.0.0"), "Ready to start TLS")
    }

    pub fn tls_not_available() -> Self {
        Self::new(454, Some("4.7.0"), "TLS not available")
    }

    // ── Authentication ────────────────────────────────────────────────────

    pub fn auth_success() -> Self {
        Self::new(235, Some("2.7.0"), "Authentication successful")
    }

    pub fn auth_challenge(data: &str) -> Self {
        Self {
            code: 334,
            enhanced: None,
            lines: vec![data.to_string()],
        }
    }

    pub fn auth_continue() -> Self {
        Self {
            code: 334,
            enhanced: None,
            lines: vec![String::new()],
        }
    }

    pub fn auth_failed() -> Self {
        Self::new(535, Some("5.7.8"), "Authentication credentials invalid")
    }

    pub fn auth_temp_failure() -> Self {
        Self::new(454, Some("4.7.0"), "Temporary authentication failure")
    }

    pub fn auth_mechanism_not_supported() -> Self {
        Self::new(504, Some("5.5.4"), "Unrecognized authentication type")
    }

    pub fn encryption_required() -> Self {
        Self::new(538, Some("5.7.11"), "Encryption required")
    }

    pub fn auth_too_many() -> Self {
        Self::new(421, Some("4.7.0"), "Too many authentication attempts")
    }

    pub fn auth_cancelled() -> Self {
        Self::new(501, Some("5.7.0"), "Authentication cancelled")
    }

    pub fn already_authenticated() -> Self {
        Self::new(503, Some("5.5.1"), "Already authenticated")
    }

    pub fn connection_refused() -> Self {
        Self::new(421, Some("4.7.0"), "Connection refused")
    }

    // ── Server errors ────────────────────────────────────────────────────

    pub fn timeout() -> Self {
        Self::new(421, Some("4.4.2"), "Timeout waiting for input")
    }

    pub fn service_unavailable() -> Self {
        Self::new(421, Some("4.3.2"), "Service not available, closing channel")
    }

    pub fn too_many_messages() -> Self {
        Self::new(421, Some("4.7.0"), "Too many messages in this session")
    }

    // ── Pipeline-driven responses ───────────────────────────────────────

    pub fn processing_reject(code: u16, enhanced: &str, message: &str) -> Self {
        Self::new(code, Some(enhanced), message)
    }

    pub fn processing_tempfail(code: u16, enhanced: &str, message: &str) -> Self {
        Self::new(code, Some(enhanced), message)
    }

    // ── Wire format ──────────────────────────────────────────────────────

    /// Serialize to SMTP wire format (multiline with `code-` / `code ` continuation).
    pub fn to_bytes(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(256);
        let last = self.lines.len().saturating_sub(1);

        for (i, line) in self.lines.iter().enumerate() {
            let sep = if i < last { '-' } else { ' ' };

            buf.extend_from_slice(format!("{}{}", self.code, sep).as_bytes());
            if let Some(ref enh) = self.enhanced {
                buf.extend_from_slice(enh.as_bytes());
                buf.extend_from_slice(b" ");
            }
            buf.extend_from_slice(line.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_format() {
        let r = SmtpResponse::greeting("mail.example.com");
        assert_eq!(r.code, 220);
        assert_eq!(r.lines[0], "mail.example.com ESMTP AI-SMTP");
        let bytes = r.to_bytes();
        assert_eq!(&bytes[..], b"220 mail.example.com ESMTP AI-SMTP\r\n");
    }

    #[test]
    fn single_line_with_enhanced() {
        let r = SmtpResponse::ok();
        let bytes = r.to_bytes();
        assert_eq!(&bytes[..], b"250 2.0.0 OK\r\n");
    }

    #[test]
    fn multiline_ehlo() {
        let r = SmtpResponse::ehlo(
            "mail.example.com",
            vec![
                "SIZE 52428800".into(),
                "8BITMIME".into(),
                "PIPELINING".into(),
            ],
        );
        let bytes = r.to_bytes();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.starts_with("250-mail.example.com greets you\r\n"));
        assert!(s.contains("250-SIZE 52428800\r\n"));
        assert!(s.contains("250-8BITMIME\r\n"));
        assert!(s.ends_with("250 PIPELINING\r\n"));
    }

    #[test]
    fn error_codes() {
        assert_eq!(SmtpResponse::command_not_recognized().code, 500);
        assert_eq!(SmtpResponse::command_not_implemented().code, 502);
        assert_eq!(SmtpResponse::syntax_error().code, 501);
        assert_eq!(SmtpResponse::bad_sequence().code, 503);
        assert_eq!(SmtpResponse::too_many_recipients().code, 452);
        assert_eq!(SmtpResponse::message_too_large().code, 552);
        assert_eq!(SmtpResponse::timeout().code, 421);
        assert_eq!(SmtpResponse::service_unavailable().code, 421);
        assert_eq!(SmtpResponse::too_many_messages().code, 421);
    }

    #[test]
    fn data_ok_includes_queue_id() {
        let r = SmtpResponse::data_ok("ABC123");
        let bytes = r.to_bytes();
        assert_eq!(&bytes[..], b"250 2.0.0 OK queued as ABC123\r\n");
    }

    #[test]
    fn start_data_code() {
        let r = SmtpResponse::start_data();
        assert_eq!(r.code, 354);
        let bytes = r.to_bytes();
        assert!(bytes.starts_with(b"354 "));
    }

    #[test]
    fn bye_response() {
        let r = SmtpResponse::bye();
        assert_eq!(&r.to_bytes()[..], b"221 2.0.0 Bye\r\n");
    }

    #[test]
    fn ready_starttls_format() {
        let r = SmtpResponse::ready_starttls();
        assert_eq!(r.code, 220);
        assert_eq!(&r.to_bytes()[..], b"220 2.0.0 Ready to start TLS\r\n");
    }

    #[test]
    fn auth_success_format() {
        let r = SmtpResponse::auth_success();
        assert_eq!(r.code, 235);
        assert_eq!(
            &r.to_bytes()[..],
            b"235 2.7.0 Authentication successful\r\n"
        );
    }

    #[test]
    fn auth_challenge_format() {
        let r = SmtpResponse::auth_challenge("VXNlcm5hbWU6");
        assert_eq!(r.code, 334);
        assert_eq!(&r.to_bytes()[..], b"334 VXNlcm5hbWU6\r\n");
    }

    #[test]
    fn auth_failed_format() {
        let r = SmtpResponse::auth_failed();
        assert_eq!(r.code, 535);
    }

    #[test]
    fn auth_temp_failure_format() {
        let r = SmtpResponse::auth_temp_failure();
        assert_eq!(r.code, 454);
        assert_eq!(
            &r.to_bytes()[..],
            b"454 4.7.0 Temporary authentication failure\r\n"
        );
    }

    #[test]
    fn auth_codes() {
        assert_eq!(SmtpResponse::auth_mechanism_not_supported().code, 504);
        assert_eq!(SmtpResponse::encryption_required().code, 538);
        assert_eq!(SmtpResponse::auth_too_many().code, 421);
        assert_eq!(SmtpResponse::auth_cancelled().code, 501);
        assert_eq!(SmtpResponse::already_authenticated().code, 503);
        assert_eq!(SmtpResponse::connection_refused().code, 421);
        assert_eq!(SmtpResponse::tls_not_available().code, 454);
    }
}
