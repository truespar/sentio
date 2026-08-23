//! Shared validation helpers for the inbound SMTP server.

/// Check if a string contains non-ASCII bytes (RFC 6531 internationalized addresses).
pub fn has_non_ascii(s: &str) -> bool {
    s.bytes().any(|b| b > 127)
}

/// Validate an EHLO/HELO domain per RFC 5321 §4.1.1.1.
/// Accepts address literals (`[...]`) and FQDN-like strings (has a dot,
/// no spaces, <= 255 chars, alphanumeric/dot/hyphen only).
pub fn is_valid_ehlo_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 255 {
        return false;
    }
    // Address literals are always accepted
    if domain.starts_with('[') && domain.ends_with(']') {
        return true;
    }
    // Must contain a dot (FQDN)
    if !domain.contains('.') {
        return false;
    }
    // Only alphanumeric, dot, hyphen
    domain
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// Dot-unstuffing per RFC 5321 §4.5.2: remove leading dot from lines that start with "..".
pub fn dot_unstuff(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut at_line_start = true;

    let mut i = 0;
    while i < data.len() {
        if at_line_start && i + 1 < data.len() && data[i] == b'.' && data[i + 1] == b'.' {
            // Skip the extra dot
            i += 1;
            at_line_start = false;
        } else {
            at_line_start = data[i] == b'\n';
            result.push(data[i]);
            i += 1;
        }
    }

    result
}

/// Count Received headers in raw message data (RFC 5321 §6.3 loop detection).
pub fn count_received_headers(data: &[u8]) -> usize {
    let needle = b"Received:";
    let mut count = 0;
    // Check start of message
    if data.len() >= needle.len() && data[..needle.len()].eq_ignore_ascii_case(needle) {
        count += 1;
    }
    // Check after each newline
    for i in memchr::memchr_iter(b'\n', data) {
        let start = i + 1;
        if start + needle.len() <= data.len()
            && data[start..start + needle.len()].eq_ignore_ascii_case(needle)
        {
            count += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── dot_unstuff tests ─────────────────────────────────────────────

    #[test]
    fn dot_unstuffing_works() {
        let data = b"Hello\r\n..dot at start\r\nno dot\r\n..another\r\n";
        let result = dot_unstuff(data);
        assert_eq!(result, b"Hello\r\n.dot at start\r\nno dot\r\n.another\r\n");
    }

    #[test]
    fn dot_unstuff_no_change() {
        let data = b"Hello\r\nWorld\r\n";
        let result = dot_unstuff(data);
        assert_eq!(result, data);
    }

    // ── count_received_headers tests ──────────────────────────────────

    #[test]
    fn count_received_zero() {
        let data = b"From: a@b.com\r\nTo: c@d.com\r\n\r\nbody\r\n";
        assert_eq!(count_received_headers(data), 0);
    }

    #[test]
    fn count_received_at_start() {
        let data = b"Received: from mail.example.com\r\nFrom: a@b.com\r\n\r\nbody\r\n";
        assert_eq!(count_received_headers(data), 1);
    }

    #[test]
    fn count_received_multiple() {
        let data = b"Received: from relay1\r\nReceived: from relay2\r\nFrom: a@b.com\r\n\r\n";
        assert_eq!(count_received_headers(data), 2);
    }

    #[test]
    fn count_received_case_insensitive() {
        let data = b"received: from relay1\r\nRECEIVED: from relay2\r\nFrom: a@b.com\r\n\r\n";
        assert_eq!(count_received_headers(data), 2);
    }
}
