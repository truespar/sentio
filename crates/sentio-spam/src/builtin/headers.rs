use sentio_core::traits::SpamRule;

/// Stateless analysis of raw message headers.
///
/// Extracts the header block (up to the first `\r\n\r\n`) and applies simple
/// string-matching rules. Each matched rule contributes a positive or negative
/// score.
pub struct HeaderAnalyzer;

impl HeaderAnalyzer {
    pub fn analyze(raw_message: &[u8]) -> Vec<SpamRule> {
        let headers = extract_headers(raw_message);
        let headers_lower = headers.to_ascii_lowercase();
        let mut rules = Vec::new();

        // Missing headers
        if !headers_lower.contains("\nfrom:") && !headers_lower.starts_with("from:") {
            rules.push(SpamRule {
                name: "MISSING_FROM".into(),
                score: 2.0,
                description: "Message has no From header".into(),
            });
        }

        if !headers_lower.contains("\ndate:") && !headers_lower.starts_with("date:") {
            rules.push(SpamRule {
                name: "MISSING_DATE".into(),
                score: 1.5,
                description: "Message has no Date header".into(),
            });
        }

        if !headers_lower.contains("\nmessage-id:") && !headers_lower.starts_with("message-id:") {
            rules.push(SpamRule {
                name: "MISSING_MESSAGE_ID".into(),
                score: 1.5,
                description: "Message has no Message-ID header".into(),
            });
        }

        if !headers_lower.contains("\nsubject:") && !headers_lower.starts_with("subject:") {
            rules.push(SpamRule {
                name: "MISSING_SUBJECT".into(),
                score: 1.0,
                description: "Message has no Subject header".into(),
            });
        }

        // Subject all caps check
        if let Some(subject) = extract_header_value(&headers, "subject") {
            let alpha_chars: Vec<char> = subject.chars().filter(|c| c.is_alphabetic()).collect();
            if alpha_chars.len() >= 5 && alpha_chars.iter().all(|c| c.is_uppercase()) {
                rules.push(SpamRule {
                    name: "SUBJECT_ALL_CAPS".into(),
                    score: 1.5,
                    description: "Subject is entirely uppercase".into(),
                });
            }
        }

        // Too many Received headers (potential forwarding chain abuse)
        let received_count = headers_lower
            .lines()
            .filter(|line| line.starts_with("received:"))
            .count();
        if received_count > 10 {
            rules.push(SpamRule {
                name: "TOO_MANY_RECEIVED".into(),
                score: 2.0,
                description: format!("Excessive Received headers ({received_count})"),
            });
        }

        // Bulk mailer indicators
        if let Some(x_mailer) = extract_header_value(&headers, "x-mailer") {
            let x_mailer_lower = x_mailer.to_ascii_lowercase();
            if x_mailer_lower.contains("bulk")
                || x_mailer_lower.contains("mass")
                || x_mailer_lower.contains("phpmailer")
            {
                rules.push(SpamRule {
                    name: "X_MAILER_BULK".into(),
                    score: 1.0,
                    description: "X-Mailer indicates bulk sending software".into(),
                });
            }
        }

        // Positive signals (reduce score)
        if headers_lower.contains("\nlist-unsubscribe:")
            || headers_lower.starts_with("list-unsubscribe:")
        {
            rules.push(SpamRule {
                name: "LIST_UNSUBSCRIBE_PRESENT".into(),
                score: -1.0,
                description: "List-Unsubscribe header present".into(),
            });
        }

        if let Some(precedence) = extract_header_value(&headers, "precedence") {
            if precedence.trim().eq_ignore_ascii_case("bulk")
                || precedence.trim().eq_ignore_ascii_case("list")
            {
                rules.push(SpamRule {
                    name: "PRECEDENCE_BULK".into(),
                    score: -0.5,
                    description: "Precedence header indicates bulk/list mail".into(),
                });
            }
        }

        rules
    }
}

/// Extract the header block from a raw message (everything before `\r\n\r\n`).
fn extract_headers(raw: &[u8]) -> String {
    let raw_str = String::from_utf8_lossy(raw);
    if let Some(pos) = raw_str.find("\r\n\r\n") {
        raw_str[..pos].to_string()
    } else if let Some(pos) = raw_str.find("\n\n") {
        raw_str[..pos].to_string()
    } else {
        raw_str.to_string()
    }
}

/// Extract the first value of a header by name (case-insensitive).
fn extract_header_value(headers: &str, name: &str) -> Option<String> {
    let name_lower = name.to_ascii_lowercase();
    let prefix = format!("{name_lower}:");

    for line in headers.lines() {
        let line_lower = line.to_ascii_lowercase();
        if let Some(rest) = line_lower.strip_prefix(&prefix) {
            // Get the original-case value
            let value = &line[prefix.len()..];
            let _ = rest; // used for prefix matching only
            return Some(value.trim().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_message(headers: &str, body: &str) -> Vec<u8> {
        format!("{headers}\r\n\r\n{body}").into_bytes()
    }

    #[test]
    fn complete_headers_no_negative_rules() {
        let msg = make_message(
            "From: sender@example.com\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\nMessage-ID: <abc@example.com>\r\nSubject: Hello",
            "body",
        );
        let rules = HeaderAnalyzer::analyze(&msg);
        let missing_rules: Vec<_> = rules
            .iter()
            .filter(|r| r.name.starts_with("MISSING"))
            .collect();
        assert!(missing_rules.is_empty(), "got: {missing_rules:?}");
    }

    #[test]
    fn missing_from_detected() {
        let msg = make_message(
            "Date: Mon, 1 Jan 2024 00:00:00 +0000\r\nSubject: test",
            "body",
        );
        let rules = HeaderAnalyzer::analyze(&msg);
        assert!(rules.iter().any(|r| r.name == "MISSING_FROM"));
        assert!(rules.iter().any(|r| r.name == "MISSING_MESSAGE_ID"));
    }

    #[test]
    fn missing_date_detected() {
        let msg = make_message("From: sender@example.com\r\nSubject: test", "body");
        let rules = HeaderAnalyzer::analyze(&msg);
        assert!(rules.iter().any(|r| r.name == "MISSING_DATE"));
    }

    #[test]
    fn missing_subject_detected() {
        let msg = make_message(
            "From: sender@example.com\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000",
            "body",
        );
        let rules = HeaderAnalyzer::analyze(&msg);
        assert!(rules.iter().any(|r| r.name == "MISSING_SUBJECT"));
    }

    #[test]
    fn subject_all_caps_detected() {
        let msg = make_message(
            "From: sender@example.com\r\nSubject: FREE MONEY NOW BUY",
            "body",
        );
        let rules = HeaderAnalyzer::analyze(&msg);
        assert!(rules.iter().any(|r| r.name == "SUBJECT_ALL_CAPS"));
    }

    #[test]
    fn subject_mixed_case_not_flagged() {
        let msg = make_message("From: sender@example.com\r\nSubject: Hello World", "body");
        let rules = HeaderAnalyzer::analyze(&msg);
        assert!(!rules.iter().any(|r| r.name == "SUBJECT_ALL_CAPS"));
    }

    #[test]
    fn too_many_received_detected() {
        let received_headers: String = (0..12)
            .map(|i| format!("Received: from server{i}.example.com"))
            .collect::<Vec<_>>()
            .join("\r\n");
        let msg = make_message(
            &format!("{received_headers}\r\nFrom: sender@example.com"),
            "body",
        );
        let rules = HeaderAnalyzer::analyze(&msg);
        assert!(rules.iter().any(|r| r.name == "TOO_MANY_RECEIVED"));
    }

    #[test]
    fn x_mailer_bulk_detected() {
        let msg = make_message(
            "From: sender@example.com\r\nX-Mailer: PHPMailer 6.5",
            "body",
        );
        let rules = HeaderAnalyzer::analyze(&msg);
        assert!(rules.iter().any(|r| r.name == "X_MAILER_BULK"));
    }

    #[test]
    fn list_unsubscribe_reduces_score() {
        let msg = make_message(
            "From: sender@example.com\r\nList-Unsubscribe: <mailto:unsub@example.com>",
            "body",
        );
        let rules = HeaderAnalyzer::analyze(&msg);
        let rule = rules.iter().find(|r| r.name == "LIST_UNSUBSCRIBE_PRESENT");
        assert!(rule.is_some());
        assert!(rule.unwrap().score < 0.0);
    }

    #[test]
    fn precedence_bulk_reduces_score() {
        let msg = make_message("From: sender@example.com\r\nPrecedence: bulk", "body");
        let rules = HeaderAnalyzer::analyze(&msg);
        let rule = rules.iter().find(|r| r.name == "PRECEDENCE_BULK");
        assert!(rule.is_some());
        assert!(rule.unwrap().score < 0.0);
    }
}
