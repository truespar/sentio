use std::sync::OnceLock;

use regex::Regex;

use sentio_core::traits::SpamRule;

/// Content heuristic analysis of email body.
pub struct HeuristicScorer;

static PHISHING_PHRASES_RE: OnceLock<Regex> = OnceLock::new();
static HTML_HREF_RE: OnceLock<Regex> = OnceLock::new();
static SHORT_URL_RE: OnceLock<Regex> = OnceLock::new();

fn phishing_regex() -> &'static Regex {
    PHISHING_PHRASES_RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:verify your account|confirm your identity|update your payment|suspend(?:ed)? your account|unusual (?:sign[- ]in|activity)|click here immediately|act now|limited time offer|you(?:'ve| have) won|congratulations.*winner|claim your (?:prize|reward)|urgent.*action required)"
        ).unwrap()
    })
}

fn html_href_regex() -> &'static Regex {
    HTML_HREF_RE.get_or_init(|| {
        Regex::new(r#"(?i)<a\s[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([^<]*)</a>"#).unwrap()
    })
}

fn short_url_regex() -> &'static Regex {
    SHORT_URL_RE.get_or_init(|| {
        Regex::new(
            r"(?i)https?://(?:bit\.ly|t\.co|goo\.gl|tinyurl\.com|is\.gd|buff\.ly|ow\.ly|rb\.gy)/",
        )
        .unwrap()
    })
}

impl HeuristicScorer {
    pub fn analyze(raw_message: &[u8]) -> Vec<SpamRule> {
        let body = extract_body(raw_message);
        let mut rules = Vec::new();

        if body.is_empty() {
            rules.push(SpamRule {
                name: "BODY_EMPTY".into(),
                score: 1.0,
                description: "Message body is empty".into(),
            });
            return rules;
        }

        // HTML only, no text part (simple heuristic: contains HTML tags but no plain text alternative)
        let has_html = body.contains("<html")
            || body.contains("<HTML")
            || body.contains("<body")
            || body.contains("<BODY");
        let has_plain_text_indicator = body.contains("Content-Type: text/plain");
        if has_html && !has_plain_text_indicator {
            rules.push(SpamRule {
                name: "HTML_ONLY_NO_TEXT".into(),
                score: 2.0,
                description: "Message contains HTML without a text/plain alternative".into(),
            });
        }

        // Body all caps percentage
        let alpha_chars: Vec<char> = body.chars().filter(|c| c.is_alphabetic()).collect();
        if alpha_chars.len() >= 20 {
            let upper_count = alpha_chars.iter().filter(|c| c.is_uppercase()).count();
            let upper_pct = upper_count as f64 / alpha_chars.len() as f64;
            if upper_pct > 0.8 {
                rules.push(SpamRule {
                    name: "BODY_ALL_CAPS_PCT".into(),
                    score: 1.5,
                    description: format!("Body is {:.0}% uppercase", upper_pct * 100.0),
                });
            }
        }

        // Phishing phrases
        if phishing_regex().is_match(&body) {
            rules.push(SpamRule {
                name: "PHISHING_PHRASES".into(),
                score: 2.5,
                description: "Body contains common phishing phrases".into(),
            });
        }

        // Excessive exclamation marks
        let excl_count = body.chars().filter(|&c| c == '!').count();
        if excl_count > 5 {
            rules.push(SpamRule {
                name: "EXCESSIVE_EXCLAMATION".into(),
                score: 1.0,
                description: format!("Body contains {excl_count} exclamation marks"),
            });
        }

        // URL/anchor text mismatch (phishing indicator)
        for cap in html_href_regex().captures_iter(&body) {
            let href = cap.get(1).map_or("", |m| m.as_str());
            let anchor_text = cap.get(2).map_or("", |m| m.as_str()).trim();

            // If anchor text looks like a URL but doesn't match the href domain
            if anchor_text.starts_with("http://") || anchor_text.starts_with("https://") {
                let href_domain = extract_domain(href);
                let anchor_domain = extract_domain(anchor_text);
                if !href_domain.is_empty()
                    && !anchor_domain.is_empty()
                    && href_domain != anchor_domain
                {
                    rules.push(SpamRule {
                        name: "URL_MISMATCH_ANCHOR".into(),
                        score: 3.0,
                        description: "Link text shows different URL than actual href".into(),
                    });
                    break; // One match is enough
                }
            }
        }

        // Short URL detection
        if short_url_regex().is_match(&body) {
            rules.push(SpamRule {
                name: "SHORT_URL".into(),
                score: 1.0,
                description: "Body contains URL shortener links".into(),
            });
        }

        rules
    }
}

/// Extract the body from a raw message (everything after the first blank line).
fn extract_body(raw: &[u8]) -> String {
    let raw_str = String::from_utf8_lossy(raw);
    if let Some(pos) = raw_str.find("\r\n\r\n") {
        raw_str[pos + 4..].to_string()
    } else if let Some(pos) = raw_str.find("\n\n") {
        raw_str[pos + 2..].to_string()
    } else {
        String::new()
    }
}

/// Extract the domain from a URL string.
fn extract_domain(url_str: &str) -> String {
    url::Url::parse(url_str)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_message(headers: &str, body: &str) -> Vec<u8> {
        format!("{headers}\r\n\r\n{body}").into_bytes()
    }

    #[test]
    fn empty_body_detected() {
        let msg = b"From: test@example.com\r\n\r\n".to_vec();
        let rules = HeuristicScorer::analyze(&msg);
        assert!(rules.iter().any(|r| r.name == "BODY_EMPTY"));
    }

    #[test]
    fn html_only_detected() {
        let msg = make_message(
            "From: test@example.com",
            "<html><body><p>Buy now!</p></body></html>",
        );
        let rules = HeuristicScorer::analyze(&msg);
        assert!(rules.iter().any(|r| r.name == "HTML_ONLY_NO_TEXT"));
    }

    #[test]
    fn body_all_caps_detected() {
        let msg = make_message(
            "From: test@example.com",
            "THIS IS ALL CAPS AND IT GOES ON AND ON FOR A WHILE",
        );
        let rules = HeuristicScorer::analyze(&msg);
        assert!(rules.iter().any(|r| r.name == "BODY_ALL_CAPS_PCT"));
    }

    #[test]
    fn body_normal_case_not_flagged() {
        let msg = make_message(
            "From: test@example.com",
            "This is a normal message with mixed case text that should not trigger caps detection.",
        );
        let rules = HeuristicScorer::analyze(&msg);
        assert!(!rules.iter().any(|r| r.name == "BODY_ALL_CAPS_PCT"));
    }

    #[test]
    fn phishing_phrases_detected() {
        let msg = make_message(
            "From: test@example.com",
            "Please verify your account immediately to avoid suspension.",
        );
        let rules = HeuristicScorer::analyze(&msg);
        assert!(rules.iter().any(|r| r.name == "PHISHING_PHRASES"));
    }

    #[test]
    fn excessive_exclamation_detected() {
        let msg = make_message(
            "From: test@example.com",
            "Amazing! Great! Wonderful! Super! Fantastic! Awesome!",
        );
        let rules = HeuristicScorer::analyze(&msg);
        assert!(rules.iter().any(|r| r.name == "EXCESSIVE_EXCLAMATION"));
    }

    #[test]
    fn url_mismatch_anchor_detected() {
        let msg = make_message(
            "From: test@example.com",
            r#"<a href="https://evil.com/steal">https://yourbank.com/login</a>"#,
        );
        let rules = HeuristicScorer::analyze(&msg);
        assert!(rules.iter().any(|r| r.name == "URL_MISMATCH_ANCHOR"));
    }

    #[test]
    fn matching_url_anchor_not_flagged() {
        let msg = make_message(
            "From: test@example.com",
            r#"<a href="https://example.com/page">https://example.com/page</a>"#,
        );
        let rules = HeuristicScorer::analyze(&msg);
        assert!(!rules.iter().any(|r| r.name == "URL_MISMATCH_ANCHOR"));
    }

    #[test]
    fn short_url_detected() {
        let msg = make_message(
            "From: test@example.com",
            "Check this out: https://bit.ly/abc123",
        );
        let rules = HeuristicScorer::analyze(&msg);
        assert!(rules.iter().any(|r| r.name == "SHORT_URL"));
    }

    #[test]
    fn normal_url_not_flagged_as_short() {
        let msg = make_message(
            "From: test@example.com",
            "Visit https://www.example.com/article for more info.",
        );
        let rules = HeuristicScorer::analyze(&msg);
        assert!(!rules.iter().any(|r| r.name == "SHORT_URL"));
    }

    #[test]
    fn clean_body_no_rules() {
        let msg = make_message(
            "From: test@example.com",
            "Hello, just wanted to follow up on our meeting yesterday. Let me know your thoughts.",
        );
        let rules = HeuristicScorer::analyze(&msg);
        assert!(rules.is_empty(), "expected no rules, got: {rules:?}");
    }
}
