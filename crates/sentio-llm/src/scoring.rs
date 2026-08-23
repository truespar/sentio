use crate::traits::TokenUsage;

/// Approximate token count using 4 chars ≈ 1 token heuristic.
pub fn estimate_tokens(text: &str) -> u32 {
    (text.len() as f64 / 4.0).ceil() as u32
}

/// Truncate text to approximately `max_tokens` tokens (4 chars ≈ 1 token).
///
/// Ensures the cut point falls on a valid UTF-8 char boundary.
pub fn truncate_to_tokens(text: &str, max_tokens: u32) -> &str {
    let max_chars = max_tokens as usize * 4;
    if text.len() <= max_chars {
        return text;
    }

    // Find the nearest char boundary at or before max_chars
    let mut end = max_chars;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Extract JSON from a response that may be wrapped in markdown code fences.
///
/// Handles:
/// - Raw JSON: `{"key": "value"}`
/// - Fenced: `` ```json\n{"key": "value"}\n``` ``
/// - Fenced without lang: `` ```\n{"key": "value"}\n``` ``
pub fn extract_json(text: &str) -> &str {
    let trimmed = text.trim();

    // Strip markdown code fences if present
    if let Some(rest) = trimmed.strip_prefix("```") {
        // Skip optional language tag on the first line
        let rest = if let Some(newline_pos) = rest.find('\n') {
            &rest[newline_pos + 1..]
        } else {
            rest
        };
        // Strip trailing fence
        let rest = rest.trim_end();
        let rest = rest.strip_suffix("```").unwrap_or(rest);
        return rest.trim();
    }

    trimmed
}

/// Log token usage for an LLM call.
pub fn log_token_usage(provider: &str, model: &str, operation: &str, usage: &TokenUsage) {
    tracing::info!(
        provider = provider,
        model = model,
        operation = operation,
        prompt_tokens = usage.prompt_tokens,
        completion_tokens = usage.completion_tokens,
        total_tokens = usage.total(),
        "LLM token usage"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_tokens_basic() {
        assert_eq!(estimate_tokens(""), 0);
        assert_eq!(estimate_tokens("abcd"), 1);
        assert_eq!(estimate_tokens("abcde"), 2);
        assert_eq!(estimate_tokens("abcdefgh"), 2);
    }

    #[test]
    fn truncate_to_tokens_short_text() {
        let text = "hello";
        assert_eq!(truncate_to_tokens(text, 10), "hello");
    }

    #[test]
    fn truncate_to_tokens_exact() {
        let text = "abcdefgh"; // 8 chars = 2 tokens
        assert_eq!(truncate_to_tokens(text, 2), "abcdefgh");
    }

    #[test]
    fn truncate_to_tokens_cuts() {
        let text = "abcdefghij"; // 10 chars
        let result = truncate_to_tokens(text, 2); // 2 tokens = 8 chars
        assert_eq!(result, "abcdefgh");
    }

    #[test]
    fn truncate_to_tokens_multibyte_safe() {
        // "café" is 5 bytes (é is 2 bytes in UTF-8)
        let text = "café world";
        let result = truncate_to_tokens(text, 1); // 1 token = 4 chars max
                                                  // Should not split in the middle of é
        assert!(result.is_char_boundary(result.len()));
        // "caf" is 3 bytes, "café" is 5 bytes - so we get "caf" (boundary before é)
        // Actually "café" = c(1) a(1) f(1) é(2) = 5 bytes total, 4 byte limit
        // byte 4 is in the middle of é, so we back up to byte 3
        assert_eq!(result, "caf");
    }

    #[test]
    fn truncate_to_tokens_cjk_safe() {
        // Each CJK character is 3 bytes in UTF-8
        let text = "你好世界"; // 12 bytes
        let result = truncate_to_tokens(text, 1); // 4 bytes max
                                                  // 你 = 3 bytes, 好 starts at byte 3 and is 3 bytes
                                                  // at byte 4 we're inside 好, so we back up to byte 3
        assert_eq!(result, "你");
    }

    #[test]
    fn extract_json_raw() {
        let input = r#"{"category": "spam", "score_delta": 3.0}"#;
        assert_eq!(extract_json(input), input);
    }

    #[test]
    fn extract_json_fenced_with_lang() {
        let input = "```json\n{\"category\": \"spam\"}\n```";
        assert_eq!(extract_json(input), "{\"category\": \"spam\"}");
    }

    #[test]
    fn extract_json_fenced_no_lang() {
        let input = "```\n{\"category\": \"spam\"}\n```";
        assert_eq!(extract_json(input), "{\"category\": \"spam\"}");
    }

    #[test]
    fn extract_json_with_whitespace() {
        let input = "  \n```json\n{\"key\": \"value\"}\n```\n  ";
        assert_eq!(extract_json(input), "{\"key\": \"value\"}");
    }

    #[test]
    fn token_usage_total() {
        let usage = TokenUsage {
            prompt_tokens: 100,
            completion_tokens: 50,
        };
        assert_eq!(usage.total(), 150);
    }
}
