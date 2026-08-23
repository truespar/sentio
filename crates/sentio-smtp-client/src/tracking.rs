use base64::Engine;
use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────────────────────────────────────
// Token generation
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct OpenToken {
    m: String,
    t: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ClickToken {
    m: String,
    t: String,
    u: String,
}

pub fn generate_open_token(message_id: &str, tenant_id: &str) -> String {
    let token = OpenToken {
        m: message_id.to_string(),
        t: tenant_id.to_string(),
    };
    let json = serde_json::to_vec(&token).unwrap_or_default();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&json)
}

pub fn generate_click_token(message_id: &str, tenant_id: &str, url: &str) -> String {
    let token = ClickToken {
        m: message_id.to_string(),
        t: tenant_id.to_string(),
        u: url.to_string(),
    };
    let json = serde_json::to_vec(&token).unwrap_or_default();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&json)
}

// ──────────────────────────────────────────────────────────────────────────────
// HTML rewriting
// ──────────────────────────────────────────────────────────────────────────────

/// Rewrite HTML to inject tracking pixel and wrap links.
///
/// - `track_opens`: injects a 1x1 transparent tracking pixel before `</body>`
/// - `track_clicks`: rewrites `href="..."` attributes to redirect through the
///   tracking endpoint, skipping `mailto:`, `tel:`, and already-tracked URLs
pub fn rewrite_html_tracking(
    html: &str,
    api_base_url: &str,
    message_id: &str,
    tenant_id: &str,
    track_opens: bool,
    track_clicks: bool,
) -> String {
    let mut result = html.to_string();

    // Rewrite click links first (before open pixel, to avoid tracking our own pixel)
    if track_clicks {
        result = rewrite_links(&result, api_base_url, message_id, tenant_id);
    }

    // Inject open tracking pixel
    if track_opens {
        let token = generate_open_token(message_id, tenant_id);
        let pixel = format!(
            r#"<img src="{api_base_url}/track/open/{token}" width="1" height="1" style="display:none" alt="" />"#
        );

        // Try to insert before </body>, otherwise append
        if let Some(pos) = result.to_lowercase().rfind("</body>") {
            result.insert_str(pos, &pixel);
        } else {
            result.push_str(&pixel);
        }
    }

    result
}

fn rewrite_links(html: &str, api_base_url: &str, message_id: &str, tenant_id: &str) -> String {
    let re = regex::Regex::new(r#"href\s*=\s*"([^"]+)""#).unwrap();

    re.replace_all(html, |caps: &regex::Captures| {
        let url = &caps[1];
        let url_lower = url.to_lowercase();

        // Skip non-http links and already-tracked URLs
        if url_lower.starts_with("mailto:")
            || url_lower.starts_with("tel:")
            || url_lower.starts_with('#')
            || url_lower.contains("/track/click/")
        {
            return caps[0].to_string();
        }

        let token = generate_click_token(message_id, tenant_id, url);
        format!(r#"href="{api_base_url}/track/click/{token}""#)
    })
    .to_string()
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const MSG_ID: &str = "00000000-0000-0000-0000-000000000001";
    const TENANT_ID: &str = "00000000-0000-0000-0000-000000000002";
    const BASE_URL: &str = "https://mail.example.com";

    #[test]
    fn test_generate_tokens_roundtrip() {
        let open_token = generate_open_token(MSG_ID, TENANT_ID);
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&open_token)
            .unwrap();
        let parsed: OpenToken = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(parsed.m, MSG_ID);
        assert_eq!(parsed.t, TENANT_ID);

        let click_token = generate_click_token(MSG_ID, TENANT_ID, "https://example.com");
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&click_token)
            .unwrap();
        let parsed: ClickToken = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(parsed.m, MSG_ID);
        assert_eq!(parsed.u, "https://example.com");
    }

    #[test]
    fn test_rewrite_injects_pixel() {
        let html = "<html><body><p>Hello</p></body></html>";
        let result = rewrite_html_tracking(html, BASE_URL, MSG_ID, TENANT_ID, true, false);

        assert!(result.contains("/track/open/"));
        assert!(result.contains(r#"width="1" height="1""#));
        // Pixel should be before </body>
        let pixel_pos = result.find("/track/open/").unwrap();
        let body_pos = result.to_lowercase().rfind("</body>").unwrap();
        assert!(pixel_pos < body_pos);
    }

    #[test]
    fn test_rewrite_wraps_links() {
        let html = r#"<a href="https://example.com/page">Click</a>"#;
        let result = rewrite_html_tracking(html, BASE_URL, MSG_ID, TENANT_ID, false, true);

        assert!(result.contains("/track/click/"));
        assert!(!result.contains("https://example.com/page\""));
    }

    #[test]
    fn test_rewrite_skips_mailto() {
        let html = r#"<a href="mailto:user@example.com">Email</a>"#;
        let result = rewrite_html_tracking(html, BASE_URL, MSG_ID, TENANT_ID, false, true);

        assert!(result.contains("mailto:user@example.com"));
        assert!(!result.contains("/track/click/"));
    }

    #[test]
    fn test_rewrite_skips_tel() {
        let html = r#"<a href="tel:+1234567890">Call</a>"#;
        let result = rewrite_html_tracking(html, BASE_URL, MSG_ID, TENANT_ID, false, true);

        assert!(result.contains("tel:+1234567890"));
        assert!(!result.contains("/track/click/"));
    }

    #[test]
    fn test_rewrite_no_html_body() {
        // Plain text - no </body> tag, pixel appended at end
        let text = "Hello world";
        let result = rewrite_html_tracking(text, BASE_URL, MSG_ID, TENANT_ID, true, false);
        assert!(result.starts_with("Hello world"));
        assert!(result.contains("/track/open/"));
    }

    #[test]
    fn test_rewrite_both_opens_and_clicks() {
        let html = r#"<html><body><a href="https://example.com">Link</a></body></html>"#;
        let result = rewrite_html_tracking(html, BASE_URL, MSG_ID, TENANT_ID, true, true);

        assert!(result.contains("/track/open/"));
        assert!(result.contains("/track/click/"));
    }
}
