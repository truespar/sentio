use std::time::Duration;

use sentio_core::config::LlmConfig;
use sentio_core::error::SentioError;

use crate::scoring::{extract_json, log_token_usage, truncate_to_tokens};
use crate::traits::{
    AutoRespondConfig, AutoResponseResult, ClassifyResult, LlmProvider, MessageCategory, TokenUsage,
};

const CLASSIFICATION_PROMPT: &str = r#"Analyze the email below and respond with ONLY a JSON object (no markdown, no explanation) with these fields:
- "category": one of "conversation", "transactional", "marketing", "billing", "notification", "support", "spam", "threat", "other"
  - conversation: person-to-person emails, discussions, replies, meeting arrangements
  - transactional: automated confirmations, shipping updates, password resets, verification codes
  - marketing: newsletters, promotions, product announcements, campaigns
  - billing: invoices, payment requests, receipts, overdue notices, financial documents
  - notification: system alerts, monitoring, automated reports, calendar reminders, out-of-office replies
  - support: help requests, ticket updates, customer service, complaints
  - spam: unsolicited bulk email, scams
  - threat: phishing, business email compromise, social engineering, malware
  - other: doesn't fit any above category
- "summary": a 1-2 sentence summary of the email content in the SAME LANGUAGE the email was written in

Email envelope:
From: {envelope_from}
To: {envelope_to}

Email content:
{message_text}"#;

fn auto_response_prompt(config: &AutoRespondConfig) -> String {
    let mut prompt = format!(
        r#"You are an email auto-response assistant. Generate a reply to the email below.

Requirements:
- Tone: {}
- Maximum length: {} characters"#,
        config.tone, config.max_length
    );

    if !config.organization.is_empty() {
        prompt.push_str(&format!("\n- Organization: {}", config.organization));
    }
    if !config.custom_instructions.is_empty() {
        prompt.push_str(&format!(
            "\n- Additional instructions: {}",
            config.custom_instructions
        ));
    }

    prompt.push_str(
        r#"

Respond with ONLY a JSON object (no markdown, no explanation) with these fields:
- "subject": the reply subject line
- "body": the reply body text

Email to reply to:
{message_text}"#,
    );

    prompt
}

/// Anthropic Messages API provider.
#[derive(Debug)]
pub struct AnthropicProvider {
    client: reqwest::Client,
    api_key: String,
    model: String,
    temperature: f64,
    max_input_tokens: u32,
}

impl AnthropicProvider {
    pub fn new(config: &LlmConfig) -> Result<Self, SentioError> {
        let api_key = std::env::var(&config.api_key_env).map_err(|_| {
            SentioError::Internal(format!(
                "LLM API key env var '{}' not set",
                config.api_key_env
            ))
        })?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| {
                SentioError::Internal(format!("failed to build Anthropic HTTP client: {e}"))
            })?;

        Ok(Self {
            client,
            api_key,
            model: config.model.clone(),
            temperature: config.temperature,
            max_input_tokens: config.max_input_tokens,
        })
    }

    async fn call_api(
        &self,
        system: &str,
        user_content: &str,
        base_url: Option<&str>,
    ) -> Result<(String, TokenUsage), SentioError> {
        let url = format!(
            "{}/v1/messages",
            base_url.unwrap_or("https://api.anthropic.com")
        );

        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": 1024,
            "temperature": self.temperature,
            "system": system,
            "messages": [
                {
                    "role": "user",
                    "content": user_content
                }
            ]
        });

        let resp = self
            .client
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| SentioError::Internal(format!("Anthropic API request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(SentioError::Internal(format!(
                "Anthropic API returned HTTP {status}: {body}"
            )));
        }

        let resp_body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SentioError::Internal(format!("Anthropic response parse failed: {e}")))?;

        let text = resp_body["content"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|c| c["text"].as_str())
            .ok_or_else(|| {
                SentioError::Internal("Anthropic response missing content[0].text".to_string())
            })?
            .to_string();

        let usage = TokenUsage {
            prompt_tokens: resp_body["usage"]["input_tokens"].as_u64().unwrap_or(0) as u32,
            completion_tokens: resp_body["usage"]["output_tokens"].as_u64().unwrap_or(0) as u32,
        };

        Ok((text, usage))
    }
}

impl LlmProvider for AnthropicProvider {
    async fn classify(
        &self,
        message_text: &str,
        envelope_from: &str,
        envelope_to: &str,
    ) -> Result<ClassifyResult, SentioError> {
        let truncated = truncate_to_tokens(message_text, self.max_input_tokens);
        let user_content = CLASSIFICATION_PROMPT
            .replace("{envelope_from}", envelope_from)
            .replace("{envelope_to}", envelope_to)
            .replace("{message_text}", truncated);

        let (raw_text, usage) = self
            .call_api(
                "You are an email classification and summarization system for a business email platform. Respond only with valid JSON.",
                &user_content,
                None,
            )
            .await?;

        log_token_usage("anthropic", &self.model, "classify", &usage);

        let json_str = extract_json(&raw_text);
        let parsed: serde_json::Value = serde_json::from_str(json_str).map_err(|e| {
            SentioError::Internal(format!(
                "failed to parse Anthropic classification JSON: {e}"
            ))
        })?;

        let category: MessageCategory =
            serde_json::from_value(parsed["category"].clone()).unwrap_or(MessageCategory::Other);

        let summary = parsed["summary"].as_str().unwrap_or("").to_string();

        Ok(ClassifyResult {
            category,
            score_delta: 0.0,
            summary,
            token_usage: usage,
        })
    }

    async fn generate_auto_response(
        &self,
        message_text: &str,
        config: &AutoRespondConfig,
    ) -> Result<AutoResponseResult, SentioError> {
        let truncated = truncate_to_tokens(message_text, self.max_input_tokens);
        let prompt_template = auto_response_prompt(config);
        let user_content = prompt_template.replace("{message_text}", truncated);

        let (raw_text, usage) = self
            .call_api(
                "You are an email auto-response assistant. Respond only with valid JSON.",
                &user_content,
                None,
            )
            .await?;

        log_token_usage("anthropic", &self.model, "auto_response", &usage);

        let json_str = extract_json(&raw_text);
        let parsed: serde_json::Value = serde_json::from_str(json_str).map_err(|e| {
            SentioError::Internal(format!("failed to parse Anthropic auto-response JSON: {e}"))
        })?;

        Ok(AutoResponseResult {
            subject: parsed["subject"]
                .as_str()
                .unwrap_or("Re: your message")
                .to_string(),
            body: parsed["body"].as_str().unwrap_or("").to_string(),
            token_usage: usage,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> LlmConfig {
        LlmConfig {
            model: "claude-sonnet-5".to_string(),
            temperature: 0.3,
            max_input_tokens: 2000,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn anthropic_classify_success() {
        let server = wiremock::MockServer::start().await;

        let response_body = serde_json::json!({
            "content": [
                {
                    "type": "text",
                    "text": "{\"category\": \"spam\", \"summary\": \"Unsolicited bulk email advertising cheap products\"}"
                }
            ],
            "usage": {
                "input_tokens": 150,
                "output_tokens": 30
            }
        });

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/messages"))
            .and(wiremock::matchers::header("x-api-key", "test-key"))
            .and(wiremock::matchers::header(
                "anthropic-version",
                "2023-06-01",
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&server)
            .await;

        let config = test_config();
        let provider = AnthropicProvider {
            client: reqwest::Client::new(),
            api_key: "test-key".to_string(),
            model: config.model.clone(),
            temperature: config.temperature,
            max_input_tokens: config.max_input_tokens,
        };

        // Override the call_api to use our test server
        let truncated = truncate_to_tokens("Buy cheap stuff now!", provider.max_input_tokens);
        let user_content = CLASSIFICATION_PROMPT
            .replace("{envelope_from}", "spammer@example.com")
            .replace("{envelope_to}", "victim@example.com")
            .replace("{message_text}", truncated);

        let (raw_text, usage) = provider
            .call_api(
                "You are an email classification system. Respond only with valid JSON.",
                &user_content,
                Some(&server.uri()),
            )
            .await
            .unwrap();

        let json_str = extract_json(&raw_text);
        let parsed: serde_json::Value = serde_json::from_str(json_str).unwrap();

        assert_eq!(parsed["category"], "spam");
        assert_eq!(
            parsed["summary"],
            "Unsolicited bulk email advertising cheap products"
        );
        assert_eq!(usage.prompt_tokens, 150);
        assert_eq!(usage.completion_tokens, 30);
    }

    #[tokio::test]
    async fn anthropic_http_error() {
        let server = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/messages"))
            .respond_with(wiremock::ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(&server)
            .await;

        let provider = AnthropicProvider {
            client: reqwest::Client::new(),
            api_key: "test-key".to_string(),
            model: "test-model".to_string(),
            temperature: 0.3,
            max_input_tokens: 2000,
        };

        let result = provider
            .call_api("system", "user", Some(&server.uri()))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("500"));
    }

    #[tokio::test]
    async fn anthropic_malformed_response() {
        let server = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/messages"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"content": []})),
            )
            .mount(&server)
            .await;

        let provider = AnthropicProvider {
            client: reqwest::Client::new(),
            api_key: "test-key".to_string(),
            model: "test-model".to_string(),
            temperature: 0.3,
            max_input_tokens: 2000,
        };

        let result = provider
            .call_api("system", "user", Some(&server.uri()))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("missing content[0].text"));
    }

    #[tokio::test]
    async fn anthropic_auto_response_success() {
        let server = wiremock::MockServer::start().await;

        let response_body = serde_json::json!({
            "content": [
                {
                    "type": "text",
                    "text": "{\"subject\": \"Re: Your inquiry\", \"body\": \"Thank you for reaching out.\"}"
                }
            ],
            "usage": {
                "input_tokens": 200,
                "output_tokens": 50
            }
        });

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/messages"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&server)
            .await;

        let provider = AnthropicProvider {
            client: reqwest::Client::new(),
            api_key: "test-key".to_string(),
            model: "test-model".to_string(),
            temperature: 0.3,
            max_input_tokens: 2000,
        };

        let config = AutoRespondConfig::default();
        let prompt_template = auto_response_prompt(&config);
        let user_content = prompt_template.replace("{message_text}", "Hello, I need help.");

        let (raw_text, usage) = provider
            .call_api(
                "You are an email auto-response assistant. Respond only with valid JSON.",
                &user_content,
                Some(&server.uri()),
            )
            .await
            .unwrap();

        let json_str = extract_json(&raw_text);
        let parsed: serde_json::Value = serde_json::from_str(json_str).unwrap();

        assert_eq!(parsed["subject"], "Re: Your inquiry");
        assert_eq!(parsed["body"], "Thank you for reaching out.");
        assert_eq!(usage.prompt_tokens, 200);
        assert_eq!(usage.completion_tokens, 50);
    }
}
