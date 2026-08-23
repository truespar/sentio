use std::time::Duration;

use sentio_core::config::LlmConfig;
use sentio_core::error::SentioError;

use crate::scoring::{extract_json, log_token_usage, truncate_to_tokens};
use crate::traits::{
    AutoRespondConfig, AutoResponseResult, ClassifyResult, LlmProvider, MessageCategory, TokenUsage,
};

const CLASSIFICATION_SYSTEM: &str =
    "You are an email classification and summarization system for a business email platform. Respond only with valid JSON.";

const CLASSIFICATION_USER: &str = r#"Analyze the email below and respond with ONLY a JSON object (no markdown, no explanation) with these fields:
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

fn auto_response_system() -> &'static str {
    "You are an email auto-response assistant. Respond only with valid JSON."
}

fn auto_response_user(config: &AutoRespondConfig) -> String {
    let mut prompt = format!(
        r#"Generate a reply to the email below.

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

/// Which OpenAI-compatible HTTP API to call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApiKind {
    /// Legacy `/v1/chat/completions` - request `{messages:[...]}`,
    /// response `choices[].message.content`.
    ChatCompletions,
    /// 2025 `/v1/responses` - request `{instructions, input,
    /// max_output_tokens}`, response `output[].content[].text` with
    /// reasoning blocks separated from message blocks.
    Responses,
}

impl ApiKind {
    fn from_config(s: &str) -> Result<Self, SentioError> {
        match s {
            "chat_completions" => Ok(Self::ChatCompletions),
            "responses" => Ok(Self::Responses),
            other => Err(SentioError::Internal(format!(
                "invalid openai_api value '{other}' (expected 'chat_completions' or 'responses')"
            ))),
        }
    }
}

/// OpenAI-compatible HTTP provider. Supports both the legacy Chat
/// Completions API and the 2025 Responses API; selected via
/// [`LlmConfig::openai_api`].
#[derive(Debug)]
pub struct OpenAiProvider {
    client: reqwest::Client,
    api_key: String,
    model: String,
    temperature: f64,
    max_input_tokens: u32,
    base_url: Option<String>,
    api: ApiKind,
}

impl OpenAiProvider {
    pub fn new(config: &LlmConfig) -> Result<Self, SentioError> {
        let api_key = if config.api_key_env.is_empty() {
            String::new()
        } else {
            std::env::var(&config.api_key_env).map_err(|_| {
                SentioError::Internal(format!(
                    "LLM API key env var '{}' not set",
                    config.api_key_env
                ))
            })?
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| {
                SentioError::Internal(format!("failed to build OpenAI HTTP client: {e}"))
            })?;

        Ok(Self {
            client,
            api_key,
            model: config.model.clone(),
            temperature: config.temperature,
            max_input_tokens: config.max_input_tokens,
            base_url: config.base_url.clone(),
            api: ApiKind::from_config(&config.openai_api)?,
        })
    }

    async fn call_api(
        &self,
        system: &str,
        user_content: &str,
        base_url: Option<&str>,
    ) -> Result<(String, TokenUsage), SentioError> {
        match self.api {
            ApiKind::ChatCompletions => {
                self.call_chat_completions(system, user_content, base_url)
                    .await
            }
            ApiKind::Responses => self.call_responses(system, user_content, base_url).await,
        }
    }

    async fn call_chat_completions(
        &self,
        system: &str,
        user_content: &str,
        base_url: Option<&str>,
    ) -> Result<(String, TokenUsage), SentioError> {
        let url = format!(
            "{}/v1/chat/completions",
            base_url.unwrap_or("https://api.openai.com")
        );

        let body = serde_json::json!({
            "model": self.model,
            "temperature": self.temperature,
            "messages": [
                { "role": "system", "content": system },
                { "role": "user", "content": user_content }
            ]
        });

        let resp_body = self.post_json(&url, body).await?;

        let text = resp_body["choices"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|c| c["message"]["content"].as_str())
            .ok_or_else(|| {
                SentioError::Internal(
                    "OpenAI response missing choices[0].message.content".to_string(),
                )
            })?
            .to_string();

        let usage = TokenUsage {
            prompt_tokens: resp_body["usage"]["prompt_tokens"].as_u64().unwrap_or(0) as u32,
            completion_tokens: resp_body["usage"]["completion_tokens"]
                .as_u64()
                .unwrap_or(0) as u32,
        };

        Ok((text, usage))
    }

    async fn call_responses(
        &self,
        system: &str,
        user_content: &str,
        base_url: Option<&str>,
    ) -> Result<(String, TokenUsage), SentioError> {
        let url = format!(
            "{}/v1/responses",
            base_url.unwrap_or("https://api.openai.com")
        );

        // Reasoning-channel models (e.g. gpt-oss-120b, o-series) burn
        // a large slice of max_output_tokens on the reasoning block
        // BEFORE emitting the message block. If we pass our usual
        // ~512-token budget the message never gets written and we get
        // an empty output. Quadruple the budget for the Responses path
        // so the model has room to finish thinking AND emit a reply.
        let max_output = (self.max_input_tokens.max(512)).saturating_mul(2);

        let body = serde_json::json!({
            "model": self.model,
            "instructions": system,
            "input": user_content,
            "temperature": self.temperature,
            "max_output_tokens": max_output,
        });

        let resp_body = self.post_json(&url, body).await?;

        // Find the first output entry of type "message" and pull
        // out its first content block's text. Reasoning blocks
        // (type="reasoning") are intentionally skipped - they're for
        // debugging, not for the classification JSON we want.
        let text = resp_body["output"]
            .as_array()
            .and_then(|arr| arr.iter().find(|o| o["type"].as_str() == Some("message")))
            .and_then(|m| m["content"].as_array())
            .and_then(|c| c.first())
            .and_then(|c| c["text"].as_str())
            .ok_or_else(|| {
                SentioError::Internal(
                    "OpenAI Responses output missing message.content[0].text".to_string(),
                )
            })?
            .to_string();

        let usage = TokenUsage {
            prompt_tokens: resp_body["usage"]["input_tokens"].as_u64().unwrap_or(0) as u32,
            completion_tokens: resp_body["usage"]["output_tokens"].as_u64().unwrap_or(0) as u32,
        };

        Ok((text, usage))
    }

    /// Shared HTTP POST + JSON decode + HTTP-error mapping for both API
    /// surfaces.
    async fn post_json(
        &self,
        url: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, SentioError> {
        let mut req = self
            .client
            .post(url)
            .header("content-type", "application/json");

        if !self.api_key.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", self.api_key));
        }

        let resp = req
            .json(&body)
            .send()
            .await
            .map_err(|e| SentioError::Internal(format!("OpenAI API request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let txt = resp.text().await.unwrap_or_default();
            return Err(SentioError::Internal(format!(
                "OpenAI API returned HTTP {status}: {txt}"
            )));
        }

        resp.json()
            .await
            .map_err(|e| SentioError::Internal(format!("OpenAI response parse failed: {e}")))
    }
}

impl LlmProvider for OpenAiProvider {
    async fn classify(
        &self,
        message_text: &str,
        envelope_from: &str,
        envelope_to: &str,
    ) -> Result<ClassifyResult, SentioError> {
        let truncated = truncate_to_tokens(message_text, self.max_input_tokens);
        let user_content = CLASSIFICATION_USER
            .replace("{envelope_from}", envelope_from)
            .replace("{envelope_to}", envelope_to)
            .replace("{message_text}", truncated);

        let (raw_text, usage) = self
            .call_api(
                CLASSIFICATION_SYSTEM,
                &user_content,
                self.base_url.as_deref(),
            )
            .await?;

        log_token_usage("openai", &self.model, "classify", &usage);

        let json_str = extract_json(&raw_text);
        let parsed: serde_json::Value = serde_json::from_str(json_str).map_err(|e| {
            SentioError::Internal(format!("failed to parse OpenAI classification JSON: {e}"))
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
        let prompt_template = auto_response_user(config);
        let user_content = prompt_template.replace("{message_text}", truncated);

        let (raw_text, usage) = self
            .call_api(
                auto_response_system(),
                &user_content,
                self.base_url.as_deref(),
            )
            .await?;

        log_token_usage("openai", &self.model, "auto_response", &usage);

        let json_str = extract_json(&raw_text);
        let parsed: serde_json::Value = serde_json::from_str(json_str).map_err(|e| {
            SentioError::Internal(format!("failed to parse OpenAI auto-response JSON: {e}"))
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

    #[tokio::test]
    async fn openai_classify_success() {
        let server = wiremock::MockServer::start().await;

        let response_body = serde_json::json!({
            "choices": [
                {
                    "message": {
                        "content": "{\"category\": \"threat\", \"summary\": \"Suspicious email with phishing links requesting credentials\"}"
                    }
                }
            ],
            "usage": {
                "prompt_tokens": 200,
                "completion_tokens": 40
            }
        });

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/chat/completions"))
            .and(wiremock::matchers::header(
                "Authorization",
                "Bearer test-key",
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&server)
            .await;

        let provider = OpenAiProvider {
            client: reqwest::Client::new(),
            api_key: "test-key".to_string(),
            model: "gpt-4o".to_string(),
            temperature: 0.3,
            max_input_tokens: 2000,
            base_url: None,
            api: ApiKind::ChatCompletions,
        };

        let (raw_text, usage) = provider
            .call_api(CLASSIFICATION_SYSTEM, "test email", Some(&server.uri()))
            .await
            .unwrap();

        let json_str = extract_json(&raw_text);
        let parsed: serde_json::Value = serde_json::from_str(json_str).unwrap();

        assert_eq!(parsed["category"], "threat");
        assert_eq!(
            parsed["summary"],
            "Suspicious email with phishing links requesting credentials"
        );
        assert_eq!(usage.prompt_tokens, 200);
        assert_eq!(usage.completion_tokens, 40);
    }

    #[tokio::test]
    async fn openai_http_error() {
        let server = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/chat/completions"))
            .respond_with(
                wiremock::ResponseTemplate::new(429).set_body_string("rate limit exceeded"),
            )
            .mount(&server)
            .await;

        let provider = OpenAiProvider {
            client: reqwest::Client::new(),
            api_key: "test-key".to_string(),
            model: "gpt-4o".to_string(),
            temperature: 0.3,
            max_input_tokens: 2000,
            base_url: None,
            api: ApiKind::ChatCompletions,
        };

        let result = provider
            .call_api("system", "user", Some(&server.uri()))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("429"));
    }

    #[tokio::test]
    async fn openai_responses_api_extracts_message_skips_reasoning() {
        let server = wiremock::MockServer::start().await;

        // Realistic Responses API body: a reasoning block (which must
        // be ignored) followed by the assistant message we care about.
        let response_body = serde_json::json!({
            "object": "response",
            "output": [
                {
                    "type": "reasoning",
                    "content": [{ "type": "reasoning_text", "text": "Thinking about the email…" }]
                },
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [{
                        "type": "output_text",
                        "text": "{\"category\":\"transactional\",\"summary\":\"order confirmation\"}"
                    }]
                }
            ],
            "usage": { "input_tokens": 150, "output_tokens": 30 }
        });

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/responses"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&server)
            .await;

        let provider = OpenAiProvider {
            client: reqwest::Client::new(),
            api_key: String::new(),
            model: "gpt-oss-120b".to_string(),
            temperature: 0.3,
            max_input_tokens: 2000,
            base_url: None,
            api: ApiKind::Responses,
        };

        let (text, usage) = provider
            .call_api(CLASSIFICATION_SYSTEM, "test email", Some(&server.uri()))
            .await
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(extract_json(&text)).unwrap();
        assert_eq!(parsed["category"], "transactional");
        assert_eq!(parsed["summary"], "order confirmation");
        assert_eq!(usage.prompt_tokens, 150);
        assert_eq!(usage.completion_tokens, 30);
    }

    #[tokio::test]
    async fn openai_responses_api_message_block_missing() {
        let server = wiremock::MockServer::start().await;
        // A response with ONLY a reasoning block - must error, not silently return empty.
        let response_body = serde_json::json!({
            "output": [{
                "type": "reasoning",
                "content": [{ "type": "reasoning_text", "text": "Just thinking, never spoke." }]
            }],
            "usage": { "input_tokens": 50, "output_tokens": 12 }
        });
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/responses"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&server)
            .await;

        let provider = OpenAiProvider {
            client: reqwest::Client::new(),
            api_key: String::new(),
            model: "gpt-oss-120b".to_string(),
            temperature: 0.3,
            max_input_tokens: 2000,
            base_url: None,
            api: ApiKind::Responses,
        };

        let err = provider
            .call_api("sys", "user", Some(&server.uri()))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("Responses output missing message.content"));
    }

    #[tokio::test]
    async fn openai_malformed_response() {
        let server = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/chat/completions"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"choices": []})),
            )
            .mount(&server)
            .await;

        let provider = OpenAiProvider {
            client: reqwest::Client::new(),
            api_key: "test-key".to_string(),
            model: "gpt-4o".to_string(),
            temperature: 0.3,
            max_input_tokens: 2000,
            base_url: None,
            api: ApiKind::ChatCompletions,
        };

        let result = provider
            .call_api("system", "user", Some(&server.uri()))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("missing choices[0].message.content"));
    }
}
