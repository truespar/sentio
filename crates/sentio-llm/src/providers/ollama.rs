use std::time::Duration;

use sentio_core::config::LlmConfig;
use sentio_core::error::SentioError;

use crate::scoring::{estimate_tokens, extract_json, log_token_usage, truncate_to_tokens};
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

/// Ollama self-hosted LLM provider.
#[derive(Debug)]
pub struct OllamaProvider {
    client: reqwest::Client,
    base_url: String,
    model: String,
    temperature: f64,
    max_input_tokens: u32,
}

impl OllamaProvider {
    pub fn new(config: &LlmConfig) -> Result<Self, SentioError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| {
                SentioError::Internal(format!("failed to build Ollama HTTP client: {e}"))
            })?;

        Ok(Self {
            client,
            base_url: config.ollama.base_url.trim_end_matches('/').to_string(),
            model: config.ollama.model.clone(),
            temperature: config.temperature,
            max_input_tokens: config.max_input_tokens,
        })
    }

    async fn call_api(
        &self,
        system: &str,
        user_content: &str,
        base_url_override: Option<&str>,
    ) -> Result<(String, TokenUsage), SentioError> {
        let base = base_url_override.unwrap_or(&self.base_url);
        let url = format!("{}/api/chat", base);

        let body = serde_json::json!({
            "model": self.model,
            "stream": false,
            "options": {
                "temperature": self.temperature
            },
            "messages": [
                { "role": "system", "content": system },
                { "role": "user", "content": user_content }
            ]
        });

        let resp = self
            .client
            .post(&url)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| SentioError::Internal(format!("Ollama API request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(SentioError::Internal(format!(
                "Ollama API returned HTTP {status}: {body}"
            )));
        }

        let resp_body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SentioError::Internal(format!("Ollama response parse failed: {e}")))?;

        let text = resp_body["message"]["content"]
            .as_str()
            .ok_or_else(|| {
                SentioError::Internal("Ollama response missing message.content".to_string())
            })?
            .to_string();

        // Ollama reports token counts in eval_count / prompt_eval_count,
        // falling back to estimation if not present.
        let prompt_tokens = resp_body["prompt_eval_count"]
            .as_u64()
            .map(|v| v as u32)
            .unwrap_or_else(|| estimate_tokens(user_content));
        let completion_tokens = resp_body["eval_count"]
            .as_u64()
            .map(|v| v as u32)
            .unwrap_or_else(|| estimate_tokens(&text));

        let usage = TokenUsage {
            prompt_tokens,
            completion_tokens,
        };

        Ok((text, usage))
    }
}

impl LlmProvider for OllamaProvider {
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

        log_token_usage("ollama", &self.model, "classify", &usage);

        let json_str = extract_json(&raw_text);
        let parsed: serde_json::Value = serde_json::from_str(json_str).map_err(|e| {
            SentioError::Internal(format!("failed to parse Ollama classification JSON: {e}"))
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

        log_token_usage("ollama", &self.model, "auto_response", &usage);

        let json_str = extract_json(&raw_text);
        let parsed: serde_json::Value = serde_json::from_str(json_str).map_err(|e| {
            SentioError::Internal(format!("failed to parse Ollama auto-response JSON: {e}"))
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
    async fn ollama_classify_success() {
        let server = wiremock::MockServer::start().await;

        let response_body = serde_json::json!({
            "message": {
                "content": "{\"category\": \"marketing\", \"summary\": \"Promotional email advertising a product launch\"}"
            },
            "prompt_eval_count": 180,
            "eval_count": 25
        });

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/chat"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&server)
            .await;

        let provider = OllamaProvider {
            client: reqwest::Client::new(),
            base_url: server.uri(),
            model: "llama3".to_string(),
            temperature: 0.3,
            max_input_tokens: 2000,
        };

        let (raw_text, usage) = provider
            .call_api("system", "test email", Some(&server.uri()))
            .await
            .unwrap();

        let json_str = extract_json(&raw_text);
        let parsed: serde_json::Value = serde_json::from_str(json_str).unwrap();

        assert_eq!(parsed["category"], "marketing");
        assert_eq!(usage.prompt_tokens, 180);
        assert_eq!(usage.completion_tokens, 25);
    }

    #[tokio::test]
    async fn ollama_fallback_token_estimation() {
        let server = wiremock::MockServer::start().await;

        // Response without token counts - should fall back to estimation
        let response_body = serde_json::json!({
            "message": {
                "content": "{\"category\": \"conversation\", \"summary\": \"A regular business email exchange\"}"
            }
        });

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/chat"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&server)
            .await;

        let provider = OllamaProvider {
            client: reqwest::Client::new(),
            base_url: server.uri(),
            model: "llama3".to_string(),
            temperature: 0.3,
            max_input_tokens: 2000,
        };

        let (_, usage) = provider
            .call_api("system", "test email content", Some(&server.uri()))
            .await
            .unwrap();

        // Token counts should be estimated (> 0)
        assert!(usage.prompt_tokens > 0);
        assert!(usage.completion_tokens > 0);
    }

    #[tokio::test]
    async fn ollama_http_error() {
        let server = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/chat"))
            .respond_with(wiremock::ResponseTemplate::new(503).set_body_string("model not loaded"))
            .mount(&server)
            .await;

        let provider = OllamaProvider {
            client: reqwest::Client::new(),
            base_url: server.uri(),
            model: "llama3".to_string(),
            temperature: 0.3,
            max_input_tokens: 2000,
        };

        let result = provider
            .call_api("system", "user", Some(&server.uri()))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("503"));
    }

    #[tokio::test]
    async fn ollama_malformed_response() {
        let server = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/chat"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"done": true})),
            )
            .mount(&server)
            .await;

        let provider = OllamaProvider {
            client: reqwest::Client::new(),
            base_url: server.uri(),
            model: "llama3".to_string(),
            temperature: 0.3,
            max_input_tokens: 2000,
        };

        let result = provider
            .call_api("system", "user", Some(&server.uri()))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("missing message.content"));
    }
}
