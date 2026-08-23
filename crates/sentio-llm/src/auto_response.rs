use sentio_core::config::LlmConfig;
use sentio_core::error::SentioError;

use crate::traits::{AutoRespondConfig, AutoResponseResult, LlmProvider};

/// Generate an auto-response draft for an inbound message.
///
/// Returns `None` if:
/// - LLM is disabled
/// - `auto_respond` is false in the LLM config
/// - `route_auto_respond` is false for the inbound route
///
/// The `auto_respond_config_json` is the JSON value from
/// `InboundRouteRecord.auto_respond_config` and is parsed into `AutoRespondConfig`.
pub async fn generate_draft<P: LlmProvider>(
    provider: &P,
    llm_config: &LlmConfig,
    route_auto_respond: bool,
    auto_respond_config_json: Option<&serde_json::Value>,
    message_text: &str,
) -> Result<Option<AutoResponseResult>, SentioError> {
    // Check if auto-response is enabled
    if !llm_config.enabled || !llm_config.auto_respond || !route_auto_respond {
        return Ok(None);
    }

    // Parse the auto-respond config from JSON, or use defaults
    let config: AutoRespondConfig = match auto_respond_config_json {
        Some(json) => serde_json::from_value(json.clone())
            .map_err(|e| SentioError::Internal(format!("invalid auto_respond_config JSON: {e}")))?,
        None => AutoRespondConfig::default(),
    };

    tracing::info!(
        tone = %config.tone,
        max_length = config.max_length,
        organization = %config.organization,
        "Generating auto-response draft"
    );

    let result = provider
        .generate_auto_response(message_text, &config)
        .await?;

    tracing::info!(
        subject = %result.subject,
        body_len = result.body.len(),
        prompt_tokens = result.token_usage.prompt_tokens,
        completion_tokens = result.token_usage.completion_tokens,
        "Auto-response draft generated"
    );

    Ok(Some(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockLlmProvider;
    use crate::traits::{AutoResponseResult, TokenUsage};

    fn test_llm_config(enabled: bool, auto_respond: bool) -> LlmConfig {
        LlmConfig {
            enabled,
            auto_respond,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn disabled_returns_none() {
        let provider = MockLlmProvider::new();
        let config = test_llm_config(false, true);

        let result = generate_draft(&provider, &config, true, None, "test message")
            .await
            .unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn auto_respond_false_returns_none() {
        let provider = MockLlmProvider::new();
        let config = test_llm_config(true, false);

        let result = generate_draft(&provider, &config, true, None, "test message")
            .await
            .unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn route_auto_respond_false_returns_none() {
        let provider = MockLlmProvider::new();
        let config = test_llm_config(true, true);

        let result = generate_draft(&provider, &config, false, None, "test message")
            .await
            .unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn enabled_returns_draft() {
        let provider = MockLlmProvider::new();
        provider.set_auto_response_result(AutoResponseResult {
            subject: "Re: Hello".to_string(),
            body: "Thank you for your message.".to_string(),
            token_usage: TokenUsage {
                prompt_tokens: 150,
                completion_tokens: 30,
            },
        });

        let config = test_llm_config(true, true);

        let result = generate_draft(&provider, &config, true, None, "Hello, I need help.")
            .await
            .unwrap();

        assert!(result.is_some());
        let draft = result.unwrap();
        assert_eq!(draft.subject, "Re: Hello");
        assert_eq!(draft.body, "Thank you for your message.");
    }

    #[tokio::test]
    async fn custom_config_json_parsed() {
        let provider = MockLlmProvider::new();
        let config = test_llm_config(true, true);

        let custom_config = serde_json::json!({
            "tone": "friendly",
            "max_length": 200,
            "organization": "Acme Corp",
            "custom_instructions": "Always mention our return policy"
        });

        let result = generate_draft(
            &provider,
            &config,
            true,
            Some(&custom_config),
            "test message",
        )
        .await
        .unwrap();

        assert!(result.is_some());
    }

    #[tokio::test]
    async fn invalid_config_json_returns_error() {
        let provider = MockLlmProvider::new();
        let config = test_llm_config(true, true);

        // Invalid JSON structure - tone should be a string, not a number
        let bad_config = serde_json::json!({
            "tone": 12345,
            "max_length": "not a number"
        });

        let result =
            generate_draft(&provider, &config, true, Some(&bad_config), "test message").await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("auto_respond_config"));
    }

    #[tokio::test]
    async fn default_config_when_json_none() {
        let provider = MockLlmProvider::new();
        let config = test_llm_config(true, true);

        let result = generate_draft(&provider, &config, true, None, "test message")
            .await
            .unwrap();

        // Should succeed with default config
        assert!(result.is_some());
    }
}
