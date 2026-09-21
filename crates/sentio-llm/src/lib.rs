pub mod auto_response;
pub mod classifier;
pub mod providers;
pub mod scoring;
pub mod traits;

#[cfg(any(test, feature = "test-support"))]
pub mod mock;

use sentio_core::config::LlmConfig;
use sentio_core::error::SentioError;

use crate::providers::anthropic::AnthropicProvider;
use crate::providers::jev::JevProvider;
use crate::providers::ollama::OllamaProvider;
use crate::providers::openai::OpenAiProvider;
use crate::traits::{
    AutoRespondConfig, AutoResponseResult, ClassifyResult, MessageClassifier, ResponseGenerator,
};

/// Enum-based dispatch for LLM provider backends.
///
/// Uses enum dispatch instead of `dyn LlmProvider` because the `LlmProvider`
/// trait uses RPITIT (return-position `impl Trait` in traits), making it
/// non-object-safe.
#[derive(Debug)]
pub enum LlmBackend {
    Anthropic(AnthropicProvider),
    OpenAi(OpenAiProvider),
    Ollama(OllamaProvider),
    /// Classification only - Jev returns typed decisions, never prose.
    Jev(JevProvider),
    Noop(NoopLlmProvider),
}

impl MessageClassifier for LlmBackend {
    async fn classify(
        &self,
        message_text: &str,
        envelope_from: &str,
        envelope_to: &str,
    ) -> Result<ClassifyResult, SentioError> {
        match self {
            Self::Anthropic(p) => p.classify(message_text, envelope_from, envelope_to).await,
            Self::OpenAi(p) => p.classify(message_text, envelope_from, envelope_to).await,
            Self::Ollama(p) => p.classify(message_text, envelope_from, envelope_to).await,
            Self::Jev(p) => p.classify(message_text, envelope_from, envelope_to).await,
            Self::Noop(p) => p.classify(message_text, envelope_from, envelope_to).await,
        }
    }
}

impl ResponseGenerator for LlmBackend {
    async fn generate_auto_response(
        &self,
        message_text: &str,
        config: &AutoRespondConfig,
    ) -> Result<AutoResponseResult, SentioError> {
        match self {
            Self::Anthropic(p) => p.generate_auto_response(message_text, config).await,
            Self::OpenAi(p) => p.generate_auto_response(message_text, config).await,
            Self::Ollama(p) => p.generate_auto_response(message_text, config).await,
            // Unreachable in practice: create_backend refuses this pairing at
            // startup, so an operator hears about it at boot, not per message.
            Self::Jev(_) => Err(SentioError::Internal(
                "the jev provider cannot generate replies; set llm.auto_respond = false \
                 or pick a provider that generates text"
                    .to_string(),
            )),
            Self::Noop(p) => p.generate_auto_response(message_text, config).await,
        }
    }
}

/// Create an LLM backend from configuration.
///
/// Returns `LlmBackend::Noop` if LLM is disabled.
/// Matches the `provider` field: "anthropic", "openai", "ollama".
pub fn create_backend(config: &LlmConfig) -> Result<LlmBackend, SentioError> {
    if !config.enabled {
        return Ok(LlmBackend::Noop(NoopLlmProvider));
    }

    match config.provider.as_str() {
        "anthropic" => Ok(LlmBackend::Anthropic(AnthropicProvider::new(config)?)),
        "openai" => Ok(LlmBackend::OpenAi(OpenAiProvider::new(config)?)),
        "ollama" => Ok(LlmBackend::Ollama(OllamaProvider::new(config)?)),
        "jev" => {
            // Fail at startup rather than on the first message that needs a
            // reply: Jev is a structured-decision model with no text output.
            if config.auto_respond {
                return Err(SentioError::Internal(
                    "llm.provider = \"jev\" cannot be combined with llm.auto_respond = true: \
                     Jev returns typed decisions, not text"
                        .to_string(),
                ));
            }
            Ok(LlmBackend::Jev(JevProvider::new(config)?))
        }
        other => Err(SentioError::Internal(format!(
            "unknown LLM provider: '{other}'"
        ))),
    }
}

/// No-op LLM provider that returns default/neutral results.
#[derive(Debug, Clone)]
pub struct NoopLlmProvider;

impl MessageClassifier for NoopLlmProvider {
    async fn classify(
        &self,
        _message_text: &str,
        _envelope_from: &str,
        _envelope_to: &str,
    ) -> Result<ClassifyResult, SentioError> {
        Ok(ClassifyResult {
            category: traits::MessageCategory::Other,
            score_delta: 0.0,
            summary: "LLM classification disabled".to_string(),
            token_usage: traits::TokenUsage::default(),
        })
    }
}

impl ResponseGenerator for NoopLlmProvider {
    async fn generate_auto_response(
        &self,
        _message_text: &str,
        _config: &AutoRespondConfig,
    ) -> Result<AutoResponseResult, SentioError> {
        Ok(AutoResponseResult {
            subject: String::new(),
            body: String::new(),
            token_usage: traits::TokenUsage::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::MessageCategory;

    #[tokio::test]
    async fn noop_provider_returns_uncertain() {
        let provider = NoopLlmProvider;
        let result = provider
            .classify("test", "from@example.com", "to@example.com")
            .await
            .unwrap();
        assert_eq!(result.category, MessageCategory::Other);
        assert_eq!(result.score_delta, 0.0);
    }

    #[tokio::test]
    async fn noop_provider_returns_empty_auto_response() {
        let provider = NoopLlmProvider;
        let config = AutoRespondConfig::default();
        let result = provider
            .generate_auto_response("test", &config)
            .await
            .unwrap();
        assert!(result.subject.is_empty());
        assert!(result.body.is_empty());
    }

    #[tokio::test]
    async fn backend_noop_variant() {
        let backend = LlmBackend::Noop(NoopLlmProvider);
        let result = backend
            .classify("test", "from@example.com", "to@example.com")
            .await
            .unwrap();
        assert_eq!(result.category, MessageCategory::Other);
    }

    #[test]
    fn create_backend_disabled() {
        let config = LlmConfig {
            enabled: false,
            ..Default::default()
        };
        let backend = create_backend(&config).unwrap();
        assert!(matches!(backend, LlmBackend::Noop(_)));
    }

    #[test]
    fn create_backend_unknown_provider() {
        let config = LlmConfig {
            enabled: true,
            provider: "unknown_provider".to_string(),
            ..Default::default()
        };
        let result = create_backend(&config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unknown LLM provider"));
    }

    #[test]
    fn create_backend_ollama_no_api_key_needed() {
        let config = LlmConfig {
            enabled: true,
            provider: "ollama".to_string(),
            ..Default::default()
        };
        let result = create_backend(&config);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), LlmBackend::Ollama(_)));
    }
}
