use std::sync::{Arc, Mutex};

use sentio_core::error::SentioError;

use crate::traits::{
    AutoRespondConfig, AutoResponseResult, ClassifyResult, LlmProvider, MessageCategory, TokenUsage,
};

/// Mock LLM provider for testing. Returns configurable results.
///
/// Available behind `cfg(test)` or the `test-support` feature.
#[derive(Clone)]
pub struct MockLlmProvider {
    classify_result: Arc<Mutex<Result<ClassifyResult, String>>>,
    auto_response_result: Arc<Mutex<Result<AutoResponseResult, String>>>,
}

impl MockLlmProvider {
    pub fn new() -> Self {
        Self {
            classify_result: Arc::new(Mutex::new(Ok(ClassifyResult {
                category: MessageCategory::Conversation,
                score_delta: 0.0,
                summary: "mock classification".to_string(),
                token_usage: TokenUsage::default(),
            }))),
            auto_response_result: Arc::new(Mutex::new(Ok(AutoResponseResult {
                subject: "Re: mock".to_string(),
                body: "Mock auto-response body".to_string(),
                token_usage: TokenUsage::default(),
            }))),
        }
    }

    /// Set the classification result that will be returned.
    pub fn set_classify_result(&self, result: ClassifyResult) {
        *self.classify_result.lock().unwrap() = Ok(result);
    }

    /// Set the classification to return an error.
    pub fn set_classify_error(&self, msg: &str) {
        *self.classify_result.lock().unwrap() = Err(msg.to_string());
    }

    /// Set the auto-response result that will be returned.
    pub fn set_auto_response_result(&self, result: AutoResponseResult) {
        *self.auto_response_result.lock().unwrap() = Ok(result);
    }

    /// Set the auto-response to return an error.
    pub fn set_auto_response_error(&self, msg: &str) {
        *self.auto_response_result.lock().unwrap() = Err(msg.to_string());
    }
}

impl Default for MockLlmProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl LlmProvider for MockLlmProvider {
    async fn classify(
        &self,
        _message_text: &str,
        _envelope_from: &str,
        _envelope_to: &str,
    ) -> Result<ClassifyResult, SentioError> {
        let guard = self.classify_result.lock().unwrap();
        match &*guard {
            Ok(result) => Ok(result.clone()),
            Err(msg) => Err(SentioError::Internal(msg.clone())),
        }
    }

    async fn generate_auto_response(
        &self,
        _message_text: &str,
        _config: &AutoRespondConfig,
    ) -> Result<AutoResponseResult, SentioError> {
        let guard = self.auto_response_result.lock().unwrap();
        match &*guard {
            Ok(result) => Ok(result.clone()),
            Err(msg) => Err(SentioError::Internal(msg.clone())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_returns_default_legitimate() {
        let mock = MockLlmProvider::new();
        let result = mock
            .classify("test", "from@example.com", "to@example.com")
            .await
            .unwrap();
        assert_eq!(result.category, MessageCategory::Conversation);
        assert_eq!(result.score_delta, 0.0);
    }

    #[tokio::test]
    async fn mock_set_classify_result() {
        let mock = MockLlmProvider::new();
        mock.set_classify_result(ClassifyResult {
            category: MessageCategory::Spam,
            score_delta: 0.0,
            summary: "test spam".to_string(),
            token_usage: TokenUsage {
                prompt_tokens: 100,
                completion_tokens: 20,
            },
        });

        let result = mock
            .classify("test", "from@example.com", "to@example.com")
            .await
            .unwrap();
        assert_eq!(result.category, MessageCategory::Spam);
        assert_eq!(result.score_delta, 0.0);
    }

    #[tokio::test]
    async fn mock_classify_error() {
        let mock = MockLlmProvider::new();
        mock.set_classify_error("API down");

        let result = mock
            .classify("test", "from@example.com", "to@example.com")
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("API down"));
    }

    #[tokio::test]
    async fn mock_returns_default_auto_response() {
        let mock = MockLlmProvider::new();
        let config = AutoRespondConfig::default();
        let result = mock.generate_auto_response("test", &config).await.unwrap();
        assert_eq!(result.subject, "Re: mock");
    }

    #[tokio::test]
    async fn mock_set_auto_response_result() {
        let mock = MockLlmProvider::new();
        mock.set_auto_response_result(AutoResponseResult {
            subject: "Re: custom".to_string(),
            body: "Custom response".to_string(),
            token_usage: TokenUsage::default(),
        });

        let config = AutoRespondConfig::default();
        let result = mock.generate_auto_response("test", &config).await.unwrap();
        assert_eq!(result.subject, "Re: custom");
        assert_eq!(result.body, "Custom response");
    }

    #[tokio::test]
    async fn mock_auto_response_error() {
        let mock = MockLlmProvider::new();
        mock.set_auto_response_error("timeout");

        let config = AutoRespondConfig::default();
        let result = mock.generate_auto_response("test", &config).await;
        assert!(result.is_err());
    }
}
