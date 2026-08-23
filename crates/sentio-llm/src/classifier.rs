use sentio_core::config::{LlmConfig, SpamConfig};
use sentio_core::error::SentioError;

use crate::traits::{ClassifyResult, LlmProvider};

/// Outcome of the borderline classification pipeline.
#[derive(Debug, Clone)]
pub struct ClassificationOutcome {
    /// Whether the LLM was actually consulted.
    pub llm_consulted: bool,
    /// The final adjusted spam score.
    pub adjusted_score: f64,
    /// The LLM classification result, if consulted.
    pub classification: Option<ClassifyResult>,
}

/// Classify a message if its spam score falls in the borderline review band.
///
/// The LLM is consulted only when:
/// 1. LLM is enabled in config
/// 2. `classify_inbound` is true
/// 3. The spam score falls within `[score_llm_review_min, score_llm_review_max]`
///
/// Returns `ClassificationOutcome` with whether the LLM was consulted and
/// the adjusted score (original + score_delta from LLM).
pub async fn classify_if_borderline<P: LlmProvider>(
    provider: &P,
    llm_config: &LlmConfig,
    spam_config: &SpamConfig,
    spam_score: f64,
    message_text: &str,
    envelope_from: &str,
    envelope_to: &str,
) -> Result<ClassificationOutcome, SentioError> {
    // Check if LLM classification is enabled
    if !llm_config.enabled || !llm_config.classify_inbound {
        return Ok(ClassificationOutcome {
            llm_consulted: false,
            adjusted_score: spam_score,
            classification: None,
        });
    }

    // Check if score is in the borderline review band
    if spam_score < spam_config.score_llm_review_min
        || spam_score > spam_config.score_llm_review_max
    {
        return Ok(ClassificationOutcome {
            llm_consulted: false,
            adjusted_score: spam_score,
            classification: None,
        });
    }

    tracing::info!(
        spam_score = spam_score,
        review_min = spam_config.score_llm_review_min,
        review_max = spam_config.score_llm_review_max,
        "Spam score in LLM review band, consulting LLM"
    );

    let result = provider
        .classify(message_text, envelope_from, envelope_to)
        .await?;

    let adjusted_score = spam_score + result.score_delta;

    tracing::info!(
        category = %result.category,
        score_delta = result.score_delta,
        original_score = spam_score,
        adjusted_score = adjusted_score,
        summary = %result.summary,
        "LLM classification complete"
    );

    Ok(ClassificationOutcome {
        llm_consulted: true,
        adjusted_score,
        classification: Some(result),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockLlmProvider;
    use crate::traits::{ClassifyResult, MessageCategory, TokenUsage};

    fn test_llm_config(enabled: bool, classify_inbound: bool) -> LlmConfig {
        LlmConfig {
            enabled,
            classify_inbound,
            ..Default::default()
        }
    }

    fn test_spam_config() -> SpamConfig {
        SpamConfig {
            score_llm_review_min: 4.0,
            score_llm_review_max: 6.0,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn disabled_config_skips_llm() {
        let provider = MockLlmProvider::new();
        let llm_config = test_llm_config(false, true);
        let spam_config = test_spam_config();

        let outcome = classify_if_borderline(
            &provider,
            &llm_config,
            &spam_config,
            5.0,
            "test message",
            "from@example.com",
            "to@example.com",
        )
        .await
        .unwrap();

        assert!(!outcome.llm_consulted);
        assert!((outcome.adjusted_score - 5.0).abs() < f64::EPSILON);
        assert!(outcome.classification.is_none());
    }

    #[tokio::test]
    async fn classify_inbound_false_skips_llm() {
        let provider = MockLlmProvider::new();
        let llm_config = test_llm_config(true, false);
        let spam_config = test_spam_config();

        let outcome = classify_if_borderline(
            &provider,
            &llm_config,
            &spam_config,
            5.0,
            "test message",
            "from@example.com",
            "to@example.com",
        )
        .await
        .unwrap();

        assert!(!outcome.llm_consulted);
    }

    #[tokio::test]
    async fn score_below_band_skips_llm() {
        let provider = MockLlmProvider::new();
        let llm_config = test_llm_config(true, true);
        let spam_config = test_spam_config();

        let outcome = classify_if_borderline(
            &provider,
            &llm_config,
            &spam_config,
            2.0, // below min 4.0
            "test message",
            "from@example.com",
            "to@example.com",
        )
        .await
        .unwrap();

        assert!(!outcome.llm_consulted);
        assert!((outcome.adjusted_score - 2.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn score_above_band_skips_llm() {
        let provider = MockLlmProvider::new();
        let llm_config = test_llm_config(true, true);
        let spam_config = test_spam_config();

        let outcome = classify_if_borderline(
            &provider,
            &llm_config,
            &spam_config,
            8.0, // above max 6.0
            "test message",
            "from@example.com",
            "to@example.com",
        )
        .await
        .unwrap();

        assert!(!outcome.llm_consulted);
        assert!((outcome.adjusted_score - 8.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn score_in_band_consults_llm() {
        let provider = MockLlmProvider::new();
        provider.set_classify_result(ClassifyResult {
            category: MessageCategory::Spam,
            score_delta: 3.0,
            summary: "Unsolicited bulk email with spam patterns".to_string(),
            token_usage: TokenUsage {
                prompt_tokens: 100,
                completion_tokens: 20,
            },
        });

        let llm_config = test_llm_config(true, true);
        let spam_config = test_spam_config();

        let outcome = classify_if_borderline(
            &provider,
            &llm_config,
            &spam_config,
            5.0, // in band [4.0, 6.0]
            "test message",
            "from@example.com",
            "to@example.com",
        )
        .await
        .unwrap();

        assert!(outcome.llm_consulted);
        assert!((outcome.adjusted_score - 8.0).abs() < f64::EPSILON); // 5.0 + 3.0
        assert!(outcome.classification.is_some());
        let classification = outcome.classification.unwrap();
        assert_eq!(classification.category, MessageCategory::Spam);
    }

    #[tokio::test]
    async fn score_at_band_min_consults_llm() {
        let provider = MockLlmProvider::new();
        provider.set_classify_result(ClassifyResult {
            category: MessageCategory::Conversation,
            score_delta: -2.0,
            summary: "Regular business email conversation".to_string(),
            token_usage: TokenUsage::default(),
        });

        let llm_config = test_llm_config(true, true);
        let spam_config = test_spam_config();

        let outcome = classify_if_borderline(
            &provider,
            &llm_config,
            &spam_config,
            4.0, // exactly at min
            "test message",
            "from@example.com",
            "to@example.com",
        )
        .await
        .unwrap();

        assert!(outcome.llm_consulted);
        assert!((outcome.adjusted_score - 2.0).abs() < f64::EPSILON); // 4.0 + (-2.0)
    }

    #[tokio::test]
    async fn score_at_band_max_consults_llm() {
        let provider = MockLlmProvider::new();
        let llm_config = test_llm_config(true, true);
        let spam_config = test_spam_config();

        let outcome = classify_if_borderline(
            &provider,
            &llm_config,
            &spam_config,
            6.0, // exactly at max
            "test message",
            "from@example.com",
            "to@example.com",
        )
        .await
        .unwrap();

        assert!(outcome.llm_consulted);
    }
}
