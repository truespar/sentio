use std::future::Future;

use serde::{Deserialize, Serialize};

use sentio_core::error::SentioError;

// ──────────────────────────────────────────────────────────────────────────────
// LlmProvider trait
// ──────────────────────────────────────────────────────────────────────────────

/// Trait for LLM providers that can classify messages and generate auto-responses.
///
/// Uses RPITIT (return-position `impl Trait` in traits) instead of `#[async_trait]`,
/// matching the codebase convention used by `SpamScorer` and other traits.
pub trait LlmProvider: Send + Sync {
    fn classify(
        &self,
        message_text: &str,
        envelope_from: &str,
        envelope_to: &str,
    ) -> impl Future<Output = Result<ClassifyResult, SentioError>> + Send;

    fn generate_auto_response(
        &self,
        message_text: &str,
        config: &AutoRespondConfig,
    ) -> impl Future<Output = Result<AutoResponseResult, SentioError>> + Send;
}

// ──────────────────────────────────────────────────────────────────────────────
// MessageCategory
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageCategory {
    Conversation,
    Transactional,
    Marketing,
    Billing,
    Notification,
    Support,
    Spam,
    Threat,
    Other,
}

impl std::fmt::Display for MessageCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conversation => write!(f, "conversation"),
            Self::Transactional => write!(f, "transactional"),
            Self::Marketing => write!(f, "marketing"),
            Self::Billing => write!(f, "billing"),
            Self::Notification => write!(f, "notification"),
            Self::Support => write!(f, "support"),
            Self::Spam => write!(f, "spam"),
            Self::Threat => write!(f, "threat"),
            Self::Other => write!(f, "other"),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// ClassifyResult
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifyResult {
    pub category: MessageCategory,
    pub score_delta: f64,
    pub summary: String,
    pub token_usage: TokenUsage,
}

// ──────────────────────────────────────────────────────────────────────────────
// AutoResponseResult
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoResponseResult {
    pub subject: String,
    pub body: String,
    pub token_usage: TokenUsage,
}

// ──────────────────────────────────────────────────────────────────────────────
// TokenUsage
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
}

impl TokenUsage {
    pub fn total(&self) -> u32 {
        self.prompt_tokens + self.completion_tokens
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// AutoRespondConfig
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoRespondConfig {
    #[serde(default = "default_tone")]
    pub tone: String,
    #[serde(default = "default_max_length")]
    pub max_length: u32,
    #[serde(default)]
    pub custom_instructions: String,
    #[serde(default)]
    pub organization: String,
}

fn default_tone() -> String {
    "professional".to_string()
}

fn default_max_length() -> u32 {
    500
}

impl Default for AutoRespondConfig {
    fn default() -> Self {
        Self {
            tone: default_tone(),
            max_length: default_max_length(),
            custom_instructions: String::new(),
            organization: String::new(),
        }
    }
}
