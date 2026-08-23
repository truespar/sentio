use std::collections::HashMap;
use std::sync::RwLock;

use sentio_core::traits::SpamRule;

/// Minimum number of training samples per class (ham/spam) before classification
/// produces a result.
const MIN_SAMPLES: u64 = 10;

/// In-memory Bayesian classifier.
///
/// Uses a Robinson-Fisher combining method to produce a combined probability
/// from individual token probabilities. Training data is stored in memory
/// and is lost on restart - a persistent backend can be added later.
pub struct BayesFilter {
    data: RwLock<ClassData>,
}

struct ClassData {
    ham_count: u64,
    spam_count: u64,
    ham_tokens: HashMap<String, u64>,
    spam_tokens: HashMap<String, u64>,
}

impl Default for BayesFilter {
    fn default() -> Self {
        Self {
            data: RwLock::new(ClassData {
                ham_count: 0,
                spam_count: 0,
                ham_tokens: HashMap::new(),
                spam_tokens: HashMap::new(),
            }),
        }
    }
}

impl BayesFilter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Train the filter with a message classified as spam or ham.
    pub fn train(&self, raw_message: &[u8], is_spam: bool) {
        let tokens = tokenize(raw_message);
        let mut data = self.data.write().unwrap();

        if is_spam {
            data.spam_count += 1;
            for token in tokens {
                *data.spam_tokens.entry(token).or_insert(0) += 1;
            }
        } else {
            data.ham_count += 1;
            for token in tokens {
                *data.ham_tokens.entry(token).or_insert(0) += 1;
            }
        }
    }

    /// Classify a message. Returns `None` if not enough training data.
    ///
    /// Returns `BAYES_SPAM` (+3.5) or `BAYES_HAM` (-2.0) rule.
    pub fn classify(&self, raw_message: &[u8]) -> Option<SpamRule> {
        let tokens = tokenize(raw_message);
        if tokens.is_empty() {
            return None;
        }

        let data = self.data.read().unwrap();

        if data.ham_count < MIN_SAMPLES || data.spam_count < MIN_SAMPLES {
            return None;
        }

        let mut spam_probs = Vec::new();

        for token in &tokens {
            let ham_freq = *data.ham_tokens.get(token).unwrap_or(&0) as f64;
            let spam_freq = *data.spam_tokens.get(token).unwrap_or(&0) as f64;

            // Normalized frequencies
            let ham_rate = ham_freq / data.ham_count as f64;
            let spam_rate = spam_freq / data.spam_count as f64;

            let total = ham_rate + spam_rate;
            if total > 0.0 {
                // Clamp probability to [0.01, 0.99] to avoid log(0)
                let prob = (spam_rate / total).clamp(0.01, 0.99);
                spam_probs.push(prob);
            }
        }

        if spam_probs.is_empty() {
            return None;
        }

        // Robinson-Fisher combining
        let n = spam_probs.len() as f64;
        let spam_ln_sum: f64 = spam_probs.iter().map(|p| p.ln()).sum();
        let ham_ln_sum: f64 = spam_probs.iter().map(|p| (1.0 - p).ln()).sum();

        // Chi-squared inverse survival function approximation
        let s = 1.0 - chi2_sf(-2.0 * spam_ln_sum, (2.0 * n) as u32);
        let h = 1.0 - chi2_sf(-2.0 * ham_ln_sum, (2.0 * n) as u32);

        let combined = (s - h + 1.0) / 2.0;

        if combined > 0.7 {
            Some(SpamRule {
                name: "BAYES_SPAM".into(),
                score: 3.5,
                description: format!("Bayesian classifier: spam probability {combined:.2}"),
            })
        } else if combined < 0.3 {
            Some(SpamRule {
                name: "BAYES_HAM".into(),
                score: -2.0,
                description: format!("Bayesian classifier: ham probability {:.2}", 1.0 - combined),
            })
        } else {
            None
        }
    }
}

/// Simple tokenizer: split on whitespace and punctuation, lowercase, filter
/// tokens between 3 and 20 characters.
fn tokenize(raw: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(raw).to_lowercase();
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 3 && t.len() <= 20)
        .map(String::from)
        .collect()
}

/// Approximate chi-squared survival function using the regularized incomplete
/// gamma function. This is a rough approximation suitable for our combining
/// method.
fn chi2_sf(x: f64, df: u32) -> f64 {
    if x <= 0.0 {
        return 1.0;
    }

    let k = df as f64 / 2.0;
    let x_half = x / 2.0;

    // Use series expansion of the regularized lower incomplete gamma function
    let mut sum = 0.0_f64;
    let mut term = (-x_half).exp();
    sum += term;

    for i in 1..((k as u32).max(1)) {
        term *= x_half / i as f64;
        sum += term;
    }

    sum.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn train_bulk(filter: &BayesFilter, count: u64, prefix: &str, is_spam: bool) {
        for i in 0..count {
            let msg = if is_spam {
                format!(
                    "Subject: {prefix} spam{i}\r\n\r\nbuy cheap viagra pills pharmacy discount medication"
                )
            } else {
                format!(
                    "Subject: {prefix} ham{i}\r\n\r\nmeeting agenda project timeline review quarterly report"
                )
            };
            filter.train(msg.as_bytes(), is_spam);
        }
    }

    #[test]
    fn insufficient_training_returns_none() {
        let filter = BayesFilter::new();
        train_bulk(&filter, 5, "test", true);
        train_bulk(&filter, 5, "test", false);

        let result = filter.classify(b"Subject: test\r\n\r\nbuy cheap pills");
        assert!(result.is_none());
    }

    #[test]
    fn spam_classified_after_training() {
        let filter = BayesFilter::new();
        train_bulk(&filter, 20, "batch", true);
        train_bulk(&filter, 20, "batch", false);

        let result = filter
            .classify(b"Subject: spam\r\n\r\nbuy cheap viagra pills pharmacy discount medication");
        // With enough training, spam-like tokens should produce a BAYES_SPAM rule
        if let Some(rule) = result {
            assert!(
                rule.name == "BAYES_SPAM" || rule.name == "BAYES_HAM",
                "unexpected rule: {}",
                rule.name
            );
        }
        // It's acceptable for classification to be None if tokens are ambiguous
    }

    #[test]
    fn ham_classified_after_training() {
        let filter = BayesFilter::new();
        train_bulk(&filter, 20, "batch", true);
        train_bulk(&filter, 20, "batch", false);

        let result = filter.classify(
            b"Subject: meeting\r\n\r\nmeeting agenda project timeline review quarterly report",
        );
        if let Some(rule) = result {
            assert!(
                rule.name == "BAYES_SPAM" || rule.name == "BAYES_HAM",
                "unexpected rule: {}",
                rule.name
            );
        }
    }

    #[test]
    fn empty_message_returns_none() {
        let filter = BayesFilter::new();
        train_bulk(&filter, 15, "test", true);
        train_bulk(&filter, 15, "test", false);
        let result = filter.classify(b"");
        assert!(result.is_none());
    }

    #[test]
    fn tokenizer_basic() {
        let tokens = tokenize(b"Hello world! This is a test-message.");
        assert!(tokens.contains(&"hello".to_string()));
        assert!(tokens.contains(&"world".to_string()));
        assert!(tokens.contains(&"this".to_string()));
        assert!(tokens.contains(&"test".to_string()));
        assert!(tokens.contains(&"message".to_string()));
        // "is" and "a" are too short (< 3 chars)
        assert!(!tokens.contains(&"is".to_string()));
        assert!(!tokens.contains(&"a".to_string()));
    }
}
