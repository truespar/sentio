//! TypeSafe Jev - a structured-decision ("System One") model.
//!
//! Unlike the chat providers in this module, Jev does not return prose. It
//! takes a state plus a map of typed questions and answers each one with a
//! typed value and a calibrated confidence:
//!
//! - `choice` - one key from a set, with per-option probabilities
//! - `noul`   - a single probability in `[0, 1]`
//! - `score`  - a position on a labelled spectrum
//!
//! Two consequences shape this file. First, there is no JSON to coax out of a
//! text completion, so none of `scoring::extract_json` is needed. Second, Jev
//! cannot write a reply, so this provider implements `MessageClassifier` only -
//! see the config validation that refuses `auto_respond` with this provider.
//!
//! The calibrated probability is what makes this provider able to return a real
//! `score_delta`. The chat providers classify into a category and leave the
//! spam score untouched.
//!
//! API: `POST {base_url}/v1/systemone`, bearer auth.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};

use sentio_core::config::{JevConfig, LlmConfig};
use sentio_core::error::SentioError;

use crate::scoring::{log_token_usage, truncate_to_tokens};
use crate::traits::{ClassifyResult, MessageCategory, MessageClassifier, TokenUsage};

const DEFAULT_BASE_URL: &str = "https://api.typesafe.ai";
const DEFAULT_MODEL: &str = "jev-latest";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// First retry delay; doubles per attempt.
const RETRY_BASE_BACKOFF: Duration = Duration::from_millis(300);
/// Ceiling on a single backoff, so a large `max_attempts` cannot park a
/// message behind a struggling third party.
const RETRY_MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Question keys. The answer map comes back under the keys we send.
const Q_CATEGORY: &str = "category";
const Q_UNSOLICITED: &str = "unsolicited";
const Q_PHISHING: &str = "phishing";

// ──────────────────────────────────────────────────────────────────────────────
// Provider
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct JevProvider {
    http: reqwest::Client,
    base_url: String,
    model: String,
    api_key: String,
    max_input_tokens: u32,
    jev: JevConfig,
}

impl JevProvider {
    pub fn new(config: &LlmConfig) -> Result<Self, SentioError> {
        let api_key = std::env::var(&config.api_key_env).map_err(|_| {
            SentioError::Internal(format!(
                "jev provider needs an API key in ${}",
                config.api_key_env
            ))
        })?;

        let model = if config.model.is_empty() {
            DEFAULT_MODEL.to_string()
        } else {
            config.model.clone()
        };

        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .map_err(|e| SentioError::Internal(format!("could not build HTTP client: {e}")))?,
            // config/oss.toml ships `base_url = ""`, which deserializes to
            // Some("") rather than None. Treating that as a value produced a
            // relative URL and every request died in the builder before it
            // reached the network.
            base_url: config
                .base_url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            model,
            api_key,
            max_input_tokens: config.max_input_tokens,
            jev: config.jev.clone(),
        })
    }

    /// What gets sent to TypeSafe.
    ///
    /// `body_mode` decides how much of the body goes with it. The default,
    /// `"preview"`, sends a bounded slice - which is still tenant content, so
    /// an operator who must keep bodies in-house sets `"none"` and gives up the
    /// body signal. Smaller input is also cheaper: input tokens are the only
    /// metered side.
    fn build_state(&self, message_text: &str, envelope_from: &str, envelope_to: &str) -> Value {
        let (subject, body) = split_headers(message_text);

        let mut state = json!({
            "envelope_from": envelope_from,
            "envelope_to": envelope_to,
            "subject": subject,
        });

        match self.jev.body_mode.as_str() {
            "none" => {}
            "full" => {
                let budget = self.max_input_tokens.min(self.jev.max_body_tokens);
                state["body"] = json!(truncate_to_tokens(body, budget));
            }
            // Unknown values fall back to the bounded preview rather than
            // widening what gets sent.
            _ => {
                let budget = self.max_input_tokens.min(self.jev.preview_tokens);
                state["body_preview"] = json!(truncate_to_tokens(body, budget));
            }
        }

        state
    }

    fn build_questions() -> Value {
        json!({
            Q_CATEGORY: {
                "type": "choice",
                "instructions": "What kind of email is this?",
                "criteria": {
                    "conversation": "Person to person: discussion, reply, arranging a meeting",
                    "transactional": "Automated confirmation, shipping update, password reset, verification code",
                    "marketing": "Newsletter, promotion, product announcement, campaign",
                    "billing": "Invoice, payment request, receipt, overdue notice",
                    "notification": "System alert, monitoring, automated report, calendar reminder, out-of-office",
                    "support": "Help request, ticket update, customer service, complaint",
                    "spam": "Unsolicited bulk email or a scam",
                    "threat": "Phishing, business email compromise, social engineering, malware",
                    "other": "Fits none of the above",
                }
            },
            Q_UNSOLICITED: {
                "type": "noul",
                "instructions": "Is this unsolicited bulk email or a scam, sent without the recipient asking for it?",
                "criteria": {
                    "true": "Bulk, unrequested, or deceptive commercial content",
                    "false": "Solicited, transactional, or genuine person-to-person mail",
                }
            },
            Q_PHISHING: {
                "type": "noul",
                "instructions": "Is this trying to steal credentials, money, or impersonate a trusted party?",
                "criteria": {
                    "true": "Credential theft, payment redirection, or impersonation of a person or brand",
                    "false": "No attempt to deceive the recipient about who sent it or what it wants",
                }
            },
        })
    }

    /// Retries only what is worth retrying. A 401 (bad key) or 422 (malformed
    /// question) fails the same way every time.
    ///
    /// Their reference documents 401, 422, 429 and 529 only. The 500 and 503
    /// here are undocumented but observed: a request the docs call valid - a
    /// noul with no `criteria`, which their reference marks optional - came
    /// back 500 after 33 seconds, and a later valid request got 503 "no
    /// healthy upstream". Classification has no side effects beyond billing,
    /// so repeating one is safe.
    fn is_transient(status: u16) -> bool {
        matches!(status, 429 | 500 | 503 | 529)
    }

    async fn ask(&self, state: Value) -> Result<JevResponse, SentioError> {
        let attempts = self.jev.max_attempts.max(1);
        let mut last: Option<SentioError> = None;

        for attempt in 1..=attempts {
            match self.ask_once(&state).await {
                Ok(r) => return Ok(r),
                Err(TransientOrFinal::Final(e)) => return Err(e),
                Err(TransientOrFinal::Transient(e)) => {
                    tracing::warn!(
                        attempt,
                        attempts,
                        error = %e,
                        "jev call failed with a transient status"
                    );
                    last = Some(e);
                    if attempt < attempts {
                        // Exponential, as their reference asks for: "retry the
                        // request with exponential backoff instead of retrying
                        // immediately". Starts short because the pipeline is
                        // already behind a queue and a classification is not
                        // worth holding a message for long: 300ms, 600ms,
                        // 1200ms, capped.
                        let backoff = RETRY_BASE_BACKOFF
                            .saturating_mul(1u32 << (attempt - 1).min(6))
                            .min(RETRY_MAX_BACKOFF);
                        tokio::time::sleep(backoff).await;
                    }
                }
            }
        }

        Err(last.unwrap_or_else(|| SentioError::Internal("jev call failed".to_string())))
    }

    async fn ask_once(&self, state: &Value) -> Result<JevResponse, TransientOrFinal> {
        let body = json!({
            "model": self.model,
            "state": state,
            "questions": Self::build_questions(),
        });

        let resp = self
            .http
            .post(format!("{}/v1/systemone", self.base_url))
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                let err = SentioError::Internal(format!("jev request failed: {e}"));
                // A builder error means the request was never sent - a bad URL,
                // say - and will fail identically forever. Only reaching the
                // network and failing there is worth another attempt.
                if e.is_builder() {
                    TransientOrFinal::Final(err)
                } else {
                    TransientOrFinal::Transient(err)
                }
            })?;

        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(|e| {
            TransientOrFinal::Final(SentioError::Internal(format!(
                "jev response unreadable: {e}"
            )))
        })?;

        if !(200..300).contains(&status) {
            // 401 bad key, 422 malformed questions, 429 rate limited, 503/529
            // overloaded. Keep the status: the caller can tell a key problem
            // from a capacity problem.
            let err = SentioError::Internal(format!(
                "jev returned {}: {}",
                status,
                text.chars().take(300).collect::<String>()
            ));
            return Err(if Self::is_transient(status) {
                TransientOrFinal::Transient(err)
            } else {
                TransientOrFinal::Final(err)
            });
        }

        serde_json::from_str(&text).map_err(|e| {
            TransientOrFinal::Final(SentioError::Internal(format!(
                "could not parse jev response: {e}"
            )))
        })
    }
}

impl MessageClassifier for JevProvider {
    async fn classify(
        &self,
        message_text: &str,
        envelope_from: &str,
        envelope_to: &str,
    ) -> Result<ClassifyResult, SentioError> {
        let state = self.build_state(message_text, envelope_from, envelope_to);
        let parsed = self.ask(state).await?;

        let usage = TokenUsage {
            prompt_tokens: parsed.usage.input_tokens,
            completion_tokens: parsed.usage.output_tokens,
        };
        log_token_usage("jev", &self.model, "classify", &usage);

        let category = parsed
            .answers
            .get(Q_CATEGORY)
            .and_then(|a| a.choice.as_deref())
            .and_then(parse_category)
            .unwrap_or(MessageCategory::Other);

        let unsolicited = parsed.answers.get(Q_UNSOLICITED);
        let phishing = parsed.answers.get(Q_PHISHING);

        // Only `choice` answers carry a confidence - verified against the live
        // API, where a noul comes back as {"type":"noul","noul":0.96} and
        // nothing else. So the category answer's confidence is the only
        // calibration signal available, and it gates both probabilities.
        let confidence = parsed
            .answers
            .get(Q_CATEGORY)
            .and_then(|a| a.confidence)
            .unwrap_or(1.0);

        let score_delta = self.score_delta(unsolicited, phishing, confidence);

        Ok(ClassifyResult {
            category,
            score_delta,
            summary: summarize(category, unsolicited, phishing),
            token_usage: usage,
        })
    }
}

impl JevProvider {
    /// Turn the two probabilities into a spam-score adjustment.
    ///
    /// Each probability is centred on 0.5 so an undecided answer moves nothing,
    /// scaled by `confidence`, and clamped. Below `min_confidence` the whole
    /// adjustment is dropped rather than applied weakly: an uncertain model
    /// should not nudge a borderline message either way.
    fn score_delta(
        &self,
        unsolicited: Option<&JevAnswer>,
        phishing: Option<&JevAnswer>,
        confidence: f64,
    ) -> f64 {
        if confidence < self.jev.min_confidence {
            return 0.0;
        }

        let weigh = |a: Option<&JevAnswer>, weight: f64| -> f64 {
            let Some(a) = a else { return 0.0 };
            let Some(p) = a.noul else { return 0.0 };
            (p - 0.5) * 2.0 * weight * confidence
        };

        let raw = weigh(unsolicited, self.jev.unsolicited_weight)
            + weigh(phishing, self.jev.phishing_weight);

        raw.clamp(-self.jev.max_score_delta, self.jev.max_score_delta)
    }
}

/// Whether a failed attempt is worth repeating.
enum TransientOrFinal {
    Transient(SentioError),
    Final(SentioError),
}

// ──────────────────────────────────────────────────────────────────────────────
// Wire format
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct JevResponse {
    #[serde(default)]
    answers: BTreeMap<String, JevAnswer>,
    #[serde(default)]
    usage: JevUsage,
}

#[derive(Debug, Deserialize)]
struct JevAnswer {
    #[serde(default)]
    choice: Option<String>,
    #[serde(default)]
    noul: Option<f64>,
    #[serde(default)]
    confidence: Option<f64>,
}

#[derive(Debug, Default, Deserialize)]
struct JevUsage {
    #[serde(default)]
    input_tokens: u32,
    #[serde(default)]
    output_tokens: u32,
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

fn parse_category(key: &str) -> Option<MessageCategory> {
    serde_json::from_value(Value::String(key.to_string())).ok()
}

/// Pull the Subject out of the headers and return the body separately.
///
/// Deliberately minimal: this runs on a message the pipeline already parsed,
/// and only needs a subject line and a body to summarise.
fn split_headers(message_text: &str) -> (String, &str) {
    let (headers, body) = match message_text.find("\r\n\r\n") {
        Some(i) => (&message_text[..i], &message_text[i + 4..]),
        None => match message_text.find("\n\n") {
            Some(i) => (&message_text[..i], &message_text[i + 2..]),
            None => (message_text, ""),
        },
    };

    let subject = headers
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("subject:"))
        .map(|l| l["subject:".len()..].trim().to_string())
        .unwrap_or_default();

    (subject, body)
}

/// Jev returns no prose, so the summary states what it decided rather than
/// pretending to be a description of the message.
fn summarize(
    category: MessageCategory,
    unsolicited: Option<&JevAnswer>,
    phishing: Option<&JevAnswer>,
) -> String {
    let p = |a: Option<&JevAnswer>| {
        a.and_then(|a| a.noul)
            .map(|v| format!("{v:.2}"))
            .unwrap_or_else(|| "n/a".to_string())
    };
    format!(
        "jev: {category}, unsolicited={}, phishing={}",
        p(unsolicited),
        p(phishing)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config(base_url: &str) -> LlmConfig {
        let mut c = LlmConfig {
            enabled: true,
            provider: "jev".into(),
            model: "jev-latest".into(),
            base_url: Some(base_url.to_string()),
            api_key_env: "SENTIO_TEST_JEV_KEY".into(),
            ..Default::default()
        };
        c.max_input_tokens = 2000;
        c
    }

    fn provider(base_url: &str) -> JevProvider {
        // SAFETY-adjacent: tests in this module are the only ones touching this
        // variable, and each sets it before building a provider.
        std::env::set_var("SENTIO_TEST_JEV_KEY", "test-key");
        JevProvider::new(&config(base_url)).unwrap()
    }

    /// Shaped like the live API: `choice` carries `confidence` and
    /// `probabilities`, a `noul` carries only its probability. Verified against
    /// api.typesafe.ai - a mock that puts confidence on a noul would let the
    /// gating logic look tested when it never fires in production.
    fn answer_body(category: &str, unsolicited: f64, phishing: f64, confidence: f64) -> Value {
        json!({
            "model": "jev-1.13.0",
            "answers": {
                "category": {
                    "type": "choice",
                    "choice": category,
                    "confidence": confidence,
                    "probabilities": {category: confidence},
                },
                "unsolicited": {"type": "noul", "noul": unsolicited},
                "phishing": {"type": "noul", "noul": phishing},
            },
            "usage": {"input_tokens": 296, "output_tokens": 20}
        })
    }

    #[tokio::test]
    async fn sends_the_documented_request_shape() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/systemone"))
            .and(header("Authorization", "Bearer test-key"))
            .and(body_partial_json(json!({
                "model": "jev-latest",
                "questions": {
                    "category": {"type": "choice"},
                    "unsolicited": {"type": "noul"},
                    "phishing": {"type": "noul"},
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(answer_body(
                "marketing",
                0.5,
                0.5,
                0.9,
            )))
            .mount(&server)
            .await;

        let out = provider(&server.uri())
            .classify(
                "Subject: Spring sale\r\n\r\nEverything half price.",
                "news@shop.test",
                "bob@inbox.test",
            )
            .await
            .unwrap();

        assert_eq!(out.category, MessageCategory::Marketing);
        assert_eq!(out.token_usage.prompt_tokens, 296);
        assert_eq!(out.token_usage.completion_tokens, 20);
    }

    /// `body_mode` is the whole privacy story, so each value is pinned.
    #[tokio::test]
    async fn body_mode_decides_what_leaves_the_server() {
        for (mode, expect_key, expect_content) in [
            ("none", None, false),
            ("preview", Some("body_preview"), true),
            ("full", Some("body"), true),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(answer_body("spam", 0.9, 0.1, 0.9)),
                )
                .mount(&server)
                .await;

            std::env::set_var("SENTIO_TEST_JEV_KEY", "test-key");
            let mut cfg = config(&server.uri());
            cfg.jev.body_mode = mode.to_string();
            let p = JevProvider::new(&cfg).unwrap();

            p.classify(
                "Subject: hello\r\n\r\nSECRET-TENANT-CONTENT",
                "a@b.test",
                "c@d.test",
            )
            .await
            .unwrap();

            let sent = &server.received_requests().await.unwrap()[0];
            let body: Value = sent.body_json().unwrap();
            let state = &body["state"];

            assert_eq!(state["subject"], "hello", "mode {mode}");
            assert_eq!(state["envelope_from"], "a@b.test", "mode {mode}");

            match expect_key {
                None => {
                    assert!(
                        state.get("body").is_none() && state.get("body_preview").is_none(),
                        "mode none sent body content: {state}"
                    );
                    assert!(
                        !state.to_string().contains("SECRET-TENANT-CONTENT"),
                        "mode none leaked the body: {state}"
                    );
                }
                Some(key) => {
                    assert!(state.get(key).is_some(), "mode {mode} missing {key}");
                    assert_eq!(
                        state[key]
                            .as_str()
                            .unwrap()
                            .contains("SECRET-TENANT-CONTENT"),
                        expect_content,
                        "mode {mode} content expectation"
                    );
                }
            }
        }
    }

    /// A preview is a bounded slice, not the whole body.
    #[tokio::test]
    async fn preview_mode_truncates_a_long_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(answer_body(
                "marketing",
                0.5,
                0.5,
                0.9,
            )))
            .mount(&server)
            .await;

        std::env::set_var("SENTIO_TEST_JEV_KEY", "test-key");
        let mut cfg = config(&server.uri());
        cfg.jev.preview_tokens = 10; // 10 tokens ~ 40 chars
        let p = JevProvider::new(&cfg).unwrap();

        let long_body = "x".repeat(5000);
        p.classify(
            &format!("Subject: s\r\n\r\n{long_body}TAIL-MARKER"),
            "a@b.test",
            "c@d.test",
        )
        .await
        .unwrap();

        let sent = &server.received_requests().await.unwrap()[0];
        let body: Value = sent.body_json().unwrap();
        let preview = body["state"]["body_preview"].as_str().unwrap();
        assert!(preview.len() <= 40, "preview was {} chars", preview.len());
        assert!(
            !preview.contains("TAIL-MARKER"),
            "truncation did not happen"
        );
    }

    #[tokio::test]
    async fn a_confident_spam_verdict_raises_the_score() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(answer_body("spam", 0.98, 0.95, 0.95)),
            )
            .mount(&server)
            .await;

        let out = provider(&server.uri())
            .classify("Subject: x\r\n\r\ny", "a@b.test", "c@d.test")
            .await
            .unwrap();

        assert_eq!(out.category, MessageCategory::Spam);
        assert!(out.score_delta > 1.0, "delta was {}", out.score_delta);
    }

    #[tokio::test]
    async fn a_confident_ham_verdict_lowers_the_score() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(answer_body(
                "conversation",
                0.02,
                0.01,
                0.95,
            )))
            .mount(&server)
            .await;

        let out = provider(&server.uri())
            .classify("Subject: lunch\r\n\r\nnoon?", "a@b.test", "c@d.test")
            .await
            .unwrap();

        assert!(out.score_delta < -1.0, "delta was {}", out.score_delta);
    }

    #[tokio::test]
    async fn an_unsure_model_does_not_move_the_score() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                // High spam probability, but the model says it is not confident.
                ResponseTemplate::new(200).set_body_json(answer_body("spam", 0.95, 0.9, 0.10)),
            )
            .mount(&server)
            .await;

        let out = provider(&server.uri())
            .classify("Subject: x\r\n\r\ny", "a@b.test", "c@d.test")
            .await
            .unwrap();

        assert_eq!(out.score_delta, 0.0, "low confidence must not move a score");
    }

    /// The defaults must reach the clamp exactly at full confidence, not
    /// exceed it: weights summing past `max_score_delta` make every confident
    /// verdict saturate and discard the gradation.
    #[test]
    fn default_weights_sum_to_the_clamp() {
        let c = JevConfig::default();
        assert!(
            (c.unsolicited_weight + c.phishing_weight - c.max_score_delta).abs() < f64::EPSILON,
            "weights {} + {} should sum to max_score_delta {}",
            c.unsolicited_weight,
            c.phishing_weight,
            c.max_score_delta
        );
    }

    #[tokio::test]
    async fn the_delta_is_clamped() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(answer_body("threat", 1.0, 1.0, 1.0)),
            )
            .mount(&server)
            .await;

        let p = provider(&server.uri());
        let out = p
            .classify("Subject: x\r\n\r\ny", "a@b.test", "c@d.test")
            .await
            .unwrap();
        assert!(out.score_delta <= p.jev.max_score_delta);
    }

    #[tokio::test]
    async fn an_error_status_is_reported_with_its_code() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(429).set_body_json(json!({"error": "slow down"})))
            .mount(&server)
            .await;

        let err = provider(&server.uri())
            .classify("Subject: x\r\n\r\ny", "a@b.test", "c@d.test")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("429"), "got: {msg}");
    }

    /// The service returned 500, 503 and 529 within minutes of each other
    /// during development, so a transient status has to be retried rather than
    /// dropping the classification.
    #[tokio::test]
    async fn a_transient_status_is_retried_and_can_succeed() {
        let server = MockServer::start().await;
        // First call: overloaded. Mounted first and limited to one hit.
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(529)
                    .set_body_json(json!({"detail": {"error_type": "system_overloaded"}})),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        // Second call: the real answer.
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(answer_body("spam", 0.9, 0.2, 0.9)),
            )
            .mount(&server)
            .await;

        let out = provider(&server.uri())
            .classify("Subject: x\r\n\r\ny", "a@b.test", "c@d.test")
            .await
            .expect("should have retried past the 529");

        assert_eq!(out.category, MessageCategory::Spam);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    /// The undocumented statuses are the ones actually seen in the wild, so
    /// pin which codes retry and which do not.
    /// `config/oss.toml` ships `base_url = ""`. Read as a value rather than as
    /// absent, it built a relative URL and every live call failed in the
    /// request builder - which no mocked test caught, because they all pass a
    /// real URL.
    #[test]
    fn an_empty_base_url_means_use_the_default() {
        std::env::set_var("SENTIO_TEST_JEV_KEY", "test-key");
        for given in [Some(""), Some("   "), None] {
            let mut cfg = config("unused");
            cfg.base_url = given.map(str::to_string);
            let p = JevProvider::new(&cfg).unwrap();
            assert_eq!(
                p.base_url, DEFAULT_BASE_URL,
                "base_url {given:?} should fall back to the default"
            );
        }
    }

    #[test]
    fn a_trailing_slash_does_not_double_up() {
        std::env::set_var("SENTIO_TEST_JEV_KEY", "test-key");
        let mut cfg = config("unused");
        cfg.base_url = Some("https://example.test/".to_string());
        let p = JevProvider::new(&cfg).unwrap();
        assert_eq!(p.base_url, "https://example.test");
    }

    /// A relative base URL cannot ever work, so it must fail once rather than
    /// burning the whole retry budget on every message.
    #[tokio::test]
    async fn a_request_that_cannot_be_built_is_not_retried() {
        std::env::set_var("SENTIO_TEST_JEV_KEY", "test-key");
        let mut cfg = config("unused");
        cfg.base_url = Some("not-a-url".to_string());
        cfg.jev.max_attempts = 3;
        let p = JevProvider::new(&cfg).unwrap();

        let started = std::time::Instant::now();
        let err = p
            .classify("Subject: x\r\n\r\ny", "a@b.test", "c@d.test")
            .await
            .unwrap_err();
        let elapsed = started.elapsed();

        assert!(err.to_string().contains("jev request failed"));
        // Retrying three times would have slept ~900ms first.
        assert!(
            elapsed < Duration::from_millis(250),
            "a builder error was retried: took {elapsed:?}"
        );
    }

    #[test]
    fn transient_covers_the_statuses_observed_not_just_the_documented_ones() {
        // Documented as retryable.
        assert!(JevProvider::is_transient(429));
        assert!(JevProvider::is_transient(529));
        // Undocumented, but observed from the live service.
        assert!(JevProvider::is_transient(500));
        assert!(JevProvider::is_transient(503));
        // Deterministic: retrying changes nothing.
        assert!(!JevProvider::is_transient(401));
        assert!(!JevProvider::is_transient(422));
        assert!(!JevProvider::is_transient(400));
    }

    /// A bad key fails the same way every time, so retrying it just wastes
    /// time on every message.
    #[tokio::test]
    async fn a_permanent_status_is_not_retried() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({"detail": "bad key"})))
            .mount(&server)
            .await;

        let err = provider(&server.uri())
            .classify("Subject: x\r\n\r\ny", "a@b.test", "c@d.test")
            .await
            .unwrap_err();

        assert!(err.to_string().contains("401"));
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            1,
            "401 must not be retried"
        );
    }

    /// Their reference asks for exponential backoff, so measure that the gaps
    /// actually grow rather than trusting the arithmetic.
    #[tokio::test]
    async fn backoff_grows_between_attempts() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(529))
            .mount(&server)
            .await;

        std::env::set_var("SENTIO_TEST_JEV_KEY", "test-key");
        let mut cfg = config(&server.uri());
        cfg.jev.max_attempts = 3;
        let p = JevProvider::new(&cfg).unwrap();

        let started = std::time::Instant::now();
        let _ = p
            .classify("Subject: x\r\n\r\ny", "a@b.test", "c@d.test")
            .await;
        let elapsed = started.elapsed();

        // Two sleeps between three attempts: 300ms then 600ms.
        assert!(
            elapsed >= Duration::from_millis(900),
            "expected at least 900ms of backoff, took {elapsed:?}"
        );
        // Guards against an accidental multiplication blow-up.
        assert!(
            elapsed < Duration::from_secs(5),
            "backoff ran long: {elapsed:?}"
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn retries_give_up_after_max_attempts() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(529))
            .mount(&server)
            .await;

        std::env::set_var("SENTIO_TEST_JEV_KEY", "test-key");
        let mut cfg = config(&server.uri());
        cfg.jev.max_attempts = 2;
        let p = JevProvider::new(&cfg).unwrap();

        let err = p
            .classify("Subject: x\r\n\r\ny", "a@b.test", "c@d.test")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("529"));
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn an_unknown_category_falls_back_to_other() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(answer_body(
                "something-new",
                0.5,
                0.5,
                0.9,
            )))
            .mount(&server)
            .await;

        let out = provider(&server.uri())
            .classify("Subject: x\r\n\r\ny", "a@b.test", "c@d.test")
            .await
            .unwrap();
        assert_eq!(out.category, MessageCategory::Other);
    }

    // ──────────────────────────────────────────────────────────────────────
    // Live API
    // ──────────────────────────────────────────────────────────────────────

    /// Hits the real api.typesafe.ai. Ignored by default; needs a key:
    ///
    ///   SENTIO_JEV_API_KEY=... cargo test -p sentio-llm -- --ignored live_api
    ///
    /// Asserts the model separates obvious phishing from obvious ham, and that
    /// the delta moves in the right direction for each. Deliberately not
    /// asserting exact probabilities - those are the vendor's to change.
    #[tokio::test]
    #[ignore = "calls the live TypeSafe API and costs money"]
    async fn live_api_separates_phishing_from_conversation() {
        if std::env::var("SENTIO_JEV_API_KEY").is_err() {
            panic!("set SENTIO_JEV_API_KEY to run this test");
        }

        let mut cfg = LlmConfig {
            enabled: true,
            provider: "jev".into(),
            model: "jev-latest".into(),
            base_url: None,
            api_key_env: "SENTIO_JEV_API_KEY".into(),
            ..Default::default()
        };
        cfg.max_input_tokens = 2000;
        cfg.jev.body_mode = "preview".into();
        let p = JevProvider::new(&cfg).unwrap();

        let phish = p
            .classify(
                "Subject: URGENT: verify your account now\r\n\r\n\
                 Click here to confirm your password or your account will be \
                 closed within 24 hours.",
                "security@paypa1-support.example",
                "bob@inbox.test",
            )
            .await
            .expect("live phishing classification");

        let ham = p
            .classify(
                "Subject: Re: lunch tomorrow\r\n\r\n\
                 Works for me - shall we say 12:30 at the usual place? \
                 I will book a table.",
                "alice@colleague.test",
                "bob@inbox.test",
            )
            .await
            .expect("live ham classification");

        println!(
            "  phishing -> {:?} delta={:+.2}",
            phish.category, phish.score_delta
        );
        println!(
            "  ham      -> {:?} delta={:+.2}",
            ham.category, ham.score_delta
        );
        println!("  tokens: {} in", phish.token_usage.prompt_tokens);

        assert!(
            matches!(
                phish.category,
                MessageCategory::Threat | MessageCategory::Spam
            ),
            "expected threat or spam, got {:?}",
            phish.category
        );
        assert!(
            phish.score_delta > 0.0,
            "phishing should raise the score, got {}",
            phish.score_delta
        );

        assert!(
            matches!(ham.category, MessageCategory::Conversation),
            "expected conversation, got {:?}",
            ham.category
        );
        assert!(
            ham.score_delta < 0.0,
            "ordinary mail should lower the score, got {}",
            ham.score_delta
        );
    }

    #[test]
    fn split_headers_finds_the_subject_either_line_ending() {
        let (s, b) = split_headers("From: a@b\r\nSubject: Hi there\r\n\r\nbody text");
        assert_eq!(s, "Hi there");
        assert_eq!(b, "body text");

        let (s, b) = split_headers("Subject: Bare newlines\n\nbody");
        assert_eq!(s, "Bare newlines");
        assert_eq!(b, "body");

        let (s, b) = split_headers("no headers at all");
        assert_eq!(s, "");
        assert_eq!(b, "");
    }
}
