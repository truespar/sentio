//! REST client for the Sentio API used by the MCP tool layer.

use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("API returned {status}: {body}")]
    Response { status: u16, body: Value },
}

impl ApiError {
    /// Map an API error into a short message suitable for surfacing to the
    /// calling agent inside a tool result.
    pub fn message(&self) -> String {
        match self {
            ApiError::Http(e) => e.to_string(),
            ApiError::Response { status, body } => {
                let detail = body
                    .pointer("/error/message")
                    .or_else(|| body.pointer("/error"))
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| body.to_string());
                format!("sentio api {status}: {detail}")
            }
        }
    }
}

#[derive(Clone)]
pub struct SentioClient {
    http: reqwest::Client,
    base_url: String,
    api_key: String,
}

impl SentioClient {
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_key: api_key.into(),
        }
    }

    pub async fn get(&self, path: &str, query: &[(&str, &str)]) -> Result<Value, ApiError> {
        let mut req = self.http.get(format!("{}{path}", self.base_url));
        for (k, v) in query {
            if !v.is_empty() {
                req = req.query(&[(k, v)]);
            }
        }
        self.execute(req).await
    }

    pub async fn post(&self, path: &str, body: Value) -> Result<Value, ApiError> {
        let req = self
            .http
            .post(format!("{}{path}", self.base_url))
            .json(&body);
        self.execute(req).await
    }

    async fn execute(&self, req: reqwest::RequestBuilder) -> Result<Value, ApiError> {
        let req = req.bearer_auth(&self.api_key);
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let body: Value = resp.json().await?;
        if (200..300).contains(&status) {
            Ok(body)
        } else {
            Err(ApiError::Response { status, body })
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::SentioClient;

    #[tokio::test]
    async fn get_sends_bearer_token_and_unwraps_data() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/messages"))
            .and(header("Authorization", "Bearer key-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": [{"id": "abc"}]
            })))
            .mount(&server)
            .await;

        let client = SentioClient::new(server.uri(), "key-123");
        let resp = client
            .get("/v1/messages", &[("limit", "10")])
            .await
            .unwrap();

        assert_eq!(resp["data"][0]["id"], "abc");
    }

    #[tokio::test]
    async fn error_responses_carry_status_and_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages/send"))
            .respond_with(ResponseTemplate::new(422).set_body_json(json!({
                "error": {"message": "from address is required"}
            })))
            .mount(&server)
            .await;

        let client = SentioClient::new(server.uri(), "k");
        let err = client
            .post("/v1/messages/send", json!({}))
            .await
            .unwrap_err();

        assert!(err.message().contains("422"));
        assert!(err.message().contains("from address is required"));
    }
}
