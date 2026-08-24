//! MCP tools exposing Sentio email operations to agents.

use rmcp::{
    handler::server::wrapper::Parameters, model::*, schemars, tool, tool_handler, tool_router,
    ErrorData as McpError, ServerHandler,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::SentioClient;

fn data(resp: Value) -> Result<String, McpError> {
    to_json(resp.get("data").cloned().unwrap_or(resp))
}

fn to_json(value: Value) -> Result<String, McpError> {
    serde_json::to_string_pretty(&value).map_err(|e| McpError::internal_error(e.to_string(), None))
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListMessagesParams {
    /// Filter by status: queued, sent, delivered, bounced, failed
    #[serde(default)]
    pub status: String,
    /// Filter by direction: inbound or outbound
    #[serde(default)]
    pub direction: String,
    /// Maximum number of messages to return (1-1000)
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Number of messages to skip
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetMessageParams {
    /// UUID of the message
    pub id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SendMessageParams {
    /// Sender address, e.g. agent@example.com (domain must exist in Sentio)
    pub from: String,
    /// Recipient addresses
    pub to: Vec<String>,
    /// CC recipients
    #[serde(default)]
    pub cc: Vec<String>,
    /// BCC recipients
    #[serde(default)]
    pub bcc: Vec<String>,
    /// Subject line
    pub subject: String,
    /// Plain-text body
    #[serde(default)]
    pub text: Option<String>,
    /// HTML body
    #[serde(default)]
    pub html: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReplyMessageParams {
    /// UUID of the inbound message to reply to
    pub id: String,
    /// Sender address for the reply, e.g. agent@example.com (domain must exist in Sentio)
    pub from: String,
    /// Reply body (plain text)
    pub text: String,
    /// Reply body (HTML); included alongside text when provided
    #[serde(default)]
    pub html: Option<String>,
    /// Additional CC recipients beyond the original sender
    #[serde(default)]
    pub cc: Vec<String>,
}

/// Extract the bare email address from a header_from value such as
/// `"Jane Doe" <jane@example.com>`, `<jane@example.com>`, or `jane@example.com`.
fn extract_address(header_from: &str) -> Option<String> {
    if let Some(open) = header_from.rfind('<') {
        let close = header_from[open..].find('>')?;
        return Some(header_from[open + 1..open + close].trim().to_string());
    }
    Some(header_from.trim().to_string()).filter(|a| a.contains('@'))
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateMailboxParams {
    /// UUID of the domain that will host the mailbox
    pub domain_id: String,
    /// Local part of the address, e.g. "agent" for agent@example.com
    pub local_part: String,
    /// Display name for the mailbox owner
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Clone)]
pub struct SentioMcpServer {
    client: SentioClient,
}

#[tool_router]
impl SentioMcpServer {
    pub fn new(client: SentioClient) -> Self {
        Self { client }
    }

    /// List recent messages for the authenticated tenant.
    #[tool(description = "List recent email messages (inbound and outbound)")]
    async fn list_messages(
        &self,
        Parameters(params): Parameters<ListMessagesParams>,
    ) -> Result<String, McpError> {
        let mut query = vec![
            ("status", params.status),
            ("direction", params.direction),
            ("limit", params.limit.to_string()),
            ("offset", params.offset.to_string()),
        ];
        query.retain(|(_, v)| !v.is_empty());
        let refs: Vec<(&str, &str)> = query.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let resp = self.client.get("/v1/messages", &refs).await;
        to_json(resp.unwrap_or_else(|e| json!({"error": {"message": e.message()}})))
    }

    /// Get a single message by ID.
    #[tool(description = "Get a single email message by ID")]
    async fn get_message(
        &self,
        Parameters(params): Parameters<GetMessageParams>,
    ) -> Result<String, McpError> {
        match self
            .client
            .get(&format!("/v1/messages/{}", params.id), &[])
            .await
        {
            Ok(resp) => data(resp),
            Err(e) => Err(McpError::internal_error(e.message(), None)),
        }
    }

    /// Send an email.
    #[tool(description = "Send an email from an owned domain address")]
    async fn send_message(
        &self,
        Parameters(params): Parameters<SendMessageParams>,
    ) -> Result<String, McpError> {
        let body = json!({
            "from": params.from,
            "to": params.to,
            "cc": params.cc,
            "bcc": params.bcc,
            "subject": params.subject,
            "text": params.text,
            "html": params.html,
        });
        match self.client.post("/v1/messages/send", body).await {
            Ok(resp) => data(resp),
            Err(e) => Err(McpError::internal_error(e.message(), None)),
        }
    }

    /// Reply to an inbound message in-thread.
    #[tool(description = "Reply to an inbound message in-thread: fetches the \
         original message, addresses the reply to its sender, and sets the \
         RFC 5322 In-Reply-To and References headers so mail clients thread it")]
    async fn reply_message(
        &self,
        Parameters(params): Parameters<ReplyMessageParams>,
    ) -> Result<String, McpError> {
        let parent = self
            .client
            .get(&format!("/v1/messages/{}", params.id), &[])
            .await
            .map_err(|e| McpError::internal_error(e.message(), None))?
            .get("data")
            .cloned()
            .unwrap_or_else(|| json!({}));

        let in_reply_to = parent["message_id_header"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                McpError::internal_error(
                    "original message has no Message-ID header; cannot thread a reply",
                    None,
                )
            })?;

        let header_from = parent["header_from"].as_str().unwrap_or_default();
        let recipient = extract_address(header_from).ok_or_else(|| {
            McpError::internal_error(
                format!("could not determine reply address from original sender '{header_from}'"),
                None,
            )
        })?;

        let subject = match parent["subject"].as_str() {
            Some(s) if s.to_ascii_lowercase().starts_with("re:") => s.to_string(),
            Some(s) => format!("Re: {s}"),
            None => "Re:".to_string(),
        };

        let body = json!({
            "from": params.from,
            "to": [recipient],
            "cc": params.cc,
            "subject": subject,
            "text": params.text,
            "html": params.html,
            // Standard reply-construction: In-Reply-To is the parent's
            // Message-ID; References chains ancestors oldest-first. The
            // REST message payload does not expose the parent's own
            // References chain, so the best available chain is the
            // parent's Message-ID alone.
            "in_reply_to": in_reply_to,
            "references": [in_reply_to],
        });

        let resp = self
            .client
            .post("/v1/messages/send", body)
            .await
            .map_err(|e| McpError::internal_error(e.message(), None))?;
        data(resp)
    }

    /// Create a mailbox on an owned domain.
    #[tool(description = "Create a new mailbox (inbox) on a verified domain")]
    async fn create_mailbox(
        &self,
        Parameters(params): Parameters<CreateMailboxParams>,
    ) -> Result<String, McpError> {
        let body = json!({
            "local_part": params.local_part,
            "display_name": params.display_name,
        });
        match self
            .client
            .post(&format!("/v1/domains/{}/mailboxes", params.domain_id), body)
            .await
        {
            Ok(resp) => data(resp),
            Err(e) => Err(McpError::internal_error(e.message(), None)),
        }
    }

    /// List mailboxes on a domain.
    #[tool(description = "List all mailboxes on one of your domains")]
    async fn list_mailboxes(
        &self,
        Parameters(params): Parameters<GetDomainParams>,
    ) -> Result<String, McpError> {
        match self
            .client
            .get(&format!("/v1/domains/{}/mailboxes", params.domain_id), &[])
            .await
        {
            Ok(resp) => data(resp),
            Err(e) => Err(McpError::internal_error(e.message(), None)),
        }
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetDomainParams {
    /// UUID of the domain
    pub domain_id: String,
}

#[tool_handler]
impl ServerHandler for SentioMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("sentio-mcp", env!("CARGO_PKG_VERSION"))
                    .with_title("Sentio Email"),
            )
            .with_instructions(
                "Tools for sending, reading, and managing email via the Sentio API. \
                 Configure SENTIO_BASE_URL and SENTIO_API_KEY before starting.",
            )
    }
}

#[cfg(test)]
mod tests {
    use super::extract_address;

    #[test]
    fn extracts_address_from_display_name_form() {
        assert_eq!(
            extract_address("\"Jane Doe\" <jane@example.com>"),
            Some("jane@example.com".into())
        );
    }

    #[test]
    fn extracts_address_from_angle_bracketed_and_bare_forms() {
        assert_eq!(
            extract_address("<jane@example.com>"),
            Some("jane@example.com".into())
        );
        assert_eq!(
            extract_address(" jane@example.com "),
            Some("jane@example.com".into())
        );
        assert_eq!(extract_address("no address here"), None);
    }
}

#[cfg(test)]
mod reply_tests {
    use super::{ReplyMessageParams, SentioClient, SentioMcpServer};
    use rmcp::handler::server::wrapper::Parameters;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn params(id: &str) -> Parameters<ReplyMessageParams> {
        Parameters(ReplyMessageParams {
            id: id.into(),
            from: "agent@example.com".into(),
            text: "Here it is.".into(),
            html: None,
            cc: vec![],
        })
    }

    #[tokio::test]
    async fn reply_threads_headers_and_addresses_original_sender() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/messages/abc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "id": "abc",
                    "message_id_header": "<parent@mail.example.com>",
                    "header_from": "\"Jane Doe\" <jane@example.com>",
                    "subject": "Quarterly report"
                }
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/v1/messages/send"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {"id": "out-1", "status": "queued"}
            })))
            .mount(&server)
            .await;

        let mcp = SentioMcpServer::new(SentioClient::new(server.uri(), "key"));
        let result = mcp.reply_message(params("abc")).await.unwrap();

        assert!(result.contains("out-1"));
        let body: serde_json::Value = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .find(|req| req.url.path() == "/v1/messages/send")
            .unwrap()
            .body_json()
            .unwrap();
        assert_eq!(body["to"][0], "jane@example.com");
        assert_eq!(body["in_reply_to"], "<parent@mail.example.com>");
        assert_eq!(body["references"][0], "<parent@mail.example.com>");
        assert_eq!(body["subject"], "Re: Quarterly report");
    }

    #[tokio::test]
    async fn reply_fails_cleanly_without_message_id() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/messages/xyz"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {"id": "xyz", "header_from": "a@b.c"}
            })))
            .mount(&server)
            .await;

        let mcp = SentioMcpServer::new(SentioClient::new(server.uri(), "key"));
        let err = mcp.reply_message(params("xyz")).await.unwrap_err();

        assert!(err.message.contains("Message-ID"));
    }
}
