use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use sentio_core::ids::WebhookDeliveryLogId;
use sentio_core::traits::{
    NewWebhook, WebhookDeliveryLogRecord, WebhookDeliveryLogRepository, WebhookRecord,
    WebhookRepository, WebhookUpdate,
};
use sentio_core::webhook::{WebhookId, WebhookStatus};
use sentio_store::postgres::{PgWebhookDeliveryLogRepository, PgWebhookRepository};
use sentio_webhooks::signing;

use crate::auth::AuthContext;
use crate::errors::{ApiError, ErrorResponse};
use crate::extract::PaginationParams;
use crate::response::{data, DataResponse};
use crate::state::AppState;

// ──────────────────────────────────────────────────────────────────────────────
// Request / Response types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateWebhookRequest {
    pub url: String,
    pub event_types: Vec<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateWebhookRequest {
    pub url: String,
    pub event_types: Vec<String>,
    pub status: WebhookStatus,
}

#[derive(Serialize, utoipa::ToSchema)]
struct WebhookResponse {
    id: WebhookId,
    url: String,
    event_types: Vec<String>,
    signing_secret: String,
    status: WebhookStatus,
    failure_count: i32,
    last_success_at: Option<DateTime<Utc>>,
    last_failure_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<WebhookRecord> for WebhookResponse {
    fn from(r: WebhookRecord) -> Self {
        Self {
            id: r.id,
            url: r.url,
            event_types: r.event_types,
            signing_secret: r.signing_secret,
            status: r.status,
            failure_count: r.failure_count,
            last_success_at: r.last_success_at,
            last_failure_at: r.last_failure_at,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Serialize, utoipa::ToSchema)]
struct DeliveryLogResponse {
    id: WebhookDeliveryLogId,
    webhook_id: WebhookId,
    event_type: String,
    http_status: Option<i32>,
    response_body: Option<String>,
    attempt_number: i32,
    delivered_at: Option<DateTime<Utc>>,
    failed_at: Option<DateTime<Utc>>,
    error_message: Option<String>,
    created_at: DateTime<Utc>,
}

impl From<WebhookDeliveryLogRecord> for DeliveryLogResponse {
    fn from(r: WebhookDeliveryLogRecord) -> Self {
        Self {
            id: r.id,
            webhook_id: r.webhook_id,
            event_type: r.event_type,
            http_status: r.http_status,
            response_body: r.response_body,
            attempt_number: r.attempt_number,
            delivered_at: r.delivered_at,
            failed_at: r.failed_at,
            error_message: r.error_message,
            created_at: r.created_at,
        }
    }
}

#[derive(Serialize, utoipa::ToSchema)]
struct TestWebhookResponse {
    success: bool,
    http_status: Option<u16>,
    response_body: Option<String>,
    error: Option<String>,
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/webhooks
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/webhooks",
    tag = "Webhooks",
    security(("bearer" = [])),
    request_body = CreateWebhookRequest,
    responses(
        (status = 200, body = DataResponse<WebhookResponse>),
    ),
)]
pub async fn create_webhook(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(body): Json<CreateWebhookRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("webhooks:write")?;

    if body.url.is_empty() {
        return Err(ApiError::Validation("url is required".into()));
    }
    if body.event_types.is_empty() {
        return Err(ApiError::Validation(
            "at least one event_type is required".into(),
        ));
    }

    // Generate signing secret (32 random bytes → 64 hex chars)
    let signing_secret = {
        use rand::RngExt;
        let bytes: [u8; 32] = rand::rng().random();
        format!(
            "whsec_{}",
            bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        )
    };

    let repo = PgWebhookRepository::new(state.pool.clone());
    let id = repo
        .create(NewWebhook {
            tenant_id: auth.tenant_id,
            url: body.url,
            event_types: body.event_types,
            signing_secret,
        })
        .await?;

    // Fetch the full record to return
    let record = repo.get(id).await?;
    Ok(data(WebhookResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/webhooks
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/webhooks",
    tag = "Webhooks",
    security(("bearer" = [])),
    responses(
        (status = 200, body = DataResponse<Vec<WebhookResponse>>),
    ),
)]
pub async fn list_webhooks(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("webhooks:read")?;

    let repo = PgWebhookRepository::new(state.pool.clone());
    let records = repo.list_by_tenant(auth.tenant_id).await?;
    let webhooks: Vec<WebhookResponse> = records.into_iter().map(Into::into).collect();

    Ok(data(webhooks))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/webhooks/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/webhooks/{id}",
    tag = "Webhooks",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,)),
    responses(
        (status = 200, body = DataResponse<WebhookResponse>),
        (status = 404, body = ErrorResponse),
    ),
)]
pub async fn get_webhook(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("webhooks:read")?;

    let repo = PgWebhookRepository::new(state.pool.clone());
    let record = repo.get(WebhookId(id)).await?;

    if record.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("webhook not found".into()));
    }

    Ok(data(WebhookResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// PUT /v1/webhooks/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    put,
    path = "/v1/webhooks/{id}",
    tag = "Webhooks",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,)),
    request_body = UpdateWebhookRequest,
    responses(
        (status = 200, body = DataResponse<WebhookResponse>),
    ),
)]
pub async fn update_webhook(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<UpdateWebhookRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("webhooks:write")?;

    let repo = PgWebhookRepository::new(state.pool.clone());

    // Verify ownership
    let record = repo.get(WebhookId(id)).await?;
    if record.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("webhook not found".into()));
    }

    repo.update(
        WebhookId(id),
        WebhookUpdate {
            url: body.url,
            event_types: body.event_types,
            status: body.status,
        },
    )
    .await?;

    let updated = repo.get(WebhookId(id)).await?;
    Ok(data(WebhookResponse::from(updated)))
}

// ──────────────────────────────────────────────────────────────────────────────
// DELETE /v1/webhooks/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    delete,
    path = "/v1/webhooks/{id}",
    tag = "Webhooks",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,)),
    responses(
        (status = 204),
    ),
)]
pub async fn delete_webhook(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("webhooks:write")?;

    let repo = PgWebhookRepository::new(state.pool.clone());

    // Verify ownership
    let record = repo.get(WebhookId(id)).await?;
    if record.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("webhook not found".into()));
    }

    repo.delete(WebhookId(id)).await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/webhooks/{id}/test
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/webhooks/{id}/test",
    tag = "Webhooks",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,)),
    responses(
        (status = 200, body = DataResponse<TestWebhookResponse>),
    ),
)]
pub async fn test_webhook(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("webhooks:write")?;

    let repo = PgWebhookRepository::new(state.pool.clone());
    let record = repo.get(WebhookId(id)).await?;

    if record.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("webhook not found".into()));
    }

    // Build test payload
    let test_payload = serde_json::json!({
        "event_type": "test",
        "tenant_id": auth.tenant_id.to_string(),
        "message": "This is a test webhook event from Sentio SMTP",
        "timestamp": Utc::now().to_rfc3339(),
    });
    let body_bytes =
        serde_json::to_vec(&test_payload).map_err(|e| ApiError::Internal(e.to_string()))?;

    // Sign the payload
    let sig = signing::build_signature(&record.signing_secret, &body_bytes);

    // Send the request
    let client = reqwest::Client::new();
    let result = client
        .post(&record.url)
        .header("Content-Type", "application/json")
        .header(signing::HEADER_TIMESTAMP, sig.timestamp.to_string())
        .header(signing::HEADER_NONCE, &sig.nonce)
        .header(signing::HEADER_SIGNATURE, &sig.signature)
        .header(signing::HEADER_EVENT, "test")
        .body(body_bytes)
        .send()
        .await;

    match result {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body_text = resp.text().await.ok();
            // Truncate response body for the API response
            let truncated = body_text.map(|b| {
                if b.len() > 1024 {
                    format!("{}...", &b[..1024])
                } else {
                    b
                }
            });

            Ok(data(TestWebhookResponse {
                success: (200..300).contains(&status),
                http_status: Some(status),
                response_body: truncated,
                error: None,
            }))
        }
        Err(err) => Ok(data(TestWebhookResponse {
            success: false,
            http_status: None,
            response_body: None,
            error: Some(err.to_string()),
        })),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/webhooks/{id}/deliveries
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/webhooks/{id}/deliveries",
    tag = "Webhooks",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,), PaginationParams),
    responses(
        (status = 200, body = DataResponse<Vec<DeliveryLogResponse>>),
    ),
)]
pub async fn list_deliveries(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
    Query(params): Query<PaginationParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("webhooks:read")?;

    // Verify ownership
    let webhook_repo = PgWebhookRepository::new(state.pool.clone());
    let record = webhook_repo.get(WebhookId(id)).await?;
    if record.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("webhook not found".into()));
    }

    let params = params.validated();
    let log_repo = PgWebhookDeliveryLogRepository::new(state.pool.clone());
    let records = log_repo
        .list_by_webhook(WebhookId(id), params.limit, params.offset)
        .await?;

    let deliveries: Vec<DeliveryLogResponse> = records.into_iter().map(Into::into).collect();
    Ok(data(deliveries))
}
