use axum::extract::{Path, State};
use axum::http::header;
use axum::response::IntoResponse;
use base64::Engine;
use serde::Deserialize;

use sentio_core::event::EngagementEventType;
use sentio_core::message::MessageId;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{EngagementEventRepository, NewEngagementEvent};
use sentio_store::postgres::PgEngagementEventRepository;

use crate::errors::ApiError;
use crate::state::AppState;

// ──────────────────────────────────────────────────────────────────────────────
// Token formats (base64url-encoded JSON)
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct OpenToken {
    m: String,
    t: String,
}

#[derive(Deserialize)]
struct ClickToken {
    m: String,
    t: String,
    u: String,
}

// 1x1 transparent GIF (43 bytes)
const TRACKING_PIXEL: &[u8] = &[
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
];

// ──────────────────────────────────────────────────────────────────────────────
// GET /track/open/{token}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/track/open/{token}",
    tag = "Tracking",
    params(("token" = String, Path,)),
    responses(
        (status = 200, content_type = "image/gif"),
    )
)]
pub async fn track_open(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&token)
        .map_err(|_| ApiError::Validation("invalid tracking token".into()))?;

    let payload: OpenToken = serde_json::from_slice(&decoded)
        .map_err(|_| ApiError::Validation("invalid tracking token payload".into()))?;

    let message_id: uuid::Uuid = payload
        .m
        .parse()
        .map_err(|_| ApiError::Validation("invalid message_id in token".into()))?;
    let tenant_id: uuid::Uuid = payload
        .t
        .parse()
        .map_err(|_| ApiError::Validation("invalid tenant_id in token".into()))?;

    // Record open event (fire-and-forget; don't fail the pixel response)
    let repo = PgEngagementEventRepository::new(state.pool.clone());
    let _ = repo
        .insert(NewEngagementEvent {
            message_id: MessageId(message_id),
            tenant_id: TenantId(tenant_id),
            event_type: EngagementEventType::Opened,
            ip_address: None,
            user_agent: None,
            url: None,
            referer: None,
            client_name: None,
            client_version: None,
            device_type: None,
            os_name: None,
            os_version: None,
            is_bot: false,
            proxy_open: false,
            country_code: None,
            region: None,
            city: None,
        })
        .await;

    Ok((
        [
            (header::CONTENT_TYPE, "image/gif"),
            (header::CACHE_CONTROL, "no-store, no-cache, must-revalidate"),
        ],
        TRACKING_PIXEL,
    ))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /track/click/{token}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/track/click/{token}",
    tag = "Tracking",
    params(("token" = String, Path,)),
    responses(
        (status = 302),
    )
)]
pub async fn track_click(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&token)
        .map_err(|_| ApiError::Validation("invalid tracking token".into()))?;

    let payload: ClickToken = serde_json::from_slice(&decoded)
        .map_err(|_| ApiError::Validation("invalid tracking token payload".into()))?;

    let message_id: uuid::Uuid = payload
        .m
        .parse()
        .map_err(|_| ApiError::Validation("invalid message_id in token".into()))?;
    let tenant_id: uuid::Uuid = payload
        .t
        .parse()
        .map_err(|_| ApiError::Validation("invalid tenant_id in token".into()))?;

    let target_url = payload.u.clone();

    // Record click event (fire-and-forget)
    let repo = PgEngagementEventRepository::new(state.pool.clone());
    let _ = repo
        .insert(NewEngagementEvent {
            message_id: MessageId(message_id),
            tenant_id: TenantId(tenant_id),
            event_type: EngagementEventType::Clicked,
            ip_address: None,
            user_agent: None,
            url: Some(target_url.clone()),
            referer: None,
            client_name: None,
            client_version: None,
            device_type: None,
            os_name: None,
            os_version: None,
            is_bot: false,
            proxy_open: false,
            country_code: None,
            region: None,
            city: None,
        })
        .await;

    // 302 redirect to the target URL
    Ok((
        axum::http::StatusCode::FOUND,
        [(header::LOCATION, target_url)],
    ))
}
