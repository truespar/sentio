use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use tower_http::request_id::{MakeRequestId, RequestId};

use crate::errors::ApiError;
use crate::state::AppState;

// ──────────────────────────────────────────────────────────────────────────────
// Request ID generator
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct UuidRequestId;

impl MakeRequestId for UuidRequestId {
    fn make_request_id<B>(&mut self, _request: &axum::http::Request<B>) -> Option<RequestId> {
        let id = uuid::Uuid::new_v4().to_string();
        Some(RequestId::new(HeaderValue::from_str(&id).unwrap()))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Per-tenant rate limiting middleware
// ──────────────────────────────────────────────────────────────────────────────

pub async fn rate_limit_middleware(
    state: axum::extract::State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Rate limiting is keyed by tenant_id from the auth context.
    // If no auth context is set (e.g. before auth middleware), skip rate limiting.
    if let Some(auth) = req.extensions().get::<crate::auth::AuthContext>() {
        let key = auth.tenant_id.to_string();
        if state.rate_limiter.check_key(&key).is_err() {
            return Err(ApiError::RateLimit(format!(
                "rate limit exceeded for tenant {key}"
            )));
        }
    }

    Ok(next.run(req).await)
}
