use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use sentio_core::error::SentioError;

// ──────────────────────────────────────────────────────────────────────────────
// API Error
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ApiError {
    NotFound(String),
    Validation(String),
    Auth(String),
    RateLimit(String),
    Internal(String),
}

#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ErrorResponse {
    error: ErrorBody,
}

#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ErrorBody {
    r#type: String,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_type, message) = match self {
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg),
            ApiError::Validation(msg) => (StatusCode::UNPROCESSABLE_ENTITY, "validation", msg),
            ApiError::Auth(msg) => (StatusCode::UNAUTHORIZED, "auth", msg),
            ApiError::RateLimit(msg) => (StatusCode::TOO_MANY_REQUESTS, "rate_limit", msg),
            ApiError::Internal(msg) => {
                tracing::error!(error = %msg, "internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "internal server error".to_string(),
                )
            }
        };

        let body = ErrorResponse {
            error: ErrorBody {
                r#type: error_type.to_string(),
                message,
            },
        };

        (status, Json(body)).into_response()
    }
}

impl From<SentioError> for ApiError {
    fn from(err: SentioError) -> Self {
        match err {
            SentioError::NotFound { entity, id } => {
                ApiError::NotFound(format!("{entity} not found: {id}"))
            }
            SentioError::Validation(msg) => ApiError::Validation(msg),
            SentioError::Auth(msg) => ApiError::Auth(msg),
            SentioError::RateLimit { key } => {
                ApiError::RateLimit(format!("rate limit exceeded: {key}"))
            }
            SentioError::Database(msg) => {
                tracing::error!(error = %msg, "database error");
                ApiError::Internal("database error".to_string())
            }
            other => {
                tracing::error!(error = %other, "internal error");
                ApiError::Internal("internal error".to_string())
            }
        }
    }
}
