use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use sentio_abuse::KvConn;
use serde::Serialize;

use crate::state::AppState;

#[derive(Serialize, utoipa::ToSchema)]
struct HealthResponse {
    #[schema(value_type = String)]
    status: &'static str,
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /health/live - always returns 200
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/health/live",
    tag = "Health",
    responses(
        (status = 200, body = HealthResponse),
    )
)]
pub async fn liveness() -> impl IntoResponse {
    Json(HealthResponse { status: "ok" })
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /health/ready - checks DB + KV connectivity
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
struct ReadyResponse {
    #[schema(value_type = String)]
    status: &'static str,
    #[schema(value_type = String)]
    database: &'static str,
    #[schema(value_type = String)]
    kv: &'static str,
}

#[utoipa::path(
    get,
    path = "/health/ready",
    tag = "Health",
    responses(
        (status = 200, body = ReadyResponse),
        (status = 503, body = ReadyResponse),
    )
)]
pub async fn readiness(State(state): State<AppState>) -> impl IntoResponse {
    // Check database
    let db_ok = sqlx::query("SELECT 1").execute(&state.pool).await.is_ok();

    // Check KV
    let kv_ok = if let Some(ref kv) = state.kv {
        kv.ping().await.is_ok()
    } else {
        false
    };

    let all_ok = db_ok && kv_ok;

    let body = ReadyResponse {
        status: if all_ok { "ok" } else { "degraded" },
        database: if db_ok { "ok" } else { "unavailable" },
        kv: if kv_ok { "ok" } else { "unavailable" },
    };

    if all_ok {
        (StatusCode::OK, Json(body))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(body))
    }
}
