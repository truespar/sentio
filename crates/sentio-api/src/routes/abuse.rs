use std::net::IpAddr;

use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use sentio_abuse::{BanChecker, KvConn, ReputationTracker, Whitelist};
use sentio_core::config::AbuseConfig;
use sentio_store::RedisPool;

use crate::auth::AuthContext;
use crate::errors::{ApiError, ErrorResponse};
use crate::response::{data, DataResponse};
use crate::state::AppState;

fn require_kv(state: &AppState) -> Result<RedisPool, ApiError> {
    state
        .kv
        .clone()
        .ok_or_else(|| ApiError::Internal("KV backend not configured".into()))
}

fn parse_ip(ip: &str) -> Result<IpAddr, ApiError> {
    ip.parse()
        .map_err(|_| ApiError::Validation("invalid IP address".into()))
}

// ──────────────────────────────────────────────────────────────────────────────
// Bans
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
struct BanEntry {
    ip: String,
}

/// GET /v1/admin/abuse/bans -- list currently banned IPs.
#[utoipa::path(
    get,
    path = "/v1/admin/abuse/bans",
    tag = "Abuse",
    security(("bearer" = [])),
    responses(
        (status = 200, body = DataResponse<Vec<BanEntry>>),
        (status = 401, body = ErrorResponse),
    )
)]
pub async fn list_bans(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:abuse")?;
    let redis = require_kv(&state)?;

    let keys = redis
        .scan_keys("sentio:smtp:ban:*")
        .await
        .map_err(|e| ApiError::Internal(format!("KV scan failed: {e}")))?;

    let entries: Vec<BanEntry> = keys
        .into_iter()
        .filter_map(|k| {
            k.strip_prefix("sentio:smtp:ban:")
                .map(|ip| BanEntry { ip: ip.to_string() })
        })
        .collect();

    Ok(data(entries))
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct BanRequest {
    pub ip: String,
    pub duration_secs: Option<u64>,
}

/// POST /v1/admin/abuse/bans -- ban an IP.
#[utoipa::path(
    post,
    path = "/v1/admin/abuse/bans",
    tag = "Abuse",
    security(("bearer" = [])),
    request_body = BanRequest,
    responses(
        (status = 200, description = "IP banned"),
        (status = 401, body = ErrorResponse),
        (status = 422, body = ErrorResponse),
    )
)]
pub async fn create_ban(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(req): Json<BanRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:abuse")?;
    let redis = require_kv(&state)?;
    let ip = parse_ip(&req.ip)?;

    let config = AbuseConfig::default();
    let checker = BanChecker::new(redis, &config);
    let duration = req.duration_secs.unwrap_or(config.ban_duration_secs);

    checker.ban(&ip, duration).await;

    Ok(data(
        serde_json::json!({ "status": "banned", "ip": req.ip, "duration_secs": duration }),
    ))
}

/// DELETE /v1/admin/abuse/bans/{ip} -- unban an IP.
#[utoipa::path(
    delete,
    path = "/v1/admin/abuse/bans/{ip}",
    tag = "Abuse",
    security(("bearer" = [])),
    params(("ip" = String, Path,)),
    responses(
        (status = 200, description = "IP unbanned"),
        (status = 401, body = ErrorResponse),
        (status = 422, body = ErrorResponse),
    )
)]
pub async fn delete_ban(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(ip): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:abuse")?;
    let redis = require_kv(&state)?;
    let parsed_ip = parse_ip(&ip)?;

    let config = AbuseConfig::default();
    let checker = BanChecker::new(redis, &config);
    checker.unban(&parsed_ip).await;

    Ok(data(serde_json::json!({ "status": "unbanned", "ip": ip })))
}

// ──────────────────────────────────────────────────────────────────────────────
// Whitelist
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
struct WhitelistEntry {
    ip: String,
}

/// GET /v1/admin/abuse/whitelist -- list dynamically whitelisted IPs.
#[utoipa::path(
    get,
    path = "/v1/admin/abuse/whitelist",
    tag = "Abuse",
    security(("bearer" = [])),
    responses(
        (status = 200, body = DataResponse<Vec<WhitelistEntry>>),
        (status = 401, body = ErrorResponse),
    )
)]
pub async fn list_whitelist(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:abuse")?;
    let redis = require_kv(&state)?;

    let keys = redis
        .scan_keys("sentio:smtp:whitelist:*")
        .await
        .map_err(|e| ApiError::Internal(format!("KV scan failed: {e}")))?;

    let entries: Vec<WhitelistEntry> = keys
        .into_iter()
        .filter_map(|k| {
            k.strip_prefix("sentio:smtp:whitelist:")
                .map(|ip| WhitelistEntry { ip: ip.to_string() })
        })
        .collect();

    Ok(data(entries))
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct WhitelistRequest {
    pub ip: String,
}

/// POST /v1/admin/abuse/whitelist -- add an IP to the dynamic whitelist.
#[utoipa::path(
    post,
    path = "/v1/admin/abuse/whitelist",
    tag = "Abuse",
    security(("bearer" = [])),
    request_body = WhitelistRequest,
    responses(
        (status = 200, description = "IP whitelisted"),
        (status = 401, body = ErrorResponse),
        (status = 422, body = ErrorResponse),
    )
)]
pub async fn create_whitelist(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(req): Json<WhitelistRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:abuse")?;
    let redis = require_kv(&state)?;
    let ip = parse_ip(&req.ip)?;

    let config = AbuseConfig::default();
    let wl = Whitelist::new(redis, &config);
    wl.add(&ip).await;

    Ok(data(
        serde_json::json!({ "status": "whitelisted", "ip": req.ip }),
    ))
}

/// DELETE /v1/admin/abuse/whitelist/{ip} -- remove an IP from the dynamic whitelist.
#[utoipa::path(
    delete,
    path = "/v1/admin/abuse/whitelist/{ip}",
    tag = "Abuse",
    security(("bearer" = [])),
    params(("ip" = String, Path,)),
    responses(
        (status = 200, description = "IP removed from whitelist"),
        (status = 401, body = ErrorResponse),
        (status = 422, body = ErrorResponse),
    )
)]
pub async fn delete_whitelist(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(ip): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:abuse")?;
    let redis = require_kv(&state)?;
    let parsed_ip = parse_ip(&ip)?;

    let config = AbuseConfig::default();
    let wl = Whitelist::new(redis, &config);
    wl.remove(&parsed_ip).await;

    Ok(data(serde_json::json!({ "status": "removed", "ip": ip })))
}

// ──────────────────────────────────────────────────────────────────────────────
// Reputation
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
struct ReputationResponse {
    ip: String,
    score: f64,
    action: String,
}

/// GET /v1/admin/abuse/reputation/{ip} -- get reputation score (with decay).
#[utoipa::path(
    get,
    path = "/v1/admin/abuse/reputation/{ip}",
    tag = "Abuse",
    security(("bearer" = [])),
    params(("ip" = String, Path,)),
    responses(
        (status = 200, body = DataResponse<ReputationResponse>),
        (status = 401, body = ErrorResponse),
        (status = 422, body = ErrorResponse),
    )
)]
pub async fn get_reputation(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(ip): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:abuse")?;
    let redis = require_kv(&state)?;
    let parsed_ip = parse_ip(&ip)?;

    let config = state.config.abuse.clone();
    let tracker = ReputationTracker::new(redis, &config);

    let score = tracker.get_score(&parsed_ip).await;
    let action = tracker.evaluate(&parsed_ip).await;

    Ok(data(ReputationResponse {
        ip,
        score,
        action: format!("{action:?}"),
    }))
}

/// POST /v1/admin/abuse/reputation/{ip}/reset -- reset reputation score to zero.
#[utoipa::path(
    post,
    path = "/v1/admin/abuse/reputation/{ip}/reset",
    tag = "Abuse",
    security(("bearer" = [])),
    params(("ip" = String, Path,)),
    responses(
        (status = 200, description = "Reputation score reset"),
        (status = 401, body = ErrorResponse),
        (status = 422, body = ErrorResponse),
    )
)]
pub async fn reset_reputation(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(ip): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("admin:abuse")?;
    let redis = require_kv(&state)?;
    let parsed_ip = parse_ip(&ip)?;

    let config = state.config.abuse.clone();
    let tracker = ReputationTracker::new(redis, &config);
    tracker.reset(&parsed_ip).await;

    Ok(data(serde_json::json!({ "status": "reset", "ip": ip })))
}
