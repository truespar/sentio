use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::Json;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use sentio_core::ids::{DmarcReportId, FblReportId, TlsrptReportId};
use sentio_core::message::{DomainId, MessageDirection};
use sentio_core::report::{ComplaintType, TlsrptPolicyType};
use sentio_core::traits::{
    DmarcReportRecord, DmarcReportRepository, FblReportRecord, FblReportRepository, SpamTrainer,
    TlsrptReportRecord, TlsrptReportRepository,
};
use sentio_spam::RspamdScorer;
use sentio_store::postgres::{
    PgDmarcReportRepository, PgFblReportRepository, PgTlsrptReportRepository,
};

use crate::auth::AuthContext;
use crate::errors::{ApiError, ErrorResponse};
use crate::extract::PaginationParams;
use crate::response::{data, DataResponse};
use crate::state::AppState;

// ──────────────────────────────────────────────────────────────────────────────
// Spam training request
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
pub struct TrainRequest {
    pub raw_message: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/spam/train/ham
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/spam/train/ham",
    tag = "Spam Training",
    security(("bearer" = [])),
    request_body = TrainRequest,
    responses(
        (status = 200, description = "Message learned as ham"),
        (status = 401, body = ErrorResponse),
    )
)]
pub async fn train_ham(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(body): Json<TrainRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("spam:write")?;

    let raw = base64::engine::general_purpose::STANDARD
        .decode(&body.raw_message)
        .map_err(|e| ApiError::Validation(format!("invalid base64: {e}")))?;

    let scorer =
        RspamdScorer::new(&state.config.spam).map_err(|e| ApiError::Internal(e.to_string()))?;

    scorer
        .learn_ham(&raw)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(data(serde_json::json!({ "status": "learned_ham" })))
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/spam/train/spam
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/spam/train/spam",
    tag = "Spam Training",
    security(("bearer" = [])),
    request_body = TrainRequest,
    responses(
        (status = 200, description = "Message learned as spam"),
        (status = 401, body = ErrorResponse),
    )
)]
pub async fn train_spam(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(body): Json<TrainRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("spam:write")?;

    let raw = base64::engine::general_purpose::STANDARD
        .decode(&body.raw_message)
        .map_err(|e| ApiError::Validation(format!("invalid base64: {e}")))?;

    let scorer =
        RspamdScorer::new(&state.config.spam).map_err(|e| ApiError::Internal(e.to_string()))?;

    scorer
        .learn_spam(&raw)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(data(serde_json::json!({ "status": "learned_spam" })))
}

// ──────────────────────────────────────────────────────────────────────────────
// DMARC report responses
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
struct DmarcReportResponse {
    id: DmarcReportId,
    domain_id: DomainId,
    direction: MessageDirection,
    report_id: String,
    org_name: Option<String>,
    date_begin: DateTime<Utc>,
    date_end: DateTime<Utc>,
    #[schema(value_type = Option<String>)]
    source_ip: Option<IpAddr>,
    total_count: i32,
    dkim_pass: i32,
    dkim_fail: i32,
    spf_pass: i32,
    spf_fail: i32,
    dmarc_pass: i32,
    dmarc_fail: i32,
    created_at: DateTime<Utc>,
}

impl From<DmarcReportRecord> for DmarcReportResponse {
    fn from(r: DmarcReportRecord) -> Self {
        Self {
            id: r.id,
            domain_id: r.domain_id,
            direction: r.direction,
            report_id: r.report_id,
            org_name: r.org_name,
            date_begin: r.date_begin,
            date_end: r.date_end,
            source_ip: r.source_ip,
            total_count: r.total_count,
            dkim_pass: r.dkim_pass,
            dkim_fail: r.dkim_fail,
            spf_pass: r.spf_pass,
            spf_fail: r.spf_fail,
            dmarc_pass: r.dmarc_pass,
            dmarc_fail: r.dmarc_fail,
            created_at: r.created_at,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/reports/dmarc
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/reports/dmarc",
    tag = "Reports",
    security(("bearer" = [])),
    params(PaginationParams),
    responses(
        (status = 200, body = DataResponse<Vec<DmarcReportResponse>>),
        (status = 401, body = ErrorResponse),
    )
)]
pub async fn list_dmarc_reports(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<PaginationParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("reports:read")?;

    let params = params.validated();
    let repo = PgDmarcReportRepository::new(state.pool.clone());
    let records = repo
        .list_by_tenant(auth.tenant_id, params.limit, params.offset)
        .await?;
    let reports: Vec<DmarcReportResponse> = records.into_iter().map(Into::into).collect();

    Ok(data(reports))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/reports/dmarc/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/reports/dmarc/{id}",
    tag = "Reports",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,)),
    responses(
        (status = 200, body = DataResponse<DmarcReportResponse>),
        (status = 404, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
    )
)]
pub async fn get_dmarc_report(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("reports:read")?;

    let repo = PgDmarcReportRepository::new(state.pool.clone());
    let record = repo.get(DmarcReportId(id)).await?;

    if record.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("DMARC report not found".into()));
    }

    Ok(data(DmarcReportResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// FBL report responses
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
struct FblReportResponse {
    id: FblReportId,
    complained_recipient: String,
    complaint_type: ComplaintType,
    feedback_type: Option<String>,
    #[schema(value_type = Option<String>)]
    source_ip: Option<IpAddr>,
    arrival_date: Option<DateTime<Utc>>,
    auto_suppressed: bool,
    processed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl From<FblReportRecord> for FblReportResponse {
    fn from(r: FblReportRecord) -> Self {
        Self {
            id: r.id,
            complained_recipient: r.complained_recipient,
            complaint_type: r.complaint_type,
            feedback_type: r.feedback_type,
            source_ip: r.source_ip,
            arrival_date: r.arrival_date,
            auto_suppressed: r.auto_suppressed,
            processed_at: r.processed_at,
            created_at: r.created_at,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/reports/fbl
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/reports/fbl",
    tag = "Reports",
    security(("bearer" = [])),
    params(PaginationParams),
    responses(
        (status = 200, body = DataResponse<Vec<FblReportResponse>>),
        (status = 401, body = ErrorResponse),
    )
)]
pub async fn list_fbl_reports(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<PaginationParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("reports:read")?;

    let params = params.validated();
    let repo = PgFblReportRepository::new(state.pool.clone());
    let records = repo
        .list_by_tenant(auth.tenant_id, params.limit, params.offset)
        .await?;
    let reports: Vec<FblReportResponse> = records.into_iter().map(Into::into).collect();

    Ok(data(reports))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/reports/fbl/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/reports/fbl/{id}",
    tag = "Reports",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,)),
    responses(
        (status = 200, body = DataResponse<FblReportResponse>),
        (status = 404, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
    )
)]
pub async fn get_fbl_report(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("reports:read")?;

    let repo = PgFblReportRepository::new(state.pool.clone());
    let record = repo.get(FblReportId(id)).await?;

    if record.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("FBL report not found".into()));
    }

    Ok(data(FblReportResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/reports/fbl/{id}/process
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/reports/fbl/{id}/process",
    tag = "Reports",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,)),
    responses(
        (status = 200, body = DataResponse<FblReportResponse>),
        (status = 404, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
    )
)]
pub async fn process_fbl_report(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("reports:write")?;

    let repo = PgFblReportRepository::new(state.pool.clone());

    // Verify ownership
    let record = repo.get(FblReportId(id)).await?;
    if record.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("FBL report not found".into()));
    }

    repo.mark_processed(FblReportId(id)).await?;

    let updated = repo.get(FblReportId(id)).await?;
    Ok(data(FblReportResponse::from(updated)))
}

// ──────────────────────────────────────────────────────────────────────────────
// TLS-RPT report responses
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
struct TlsrptReportResponse {
    id: TlsrptReportId,
    domain_id: DomainId,
    direction: MessageDirection,
    report_id: String,
    org_name: Option<String>,
    date_begin: DateTime<Utc>,
    date_end: DateTime<Utc>,
    policy_type: TlsrptPolicyType,
    policy_domain: Option<String>,
    total_success: i32,
    total_failure: i32,
    #[schema(value_type = Option<Object>)]
    failure_details: Option<serde_json::Value>,
    created_at: DateTime<Utc>,
}

impl From<TlsrptReportRecord> for TlsrptReportResponse {
    fn from(r: TlsrptReportRecord) -> Self {
        Self {
            id: r.id,
            domain_id: r.domain_id,
            direction: r.direction,
            report_id: r.report_id,
            org_name: r.org_name,
            date_begin: r.date_begin,
            date_end: r.date_end,
            policy_type: r.policy_type,
            policy_domain: r.policy_domain,
            total_success: r.total_success,
            total_failure: r.total_failure,
            failure_details: r.failure_details,
            created_at: r.created_at,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/reports/tlsrpt
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/reports/tlsrpt",
    tag = "Reports",
    security(("bearer" = [])),
    params(PaginationParams),
    responses(
        (status = 200, body = DataResponse<Vec<TlsrptReportResponse>>),
        (status = 401, body = ErrorResponse),
    )
)]
pub async fn list_tlsrpt_reports(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<PaginationParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("reports:read")?;

    let params = params.validated();
    let repo = PgTlsrptReportRepository::new(state.pool.clone());
    let records = repo
        .list_by_tenant(auth.tenant_id, params.limit, params.offset)
        .await?;
    let reports: Vec<TlsrptReportResponse> = records.into_iter().map(Into::into).collect();

    Ok(data(reports))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/reports/tlsrpt/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/reports/tlsrpt/{id}",
    tag = "Reports",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,)),
    responses(
        (status = 200, body = DataResponse<TlsrptReportResponse>),
        (status = 404, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
    )
)]
pub async fn get_tlsrpt_report(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("reports:read")?;

    let repo = PgTlsrptReportRepository::new(state.pool.clone());
    let record = repo.get(TlsrptReportId(id)).await?;

    if record.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("TLS-RPT report not found".into()));
    }

    Ok(data(TlsrptReportResponse::from(record)))
}
