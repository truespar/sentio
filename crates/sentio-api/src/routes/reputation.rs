use axum::extract::{Path, State};
use axum::response::IntoResponse;
use serde::Serialize;

use sentio_abuse::ReputationTracker;
use sentio_core::message::DomainId;
use sentio_core::traits::{
    DmarcReportRepository, DomainRecord, DomainRepository, FblReportRepository,
};
use sentio_store::postgres::{PgDmarcReportRepository, PgDomainRepository, PgFblReportRepository};

use crate::auth::AuthContext;
use crate::errors::{ApiError, ErrorResponse};
use crate::response::{data, DataResponse};
use crate::state::AppState;

// ──────────────────────────────────────────────────────────────────────────────
// Response types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
struct DomainReputationSummary {
    domain_id: DomainId,
    domain_name: String,
    dmarc_pass: i64,
    dmarc_fail: i64,
    dmarc_pass_rate: f64,
    fbl_complaints: i64,
}

#[derive(Serialize, utoipa::ToSchema)]
struct IpReputationResponse {
    ip: String,
    score: f64,
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/reputation/domains
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/reputation/domains",
    tag = "Reputation",
    security(("bearer" = [])),
    responses(
        (status = 200, body = DataResponse<Vec<DomainReputationSummary>>),
    ),
)]
pub async fn list_domain_reputations(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("reputation:read")?;

    let domain_repo = PgDomainRepository::new(state.pool.clone());
    let dmarc_repo = PgDmarcReportRepository::new(state.pool.clone());
    let fbl_repo = PgFblReportRepository::new(state.pool.clone());

    let domains = domain_repo.list_by_tenant(auth.tenant_id).await?;

    let mut summaries = Vec::with_capacity(domains.len());
    for domain in domains {
        let summary =
            build_domain_reputation(&dmarc_repo, &fbl_repo, auth.tenant_id, &domain).await?;
        summaries.push(summary);
    }

    Ok(data(summaries))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/reputation/domains/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/reputation/domains/{id}",
    tag = "Reputation",
    security(("bearer" = [])),
    params(
        ("id" = uuid::Uuid, Path,),
    ),
    responses(
        (status = 200, body = DataResponse<DomainReputationSummary>),
        (status = 404, body = ErrorResponse),
    ),
)]
pub async fn get_domain_reputation(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("reputation:read")?;

    let domain_repo = PgDomainRepository::new(state.pool.clone());
    let domain = domain_repo.get(DomainId(id)).await?;

    if domain.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("domain not found".into()));
    }

    let dmarc_repo = PgDmarcReportRepository::new(state.pool.clone());
    let fbl_repo = PgFblReportRepository::new(state.pool.clone());

    let summary = build_domain_reputation(&dmarc_repo, &fbl_repo, auth.tenant_id, &domain).await?;

    Ok(data(summary))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/reputation/ips/{ip}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/reputation/ips/{ip}",
    tag = "Reputation",
    security(("bearer" = [])),
    params(
        ("ip" = String, Path,),
    ),
    responses(
        (status = 200, body = DataResponse<IpReputationResponse>),
    ),
)]
pub async fn get_ip_reputation(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(ip): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("reputation:read")?;

    let parsed_ip: std::net::IpAddr = ip
        .parse()
        .map_err(|_| ApiError::Validation("invalid IP address".into()))?;

    let score = if let Some(ref kv) = state.kv {
        let config = state.config.abuse.clone();
        let tracker = ReputationTracker::new(kv.clone(), &config);
        tracker.get_score(&parsed_ip).await
    } else {
        0.0
    };

    Ok(data(IpReputationResponse { ip, score }))
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

async fn build_domain_reputation(
    dmarc_repo: &PgDmarcReportRepository,
    fbl_repo: &PgFblReportRepository,
    tenant_id: sentio_core::tenant::TenantId,
    domain: &DomainRecord,
) -> Result<DomainReputationSummary, ApiError> {
    // Fetch recent DMARC reports for this domain (up to 100)
    let dmarc_reports = dmarc_repo.list_by_domain(domain.id, 100, 0).await?;

    let mut dmarc_pass: i64 = 0;
    let mut dmarc_fail: i64 = 0;
    for report in &dmarc_reports {
        dmarc_pass += report.dmarc_pass as i64;
        dmarc_fail += report.dmarc_fail as i64;
    }

    let total = dmarc_pass + dmarc_fail;
    let dmarc_pass_rate = if total > 0 {
        dmarc_pass as f64 / total as f64
    } else {
        1.0
    };

    // Fetch recent FBL reports for complaint count
    let fbl_reports = fbl_repo.list_by_tenant(tenant_id, 1000, 0).await?;
    let fbl_complaints = fbl_reports.len() as i64;

    Ok(DomainReputationSummary {
        domain_id: domain.id,
        domain_name: domain.domain_name.clone(),
        dmarc_pass,
        dmarc_fail,
        dmarc_pass_rate,
        fbl_complaints,
    })
}
