use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use sentio_core::auth::DomainStatus;
use sentio_core::ids::{TrackingCertificateId, TrackingDomainId};
use sentio_core::message::DomainId;
use sentio_core::traits::{
    NewTrackingCertificate, NewTrackingDomain, TrackingCertificateRecord,
    TrackingCertificateRepository, TrackingDomainRecord, TrackingDomainRepository,
};
use sentio_store::postgres::{PgTrackingCertificateRepository, PgTrackingDomainRepository};

use crate::auth::AuthContext;
use crate::errors::{ApiError, ErrorResponse};
use crate::response::{data, DataResponse};
use crate::state::AppState;

// ──────────────────────────────────────────────────────────────────────────────
// Request / Response types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateTrackingDomainRequest {
    pub domain_name: String,
    pub cname_target: String,
    pub domain_id: Option<uuid::Uuid>,
    #[serde(default = "default_true")]
    pub ssl_enabled: bool,
    #[serde(default = "default_true")]
    pub track_opens: bool,
    #[serde(default = "default_true")]
    pub track_clicks: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateCertificateRequest {
    pub certificate: String,
    pub intermediaries: Option<String>,
    pub private_key: String,
    pub expires_at: DateTime<Utc>,
    pub renew_after: DateTime<Utc>,
}

#[derive(Serialize, utoipa::ToSchema)]
struct TrackingDomainResponse {
    id: TrackingDomainId,
    domain_name: String,
    cname_target: String,
    domain_id: Option<DomainId>,
    dns_status: DomainStatus,
    dns_error: Option<String>,
    dns_checked_at: Option<DateTime<Utc>>,
    ssl_enabled: bool,
    track_opens: bool,
    track_clicks: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<TrackingDomainRecord> for TrackingDomainResponse {
    fn from(r: TrackingDomainRecord) -> Self {
        Self {
            id: r.id,
            domain_name: r.domain_name,
            cname_target: r.cname_target,
            domain_id: r.domain_id,
            dns_status: r.dns_status,
            dns_error: r.dns_error,
            dns_checked_at: r.dns_checked_at,
            ssl_enabled: r.ssl_enabled,
            track_opens: r.track_opens,
            track_clicks: r.track_clicks,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Serialize, utoipa::ToSchema)]
struct TrackingCertificateResponse {
    id: TrackingCertificateId,
    tracking_domain_id: TrackingDomainId,
    expires_at: DateTime<Utc>,
    renew_after: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

impl From<TrackingCertificateRecord> for TrackingCertificateResponse {
    fn from(r: TrackingCertificateRecord) -> Self {
        Self {
            id: r.id,
            tracking_domain_id: r.tracking_domain_id,
            expires_at: r.expires_at,
            renew_after: r.renew_after,
            created_at: r.created_at,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/tracking-domains
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/tracking-domains",
    tag = "Tracking Domains",
    security(("bearer" = [])),
    request_body = CreateTrackingDomainRequest,
    responses(
        (status = 200, body = DataResponse<TrackingDomainResponse>),
        (status = 401, body = ErrorResponse),
        (status = 422, body = ErrorResponse),
    )
)]
pub async fn create_tracking_domain(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(body): Json<CreateTrackingDomainRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("tracking:write")?;

    if body.domain_name.is_empty() {
        return Err(ApiError::Validation("domain_name is required".into()));
    }
    if body.cname_target.is_empty() {
        return Err(ApiError::Validation("cname_target is required".into()));
    }

    let repo = PgTrackingDomainRepository::new(state.pool.clone());
    let id = repo
        .create(NewTrackingDomain {
            tenant_id: auth.tenant_id,
            domain_id: body.domain_id.map(DomainId),
            domain_name: body.domain_name,
            cname_target: body.cname_target,
            ssl_enabled: body.ssl_enabled,
            track_opens: body.track_opens,
            track_clicks: body.track_clicks,
        })
        .await?;

    let record = repo.get(id).await?;
    Ok(data(TrackingDomainResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/tracking-domains
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/tracking-domains",
    tag = "Tracking Domains",
    security(("bearer" = [])),
    responses(
        (status = 200, body = DataResponse<Vec<TrackingDomainResponse>>),
        (status = 401, body = ErrorResponse),
    )
)]
pub async fn list_tracking_domains(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("tracking:read")?;

    let repo = PgTrackingDomainRepository::new(state.pool.clone());
    let records = repo.list_by_tenant(auth.tenant_id).await?;
    let domains: Vec<TrackingDomainResponse> = records.into_iter().map(Into::into).collect();

    Ok(data(domains))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/tracking-domains/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/tracking-domains/{id}",
    tag = "Tracking Domains",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,)),
    responses(
        (status = 200, body = DataResponse<TrackingDomainResponse>),
        (status = 404, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
    )
)]
pub async fn get_tracking_domain(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("tracking:read")?;

    let repo = PgTrackingDomainRepository::new(state.pool.clone());
    let record = repo.get(TrackingDomainId(id)).await?;

    if record.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("tracking_domain".into()));
    }

    Ok(data(TrackingDomainResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/tracking-domains/{id}/verify
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/tracking-domains/{id}/verify",
    tag = "Tracking Domains",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,)),
    responses(
        (status = 200, body = DataResponse<TrackingDomainResponse>),
        (status = 404, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
    )
)]
pub async fn verify_tracking_domain(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("tracking:write")?;

    let repo = PgTrackingDomainRepository::new(state.pool.clone());
    let record = repo.get(TrackingDomainId(id)).await?;

    if record.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("tracking_domain".into()));
    }

    // Perform CNAME lookup
    let resolver = hickory_resolver::TokioResolver::builder_tokio()
        .and_then(|b| b.build())
        .unwrap_or_else(|_| {
            hickory_resolver::TokioResolver::builder_with_config(
                hickory_resolver::config::ResolverConfig::udp_and_tcp(
                    &hickory_resolver::config::GOOGLE,
                ),
                hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
            )
            .build()
            .expect("build Google DNS resolver")
        });

    let (status, error): (DomainStatus, Option<String>) = match resolver
        .lookup(
            &record.domain_name,
            hickory_resolver::proto::rr::RecordType::CNAME,
        )
        .await
    {
        Ok(lookup) => {
            let found_target = lookup.answers().iter().any(|record_entry| {
                record_entry.data.to_string().trim_end_matches('.')
                    == record.cname_target.trim_end_matches('.')
            });
            if found_target {
                (DomainStatus::Verified, None)
            } else {
                (
                    DomainStatus::Failed,
                    Some(format!("CNAME does not point to {}", record.cname_target)),
                )
            }
        }
        Err(e) => (
            DomainStatus::Failed,
            Some(format!("DNS lookup failed: {e}")),
        ),
    };

    repo.update_dns_status(TrackingDomainId(id), status, error.as_deref())
        .await?;

    let updated = repo.get(TrackingDomainId(id)).await?;
    Ok(data(TrackingDomainResponse::from(updated)))
}

// ──────────────────────────────────────────────────────────────────────────────
// DELETE /v1/tracking-domains/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    delete,
    path = "/v1/tracking-domains/{id}",
    tag = "Tracking Domains",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,)),
    responses(
        (status = 204, description = "Tracking domain deleted"),
        (status = 404, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
    )
)]
pub async fn delete_tracking_domain(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("tracking:write")?;

    let repo = PgTrackingDomainRepository::new(state.pool.clone());
    let record = repo.get(TrackingDomainId(id)).await?;

    if record.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("tracking_domain".into()));
    }

    repo.delete(TrackingDomainId(id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/tracking-domains/{id}/certificate
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/tracking-domains/{id}/certificate",
    tag = "Tracking Domains",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,)),
    responses(
        (status = 200, body = DataResponse<TrackingCertificateResponse>),
        (status = 404, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
    )
)]
pub async fn get_certificate(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("tracking:read")?;

    // Verify ownership
    let domain_repo = PgTrackingDomainRepository::new(state.pool.clone());
    let domain = domain_repo.get(TrackingDomainId(id)).await?;
    if domain.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("tracking_domain".into()));
    }

    let cert_repo = PgTrackingCertificateRepository::new(state.pool.clone());
    let cert = cert_repo
        .get_active_for_domain(TrackingDomainId(id))
        .await?;

    Ok(data(TrackingCertificateResponse::from(cert)))
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/tracking-domains/{id}/certificate
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/tracking-domains/{id}/certificate",
    tag = "Tracking Domains",
    security(("bearer" = [])),
    params(("id" = uuid::Uuid, Path,)),
    request_body = CreateCertificateRequest,
    responses(
        (status = 200, body = DataResponse<TrackingCertificateResponse>),
        (status = 404, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
        (status = 422, body = ErrorResponse),
    )
)]
pub async fn upload_certificate(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<CreateCertificateRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("tracking:write")?;

    // Verify ownership
    let domain_repo = PgTrackingDomainRepository::new(state.pool.clone());
    let domain = domain_repo.get(TrackingDomainId(id)).await?;
    if domain.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("tracking_domain".into()));
    }

    if body.certificate.is_empty() {
        return Err(ApiError::Validation("certificate is required".into()));
    }
    if body.private_key.is_empty() {
        return Err(ApiError::Validation("private_key is required".into()));
    }

    let cert_repo = PgTrackingCertificateRepository::new(state.pool.clone());
    let cert_id = cert_repo
        .create(NewTrackingCertificate {
            tracking_domain_id: TrackingDomainId(id),
            certificate: body.certificate,
            intermediaries: body.intermediaries,
            private_key: body.private_key,
            expires_at: body.expires_at,
            renew_after: body.renew_after,
        })
        .await?;

    let cert = cert_repo.get(cert_id).await?;
    Ok(data(TrackingCertificateResponse::from(cert)))
}
