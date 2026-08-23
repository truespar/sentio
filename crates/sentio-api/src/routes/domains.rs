use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use sentio_core::auth::{DnsCheckStatus, DomainStatus};
use sentio_core::message::DomainId;
use sentio_core::traits::{
    DkimKeyRecord, DkimKeyRepository, DnsCheckUpdate, DomainRecord, DomainRepository, DomainUpdate,
    NewDomain, TenantRepository,
};
use sentio_store::postgres::{PgDkimKeyRepository, PgDomainRepository, PgTenantRepository};

use crate::auth::AuthContext;
use crate::errors::{ApiError, ErrorResponse};
use crate::response::{data, DataResponse};
use crate::state::AppState;

// ──────────────────────────────────────────────────────────────────────────────
// Request / Response types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateDomainRequest {
    pub domain_name: String,
    #[serde(default)]
    pub use_for_sending: bool,
    #[serde(default)]
    pub use_for_receiving: bool,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateDomainRequest {
    pub use_for_sending: bool,
    pub use_for_receiving: bool,
    #[serde(default)]
    pub reject_unknown_recipients: bool,
}

#[derive(Serialize, utoipa::ToSchema)]
struct DomainResponse {
    id: DomainId,
    domain_name: String,
    use_for_sending: bool,
    use_for_receiving: bool,
    status: DomainStatus,
    spf_status: DnsCheckStatus,
    spf_error: Option<String>,
    dkim_status: DnsCheckStatus,
    dkim_error: Option<String>,
    dmarc_status: DnsCheckStatus,
    dmarc_error: Option<String>,
    mx_status: DnsCheckStatus,
    mx_error: Option<String>,
    return_path_status: DnsCheckStatus,
    return_path_error: Option<String>,
    dns_checked_at: Option<DateTime<Utc>>,
    verification_token: String,
    verified_at: Option<DateTime<Utc>>,
    reject_unknown_recipients: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<DomainRecord> for DomainResponse {
    fn from(r: DomainRecord) -> Self {
        Self {
            id: r.id,
            domain_name: r.domain_name,
            use_for_sending: r.use_for_sending,
            use_for_receiving: r.use_for_receiving,
            status: r.status,
            spf_status: r.spf_status,
            spf_error: r.spf_error,
            dkim_status: r.dkim_status,
            dkim_error: r.dkim_error,
            dmarc_status: r.dmarc_status,
            dmarc_error: r.dmarc_error,
            mx_status: r.mx_status,
            mx_error: r.mx_error,
            return_path_status: r.return_path_status,
            return_path_error: r.return_path_error,
            dns_checked_at: r.dns_checked_at,
            verification_token: r.verification_token,
            verified_at: r.verified_at,
            reject_unknown_recipients: r.reject_unknown_recipients,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Serialize, utoipa::ToSchema)]
struct DnsRecordEntry {
    record_type: String,
    host: String,
    value: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/domains
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/domains",
    tag = "Domains",
    security(("bearer" = [])),
    request_body = CreateDomainRequest,
    responses(
        (status = 200, body = DataResponse<DomainResponse>),
    ),
)]
pub async fn create_domain(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(body): Json<CreateDomainRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("domains:write")?;

    if body.domain_name.is_empty() {
        return Err(ApiError::Validation("domain_name is required".into()));
    }

    let repo = PgDomainRepository::new(state.pool.clone());
    let record = repo
        .create(NewDomain {
            tenant_id: auth.tenant_id,
            domain_name: body.domain_name,
            use_for_sending: body.use_for_sending,
            use_for_receiving: body.use_for_receiving,
        })
        .await?;

    Ok(data(DomainResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/domains
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/domains",
    tag = "Domains",
    security(("bearer" = [])),
    responses(
        (status = 200, body = DataResponse<Vec<DomainResponse>>),
    ),
)]
pub async fn list_domains(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("domains:read")?;

    let repo = PgDomainRepository::new(state.pool.clone());
    let records = repo.list_by_tenant(auth.tenant_id).await?;
    let domains: Vec<DomainResponse> = records.into_iter().map(Into::into).collect();

    Ok(data(domains))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/domains/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/domains/{id}",
    tag = "Domains",
    security(("bearer" = [])),
    params(
        ("id" = uuid::Uuid, Path,),
    ),
    responses(
        (status = 200, body = DataResponse<DomainResponse>),
        (status = 404, body = ErrorResponse),
    ),
)]
pub async fn get_domain(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("domains:read")?;

    let repo = PgDomainRepository::new(state.pool.clone());
    let record = repo.get(DomainId(id)).await?;

    if record.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("domain not found".into()));
    }

    Ok(data(DomainResponse::from(record)))
}

// ──────────────────────────────────────────────────────────────────────────────
// PUT /v1/domains/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    put,
    path = "/v1/domains/{id}",
    tag = "Domains",
    security(("bearer" = [])),
    params(
        ("id" = uuid::Uuid, Path,),
    ),
    request_body = UpdateDomainRequest,
    responses(
        (status = 200, body = DataResponse<DomainResponse>),
    ),
)]
pub async fn update_domain(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<UpdateDomainRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("domains:write")?;

    let repo = PgDomainRepository::new(state.pool.clone());

    // Verify ownership
    let record = repo.get(DomainId(id)).await?;
    if record.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("domain not found".into()));
    }

    repo.update(
        DomainId(id),
        DomainUpdate {
            use_for_sending: body.use_for_sending,
            use_for_receiving: body.use_for_receiving,
            reject_unknown_recipients: body.reject_unknown_recipients,
        },
    )
    .await?;

    // Return updated record
    let updated = repo.get(DomainId(id)).await?;
    Ok(data(DomainResponse::from(updated)))
}

// ──────────────────────────────────────────────────────────────────────────────
// DELETE /v1/domains/{id}
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    delete,
    path = "/v1/domains/{id}",
    tag = "Domains",
    security(("bearer" = [])),
    params(
        ("id" = uuid::Uuid, Path,),
    ),
    responses(
        (status = 204),
    ),
)]
pub async fn delete_domain(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("domains:write")?;

    let repo = PgDomainRepository::new(state.pool.clone());

    // Verify ownership
    let record = repo.get(DomainId(id)).await?;
    if record.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("domain not found".into()));
    }

    repo.delete(DomainId(id)).await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/domains/{id}/verify
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
pub struct VerifyDomainRequest {
    pub token: String,
}

#[utoipa::path(
    post,
    path = "/v1/domains/{id}/verify",
    tag = "Domains",
    security(("bearer" = [])),
    params(
        ("id" = uuid::Uuid, Path,),
    ),
    request_body = VerifyDomainRequest,
    responses(
        (status = 200, body = DataResponse<DomainResponse>),
    ),
)]
pub async fn verify_domain(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<VerifyDomainRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("domains:write")?;

    let repo = PgDomainRepository::new(state.pool.clone());

    // Verify ownership
    let record = repo.get(DomainId(id)).await?;
    if record.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("domain not found".into()));
    }

    repo.verify(DomainId(id), &body.token).await?;

    // Return updated record
    let updated = repo.get(DomainId(id)).await?;
    Ok(data(DomainResponse::from(updated)))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/domains/{id}/dns-records
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/domains/{id}/dns-records",
    tag = "Domains",
    security(("bearer" = [])),
    params(
        ("id" = uuid::Uuid, Path,),
    ),
    responses(
        (status = 200, body = DataResponse<Vec<DnsRecordEntry>>),
    ),
)]
pub async fn get_dns_records(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("domains:read")?;

    let domain_repo = PgDomainRepository::new(state.pool.clone());
    let domain = domain_repo.get(DomainId(id)).await?;

    if domain.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("domain not found".into()));
    }

    let hostname = &state.config.server.hostname;
    let mut records = Vec::new();

    // SPF
    records.push(DnsRecordEntry {
        record_type: "TXT".into(),
        host: domain.domain_name.clone(),
        value: format!("v=spf1 include:{hostname} -all"),
    });

    // DKIM - include all active keys (dual signing)
    let dkim_repo = PgDkimKeyRepository::new(state.pool.clone());
    if let Ok(keys) = dkim_repo.list_by_domain(DomainId(id)).await {
        for key in keys
            .iter()
            .filter(|k| k.status == sentio_core::auth::DkimKeyStatus::Active)
        {
            records.push(DnsRecordEntry {
                record_type: "TXT".into(),
                host: format!("{}._domainkey.{}", key.selector, domain.domain_name),
                value: format!(
                    "v=DKIM1; k={}; p={}",
                    dkim_algorithm_label(key),
                    key.public_key
                ),
            });
        }
    }

    // DMARC
    records.push(DnsRecordEntry {
        record_type: "TXT".into(),
        host: format!("_dmarc.{}", domain.domain_name),
        value: format!("v=DMARC1; p=quarantine; rua=mailto:dmarc@{hostname}"),
    });

    // MX (for receiving)
    if domain.use_for_receiving {
        records.push(DnsRecordEntry {
            record_type: "MX".into(),
            host: domain.domain_name.clone(),
            value: format!("10 {hostname}"),
        });
    }

    // VERP return-path records - only suggested when the tenant has
    // opted in to VERP. Without the bounce.* subdomain pointing at this
    // server, MAIL FROM rewriting would direct bounces into a black hole.
    let tenant_repo = PgTenantRepository::new(state.pool.clone());
    let tenant = tenant_repo.get(domain.tenant_id).await?;
    if tenant.verp_enabled {
        // Bounce subdomain CNAMEd to this server so DSN bounces route here.
        //
        // We DON'T suggest a TXT record on the bounce subdomain - RFC 1034
        // forbids a CNAME coexisting with any other RR type at the same
        // name. SPF lookups on `bounce.{domain}` follow the CNAME to the
        // server hostname and read its TXT, so the operator publishes
        // `{hostname} TXT "v=spf1 a -all"` once for the whole instance.
        records.push(DnsRecordEntry {
            record_type: "CNAME".into(),
            host: format!("bounce.{}", domain.domain_name),
            value: hostname.clone(),
        });
    }

    Ok(data(records))
}

fn dkim_algorithm_label(key: &DkimKeyRecord) -> &'static str {
    match key.algorithm.to_string().as_str() {
        "ed25519" => "ed25519",
        _ => "rsa",
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /v1/domains/{id}/dns-check
// ──────────────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/domains/{id}/dns-check",
    tag = "Domains",
    security(("bearer" = [])),
    params(
        ("id" = uuid::Uuid, Path,),
    ),
    responses(
        (status = 200, body = DataResponse<DomainResponse>),
        (status = 404, body = ErrorResponse),
    ),
)]
pub async fn run_dns_check(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("domains:write")?;

    let domain_repo = PgDomainRepository::new(state.pool.clone());
    let dkim_repo = PgDkimKeyRepository::new(state.pool.clone());

    let domain = domain_repo.get(DomainId(id)).await?;
    if domain.tenant_id != auth.tenant_id {
        return Err(ApiError::NotFound("domain not found".into()));
    }

    let checker = sentio_auth::DnsChecker::new(state.config.server.hostname.clone())
        .map_err(|e| ApiError::Internal(format!("dns checker init: {e}")))?;

    // Tenant's VERP opt-in flag drives whether bounce.{domain} is verified.
    // Pre-fetched here rather than inside DnsChecker so the auth crate
    // stays free of repository dependencies.
    let tenant_repo = PgTenantRepository::new(state.pool.clone());
    let verp_enabled = tenant_repo
        .get(domain.tenant_id)
        .await
        .map(|t| t.verp_enabled)
        .unwrap_or(false);

    let outcome = checker.check(&domain, &dkim_repo, verp_enabled).await;

    domain_repo
        .update_dns_checks(
            DomainId(id),
            DnsCheckUpdate {
                spf_status: outcome.spf.0,
                spf_error: outcome.spf.1,
                dkim_status: outcome.dkim.0,
                dkim_error: outcome.dkim.1,
                dmarc_status: outcome.dmarc.0,
                dmarc_error: outcome.dmarc.1,
                mx_status: outcome.mx.0,
                mx_error: outcome.mx.1,
                return_path_status: outcome.return_path.0,
                return_path_error: outcome.return_path.1,
            },
        )
        .await?;

    let updated = domain_repo.get(DomainId(id)).await?;
    Ok(data(DomainResponse::from(updated)))
}
