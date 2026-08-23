use axum::extract::{Query, State};
use axum::response::IntoResponse;
use serde::Serialize;

use sentio_core::event::{BounceClass, EngagementEventType, EventType};
use sentio_core::traits::{
    EngagementEventRepository, EngagementFilter, EventFilter, MessageEventRepository,
    MessageRepository, StatusCount,
};
use sentio_store::postgres::{
    PgEngagementEventRepository, PgMessageEventRepository, PgMessageRepository,
};

use crate::auth::AuthContext;
use crate::errors::ApiError;
use crate::extract::DateRangeParams;
use crate::response::{data, DataResponse};
use crate::state::AppState;

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/analytics/overview
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
struct OverviewResponse {
    total_sent: i64,
    delivered: i64,
    bounced: i64,
    deferred: i64,
    dropped: i64,
    delivery_rate: f64,
    bounce_rate: f64,
}

#[utoipa::path(
    get,
    path = "/v1/analytics/overview",
    tag = "Analytics",
    security(("bearer" = [])),
    params(DateRangeParams),
    responses(
        (status = 200, body = DataResponse<OverviewResponse>),
    ),
)]
pub async fn overview(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<DateRangeParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("analytics:read")?;

    let (from, to) = params.validated();

    let msg_repo = PgMessageRepository::new(state.pool.clone());
    let counts = msg_repo.count_by_status(auth.tenant_id, from, to).await?;

    let mut total_sent: i64 = 0;
    let mut delivered: i64 = 0;
    let mut bounced: i64 = 0;
    let mut deferred: i64 = 0;
    let mut dropped: i64 = 0;

    for sc in &counts {
        let count = sc.count;
        total_sent += count;
        match sc.status.as_str() {
            "delivered" => delivered += count,
            "bounced" => bounced += count,
            "deferred" => deferred += count,
            "dropped" | "rejected" => dropped += count,
            _ => {}
        }
    }

    let delivery_rate = if total_sent > 0 {
        delivered as f64 / total_sent as f64
    } else {
        0.0
    };
    let bounce_rate = if total_sent > 0 {
        bounced as f64 / total_sent as f64
    } else {
        0.0
    };

    Ok(data(OverviewResponse {
        total_sent,
        delivered,
        bounced,
        deferred,
        dropped,
        delivery_rate,
        bounce_rate,
    }))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/analytics/delivery
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
struct DeliveryStatsResponse {
    status_counts: Vec<StatusCountResponse>,
}

#[derive(Serialize, utoipa::ToSchema)]
struct StatusCountResponse {
    status: String,
    count: i64,
}

impl From<StatusCount> for StatusCountResponse {
    fn from(sc: StatusCount) -> Self {
        Self {
            status: sc.status,
            count: sc.count,
        }
    }
}

#[utoipa::path(
    get,
    path = "/v1/analytics/delivery",
    tag = "Analytics",
    security(("bearer" = [])),
    params(DateRangeParams),
    responses(
        (status = 200, body = DataResponse<DeliveryStatsResponse>),
    ),
)]
pub async fn delivery(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<DateRangeParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("analytics:read")?;

    let (from, to) = params.validated();

    let msg_repo = PgMessageRepository::new(state.pool.clone());
    let counts = msg_repo.count_by_status(auth.tenant_id, from, to).await?;

    let status_counts: Vec<StatusCountResponse> = counts.into_iter().map(Into::into).collect();

    Ok(data(DeliveryStatsResponse { status_counts }))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/analytics/engagement
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
struct EngagementStatsResponse {
    opens: i64,
    clicks: i64,
    unsubscribes: i64,
}

#[utoipa::path(
    get,
    path = "/v1/analytics/engagement",
    tag = "Analytics",
    security(("bearer" = [])),
    params(DateRangeParams),
    responses(
        (status = 200, body = DataResponse<EngagementStatsResponse>),
    ),
)]
pub async fn engagement(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<DateRangeParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("analytics:read")?;

    let (from, to) = params.validated();

    let engagement_repo = PgEngagementEventRepository::new(state.pool.clone());

    // Fetch all engagement events in the date range
    let filter = EngagementFilter {
        event_type: None,
        from,
        to,
        limit: 100_000,
        offset: 0,
    };
    let events = engagement_repo
        .list_by_tenant(auth.tenant_id, filter)
        .await?;

    let mut opens: i64 = 0;
    let mut clicks: i64 = 0;
    let mut unsubscribes: i64 = 0;

    for event in &events {
        match event.event_type {
            EngagementEventType::Opened => opens += 1,
            EngagementEventType::Clicked => clicks += 1,
            EngagementEventType::Unsubscribed => unsubscribes += 1,
        }
    }

    Ok(data(EngagementStatsResponse {
        opens,
        clicks,
        unsubscribes,
    }))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /v1/analytics/bounces
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
struct BounceStatsResponse {
    hard: i64,
    soft: i64,
    block: i64,
    total: i64,
}

#[utoipa::path(
    get,
    path = "/v1/analytics/bounces",
    tag = "Analytics",
    security(("bearer" = [])),
    params(DateRangeParams),
    responses(
        (status = 200, body = DataResponse<BounceStatsResponse>),
    ),
)]
pub async fn bounces(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<DateRangeParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_scope("analytics:read")?;

    let (from, to) = params.validated();

    let event_repo = PgMessageEventRepository::new(state.pool.clone());
    let filter = EventFilter {
        event_type: Some(EventType::Bounced),
        from,
        to,
        limit: 100_000,
        offset: 0,
    };
    let events = event_repo.list_by_tenant(auth.tenant_id, filter).await?;

    let mut hard: i64 = 0;
    let mut soft: i64 = 0;
    let mut block: i64 = 0;

    for event in &events {
        match event.bounce_class {
            Some(BounceClass::Hard) => hard += 1,
            Some(BounceClass::Soft) => soft += 1,
            Some(BounceClass::Block) => block += 1,
            None => soft += 1, // default to soft if unknown
        }
    }

    let total = hard + soft + block;

    Ok(data(BounceStatsResponse {
        hard,
        soft,
        block,
        total,
    }))
}
