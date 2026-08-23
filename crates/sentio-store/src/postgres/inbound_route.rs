use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::error::SentioError;
use sentio_core::ids::InboundRouteId;
use sentio_core::inbound::InboundRouteMatchType;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{
    InboundRouteRecord, InboundRouteRepository, InboundRouteUpdate, NewInboundRoute,
};

pub struct PgInboundRouteRepository {
    pool: PgPool,
}

impl PgInboundRouteRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_inbound_route_row(
    id: Uuid,
    tenant_id: Uuid,
    pattern: String,
    match_type: String,
    webhook_url: String,
    priority: i32,
    llm_classify: bool,
    auto_respond: bool,
    auto_respond_config: Option<serde_json::Value>,
    created_at: DateTime<Utc>,
) -> Result<InboundRouteRecord, SentioError> {
    Ok(InboundRouteRecord {
        id: InboundRouteId(id),
        tenant_id: TenantId(tenant_id),
        pattern,
        match_type: InboundRouteMatchType::from_str(&match_type)
            .map_err(|_| SentioError::Database(format!("invalid match_type: {match_type}")))?,
        webhook_url,
        priority,
        llm_classify,
        auto_respond,
        auto_respond_config,
        created_at,
    })
}

impl InboundRouteRepository for PgInboundRouteRepository {
    async fn create(&self, route: NewInboundRoute) -> Result<InboundRouteId, SentioError> {
        let match_type_str = route.match_type.to_string();
        let row = sqlx::query!(
            "INSERT INTO inbound_routes \
                (tenant_id, pattern, match_type, webhook_url, priority, \
                 llm_classify, auto_respond, auto_respond_config) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
            route.tenant_id.0,
            route.pattern,
            match_type_str,
            route.webhook_url,
            route.priority,
            route.llm_classify,
            route.auto_respond,
            route.auto_respond_config,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(InboundRouteId(row.id))
    }

    async fn get(&self, id: InboundRouteId) -> Result<InboundRouteRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, tenant_id, pattern, match_type, webhook_url, priority, \
                    llm_classify, auto_respond, auto_respond_config, created_at \
             FROM inbound_routes WHERE id = $1",
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "inbound_route",
            id: id.to_string(),
        })?;

        parse_inbound_route_row(
            row.id,
            row.tenant_id,
            row.pattern,
            row.match_type,
            row.webhook_url,
            row.priority,
            row.llm_classify,
            row.auto_respond,
            row.auto_respond_config,
            row.created_at,
        )
    }

    async fn list_by_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<InboundRouteRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, tenant_id, pattern, match_type, webhook_url, priority, \
                    llm_classify, auto_respond, auto_respond_config, created_at \
             FROM inbound_routes WHERE tenant_id = $1 ORDER BY priority DESC, created_at DESC",
            tenant_id.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|r| {
                parse_inbound_route_row(
                    r.id,
                    r.tenant_id,
                    r.pattern,
                    r.match_type,
                    r.webhook_url,
                    r.priority,
                    r.llm_classify,
                    r.auto_respond,
                    r.auto_respond_config,
                    r.created_at,
                )
            })
            .collect()
    }

    async fn update(
        &self,
        id: InboundRouteId,
        update: InboundRouteUpdate,
    ) -> Result<(), SentioError> {
        let match_type_str = update.match_type.to_string();
        let result = sqlx::query!(
            "UPDATE inbound_routes SET \
                pattern = $1, match_type = $2, webhook_url = $3, priority = $4, \
                llm_classify = $5, auto_respond = $6, auto_respond_config = $7 \
             WHERE id = $8",
            update.pattern,
            match_type_str,
            update.webhook_url,
            update.priority,
            update.llm_classify,
            update.auto_respond,
            update.auto_respond_config,
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "inbound_route",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn delete(&self, id: InboundRouteId) -> Result<(), SentioError> {
        let result = sqlx::query!("DELETE FROM inbound_routes WHERE id = $1", id.0)
            .execute(&self.pool)
            .await
            .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "inbound_route",
                id: id.to_string(),
            });
        }
        Ok(())
    }
}
