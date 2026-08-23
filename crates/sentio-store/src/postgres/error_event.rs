use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::error::SentioError;
use sentio_core::event::{ErrorCategory, ErrorComponent, ErrorSeverity};
use sentio_core::ids::ErrorEventId;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{
    ErrorEventFilter, ErrorEventRecord, ErrorEventRepository, ErrorEventSummary, NewErrorEvent,
};

pub struct PgErrorEventRepository {
    pool: PgPool,
}

impl PgErrorEventRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_error_event_row(
    id: Uuid,
    tenant_id: Uuid,
    severity: String,
    component: String,
    error_type: String,
    message: String,
    stack_trace: Option<String>,
    message_id: Option<Uuid>,
    request_id: Option<String>,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
) -> ErrorEventRecord {
    ErrorEventRecord {
        id: ErrorEventId(id),
        tenant_id: TenantId(tenant_id),
        severity: severity
            .parse::<ErrorSeverity>()
            .unwrap_or(ErrorSeverity::Error),
        component: component
            .parse::<ErrorComponent>()
            .unwrap_or(ErrorComponent::Api),
        error_type: error_type
            .parse::<ErrorCategory>()
            .unwrap_or(ErrorCategory::Internal),
        message,
        stack_trace,
        message_id,
        request_id,
        metadata,
        created_at,
    }
}

impl ErrorEventRepository for PgErrorEventRepository {
    async fn insert(&self, event: NewErrorEvent) -> Result<ErrorEventId, SentioError> {
        let severity_str = event.severity.to_string();
        let component_str = event.component.to_string();
        let error_type_str = event.error_type.to_string();

        let row = sqlx::query!(
            "INSERT INTO error_events \
                (tenant_id, severity, component, error_type, message, \
                 stack_trace, message_id, request_id, metadata) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
            event.tenant_id.0,
            severity_str,
            component_str,
            error_type_str,
            event.message,
            event.stack_trace,
            event.message_id,
            event.request_id,
            event.metadata,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(ErrorEventId(row.id))
    }

    async fn get(&self, id: ErrorEventId) -> Result<ErrorEventRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, tenant_id, severity, component, error_type, message, \
                    stack_trace, message_id, request_id, metadata, created_at \
             FROM error_events WHERE id = $1",
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "error_event",
            id: id.to_string(),
        })?;

        Ok(parse_error_event_row(
            row.id,
            row.tenant_id,
            row.severity,
            row.component,
            row.error_type,
            row.message,
            row.stack_trace,
            row.message_id,
            row.request_id,
            row.metadata,
            row.created_at,
        ))
    }

    async fn list(
        &self,
        tenant_id: TenantId,
        filter: ErrorEventFilter,
    ) -> Result<Vec<ErrorEventRecord>, SentioError> {
        let severity_str = filter.severity.map(|s| s.to_string());
        let component_str = filter.component.map(|c| c.to_string());
        let error_type_str = filter.error_type.map(|e| e.to_string());

        let rows = sqlx::query!(
            "SELECT id, tenant_id, severity, component, error_type, message, \
                    stack_trace, message_id, request_id, metadata, created_at \
             FROM error_events \
             WHERE tenant_id = $1 \
               AND ($2::text IS NULL OR severity = $2) \
               AND ($3::text IS NULL OR component = $3) \
               AND ($4::text IS NULL OR error_type = $4) \
               AND ($5::timestamptz IS NULL OR created_at >= $5) \
               AND ($6::timestamptz IS NULL OR created_at <= $6) \
             ORDER BY created_at DESC \
             LIMIT $7 OFFSET $8",
            tenant_id.0,
            severity_str as Option<String>,
            component_str as Option<String>,
            error_type_str as Option<String>,
            filter.from,
            filter.to,
            filter.limit,
            filter.offset,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| {
                parse_error_event_row(
                    r.id,
                    r.tenant_id,
                    r.severity,
                    r.component,
                    r.error_type,
                    r.message,
                    r.stack_trace,
                    r.message_id,
                    r.request_id,
                    r.metadata,
                    r.created_at,
                )
            })
            .collect())
    }

    async fn summary(
        &self,
        tenant_id: TenantId,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<ErrorEventSummary>, SentioError> {
        let rows = sqlx::query!(
            "SELECT component, severity, COUNT(*) as count \
             FROM error_events \
             WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3 \
             GROUP BY component, severity \
             ORDER BY count DESC",
            tenant_id.0,
            from,
            to,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| ErrorEventSummary {
                component: r.component,
                severity: r.severity,
                count: r.count.unwrap_or(0),
            })
            .collect())
    }

    async fn delete_before(&self, before: DateTime<Utc>) -> Result<u64, SentioError> {
        let result = sqlx::query!("DELETE FROM error_events WHERE created_at < $1", before,)
            .execute(&self.pool)
            .await
            .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }
}
