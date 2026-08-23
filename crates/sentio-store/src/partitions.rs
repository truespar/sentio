use sqlx::PgPool;

use sentio_core::error::SentioError;

/// Create month partitions for the four monthly-partitioned tables for the
/// current month plus `months_ahead` future months. Idempotent.
///
/// Returns the number of partitions actually created. Calls the
/// `sentio_create_month_partitions` SECURITY DEFINER function (see migration
/// 009) so the runtime user does not need ownership of the parent tables.
pub async fn ensure_future_partitions(
    pool: &PgPool,
    months_ahead: i32,
) -> Result<i32, SentioError> {
    let created: i32 = sqlx::query_scalar("SELECT sentio_create_month_partitions($1)")
        .bind(months_ahead)
        .fetch_one(pool)
        .await
        .map_err(|e| SentioError::Database(format!("ensure_future_partitions: {e}")))?;
    Ok(created)
}
