use sentio_core::error::SentioError;
use sqlx::PgPool;

/// Run all pending database migrations from `migrations/`.
pub async fn run_migrations(pool: &PgPool) -> Result<(), SentioError> {
    tracing::info!("Running database migrations...");

    sqlx::migrate!("../../migrations")
        .run(pool)
        .await
        .map_err(|e| SentioError::Database(format!("migration failed: {e}")))?;

    tracing::info!("Database migrations complete");
    Ok(())
}
