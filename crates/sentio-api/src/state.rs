use std::num::NonZeroU32;
use std::sync::Arc;

use governor::clock::DefaultClock;
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter};
use sqlx::PgPool;

use sentio_core::config::SentioConfig;
use sentio_queue::Publisher;
use sentio_storage::S3BlobStore;
use sentio_store::RedisPool;

// ──────────────────────────────────────────────────────────────────────────────
// Application state
// ──────────────────────────────────────────────────────────────────────────────

pub type KeyedRateLimiter = RateLimiter<String, DashMapStateStore<String>, DefaultClock>;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub publisher: Arc<Publisher>,
    pub blob_store: Arc<S3BlobStore>,
    pub config: Arc<SentioConfig>,
    pub rate_limiter: Arc<KeyedRateLimiter>,
    pub kv: Option<RedisPool>,
}

impl AppState {
    pub fn new(
        pool: PgPool,
        publisher: Publisher,
        blob_store: S3BlobStore,
        config: SentioConfig,
    ) -> Self {
        let quota = Quota::per_minute(NonZeroU32::new(600).unwrap());
        let rate_limiter = RateLimiter::dashmap(quota);

        Self {
            pool,
            publisher: Arc::new(publisher),
            blob_store: Arc::new(blob_store),
            config: Arc::new(config),
            rate_limiter: Arc::new(rate_limiter),
            kv: None,
        }
    }

    pub fn with_kv(mut self, kv: RedisPool) -> Self {
        self.kv = Some(kv);
        self
    }
}
