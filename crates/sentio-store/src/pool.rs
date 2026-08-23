use std::future::Future;

use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use sentio_core::config::{DatabaseConfig, KvConfig, RedisConfig};
use sentio_core::error::SentioError;
use sentio_core::kv::KvConn;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

// ──────────────────────────────────────────────────────────────────────────────
// PostgreSQL connection pool
// ──────────────────────────────────────────────────────────────────────────────

pub struct PostgresPool {
    pool: PgPool,
}

impl PostgresPool {
    pub async fn connect(config: &DatabaseConfig) -> Result<Self, SentioError> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .connect(&config.url)
            .await
            .map_err(|e| SentioError::Database(e.to_string()))?;

        tracing::info!(
            max_connections = config.max_connections,
            min_connections = config.min_connections,
            "PostgreSQL connection pool established"
        );

        Ok(Self { pool })
    }

    pub fn inner(&self) -> &PgPool {
        &self.pool
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Redis KV connection pool
// ──────────────────────────────────────────────────────────────────────────────

fn re(e: redis::RedisError) -> SentioError {
    SentioError::Kv(e.to_string())
}

/// Multiplexed Redis connection. `ConnectionManager` pipelines commands
/// over a single TCP connection and transparently reconnects on drop, so a
/// single handle outperforms a conventional connection pool.
#[derive(Clone)]
pub struct RedisPool {
    manager: ConnectionManager,
}

impl RedisPool {
    pub async fn connect(config: &RedisConfig) -> Result<Self, SentioError> {
        let client = redis::Client::open(config.url.as_str())
            .map_err(|e| SentioError::Kv(format!("redis open {}: {}", config.url, e)))?;
        let manager = ConnectionManager::new(client)
            .await
            .map_err(|e| SentioError::Kv(format!("redis connect {}: {}", config.url, e)))?;
        tracing::info!(url = %config.url, "Redis connection established");
        Ok(Self { manager })
    }
}

impl KvConn for RedisPool {
    fn get_opt<'a>(
        &'a self,
        key: &'a str,
    ) -> impl Future<Output = Result<Option<String>, SentioError>> + Send + 'a {
        let mut conn = self.manager.clone();
        async move { conn.get(key).await.map_err(re) }
    }

    fn set_ex<'a>(
        &'a self,
        key: &'a str,
        value: &'a str,
        secs: u64,
    ) -> impl Future<Output = Result<(), SentioError>> + Send + 'a {
        let mut conn = self.manager.clone();
        async move { conn.set_ex::<_, _, ()>(key, value, secs).await.map_err(re) }
    }

    fn del<'a>(
        &'a self,
        key: &'a str,
    ) -> impl Future<Output = Result<(), SentioError>> + Send + 'a {
        let mut conn = self.manager.clone();
        async move { conn.del::<_, ()>(key).await.map_err(re) }
    }

    fn exists<'a>(
        &'a self,
        key: &'a str,
    ) -> impl Future<Output = Result<bool, SentioError>> + Send + 'a {
        let mut conn = self.manager.clone();
        async move { conn.exists(key).await.map_err(re) }
    }

    fn incr<'a>(
        &'a self,
        key: &'a str,
    ) -> impl Future<Output = Result<i64, SentioError>> + Send + 'a {
        let mut conn = self.manager.clone();
        async move { conn.incr(key, 1i64).await.map_err(re) }
    }

    fn expire<'a>(
        &'a self,
        key: &'a str,
        secs: u64,
    ) -> impl Future<Output = Result<bool, SentioError>> + Send + 'a {
        let mut conn = self.manager.clone();
        async move { conn.expire(key, secs as i64).await.map_err(re) }
    }

    fn incr_by_float<'a>(
        &'a self,
        key: &'a str,
        delta: f64,
    ) -> impl Future<Output = Result<f64, SentioError>> + Send + 'a {
        let mut conn = self.manager.clone();
        async move { conn.incr(key, delta).await.map_err(re) }
    }

    fn scan_keys<'a>(
        &'a self,
        pattern: &'a str,
    ) -> impl Future<Output = Result<Vec<String>, SentioError>> + Send + 'a {
        let mut conn = self.manager.clone();
        let pat = pattern.to_string();
        async move {
            let mut iter = conn.scan_match::<_, String>(pat).await.map_err(re)?;
            let mut out = Vec::new();
            while let Some(k) = iter.next_item().await {
                out.push(k.map_err(re)?);
            }
            Ok(out)
        }
    }

    fn ttl<'a>(
        &'a self,
        key: &'a str,
    ) -> impl Future<Output = Result<i64, SentioError>> + Send + 'a {
        let mut conn = self.manager.clone();
        async move { conn.ttl(key).await.map_err(re) }
    }

    fn ping<'a>(&'a self) -> impl Future<Output = Result<(), SentioError>> + Send + 'a {
        let mut conn = self.manager.clone();
        async move {
            redis::cmd("PING")
                .query_async::<()>(&mut conn)
                .await
                .map_err(re)
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// KV backend selection
// ──────────────────────────────────────────────────────────────────────────────

/// Connect the KV store named by `[kv] backend`.
///
/// This build ships a single backend: `redis`, which uses RESP and so works
/// against Redis, Valkey, or any wire-compatible server. Additional stores plug
/// in by implementing [`KvConn`] and adding an arm here.
pub async fn connect_kv(kv: &KvConfig, redis: &RedisConfig) -> Result<RedisPool, SentioError> {
    match kv.backend.as_str() {
        "redis" => RedisPool::connect(redis).await,
        other => Err(SentioError::Kv(format!(
            "unknown kv backend {other:?} (expected \"redis\")"
        ))),
    }
}
