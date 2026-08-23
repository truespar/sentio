use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

// ──────────────────────────────────────────────────────────────────────────────
// Configuration
// ──────────────────────────────────────────────────────────────────────────────

/// Configuration for the outbound connection pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum total connections across all destinations.
    pub max_connections: u32,
    /// Maximum connections to a single destination domain.
    pub max_connections_per_dest: u32,
    /// Idle connections older than this are closed.
    pub idle_timeout: Duration,
    /// Connections older than this (regardless of activity) are closed.
    pub max_connection_age: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 1000,
            max_connections_per_dest: 20,
            idle_timeout: Duration::from_secs(300),
            max_connection_age: Duration::from_secs(3600),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Pool types
// ──────────────────────────────────────────────────────────────────────────────

/// Trait alias for a bidirectional async stream (AsyncRead + AsyncWrite).
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

type BoxedStream = Box<dyn AsyncStream>;

/// A pooled connection entry with age tracking.
struct PooledEntry {
    stream: BoxedStream,
    created_at: Instant,
    last_used: Instant,
}

/// Per-domain pool of idle connections.
struct DomainPool {
    idle: Vec<PooledEntry>,
    semaphore: Arc<Semaphore>,
}

/// RAII guard that releases both global and per-domain semaphore permits on drop.
pub struct PoolPermit {
    _global: OwnedSemaphorePermit,
    _domain: OwnedSemaphorePermit,
}

/// Per-domain connection pool for outbound SMTP delivery.
pub struct ConnectionPool {
    config: PoolConfig,
    global_semaphore: Arc<Semaphore>,
    domains: Arc<Mutex<HashMap<String, DomainPool>>>,
}

impl ConnectionPool {
    pub fn new(config: PoolConfig) -> Self {
        Self {
            global_semaphore: Arc::new(Semaphore::new(config.max_connections as usize)),
            domains: Arc::new(Mutex::new(HashMap::new())),
            config,
        }
    }

    /// Acquire a permit to open a connection to `domain`.
    ///
    /// Blocks if the global or per-domain limit is reached.
    pub async fn acquire_permit(&self, domain: &str) -> PoolPermit {
        let global = self
            .global_semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("global semaphore closed");

        let domain_sem = {
            let mut domains = self.domains.lock().await;
            let entry = domains
                .entry(domain.to_string())
                .or_insert_with(|| DomainPool {
                    idle: Vec::new(),
                    semaphore: Arc::new(Semaphore::new(
                        self.config.max_connections_per_dest as usize,
                    )),
                });
            entry.semaphore.clone()
        };

        let domain_permit = domain_sem
            .acquire_owned()
            .await
            .expect("domain semaphore closed");

        PoolPermit {
            _global: global,
            _domain: domain_permit,
        }
    }

    /// Try to retrieve a cached idle connection for `domain`.
    pub async fn checkout(&self, domain: &str) -> Option<BoxedStream> {
        let mut domains = self.domains.lock().await;
        let pool = domains.get_mut(domain)?;
        let now = Instant::now();

        // Remove expired entries and return the first valid one.
        while let Some(entry) = pool.idle.pop() {
            let idle_age = now.duration_since(entry.last_used);
            let total_age = now.duration_since(entry.created_at);

            if idle_age < self.config.idle_timeout && total_age < self.config.max_connection_age {
                return Some(entry.stream);
            }
            // Entry expired; drop it.
        }

        None
    }

    /// Return a connection to the pool for future reuse.
    pub async fn checkin(&self, domain: &str, stream: BoxedStream) {
        self.checkin_with_age(domain, stream, Instant::now()).await;
    }

    /// Return a connection with a specific creation time (for testing).
    async fn checkin_with_age(&self, domain: &str, stream: BoxedStream, created_at: Instant) {
        let mut domains = self.domains.lock().await;
        let pool = domains
            .entry(domain.to_string())
            .or_insert_with(|| DomainPool {
                idle: Vec::new(),
                semaphore: Arc::new(Semaphore::new(
                    self.config.max_connections_per_dest as usize,
                )),
            });
        pool.idle.push(PooledEntry {
            stream,
            created_at,
            last_used: Instant::now(),
        });
    }

    /// Remove expired idle connections from all domain pools.
    pub async fn cleanup_expired(&self) -> usize {
        let mut domains = self.domains.lock().await;
        let now = Instant::now();
        let mut removed = 0;

        domains.retain(|_domain, pool| {
            let before = pool.idle.len();
            pool.idle.retain(|entry| {
                let idle_age = now.duration_since(entry.last_used);
                let total_age = now.duration_since(entry.created_at);
                idle_age < self.config.idle_timeout && total_age < self.config.max_connection_age
            });
            removed += before - pool.idle.len();
            // Keep domain entry if it has idle connections or outstanding permits.
            !pool.idle.is_empty()
        });

        removed
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn make_stream() -> BoxedStream {
        let (client, _server) = duplex(64);
        Box::new(client)
    }

    #[tokio::test]
    async fn idle_connection_reuse() {
        let pool = ConnectionPool::new(PoolConfig::default());
        pool.checkin("example.com", make_stream()).await;

        let conn = pool.checkout("example.com").await;
        assert!(conn.is_some(), "should return idle connection");

        // After checkout, pool should be empty.
        let conn2 = pool.checkout("example.com").await;
        assert!(conn2.is_none(), "pool should be empty after checkout");
    }

    #[tokio::test]
    async fn checkout_nonexistent_domain_returns_none() {
        let pool = ConnectionPool::new(PoolConfig::default());
        assert!(pool.checkout("no-such.com").await.is_none());
    }

    #[tokio::test]
    async fn per_domain_limits() {
        let config = PoolConfig {
            max_connections: 100,
            max_connections_per_dest: 2,
            ..Default::default()
        };
        let pool = ConnectionPool::new(config);

        let _permit1 = pool.acquire_permit("limited.com").await;
        let _permit2 = pool.acquire_permit("limited.com").await;

        // Third permit would block - test with a timeout.
        let result = tokio::time::timeout(
            Duration::from_millis(50),
            pool.acquire_permit("limited.com"),
        )
        .await;
        assert!(result.is_err(), "should timeout waiting for permit");
    }

    #[tokio::test]
    async fn global_limits() {
        let config = PoolConfig {
            max_connections: 2,
            max_connections_per_dest: 10,
            ..Default::default()
        };
        let pool = ConnectionPool::new(config);

        let _p1 = pool.acquire_permit("a.com").await;
        let _p2 = pool.acquire_permit("b.com").await;

        let result =
            tokio::time::timeout(Duration::from_millis(50), pool.acquire_permit("c.com")).await;
        assert!(result.is_err(), "should timeout on global limit");
    }

    #[tokio::test]
    async fn expired_connections_cleaned_up() {
        let config = PoolConfig {
            idle_timeout: Duration::from_millis(10),
            max_connection_age: Duration::from_secs(3600),
            ..Default::default()
        };
        let pool = ConnectionPool::new(config);

        pool.checkin("expire.com", make_stream()).await;

        // Wait for idle timeout.
        tokio::time::sleep(Duration::from_millis(20)).await;

        let removed = pool.cleanup_expired().await;
        assert_eq!(removed, 1);

        // Checkout should return nothing now.
        assert!(pool.checkout("expire.com").await.is_none());
    }

    #[tokio::test]
    async fn max_age_expiry() {
        let config = PoolConfig {
            idle_timeout: Duration::from_secs(300),
            max_connection_age: Duration::from_millis(10),
            ..Default::default()
        };
        let pool = ConnectionPool::new(config);

        // Check in with an old creation time.
        let old_time = Instant::now() - Duration::from_millis(20);
        pool.checkin_with_age("old.com", make_stream(), old_time)
            .await;

        // Checkout should skip expired-by-age entry.
        let conn = pool.checkout("old.com").await;
        assert!(conn.is_none(), "connection should be expired by max age");
    }

    #[tokio::test]
    async fn permits_released_on_drop() {
        let config = PoolConfig {
            max_connections: 1,
            max_connections_per_dest: 1,
            ..Default::default()
        };
        let pool = ConnectionPool::new(config);

        {
            let _permit = pool.acquire_permit("test.com").await;
            // permit dropped here
        }

        // Should be able to acquire again.
        let result =
            tokio::time::timeout(Duration::from_millis(50), pool.acquire_permit("test.com")).await;
        assert!(result.is_ok(), "should acquire after permit released");
    }
}
