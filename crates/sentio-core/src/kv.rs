//! Backend-agnostic key-value store abstraction.
//!
//! `KvConn` is the surface that abuse control, rate limiting, and warmup
//! throttling talk to. This build ships one implementation, selected via
//! `[kv] backend` in the config: `redis`, which uses RESP and so works
//! against Redis, Valkey, or any wire-compatible server. The impl lives in
//! `sentio-store` alongside the connection pools.
//!
//! The trait intentionally uses RPITIT (return-position `impl Trait` in
//! traits) rather than `#[async_trait]` for zero-cost dispatch, matching
//! the convention used by `SpamScorer` and `LlmProvider`. Consumers stay
//! generic over `K: KvConn`, so an additional backend only needs a new impl
//! plus an arm in `sentio_store::pool::connect_kv`.

use std::future::Future;

use crate::error::SentioError;

pub trait KvConn: Send + Sync + Clone + 'static {
    fn get_opt<'a>(
        &'a self,
        key: &'a str,
    ) -> impl Future<Output = Result<Option<String>, SentioError>> + Send + 'a;

    fn set_ex<'a>(
        &'a self,
        key: &'a str,
        value: &'a str,
        secs: u64,
    ) -> impl Future<Output = Result<(), SentioError>> + Send + 'a;

    fn del<'a>(&'a self, key: &'a str)
        -> impl Future<Output = Result<(), SentioError>> + Send + 'a;

    fn exists<'a>(
        &'a self,
        key: &'a str,
    ) -> impl Future<Output = Result<bool, SentioError>> + Send + 'a;

    fn incr<'a>(
        &'a self,
        key: &'a str,
    ) -> impl Future<Output = Result<i64, SentioError>> + Send + 'a;

    fn expire<'a>(
        &'a self,
        key: &'a str,
        secs: u64,
    ) -> impl Future<Output = Result<bool, SentioError>> + Send + 'a;

    fn incr_by_float<'a>(
        &'a self,
        key: &'a str,
        delta: f64,
    ) -> impl Future<Output = Result<f64, SentioError>> + Send + 'a;

    /// Scan for keys matching a glob pattern (e.g. `sentio:smtp:ban:*`).
    fn scan_keys<'a>(
        &'a self,
        pattern: &'a str,
    ) -> impl Future<Output = Result<Vec<String>, SentioError>> + Send + 'a;

    /// Remaining TTL on `key` in seconds. Returns -1 if the key exists
    /// with no expiry, -2 if the key does not exist (Redis convention).
    fn ttl<'a>(
        &'a self,
        key: &'a str,
    ) -> impl Future<Output = Result<i64, SentioError>> + Send + 'a;

    /// Round-trip health check.
    fn ping<'a>(&'a self) -> impl Future<Output = Result<(), SentioError>> + Send + 'a;
}
