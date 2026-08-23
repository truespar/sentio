use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sentio_core::error::SentioError;

use crate::redis_conn::KvConn;

struct MockEntry {
    value: String,
    expires_at: Option<Instant>,
}

/// In-memory Redis mock for unit tests.
///
/// Uses `std::sync::Mutex` (not tokio) because the lock is never held across
/// `.await` points - each method does a quick lock-unlock.
#[derive(Clone)]
pub struct MockRedis {
    data: Arc<Mutex<HashMap<String, MockEntry>>>,
}

impl MockRedis {
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Directly set a key-value pair (no TTL). Useful for test setup.
    pub fn raw_set(&self, key: &str, value: &str) {
        let mut data = self.data.lock().unwrap();
        data.insert(
            key.to_string(),
            MockEntry {
                value: value.to_string(),
                expires_at: None,
            },
        );
    }

    /// Directly read a value, ignoring expiry. Useful for test assertions.
    pub fn raw_get(&self, key: &str) -> Option<String> {
        let data = self.data.lock().unwrap();
        data.get(key).map(|e| e.value.clone())
    }

    fn get_live(data: &mut HashMap<String, MockEntry>, key: &str) -> Option<String> {
        if let Some(entry) = data.get(key) {
            if entry.expires_at.is_some_and(|exp| Instant::now() >= exp) {
                data.remove(key);
                None
            } else {
                Some(entry.value.clone())
            }
        } else {
            None
        }
    }
}

impl Default for MockRedis {
    fn default() -> Self {
        Self::new()
    }
}

impl KvConn for MockRedis {
    fn get_opt<'a>(
        &'a self,
        key: &'a str,
    ) -> impl std::future::Future<Output = Result<Option<String>, SentioError>> + Send + 'a {
        let mut data = self.data.lock().unwrap();
        let result = Self::get_live(&mut data, key);
        std::future::ready(Ok(result))
    }

    fn set_ex<'a>(
        &'a self,
        key: &'a str,
        value: &'a str,
        secs: u64,
    ) -> impl std::future::Future<Output = Result<(), SentioError>> + Send + 'a {
        let mut data = self.data.lock().unwrap();
        data.insert(
            key.to_string(),
            MockEntry {
                value: value.to_string(),
                expires_at: Some(Instant::now() + Duration::from_secs(secs)),
            },
        );
        std::future::ready(Ok(()))
    }

    fn del<'a>(
        &'a self,
        key: &'a str,
    ) -> impl std::future::Future<Output = Result<(), SentioError>> + Send + 'a {
        let mut data = self.data.lock().unwrap();
        data.remove(key);
        std::future::ready(Ok(()))
    }

    fn exists<'a>(
        &'a self,
        key: &'a str,
    ) -> impl std::future::Future<Output = Result<bool, SentioError>> + Send + 'a {
        let mut data = self.data.lock().unwrap();
        let exists = Self::get_live(&mut data, key).is_some();
        std::future::ready(Ok(exists))
    }

    fn incr<'a>(
        &'a self,
        key: &'a str,
    ) -> impl std::future::Future<Output = Result<i64, SentioError>> + Send + 'a {
        let mut data = self.data.lock().unwrap();
        let current = Self::get_live(&mut data, key)
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        let new_val = current + 1;
        // Preserve existing TTL
        let expires_at = data.get(key).and_then(|e| e.expires_at);
        data.insert(
            key.to_string(),
            MockEntry {
                value: new_val.to_string(),
                expires_at,
            },
        );
        std::future::ready(Ok(new_val))
    }

    fn expire<'a>(
        &'a self,
        key: &'a str,
        secs: u64,
    ) -> impl std::future::Future<Output = Result<bool, SentioError>> + Send + 'a {
        let mut data = self.data.lock().unwrap();
        if let Some(entry) = data.get_mut(key) {
            entry.expires_at = Some(Instant::now() + Duration::from_secs(secs));
            std::future::ready(Ok(true))
        } else {
            std::future::ready(Ok(false))
        }
    }

    fn incr_by_float<'a>(
        &'a self,
        key: &'a str,
        delta: f64,
    ) -> impl std::future::Future<Output = Result<f64, SentioError>> + Send + 'a {
        let mut data = self.data.lock().unwrap();
        let current = Self::get_live(&mut data, key)
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0);
        let new_val = current + delta;
        let expires_at = data.get(key).and_then(|e| e.expires_at);
        data.insert(
            key.to_string(),
            MockEntry {
                value: new_val.to_string(),
                expires_at,
            },
        );
        std::future::ready(Ok(new_val))
    }

    fn scan_keys<'a>(
        &'a self,
        pattern: &'a str,
    ) -> impl std::future::Future<Output = Result<Vec<String>, SentioError>> + Send + 'a {
        let mut data = self.data.lock().unwrap();
        // Simple glob matching: only support trailing `*`
        let prefix = pattern.trim_end_matches('*');
        // Purge expired keys during scan
        let now = Instant::now();
        data.retain(|_, entry| entry.expires_at.map_or(true, |exp| now < exp));
        let keys: Vec<String> = data
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();
        std::future::ready(Ok(keys))
    }

    fn ttl<'a>(
        &'a self,
        key: &'a str,
    ) -> impl std::future::Future<Output = Result<i64, SentioError>> + Send + 'a {
        let data = self.data.lock().unwrap();
        let result = match data.get(key) {
            None => -2,
            Some(entry) => match entry.expires_at {
                None => -1,
                Some(exp) => {
                    let now = Instant::now();
                    if now >= exp {
                        -2
                    } else {
                        (exp - now).as_secs() as i64
                    }
                }
            },
        };
        std::future::ready(Ok(result))
    }

    fn ping<'a>(
        &'a self,
    ) -> impl std::future::Future<Output = Result<(), SentioError>> + Send + 'a {
        std::future::ready(Ok(()))
    }
}
