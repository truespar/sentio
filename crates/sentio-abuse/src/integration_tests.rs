//! Integration tests against a real Redis instance at 127.0.0.1:6379.
//!
//! Run with: `cargo test -p sentio-abuse --features integration`
//!
//! Each test uses a unique IP address to avoid inter-test conflicts.

use std::future::Future;
use std::net::IpAddr;

use sentio_core::config::{AbuseConfig, GreylistConfig, RedisConfig};
use sentio_store::RedisPool;

use crate::auth_guard::AuthGuard;
use crate::ban::BanChecker;
use crate::dnsbl_cache::{DnsLookup, DnsblChecker};
use crate::greylist::Greylister;
use crate::ip_reputation::ReputationTracker;
use crate::rate_guard::RateGuard;
use crate::redis_conn::KvConn;
use crate::AbuseGuard;

async fn kv_conn() -> RedisPool {
    let cfg = RedisConfig {
        url: "redis://127.0.0.1:6379/0".to_string(),
    };
    RedisPool::connect(&cfg)
        .await
        .expect("Failed to connect to Redis at 127.0.0.1:6379")
}

/// Delete a list of keys to clean up after a test.
async fn cleanup(conn: &RedisPool, keys: &[&str]) {
    for key in keys {
        let _ = conn.del(*key).await;
    }
}

struct MockDns {
    listed: bool,
}

impl DnsLookup for MockDns {
    fn lookup_a<'a>(
        &'a self,
        _name: &'a str,
    ) -> impl Future<Output = Result<bool, String>> + Send + 'a {
        std::future::ready(Ok(self.listed))
    }

    fn reverse_lookup<'a>(
        &'a self,
        _ip: &'a IpAddr,
    ) -> impl Future<Output = Result<bool, String>> + Send + 'a {
        std::future::ready(Ok(true))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BanChecker
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn real_kv_ban_cycle() {
    let conn = kv_conn().await;
    let config = AbuseConfig::default();
    let checker = BanChecker::new(conn.clone(), &config);
    let ip: IpAddr = "100.0.0.1".parse().unwrap();

    assert!(!checker.is_banned(&ip).await);

    checker.ban(&ip, 60).await;
    assert!(checker.is_banned(&ip).await);

    checker.unban(&ip).await;
    assert!(!checker.is_banned(&ip).await);

    cleanup(&conn, &["sentio:smtp:ban:100.0.0.1"]).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// RateGuard
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn real_kv_rate_under_limit() {
    let conn = kv_conn().await;
    let config = AbuseConfig {
        max_connections_per_minute: 10,
        ..Default::default()
    };
    let guard = RateGuard::new(conn.clone(), &config);
    let ip: IpAddr = "100.0.1.1".parse().unwrap();

    for _ in 0..9 {
        assert!(guard.check_rate(&ip).await.is_ok());
    }

    let now = chrono::Utc::now().timestamp() / 60;
    cleanup(
        &conn,
        &[
            &format!("sentio:smtp:rate:conn:{ip}:{now}"),
            &format!("sentio:smtp:rate:conn:{ip}:{}", now - 1),
        ],
    )
    .await;
}

#[tokio::test]
async fn real_kv_rate_over_limit() {
    let conn = kv_conn().await;
    let config = AbuseConfig {
        max_connections_per_minute: 5,
        ..Default::default()
    };
    let guard = RateGuard::new(conn.clone(), &config);
    let ip: IpAddr = "100.0.1.2".parse().unwrap();

    for _ in 0..5 {
        let _ = guard.check_rate(&ip).await;
    }
    assert!(guard.check_rate(&ip).await.is_err());

    let now = chrono::Utc::now().timestamp() / 60;
    cleanup(
        &conn,
        &[
            &format!("sentio:smtp:rate:conn:{ip}:{now}"),
            &format!("sentio:smtp:rate:conn:{ip}:{}", now - 1),
        ],
    )
    .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// AuthGuard
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn real_kv_auth_failures_and_auto_ban() {
    let conn = kv_conn().await;
    let config = AbuseConfig {
        max_auth_failures_per_hour: 3,
        ban_duration_secs: 60,
        ..Default::default()
    };
    let guard = AuthGuard::new(conn.clone(), &config);
    let checker = BanChecker::new(conn.clone(), &config);
    let ip: IpAddr = "100.0.2.1".parse().unwrap();

    assert!(!guard.record_failure(&ip).await);
    assert_eq!(guard.failure_count(&ip).await, 1);

    assert!(!guard.record_failure(&ip).await);
    assert_eq!(guard.failure_count(&ip).await, 2);

    assert!(guard.record_failure(&ip).await);
    assert!(checker.is_banned(&ip).await);

    guard.reset(&ip).await;
    assert_eq!(guard.failure_count(&ip).await, 0);

    let hour = chrono::Utc::now().timestamp() / 3600;
    cleanup(
        &conn,
        &[
            &format!("sentio:smtp:auth:fail:{ip}:{hour}"),
            &format!("sentio:smtp:ban:{ip}"),
        ],
    )
    .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// ReputationTracker
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn real_kv_reputation_scoring() {
    let conn = kv_conn().await;
    let config = AbuseConfig {
        reputation_reject_threshold: 10.0,
        reputation_decay_hours: 24,
        ..Default::default()
    };
    let tracker = ReputationTracker::new(conn.clone(), &config);
    let ip: IpAddr = "100.0.3.1".parse().unwrap();

    assert_eq!(tracker.get_score(&ip).await, 0.0);

    let score = tracker.record_infraction(&ip, 5.0).await;
    assert!((score - 5.0).abs() < 0.1);

    let score = tracker.record_infraction(&ip, 3.0).await;
    assert!((score - 8.0).abs() < 0.2);

    assert!(!tracker.is_suspicious(&ip).await);

    let score = tracker.record_infraction(&ip, 5.0).await;
    assert!(score > 10.0);
    assert!(tracker.is_suspicious(&ip).await);

    cleanup(
        &conn,
        &[
            &format!("sentio:smtp:rep:{ip}"),
            &format!("sentio:smtp:rep:ts:{ip}"),
        ],
    )
    .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// DnsblChecker (DNS mocked, KV cache is real)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn real_kv_dnsbl_caching() {
    let conn = kv_conn().await;
    let config = AbuseConfig::default();
    let ip: IpAddr = "100.0.4.1".parse().unwrap();

    let checker = DnsblChecker::new(conn.clone(), MockDns { listed: true }, &config);
    let result = checker.check(&ip).await;
    assert!(result.listed);

    for list in &config.dnsbl_lists {
        let cached = conn
            .get_opt(&format!("sentio:smtp:dnsbl:{list}:{ip}"))
            .await
            .unwrap();
        assert_eq!(cached.as_deref(), Some("1"));
    }

    let checker2 = DnsblChecker::new(conn.clone(), MockDns { listed: false }, &config);
    let result = checker2.check(&ip).await;
    assert!(result.listed, "cache should override DNS result");

    let keys: Vec<String> = config
        .dnsbl_lists
        .iter()
        .map(|list| format!("sentio:smtp:dnsbl:{list}:{ip}"))
        .collect();
    let key_refs: Vec<&str> = keys.iter().map(|s| s.as_str()).collect();
    cleanup(&conn, &key_refs).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Greylister
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn real_kv_greylist_new_triplet_defers() {
    let conn = kv_conn().await;
    let config = GreylistConfig {
        enabled: true,
        min_delay_secs: 300,
        max_age_hours: 48,
    };
    let gl = Greylister::new(conn.clone(), &config);
    let ip: IpAddr = "100.0.5.1".parse().unwrap();
    let from = "test-int@sender.com";
    let to = "test-int@rcpt.com";

    let action = gl.check(&ip, from, to).await;
    assert_eq!(action, crate::greylist::GreylistAction::Defer);

    let action = gl.check(&ip, from, to).await;
    assert_eq!(action, crate::greylist::GreylistAction::Defer);

    let hash = crate::greylist::sha256_hex(&format!("{ip}|{from}|{to}"));
    cleanup(&conn, &[&format!("sentio:smtp:grey:{hash}")]).await;
}

#[tokio::test]
async fn real_kv_greylist_aged_triplet_accepts() {
    let conn = kv_conn().await;
    let config = GreylistConfig {
        enabled: true,
        min_delay_secs: 2,
        max_age_hours: 48,
    };
    let gl = Greylister::new(conn.clone(), &config);
    let ip: IpAddr = "100.0.5.2".parse().unwrap();
    let from = "test-int-aged@sender.com";
    let to = "test-int-aged@rcpt.com";

    gl.check(&ip, from, to).await;
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let action = gl.check(&ip, from, to).await;
    assert_eq!(action, crate::greylist::GreylistAction::Accept);

    let hash = crate::greylist::sha256_hex(&format!("{ip}|{from}|{to}"));
    cleanup(&conn, &[&format!("sentio:smtp:grey:{hash}")]).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// AbuseGuard facade (end-to-end)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn real_kv_abuse_guard_clean_ip() {
    let conn = kv_conn().await;
    let config = AbuseConfig::default();
    let guard = AbuseGuard::new(conn.clone(), MockDns { listed: false }, &config);
    let ip: IpAddr = "100.0.6.1".parse().unwrap();

    assert!(guard.check_connection(&ip).await.is_ok());

    let now = chrono::Utc::now().timestamp() / 60;
    cleanup(&conn, &[&format!("sentio:smtp:rate:conn:{ip}:{now}")]).await;
}

#[tokio::test]
async fn real_kv_abuse_guard_banned_ip() {
    let conn = kv_conn().await;
    let config = AbuseConfig::default();
    let guard = AbuseGuard::new(conn.clone(), MockDns { listed: false }, &config);
    let ip: IpAddr = "100.0.6.2".parse().unwrap();

    guard.bans.ban(&ip, 60).await;
    assert!(guard.check_connection(&ip).await.is_err());

    cleanup(&conn, &[&format!("sentio:smtp:ban:{ip}")]).await;
}
