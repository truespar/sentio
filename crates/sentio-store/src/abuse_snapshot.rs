use sqlx::PgPool;
use tracing::{debug, info, warn};

use sentio_core::error::SentioError;
use sentio_core::kv::KvConn;

/// Snapshot KV-backed abuse state (bans, reputation, whitelist) into
/// PostgreSQL for persistence across KV-store restarts.
pub async fn snapshot_to_db<K: KvConn>(pool: &PgPool, kv: &K) -> Result<(), SentioError> {
    // Snapshot bans
    let ban_keys = kv.scan_keys("sentio:smtp:ban:*").await?;
    for key in &ban_keys {
        if let Some(ip_str) = key.strip_prefix("sentio:smtp:ban:") {
            let ttl = kv.ttl(key).await.unwrap_or(-1);
            let expires_at = if ttl > 0 {
                Some(chrono::Utc::now() + chrono::Duration::seconds(ttl))
            } else {
                None
            };

            if let Err(e) = sqlx::query(
                r#"
                INSERT INTO abuse_snapshots (ip, snapshot_type, value, expires_at, updated_at)
                VALUES ($1::inet, 'ban', '1', $2, now())
                ON CONFLICT (ip, snapshot_type) DO UPDATE
                SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at, updated_at = now()
                "#,
            )
            .bind(ip_str)
            .bind(expires_at)
            .execute(pool)
            .await
            {
                warn!(ip = ip_str, error = %e, "failed to snapshot ban");
            }
        }
    }

    // Snapshot reputation scores (with decay timestamp)
    let rep_keys = kv.scan_keys("sentio:smtp:rep:*").await?;
    for key in &rep_keys {
        // Skip timestamp keys - we combine score + ts
        if key.contains(":rep:ts:") {
            continue;
        }
        if let Some(ip_str) = key.strip_prefix("sentio:smtp:rep:") {
            let score = kv.get_opt(key).await.ok().flatten();
            let ts_key = format!("sentio:smtp:rep:ts:{ip_str}");
            let ts = kv.get_opt(&ts_key).await.ok().flatten();

            let value = match (score, ts) {
                (Some(s), Some(t)) => format!("{s}|{t}"),
                (Some(s), None) => s,
                _ => continue,
            };

            if let Err(e) = sqlx::query(
                r#"
                INSERT INTO abuse_snapshots (ip, snapshot_type, value, updated_at)
                VALUES ($1::inet, 'reputation', $2, now())
                ON CONFLICT (ip, snapshot_type) DO UPDATE
                SET value = EXCLUDED.value, updated_at = now()
                "#,
            )
            .bind(ip_str)
            .bind(&value)
            .execute(pool)
            .await
            {
                warn!(ip = ip_str, error = %e, "failed to snapshot reputation");
            }
        }
    }

    // Snapshot whitelist entries
    let wl_keys = kv.scan_keys("sentio:smtp:whitelist:*").await?;
    for key in &wl_keys {
        if let Some(ip_str) = key.strip_prefix("sentio:smtp:whitelist:") {
            if let Err(e) = sqlx::query(
                r#"
                INSERT INTO abuse_snapshots (ip, snapshot_type, value, updated_at)
                VALUES ($1::inet, 'whitelist', '1', now())
                ON CONFLICT (ip, snapshot_type) DO UPDATE
                SET value = EXCLUDED.value, updated_at = now()
                "#,
            )
            .bind(ip_str)
            .execute(pool)
            .await
            {
                warn!(ip = ip_str, error = %e, "failed to snapshot whitelist");
            }
        }
    }

    // Clean up expired snapshots
    let deleted = sqlx::query(
        "DELETE FROM abuse_snapshots WHERE expires_at IS NOT NULL AND expires_at < now()",
    )
    .execute(pool)
    .await
    .map(|r| r.rows_affected())
    .unwrap_or(0);

    if deleted > 0 {
        debug!(deleted, "cleaned up expired abuse snapshots");
    }

    info!(
        bans = ban_keys.len(),
        reputations = rep_keys.iter().filter(|k| !k.contains(":rep:ts:")).count(),
        whitelisted = wl_keys.len(),
        "abuse state snapshotted to database"
    );

    Ok(())
}

/// Restore KV-backed abuse state from PostgreSQL snapshots at startup.
pub async fn restore_from_db<K: KvConn>(pool: &PgPool, kv: &K) -> Result<(), SentioError> {
    // Clean up expired rows first
    let _ = sqlx::query(
        "DELETE FROM abuse_snapshots WHERE expires_at IS NOT NULL AND expires_at < now()",
    )
    .execute(pool)
    .await;

    let rows = sqlx::query_as::<_, SnapshotRow>(
        "SELECT ip::text, snapshot_type, value, expires_at FROM abuse_snapshots",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| SentioError::Database(format!("failed to read abuse snapshots: {e}")))?;

    let mut restored = 0u64;

    for row in &rows {
        match row.snapshot_type.as_str() {
            "ban" => {
                let key = format!("sentio:smtp:ban:{}", row.ip);
                let ttl = row
                    .expires_at
                    .map(|exp| {
                        let remaining = (exp - chrono::Utc::now()).num_seconds();
                        remaining.max(1) as u64
                    })
                    .unwrap_or(3600); // default 1h if no expiry info
                let _ = kv.set_ex(&key, "1", ttl).await;
                restored += 1;
            }
            "reputation" => {
                let key = format!("sentio:smtp:rep:{}", row.ip);
                let ts_key = format!("sentio:smtp:rep:ts:{}", row.ip);
                let ttl = 86400u64 * 7; // 7 days

                if let Some((score, ts)) = row.value.split_once('|') {
                    let _ = kv.set_ex(&key, score, ttl).await;
                    let _ = kv.set_ex(&ts_key, ts, ttl).await;
                } else {
                    let _ = kv.set_ex(&key, row.value.as_str(), ttl).await;
                }
                restored += 1;
            }
            "whitelist" => {
                let key = format!("sentio:smtp:whitelist:{}", row.ip);
                let ttl = 86400u64 * 365; // 1 year
                let _ = kv.set_ex(&key, "1", ttl).await;
                restored += 1;
            }
            other => {
                warn!(snapshot_type = other, "unknown snapshot type, skipping");
            }
        }
    }

    info!(
        restored,
        total = rows.len(),
        "abuse state restored from database"
    );
    Ok(())
}

#[derive(sqlx::FromRow)]
struct SnapshotRow {
    ip: String,
    snapshot_type: String,
    value: String,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}
