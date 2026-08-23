use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::error::SentioError;
use sentio_core::event::BounceClass;
use sentio_core::message::{DomainId, MessageDirection, MessageId, MessageStatus};
use sentio_core::tenant::TenantId;
use sentio_core::traits::{
    MessageFilter, MessageRecord, MessageRepository, NewMessage, StatusCount,
};

pub struct PgMessageRepository {
    pool: PgPool,
}

impl PgMessageRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_message_row(
    id: Uuid,
    tenant_id: Uuid,
    domain_id: Option<Uuid>,
    direction: String,
    envelope_from: String,
    envelope_to: Vec<String>,
    header_from: Option<String>,
    header_to: Option<Vec<String>>,
    header_cc: Option<Vec<String>>,
    header_reply_to: Option<String>,
    subject: Option<String>,
    message_id_header: Option<String>,
    status: String,
    tags: Option<Vec<String>>,
    metadata: Option<serde_json::Value>,
    message_size: Option<i64>,
    raw_eml_key: Option<String>,
    spam_score: Option<f64>,
    spam_action: Option<String>,
    send_at: Option<DateTime<Utc>>,
    dsn_ret: Option<String>,
    dsn_envid: Option<String>,
    dsn_notify: serde_json::Value,
    dsn_orcpt: serde_json::Value,
    created_at: DateTime<Utc>,
    delivered_at: Option<DateTime<Utc>>,
    bounced_at: Option<DateTime<Utc>>,
    llm_category: Option<String>,
    llm_summary: Option<String>,
    llm_classified_at: Option<DateTime<Utc>>,
) -> Result<MessageRecord, SentioError> {
    Ok(MessageRecord {
        id: MessageId(id),
        tenant_id: TenantId(tenant_id),
        domain_id: domain_id.map(DomainId),
        direction: MessageDirection::from_str(&direction)
            .map_err(|_| SentioError::Database(format!("invalid direction: {direction}")))?,
        envelope_from,
        envelope_to,
        header_from,
        header_to: header_to.unwrap_or_default(),
        header_cc: header_cc.unwrap_or_default(),
        header_reply_to,
        subject,
        message_id_header,
        status: MessageStatus::from_str(&status)
            .map_err(|_| SentioError::Database(format!("invalid status: {status}")))?,
        tags: tags.unwrap_or_default(),
        metadata: metadata.unwrap_or(serde_json::json!({})),
        message_size,
        // (live DB rename + .sqlx cache regen). Mapped to the new
        // `raw_eml_key` field on the trait record.
        raw_eml_key,
        spam_score,
        spam_action,
        send_at,
        dsn_ret,
        dsn_envid,
        dsn_notify,
        dsn_orcpt,
        created_at,
        delivered_at,
        bounced_at,
        llm_category,
        llm_summary,
        llm_classified_at,
    })
}

impl MessageRepository for PgMessageRepository {
    async fn insert(&self, msg: NewMessage) -> Result<MessageId, SentioError> {
        let id = msg.id;
        let direction_str = msg.direction.to_string();
        let metadata = msg.metadata.unwrap_or(serde_json::json!({}));

        sqlx::query!(
            "INSERT INTO messages \
                (id, tenant_id, domain_id, direction, envelope_from, envelope_to, \
                 header_from, header_to, header_cc, header_reply_to, subject, \
                 message_id_header, tags, metadata, message_size, raw_eml_key, \
                 spam_score, spam_action, send_at, dsn_ret, dsn_envid, dsn_notify, dsn_orcpt) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)",
            id.0,
            msg.tenant_id.0,
            msg.domain_id.map(|d| d.0),
            direction_str,
            msg.envelope_from,
            &msg.envelope_to,
            msg.header_from,
            &msg.header_to,
            &msg.header_cc,
            msg.header_reply_to,
            msg.subject,
            msg.message_id_header,
            &msg.tags,
            metadata,
            msg.message_size,
            msg.raw_eml_key,
            msg.spam_score,
            msg.spam_action,
            msg.send_at,
            msg.dsn_ret,
            msg.dsn_envid,
            msg.dsn_notify,
            msg.dsn_orcpt,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(id)
    }

    async fn get(&self, tenant_id: TenantId, id: MessageId) -> Result<MessageRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, tenant_id, domain_id, direction, envelope_from, envelope_to, \
                    header_from, header_to, header_cc, header_reply_to, subject, \
                    message_id_header, status, tags, metadata, message_size, \
                    raw_eml_key, spam_score, spam_action, send_at, \
                    dsn_ret, dsn_envid, dsn_notify, dsn_orcpt, \
                    created_at, delivered_at, bounced_at, \
                    llm_category, llm_summary, llm_classified_at \
             FROM messages WHERE id = $1 AND tenant_id = $2",
            id.0,
            tenant_id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "message",
            id: id.to_string(),
        })?;

        parse_message_row(
            row.id,
            row.tenant_id,
            row.domain_id,
            row.direction,
            row.envelope_from,
            row.envelope_to,
            row.header_from,
            row.header_to,
            row.header_cc,
            row.header_reply_to,
            row.subject,
            row.message_id_header,
            row.status,
            row.tags,
            row.metadata,
            row.message_size,
            row.raw_eml_key,
            row.spam_score,
            row.spam_action,
            row.send_at,
            row.dsn_ret,
            row.dsn_envid,
            row.dsn_notify,
            row.dsn_orcpt,
            row.created_at,
            row.delivered_at,
            row.bounced_at,
            row.llm_category,
            row.llm_summary,
            row.llm_classified_at,
        )
    }

    async fn list(
        &self,
        tenant_id: TenantId,
        filter: MessageFilter,
    ) -> Result<Vec<MessageRecord>, SentioError> {
        // Partition-aware: always filters on created_at range for pruning.
        // Each arm returns Vec<MessageRecord> directly because sqlx::query!
        // generates distinct anonymous Record types per query.
        match (filter.status, filter.direction) {
            (Some(status), Some(direction)) => {
                let s = status.to_string();
                let d = direction.to_string();
                let rows = sqlx::query!(
                    "SELECT id, tenant_id, domain_id, direction, envelope_from, envelope_to, \
                            header_from, header_to, header_cc, header_reply_to, subject, \
                            message_id_header, status, tags, metadata, message_size, \
                            raw_eml_key, spam_score, spam_action, send_at, \
                            dsn_ret, dsn_envid, dsn_notify, dsn_orcpt, \
                            created_at, delivered_at, bounced_at, \
                            llm_category, llm_summary, llm_classified_at \
                     FROM messages \
                     WHERE tenant_id = $1 AND created_at >= $2 AND created_at < $3 \
                           AND status = $4 AND direction = $5 \
                     ORDER BY created_at DESC LIMIT $6 OFFSET $7",
                    tenant_id.0,
                    filter.from,
                    filter.to,
                    s,
                    d,
                    filter.limit,
                    filter.offset,
                )
                .fetch_all(&self.pool)
                .await
                .map_err(|e| SentioError::Database(e.to_string()))?;

                rows.into_iter()
                    .map(|r| {
                        parse_message_row(
                            r.id,
                            r.tenant_id,
                            r.domain_id,
                            r.direction,
                            r.envelope_from,
                            r.envelope_to,
                            r.header_from,
                            r.header_to,
                            r.header_cc,
                            r.header_reply_to,
                            r.subject,
                            r.message_id_header,
                            r.status,
                            r.tags,
                            r.metadata,
                            r.message_size,
                            r.raw_eml_key,
                            r.spam_score,
                            r.spam_action,
                            r.send_at,
                            r.dsn_ret,
                            r.dsn_envid,
                            r.dsn_notify,
                            r.dsn_orcpt,
                            r.created_at,
                            r.delivered_at,
                            r.bounced_at,
                            r.llm_category,
                            r.llm_summary,
                            r.llm_classified_at,
                        )
                    })
                    .collect()
            }
            (Some(status), None) => {
                let s = status.to_string();
                let rows = sqlx::query!(
                    "SELECT id, tenant_id, domain_id, direction, envelope_from, envelope_to, \
                            header_from, header_to, header_cc, header_reply_to, subject, \
                            message_id_header, status, tags, metadata, message_size, \
                            raw_eml_key, spam_score, spam_action, send_at, \
                            dsn_ret, dsn_envid, dsn_notify, dsn_orcpt, \
                            created_at, delivered_at, bounced_at, \
                            llm_category, llm_summary, llm_classified_at \
                     FROM messages \
                     WHERE tenant_id = $1 AND created_at >= $2 AND created_at < $3 \
                           AND status = $4 \
                     ORDER BY created_at DESC LIMIT $5 OFFSET $6",
                    tenant_id.0,
                    filter.from,
                    filter.to,
                    s,
                    filter.limit,
                    filter.offset,
                )
                .fetch_all(&self.pool)
                .await
                .map_err(|e| SentioError::Database(e.to_string()))?;

                rows.into_iter()
                    .map(|r| {
                        parse_message_row(
                            r.id,
                            r.tenant_id,
                            r.domain_id,
                            r.direction,
                            r.envelope_from,
                            r.envelope_to,
                            r.header_from,
                            r.header_to,
                            r.header_cc,
                            r.header_reply_to,
                            r.subject,
                            r.message_id_header,
                            r.status,
                            r.tags,
                            r.metadata,
                            r.message_size,
                            r.raw_eml_key,
                            r.spam_score,
                            r.spam_action,
                            r.send_at,
                            r.dsn_ret,
                            r.dsn_envid,
                            r.dsn_notify,
                            r.dsn_orcpt,
                            r.created_at,
                            r.delivered_at,
                            r.bounced_at,
                            r.llm_category,
                            r.llm_summary,
                            r.llm_classified_at,
                        )
                    })
                    .collect()
            }
            (None, Some(direction)) => {
                let d = direction.to_string();
                let rows = sqlx::query!(
                    "SELECT id, tenant_id, domain_id, direction, envelope_from, envelope_to, \
                            header_from, header_to, header_cc, header_reply_to, subject, \
                            message_id_header, status, tags, metadata, message_size, \
                            raw_eml_key, spam_score, spam_action, send_at, \
                            dsn_ret, dsn_envid, dsn_notify, dsn_orcpt, \
                            created_at, delivered_at, bounced_at, \
                            llm_category, llm_summary, llm_classified_at \
                     FROM messages \
                     WHERE tenant_id = $1 AND created_at >= $2 AND created_at < $3 \
                           AND direction = $4 \
                     ORDER BY created_at DESC LIMIT $5 OFFSET $6",
                    tenant_id.0,
                    filter.from,
                    filter.to,
                    d,
                    filter.limit,
                    filter.offset,
                )
                .fetch_all(&self.pool)
                .await
                .map_err(|e| SentioError::Database(e.to_string()))?;

                rows.into_iter()
                    .map(|r| {
                        parse_message_row(
                            r.id,
                            r.tenant_id,
                            r.domain_id,
                            r.direction,
                            r.envelope_from,
                            r.envelope_to,
                            r.header_from,
                            r.header_to,
                            r.header_cc,
                            r.header_reply_to,
                            r.subject,
                            r.message_id_header,
                            r.status,
                            r.tags,
                            r.metadata,
                            r.message_size,
                            r.raw_eml_key,
                            r.spam_score,
                            r.spam_action,
                            r.send_at,
                            r.dsn_ret,
                            r.dsn_envid,
                            r.dsn_notify,
                            r.dsn_orcpt,
                            r.created_at,
                            r.delivered_at,
                            r.bounced_at,
                            r.llm_category,
                            r.llm_summary,
                            r.llm_classified_at,
                        )
                    })
                    .collect()
            }
            (None, None) => {
                let rows = sqlx::query!(
                    "SELECT id, tenant_id, domain_id, direction, envelope_from, envelope_to, \
                            header_from, header_to, header_cc, header_reply_to, subject, \
                            message_id_header, status, tags, metadata, message_size, \
                            raw_eml_key, spam_score, spam_action, send_at, \
                            dsn_ret, dsn_envid, dsn_notify, dsn_orcpt, \
                            created_at, delivered_at, bounced_at, \
                            llm_category, llm_summary, llm_classified_at \
                     FROM messages \
                     WHERE tenant_id = $1 AND created_at >= $2 AND created_at < $3 \
                     ORDER BY created_at DESC LIMIT $4 OFFSET $5",
                    tenant_id.0,
                    filter.from,
                    filter.to,
                    filter.limit,
                    filter.offset,
                )
                .fetch_all(&self.pool)
                .await
                .map_err(|e| SentioError::Database(e.to_string()))?;

                rows.into_iter()
                    .map(|r| {
                        parse_message_row(
                            r.id,
                            r.tenant_id,
                            r.domain_id,
                            r.direction,
                            r.envelope_from,
                            r.envelope_to,
                            r.header_from,
                            r.header_to,
                            r.header_cc,
                            r.header_reply_to,
                            r.subject,
                            r.message_id_header,
                            r.status,
                            r.tags,
                            r.metadata,
                            r.message_size,
                            r.raw_eml_key,
                            r.spam_score,
                            r.spam_action,
                            r.send_at,
                            r.dsn_ret,
                            r.dsn_envid,
                            r.dsn_notify,
                            r.dsn_orcpt,
                            r.created_at,
                            r.delivered_at,
                            r.bounced_at,
                            r.llm_category,
                            r.llm_summary,
                            r.llm_classified_at,
                        )
                    })
                    .collect()
            }
        }
    }

    async fn update_status(&self, id: MessageId, status: MessageStatus) -> Result<(), SentioError> {
        let status_str = status.to_string();
        let result = sqlx::query!(
            "UPDATE messages SET status = $1 WHERE id = $2",
            status_str,
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "message",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn set_delivered(&self, id: MessageId) -> Result<(), SentioError> {
        let result = sqlx::query!(
            "UPDATE messages SET status = 'delivered', delivered_at = now() WHERE id = $1",
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "message",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn set_bounced(&self, id: MessageId) -> Result<(), SentioError> {
        let result = sqlx::query!(
            "UPDATE messages SET status = 'bounced', bounced_at = now() WHERE id = $1",
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "message",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn find_by_id(&self, id: MessageId) -> Result<Option<MessageRecord>, SentioError> {
        // No tenant filter: this path is used by the VERP bounce handler
        // which has only verified a per-instance HMAC over the message id.
        let row = sqlx::query!(
            "SELECT id, tenant_id, domain_id, direction, envelope_from, envelope_to, \
                    header_from, header_to, header_cc, header_reply_to, subject, \
                    message_id_header, status, tags, metadata, message_size, \
                    raw_eml_key, spam_score, spam_action, send_at, \
                    dsn_ret, dsn_envid, dsn_notify, dsn_orcpt, \
                    created_at, delivered_at, bounced_at, \
                    llm_category, llm_summary, llm_classified_at \
             FROM messages WHERE id = $1",
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        match row {
            None => Ok(None),
            Some(r) => Ok(Some(parse_message_row(
                r.id,
                r.tenant_id,
                r.domain_id,
                r.direction,
                r.envelope_from,
                r.envelope_to,
                r.header_from,
                r.header_to,
                r.header_cc,
                r.header_reply_to,
                r.subject,
                r.message_id_header,
                r.status,
                r.tags,
                r.metadata,
                r.message_size,
                r.raw_eml_key,
                r.spam_score,
                r.spam_action,
                r.send_at,
                r.dsn_ret,
                r.dsn_envid,
                r.dsn_notify,
                r.dsn_orcpt,
                r.created_at,
                r.delivered_at,
                r.bounced_at,
                r.llm_category,
                r.llm_summary,
                r.llm_classified_at,
            )?)),
        }
    }

    async fn mark_bounced(
        &self,
        id: MessageId,
        class: BounceClass,
        smtp_code: Option<u16>,
        enhanced_status: Option<&str>,
        diagnostic: Option<&str>,
        failed_recipient: Option<&str>,
    ) -> Result<(), SentioError> {
        // Single UPDATE writes both the lifecycle flip and the parsed
        // bounce details, so a partial write cannot leave the row marked
        // bounced without diagnostic context (or vice versa).
        let class_str = class.to_string();
        let smtp_code_i32 = smtp_code.map(i32::from);
        let result = sqlx::query!(
            "UPDATE messages \
                SET status           = 'bounced', \
                    bounced_at       = now(), \
                    bounce_class     = $2, \
                    smtp_code        = $3, \
                    enhanced_status  = $4, \
                    diagnostic       = $5, \
                    failed_recipient = $6 \
              WHERE id = $1",
            id.0,
            class_str,
            smtp_code_i32,
            enhanced_status,
            diagnostic,
            failed_recipient,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "message",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn update_spam_score(&self, id: MessageId, spam_score: f64) -> Result<(), SentioError> {
        let result = sqlx::query!(
            "UPDATE messages SET spam_score = $1 WHERE id = $2",
            spam_score,
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "message",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn update_llm_classification(
        &self,
        id: MessageId,
        category: &str,
        summary: &str,
    ) -> Result<(), SentioError> {
        let result = sqlx::query!(
            "UPDATE messages SET llm_category = $1, llm_summary = $2, llm_classified_at = now() WHERE id = $3",
            category,
            summary,
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "message",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn count_by_status(
        &self,
        tenant_id: TenantId,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<StatusCount>, SentioError> {
        let rows = sqlx::query!(
            "SELECT status, COUNT(*) as count FROM messages \
             WHERE tenant_id = $1 AND created_at >= $2 AND created_at < $3 \
             GROUP BY status",
            tenant_id.0,
            from,
            to,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| StatusCount {
                status: r.status,
                count: r.count.unwrap_or(0),
            })
            .collect())
    }
}
