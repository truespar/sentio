use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::error::SentioError;
use sentio_core::event::MailboxStatus;
use sentio_core::ids::MailboxId;
use sentio_core::message::DomainId;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{MailboxRecord, MailboxRepository, MailboxUpdate, NewMailbox};

#[derive(Clone)]
pub struct PgMailboxRepository {
    pool: PgPool,
}

impl PgMailboxRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_mailbox_row(
    id: Uuid,
    domain_id: Uuid,
    tenant_id: Uuid,
    address: String,
    display_name: Option<String>,
    status: String,
    forward_to: Option<Vec<String>>,
    auto_reply: bool,
    auto_reply_subject: Option<String>,
    auto_reply_body: Option<String>,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
) -> Result<MailboxRecord, SentioError> {
    Ok(MailboxRecord {
        id: MailboxId(id),
        domain_id: DomainId(domain_id),
        tenant_id: TenantId(tenant_id),
        address,
        display_name,
        status: MailboxStatus::from_str(&status)
            .map_err(|_| SentioError::Database(format!("invalid mailbox status: {status}")))?,
        forward_to: forward_to.unwrap_or_default(),
        auto_reply,
        auto_reply_subject,
        auto_reply_body,
        metadata,
        created_at,
        updated_at,
    })
}

impl MailboxRepository for PgMailboxRepository {
    async fn create(&self, mailbox: NewMailbox) -> Result<MailboxRecord, SentioError> {
        let forward_to: Vec<String> = mailbox.forward_to;
        let row = sqlx::query!(
            "INSERT INTO mailboxes (domain_id, tenant_id, address, display_name, \
                                    forward_to, auto_reply, auto_reply_subject, \
                                    auto_reply_body, metadata) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             RETURNING id, domain_id, tenant_id, address, display_name, status, \
                       forward_to, auto_reply, auto_reply_subject, auto_reply_body, \
                       metadata, created_at, updated_at",
            mailbox.domain_id.0,
            mailbox.tenant_id.0,
            mailbox.address,
            mailbox.display_name,
            &forward_to,
            mailbox.auto_reply,
            mailbox.auto_reply_subject,
            mailbox.auto_reply_body,
            mailbox.metadata,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        parse_mailbox_row(
            row.id,
            row.domain_id,
            row.tenant_id,
            row.address,
            row.display_name,
            row.status,
            row.forward_to,
            row.auto_reply,
            row.auto_reply_subject,
            row.auto_reply_body,
            row.metadata,
            row.created_at,
            row.updated_at,
        )
    }

    async fn get(&self, id: MailboxId) -> Result<MailboxRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, domain_id, tenant_id, address, display_name, status, \
                    forward_to, auto_reply, auto_reply_subject, auto_reply_body, \
                    metadata, created_at, updated_at \
             FROM mailboxes WHERE id = $1",
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "mailbox",
            id: id.to_string(),
        })?;

        parse_mailbox_row(
            row.id,
            row.domain_id,
            row.tenant_id,
            row.address,
            row.display_name,
            row.status,
            row.forward_to,
            row.auto_reply,
            row.auto_reply_subject,
            row.auto_reply_body,
            row.metadata,
            row.created_at,
            row.updated_at,
        )
    }

    async fn list_by_domain(&self, domain_id: DomainId) -> Result<Vec<MailboxRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, domain_id, tenant_id, address, display_name, status, \
                    forward_to, auto_reply, auto_reply_subject, auto_reply_body, \
                    metadata, created_at, updated_at \
             FROM mailboxes WHERE domain_id = $1 ORDER BY address",
            domain_id.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|r| {
                parse_mailbox_row(
                    r.id,
                    r.domain_id,
                    r.tenant_id,
                    r.address,
                    r.display_name,
                    r.status,
                    r.forward_to,
                    r.auto_reply,
                    r.auto_reply_subject,
                    r.auto_reply_body,
                    r.metadata,
                    r.created_at,
                    r.updated_at,
                )
            })
            .collect()
    }

    async fn list_by_tenant(&self, tenant_id: TenantId) -> Result<Vec<MailboxRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, domain_id, tenant_id, address, display_name, status, \
                    forward_to, auto_reply, auto_reply_subject, auto_reply_body, \
                    metadata, created_at, updated_at \
             FROM mailboxes WHERE tenant_id = $1 ORDER BY address",
            tenant_id.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|r| {
                parse_mailbox_row(
                    r.id,
                    r.domain_id,
                    r.tenant_id,
                    r.address,
                    r.display_name,
                    r.status,
                    r.forward_to,
                    r.auto_reply,
                    r.auto_reply_subject,
                    r.auto_reply_body,
                    r.metadata,
                    r.created_at,
                    r.updated_at,
                )
            })
            .collect()
    }

    async fn update(&self, id: MailboxId, update: MailboxUpdate) -> Result<(), SentioError> {
        let status_str = update.status.to_string();
        let forward_to: Vec<String> = update.forward_to;
        let result = sqlx::query!(
            "UPDATE mailboxes SET display_name = $1, status = $2, forward_to = $3, \
                                  auto_reply = $4, auto_reply_subject = $5, \
                                  auto_reply_body = $6, metadata = $7, \
                                  updated_at = now() \
             WHERE id = $8",
            update.display_name,
            status_str,
            &forward_to,
            update.auto_reply,
            update.auto_reply_subject,
            update.auto_reply_body,
            update.metadata,
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "mailbox",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn delete(&self, id: MailboxId) -> Result<(), SentioError> {
        let result = sqlx::query!("DELETE FROM mailboxes WHERE id = $1", id.0)
            .execute(&self.pool)
            .await
            .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "mailbox",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    async fn find_by_address(
        &self,
        domain_id: DomainId,
        local_part: &str,
    ) -> Result<Option<MailboxRecord>, SentioError> {
        let row = sqlx::query!(
            "SELECT id, domain_id, tenant_id, address, display_name, status, \
                    forward_to, auto_reply, auto_reply_subject, auto_reply_body, \
                    metadata, created_at, updated_at \
             FROM mailboxes WHERE domain_id = $1 AND lower(address) = lower($2) \
             AND status = 'active' LIMIT 1",
            domain_id.0,
            local_part,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        match row {
            Some(r) => Ok(Some(parse_mailbox_row(
                r.id,
                r.domain_id,
                r.tenant_id,
                r.address,
                r.display_name,
                r.status,
                r.forward_to,
                r.auto_reply,
                r.auto_reply_subject,
                r.auto_reply_body,
                r.metadata,
                r.created_at,
                r.updated_at,
            )?)),
            None => Ok(None),
        }
    }
}
