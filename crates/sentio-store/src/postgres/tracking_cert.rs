use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sentio_core::error::SentioError;
use sentio_core::ids::{TrackingCertificateId, TrackingDomainId};
use sentio_core::traits::{
    NewTrackingCertificate, TrackingCertificateRecord, TrackingCertificateRepository,
};

pub struct PgTrackingCertificateRepository {
    pool: PgPool,
}

impl PgTrackingCertificateRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn parse_tracking_cert_row(
    id: Uuid,
    tracking_domain_id: Uuid,
    certificate: String,
    intermediaries: Option<String>,
    private_key: String,
    expires_at: DateTime<Utc>,
    renew_after: DateTime<Utc>,
    created_at: DateTime<Utc>,
) -> TrackingCertificateRecord {
    TrackingCertificateRecord {
        id: TrackingCertificateId(id),
        tracking_domain_id: TrackingDomainId(tracking_domain_id),
        certificate,
        intermediaries,
        private_key,
        expires_at,
        renew_after,
        created_at,
    }
}

impl TrackingCertificateRepository for PgTrackingCertificateRepository {
    async fn create(
        &self,
        cert: NewTrackingCertificate,
    ) -> Result<TrackingCertificateId, SentioError> {
        let row = sqlx::query!(
            "INSERT INTO tracking_certificates \
                (tracking_domain_id, certificate, intermediaries, private_key, \
                 expires_at, renew_after) \
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
            cert.tracking_domain_id.0,
            cert.certificate,
            cert.intermediaries,
            cert.private_key,
            cert.expires_at,
            cert.renew_after,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(TrackingCertificateId(row.id))
    }

    async fn get(
        &self,
        id: TrackingCertificateId,
    ) -> Result<TrackingCertificateRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, tracking_domain_id, certificate, intermediaries, private_key, \
                    expires_at, renew_after, created_at \
             FROM tracking_certificates WHERE id = $1",
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "tracking_certificate",
            id: id.to_string(),
        })?;

        Ok(parse_tracking_cert_row(
            row.id,
            row.tracking_domain_id,
            row.certificate,
            row.intermediaries,
            row.private_key,
            row.expires_at,
            row.renew_after,
            row.created_at,
        ))
    }

    async fn get_active_for_domain(
        &self,
        tracking_domain_id: TrackingDomainId,
    ) -> Result<TrackingCertificateRecord, SentioError> {
        let row = sqlx::query!(
            "SELECT id, tracking_domain_id, certificate, intermediaries, private_key, \
                    expires_at, renew_after, created_at \
             FROM tracking_certificates \
             WHERE tracking_domain_id = $1 AND expires_at > now() \
             ORDER BY created_at DESC LIMIT 1",
            tracking_domain_id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?
        .ok_or_else(|| SentioError::NotFound {
            entity: "tracking_certificate",
            id: tracking_domain_id.to_string(),
        })?;

        Ok(parse_tracking_cert_row(
            row.id,
            row.tracking_domain_id,
            row.certificate,
            row.intermediaries,
            row.private_key,
            row.expires_at,
            row.renew_after,
            row.created_at,
        ))
    }

    async fn list_due_for_renewal(&self) -> Result<Vec<TrackingCertificateRecord>, SentioError> {
        let rows = sqlx::query!(
            "SELECT id, tracking_domain_id, certificate, intermediaries, private_key, \
                    expires_at, renew_after, created_at \
             FROM tracking_certificates WHERE renew_after <= now() \
             ORDER BY renew_after ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentioError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| {
                parse_tracking_cert_row(
                    r.id,
                    r.tracking_domain_id,
                    r.certificate,
                    r.intermediaries,
                    r.private_key,
                    r.expires_at,
                    r.renew_after,
                    r.created_at,
                )
            })
            .collect())
    }

    async fn delete(&self, id: TrackingCertificateId) -> Result<(), SentioError> {
        let result = sqlx::query!("DELETE FROM tracking_certificates WHERE id = $1", id.0)
            .execute(&self.pool)
            .await
            .map_err(|e| SentioError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SentioError::NotFound {
                entity: "tracking_certificate",
                id: id.to_string(),
            });
        }
        Ok(())
    }
}
