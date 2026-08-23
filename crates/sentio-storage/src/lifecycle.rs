use tracing::instrument;

use sentio_core::error::SentioError;
use sentio_core::traits::{BlobStore, PendingUploadRepository};

const BATCH_SIZE: i64 = 100;

pub struct BlobLifecycle<B: BlobStore, P: PendingUploadRepository> {
    blob_store: B,
    pending_uploads: P,
}

impl<B: BlobStore, P: PendingUploadRepository> BlobLifecycle<B, P> {
    pub fn new(blob_store: B, pending_uploads: P) -> Self {
        Self {
            blob_store,
            pending_uploads,
        }
    }

    /// Delete orphaned blobs: list expired pending uploads, delete from the blob store,
    /// then delete the DB rows. Processes in batches to avoid unbounded memory.
    #[instrument(skip(self), name = "lifecycle.cleanup_orphans")]
    pub async fn cleanup_orphans(&self) -> Result<u64, SentioError> {
        let mut total_cleaned = 0u64;

        loop {
            let expired = self.pending_uploads.list_expired(BATCH_SIZE).await?;
            if expired.is_empty() {
                break;
            }

            let batch_count = expired.len() as u64;

            for upload in &expired {
                if let Err(e) = self.blob_store.delete(&upload.blob_key).await {
                    tracing::warn!(
                        fid = %upload.blob_key,
                        id = %upload.id,
                        error = %e,
                        "failed to delete orphaned blob from the blob store, will still remove DB row"
                    );
                }
            }

            let deleted = self.pending_uploads.delete_expired().await?;
            total_cleaned += deleted;

            tracing::info!(
                batch = batch_count,
                total = total_cleaned,
                "cleaned orphan batch"
            );

            if batch_count < BATCH_SIZE as u64 {
                break;
            }
        }

        tracing::info!(total = total_cleaned, "orphan cleanup complete");
        Ok(total_cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{MockBlobStore, MockPendingUploads};

    #[tokio::test]
    async fn cleanup_with_no_orphans() {
        let store = MockBlobStore::new();
        let uploads = MockPendingUploads::new();
        let lifecycle = BlobLifecycle::new(store, uploads);

        let cleaned = lifecycle.cleanup_orphans().await.unwrap();
        assert_eq!(cleaned, 0);
    }

    #[tokio::test]
    async fn cleanup_deletes_expired() {
        let store = MockBlobStore::new();
        let uploads = MockPendingUploads::new();

        // Pre-populate: put a blob in the store and an expired upload in the repo
        store.put("1,abc123", b"data");
        uploads.add_expired("1,abc123");

        let lifecycle = BlobLifecycle::new(store.clone(), uploads);
        let cleaned = lifecycle.cleanup_orphans().await.unwrap();

        assert_eq!(cleaned, 1);
        assert!(!store.contains("1,abc123"));
    }
}
