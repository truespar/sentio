use bytes::Bytes;
use tracing::instrument;

use sentio_core::error::SentioError;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{BlobStore, ScanResult, UploadResult, VirusScanner};

/// Result of processing a single attachment through the pipeline.
#[derive(Debug, Clone)]
pub struct ProcessedAttachment {
    pub fid: String,
    pub size: u64,
    pub checksum_sha256: String,
    pub scan_result: ScanResult,
}

/// Result of storing a raw EML blob.
#[derive(Debug, Clone)]
pub struct StoredEml {
    pub fid: String,
    pub size: u64,
    pub checksum_sha256: String,
}

pub struct AttachmentProcessor<B: BlobStore, S: VirusScanner> {
    blob_store: B,
    scanner: S,
    store_raw_eml: bool,
}

impl<B: BlobStore, S: VirusScanner> AttachmentProcessor<B, S> {
    pub fn new(blob_store: B, scanner: S, store_raw_eml: bool) -> Self {
        Self {
            blob_store,
            scanner,
            store_raw_eml,
        }
    }

    /// Full attachment pipeline: assign FID → upload → scan → if infected, delete blob.
    #[instrument(skip(self, data), name = "attachment.process", fields(filename, content_type, %tenant_id))]
    pub async fn process_attachment(
        &self,
        data: Bytes,
        filename: &str,
        content_type: &str,
        tenant_id: TenantId,
    ) -> Result<ProcessedAttachment, SentioError> {
        let assigned = self.blob_store.assign().await?;

        let upload_result: UploadResult = self
            .blob_store
            .upload(&assigned.fid, data.clone(), filename, content_type)
            .await?;

        let scan_result = self.scanner.scan(&data).await?;

        if let ScanResult::Infected(_) = &scan_result {
            tracing::warn!(
                fid = %upload_result.fid,
                %tenant_id,
                "infected attachment detected, deleting blob"
            );
            if let Err(e) = self.blob_store.delete(&upload_result.fid).await {
                tracing::error!(fid = %upload_result.fid, error = %e, "failed to delete infected blob");
            }
        }

        Ok(ProcessedAttachment {
            fid: upload_result.fid,
            size: upload_result.size,
            checksum_sha256: upload_result.checksum_sha256,
            scan_result,
        })
    }

    /// Store raw EML if configured. Returns None if store_raw_eml is false.
    #[instrument(skip(self, data), name = "attachment.process_raw_eml", fields(data_len = data.len()))]
    pub async fn process_raw_eml(&self, data: Bytes) -> Result<Option<StoredEml>, SentioError> {
        if !self.store_raw_eml {
            return Ok(None);
        }

        let assigned = self.blob_store.assign().await?;

        let upload_result = self
            .blob_store
            .upload(&assigned.fid, data, "raw.eml", "message/rfc822")
            .await?;

        Ok(Some(StoredEml {
            fid: upload_result.fid,
            size: upload_result.size,
            checksum_sha256: upload_result.checksum_sha256,
        }))
    }

    /// Pass-through download from the blob store.
    pub async fn download(&self, fid: &str) -> Result<Bytes, SentioError> {
        self.blob_store.download(fid).await
    }

    /// Pass-through delete from the blob store.
    pub async fn delete(&self, fid: &str) -> Result<(), SentioError> {
        self.blob_store.delete(fid).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{MockBlobStore, MockScanner};

    #[tokio::test]
    async fn process_clean_attachment() {
        let store = MockBlobStore::new();
        let scanner = MockScanner::new();
        let processor = AttachmentProcessor::new(store, scanner, false);

        let data = Bytes::from_static(b"hello world");
        let result = processor
            .process_attachment(
                data,
                "test.txt",
                "text/plain",
                TenantId(uuid::Uuid::new_v4()),
            )
            .await
            .unwrap();

        assert_eq!(result.scan_result, ScanResult::Clean);
        assert!(!result.fid.is_empty());
        assert!(result.size > 0);
    }

    #[tokio::test]
    async fn process_infected_attachment_deletes_blob() {
        let store = MockBlobStore::new();
        let scanner = MockScanner::new();
        scanner.set_infected("Eicar-Test");

        let processor = AttachmentProcessor::new(store.clone(), scanner, false);

        let data = Bytes::from_static(b"virus content");
        let result = processor
            .process_attachment(
                data,
                "bad.exe",
                "application/octet-stream",
                TenantId(uuid::Uuid::new_v4()),
            )
            .await
            .unwrap();

        assert!(matches!(result.scan_result, ScanResult::Infected(_)));
        // Blob should have been deleted
        assert!(!store.contains(&result.fid));
    }

    #[tokio::test]
    async fn process_raw_eml_when_enabled() {
        let store = MockBlobStore::new();
        let scanner = MockScanner::new();
        let processor = AttachmentProcessor::new(store, scanner, true);

        let data = Bytes::from_static(b"From: test@example.com\r\nSubject: hi\r\n\r\nBody");
        let result = processor.process_raw_eml(data).await.unwrap();

        assert!(result.is_some());
        let stored = result.unwrap();
        assert!(!stored.fid.is_empty());
    }

    #[tokio::test]
    async fn process_raw_eml_when_disabled() {
        let store = MockBlobStore::new();
        let scanner = MockScanner::new();
        let processor = AttachmentProcessor::new(store, scanner, false);

        let data = Bytes::from_static(b"From: test@example.com\r\n");
        let result = processor.process_raw_eml(data).await.unwrap();

        assert!(result.is_none());
    }
}
