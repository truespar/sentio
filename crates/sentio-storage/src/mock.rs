use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use sha2::{Digest, Sha256};

use sentio_core::error::SentioError;
use sentio_core::ids::PendingUploadId;
use sentio_core::message::ScanStatus;
use sentio_core::tenant::TenantId;
use sentio_core::traits::{
    AssignedFid, BlobStore, PendingUploadRecord, PendingUploadRepository, ScanResult, UploadResult,
    VirusScanner,
};

// ──────────────────────────────────────────────────────────────────────────────
// MockBlobStore
// ──────────────────────────────────────────────────────────────────────────────

#[allow(dead_code)]
struct StoredBlob {
    data: Bytes,
    filename: String,
    content_type: String,
}

#[derive(Clone)]
pub struct MockBlobStore {
    blobs: Arc<Mutex<HashMap<String, StoredBlob>>>,
    counter: Arc<AtomicU64>,
}

impl MockBlobStore {
    pub fn new() -> Self {
        Self {
            blobs: Arc::new(Mutex::new(HashMap::new())),
            counter: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Check if a FID exists in the store.
    pub fn contains(&self, fid: &str) -> bool {
        self.blobs.lock().unwrap().contains_key(fid)
    }

    /// Directly insert data for testing.
    pub fn put(&self, fid: &str, data: &[u8]) {
        self.blobs.lock().unwrap().insert(
            fid.to_string(),
            StoredBlob {
                data: Bytes::copy_from_slice(data),
                filename: "test".to_string(),
                content_type: "application/octet-stream".to_string(),
            },
        );
    }
}

impl Default for MockBlobStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BlobStore for MockBlobStore {
    async fn assign(&self) -> Result<AssignedFid, SentioError> {
        let id = self.counter.fetch_add(1, Ordering::Relaxed);
        let fid = format!("1,{id:08x}");
        Ok(AssignedFid {
            fid,
            url: "mock://localhost:8080".to_string(),
        })
    }

    async fn upload(
        &self,
        fid: &str,
        data: Bytes,
        filename: &str,
        content_type: &str,
    ) -> Result<UploadResult, SentioError> {
        let size = data.len() as u64;
        let checksum = {
            let mut hasher = Sha256::new();
            hasher.update(&data);
            hex::encode(hasher.finalize())
        };

        self.blobs.lock().unwrap().insert(
            fid.to_string(),
            StoredBlob {
                data,
                filename: filename.to_string(),
                content_type: content_type.to_string(),
            },
        );

        Ok(UploadResult {
            fid: fid.to_string(),
            size,
            checksum_sha256: checksum,
        })
    }

    async fn download(&self, fid: &str) -> Result<Bytes, SentioError> {
        self.blobs
            .lock()
            .unwrap()
            .get(fid)
            .map(|b| b.data.clone())
            .ok_or_else(|| SentioError::NotFound {
                entity: "blob",
                id: fid.to_string(),
            })
    }

    async fn delete(&self, fid: &str) -> Result<(), SentioError> {
        self.blobs.lock().unwrap().remove(fid);
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// MockScanner
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct MockScanner {
    result: Arc<Mutex<ScanResult>>,
}

impl MockScanner {
    pub fn new() -> Self {
        Self {
            result: Arc::new(Mutex::new(ScanResult::Clean)),
        }
    }

    pub fn set_infected(&self, virus_name: &str) {
        *self.result.lock().unwrap() = ScanResult::Infected(virus_name.to_string());
    }

    pub fn set_error(&self, message: &str) {
        *self.result.lock().unwrap() = ScanResult::Error(message.to_string());
    }

    pub fn set_clean(&self) {
        *self.result.lock().unwrap() = ScanResult::Clean;
    }
}

impl Default for MockScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl VirusScanner for MockScanner {
    async fn scan(&self, _data: &[u8]) -> Result<ScanResult, SentioError> {
        Ok(self.result.lock().unwrap().clone())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// MockPendingUploads
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct MockPendingUploads {
    expired: Arc<Mutex<Vec<PendingUploadRecord>>>,
}

impl MockPendingUploads {
    pub fn new() -> Self {
        Self {
            expired: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Add a record that will be returned by list_expired.
    pub fn add_expired(&self, fid: &str) {
        let now = chrono::Utc::now();
        self.expired.lock().unwrap().push(PendingUploadRecord {
            id: PendingUploadId(uuid::Uuid::new_v4()),
            tenant_id: TenantId(uuid::Uuid::new_v4()),
            blob_key: fid.to_string(),
            filename: "expired.dat".to_string(),
            content_type: "application/octet-stream".to_string(),
            size: 100,
            checksum_sha256: None,
            scan_status: ScanStatus::Pending,
            scan_result: None,
            claimed: false,
            expires_at: now - chrono::Duration::hours(1),
            created_at: now - chrono::Duration::hours(2),
        });
    }
}

impl Default for MockPendingUploads {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingUploadRepository for MockPendingUploads {
    async fn create(
        &self,
        _upload: sentio_core::traits::NewPendingUpload,
    ) -> Result<PendingUploadId, SentioError> {
        Ok(PendingUploadId(uuid::Uuid::new_v4()))
    }

    async fn get(&self, _id: PendingUploadId) -> Result<PendingUploadRecord, SentioError> {
        Err(SentioError::NotFound {
            entity: "pending_upload",
            id: "mock".to_string(),
        })
    }

    async fn claim(&self, _id: PendingUploadId) -> Result<(), SentioError> {
        Ok(())
    }

    async fn update_scan_status(
        &self,
        _id: PendingUploadId,
        _scan_status: ScanStatus,
        _scan_result: Option<&str>,
    ) -> Result<(), SentioError> {
        Ok(())
    }

    async fn delete_expired(&self) -> Result<u64, SentioError> {
        let mut expired = self.expired.lock().unwrap();
        let count = expired.len() as u64;
        expired.clear();
        Ok(count)
    }

    async fn list_expired(&self, limit: i64) -> Result<Vec<PendingUploadRecord>, SentioError> {
        let expired = self.expired.lock().unwrap();
        Ok(expired.iter().take(limit as usize).cloned().collect())
    }
}
