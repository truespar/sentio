//! S3-compatible blob store.
//!
//! The on-the-wire protocol is plain S3 (auto-create bucket, PUT / GET /
//! DELETE object), so any S3-compatible endpoint works - AWS S3,
//! Cloudflare R2, Backblaze B2, MinIO, SeaweedFS, Ceph RGW, Garage,
//! etc. Configure the endpoint URL, region, credentials
//! and `path_style` flag in `[storage]`.
//!
//! For backwards compatibility with the rest of the workspace this type
//! implements the `BlobStore` trait whose vocabulary still talks about
//! "fid"s - when used here the `fid` is simply the S3 object key (a
//! UUIDv4 string by default), and `AssignedFid.url` carries the bucket
//! endpoint.

use aws_config::{BehaviorVersion, Region};
use aws_credential_types::Credentials;
use aws_sdk_s3::config::Builder as S3ConfigBuilder;
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::operation::head_bucket::HeadBucketError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client as AwsS3Client;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use tracing::instrument;

use sentio_core::config::StorageConfig;
use sentio_core::error::SentioError;
use sentio_core::traits::{AssignedFid, BlobStore, UploadResult};

/// S3-backed blob store.
///
/// The struct field set deliberately mirrors what the rest of the
/// workspace needs: a configured client and the target bucket. The
/// endpoint URL, credentials, region and path-style flag are all baked
/// into the `aws_sdk_s3::Client` at construction time.
#[derive(Clone)]
pub struct S3BlobStore {
    client: AwsS3Client,
    bucket: String,
    /// Cached endpoint URL - returned via `AssignedFid.url` for
    /// observability / legacy compatibility.
    endpoint: String,
}

impl std::fmt::Debug for S3BlobStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3BlobStore")
            .field("bucket", &self.bucket)
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

impl S3BlobStore {
    /// Build a client from a `StorageConfig` and ensure the target bucket
    /// exists (creating it if not).
    #[instrument(skip(config), name = "s3.connect", fields(endpoint = %config.endpoint_url, bucket = %config.bucket))]
    pub async fn connect(config: &StorageConfig) -> Result<Self, SentioError> {
        let creds = Credentials::new(
            &config.access_key,
            &config.secret_key,
            None,
            None,
            "sentio-storage-config",
        );

        let s3_conf = S3ConfigBuilder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(config.region.clone()))
            .endpoint_url(&config.endpoint_url)
            .credentials_provider(creds)
            .force_path_style(config.path_style)
            .build();

        let client = AwsS3Client::from_conf(s3_conf);

        let store = Self {
            client,
            bucket: config.bucket.clone(),
            endpoint: config.endpoint_url.clone(),
        };

        store.ensure_bucket().await?;

        tracing::info!(
            endpoint = %config.endpoint_url,
            bucket = %config.bucket,
            "S3 blob store connected"
        );
        Ok(store)
    }

    /// Idempotently create the bucket if it does not already exist.
    async fn ensure_bucket(&self) -> Result<(), SentioError> {
        match self.client.head_bucket().bucket(&self.bucket).send().await {
            Ok(_) => Ok(()),
            Err(SdkError::ServiceError(svc_err)) => match svc_err.err() {
                HeadBucketError::NotFound(_) => {
                    tracing::info!(bucket = %self.bucket, "bucket not found, creating");
                    match self
                        .client
                        .create_bucket()
                        .bucket(&self.bucket)
                        .send()
                        .await
                    {
                        Ok(_) => Ok(()),
                        Err(e) => {
                            // Race: another worker / earlier run already created it.
                            let s = format!("{e:?}");
                            if s.contains("BucketAlreadyOwnedByYou")
                                || s.contains("BucketAlreadyExists")
                            {
                                tracing::info!(bucket = %self.bucket, "bucket already exists, continuing");
                                Ok(())
                            } else {
                                Err(SentioError::Storage(format!(
                                    "failed to create bucket {}: {e:?}",
                                    self.bucket
                                )))
                            }
                        }
                    }
                }
                other => Err(SentioError::Storage(format!(
                    "head_bucket failed for {}: {other:?}",
                    self.bucket
                ))),
            },
            Err(e) => Err(SentioError::Storage(format!(
                "head_bucket request failed for {}: {e:?}",
                self.bucket
            ))),
        }
    }

    /// Native S3 upload. Mirrors the surface the spec asked for - if no
    /// key is supplied a UUIDv4 is generated. Returns the key + size +
    /// sha256 (the trait `UploadResult` is reused so this aligns with
    /// the `BlobStore` implementation below).
    #[instrument(skip(self, bytes), name = "s3.upload_object", fields(bucket = %self.bucket, key, size = bytes.len()))]
    pub async fn upload_object(
        &self,
        key: Option<String>,
        bytes: Bytes,
        content_type: Option<&str>,
    ) -> Result<UploadResult, SentioError> {
        let key = key.unwrap_or_else(generate_key);
        let size = bytes.len() as u64;
        let checksum = Self::sha256(&bytes);

        let mut req = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(ByteStream::from(bytes));

        if let Some(ct) = content_type {
            req = req.content_type(ct);
        }

        req.send()
            .await
            .map_err(|e| SentioError::Storage(format!("put_object failed for {key}: {e}")))?;

        Ok(UploadResult {
            fid: key,
            size,
            checksum_sha256: checksum,
        })
    }

    /// Download bytes by object key.
    #[instrument(skip(self), name = "s3.download_object", fields(bucket = %self.bucket, key = %key))]
    pub async fn download_object(&self, key: &str) -> Result<Bytes, SentioError> {
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| SentioError::Storage(format!("get_object failed for {key}: {e}")))?;

        let bytes = resp
            .body
            .collect()
            .await
            .map_err(|e| SentioError::Storage(format!("failed to read body for {key}: {e}")))?
            .into_bytes();

        Ok(bytes)
    }

    /// Delete by object key.
    #[instrument(skip(self), name = "s3.delete_object", fields(bucket = %self.bucket, key = %key))]
    pub async fn delete_object(&self, key: &str) -> Result<(), SentioError> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| SentioError::Storage(format!("delete_object failed for {key}: {e}")))?;
        Ok(())
    }

    /// SHA256 helper (client-side content checksum).
    pub fn sha256(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    /// Bucket the client is bound to.
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Configured endpoint URL.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

fn generate_key() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ──────────────────────────────────────────────────────────────────────────────
// BlobStore trait - bridges the legacy `assign + upload(fid, …)` flow onto S3.
// ──────────────────────────────────────────────────────────────────────────────

impl BlobStore for S3BlobStore {
    /// Pre-allocate an object key so the caller can record the FID
    /// before the data has actually landed. With S3 there is no real
    /// "assign" step - we just mint a UUID and return it.
    #[instrument(skip(self), name = "s3.assign")]
    async fn assign(&self) -> Result<AssignedFid, SentioError> {
        Ok(AssignedFid {
            fid: generate_key(),
            url: self.endpoint.clone(),
        })
    }

    /// Upload to a previously-assigned key (or, equivalently, to any
    /// caller-chosen key). `filename` is best-effort propagated as a
    /// `Content-Disposition` header for friendlier downloads.
    #[instrument(
        skip(self, data),
        name = "s3.upload",
        fields(bucket = %self.bucket, key = %fid, filename, content_type, size = data.len())
    )]
    async fn upload(
        &self,
        fid: &str,
        data: Bytes,
        filename: &str,
        content_type: &str,
    ) -> Result<UploadResult, SentioError> {
        let size = data.len() as u64;
        let checksum = Self::sha256(&data);

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(fid)
            .body(ByteStream::from(data))
            .content_type(content_type)
            .content_disposition(format!("attachment; filename=\"{filename}\""))
            .send()
            .await
            .map_err(|e| SentioError::Storage(format!("put_object failed for {fid}: {e}")))?;

        Ok(UploadResult {
            fid: fid.to_string(),
            size,
            checksum_sha256: checksum,
        })
    }

    async fn download(&self, fid: &str) -> Result<Bytes, SentioError> {
        self.download_object(fid).await
    }

    async fn delete(&self, fid: &str) -> Result<(), SentioError> {
        self.delete_object(fid).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_helper_matches_known_vector() {
        // SHA-256 of "abc"
        assert_eq!(
            S3BlobStore::sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn generate_key_is_uuid_v4_shape() {
        let k = generate_key();
        // 8-4-4-4-12 hex = 36 chars
        assert_eq!(k.len(), 36);
        assert_eq!(k.chars().filter(|c| *c == '-').count(), 4);
    }
}
