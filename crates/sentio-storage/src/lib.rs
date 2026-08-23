pub mod attachment;
pub mod lifecycle;
pub mod s3;
pub mod scanner;

#[cfg(any(test, feature = "test-support"))]
pub mod mock;

pub use attachment::{AttachmentProcessor, ProcessedAttachment, StoredEml};
pub use lifecycle::BlobLifecycle;
pub use s3::S3BlobStore;
pub use scanner::ClamAvScanner;
