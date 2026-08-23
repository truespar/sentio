//! Backwards-compatibility shim.
//!
//! The `KvConn` trait moved to `sentio_core::kv` and the backend impl
//! (`RedisPool`) now lives in `sentio-store`. This module keeps the
//! historical `sentio_abuse::KvConn` re-export so external callers don't
//! have to change imports.

pub use sentio_core::kv::KvConn;
