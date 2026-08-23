//! VERP (Variable Envelope Return Path) codec.
//!
//! Encodes a message UUID + per-instance HMAC tag into a bounce return-path
//! local-part of the form:
//!
//! ```text
//! bounce+{hex-uuid-no-dashes}.{hex-hmac-first-10-chars}
//! ```
//!
//! When the receiving MTA bounces a message, the bounce report arrives at
//! `bounce.{sending_domain}` and we can recover the original message ID
//! (with cryptographic confidence that the token wasn't fabricated) by
//! verifying the HMAC.
//!
//! HMAC verification is constant-time (via `subtle::ConstantTimeEq`) so an
//! attacker cannot recover the secret by timing how long a probe takes to
//! be rejected.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Length of the truncated HMAC tag in the local-part, in hex characters.
/// 10 hex chars = 5 bytes = 40 bits of HMAC, which is plenty to prevent
/// forgery without making the address absurdly long.
const TAG_HEX_LEN: usize = 10;
const TAG_BYTE_LEN: usize = TAG_HEX_LEN / 2;

/// Encoder/decoder for VERP bounce return-path local-parts.
#[derive(Clone)]
pub struct VerpCodec {
    secret: Vec<u8>,
}

impl VerpCodec {
    /// Create a new codec with the given per-instance secret.
    /// The secret must be the same on every node that may produce or parse
    /// bounce tokens. Rotating it invalidates all in-flight tokens.
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            secret: secret.into(),
        }
    }

    /// Compute the HMAC tag for a given hex-encoded UUID.
    fn tag_hex(&self, id_hex: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts any key size");
        mac.update(id_hex.as_bytes());
        let sig = mac.finalize().into_bytes();
        sig.iter()
            .take(TAG_BYTE_LEN)
            .fold(String::with_capacity(TAG_HEX_LEN), |mut acc, b| {
                use std::fmt::Write;
                write!(acc, "{:02x}", b).expect("writing to String never fails");
                acc
            })
    }

    /// Build a bounce local-part for the given message id.
    ///
    /// Format: `bounce+{hex-uuid-no-dashes}.{hex-hmac-first-10-chars}`
    pub fn encode_local_part(&self, msg_id: uuid::Uuid) -> String {
        let id_hex = msg_id.simple().to_string(); // 32 chars no dashes
        let sig_hex = self.tag_hex(&id_hex);
        format!("bounce+{id_hex}.{sig_hex}")
    }

    /// Build a full bounce return-path address.
    ///
    /// Format: `bounce+{token}@bounce.{sending_domain}`
    pub fn encode_address(&self, msg_id: uuid::Uuid, sending_domain: &str) -> String {
        format!(
            "{}@bounce.{}",
            self.encode_local_part(msg_id),
            sending_domain
        )
    }

    /// Parse a bounce local-part back to a UUID, verifying the HMAC.
    ///
    /// Returns `None` if the format is wrong OR the HMAC does not match.
    /// HMAC verification is constant-time.
    pub fn decode_local_part(&self, local_part: &str) -> Option<uuid::Uuid> {
        let rest = local_part.strip_prefix("bounce+")?;
        let (id_hex, sig_hex) = rest.split_once('.')?;
        if id_hex.len() != 32 || sig_hex.len() != TAG_HEX_LEN {
            return None;
        }
        // Parse the UUID first so we reject malformed hex up-front.
        let uuid = uuid::Uuid::parse_str(id_hex).ok()?;

        let expected_hex = self.tag_hex(id_hex);
        // Constant-time comparison.
        if expected_hex
            .as_bytes()
            .ct_eq(sig_hex.as_bytes())
            .unwrap_u8()
            == 1
        {
            Some(uuid)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let c = VerpCodec::new(b"test-secret".to_vec());
        let id = uuid::Uuid::new_v4();
        let local = c.encode_local_part(id);
        assert!(local.starts_with("bounce+"));
        // 7 ("bounce+") + 32 (uuid) + 1 (".") + 10 (sig) = 50
        assert_eq!(local.len(), 50);
        assert_eq!(c.decode_local_part(&local), Some(id));
    }

    #[test]
    fn encode_address_includes_subdomain() {
        let c = VerpCodec::new(b"k".to_vec());
        let id = uuid::Uuid::nil();
        let addr = c.encode_address(id, "example.com");
        assert!(addr.starts_with("bounce+"));
        assert!(addr.ends_with("@bounce.example.com"));
    }

    #[test]
    fn tamper_detected() {
        let c = VerpCodec::new(b"test-secret".to_vec());
        let id = uuid::Uuid::new_v4();
        let mut local = c.encode_local_part(id);
        // Flip the last hex digit.
        let last = local.pop().unwrap();
        local.push(if last == 'f' { '0' } else { 'f' });
        assert_eq!(c.decode_local_part(&local), None);
    }

    #[test]
    fn wrong_secret_rejected() {
        let c1 = VerpCodec::new(b"key-one".to_vec());
        let c2 = VerpCodec::new(b"key-two".to_vec());
        let id = uuid::Uuid::new_v4();
        let local = c1.encode_local_part(id);
        assert_eq!(c2.decode_local_part(&local), None);
    }

    #[test]
    fn bad_prefix_rejected() {
        let c = VerpCodec::new(b"k".to_vec());
        assert_eq!(c.decode_local_part("info"), None);
        assert_eq!(c.decode_local_part("bounce-abc.1234567890"), None);
    }

    #[test]
    fn bad_lengths_rejected() {
        let c = VerpCodec::new(b"k".to_vec());
        // UUID hex too short
        assert_eq!(c.decode_local_part("bounce+abc.1234567890"), None);
        // tag too short
        assert_eq!(
            c.decode_local_part("bounce+00000000000000000000000000000000.12345"),
            None
        );
        // tag too long
        assert_eq!(
            c.decode_local_part("bounce+00000000000000000000000000000000.1234567890abcdef"),
            None
        );
    }

    #[test]
    fn missing_separator_rejected() {
        let c = VerpCodec::new(b"k".to_vec());
        assert_eq!(
            c.decode_local_part("bounce+00000000000000000000000000000000abcdef0123"),
            None
        );
    }

    #[test]
    fn invalid_uuid_hex_rejected() {
        let c = VerpCodec::new(b"k".to_vec());
        // 32 chars but not valid hex
        let id_hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let sig = c.tag_hex(id_hex);
        let local = format!("bounce+{id_hex}.{sig}");
        // tag_hex would happily compute for any input, but Uuid::parse_str rejects
        assert_eq!(c.decode_local_part(&local), None);
    }
}
