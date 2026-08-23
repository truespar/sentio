use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// Headers attached to webhook HTTP requests.
pub const HEADER_TIMESTAMP: &str = "X-Sentio-Timestamp";
pub const HEADER_NONCE: &str = "X-Sentio-Nonce";
pub const HEADER_SIGNATURE: &str = "X-Sentio-Signature";
pub const HEADER_EVENT: &str = "X-Sentio-Event";

/// A computed webhook signature with its timestamp and nonce.
#[derive(Debug, Clone)]
pub struct WebhookSignature {
    pub timestamp: i64,
    pub nonce: String,
    pub signature: String,
}

/// Sign a webhook payload using HMAC-SHA256.
///
/// The signed message is the concatenation of `"{timestamp}.{nonce}."` and the
/// raw body bytes. Returns the hex-encoded signature.
pub fn sign_payload(secret: &str, timestamp: i64, nonce: &str, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    let prefix = format!("{}.{}.", timestamp, nonce);
    mac.update(prefix.as_bytes());
    mac.update(body);
    to_hex(&mac.finalize().into_bytes())
}

/// Build a complete webhook signature with a fresh timestamp and random nonce.
pub fn build_signature(secret: &str, body: &[u8]) -> WebhookSignature {
    let timestamp = chrono::Utc::now().timestamp();
    let nonce = generate_nonce();
    let signature = sign_payload(secret, timestamp, &nonce, body);
    WebhookSignature {
        timestamp,
        nonce,
        signature,
    }
}

/// Verify a webhook signature using constant-time comparison.
///
/// Returns `false` if the timestamp is outside the tolerance window (replay
/// prevention) or if the signature does not match.
pub fn verify_signature(
    secret: &str,
    timestamp: i64,
    nonce: &str,
    body: &[u8],
    provided_signature: &str,
    tolerance_secs: i64,
) -> bool {
    let now = chrono::Utc::now().timestamp();
    if (now - timestamp).abs() > tolerance_secs {
        return false;
    }

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    let prefix = format!("{}.{}.", timestamp, nonce);
    mac.update(prefix.as_bytes());
    mac.update(body);

    match hex_decode(provided_signature) {
        Some(sig_bytes) => mac.verify_slice(&sig_bytes).is_ok(),
        None => false,
    }
}

fn generate_nonce() -> String {
    use rand::RngExt;
    let bytes: [u8; 16] = rand::rng().random();
    to_hex(&bytes)
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let secret = "whsec_test_secret_123";
        let body = b"{\"event\":\"delivered\",\"message_id\":\"abc\"}";
        let timestamp = 1700000000i64;
        let nonce = "deadbeef01234567deadbeef01234567";

        let sig = sign_payload(secret, timestamp, nonce, body);
        assert_eq!(sig.len(), 64); // SHA-256 produces 32 bytes = 64 hex chars

        // Same inputs produce the same signature.
        let sig2 = sign_payload(secret, timestamp, nonce, body);
        assert_eq!(sig, sig2);

        // Different secret produces a different signature.
        let sig3 = sign_payload("other_secret", timestamp, nonce, body);
        assert_ne!(sig, sig3);

        // Different body produces a different signature.
        let sig4 = sign_payload(secret, timestamp, nonce, b"different");
        assert_ne!(sig, sig4);
    }

    #[test]
    fn build_signature_produces_valid_output() {
        let secret = "whsec_test";
        let body = b"hello";
        let ws = build_signature(secret, body);

        assert_eq!(ws.signature.len(), 64);
        assert_eq!(ws.nonce.len(), 32); // 16 bytes = 32 hex chars
        assert!(ws.timestamp > 0);

        // Verify the signature we just built (generous tolerance).
        assert!(verify_signature(
            secret,
            ws.timestamp,
            &ws.nonce,
            body,
            &ws.signature,
            60,
        ));
    }

    #[test]
    fn verify_rejects_expired_timestamp() {
        let secret = "sec";
        let body = b"payload";
        let old_timestamp = 1000000000i64; // ~2001, well outside any tolerance
        let nonce = "aabbccdd00112233aabbccdd00112233";
        let sig = sign_payload(secret, old_timestamp, nonce, body);

        assert!(!verify_signature(
            secret,
            old_timestamp,
            nonce,
            body,
            &sig,
            300
        ));
    }

    #[test]
    fn verify_rejects_wrong_signature() {
        let secret = "sec";
        let body = b"payload";
        let timestamp = chrono::Utc::now().timestamp();
        let nonce = "aabbccdd00112233aabbccdd00112233";

        assert!(!verify_signature(
            secret,
            timestamp,
            nonce,
            body,
            "0000000000000000000000000000000000000000000000000000000000000000",
            300,
        ));
    }

    #[test]
    fn verify_rejects_invalid_hex() {
        assert!(!verify_signature("s", 0, "n", b"b", "not-hex!", 999999999));
        assert!(!verify_signature("s", 0, "n", b"b", "abc", 999999999)); // odd length
    }

    #[test]
    fn hex_roundtrip() {
        let bytes = [0u8, 1, 15, 16, 255, 128];
        let hex = to_hex(&bytes);
        assert_eq!(hex, "00010f10ff80");
        let decoded = hex_decode(&hex).unwrap();
        assert_eq!(decoded, bytes);
    }
}
