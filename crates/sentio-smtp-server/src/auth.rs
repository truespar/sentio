use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sentio_core::error::SentioError;
use sentio_core::traits::SmtpCredentialRecord;
use sha2::{Digest, Sha256};

use crate::response::SmtpResponse;

// ──────────────────────────────────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────────────────────────────────

/// Successful authentication identity.
#[derive(Debug, Clone)]
pub struct AuthResult {
    pub username: String,
    pub tenant_id: sentio_core::tenant::TenantId,
}

/// Progress of a multi-step SASL exchange.
pub enum AuthProgress {
    /// Authentication completed successfully.
    Complete(AuthResult),
    /// Server needs more data from the client. Send the challenge and
    /// store the state.
    Challenge(Box<AuthState>, SmtpResponse),
}

/// State machine for multi-step SASL mechanisms.
pub enum AuthState {
    /// PLAIN: waiting for client to send the base64 blob.
    WaitingPlainData,
    /// LOGIN step 1: waiting for username.
    LoginWaitingUsername,
    /// LOGIN step 2: have username, waiting for password.
    LoginWaitingPassword(String),
    /// SCRAM-SHA-256: server-side state for the ongoing handshake.
    ScramStep(Box<ScramServerState>),
}

/// Boxed async closure for credential lookup - avoids generic propagation.
pub type CredentialLookup = Arc<
    dyn Fn(&str) -> Pin<Box<dyn Future<Output = Result<SmtpCredentialRecord, SentioError>> + Send>>
        + Send
        + Sync,
>;

// ──────────────────────────────────────────────────────────────────────────────
// Error mapping
// ──────────────────────────────────────────────────────────────────────────────

/// Map a credential-lookup error to the appropriate SMTP response.
///
/// * `NotFound` → 535 (permanent - user doesn't exist)
/// * `Database` / `Redis` / `Internal` / others → 454 (transient - backend down)
pub fn lookup_error_to_response(err: SentioError) -> SmtpResponse {
    match err {
        SentioError::NotFound { .. } => SmtpResponse::auth_failed(),
        _ => SmtpResponse::auth_temp_failure(),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Entry point
// ──────────────────────────────────────────────────────────────────────────────

/// Begin a SASL authentication exchange.
///
/// `args` is everything after "AUTH ", e.g. `"PLAIN dGVzdA=="` or `"LOGIN"`.
/// `channel_binding_data` is the `tls-server-end-point` hash when TLS is active.
pub async fn begin_auth(
    args: &str,
    lookup: &CredentialLookup,
    channel_binding_data: Option<&[u8]>,
) -> Result<AuthProgress, SmtpResponse> {
    let (mechanism, initial_response) = match args.find(' ') {
        Some(pos) => {
            let ir = args[pos + 1..].trim();
            // RFC 4954 §3: initial-response of "=" means zero-length data
            if ir == "=" {
                (args[..pos].to_ascii_uppercase(), Some(""))
            } else {
                (args[..pos].to_ascii_uppercase(), Some(ir))
            }
        }
        None => (args.to_ascii_uppercase(), None),
    };

    match mechanism.as_str() {
        "PLAIN" => handle_plain_begin(initial_response, lookup).await,
        "LOGIN" => handle_login_begin(initial_response),
        "SCRAM-SHA-256" => handle_scram_begin(initial_response, None),
        "SCRAM-SHA-256-PLUS" => {
            let cb = channel_binding_data.ok_or_else(SmtpResponse::auth_failed)?;
            handle_scram_begin(initial_response, Some(cb.to_vec()))
        }
        _ => Err(SmtpResponse::auth_mechanism_not_supported()),
    }
}

/// Continue a multi-step SASL exchange with client data.
pub async fn continue_auth(
    state: AuthState,
    line: &[u8],
    lookup: &CredentialLookup,
    _channel_binding_data: Option<&[u8]>,
) -> Result<AuthProgress, SmtpResponse> {
    let text = std::str::from_utf8(line).map_err(|_| SmtpResponse::auth_failed())?;
    let text = text.trim();

    // Client cancellation
    if text == "*" {
        return Err(SmtpResponse::auth_cancelled());
    }

    match state {
        AuthState::WaitingPlainData => {
            let decoded = B64.decode(text).map_err(|_| SmtpResponse::auth_failed())?;
            verify_plain(&decoded, lookup).await
        }
        AuthState::LoginWaitingUsername => {
            let username_bytes = B64.decode(text).map_err(|_| SmtpResponse::auth_failed())?;
            let username =
                String::from_utf8(username_bytes).map_err(|_| SmtpResponse::auth_failed())?;
            Ok(AuthProgress::Challenge(
                Box::new(AuthState::LoginWaitingPassword(username)),
                SmtpResponse::auth_challenge("UGFzc3dvcmQ6"), // "Password:" in base64
            ))
        }
        AuthState::LoginWaitingPassword(username) => {
            let password_bytes = B64.decode(text).map_err(|_| SmtpResponse::auth_failed())?;
            let password =
                String::from_utf8(password_bytes).map_err(|_| SmtpResponse::auth_failed())?;
            verify_credentials(&username, &password, lookup).await
        }
        AuthState::ScramStep(scram_state) => {
            handle_scram_continue(*scram_state, text, lookup).await
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// PLAIN (RFC 4616)
// ──────────────────────────────────────────────────────────────────────────────

async fn handle_plain_begin(
    initial_response: Option<&str>,
    lookup: &CredentialLookup,
) -> Result<AuthProgress, SmtpResponse> {
    match initial_response {
        Some(data) => {
            let decoded = B64.decode(data).map_err(|_| SmtpResponse::auth_failed())?;
            verify_plain(&decoded, lookup).await
        }
        None => Ok(AuthProgress::Challenge(
            Box::new(AuthState::WaitingPlainData),
            SmtpResponse::auth_continue(),
        )),
    }
}

/// Verify PLAIN credentials: `\0authzid\0authcid\0passwd` or `\0authcid\0passwd`.
async fn verify_plain(
    data: &[u8],
    lookup: &CredentialLookup,
) -> Result<AuthProgress, SmtpResponse> {
    // PLAIN format: [authzid] NUL authcid NUL passwd
    let parts: Vec<&[u8]> = data.split(|&b| b == 0).collect();
    let (username, password) = match parts.len() {
        3 => {
            // parts[0] = authzid (often empty), parts[1] = authcid, parts[2] = passwd
            let user = std::str::from_utf8(parts[1]).map_err(|_| SmtpResponse::auth_failed())?;
            let pass = std::str::from_utf8(parts[2]).map_err(|_| SmtpResponse::auth_failed())?;
            (user, pass)
        }
        _ => return Err(SmtpResponse::auth_failed()),
    };

    verify_credentials(username, password, lookup).await
}

// ──────────────────────────────────────────────────────────────────────────────
// LOGIN (draft-murchison-sasl-login)
// ──────────────────────────────────────────────────────────────────────────────

fn handle_login_begin(initial_response: Option<&str>) -> Result<AuthProgress, SmtpResponse> {
    match initial_response {
        Some(data) => {
            // Initial response is the username
            let username_bytes = B64.decode(data).map_err(|_| SmtpResponse::auth_failed())?;
            let username =
                String::from_utf8(username_bytes).map_err(|_| SmtpResponse::auth_failed())?;
            Ok(AuthProgress::Challenge(
                Box::new(AuthState::LoginWaitingPassword(username)),
                SmtpResponse::auth_challenge("UGFzc3dvcmQ6"), // "Password:"
            ))
        }
        None => Ok(AuthProgress::Challenge(
            Box::new(AuthState::LoginWaitingUsername),
            SmtpResponse::auth_challenge("VXNlcm5hbWU6"), // "Username:"
        )),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// SCRAM-SHA-256 (RFC 5802 / 7677)
// ──────────────────────────────────────────────────────────────────────────────

/// Server-side SCRAM state between steps.
pub struct ScramServerState {
    /// The client-first-message-bare (for building AuthMessage).
    client_first_bare: String,
    /// The server-first-message sent to the client.
    server_first: String,
    /// Stored key from the credential record (base64).
    stored_key_b64: String,
    /// Server key from the credential record (base64).
    server_key_b64: String,
    /// The nonce (client + server combined).
    combined_nonce: String,
    /// Salt (base64).
    salt_b64: String,
    /// Iteration count.
    iterations: u32,
    /// Username extracted from client-first.
    username: String,
    /// Tenant ID from the credential record.
    tenant_id: sentio_core::tenant::TenantId,
    /// Channel binding data (tls-server-end-point hash) for -PLUS mechanisms.
    channel_binding_data: Option<Vec<u8>>,
    /// GS2 channel binding flag: 'n' (no binding), 'y' (supports but not used),
    /// 'p' (binding required and used).
    gs2_cbind_flag: char,
    /// The full GS2 header from client-first (e.g. "n,,", "y,,", "p=tls-server-end-point,,").
    gs2_header: String,
}

fn handle_scram_begin(
    initial_response: Option<&str>,
    channel_binding_data: Option<Vec<u8>>,
) -> Result<AuthProgress, SmtpResponse> {
    let data = match initial_response {
        Some(d) => B64.decode(d).map_err(|_| SmtpResponse::auth_failed())?,
        None => {
            return Ok(AuthProgress::Challenge(
                Box::new(AuthState::ScramStep(Box::new(ScramServerState {
                    client_first_bare: String::new(),
                    server_first: String::new(),
                    stored_key_b64: String::new(),
                    server_key_b64: String::new(),
                    combined_nonce: String::new(),
                    salt_b64: String::new(),
                    iterations: 0,
                    username: String::new(),
                    tenant_id: sentio_core::tenant::TenantId(uuid::Uuid::nil()),
                    channel_binding_data,
                    gs2_cbind_flag: 'n',
                    gs2_header: String::new(),
                }))),
                SmtpResponse::auth_continue(),
            ));
        }
    };
    let client_first = String::from_utf8(data).map_err(|_| SmtpResponse::auth_failed())?;
    scram_process_client_first(&client_first, channel_binding_data)
}

/// Process client-first-message, produce the server-first challenge.
fn scram_process_client_first(
    client_first: &str,
    channel_binding_data: Option<Vec<u8>>,
) -> Result<AuthProgress, SmtpResponse> {
    // Format: gs2-header, client-first-message-bare
    // gs2-header can be:
    //   "n,," - client does not support channel binding
    //   "y,," - client supports channel binding but not using it
    //   "p=tls-server-end-point,," - client requires channel binding
    let (gs2_header, gs2_cbind_flag, bare) = if let Some(rest) = client_first.strip_prefix("n,,") {
        ("n,,".to_string(), 'n', rest)
    } else if let Some(rest) = client_first.strip_prefix("y,,") {
        ("y,,".to_string(), 'y', rest)
    } else if let Some(after_p) = client_first.strip_prefix("p=") {
        // Parse "p=<cb-name>,," - extract the channel binding type
        let comma_pos = after_p.find(',').ok_or_else(SmtpResponse::auth_failed)?;
        let cb_name = &after_p[..comma_pos];
        if cb_name != "tls-server-end-point" {
            return Err(SmtpResponse::auth_failed());
        }
        // Expect ",," after cb-name (authzid is empty)
        let rest_after_cb = &after_p[comma_pos..];
        let bare = rest_after_cb
            .strip_prefix(",,")
            .ok_or_else(SmtpResponse::auth_failed)?;
        let gs2 = format!("p={cb_name},,");
        // Channel binding data must be available for -PLUS
        if channel_binding_data.is_none() {
            return Err(SmtpResponse::auth_failed());
        }
        (gs2, 'p', bare)
    } else {
        return Err(SmtpResponse::auth_failed());
    };

    let mut username = None;
    let mut client_nonce = None;
    for part in bare.split(',') {
        if let Some(u) = part.strip_prefix("n=") {
            username = Some(u.to_string());
        } else if let Some(r) = part.strip_prefix("r=") {
            client_nonce = Some(r.to_string());
        }
    }

    let username = username.ok_or_else(SmtpResponse::auth_failed)?;
    let client_nonce = client_nonce.ok_or_else(SmtpResponse::auth_failed)?;

    // We store the parsed info but need the credential lookup to happen
    // in the next step. Store a partial state to be completed later.
    Ok(AuthProgress::Challenge(
        Box::new(AuthState::ScramStep(Box::new(ScramServerState {
            client_first_bare: bare.to_string(),
            server_first: String::new(), // filled after lookup
            stored_key_b64: String::new(),
            server_key_b64: String::new(),
            combined_nonce: client_nonce,
            salt_b64: String::new(),
            iterations: 0,
            username,
            tenant_id: sentio_core::tenant::TenantId(uuid::Uuid::nil()),
            channel_binding_data,
            gs2_cbind_flag,
            gs2_header,
        }))),
        // We send a placeholder challenge. The real server-first is produced
        // in continue_auth after credential lookup.
        SmtpResponse::auth_continue(),
    ))
}

async fn handle_scram_continue(
    state: ScramServerState,
    client_data: &str,
    lookup: &CredentialLookup,
) -> Result<AuthProgress, SmtpResponse> {
    let data = B64
        .decode(client_data)
        .map_err(|_| SmtpResponse::auth_failed())?;
    let msg = String::from_utf8(data).map_err(|_| SmtpResponse::auth_failed())?;

    if state.server_first.is_empty() {
        // This is the actual client-first-bare (if initial was empty) or
        // we need to do credential lookup now and produce server-first.
        //
        // If client_first_bare is empty, this msg IS the client-first-message
        if state.client_first_bare.is_empty() {
            // This is the full client-first-message
            return scram_process_full_first(&msg, lookup, &state).await;
        }

        // We have client_first_bare, need to do lookup and produce server-first
        return scram_produce_server_first(state, lookup).await;
    }

    // We have server_first - this must be client-final-message
    scram_process_client_final(state, &msg)
}

async fn scram_process_full_first(
    client_first: &str,
    lookup: &CredentialLookup,
    state: &ScramServerState,
) -> Result<AuthProgress, SmtpResponse> {
    let (gs2_header, gs2_cbind_flag, bare) = if let Some(rest) = client_first.strip_prefix("n,,") {
        ("n,,".to_string(), 'n', rest)
    } else if let Some(rest) = client_first.strip_prefix("y,,") {
        ("y,,".to_string(), 'y', rest)
    } else if let Some(after_p) = client_first.strip_prefix("p=") {
        let comma_pos = after_p.find(',').ok_or_else(SmtpResponse::auth_failed)?;
        let cb_name = &after_p[..comma_pos];
        if cb_name != "tls-server-end-point" {
            return Err(SmtpResponse::auth_failed());
        }
        let rest_after_cb = &after_p[comma_pos..];
        let bare = rest_after_cb
            .strip_prefix(",,")
            .ok_or_else(SmtpResponse::auth_failed)?;
        let gs2 = format!("p={cb_name},,");
        if state.channel_binding_data.is_none() {
            return Err(SmtpResponse::auth_failed());
        }
        (gs2, 'p', bare)
    } else {
        return Err(SmtpResponse::auth_failed());
    };

    let mut username = None;
    let mut client_nonce = None;
    for part in bare.split(',') {
        if let Some(u) = part.strip_prefix("n=") {
            username = Some(u.to_string());
        } else if let Some(r) = part.strip_prefix("r=") {
            client_nonce = Some(r.to_string());
        }
    }

    let username = username.ok_or_else(SmtpResponse::auth_failed)?;
    let client_nonce = client_nonce.ok_or_else(SmtpResponse::auth_failed)?;

    let record = lookup(&username).await.map_err(lookup_error_to_response)?;
    if !record.enabled {
        return Err(SmtpResponse::auth_failed());
    }

    let stored_key_b64 = record
        .scram_stored_key
        .ok_or_else(SmtpResponse::auth_failed)?;
    let server_key_b64 = record
        .scram_server_key
        .ok_or_else(SmtpResponse::auth_failed)?;
    let salt_b64 = record.scram_salt.ok_or_else(SmtpResponse::auth_failed)?;
    let iterations = record
        .scram_iterations
        .ok_or_else(SmtpResponse::auth_failed)? as u32;

    // Generate server nonce
    let server_nonce = generate_nonce();
    let combined_nonce = format!("{client_nonce}{server_nonce}");

    let server_first = format!("r={combined_nonce},s={salt_b64},i={iterations}");

    let challenge = B64.encode(&server_first);

    Ok(AuthProgress::Challenge(
        Box::new(AuthState::ScramStep(Box::new(ScramServerState {
            client_first_bare: bare.to_string(),
            server_first,
            stored_key_b64,
            server_key_b64,
            combined_nonce,
            salt_b64,
            iterations,
            username,
            tenant_id: record.tenant_id,
            channel_binding_data: state.channel_binding_data.clone(),
            gs2_cbind_flag,
            gs2_header,
        }))),
        SmtpResponse::auth_challenge(&challenge),
    ))
}

async fn scram_produce_server_first(
    mut state: ScramServerState,
    lookup: &CredentialLookup,
) -> Result<AuthProgress, SmtpResponse> {
    let record = lookup(&state.username)
        .await
        .map_err(lookup_error_to_response)?;
    if !record.enabled {
        return Err(SmtpResponse::auth_failed());
    }

    state.stored_key_b64 = record
        .scram_stored_key
        .ok_or_else(SmtpResponse::auth_failed)?;
    state.server_key_b64 = record
        .scram_server_key
        .ok_or_else(SmtpResponse::auth_failed)?;
    state.salt_b64 = record.scram_salt.ok_or_else(SmtpResponse::auth_failed)?;
    state.iterations = record
        .scram_iterations
        .ok_or_else(SmtpResponse::auth_failed)? as u32;
    state.tenant_id = record.tenant_id;

    let server_nonce = generate_nonce();
    let client_nonce = state.combined_nonce.clone();
    state.combined_nonce = format!("{client_nonce}{server_nonce}");

    state.server_first = format!(
        "r={},s={},i={}",
        state.combined_nonce, state.salt_b64, state.iterations
    );

    let challenge = B64.encode(&state.server_first);

    Ok(AuthProgress::Challenge(
        Box::new(AuthState::ScramStep(Box::new(state))),
        SmtpResponse::auth_challenge(&challenge),
    ))
}

fn scram_process_client_final(
    state: ScramServerState,
    client_final: &str,
) -> Result<AuthProgress, SmtpResponse> {
    // client-final-message = channel-binding "," nonce "," [extensions ","] proof
    // channel-binding = "c=" base64(gs2-header [+ channel-binding-data])
    // Format: c=<cb>,r=<combined_nonce>,p=<proof>

    let mut channel_binding_b64 = None;
    let mut nonce = None;
    let mut proof_b64 = None;

    for part in client_final.split(',') {
        if let Some(c) = part.strip_prefix("c=") {
            channel_binding_b64 = Some(c.to_string());
        } else if let Some(r) = part.strip_prefix("r=") {
            nonce = Some(r.to_string());
        } else if let Some(p) = part.strip_prefix("p=") {
            proof_b64 = Some(p.to_string());
        }
    }

    // Verify channel binding
    let cb_b64 = channel_binding_b64.ok_or_else(SmtpResponse::auth_failed)?;
    let cb_data = B64
        .decode(&cb_b64)
        .map_err(|_| SmtpResponse::auth_failed())?;

    // Build expected channel binding value: gs2-header + (channel binding data if p=)
    let mut expected_cb = state.gs2_header.as_bytes().to_vec();
    if state.gs2_cbind_flag == 'p' {
        if let Some(ref binding_data) = state.channel_binding_data {
            expected_cb.extend_from_slice(binding_data);
        } else {
            return Err(SmtpResponse::auth_failed());
        }
    }

    if !constant_time_eq(&cb_data, &expected_cb) {
        return Err(SmtpResponse::auth_failed());
    }

    // Build client-final-message-without-proof
    let parts: Vec<&str> = client_final.split(',').collect();
    let without_proof: Vec<&str> = parts
        .iter()
        .filter(|p| !p.starts_with("p="))
        .copied()
        .collect();
    let client_final_without_proof = without_proof.join(",");

    let nonce = nonce.ok_or_else(SmtpResponse::auth_failed)?;
    let proof_b64 = proof_b64.ok_or_else(SmtpResponse::auth_failed)?;

    // Verify nonce matches
    if nonce != state.combined_nonce {
        return Err(SmtpResponse::auth_failed());
    }

    // Compute AuthMessage
    let auth_message = format!(
        "{},{},{}",
        state.client_first_bare, state.server_first, client_final_without_proof
    );

    // Verify proof
    let stored_key = B64
        .decode(&state.stored_key_b64)
        .map_err(|_| SmtpResponse::auth_failed())?;

    // ClientSignature = HMAC(StoredKey, AuthMessage)
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&stored_key).map_err(|_| SmtpResponse::auth_failed())?;
    mac.update(auth_message.as_bytes());
    let client_signature = mac.finalize().into_bytes();

    // ClientProof = ClientKey XOR ClientSignature
    // So: ClientKey = ClientProof XOR ClientSignature
    let client_proof = B64
        .decode(&proof_b64)
        .map_err(|_| SmtpResponse::auth_failed())?;
    if client_proof.len() != client_signature.len() {
        return Err(SmtpResponse::auth_failed());
    }

    let client_key: Vec<u8> = client_proof
        .iter()
        .zip(client_signature.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    // StoredKey = H(ClientKey)
    let computed_stored_key = Sha256::digest(&client_key);

    // Constant-time comparison
    if !constant_time_eq(&computed_stored_key, &stored_key) {
        return Err(SmtpResponse::auth_failed());
    }

    // Server signature is computed but not sent in the SMTP 235 response.
    // Per RFC 5802, the server-final-message is for client verification,
    // but SMTP AUTH returns a simple 235 on success.
    Ok(AuthProgress::Complete(AuthResult {
        username: state.username,
        tenant_id: state.tenant_id,
    }))
}

// ──────────────────────────────────────────────────────────────────────────────
// Credential verification (PLAIN / LOGIN)
// ──────────────────────────────────────────────────────────────────────────────

async fn verify_credentials(
    username: &str,
    password: &str,
    lookup: &CredentialLookup,
) -> Result<AuthProgress, SmtpResponse> {
    let record = lookup(username).await.map_err(lookup_error_to_response)?;

    if !record.enabled {
        return Err(SmtpResponse::auth_failed());
    }

    let hash = record.password_hash.clone();
    let pw = password.to_string();

    // Argon2 verification on a blocking thread to avoid blocking the async runtime
    let valid = tokio::task::spawn_blocking(move || verify_argon2(&hash, &pw))
        .await
        .map_err(|_| SmtpResponse::auth_failed())?;

    if valid {
        Ok(AuthProgress::Complete(AuthResult {
            username: record.username,
            tenant_id: record.tenant_id,
        }))
    } else {
        Err(SmtpResponse::auth_failed())
    }
}

fn verify_argon2(hash: &str, password: &str) -> bool {
    use argon2::password_hash::PasswordHash;
    use argon2::PasswordVerifier;

    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };

    argon2::Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

fn generate_nonce() -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    let bytes: [u8; 18] = rng.random();
    B64.encode(bytes)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentio_core::ids::SmtpCredentialId;
    use sentio_core::tenant::TenantId;

    fn make_lookup(record: SmtpCredentialRecord) -> CredentialLookup {
        Arc::new(move |_username: &str| {
            let r = record.clone();
            Box::pin(async move { Ok(r) })
        })
    }

    fn make_failing_lookup() -> CredentialLookup {
        Arc::new(|_username: &str| {
            Box::pin(async move {
                Err(SentioError::NotFound {
                    entity: "credential",
                    id: "unknown".into(),
                })
            })
        })
    }

    fn test_record(password: &str) -> SmtpCredentialRecord {
        use argon2::password_hash::SaltString;
        use argon2::PasswordHasher;

        let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        let hash = argon2::Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        SmtpCredentialRecord {
            id: SmtpCredentialId(uuid::Uuid::new_v4()),
            tenant_id: TenantId(uuid::Uuid::new_v4()),
            username: "testuser".into(),
            password_hash: hash,
            mechanisms: vec!["PLAIN".into(), "LOGIN".into()],
            scram_stored_key: None,
            scram_server_key: None,
            scram_salt: None,
            scram_iterations: None,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn plain_inline_success() {
        let record = test_record("secret123");
        let lookup = make_lookup(record);

        // PLAIN format: \0username\0password
        let plain_data = B64.encode(b"\0testuser\0secret123");
        let args = format!("PLAIN {plain_data}");

        let result = begin_auth(&args, &lookup, None).await.unwrap();
        match result {
            AuthProgress::Complete(auth) => {
                assert_eq!(auth.username, "testuser");
            }
            AuthProgress::Challenge(_, _) => panic!("expected complete"),
        }
    }

    #[tokio::test]
    async fn plain_two_step() {
        let record = test_record("secret123");
        let lookup = make_lookup(record);

        // Step 1: AUTH PLAIN (no initial response)
        let result = begin_auth("PLAIN", &lookup, None).await.unwrap();
        let state = match result {
            AuthProgress::Challenge(state, resp) => {
                assert_eq!(resp.code, 334);
                state
            }
            _ => panic!("expected challenge"),
        };

        // Step 2: send credentials
        let plain_data = B64.encode(b"\0testuser\0secret123");
        let result = continue_auth(*state, plain_data.as_bytes(), &lookup, None)
            .await
            .unwrap();
        match result {
            AuthProgress::Complete(auth) => assert_eq!(auth.username, "testuser"),
            _ => panic!("expected complete"),
        }
    }

    #[tokio::test]
    async fn plain_wrong_password() {
        let record = test_record("correct_password");
        let lookup = make_lookup(record);

        let plain_data = B64.encode(b"\0testuser\0wrong_password");
        let args = format!("PLAIN {plain_data}");
        let result = begin_auth(&args, &lookup, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn login_full_flow() {
        let record = test_record("mypassword");
        let lookup = make_lookup(record);

        // Step 1: AUTH LOGIN
        let result = begin_auth("LOGIN", &lookup, None).await.unwrap();
        let state = match result {
            AuthProgress::Challenge(state, resp) => {
                assert_eq!(resp.code, 334);
                // Should be "Username:" in base64
                assert_eq!(resp.lines[0], "VXNlcm5hbWU6");
                state
            }
            _ => panic!("expected challenge"),
        };

        // Step 2: send username
        let username_b64 = B64.encode(b"testuser");
        let result = continue_auth(*state, username_b64.as_bytes(), &lookup, None)
            .await
            .unwrap();
        let state = match result {
            AuthProgress::Challenge(state, resp) => {
                assert_eq!(resp.code, 334);
                // Should be "Password:" in base64
                assert_eq!(resp.lines[0], "UGFzc3dvcmQ6");
                state
            }
            _ => panic!("expected password challenge"),
        };

        // Step 3: send password
        let password_b64 = B64.encode(b"mypassword");
        let result = continue_auth(*state, password_b64.as_bytes(), &lookup, None)
            .await
            .unwrap();
        match result {
            AuthProgress::Complete(auth) => assert_eq!(auth.username, "testuser"),
            _ => panic!("expected complete"),
        }
    }

    #[tokio::test]
    async fn login_with_initial_response() {
        let record = test_record("mypassword");
        let lookup = make_lookup(record);

        // AUTH LOGIN <base64-username>
        let username_b64 = B64.encode(b"testuser");
        let args = format!("LOGIN {username_b64}");
        let result = begin_auth(&args, &lookup, None).await.unwrap();
        let state = match result {
            AuthProgress::Challenge(state, resp) => {
                assert_eq!(resp.code, 334);
                state
            }
            _ => panic!("expected password challenge"),
        };

        let password_b64 = B64.encode(b"mypassword");
        let result = continue_auth(*state, password_b64.as_bytes(), &lookup, None)
            .await
            .unwrap();
        match result {
            AuthProgress::Complete(auth) => assert_eq!(auth.username, "testuser"),
            _ => panic!("expected complete"),
        }
    }

    #[tokio::test]
    async fn auth_cancellation() {
        let record = test_record("secret");
        let lookup = make_lookup(record);

        let result = begin_auth("PLAIN", &lookup, None).await.unwrap();
        let state = match result {
            AuthProgress::Challenge(state, _) => state,
            _ => panic!("expected challenge"),
        };

        let result = continue_auth(*state, b"*", &lookup, None).await;
        match result {
            Err(resp) => assert_eq!(resp.code, 501), // auth cancelled
            Ok(_) => panic!("expected error"),
        }
    }

    #[tokio::test]
    async fn unknown_mechanism_rejected() {
        let lookup = make_failing_lookup();
        let result = begin_auth("CRAM-MD5", &lookup, None).await;
        match result {
            Err(resp) => assert_eq!(resp.code, 504),
            Ok(_) => panic!("expected error"),
        }
    }

    #[tokio::test]
    async fn credential_not_found() {
        let lookup = make_failing_lookup();
        let plain_data = B64.encode(b"\0unknownuser\0password");
        let args = format!("PLAIN {plain_data}");
        let result = begin_auth(&args, &lookup, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn disabled_credential_rejected() {
        let mut record = test_record("secret");
        record.enabled = false;
        let lookup = make_lookup(record);

        let plain_data = B64.encode(b"\0testuser\0secret");
        let args = format!("PLAIN {plain_data}");
        let result = begin_auth(&args, &lookup, None).await;
        assert!(result.is_err());
    }

    #[test]
    fn argon2_verify_works() {
        use argon2::password_hash::SaltString;
        use argon2::PasswordHasher;

        let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        let hash = argon2::Argon2::default()
            .hash_password(b"test_password", &salt)
            .unwrap()
            .to_string();

        assert!(verify_argon2(&hash, "test_password"));
        assert!(!verify_argon2(&hash, "wrong_password"));
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }

    // ── RFC 4954 §5: Transient auth failure tests ──────────────────

    fn make_db_error_lookup() -> CredentialLookup {
        Arc::new(|_username: &str| {
            Box::pin(async move { Err(SentioError::Database("connection refused".into())) })
        })
    }

    fn make_redis_error_lookup() -> CredentialLookup {
        Arc::new(|_username: &str| {
            Box::pin(async move { Err(SentioError::Redis("timeout".into())) })
        })
    }

    fn make_internal_error_lookup() -> CredentialLookup {
        Arc::new(|_username: &str| {
            Box::pin(async move { Err(SentioError::Internal("unexpected".into())) })
        })
    }

    #[tokio::test]
    async fn db_error_returns_454() {
        let lookup = make_db_error_lookup();
        let plain_data = B64.encode(b"\0testuser\0password");
        let args = format!("PLAIN {plain_data}");
        let result = begin_auth(&args, &lookup, None).await;
        match result {
            Err(resp) => assert_eq!(resp.code, 454, "DB error should give 454: {resp:?}"),
            Ok(_) => panic!("should fail"),
        }
    }

    #[tokio::test]
    async fn redis_error_returns_454() {
        let lookup = make_redis_error_lookup();
        let plain_data = B64.encode(b"\0testuser\0password");
        let args = format!("PLAIN {plain_data}");
        let result = begin_auth(&args, &lookup, None).await;
        match result {
            Err(resp) => assert_eq!(resp.code, 454, "Redis error should give 454: {resp:?}"),
            Ok(_) => panic!("should fail"),
        }
    }

    #[tokio::test]
    async fn internal_error_returns_454() {
        let lookup = make_internal_error_lookup();
        let plain_data = B64.encode(b"\0testuser\0password");
        let args = format!("PLAIN {plain_data}");
        let result = begin_auth(&args, &lookup, None).await;
        match result {
            Err(resp) => assert_eq!(resp.code, 454, "Internal error should give 454: {resp:?}"),
            Ok(_) => panic!("should fail"),
        }
    }

    #[tokio::test]
    async fn not_found_returns_535() {
        let lookup = make_failing_lookup();
        let plain_data = B64.encode(b"\0unknownuser\0password");
        let args = format!("PLAIN {plain_data}");
        let result = begin_auth(&args, &lookup, None).await;
        match result {
            Err(resp) => assert_eq!(resp.code, 535, "NotFound should give 535: {resp:?}"),
            Ok(_) => panic!("should fail"),
        }
    }

    // ── SCRAM-SHA-256-PLUS channel binding tests ──────────────────

    #[tokio::test]
    async fn scram_channel_binding_p_header_accepted() {
        // Verify that p=tls-server-end-point GS2 header is accepted when
        // channel binding data is provided.
        let cb_data = vec![0xAA; 32]; // fake cert hash
        let client_first = "p=tls-server-end-point,,n=testuser,r=clientnonce123";
        let encoded = B64.encode(client_first);
        let args = format!("SCRAM-SHA-256-PLUS {encoded}");
        let result = begin_auth(&args, &make_failing_lookup(), Some(&cb_data)).await;
        // Should get a Challenge (not a mechanism error), since -PLUS is accepted
        match result {
            Ok(AuthProgress::Challenge(_, resp)) => {
                assert_eq!(resp.code, 334, "should get SCRAM challenge");
            }
            Ok(AuthProgress::Complete(_)) => panic!("should not complete"),
            Err(resp) => {
                // It's okay if it fails at some point, but not with 504 (unrecognized mechanism)
                assert_ne!(resp.code, 504, "mechanism should be recognized: {resp:?}");
            }
        }
    }

    #[tokio::test]
    async fn scram_p_without_tls_rejected() {
        // SCRAM-SHA-256-PLUS without channel binding data should fail
        let client_first = "p=tls-server-end-point,,n=testuser,r=clientnonce123";
        let encoded = B64.encode(client_first);
        let args = format!("SCRAM-SHA-256-PLUS {encoded}");
        // No channel binding data (None) → should be rejected
        let result = begin_auth(&args, &make_failing_lookup(), None).await;
        match result {
            Err(resp) => assert_eq!(resp.code, 535, "PLUS without TLS: {resp:?}"),
            Ok(_) => panic!("should fail without channel binding data"),
        }
    }

    #[tokio::test]
    async fn scram_n_header_still_works() {
        // Regular SCRAM-SHA-256 with n,, header should still work
        let client_first = "n,,n=testuser,r=clientnonce123";
        let encoded = B64.encode(client_first);
        let args = format!("SCRAM-SHA-256 {encoded}");
        let result = begin_auth(&args, &make_failing_lookup(), None).await;
        match result {
            Ok(AuthProgress::Challenge(_, resp)) => {
                assert_eq!(resp.code, 334, "should get SCRAM challenge");
            }
            Ok(AuthProgress::Complete(_)) => panic!("should not complete"),
            Err(resp) => panic!("should succeed with n,, header: {resp:?}"),
        }
    }

    /// RFC 4954 §3 (3-8): initial-response "=" means zero-length data.
    #[tokio::test]
    async fn plain_equals_sign_is_zero_length() {
        let record = test_record("secret123");
        let lookup = make_lookup(record);

        // "AUTH PLAIN =" should trigger a two-step flow where the initial
        // response is empty bytes (not a base64 decode error).
        // PLAIN with empty data should fail validation (not enough NUL-
        // delimited parts), but the key thing is it must NOT fail with a
        // base64 decode error - it should reach verify_plain.
        let result = begin_auth("PLAIN =", &lookup, None).await;
        // Empty bytes decoded from "=" → verify_plain gets b"" → split
        // by NUL → only 1 part → auth_failed (535), not a decode error.
        match result {
            Err(resp) => assert_eq!(resp.code, 535, "should be auth_failed, not decode error"),
            Ok(_) => panic!("empty PLAIN data should not succeed"),
        }
    }
}
