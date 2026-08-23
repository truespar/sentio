# RFC 4954 Compliance Audit (SMTP AUTH)

Audit date: 2026-02-14
Codebase: `sentio-smtp-server` + `sentio-smtp-client`

Legend: PASS = compliant, FAIL = not compliant, PARTIAL = partially compliant, N/A = not applicable

---

## §3 - The AUTH Command

| # | Level | Status | Requirement | Notes |
|---|-------|--------|-------------|-------|
| 3-1 | MUST | PASS | AUTH command format: `AUTH mechanism [initial-response]` | `commands.rs:121-126` parses `AUTH <rest>`, then `auth.rs:64-67` splits into mechanism + optional initial-response |
| 3-2 | MUST | PASS | Server MUST return 235 on successful authentication | `response.rs:109-111` - `auth_success()` returns 235 with `2.7.0` |
| 3-3 | MUST | PASS | Server MUST return 535 on authentication failure | `response.rs:129-131` - `auth_failed()` returns 535 with `5.7.8` |
| 3-4 | MUST | PASS | Server MUST advertise supported mechanisms in EHLO | `extensions.rs:99-101` - emits `AUTH <mechanisms>` line. `session.rs:389` passes `auth_mechanisms` to `ehlo_lines()` |
| 3-5 | MUST NOT | PASS | AUTH MUST NOT be advertised after already authenticated | `session.rs:handle_ehlo()` clears `AUTH` extension when `self.authenticated.is_some()`. Test: `ehlo_hides_auth_after_authenticated` |
| 3-6 | MUST NOT | PASS | AUTH MUST NOT be issued during a mail transaction | `session.rs:handle_auth_begin()` returns 503 when `self.state` is `MailFrom` or `RcptTo`. Test: `auth_rejected_during_mail_transaction` |
| 3-7 | MUST | PASS | AUTH MUST be rejected with 503 if already authenticated | `session.rs:577-579` - checks `self.authenticated.is_some()`, returns `already_authenticated()` (503 with `5.5.1`) |
| 3-8 | SHOULD | PASS | Initial-response `=` represents zero-length response | `auth.rs:begin_auth()` maps `"="` to `Some("")` before mechanism dispatch. `B64.decode("")` yields empty bytes. Test: `plain_equals_sign_is_zero_length` |
| 3-9 | MUST | PASS | Client can cancel authentication with `*` | `auth.rs:87-89` - `continue_auth()` checks `text == "*"`, returns `auth_cancelled()` (501 with `5.7.0`) |
| 3-10 | MUST | PASS | Server MUST return 501 on malformed AUTH (no mechanism) | `commands.rs:122-124` - returns `syntax_error()` (501 with `5.5.4`) |
| 3-11 | MUST | PASS | Server MUST return 504 for unrecognized mechanism | `auth.rs:73` - unknown mechanisms return `auth_mechanism_not_supported()` (504 with `5.5.4`) |

## §4 - AUTH= Parameter for MAIL FROM

| # | Level | Status | Requirement | Notes |
|---|-------|--------|-------------|-------|
| 4-1 | MAY | PASS | Support optional `AUTH=<identity>` parameter in MAIL FROM | `commands.rs` - `MailFromParams::auth_param` stores the AUTH= identity; `AUTH=<>` treated as empty. Tests: `parse_mail_from_auth_identity`, `parse_mail_from_auth_empty` |

## §5 - Response Codes

| # | Level | Status | Requirement | Notes |
|---|-------|--------|-------------|-------|
| 5-1 | MUST | PASS | 235 Authentication Succeeded | `response.rs:109-111` |
| 5-2 | MUST | PASS | 334 Server challenge (multi-step mechanisms) | `response.rs:113-119` - `auth_challenge(data)` returns 334; `auth_continue()` returns 334 with empty data |
| 5-3 | MAY | N/A | 432 Password transition needed | Not implemented; MAY-level for password expiry scenarios |
| 5-4 | MAY | PASS | 454 Temporary authentication failure | `response.rs` - `auth_temp_failure()` returns 454 with `4.7.0`. `auth.rs` - `lookup_error_to_response()` maps `Database`/`Redis`/`Internal` → 454, `NotFound` → 535. Session does not count 454 against attempt limit. Tests: `db_error_returns_454`, `redis_error_returns_454`, `auth_454_does_not_count_as_attempt` |
| 5-5 | MUST | PASS | 500 Line too long / unrecognized | `response.rs:73-74` `command_not_recognized()`, `response.rs:97-99` `line_too_long()` |
| 5-6 | MUST | PASS | 501 Malformed auth input / cancellation | `response.rs:81-83` `syntax_error()`, `response.rs:145-147` `auth_cancelled()` |
| 5-7 | MUST | PASS | 504 Mechanism not recognized | `response.rs:133-135` - `auth_mechanism_not_supported()` returns 504 with `5.5.4` |
| 5-8 | MAY | N/A | 530 Authentication required | Not implemented; server does not mandate AUTH before MAIL FROM |
| 5-9 | MAY | N/A | 534 Mechanism too weak | Not implemented; all offered mechanisms accepted equally |
| 5-10 | MUST | PASS | 535 Authentication credentials invalid | `response.rs:129-131` - `auth_failed()` returns 535 with `5.7.8` |
| 5-11 | N/A | PASS | 538 Encryption required for mechanism | `response.rs:137-139` - `encryption_required()` returns 538 with `5.7.11`. Non-standard code but widely used and interoperable. |

## §6 - SASL Mechanisms

| # | Level | Status | Requirement | Notes |
|---|-------|--------|-------------|-------|
| 6-1 | MUST | PASS | Support PLAIN mechanism (RFC 4616) | `auth.rs:124-158` - full PLAIN implementation; parses `\0authcid\0passwd`; supports inline and two-step challenge |
| 6-2 | N/A | PASS | LOGIN mechanism (draft, widely used) | `auth.rs:165-185` - full LOGIN implementation; correct base64 challenges (`VXNlcm5hbWU6` / `UGFzc3dvcmQ6`) |
| 6-3 | N/A | PASS | SCRAM-SHA-256 (RFC 5802/7677) | `auth.rs:192-485` - full implementation with HMAC-SHA256 and constant-time proof verification |
| 6-4 | SHOULD NOT | PASS | SHOULD NOT advertise AUTH on unencrypted connections | `session.rs:384-387` - clears AUTH extension when TLS not active on non-SMTPS ports. Tests: `session.rs:1352-1403` |
| 6-5 | SHOULD | PASS | PLAIN/LOGIN SHOULD only be offered after TLS | Same as 6-4; also `session.rs:582-585` rejects AUTH commands without TLS, returning 538 |

## §12 - Security Considerations

| # | Level | Status | Requirement | Notes |
|---|-------|--------|-------------|-------|
| 12-1 | MUST NOT | PASS | MUST NOT advertise AUTH PLAIN without TLS | See 6-4/6-5. AUTH stripped from EHLO when TLS not active on ports 25/587. Port 465 (SMTPS) TLS is implicit. |
| 12-2 | SHOULD | PASS | Implementations SHOULD support SASL channel binding | SCRAM-SHA-256-PLUS with `tls-server-end-point` channel binding (RFC 5929). `tls.rs` - `compute_cert_hash()` / `compute_cert_hash_from_der()`. `auth.rs` - parses `p=tls-server-end-point,,` GS2 header, verifies `c=` value in client-final with constant-time comparison. `session.rs` - dynamically adds SCRAM-SHA-256-PLUS to EHLO mechanisms when TLS active and cert hash available. Tests: `scram_channel_binding_p_header_accepted`, `scram_p_without_tls_rejected` |

---

## Additional Auth Capabilities

| # | Status | Requirement | Notes |
|---|--------|-------------|-------|
| A-1 | PASS | Rate limiting on failed auth attempts | `session.rs:593` - `max_auth_attempts` (default 3); session terminated on exceed. `on_auth_failure` callback for abuse tracking. `config.rs:348` - `max_auth_failures_per_hour = 10` at abuse layer. |
| A-2 | PASS | AUTH state persists across RSET (correct per RFC) | `session.rs:538-545` - `handle_rset()` clears envelope but NOT `authenticated`/`auth_state`. Correct: RSET resets transaction, not auth. |
| A-3 | PASS | AUTH state persists across re-EHLO (correct per RFC) | `session.rs:371-372` - `handle_ehlo()` resets transaction but NOT `authenticated`. Correct: auth persists for the session. |
| A-4 | PASS | Credential verification uses secure hashing | `auth.rs:520-532` - Argon2 via `spawn_blocking`; SCRAM uses SHA-256 with constant-time comparison |
| A-5 | PASS | Credential lookup abstracted via trait | `traits.rs:764-791` - `SmtpCredentialRepository` with `lookup()`. `auth.rs:47-51` - `CredentialLookup` type alias. |
| A-6 | PASS | Post-STARTTLS session discards pre-TLS auth state | `session.rs:216-243` - `new_after_starttls()` creates fresh session with `authenticated: None`, `auth_state: None` |
| A-7 | PASS | Outbound AUTH capability parsing | `connection.rs:90-92` - `ServerCapabilities` parses `AUTH` line and extracts mechanism list |

---

## Summary

| Category | Pass | Partial | Fail | N/A | Total |
|----------|------|---------|------|-----|-------|
| §3 AUTH Command | 11 | 0 | 0 | 0 | 11 |
| §4 AUTH= MAIL FROM | 1 | 0 | 0 | 0 | 1 |
| §5 Response Codes | 8 | 0 | 0 | 3 | 11 |
| §6 SASL Mechanisms | 5 | 0 | 0 | 0 | 5 |
| §12 Security | 2 | 0 | 0 | 0 | 2 |
| **Total** | **27** | **0** | **0** | **3** | **30** |

**Effective compliance: 27/27 testable items PASS (100%)**

---

## Critical Findings

All previously identified issues have been resolved:

| # | Severity | Issue | Resolution |
|---|----------|-------|------------|
| F1 | **MUST NOT** | 3-5: AUTH advertised in EHLO after already authenticated | Fixed in `handle_ehlo()`: clears AUTH extension when `self.authenticated.is_some()` |
| F2 | **MUST NOT** | 3-6: AUTH accepted during mail transaction (after MAIL FROM) | Fixed in `handle_auth_begin()`: returns 503 when state is `MailFrom` or `RcptTo` |
| F3 | **SHOULD** | 3-8: Initial-response `"="` not decoded as zero-length | Fixed in `begin_auth()`: maps `"="` to `Some("")` before mechanism dispatch |
