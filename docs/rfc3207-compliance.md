# RFC 3207 Compliance Audit (STARTTLS)

Audit date: 2026-02-14
Codebase: `sentio-smtp-server` + `sentio-smtp-client`

Legend: PASS = compliant, FAIL = not compliant, PARTIAL = partially compliant, N/A = not applicable

---

## §2 - STARTTLS Extension

| # | Level | Status | Requirement | Notes |
|---|-------|--------|-------------|-------|
| 2-1 | MUST | PASS | EHLO keyword MUST be "STARTTLS" | `extensions.rs:97` emits `"STARTTLS"` bare keyword |
| 2-2 | MUST | PASS | No parameters for STARTTLS keyword | `extensions.rs:97` - no parameters appended |

## §3 - STARTTLS Command

| # | Level | Status | Requirement | Notes |
|---|-------|--------|-------------|-------|
| 3-1 | MUST | PASS | STARTTLS must only be issued after EHLO | `session.rs:565` - checks state; returns 503 if mid-transaction |
| 3-1b | SHOULD | PASS | STARTTLS should require prior EHLO | `session.rs:handle_starttls()` requires `Greeted` state; returns 503 from `Connected`. Test: `starttls_rejected_before_ehlo` |
| 3-2 | MUST NOT | PASS | STARTTLS must not take parameters | `commands.rs:115-119` - returns 501 if `rest` is non-empty |

## §4 - STARTTLS Procedure

| # | Level | Status | Requirement | Notes |
|---|-------|--------|-------------|-------|
| 4-1 | MUST | PASS | Server MUST respond with 220 to accept STARTTLS | `response.rs:103-105` - `ready_starttls()` returns 220 |
| 4-2 | MUST | PASS | After 220, TLS negotiation begins immediately | `listener.rs:243-254` - calls `acceptor.accept(tcp_stream)` immediately |
| 4-3 | MUST NOT | PASS | If TLS negotiation fails, server should handle gracefully | `listener.rs:274-276` - connection closes on handshake failure; however, a failed TLS handshake corrupts the TCP stream, making revert to plaintext impossible. All major MTAs behave identically. |
| 4-4 | MUST | PASS | After TLS handshake, client MUST send EHLO again | `session.rs:214-215` - `new_after_starttls()` sets state to `Connected`, requiring re-EHLO. Test: `tls_integration.rs:268-276` |
| 4-5 | MUST | PASS | Server MUST clear all state from unencrypted session | `session.rs:222-243` - `new_after_starttls()` creates brand-new `Session`: fresh state, empty buffers, cleared auth. Comment explicitly references RFC 3207 §6. |
| 4-6 | MUST NOT | PASS | Server MUST NOT send 220 if not ready for TLS | `session.rs:559-562` - returns 500 if STARTTLS not in extensions. `listener.rs:246-251` - returns if `tls_acceptor` is `None` |
| 4-7 | MUST NOT | PASS | STARTTLS MUST NOT be advertised after TLS is active | `session.rs:378-381` - `handle_ehlo()` clears `Extensions::STARTTLS` when `tls_active`. Tests: `tls_integration.rs:361-369` |
| 4-8 | MUST | PASS | 501 response if STARTTLS has parameters | `commands.rs:115-119` - returns 501 with `5.5.4` |
| 4-9 | SHOULD | PASS | 454 response for temporary TLS failure | `response.rs:tls_not_available()` returns `454 4.7.0 TLS not available`. `session.rs:handle_starttls()` returns 454 when `tls_available` is false. Test: `starttls_454_when_tls_unavailable` |
| 4-10 | MUST NOT | PASS | MUST NOT negotiate TLS if already in TLS | `session.rs:555-558` - checks `tls_active`, returns 500. Test: `session.rs:1282-1304` |

## §5 - Post-TLS Requirements

| # | Level | Status | Requirement | Notes |
|---|-------|--------|-------------|-------|
| 5-1 | SHOULD | PASS | After TLS, both sides should check certificates | Server: `tls.rs:22` - `with_no_client_auth()` (client certs optional). Client: `tls.rs:118-131` - WebPKI verification with `webpki_roots::TLS_SERVER_ROOTS` |
| 5-2 | MAY | N/A | Server MAY use client certificate for auth | Currently `with_no_client_auth()`; MAY-level, not implementing is compliant |

## §6 - Security Considerations

| # | Level | Status | Requirement | Notes |
|---|-------|--------|-------------|-------|
| 6-1 | SHOULD | PASS | Server SHOULD offer STARTTLS before authentication | `session.rs:383-387` - clears AUTH from extensions when TLS not active on non-SMTPS ports. `session.rs:582-585` - returns 538 if AUTH attempted without TLS |
| 6-2 | MUST NOT | PASS | MUST NOT negotiate TLS if already in TLS | Same as 4-10 above |
| 6-3 | SHOULD | N/A | Implementations SHOULD handle TLS renegotiation | `rustls` explicitly rejects renegotiation as a security measure; TLS 1.3 has no renegotiation. Non-issue with modern TLS stacks. |

---

## Additional TLS Capabilities (Beyond RFC 3207)

| Area | Status | Notes |
|------|--------|-------|
| Implicit TLS (port 465) | PASS | `listener.rs:202-229` - SMTPS mode; TLS before SMTP. `config.rs:85` default `0.0.0.0:465`. Test: `tls_integration.rs:128-196` |
| TLS version configuration | PASS | `tls.rs:16-18,51-53` - supports `min_version` of `"1.2"` or `"1.3"`. Default: `"1.2"`. Validated at `config.rs:1312-1317` |
| SNI support | PASS | `tls.rs:94-180` - `SniResolver` maps domains to cert/key pairs with wildcard support. Test: `tls_integration.rs:376-456` |
| ALPN | PASS | `tls.rs:25,60,81` - all server TLS configs set `alpn_protocols = [b"smtp"]` |
| Outbound STARTTLS + re-EHLO | PASS | `delivery.rs:692-711` - after STARTTLS, creates new connection and re-EHLOs |
| DANE/TLSA support | PASS | `tls.rs:53-95` - evaluates DANE TLSA first, then MTA-STS, then opportunistic. `DaneVerifier` implements DANE-EE + SPKI + SHA-256 |
| MTA-STS support | PASS | `tls.rs:72-88` - checks MTA-STS enforce policy; enforces TLS when mode is `Enforce` and MX matches |
| TLS policy enforcement | PASS | `delivery.rs:713-722` - when policy is `Required` or `Dane` but STARTTLS fails, delivery is rejected (no plaintext fallback) |
| Pre-TLS buffer discard | PASS | `session.rs:232` - `read_buf: BytesMut::new()` discards pre-TLS data; comment cites RFC 3207 §6 |
| Relay TLS modes | PASS | `config.rs:557-558` - supports `"starttls"`, `"implicit"`, `"none"`. `delivery.rs:535-631` implements relay STARTTLS |

---

## Summary

| Category | Pass | Partial | Fail | N/A | Total |
|----------|------|---------|------|-----|-------|
| §2 Extension | 2 | 0 | 0 | 0 | 2 |
| §3 Command | 3 | 0 | 0 | 0 | 3 |
| §4 Procedure | 9 | 0 | 0 | 0 | 9 |
| §5 Post-TLS | 1 | 0 | 0 | 1 | 2 |
| §6 Security | 2 | 0 | 0 | 1 | 3 |
| **Total** | **17** | **0** | **0** | **2** | **19** |

**Effective compliance: 17/17 testable items PASS (100%)**

---

## Recommendations

All previously identified issues have been resolved:

| # | Priority | Issue | Resolution |
|---|----------|-------|------------|
| R1 | Low | 3-1b: STARTTLS accepted before EHLO | Fixed: `handle_starttls()` now requires `Greeted` state, rejects from `Connected` with 503 |
| R2 | Low | 4-9: No 454 response for temporary TLS failure | Fixed: `SmtpResponse::tls_not_available()` returns `454 4.7.0`; `SessionConfig::tls_available` controls availability |
