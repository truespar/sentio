-- =============================================================================
-- Sentio SMTP - bootstrap tenant and admin API key
-- =============================================================================
-- The minimum data needed to talk to the API at all: one system tenant and one
-- wildcard-scope key.
--
--   Tenant : 00000000-0000-0000-0000-000000000001
--   Key    : sentio_bootstrap_admin_CHANGE_ME
--
--     curl -H "Authorization: Bearer sentio_bootstrap_admin_CHANGE_ME" \
--          http://localhost:8080/v1/tenants
--
-- Rotate this before the host is reachable by anything you do not trust:
-- create a replacement with POST /v1/tenants/{id}/api-keys, then delete this
-- one. It carries wildcard (*) scope.
--
-- key_hash is hex(sha256(token)), which is exactly how the API resolves a
-- bearer token (crates/sentio-api/src/auth.rs). Verify with:
--     printf %s 'sentio_bootstrap_admin_CHANGE_ME' | sha256sum
--
-- Idempotent, so re-running cannot clobber a rotated key.
-- =============================================================================

INSERT INTO tenants (id, name, tier, status, config, rate_limits)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'Sentio Platform',
    'dedicated',
    'active',
    '{"system": true}',
    '{}'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO api_keys (id, tenant_id, key_hash, key_prefix, name, scopes)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',
    'b19cdf7c08544b51072675750216e80b6652b58ad39b7f59b20fc921352b4621',
    'sentio_boot',
    'Bootstrap Admin (ROTATE ME)',
    '{*}'
)
ON CONFLICT (id) DO NOTHING;
