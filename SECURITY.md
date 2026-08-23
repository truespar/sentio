# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities privately rather than through a public
issue, so that a fix can be prepared before details are widely known.

Use GitHub's [private vulnerability
reporting](https://github.com/truespar/sentio/security/advisories/new) for this
repository.

Please include enough detail to reproduce: affected version or commit, the
configuration involved, and the impact you believe it has.

## Hardening a deployment

A few defaults exist for convenience and are wrong for anything internet-facing:

- **Rotate the bootstrap API key.** Migration `007` seeds
  `sentio_bootstrap_admin_CHANGE_ME` with wildcard scope. Replace it via
  `POST /v1/tenants/{id}/api-keys` and delete the original.
- **Change the compose credentials.** `docker-compose.yml` ships development
  passwords for PostgreSQL and MinIO. They are fine on a laptop and unsafe
  anywhere else.
- **Terminate TLS.** Without a certificate at `/etc/sentio/tls/` the server runs
  plaintext SMTP and does not bind port 465.
- **Keep the metrics endpoint internal.** Prometheus metrics are unauthenticated
  and are not published by the compose stack.
- **Do not expose the rspamd controller, MinIO console, or NATS monitoring
  port** beyond your own network.

## Credentials in configuration

Every setting can be supplied as a `SENTIO__SECTION__KEY` environment variable,
which takes precedence over the file. Prefer that for secrets and leave them out
of the TOML entirely.
