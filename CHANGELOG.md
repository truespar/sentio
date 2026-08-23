# Changelog

Notable changes to Sentio SMTP. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it
reaches 1.0.

## [Unreleased]

### Added
- Docker Compose quickstart covering the full stack, plus a from-source install
  path with build dependencies and required services.
- End-to-end test harness (`scripts/e2e/`) exercising inbound and outbound mail
  against a running stack, with a standalone SMTP client.
- `openapi` subcommand printing the OpenAPI 3.1 document; a generated copy is
  committed at `docs/openapi.json`.
- Guide for building email-native agents on Sentio (`docs/building-agents.md`).
- Documented mailbox forwarding to external addresses, which rewrites `From:`
  and re-signs so forwarded mail still passes DMARC.
- CI workflow, issue and pull request templates, changelog, and code of conduct.
- Startup banner on `serve`, listing listeners, the API and reference URLs, and
  which backing services were reached. Suppressed under JSON logging.
- `CONTRIBUTING.md`, `SECURITY.md`, and `.env.example`.

### Changed
- Relicensed under Apache-2.0.
- KV storage ships a single Redis backend behind the `KvConn` trait.
- Documentation rewritten around the agent-inbox use case, with the full API
  surface enumerated.

### Fixed
- Bootstrap API key hash did not match its documented token, so the documented
  credential always returned 401.
- PostgreSQL 18 containers failed to start against a volume mounted at
  `/var/lib/postgresql/data`.
- Duplicate `0.0.0.0` and `[::]` listener entries caused `EADDRINUSE`, which
  aborted listener setup and left ports 465 and 587 unbound while the process
  still reported healthy.
- Removed hardcoded production credentials from configuration defaults.
- Webhook signature documentation described headers the server does not send.
- Cleared all clippy lints; CI now gates on `-D warnings`.
- Partition manager could never extend the install-time window: it ran under
  `Europe/Berlin` while the bootstrap block used the session timezone, so the
  next month's bounds overlapped and creation failed. Both are pinned to UTC.

- Migration history squashed to `001_initial_schema.sql` and `002_bootstrap.sql`.
  Verified equivalent: a fresh run produces a schema identical to the one the
  previous fourteen migrations converged on.

### Removed
- `002_seed_test_data.sql`, which could not apply to a fresh database and seeded
  fake tenants with working API keys.
