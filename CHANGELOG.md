# Changelog

Notable changes to Sentio SMTP. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it
reaches 1.0.

## [Unreleased]

## [0.1.6] - 2026-09-21

### Added
- TypeSafe Jev as a fourth classification backend (`llm.provider = "jev"`). A
  structured-decision model: typed questions in, calibrated probabilities out.
  It labels a message with a category and, unlike the chat backends, also
  returns how likely it is to be unsolicited bulk and how likely it is to be
  phishing. Both land on the message row and the webhook payload. It also
  computes a spam-score adjustment from those probabilities, which nothing
  applies to a delivery decision yet. `llm.jev.body_mode` decides whether the
  envelope, a bounded preview or the full body leaves the server.
- `scripts/check.sh`, which runs every check that has to pass before a change
  lands: formatting, clippy, tests, release build, `cargo deny`, the
  third-party notices diff and the OpenAPI spec diff.
- `scripts/install-git-hooks.sh`, a pre-push hook for formatting and lints.

### Changed
- `LlmProvider` split into `MessageClassifier` and `ResponseGenerator`. A
  decision model can classify but cannot write text, so the two capabilities
  are no longer one trait. `LlmProvider` remains as a supertrait with a
  blanket impl, so existing providers are unaffected.
- Dependency updates: argon2 0.6 (its API moved `SaltString` and now draws the
  salt itself), mail-auth 0.13, mail-builder 1.0, rmcp, and 18 crates in the
  grouped update. Release archives now also carry the notices for
  `sentio-mcp`'s dependencies.
- Hosted CI removed. `scripts/check.sh` is the gate; `publish.yml` still
  builds and publishes releases on a tag.
- Dependabot groups all ecosystems and runs monthly.

### Fixed
- **rustls 0.23.43 to 0.23.45**, covering RUSTSEC-2026-0285: TLS 1.3 handshake
  messages were accepted across encryption level boundaries. This affects
  STARTTLS and SMTPS.
- Two flaky checks in the end-to-end harness: the webhook test left a
  subscription behind on every run, so later runs verified deliveries against
  the wrong signing secret, and the inbound test grepped the log for a generic
  success line that could match a previous run.

## [0.1.5] - 2026-08-24

### Added
- `sentio-mcp`, an MCP server that exposes the REST API as agent-callable
  tools, so an MCP client gets email without any integration code. Ships as
  its own archive for Linux x86_64, Linux aarch64 and Windows x86_64, and is
  included in the container image. Thanks to @mrorigo.
- Unauthenticated API requests are rate limited by client IP, so a request
  without a valid key is bounded before it reaches the database. Thanks to
  @mrorigo.

### Changed
- `/docs` no longer loads the Scalar front-end from a CDN. The bundle ships
  embedded in the binary (gzipped, ~1 MiB) and is served by Sentio itself, so
  the API reference renders on hosts with no outbound internet access. The
  provenance of the vendored bundle is documented in
  `crates/sentio-api/assets/README.md`.
- Third-party notices are generated across the workspace. Without that they
  cover only the root package, and the dependencies of the newly shipped
  `sentio-mcp` would go unattributed.

### Fixed
- An authentication backend failure was reported to the caller as an invalid
  token, hiding a database outage behind a 401. Thanks to @mrorigo. A missing
  OAuth token is still a 401 rather than a 500, since the two repositories
  report "no such row" differently.
- The MCP tools interpolated caller-supplied ids straight into the request
  path, so an id of `../../v1/domains` reached routes the tool set does not
  expose. Ids are parsed as UUIDs before use.
- The bootstrap admin API key from `002_bootstrap.sql` now logs a warning at
  startup while it is still active. Thanks to @mrorigo.

## [0.1.4] - 2026-08-24

### Fixed
- Inbound SMTP dropped the CRLF that ends the last line of a message body,
  keeping only the bytes before the `\r\n.\r\n` terminator. Anything anchored
  to the final line then failed to match: rspamd scored GTUBE at -0.1 instead
  of 15, so spam scoring was quietly degraded for every message.
- Manual install instructions, after running them on a clean host: the
  PostgreSQL 18 floor and the `uuidv7()` error it produces on older servers,
  the interactive `createuser --pwprompt` and its undocumented password
  coupling, a `setcap` aimed at a path that did not exist yet, and a systemd
  unit that ran as an undefined user against a config path the README never
  creates.

## [0.1.3] - 2026-08-24

### Added
- Windows x86_64 binary in the release, alongside the two Linux builds.

### Fixed
- The startup banner and the OpenAPI document both report the release
  version; previously they read 0.1.0 and 1.0.0 regardless of the tag.
- Third-party notices no longer list first-party crates, so a version bump
  cannot stale them.

## [0.1.2] - 2026-08-24

### Added
- Third-party notices ship in the image and release tarballs.
- `cargo-deny` and a notices freshness check run in CI.

### Changed
- Dual-licensed `MIT OR Apache-2.0`.

### Fixed
- `POST /v1/messages/send-multipart` and `POST /v1/domains/{id}/dns-check`
  were routed but missing from the OpenAPI document, so generated clients
  lost them. The spec now covers all 116 operations.
- README documented 13 of 20 configuration sections and carried stale
  operation counts.

## [0.1.1] - 2026-08-24

First release with published artifacts: a multi-arch container image and
prebuilt binaries. `0.1.0` exists as an image tag only - it was cut while the
release pipeline was still being wired up.

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
- Published container image at `ghcr.io/truespar/sentio` for `linux/amd64` and
  `linux/arm64`, so the quickstart pulls instead of compiling. Each architecture
  is built on a native runner and merged into one manifest.
  `docker-compose.build.yml` still builds from a checkout.
- Startup banner on `serve`, listing listeners, the API and reference URLs, and
  which backing services were reached. Suppressed under JSON logging.
- `CONTRIBUTING.md`, `SECURITY.md`, and `.env.example`.

### Changed
- Relicensed as `MIT OR Apache-2.0`, so a user may take whichever terms suit them.
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
