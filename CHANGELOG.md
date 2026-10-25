# Changelog

Notable changes to Sentio SMTP. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it
reaches 1.0.

## [Unreleased]

### Fixed
- `[auth] dmarc_check_inbound = false` was parsed and ignored: a DMARC `fail`
  under `p=reject` was always answered with 550. The flag now turns that
  rejection off; DMARC is still evaluated and recorded in
  Authentication-Results. It matters on an MX that receives forwarded mail,
  where the forwarding hop breaks SPF. `spf_check_inbound` is documented as
  having no effect: SPF never rejected on its own.

## [0.2.0] - 2026-10-17

A security release. Three of its changes are breaking for an existing
deployment and are marked below.

### Security
- Cross-tenant isolation on every `/v1/tenants/{id}/...` handler. The path
  tenant is client-controlled and was taken at face value, so an admin key for
  one tenant could read, change or delete another tenant's API keys, SMTP
  credentials, inbound routes, IP pool assignments and the tenant row itself.
  Handlers now go through `ensure_tenant_match`, which answers 404 rather than
  403 so another tenant's resources do not announce their existence, and the
  repository methods take the tenant and filter on it, so a guessed UUID is no
  longer enough on its own.
- `platform:admin`, a named scope for reach across tenants. `*` deliberately
  does not cover it and a session cannot grant it unless it holds it, so a
  tenant minting itself a wildcard key is not a way out of its tenant.
  **BREAKING**: `POST /v1/tenants` now requires it, and `GET /v1/tenants`
  returns only your own tenant without it. Migration `005` grants it to the
  wildcard keys of the system tenant, which are the ones that already had the
  reach, so an operator key carries across untouched.
- **BREAKING**: `smtp_credentials.username` is globally unique (migration
  `003`). SMTP AUTH resolves a credential by username alone - an
  unauthenticated connection carries no tenant, and that lookup is what
  establishes one - so two tenants both naming a credential "agent" handed
  whichever row the database returned first one tenant's privileges to the
  other. The migration prefixes cross-tenant duplicates with their tenant id;
  those usernames stop authenticating until the SMTP client is updated.
- The server refuses to start while the publicly-known bootstrap API key is
  active, and also when it cannot prove the key is inactive, so a database
  outage cannot quietly defeat the check. `SENTIO_ALLOW_BOOTSTRAP_KEY=1` is the
  recovery hatch, and the compose stack sets it because the two cannot both
  hold on a first run.
- Dropped the legacy rustls 0.21 stack that `aws-sdk-s3` pulled in alongside
  the modern one (RUSTSEC-2026-0346, -0349, no fix on that line) by taking the
  SDK with `default-features = false`. HTTPS still comes from rustls 0.23.
- Dropped `mail-auth`'s default `report` feature and the three zip advisories
  with it (RUSTSEC-2026-0367, -0368, -0369). It is DMARC aggregate report
  parsing; Sentio verifies DKIM, SPF, DMARC and ARC and never extracts an
  archive.
- A username conflict answers 409 instead of 500.

### Changed
- **BREAKING**: the compose stack's object store is SeaweedFS rather than
  MinIO. MinIO's community edition was archived and its images withdrawn from
  both Docker Hub and quay.io, so `docker compose up -d` could no longer pull
  them. `weed mini` is master, volume server, filer and S3 gateway in one
  process, which also retires the `mc` one-shot that created the bucket -
  `ensure_bucket()` had always done that itself. Upgrading keeps the old
  `minio_data` volume while Sentio talks to an empty store, so copy anything
  you need out of it first; new installs are unaffected. Production can still
  point `[storage]` at any S3-compatible endpoint, MinIO included.
- Every dependency moved to its latest compatible version, utoipa 6 and
  utoipa-scalar 0.4 among them. Each pinned image in the compose stack is on
  its current release: NATS 2.15, rspamd 4.2.2, mailpit v1.31.6, SeaweedFS
  4.48. rspamd and mailpit were tracking `latest`, so the stack you got
  depended on the day you pulled it; a pin is reproducible and is something
  dependabot can raise a pull request against.

### Fixed
- Delivery could park indefinitely. `TlsConnector::connect` has no timeout of
  its own, so a remote that stalled after acknowledging `220 STARTTLS` held the
  delivery future and leaked a per-domain pool permit; the STARTTLS upgrade,
  each MX attempt and the whole handler now have timeouts, and an exhausted
  handler returns `RetryAfter` so JetStream redelivers instead of losing the
  task. The MTA-STS client gained timeouts for the same reason.
- A 5xx without an enhanced code was read as a bad address, so a
  Spamhaus-worded 550 or a "poor reputation" 554 flagged the recipient for
  permanent suppression over a problem at our end. `classify_bounce` now reads
  DNSBL, reputation and policy wording as a block.
- A suppressed recipient produced no `message_events` row and no webhook, and
  left the message `queued` for ever. Suppressions go through `record_outcome`
  now, and a message whose every recipient is suppressed becomes `Dropped`.
- The docs claimed Jev moves the spam score. It computes a delta and nothing
  applies it; labelling depends on a route setting `llm_classify`, not on a
  score band.

### Removed
- The GitHub Actions CI workflow. `./scripts/check.sh` and
  `./scripts/e2e/run-e2e.sh` are the gate, run before a tag goes up.

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
