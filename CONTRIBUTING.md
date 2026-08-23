# Contributing to Sentio SMTP

Thanks for your interest. This document covers the development workflow and the
conventions the codebase follows.

## Getting set up

See [Installing without Docker](README.md#installing-without-docker) in the
README for build dependencies. In short: a stable Rust toolchain, `cmake`,
`libclang-dev`, and a C toolchain.

The fastest way to get the supporting services is the compose stack:

```bash
docker compose up -d postgres redis nats minio
```

## Build and check

```bash
cargo check --workspace            # fastest full-tree check
cargo check --workspace --all-targets   # includes tests and benches
cargo build --release              # optimised binary
cargo test --workspace             # unit tests; no infrastructure needed
cargo clippy --workspace --all-targets  # lints
cargo fmt --all                    # formatting
```

## SQL and the offline cache

Queries are checked at compile time by `sqlx`. The committed `.sqlx/` directory
lets the workspace build without a database, which is what makes the Docker
build and CI work.

If you add or change a query you must regenerate that cache against a live
database, and commit the result:

```bash
echo 'DATABASE_URL=postgres://sentio:sentio@localhost:5432/sentio' > .env
cargo sqlx prepare --workspace
```

`.env` is gitignored. A build that fails with "query not found in offline
cache" means someone changed SQL without re-running the command above.

## Migrations

Migrations live in `migrations/` and are embedded into the binary at compile
time by `sqlx::migrate!`, so a rebuild is required after adding one.

- Name them `NNN_short_description.sql`, continuing the existing sequence.
- **Never edit a migration that has already shipped.** `sqlx` records a
  checksum for every applied migration and refuses to start when one changes.
  Correct a released migration by adding a new one.
- Write them so re-running is safe (`IF NOT EXISTS`, `ON CONFLICT DO NOTHING`)
  where it is reasonable to do so.

Apply them with the binary:

```bash
cargo run -- --config config/default.toml migrate
```

## The OpenAPI specification

The server describes itself. `crates/sentio-api/src/openapi.rs` declares the
document; every route annotated with `#[utoipa::path(...)]` appears in it.

A generated copy is committed at [`docs/openapi.json`](docs/openapi.json) so the
API can be reviewed, diffed in pull requests, and fed to client generators
without running anything. Regenerate it after adding or changing a route:

```bash
cargo run -- openapi > docs/openapi.json
```

The subcommand needs no configuration, database, or network - the document is
static - so it also works in CI.

## Testing

Unit tests run without infrastructure and should stay that way - use the
in-tree mocks (`MockKv`, `MockBlobStore`) rather than reaching for a live
service.

The end-to-end harness covers the full round trip against a running stack:

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml up -d
scripts/e2e/run-e2e.sh
```

See [`docs/testing.md`](docs/testing.md).

## Conventions

**Identifiers.** UUIDv4 for most entities; UUIDv7 for anything in a partitioned
table (messages, events) so that ordering matches insertion time.

**Enums.** `strum` with `snake_case` serialization, matching the `CHECK`
constraints in the schema. If you add a variant, update the constraint in a
migration too.

**Repository pattern.** Traits are declared in `sentio-core::traits`;
PostgreSQL implementations live in `sentio-store::postgres`. Depend on the
trait, not the implementation - this is what keeps crates testable with mocks.

**Errors.** One `SentioError` (`thiserror`) is propagated across every crate.
Add a variant rather than stringly-typing a new failure mode.

**Configuration.** TOML with `SENTIO__SECTION__KEY` environment overrides. A
new setting needs three things: the field with a `#[serde(default)]`, a
sensible `Default`, and an arm in the env-override matcher in
`sentio-core/src/config.rs`. Defaults must be safe for a local install -
never point one at a real host, and never put a credential in one.

**Async traits.** Prefer return-position `impl Trait` (RPITIT) over
`#[async_trait]` for zero-cost dispatch, following `KvConn`, `SpamScorer`, and
`LlmProvider`.

## Pull requests

- Keep commits focused, and explain *why* in the message rather than restating
  the diff.
- `cargo fmt --all` and `cargo clippy --workspace --all-targets` should be
  clean.
- Add tests for behaviour changes.
- Update the README or `docs/` when you change setup or configuration.

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).
