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

The `sentio` service itself pulls `ghcr.io/truespar/sentio`. When testing your
own changes, add `-f docker-compose.build.yml` so it is built from your
checkout rather than pulled.

## Build and check

```bash
cargo check --workspace            # fastest full-tree check
cargo check --workspace --all-targets   # includes tests and benches
cargo build --release              # optimised binary
cargo test --workspace             # unit tests; no infrastructure needed
cargo clippy --workspace --all-targets  # lints
cargo fmt --all                    # formatting
```

Or run every check that has to pass, in one go:

```bash
./scripts/check.sh                # fmt, clippy, tests, release build,
                                  # cargo-deny, notices, OpenAPI spec
./scripts/check.sh fmt clippy     # or just the ones you want
```

There is no hosted CI on this repository, so that script is the gate: nothing
runs it for you when you push or open a pull request. Run it before asking for
a review, and expect a reviewer to run it too.

To have formatting and lints checked automatically before every push:

```bash
./scripts/install-git-hooks.sh
```

`git push --no-verify` skips the hook when you need it to.

## SQL and the offline cache

Queries are checked at compile time by `sqlx`. The committed `.sqlx/` directory
lets the workspace build without a database, which is what makes the Docker
build work without spinning up PostgreSQL first.

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
static - so it runs anywhere the binary builds.

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

## Licences and third-party notices

Two separate things, both checked by `./scripts/check.sh`:

- **Policy** - `deny.toml` lists which licences may appear in the dependency
  graph. `cargo deny check` fails on anything else, so a new dependency with an
  unexpected licence is a deliberate decision rather than a surprise. Advisory
  exceptions are recorded there with reasons; revisit them on dependency bumps.
- **Attribution** - MIT and BSD require their copyright notices to ship with a
  binary. `THIRD-PARTY-NOTICES.md` is generated from the resolved graph and
  shipped in the image and release tarballs. Regenerate it whenever
  dependencies change:

```bash
cargo about generate --fail --workspace about.hbs | tr -d '\r' > THIRD-PARTY-NOTICES.md
```

Sentio itself is dual-licensed `MIT OR Apache-2.0`; contributions are accepted
under the same terms.

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

## Cutting a release

The version lives in one place: `version` under `[workspace.package]` in the
root `Cargo.toml`. Everything else reads it - the startup banner prints
`CARGO_PKG_VERSION`, and the OpenAPI document takes its `info.version` from the
same value. A tag alone changes neither, so bump first, then tag:

```bash
# 1. bump [workspace.package] version, then
cargo check --workspace          # refresh Cargo.lock
cargo run -- openapi > docs/openapi.json
git commit -am "Release 0.2.0"
git tag -a v0.2.0 -m "v0.2.0"
git push origin main v0.2.0
```

Pushing the tag builds the multi-arch image, publishes `0.2.0`/`0.2`/`0` and
moves `latest`, and creates the GitHub Release with per-architecture tarballs.
Pushes to `main` publish nothing.

## Pull requests

- Keep commits focused, and explain *why* in the message rather than restating
  the diff.
- `cargo fmt --all` and `cargo clippy --workspace --all-targets` should be
  clean.
- Add tests for behaviour changes.
- Update the README or `docs/` when you change setup or configuration.

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).
