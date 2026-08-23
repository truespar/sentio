# Testing Sentio

## Unit tests

The whole workspace tests without any infrastructure. Anything that would
otherwise need a live service uses an in-tree mock (`MockKv`, `MockBlobStore`).

```bash
cargo test --workspace
```

| Area | Command |
|---|---|
| Email auth (DKIM / SPF / DMARC / ARC) | `cargo test -p sentio-auth` |
| Abuse (rate limit / ban / greylist) | `cargo test -p sentio-abuse` |
| SMTP protocol logic | `cargo test -p sentio-smtp-server -p sentio-smtp-client` |
| Blob store and attachment helpers | `cargo test -p sentio-storage` |
| Config parsing and env overrides | `cargo test -p sentio-core` |

## End-to-end tests

`docker-compose.test.yml` overlays two sinks onto the normal stack and points
outbound delivery at one of them, so a full round trip can be asserted:

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml up -d
scripts/e2e/run-e2e.sh
```

Two flows are exercised:

| Direction | Path |
|---|---|
| Inbound | host SMTP client → `sentio:25` → pipeline → inbound route → `webhook-sink` |
| Outbound | host HTTP client → `POST /v1/messages/send` → relay → `mailpit` |

The assertions check that mail was *processed*, not merely accepted: the
inbound message must appear via `GET /v1/messages` and produce a successful
webhook dispatch, and the delivered outbound message must carry a
`DKIM-Signature` header - which fails if the signing path is skipped.

Captured mail is browsable at <http://localhost:8025>.

### No mail can reach the internet

Two independent mechanisms, either sufficient on its own:

1. `[delivery.relay]` is enabled in the overlay. That makes the delivery engine
   skip MX resolution entirely and hand every message to the relay host, so no
   code path dials a public MX. `run-e2e.sh` refuses to run if the relay is not
   enabled.
2. All fixtures use `.test` domains. RFC 6761 reserves `.test` as never
   globally resolvable, so even a misconfigured relay fails to resolve rather
   than reaching a real server.

### Scripts

| Script | Purpose |
|---|---|
| `scripts/e2e/run-e2e.sh` | Preflight, provision, then both flows with assertions |
| `scripts/e2e/provision.sh` | Idempotent fixtures: domains, DKIM key, inbound route |
| `scripts/e2e/smtp-send.py` | Standalone SMTP client - useful on its own |
| `scripts/e2e/lib.sh` | Shared config and helpers |

`smtp-send.py` has no dependencies and is handy for poking at any running
server:

```bash
scripts/e2e/smtp-send.py --port 2525 \
    --from alice@sender.test --to support@inbound.test \
    --subject 'hello' --body 'test body' --verbose
```

It prints the server's reply on rejection and exits non-zero, so failures are
diagnosable rather than silent. `--starttls` and `--auth-user`/`--auth-pass`
cover the submission port.

Provisioning marks its `.test` domains verified with a direct `UPDATE` against
the compose database. Real verification requires live DNS that `.test` cannot
satisfy, and this keeps the fixture from weakening the API's verification gate.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | *(unset)* | Required by the sqlx compile-time query macros when regenerating the cache |
| `SQLX_OFFLINE` | *(unset)* | `true` uses the committed `.sqlx/` cache instead of a live database |
| `RUST_LOG` | *(unset)* | Tracing filter, e.g. `info` or `sentio=debug` |

The e2e scripts additionally honour `SENTIO_API`, `SENTIO_API_KEY`,
`SENTIO_TENANT`, `MAILPIT_URL`, `SEND_DOMAIN`, and `RECV_DOMAIN`.

## Regenerating the sqlx offline cache

Normal builds need no database - they read the committed `.sqlx/`. After
changing any `sqlx::query*!` macro, regenerate it against a live database and
commit the result:

```bash
echo 'DATABASE_URL=postgres://sentio:sentio@localhost:5432/sentio' > .env
cargo sqlx prepare --workspace
```
