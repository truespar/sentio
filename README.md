<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/wordmark-dark.svg">
  <img alt="Sentio" src="docs/assets/wordmark-light.svg" width="264">
</picture>

# Sentio SMTP

**Email inbox API for AI agents.** Give every agent its own real email address,
receive mail as structured webhooks, and reply in-thread over REST - then run
thousands of those inboxes side by side, isolated per tenant.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)

Agents increasingly need to *be* an email participant: receive a customer
thread, act on it, reply as themselves. That normally means wiring an IMAP
poller to a parser to an SMTP relay, and inheriting a legacy MTA's operational
surface. Sentio is the whole path in one service - an inbox per agent, parsed
and authenticated inbound delivered as a webhook, and sending over the same
API.

```
                        ┌──────────────── Sentio ────────────────┐
   customer ──SMTP──►   │  agent@acme.example.com                │  ──webhook──►  your agent
                        │  authenticate → scan → score → route   │
                        │                                        │
   your agent ──REST──► │  sign (DKIM) → queue → deliver         │  ──SMTP────►   customer
                        └────────────────────────────────────────┘
                              multi-tenant: one deployment,
                              many customers, many agents
```

**Built for platforms.** Tenancy reaches every layer: each domain, mailbox, API
key, rate limit, suppression list, and spam profile belongs to a tenant. If you
run an agentic platform or sell email as a feature, each of your customers gets
isolated sending reputation, their own domains, and their own inboxes on one
deployment.

**It is also a complete mail server.** Sentio implements the full protocol -
inbound and outbound, DKIM/SPF/DMARC/ARC, MTA-STS, DANE, three-tier anti-spam -
so the agent inbox rests on real mail infrastructure rather than a wrapper
around someone else's API.

---

## Contents

- [Quick start with Docker](#quick-start-with-docker) - running in ~5 minutes
- [Installing without Docker](#installing-without-docker) - requirements and manual setup
- [Configuration](#configuration)
- [API reference and testing UI](#api-reference-and-testing-ui) - browse and call every endpoint
- [Give an agent its own inbox](#give-an-agent-its-own-inbox) - the flagship walkthrough
- [Building agents](docs/building-agents.md) - patterns for running agents in production
- [Sending your first message](#sending-your-first-message)
- [Receiving mail](#receiving-mail)
- [Beyond sending and receiving](#beyond-sending-and-receiving) - tracking, suppressions, webhooks, warmup
- [Running a real mail server](#running-a-real-mail-server) - DNS, PTR, port 25
- [Testing](#testing)
- [Architecture](#architecture)
- [Contributing](#contributing)

---

## Quick start with Docker

The compose stack brings up Sentio plus every service it needs: PostgreSQL,
Redis, NATS/JetStream, MinIO, ClamAV, and rspamd.

**Requirements:** Docker Engine 24+ with the Compose plugin, ~4 GB RAM, ~8 GB disk.
The first build compiles the whole workspace in release mode and takes a while;
later rebuilds reuse the cached dependency layer.

```bash
git clone https://github.com/truespar/sentio.git
cd sentio
docker compose up -d --build
```

Watch it come up - migrations run once, then the server starts:

```bash
docker compose logs -f sentio-migrate   # schema + bootstrap tenant
docker compose logs -f sentio           # the server
```

Confirm it is healthy:

```bash
curl localhost:8080/health/ready
# {"status":"ok","database":"ok","kv":"ok"}
```

### Bootstrap credentials

Migration `007` seeds one admin tenant and one API key:

| | |
|---|---|
| Tenant ID | `00000000-0000-0000-0000-000000000001` |
| API key | `sentio_bootstrap_admin_CHANGE_ME` |

```bash
curl -H "Authorization: Bearer sentio_bootstrap_admin_CHANGE_ME" \
     localhost:8080/v1/tenants
```

> [!WARNING]
> Rotate this key before exposing the host to anything untrusted. It has
> wildcard (`*`) scope. Create a replacement via
> `POST /v1/tenants/{id}/api-keys`, then delete the bootstrap key.

### Ports

| Port | Purpose | Notes |
|------|---------|-------|
| 25 | SMTP (MX) | Inbound mail from other servers |
| 465 | SMTPS | Implicit TLS - only binds when certificates are present |
| 587 | Submission | STARTTLS |
| 8080 | REST API | Also serves `/openapi.json` |
| 9001 | MinIO console | Optional; remove from compose to hide |

Already running something on port 25 (Postfix, Exim)? Either stop it or remap,
by creating a `docker-compose.override.yml`:

```yaml
services:
  sentio:
    ports: !override
      - "2525:25"
      - "4465:465"
      - "5587:587"
      - "8080:8080"
```

`!override` replaces the port list instead of appending to it. The file is
gitignored and loaded automatically.

### TLS

No certificates ship with the image, so Sentio starts in plaintext and skips
port 465. Mount a certificate and key to enable TLS:

```yaml
services:
  sentio:
    volumes:
      - ./tls:/etc/sentio/tls:ro   # expects cert.pem and key.pem
```

### Shutting down

```bash
docker compose down       # stop, keep data
docker compose down -v    # stop and delete all volumes
```

---

## Installing without Docker

### Requirements

**Build toolchain**

| Requirement | Notes |
|---|---|
| Rust stable | Edition 2021. Install via [rustup](https://rustup.rs) |
| `cmake` | Needed by `aws-lc-rs`, the rustls crypto backend |
| `libclang-dev` | Needed by bindgen-based dependencies |
| A C toolchain | `build-essential` or equivalent |

**Required services**

| Service | Default address | Purpose |
|---|---|---|
| PostgreSQL 18 | `localhost:5432` | All persistent state |
| Redis or Valkey | `localhost:6379` | Rate limits, bans, greylist, reputation |
| NATS with JetStream | `localhost:4222` | Delivery, retry, webhook, and event pipelines |
| S3-compatible storage | `localhost:9000` | Raw `.eml` and attachment blobs |

Any S3-compatible endpoint works - AWS S3, Cloudflare R2, MinIO, SeaweedFS,
Ceph. For NATS, JetStream must be enabled (`nats-server -js`); Sentio creates
its own streams on startup.

**Optional services** - Sentio degrades gracefully if these are absent.

| Service | Default address | Without it |
|---|---|---|
| ClamAV (`clamd`) | `localhost:3310` | Attachments are not virus-scanned |
| rspamd | `localhost:11333` | Falls back to the built-in Rust scorer |

### 1. Install build dependencies

```bash
# Debian / Ubuntu
sudo apt-get install -y build-essential cmake libclang-dev pkg-config

# Fedora / RHEL
sudo dnf install -y gcc gcc-c++ cmake clang-devel pkgconf

# macOS
brew install cmake llvm
```

### 2. Build

```bash
git clone https://github.com/truespar/sentio.git
cd sentio
cargo build --release
```

The binary lands at `target/release/sentio-smtp`.

Compile-time-checked SQL is served from the committed `.sqlx/` cache, so no
database is needed to build. If you change a query, regenerate it with a live
database:

```bash
echo 'DATABASE_URL=postgres://sentio:sentio@localhost:5432/sentio' > .env
cargo sqlx prepare --workspace
```

### 3. Create the database

```bash
sudo -u postgres createuser --pwprompt sentio
sudo -u postgres createdb --owner=sentio sentio
```

### 4. Apply migrations

The binary embeds its migrations and applies them in order:

```bash
./target/release/sentio-smtp --config config/default.toml migrate
```

This creates the schema and seeds the bootstrap tenant and API key described
[above](#bootstrap-credentials).

### 5. Configure

Copy the shipped defaults and edit:

```bash
sudo mkdir -p /etc/sentio
sudo cp config/default.toml /etc/sentio/sentio.toml
```

At minimum set `server.hostname`, `database.url`, and the `[storage]`
credentials. See [Configuration](#configuration).

### 6. Run

```bash
./target/release/sentio-smtp --config /etc/sentio/sentio.toml serve
```

Binding ports below 1024 as a non-root user needs the capability rather than
root:

```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/sentio-smtp
```

### 7. Run as a service

A unit file is included at [`deploy/sentio-smtp.service`](deploy/sentio-smtp.service):

```bash
sudo cp target/release/sentio-smtp /usr/local/bin/
sudo cp deploy/sentio-smtp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentio-smtp
journalctl -u sentio-smtp -f
```

Review the unit's `Requires=`/`After=` lines first - they assume the supporting
services run on the same host.

---

## Configuration

TOML, with every value overridable by environment variable. The env form is
`SENTIO__SECTION__KEY` - a double underscore between levels, uppercased:

```bash
SENTIO__DATABASE__URL="postgres://sentio:secret@db.internal:5432/sentio"
SENTIO__SERVER__HOSTNAME="mail.example.com"
SENTIO__STORAGE__SECRET_KEY="…"
SENTIO__SPAM__RSPAMD__URL="http://127.0.0.1:11333"   # [spam.rspamd] url
```

Environment overrides win over the file, which makes secrets easy to keep out
of config: leave them unset in TOML and inject them at runtime.

Key sections:

| Section | Controls |
|---|---|
| `[server]` | Hostname, listener addresses, worker counts, session limits |
| `[tls]` | Certificate paths, minimum version, SNI, optional ACME |
| `[database]` | PostgreSQL URL and pool sizing |
| `[kv]` / `[redis]` | KV backend selection and connection |
| `[nats]` | JetStream URL, prefetch, stream retention |
| `[storage]` | S3 endpoint, credentials, bucket, path-style addressing |
| `[scanning]` | ClamAV host, size limits |
| `[spam]` | Backend choice, score thresholds |
| `[abuse]` | Rate limits, DNSBLs, greylisting, reputation thresholds |
| `[delivery]` | Retry schedule, connection pooling, optional smart-host relay |
| `[auth]` | DKIM/SPF/DMARC/ARC behaviour |
| `[llm]` | Provider, model, and when classification runs |
| `[observability]` | Log format and level, metrics, tracing |

Defaults live in [`config/default.toml`](config/default.toml); the container
image ships [`config/oss.toml`](config/oss.toml).

---

## API reference and testing UI

The server documents itself. Two endpoints, both live as soon as it starts:

| Endpoint | What it is |
|---|---|
| `/docs` | Interactive API reference with a built-in request client |
| `/openapi.json` | The OpenAPI 3.1 document - 114 operations across 83 paths |

Open <http://localhost:8080/docs> and you get every endpoint with its schemas,
examples, and a **Test Request** button that calls your running server. Set the
bearer token once in the auth panel and you can exercise the whole API from the
browser without writing a line of curl.

> [!NOTE]
> `/docs` loads its front-end assets from a CDN, so the browser opening it needs
> outbound internet access. Where that is blocked the page renders blank - use
> `/openapi.json` with your own tooling instead.

A generated copy of the specification is committed at
[`docs/openapi.json`](docs/openapi.json), so you can read the API, diff it
across versions, or generate a client without starting anything. Export it
yourself at any time - no config, database, or network required:

```bash
cargo run -- openapi > openapi.json          # from source
docker compose exec sentio sentio-smtp openapi   # from the container
```

Because it is a standard OpenAPI document, the usual generators work directly:

```bash
npx @openapitools/openapi-generator-cli generate \
    -i docs/openapi.json -g typescript-fetch -o ./client
```

### What the API covers

| Group | Ops | What it covers |
|---|--:|---|
| Messages | 9 | Submit single, batch, raw, or multipart mail; read status, events, and raw source |
| Domains | 7 | Register sending/receiving domains, fetch the DNS records to publish, verify them |
| Mailboxes | 5 | Per-address inboxes on a domain, with forwarding and auto-reply |
| Inbound Routes | 4 | Match inbound mail (exact, domain, regex, catch-all) to a webhook |
| Tenants | 6 | Create and manage tenants, tiers, and status |
| API Keys | 3 | Scoped keys per tenant |
| SMTP Credentials | 4 | Username/password pairs for SMTP submission (argon2-hashed) |
| OAuth | 5 | OAuth 2.0 clients - authorization code with PKCE, and client credentials |
| DKIM Keys | 5 | Generate, rotate, and retire signing keys; export the DNS record |
| Webhooks | 7 | Subscribe to delivery and engagement events, HMAC-signed with retries |
| Suppressions | 5 | Bounce, complaint, and unsubscribe lists; check an address before sending |
| IP Pools | 12 | Dedicated and shared pools, tenant assignment, and IP warmup schedules |
| Reputation | 3 | Per-IP and per-domain reputation scores |
| Abuse | 8 | IP bans, whitelists, and reputation controls for the connection tier |
| Spam Training | 2 | Train the Bayesian classifier on spam and ham |
| Tracking | 2 | Open-pixel and click-redirect endpoints |
| Tracking Domains | 7 | Branded CNAME tracking domains with managed certificates |
| Queues | 4 | Inspect depth, list deferred mail, pause and resume delivery |
| Reports | 7 | Ingest and read DMARC aggregate, FBL/ARF, and TLS-RPT reports |
| Analytics | 4 | Delivery, engagement, and volume summaries |
| Errors | 3 | Captured error events with a summary endpoint |
| Health | 2 | Liveness and readiness probes |

114 operations across 83 paths.

Authentication is a bearer token on every `/v1/**` route:

```
Authorization: Bearer <your-api-key>
```

---

## Give an agent its own inbox

A **mailbox** is an address that belongs to a tenant's domain. Give each agent
one, and mail addressed to it arrives at your webhook already parsed,
authenticated, and scored.

```bash
KEY="sentio_bootstrap_admin_CHANGE_ME"
API="http://localhost:8080"
TENANT="00000000-0000-0000-0000-000000000001"

# 1. A receiving domain for this tenant
DOMAIN_ID=$(curl -s -X POST "$API/v1/domains" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"domain_name":"acme.example.com","use_for_receiving":true,"use_for_sending":true}' \
  | jq -r .data.id)

# 2. One mailbox per agent. metadata is yours - put the agent id in it.
curl -X POST "$API/v1/domains/$DOMAIN_ID/mailboxes" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{
    "address": "support-agent",
    "display_name": "Acme Support Agent",
    "metadata": {"agent_id": "agt_01H8..."}
  }'

# 3. Route the domain to your application
curl -X POST "$API/v1/tenants/$TENANT/inbound-routes" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{
    "match_type": "domain",
    "pattern": "acme.example.com",
    "webhook_url": "https://your-platform.example.com/hooks/inbound",
    "priority": 100
  }'
```

`support-agent@acme.example.com` is now live. Inbound mail is SPF/DKIM/DMARC
verified, virus-scanned, and spam-scored *before* your webhook fires, and those
verdicts arrive with the payload - so an agent never has to reason about
whether a sender was forged.

### Replying in thread

Pass the inbound `Message-ID` back as `in_reply_to` and the reply threads
correctly in the recipient's client:

```bash
curl -X POST "$API/v1/messages/send" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{
    "from": "support-agent@acme.example.com",
    "to": ["customer@example.net"],
    "subject": "Re: Order #1234",
    "text": "Refund processed - you should see it in 3-5 days.",
    "in_reply_to": "<abc123@example.net>",
    "references": ["<abc123@example.net>"]
  }'
```

Outbound is DKIM-signed with the tenant's own key, so replies authenticate as
the customer's domain rather than yours.

### Useful mailbox options

| Field | Effect |
|---|---|
| `metadata` | Free-form JSON - the natural place for your `agent_id` |
| `forward_to` | Forward inbound mail on to external addresses (see below) |
| `auto_reply` | Immediate acknowledgement, threaded via `In-Reply-To`, while the agent works |
| `status` | `disabled` stops delivery without deleting history |

### Forwarding a mailbox to external addresses

Set `forward_to` and everything arriving at that mailbox is forwarded on, to any
address anywhere - a personal Gmail account, a shared team inbox, a helpdesk:

```bash
curl -X PUT "$API/v1/domains/$DOMAIN_ID/mailboxes/$MAILBOX_ID" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{
    "address": "support-agent",
    "forward_to": ["oncall@gmail.com", "team@helpdesk.example.net"]
  }'
```

Forwarding is where most mail servers quietly break DMARC: they relay the
message unchanged, so the original `From:` no longer aligns with the forwarding
host's SPF, and the receiver rejects it. Sentio rewrites the envelope instead -
`From:` becomes the mailbox, and the message is re-signed with that domain's
DKIM key, so it authenticates as yours and survives the trip. The
original sender is preserved in `Reply-To:` and `Resent-From:`, so hitting reply
still answers the person who wrote in, and `Resent-To:` / `Resent-Date:` record
the hop per RFC 5322. The body is untouched.

That combination makes forwarding useful for more than escalation: point a
mailbox at a human while an agent is being tuned, fan one address out to a
team, or run a catch-all that lands in an inbox somebody already reads. Pair it
with `auto_reply` to acknowledge the sender immediately while the mail is on its
way to a human.

> [!IMPORTANT]
> Give the forwarding domain its own DKIM key. Re-signing is what makes the
> rewritten `From:` authenticate; without an active key the forward still goes
> out, but unsigned, and picky receivers will treat it accordingly.

### Scaling to many tenants

Create a tenant per customer, then give each its own domains, mailboxes, and
API key:

```bash
curl -X POST "$API/v1/tenants" -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' -d '{"name":"Acme Corp","tier":"shared_premium"}'

curl -X POST "$API/v1/tenants/$NEW_TENANT_ID/api-keys" -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' -d '{"name":"Acme production","scopes":["*"]}'
```

Tiers (`dedicated`, `shared_premium`, `shared_standard`) select the isolation
level, including whether the tenant sends from a dedicated IP pool. Rate limits,
suppression lists, and Bayesian spam profiles are all per-tenant, so one noisy
customer cannot spend another's reputation.

---

## Sending your first message

Outbound requires a **verified** sending domain, which proves you control it.

```bash
KEY="sentio_bootstrap_admin_CHANGE_ME"
API="http://localhost:8080"

# 1. Register the domain
curl -X POST "$API/v1/domains" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"domain_name":"example.com","use_for_sending":true}'

# 2. Get the DNS records to publish, then publish them at your DNS host
curl -H "Authorization: Bearer $KEY" "$API/v1/domains/$DOMAIN_ID/dns-records"

# 3. Ask Sentio to check them
curl -X POST -H "Authorization: Bearer $KEY" "$API/v1/domains/$DOMAIN_ID/verify"

# 4. Send
curl -X POST "$API/v1/messages/send" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{
    "from": "hello@example.com",
    "to": ["someone@elsewhere.com"],
    "subject": "Sent with Sentio",
    "text": "Plain text body",
    "html": "<p>HTML body</p>"
  }'
```

Also available: `/v1/messages/send-batch` (up to 500), `/v1/messages/send-raw`
(pre-built EML), and `/v1/messages/send-multipart` (file upload). Delivery
status and per-message events come from `/v1/messages/{id}` and
`/v1/messages/{id}/events`.

The full API - 114 operations across 83 paths - is described by the OpenAPI
document the server serves at `/openapi.json`.

---

## Receiving mail

Register a receiving domain, then attach a route that POSTs parsed messages to
your application:

```bash
curl -X POST "$API/v1/domains" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"domain_name":"example.com","use_for_receiving":true}'

curl -X POST "$API/v1/tenants/$TENANT_ID/inbound-routes" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{
    "match_type": "domain",
    "pattern": "example.com",
    "webhook_url": "https://your-app.example.com/hooks/inbound",
    "priority": 100
  }'
```

`match_type` is one of `exact`, `domain`, `regex`, or `catch_all`; lower
`priority` wins. Every inbound message is SPF/DKIM/DMARC/ARC verified,
virus-scanned, and spam-scored before your webhook fires, and the results
travel with the payload.

---

## Beyond sending and receiving

Features that matter once mail is actually flowing, all driven from the same API.

**Engagement tracking.** Open-pixel injection and click-through URL rewriting,
with bot detection so mail-scanner opens are not counted as human ones, plus
device/client parsing. Serve it from your own branded CNAME via
`/v1/tracking-domains` rather than a shared host.

**Suppression management.** Hard bounces and ISP complaint (FBL/ARF) reports
suppress addresses automatically, RFC 8058 one-click unsubscribe is honoured,
and `/v1/suppressions` lets you check an address before you spend a send on it.

**Event webhooks.** Distinct from inbound routing: subscribe to lifecycle events
(`delivered`, `bounced`, `deferred`, `dropped`, `opened`, `clicked`,
`unsubscribed`, and more), signed with HMAC-SHA256 in an `X-Sentio-Signature`
header over `{timestamp}.{nonce}.` plus the raw body, with retries, per-endpoint
concurrency caps, delivery logs, and a test-dispatch endpoint. See
[building agents on Sentio](docs/building-agents.md).

**Mailbox forwarding.** Any mailbox can forward to external addresses, with
`From:` rewritten and re-signed so the message keeps authenticating after the
hop, and the original sender kept in `Reply-To:`. See
[above](#forwarding-a-mailbox-to-external-addresses).

**IP pools and warmup.** Assign tenants to dedicated or shared pools and ramp
new addresses on a schedule with per-ISP overrides, instead of sending an
untrusted IP straight to full volume.

**Reports.** DMARC aggregate, FBL/ARF, and TLS-RPT reports are ingested and
readable over the API, so authentication failures and TLS problems surface as
data rather than as unexplained delivery loss.

**Queue control.** Inspect queue depth, list deferred mail, and pause or resume
delivery without stopping the server.

**Observability.** Prometheus metrics, OpenTelemetry traces spanning submission
through delivery, structured JSON logs with per-component levels, a per-message
trace ID, and captured error events with a summary endpoint. `/health/live` and
`/health/ready` are the probes; the metrics endpoint is unauthenticated and is
deliberately not published by the compose stack.

---

## Running a real mail server

Software is the easy half. Mail deliverability depends on DNS and IP
reputation, and skipping this is the usual reason self-hosted mail lands in
spam folders.

**DNS records you need,** for `mail.example.com` serving `example.com`:

| Record | Example | Why |
|---|---|---|
| `A`/`AAAA` | `mail.example.com → 203.0.113.10` | Reachability |
| `MX` | `example.com → 10 mail.example.com` | Where inbound mail goes |
| `PTR` | `203.0.113.10 → mail.example.com` | Reverse DNS; **set by your hosting provider**, not your DNS host |
| `SPF` | `v=spf1 mx -all` | Which hosts may send for the domain |
| `DKIM` | from `/v1/domains/{id}/dns-records` | Signature verification |
| `DMARC` | `v=DMARC1; p=quarantine; rua=mailto:…` | Alignment policy and reports |

Sentio generates the SPF, DKIM, and DMARC records for you -
`GET /v1/domains/{id}/dns-records` - and `POST /v1/domains/{id}/verify` checks
what has actually propagated.

**Two things that catch people out:**

- **Port 25 outbound is blocked** by most residential ISPs and by several cloud
  providers by default (AWS, GCP, Azure, Oracle, and Hetzner all restrict it).
  You may need to request a limit lift, or relay through a smart host -
  see `[delivery.relay]`.
- **Forward and reverse DNS must agree.** Many receivers reject mail from a host
  whose `PTR` does not resolve back to its address. Only your hosting provider
  can set `PTR`.

---

## Testing

Unit tests need no infrastructure:

```bash
cargo test --workspace
```

An end-to-end harness exercises both directions against a running stack:

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml up -d
scripts/e2e/run-e2e.sh
```

It sends real mail into the SMTP listener from the host and asserts that it is
stored and routed, then submits via the API and asserts the delivered message
reaches the sink carrying a DKIM signature. Captured outbound mail is
browsable at <http://localhost:8025>.

Nothing escapes to the internet: the overlay enables `[delivery.relay]`, which
bypasses MX resolution entirely, and all fixtures use the reserved `.test` TLD.
`scripts/e2e/smtp-send.py` also works standalone for poking at a running
server. See [`docs/testing.md`](docs/testing.md).

---

## Architecture

A Rust workspace of 13 crates:

| Crate | Responsibility |
|-------|----------------|
| `sentio-core` | Shared types, error model, configuration, repository traits |
| `sentio-store` | PostgreSQL repositories and the Redis KV pool |
| `sentio-smtp-server` | Inbound SMTP state machine, TLS, SASL AUTH |
| `sentio-smtp-client` | Outbound delivery, MX resolution, connection pooling |
| `sentio-auth` | DKIM, SPF, DMARC, ARC, MTA-STS, DANE, BIMI |
| `sentio-queue` | NATS/JetStream producers and consumers |
| `sentio-storage` | S3-compatible blob storage, ClamAV scanning |
| `sentio-spam` | rspamd integration and the built-in scoring engine |
| `sentio-abuse` | Rate limiting, IP bans, greylisting, reputation |
| `sentio-llm` | LLM classification (Anthropic, OpenAI, Ollama) |
| `sentio-webhooks` | HMAC-signed event dispatch with retries |
| `sentio-observe` | Structured logging, Prometheus metrics, OpenTelemetry |
| `sentio-api` | Axum REST API with generated OpenAPI |

**Anti-spam runs in three tiers,** so expensive checks only see traffic that
cheap ones could not decide:

1. **Connection level**, sub-millisecond - IP bans, connection and AUTH rate
   limits, DNSBL lookups, greylisting, reputation scoring, reverse DNS.
2. **Content scoring**, tens of milliseconds - rspamd or the built-in engine:
   Bayesian classification, fuzzy hashes, URL reputation, header heuristics.
3. **LLM tiebreak**, borderline scores only - `classifier.rs` skips any message
   scoring outside the configurable review band (`score_llm_review_min`..
   `score_llm_review_max`, 4.0-6.0 by default), so clear ham and clear spam
   never reach a model.

**Standards.** Core SMTP (RFC 5321/5322 and the ESMTP extensions), transport
security (STARTTLS, MTA-STS, DANE, TLS-RPT), authentication (SASL, DKIM, SPF,
DMARC, ARC, BIMI), and deliverability (one-click unsubscribe, FBL/ARF, BATV,
DNSBL/URIBL). Per-RFC notes live in [`docs/`](docs/).

---

## Documentation

| Document | Contents |
|---|---|
| [Building agents](docs/building-agents.md) | Addressing, receiving and replying, untrusted input, event verification |
| [Capabilities](docs/sentio-capabilities.md) | Full feature catalogue |
| [Testing](docs/testing.md) | Unit tests and the end-to-end harness |
| [OpenAPI spec](docs/openapi.json) | Generated API description |
| RFC compliance | Line-by-line audits of [5321](docs/rfc5321-compliance.md), [3207](docs/rfc3207-compliance.md), [4954](docs/rfc4954-compliance.md) |
| [Changelog](CHANGELOG.md) | Notable changes |

## Contributing

Issues and pull requests are welcome - see [CONTRIBUTING.md](CONTRIBUTING.md)
for the development workflow, build commands, and code conventions. By
participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Please do not report security vulnerabilities through public issues. See
[SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE).
