# Sentio SMTP - Product Capabilities

> A next-generation, self-hosted email infrastructure platform built in Rust.
> Multi-tenant. API-first. AI-native.

---

## Product Overview

Sentio SMTP is a complete email infrastructure platform - not a patched legacy MTA. Built from the ground up in Rust with async I/O, it handles both inbound and outbound email at scale with full programmatic control through a comprehensive REST API.

**Who it's for:** Developers, SaaS providers, managed service providers, and enterprises that need self-hosted email infrastructure with the developer experience of modern SaaS email APIs.

**What makes it different:**

- **Rust performance and safety** - no buffer overflows, no data races, zero-copy parsing
- **API-first** - 100+ REST endpoints; SMTP is a protocol layer, not the primary interface
- **Multi-tenant from the ground up** - tenant isolation reaches every layer
- **AI-native** - LLM-based classification and auto-response built into the processing pipeline
- **Three-tier anti-spam** - Redis abuse guard + rspamd/builtin scoring + LLM tiebreaker
- **Standards-complete** - 30+ RFCs implemented; RFC 5321, 3207, and 4954 formally audited line by line (179 requirements, no failures)

---

## RFC & Standards Compliance

Sentio implements a comprehensive set of email standards. All testable requirements pass compliance audits at 100%.

### Core SMTP Protocol

| RFC | Standard | Description |
|-----|----------|-------------|
| RFC 5321 | SMTP | Full SMTP protocol - 117/117 testable items pass |
| RFC 5322 | Internet Message Format | Message parsing, header handling, envelope/header separation |
| RFC 2034 | Enhanced Status Codes | Structured error codes on all SMTP responses |
| RFC 2920 | PIPELINING | Batch multiple commands per TCP send, reducing round-trips |
| RFC 6152 | 8BITMIME | 8-bit binary data transmission |
| RFC 1870 | SIZE | Message size declaration before transmission |
| RFC 3030 | CHUNKING / BINARYMIME | BDAT command for chunked and binary content transfer |
| RFC 6531 | SMTPUTF8 | Internationalized email addresses (full UTF-8 support) |
| RFC 3461 | DSN | Delivery Status Notifications with per-recipient control |
| RFC 3464 | DSN Format | Machine-readable delivery status messages |
| RFC 7505 | Null MX | Proper handling of domains that do not accept mail |

### Transport Security

| RFC | Standard | Description |
|-----|----------|-------------|
| RFC 3207 | STARTTLS | Opportunistic and enforced TLS - 17/17 items pass |
| RFC 8314 | Implicit TLS | Port 465 immediate TLS for mail submission |
| RFC 8446 | TLS 1.3 | TLS 1.2 and 1.3 support with configurable minimum version |
| RFC 7672 | DANE | DNSSEC-authenticated TLSA record validation for outbound delivery |
| RFC 8461 | MTA-STS | TLS enforcement policy discovery and caching |
| RFC 8460 | TLSRPT | TLS failure reporting with database storage |
| RFC 5929 | Channel Binding | `tls-server-end-point` binding for SCRAM-SHA-256-PLUS |

### Authentication & Identity

| RFC | Standard | Description |
|-----|----------|-------------|
| RFC 4954 | SMTP AUTH | SASL authentication - 27/27 items pass |
| RFC 4616 | SASL PLAIN | Username/password authentication over TLS |
| RFC 5802 | SCRAM-SHA-256 | Challenge-response with server proof verification |
| RFC 7677 | SCRAM-SHA-256 for SMTP | SCRAM binding for SMTP AUTH |
| RFC 6376 | DKIM | Signing (Ed25519 + RSA) and verification with automated key rotation |
| RFC 7208 | SPF | Record parsing, validation, macro expansion, DNS lookup counting |
| RFC 7489 | DMARC | Policy enforcement, alignment checking, aggregate/forensic reporting |
| RFC 8617 | ARC | Authenticated Received Chain for forwarded messages |
| RFC 8601 | Authentication-Results | Standardized auth result headers on every inbound message |
| RFC 9495 | BIMI | Brand logo discovery, SVG validation, optional VMC verification |

### Deliverability & Compliance

| RFC | Standard | Description |
|-----|----------|-------------|
| RFC 8058 | List-Unsubscribe | Auto-injected one-click unsubscribe headers (Google/Yahoo requirement) |
| RFC 5965 | ARF / FBL | ISP Feedback Loop complaint processing with auto-suppression |
| RFC 2606 | Reserved Domains | Proper use of `.invalid` TLD in testing and validation |

### Additional Standards

| Standard | Description |
|----------|-------------|
| BATV | Bounce Address Tag Validation - forged bounce (backscatter) prevention |
| DNSBL/RBL | Real-time blocklist lookups (Spamhaus, Barracuda, SpamCop, SORBS) |
| URIBL | URI-based blocklist lookups for content scanning |
| OAuth 2.0 | Authorization code + client credentials flows with PKCE (S256) |
| PROXY Protocol | HAProxy v1/v2 for load-balanced deployments |
| XCLIENT | Testing and proxy support for client IP forwarding |
| OpenAPI 3.0 | Auto-generated API documentation with Scalar UI |

---

## Feature Catalog

### Sending & Delivery

| Feature | Description |
|---------|-------------|
| REST API message submission | Send single messages, batches (up to 500), or raw RFC 5322 EML |
| SMTP submission | Ports 25, 465 (implicit TLS), 587 (STARTTLS) with SASL authentication |
| Message scheduling | `send_at` parameter for future delivery (up to 72 hours) |
| Connection pooling | Persistent, TLS-amortized pools per destination domain |
| MX resolution | Preference-ordered MX with A/AAAA fallback and null MX handling |
| Exponential retry | 5m → 10m → 20m → 40m → 67m with jitter; 5-day queue lifetime |
| Per-domain retry overrides | Custom retry schedules for Gmail, Microsoft, Yahoo, etc. |
| Per-destination rate limiting | Respect ISP sending limits with configurable per-domain caps |
| DSN generation | RFC 3464 bounce messages with original envelope and recipient data |
| Relay support | Configurable smart host relay with STARTTLS and AUTH |
| IPv6 dual-stack | Native IPv4 + IPv6 on all listening ports |
| Batch delivery | Configurable batch sizes for high-throughput processing |

### Receiving & Inbound Processing

| Feature | Description |
|---------|-------------|
| Full SMTP server | Standards-compliant inbound on port 25 with all ESMTP extensions |
| Inbound webhooks | Parsed message data dispatched as structured HTTP events |
| Per-address routing | Exact, regex, domain, and catch-all webhook routing rules |
| MIME parsing | Headers, text/HTML body parts, and attachment metadata extraction |
| Authentication verification | SPF, DKIM, DMARC, ARC validation on every inbound message |
| Virus scanning | ClamAV integration - attachments scanned before storage |
| Spam scoring | rspamd or native Rust engine with per-rule symbol breakdowns |
| LLM classification | AI-powered tiebreaker for borderline spam decisions |
| Auto-response | LLM-generated responses with tenant-specific templates |
| Loop detection | Received header counting (configurable threshold, default 50) |

### Email Authentication Lifecycle

| Feature | Description |
|---------|-------------|
| DKIM key generation | Ed25519 (default) and RSA-2048 with DNS record output via API |
| Automated DKIM rotation | Overlap periods during key transition, with active/rotating/retired states |
| SPF verification | Full record parsing with macro expansion and 10-lookup limit enforcement |
| DMARC enforcement | Policy evaluation, organizational domain alignment, rollout recommendations |
| DMARC aggregate reports | Stored in database with per-domain pass/fail statistics |
| ARC signing | Authenticated Received Chain for forwarded messages |
| MTA-STS enforcement | Policy discovery with configurable cache (default 24h) |
| DANE/TLSA validation | DNSSEC-authenticated TLS with DANE-EE + SPKI + SHA-256 |
| BIMI support | Brand logo lookup, SVG validation, optional VMC requirement |
| DNS verification API | Check SPF, DKIM, DMARC, MX, and return path status per domain |

### Multi-Tenancy

| Feature | Description |
|---------|-------------|
| Tiered isolation | Dedicated, Shared Premium, and Shared Standard tiers |
| Per-tenant configuration | JSONB config overrides per tenant for every feature |
| IP pool management | Shared and dedicated pools with tenant assignments and priority |
| IP warming schedules | Gradual volume ramp-up with per-ISP overrides and daily increase % |
| Per-tenant rate limiting | Messages per second/minute/hour/day with token bucket and burst |
| Per-tenant Bayesian filters | Redis-backed spam classifiers that learn from each tenant's mail |
| Per-tenant observability | Delivery, bounce, complaint, and authentication metrics per tenant |
| Tenant status management | Active, suspended, and deleted states with API control |
| Configurable retention | Per-tenant message, raw EML, and attachment retention periods |

### API

Sentio exposes 100+ REST endpoints across 18 resource groups, all versioned under `/v1/`.

| Resource Group | Key Endpoints |
|----------------|---------------|
| **Messages** | Send, send-batch, send-raw, list, get, events, raw download, attachments |
| **Domains** | Create, verify, DNS records, DKIM key management, mailboxes |
| **Webhooks** | CRUD, test dispatch, delivery logs |
| **Queues** | Stats, pause/resume, deferred inspection |
| **Suppressions** | List, add, remove, check (hard bounces, complaints, unsubscribes, manual) |
| **Tenants** | CRUD, status, IP pool assignments, API keys, SMTP credentials, inbound routes |
| **IP Pools** | CRUD, add/remove IPs, pool status, tenant assignments |
| **Spam** | Train ham/spam for Bayesian filters |
| **Reports** | DMARC aggregate, FBL/ARF complaints, TLSRPT TLS failures |
| **Reputation** | Domain reputation scores, IP reputation scores |
| **Analytics** | Overview, delivery stats, engagement stats, bounce breakdown |
| **Tracking Domains** | Custom CNAME domains for open/click tracking with TLS certificates |
| **OAuth** | Client management, authorization, token lifecycle |
| **Abuse** | IP bans, whitelist, reputation scores, reputation reset |
| **Errors** | Error event log, summary, detail view |
| **Health** | Liveness and readiness probes |
| **Tracking** | Open pixel and click redirect endpoints |
| **OpenAPI / Docs** | Auto-generated OpenAPI 3.0 spec with Scalar interactive UI |

**Authentication options:**
- API keys with scoped permissions (send-only, read-only, admin)
- OAuth 2.0 (authorization code with PKCE + client credentials)
- mTLS for internal service communication

**Rate limiting:** Standard `X-RateLimit-*` headers with `429 Too Many Requests` and `Retry-After`.

### Webhooks

| Feature | Description |
|---------|-------------|
| Real-time event dispatch | HTTP POST for every email lifecycle event |
| Delivery events | `queued`, `processed`, `delivered`, `deferred`, `bounced`, `dropped`, `held`, `released` |
| Engagement events | `opened`, `clicked`, `unsubscribed` |
| Inbound events | `inbound.received`, `inbound.processed`, `inbound.classified` |
| System events | `domain.verified`, `domain.failed`, `reputation.warning`, `quota.exceeded` |
| HMAC-SHA256 signatures | `X-Sentio-Signature` over `{timestamp}.{nonce}.` + raw body, with `X-Sentio-Timestamp` / `X-Sentio-Nonce` / `X-Sentio-Event` alongside it for replay protection |
| Tiered retry strategy | Critical events (bounces): aggressive retries; informational events: standard retries |
| Per-endpoint concurrency | Configurable concurrent deliveries and per-second rate caps |
| Delivery logs | Full history of dispatch attempts, HTTP status, and response bodies |
| Test dispatch | Send a synthetic event to verify endpoint connectivity |
| Dead letter queue | Persistently failing events preserved for investigation |

### Anti-Spam & Abuse Protection

**Tier 1 - Connection-Level (Redis, sub-millisecond):**

| Check | Description |
|-------|-------------|
| IP bans | Temporary and permanent ban list with configurable TTL |
| Connection rate limiting | Sliding window per IP per minute |
| Failed AUTH tracking | Auto-ban after configurable failures per hour |
| DNSBL/RBL | Cached lookups against Spamhaus, Barracuda, SpamCop, SORBS |
| Greylisting | Triplet-based first-seen tracking with configurable delay |
| IP reputation scoring | Accumulated abuse score with time-based decay |
| Reverse DNS | Optional requirement for valid rDNS on connecting IPs |
| IP/CIDR whitelist | Bypass abuse checks for trusted sources |

**Tier 2 - Content Scoring (~50ms):**

| Backend | Description |
|---------|-------------|
| rspamd | Production-grade: Bayesian classification, fuzzy hashing, URL reputation, hundreds of rules |
| Builtin (Rust-native) | Cross-platform: DNSBL, URIBL, header analysis, content heuristics, Redis-backed Bayes |

Configurable score thresholds: accept → add header → greylist → reject → LLM review.

**Tier 3 - LLM Tiebreaker (borderline only, ~500ms):**

Only invoked for messages whose spam score falls inside the configurable review band (`score_llm_review_min`..`score_llm_review_max`, 4.0-6.0 by default). Messages scoring clearly ham or clearly spam never reach the LLM, so cost tracks how much of your mail lands in that band.

**Additional protections:**
- ClamAV virus scanning on all attachments before storage
- Per-session command rate limiting (default 1,000 commands)
- Per-session message count limiting (default 50 messages)
- Configurable max message size (default 50 MB)
- Backscatter prevention via BATV

### LLM Integration

| Feature | Description |
|---------|-------------|
| Inbound classification | Categorize incoming email: Legitimate, Commercial, Unsolicited, Harmful |
| Confidence scoring | High, Medium, Low confidence with configurable thresholds |
| Outbound compliance scanning | Detect PII, credential leaks, and policy violations before delivery |
| Auto-response generation | LLM-drafted responses with approval workflows |
| Pluggable providers | Anthropic Claude, OpenAI, self-hosted via Ollama/vLLM |
| Per-tenant configuration | Enable/disable, model selection, custom prompts per tenant |
| Cost management | Tiered processing (heuristics first), per-tenant usage quotas, caching |
| Async processing | LLM classification does not block the SMTP pipeline |

### Engagement Tracking

| Feature | Description |
|---------|-------------|
| Open tracking | Transparent pixel injection with bot detection and proxy open flagging |
| Click tracking | URL rewriting with redirect through tracking endpoint |
| Custom tracking domains | Branded CNAME domains with auto-managed TLS certificates |
| Device & client parsing | Client name/version, device type (desktop/mobile/tablet), OS detection |
| Geolocation | Country, region, and city from IP address (MaxMind GeoLite2) |
| Bot detection | Identify automated opens from mail scanners vs. real engagement |

### Mailbox Forwarding & Auto-Reply

| Feature | Description |
|---------|-------------|
| Forward to external addresses | Any mailbox can forward to one or more arbitrary addresses |
| DMARC-safe rewriting | `From:` is rewritten to the mailbox and the message re-signed with the domain's DKIM key, so forwarded mail still authenticates |
| Sender preserved | Original sender kept in `Reply-To:` and `Resent-From:`; `Resent-To:` and `Resent-Date:` record the hop per RFC 5322 |
| Fan-out | A single mailbox may forward to several recipients at once |
| Auto-reply | Optional immediate acknowledgement, threaded via `In-Reply-To` |

### Suppression Management

| Feature | Description |
|---------|-------------|
| Hard bounce suppression | Automatically suppress permanently invalid addresses |
| Complaint suppression | Auto-suppress addresses from ISP FBL/ARF reports |
| Unsubscribe suppression | One-click RFC 8058 unsubscribe with automatic suppression |
| Manual suppression | Add/remove addresses via API |
| Pre-send checking | API endpoint to check suppression status before sending |
| Bounce classification | Hard bounce, soft bounce, and block bounce categories |

### Observability

| Feature | Description |
|---------|-------------|
| Prometheus metrics | Messages sent/received/bounced, queue depth, latency, auth rates, LLM usage |
| OpenTelemetry tracing | Distributed traces from API submission through delivery |
| Structured JSON logging | Per-component log levels with tenant isolation |
| Health checks | `/health/live` (process alive) and `/health/ready` (dependencies connected) |
| Error event capture | Persistent error log with 30-day retention and summary endpoint |
| Per-message trace ID | End-to-end debugging across every pipeline stage |

### Storage & Data Architecture

| Component | Purpose |
|-----------|---------|
| PostgreSQL | Tenants, domains, DKIM keys, messages, events, suppressions, OAuth, reports (26 tables) |
| KV store (Redis) | Rate limiters, DNS cache, reputation scores, Bayesian token stores, real-time counters |
| NATS JetStream | Delivery, deferred, bounce, hold, webhook, LLM, and dead-letter streams |
| S3-compatible blob store | Raw EML archival and attachment storage (AWS S3, R2, B2, MinIO, SeaweedFS, …) |
| ClamAV | Virus scanning via clamd TCP protocol |

**Key data design decisions:**
- UUIDv7 (time-ordered) for partitioned tables - optimal B-tree insert locality
- Monthly partitioning on messages, events, engagement events, and attachments
- Automatic partition creation for future months
- Configurable per-tenant retention periods for messages, EML, and attachments
- Orphan upload cleanup for the upload-first attachment flow

---

## Architecture Highlights

### Built in Rust

- **Async I/O with Tokio** - multi-threaded, work-stealing scheduler handles tens of thousands of concurrent connections
- **Zero-copy parsing** - `Cow<str>` references into input buffers minimize allocation during high-throughput processing
- **Memory safety by construction** - no buffer overflows, no use-after-free, no data races
- **RAII resource management** - connections, file handles, and buffers are deterministically released

### Modular Crate Architecture

Sentio is a Rust workspace with 13 specialized crates:

| Crate | Responsibility |
|-------|----------------|
| `sentio-core` | Shared types, enums, error model, config, repository traits |
| `sentio-store` | PostgreSQL implementation of repository traits + Redis KV pool wrapper |
| `sentio-smtp-server` | Inbound SMTP state machine, TLS, SASL AUTH, pipeline |
| `sentio-smtp-client` | Outbound delivery, MX resolution, connection pooling, DSN generation |
| `sentio-auth` | DKIM, SPF, DMARC, ARC, MTA-STS, DANE, BIMI |
| `sentio-queue` | NATS/JetStream producer/consumer with retry logic |
| `sentio-storage` | S3-compatible blob storage and ClamAV scanning |
| `sentio-spam` | rspamd integration and native Rust scoring engine |
| `sentio-abuse` | KV-backed rate limiting, IP bans, greylisting, reputation |
| `sentio-llm` | LLM classification (Anthropic, OpenAI, Ollama) |
| `sentio-webhooks` | HMAC-signed webhook dispatch with tiered retries |
| `sentio-observe` | Logging, Prometheus metrics, OpenTelemetry |
| `sentio-api` | Axum REST API with OpenAPI documentation |

### Configuration

- TOML-based configuration (`config/default.toml`) with environment variable overrides (`SENTIO__SECTION__KEY`)
- SIGHUP-based hot reload for non-structural settings
- Per-tenant configuration overrides stored as JSONB in PostgreSQL
- Graceful shutdown with configurable drain and force timeouts

### Queue Architecture

Three JetStream streams carry the working set; consumers subscribe to
subject prefixes for the workload they own:

| Stream          | Subjects                                        | Retention   |
|-----------------|-------------------------------------------------|-------------|
| `sentio-submit` | `sentio.submit.message.{outbound,inbound}.>`    | WorkQueue   |
| `sentio-events` | `sentio.events.event.>`                         | Limits      |
| `sentio-dead`   | `sentio.dead.>`                                 | Limits (30d)|

Retry delays are driven by `AckKind::Nak(delay)` from the consumer;
permanent failures land on the dead stream for later inspection.

---

## Competitive Comparison

| Capability | Postfix / Exim | SendGrid / SES | Sentio SMTP |
|------------|----------------|----------------|-------------|
| Language | C | Managed | Rust |
| Memory safety | No | N/A | Yes |
| REST API | None | Yes | Yes (100+ endpoints) |
| Multi-tenancy | None | Limited | Full (3-tier isolation) |
| Webhooks | None | Yes | Yes (HMAC-signed, tiered retry) |
| Anti-spam | External (SpamAssassin) | Managed | Three-tier native (Redis + rspamd + LLM) |
| Abuse protection | External (fail2ban) | Managed | Native (sub-ms Redis) |
| LLM integration | None | None | Yes (classification + auto-response) |
| Self-hosted | Yes | No | Yes |
| DKIM management | Manual | Automated | Automated (Ed25519 + RSA, rotation) |
| DMARC reporting | None | Dashboard | Database + API |
| MTA-STS / DANE | Partial | Managed | Full |
| BIMI | None | Partial | Full (lookup + validation + API) |
| List-Unsubscribe | Manual header | Managed | Auto-inject RFC 8058 + one-click endpoint |
| Backscatter prevention | None | Managed | BATV |
| Engagement tracking | None | Yes | Yes (opens, clicks, custom domains) |
| Message scheduling | None | Yes | Yes (`send_at`) |
| Virus scanning | External (amavis) | Managed | ClamAV (native async) |
| Observability | Syslog | Dashboard | OpenTelemetry + Prometheus |
| Queue visibility | Opaque (file-based) | N/A | JetStream (per-subject inspection) |
| IP warming | Manual | Managed | Automated schedules with ISP overrides |
| FBL processing | Manual | Managed | Automated (RFC 5965 ARF + auto-suppress) |
| TLS cert management | Manual | Managed | ACME / Let's Encrypt auto-renewal + SNI |
| PROXY protocol | Patch / config | N/A | Native v1/v2 |
| IPv6 | Manual config | Managed | Native dual-stack on all ports |
| Open source | Yes | No | Yes |
| Config hot-reload | Requires restart | N/A | SIGHUP-based reload |
| API documentation | None | Yes | OpenAPI 3.0 + Scalar UI |

---

## Summary

Sentio SMTP is the first open-source email platform that combines:

- **The control of self-hosted infrastructure** - your data, your servers, your rules
- **The developer experience of modern SaaS email APIs** - REST API, webhooks, OAuth, OpenAPI docs
- **Rust performance and safety** - async I/O, zero-copy parsing, no memory safety vulnerabilities
- **AI-native intelligence** - LLM classification and auto-response built into the pipeline
- **Standards-complete** - 30+ RFCs implemented, with line-by-line audits of RFC 5321, 3207, and 4954 in `docs/`
