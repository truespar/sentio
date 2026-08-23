# Building agents on Sentio

How to run an email-native agent, or a platform of them, on top of Sentio. The
patterns here come from operating this in production; the ordering follows the
mistakes that are expensive to fix later.

## The two webhook streams

Sentio delivers two different things over HTTP, and treating them as one is the
most common early mistake.

| | Configured via | Fires when | Auth |
|---|---|---|---|
| **Inbound routes** | `POST /v1/tenants/{id}/inbound-routes` | Mail arrives for a matching recipient | Admin-scoped key |
| **Event webhooks** | `POST /v1/webhooks` | A message changes state: `delivered`, `bounced`, `deferred`, `dropped`, `opened`, `clicked`, `unsubscribed` | Per-tenant key |

An agent needs the first to receive mail and the second to learn whether its own
replies landed. The two use **different API keys**: inbound routes are
administered per tenant by an operator key, while `/v1/webhooks` is scoped to
the calling tenant. Plan for both credentials from the start.

## Addressing

Give each agent a stable address on a domain you control:

```
<agent-slug>@agents.example.com
```

Three rules worth adopting before you have users:

- **Globally unique**, not unique-per-tenant. Two tenants that both want
  `support@` will collide the moment you use one shared domain.
- **Append-only, never reused.** When an agent is deleted, retire the slug and
  leave it retired. Replies to a months-old thread still arrive, and handing
  that address to a different tenant leaks one customer's mail to another.
- **Allocate at creation, not on first send**, so the address exists before
  anyone is told about it.

A single `match_type: "domain"` route over the whole domain is usually better
than one route per agent: one route to keep healthy instead of thousands, and
new agents work the moment their slug is allocated. Resolve the slug to an agent
in your own handler.

## Receiving a message

Point the route at one endpoint and resolve the agent from the recipient:

```bash
curl -X POST "$API/v1/tenants/$TENANT/inbound-routes" \
  -H "Authorization: Bearer $ADMIN_KEY" -H 'Content-Type: application/json' \
  -d '{
    "match_type": "domain",
    "pattern": "agents.example.com",
    "webhook_url": "https://your-platform.example.com/hooks/inbound",
    "llm_classify": true,
    "priority": 100
  }'
```

The payload arrives parsed - headers, text and HTML bodies, attachments - and
already carries Sentio's verdicts. **Use them as an intake gate before you spend
a single token.** SPF/DKIM/DMARC results, the spam score, and the virus scan
result are all present; junk should be dropped or quarantined by your handler,
not reasoned about by a model.

Setting `llm_classify: true` asks Sentio to classify borderline mail for you,
which is worth it on a catch-all route where anything can arrive.

Answer webhooks fast and do the work asynchronously. Acknowledge with a 2xx once
the message is durably enqueued on your side; Sentio retries non-2xx responses,
and a slow handler turns into duplicate deliveries.

## Replying as the agent

Send from the agent's own address and thread the reply:

```bash
curl -X POST "$API/v1/messages/send" \
  -H "Authorization: Bearer $TENANT_KEY" -H 'Content-Type: application/json' \
  -d '{
    "from": "support-agent@agents.example.com",
    "to": ["customer@example.net"],
    "subject": "Re: Order #1234",
    "text": "...",
    "in_reply_to": "<the-inbound-message-id>",
    "references": ["<the-inbound-message-id>"]
  }'
```

`in_reply_to` is what makes Gmail, Outlook, and Apple Mail file the reply into
the existing conversation instead of starting a new one. Build `references` by
taking the parent's `References` and appending the parent's `Message-ID`.

The reply is DKIM-signed with the tenant's key, so it authenticates as their
domain rather than yours.

## Treat the message body as hostile

This is the part with no equivalent in a normal webhook integration: **anyone in
the world can send text to your agent.** An inbound body is untrusted input that
will be placed in a model's context.

- Keep the body as *data*, never as instructions. Do not concatenate it into a
  system prompt.
- Bound the blast radius. An agent acting on mail should not hold credentials or
  tools whose misuse you could not tolerate a stranger triggering.
- Put a human in the loop for irreversible actions - refunds, account changes,
  anything outward-facing.
- Constrain the recipients an agent may reply to. Replying only to the inbound
  sender prevents a crafted message from turning your agent into a relay.
- Rate-limit per sender and per tenant, so one adversary cannot exhaust a
  tenant's budget.

## Escalating to a human

An agent that cannot answer should hand off rather than guess. Set `forward_to`
on the mailbox and inbound mail is forwarded to real people as well, with
`From:` rewritten to the mailbox and re-signed with that domain's DKIM key so it
still passes DMARC after the hop, and the original sender preserved in
`Reply-To:` so a human reply goes back to the right place. Make sure the domain
has an active DKIM key, or the forward goes out unsigned.

This is also the safest way to start: point a new agent's mailbox at a human
inbox, watch what actually arrives for a week, and only then let the agent
answer on its own.

## Knowing whether the reply landed

Subscribe to lifecycle events so the agent learns the outcome of its own send:

```bash
curl -X POST "$API/v1/webhooks" \
  -H "Authorization: Bearer $TENANT_KEY" -H 'Content-Type: application/json' \
  -d '{
    "url": "https://your-platform.example.com/hooks/events",
    "event_types": ["delivered","bounced","dropped","deferred","opened","clicked","unsubscribed"]
  }'
```

Every dispatch carries four headers:

```
X-Sentio-Event:     delivered
X-Sentio-Timestamp: 1787513589
X-Sentio-Nonce:     <random>
X-Sentio-Signature: <hex hmac-sha256>
```

The signature is HMAC-SHA256 over `"{timestamp}.{nonce}."` concatenated with
the raw request body, hex-encoded, keyed by the webhook's signing secret.
Verify it against the **raw bytes** before any JSON parsing, use a constant-time
comparison, and reject timestamps outside a tolerance window - the nonce and
timestamp are what stop a captured request being replayed. Skip this and your
events endpoint is an unauthenticated write path into your platform.

`bounced` and `dropped` deserve product behaviour, not just a log line: a hard
bounce means that address is gone, and Sentio has already added it to the
tenant's suppression list. An agent that keeps composing replies to a dead
address wastes tokens and reputation.

## Multi-tenant checklist

Running many customers' agents on one deployment:

- One Sentio tenant per customer, so reputation, rate limits, suppression lists,
  and Bayesian spam profiles stay separate.
- A per-tenant API key, never the bootstrap key.
- Their own sending domain and DKIM key, so mail authenticates as them.
- `dedicated` tier plus an IP pool for anyone whose volume justifies it, with a
  warmup schedule rather than full volume on day one.
- Per-tenant rate limits, so one noisy customer cannot spend another's
  reputation.

## Testing without sending real mail

`docker-compose.test.yml` enables `[delivery.relay]`, which bypasses MX
resolution so every outbound message goes to a local sink instead of the
internet, and the fixtures use the reserved `.test` TLD. Point your integration
tests at that stack and assert against the sink's API. See
[testing.md](testing.md).
