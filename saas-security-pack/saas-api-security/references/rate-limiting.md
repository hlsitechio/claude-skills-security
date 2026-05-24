# Rate Limiting Reference

Load this when designing or auditing API rate limits.

## Why per-tenant matters more than per-IP

In B2B SaaS, one customer's IP can serve dozens of users behind NAT. Per-IP limits either:
- Are too tight (blocking legitimate customers behind one office IP), or
- Are too loose (letting one customer DoS everyone).

The right model is multi-dimensional:

| Dimension | Why |
|-----------|-----|
| Per IP | Mitigates anonymous abuse, credential stuffing |
| Per API key / per JWT subject | One customer's abuse contained |
| Per tenant | One organization's runaway integration contained |
| Per endpoint | Expensive endpoints get their own bucket |
| Global | Absolute floor; protects infrastructure |

A request must pass all applicable buckets.

## Algorithms — when to use what

| Algorithm | Properties | Use when |
|-----------|------------|----------|
| **Token bucket** | Allows bursts up to bucket size, refills at fixed rate | Most APIs; customers expect occasional bursts |
| **Sliding window log** | Exact count over window; memory grows with request rate | Accuracy matters more than perf (auth endpoints) |
| **Sliding window counter** | Approximation: combines current + previous window | Good balance of accuracy and perf |
| **Fixed window** | Simple counter resets at window boundary | Easiest to implement; allows 2x burst at boundary |
| **Leaky bucket** | Smooths request rate; rejects bursts | When downstream can't handle bursts |

For most SaaS, **token bucket** (Redis-backed) is the default. Sliding window for auth endpoints where accuracy matters.

## Where to enforce

```
Client → CDN → Gateway/WAF → Application → Backend services
         ↑       ↑              ↑
         |       |              └ App-layer (most flexible, slowest to update)
         |       └ Gateway (per-key/per-IP, fast)
         └ Edge (global DDoS, per-IP coarse)
```

Defense in depth: limits at every layer, with stricter ones outside, looser ones inside. The edge handles volumetric attacks before they reach your app.

### Cloudflare / Fastly / CloudFront

Set per-IP and per-path limits at the edge. These are coarse but free and fast. Block obvious abuse before it costs you compute.

### API gateway

Kong, AWS API Gateway, Apigee, Tyk: enforce per-key or per-JWT limits. Configurable per-plan / per-customer. Gateway returns 429 without invoking your app.

### Application layer

For limits that depend on business logic (per-tenant quotas, cost-based limits, per-resource limits), enforce in the app with a Redis-backed counter.

## Token bucket in Redis (Lua script)

```lua
-- KEYS[1] = bucket key
-- ARGV[1] = capacity, ARGV[2] = refill_rate_per_sec, ARGV[3] = now_unix, ARGV[4] = requested_tokens
local capacity = tonumber(ARGV[1])
local refill = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local needed = tonumber(ARGV[4])

local data = redis.call('HMGET', KEYS[1], 'tokens', 'updated')
local tokens = tonumber(data[1]) or capacity
local updated = tonumber(data[2]) or now

local delta = math.max(0, now - updated) * refill
tokens = math.min(capacity, tokens + delta)

local allowed = 0
if tokens >= needed then
  tokens = tokens - needed
  allowed = 1
end

redis.call('HMSET', KEYS[1], 'tokens', tokens, 'updated', now)
redis.call('EXPIRE', KEYS[1], math.ceil(capacity / refill) + 60)
return { allowed, tokens, capacity }
```

The script is atomic, so concurrent requests don't double-spend tokens.

## Multi-dimensional check

```ts
async function rateLimit(ctx: RequestContext) {
  // Check in order: global → tenant → key → ip → endpoint
  const buckets = [
    { key: 'global:requests', capacity: 100_000, refill: 100_000 / 60 },
    { key: `tenant:${ctx.tenantId}:requests`, capacity: 1_000, refill: 1_000 / 60 },
    { key: `apikey:${ctx.apiKeyId}:requests`, capacity: 100, refill: 100 / 60 },
    { key: `ip:${ctx.ip}:requests`, capacity: 60, refill: 60 / 60 },
  ];
  for (const b of buckets) {
    const ok = await consumeToken(b.key, b.capacity, b.refill, 1);
    if (!ok) return { allowed: false, bucket: b.key };
  }
  return { allowed: true };
}
```

## Response headers

When limiting, return standard headers so clients can self-throttle:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 23
X-RateLimit-Reset: 1716499200
Retry-After: 30
```

On 429 responses, include `Retry-After` (seconds to wait) — clients with proper SDKs honor it.

## Cost-based limiting

Not every endpoint costs the same. A simple GET is cheap; a full-text search across millions of rows is expensive. Naive request-count limiting either undershoots (lets expensive queries crush you) or overshoots (blocks cheap requests).

Cost-based: each endpoint declares its cost in "units"; rate limits count units, not requests.

```ts
const endpointCosts = {
  'GET /users/me':        1,
  'GET /projects':        5,
  'GET /search':         20,
  'POST /export':       100,
};
```

GraphQL is the canonical case for cost-based: each query has a computed cost based on returned fields and resolvers. Tools: graphql-cost-analysis, GraphQL Armor.

## Auth-specific rate limiting

Login, password reset, signup, and MFA endpoints need aggressive limits with specific properties:

```ts
// Per-IP: stop credential stuffing
// Per-account: stop bruteforce on a specific username
const loginLimits = {
  perIp: { capacity: 10, refill: 10 / 600 },         // 10 per 10 minutes
  perAccount: { capacity: 5, refill: 5 / 900 },       // 5 per 15 minutes
};
```

The per-account counter increments on failed attempts but does NOT increment on successful login (else legitimate logins lock out shared accounts).

After a threshold, escalate:
- Trigger CAPTCHA
- Lock account with email notification
- Add to slow-response cohort (artificial 2-5 sec delay)

## DDoS considerations

App-layer rate limiting doesn't protect against volumetric DDoS — by the time the request hits your app, the bandwidth cost has been paid. For that:

- CDN with DDoS mitigation (Cloudflare, AWS Shield, GCP Cloud Armor).
- Anycast at the edge.
- Rate limit at the edge based on TLS fingerprint, ASN, country if needed.
- Challenge ramp (JS challenge → CAPTCHA → block) at the edge.

## Tenant fairness

In a multi-tenant system, a single tenant should not be able to monopolize shared capacity. Solutions:

- **Per-tenant quota**: hard cap on requests/sec per tenant.
- **Weighted fair queue**: requests from heavy tenants queue, others bypass.
- **Burst credit**: small bonus tokens for occasional bursts beyond steady-state.

Pricing tiers can also map to rate limits (free: 10/min; pro: 100/min; enterprise: custom).

## Observability

Per-bucket metrics worth tracking:

- Allow rate vs deny rate per dimension (IP, tenant, key)
- Top-N consumers per dimension (who's near limit)
- 429 rate over time
- Endpoint cost distribution

Alerts:
- A new tenant rapidly approaching their tier limit (could be onboarding success or abuse).
- A spike in 429s on auth endpoints (potential credential stuffing).
- Per-IP 429 from many different IPs hitting the same account (distributed credential stuffing).

## Audit checklist

1. Every public endpoint has a limit somewhere (edge, gateway, or app).
2. Auth endpoints have aggressive per-IP and per-account limits.
3. Per-tenant limits exist for B2B SaaS.
4. Algorithm uses Redis or equivalent atomic store (no in-process counters that don't scale across replicas).
5. Cost-based limiting on expensive endpoints (GraphQL, export, search).
6. Response includes RateLimit headers and 429 with Retry-After.
7. Limits configurable per pricing tier.
8. Observability in place; alerts on abnormal rates.
9. DDoS protection at the edge.
