---
name: saas-api-security
description: Audit SaaS API surface security including rate limiting, CORS configuration, webhook signature verification, GraphQL query depth/complexity, REST API best practices, idempotency keys, request signing, and API key management. Use this skill whenever the user asks about rate limiting, CORS, webhook security, HMAC signatures, GraphQL security, API abuse, throttling, idempotency, replay protection, or "is my API safe". Trigger on phrases like "audit my API", "review my CORS", "webhook security", "rate limit", "GraphQL depth attack", "API abuse", "signature verification". Use this even when only one API surface is mentioned.
---

# SaaS API Security Audit

Audit the API surface of a SaaS — the endpoints exposed to customers, their integrations, and (when applicable) the public internet. Defensive focus.

## When this skill applies

- Reviewing CORS configuration on web APIs
- Auditing rate limiting strategy (per-key, per-IP, per-tenant, global)
- Verifying webhook signature implementation (Stripe, GitHub, custom HMAC)
- Reviewing GraphQL query cost / depth limits
- Reviewing idempotency keys on write endpoints
- Auditing API key management (generation, storage, rotation, revocation)

Use other skills for: code-level vulnerabilities (`saas-code-security-review`), tenant isolation in queries (`saas-tenant-isolation`), Supabase-specific edge function auth (`supabase-security-audit`).

## Workflow

Follow `../_shared/audit-workflow.md`. API-specific notes below.

### Phase 1: Scope confirmation

- Public API or internal-only?
- REST, GraphQL, gRPC, WebSocket, or mix?
- Auth mechanisms (API keys, JWT, OAuth, mTLS)?
- Gateway in front (Cloudflare, Kong, AWS API Gateway, Apigee)?
- Customer-facing webhooks outbound, inbound, both?

### Phase 2: Inventory

- List all endpoints / GraphQL resolvers / WebSocket events.
- List rate-limit configurations (gateway + application layer).
- List CORS configurations per route or group.
- List webhook endpoints (inbound) and webhook destinations (outbound).
- List API key types (admin, scoped, ephemeral) and their issuance flow.

### Phase 3: Detection — the checks

#### Rate limiting — see `references/rate-limiting.md`

- **SAPI-RL-1** Every public endpoint has a rate limit (gateway or app layer).
- **SAPI-RL-2** Auth endpoints (login, password reset, signup) have aggressive limits per IP AND per account.
- **SAPI-RL-3** Rate limits are per-tenant on data endpoints — one tenant can't exhaust the global limit.
- **SAPI-RL-4** Rate limit responses use 429 with `Retry-After` header.
- **SAPI-RL-5** Internal services have their own limits (a buggy internal service shouldn't take down the whole gateway).
- **SAPI-RL-6** Cost-based limiting on expensive endpoints (exports, search, batch operations) — not just request count.
- **SAPI-RL-7** Limits scoped by API key, not just IP (one customer behind one IP shouldn't share a limit with others).

#### CORS — see `references/cors-patterns.md`

- **SAPI-CORS-1** `Access-Control-Allow-Origin` uses an explicit allowlist, not `*`, on endpoints that return user data.
- **SAPI-CORS-2** No origin reflection without validation (`Allow-Origin: <whatever was in Origin header>`).
- **SAPI-CORS-3** `Access-Control-Allow-Credentials: true` only when needed and never with `Allow-Origin: *`.
- **SAPI-CORS-4** Preflight responses (OPTIONS) cached with reasonable `Access-Control-Max-Age`.
- **SAPI-CORS-5** Methods and headers allowlisted precisely, not `*`.
- **SAPI-CORS-6** Wildcard subdomain patterns (`*.example.com`) verified — easy to mis-implement and reflect attacker.example.com.attacker.com.

#### Webhook security — see `references/webhook-security.md`

For **inbound** webhooks (your endpoints receiving from Stripe, GitHub, etc.):
- **SAPI-WH-IN-1** Signature verified using provider's library (Stripe SDK, GitHub HMAC).
- **SAPI-WH-IN-2** Raw body used for signature verification, not parsed JSON.
- **SAPI-WH-IN-3** Timestamp checked; events older than 5-15 min rejected (replay protection).
- **SAPI-WH-IN-4** Idempotency: handler tolerates duplicate delivery without double-processing.
- **SAPI-WH-IN-5** Webhook secret stored as a secret, not in code.
- **SAPI-WH-IN-6** Secret rotated after suspected exposure or every 12 months.

For **outbound** webhooks (your service notifying customers):
- **SAPI-WH-OUT-1** Sign the payload (HMAC-SHA256 with per-customer secret) and include `X-Webhook-Signature` header.
- **SAPI-WH-OUT-2** Include a timestamp in the signed payload; customer can reject stale events.
- **SAPI-WH-OUT-3** URL validation at config time and delivery time — SSRF protection.
- **SAPI-WH-OUT-4** Retry with exponential backoff; cap total attempts.
- **SAPI-WH-OUT-5** Customer can rotate their secret without losing in-flight events.

#### GraphQL specifics

- **SAPI-GQL-1** Query depth limit (typical: 10).
- **SAPI-GQL-2** Query complexity / cost limit (preferred over depth alone).
- **SAPI-GQL-3** Field-level rate limits on expensive resolvers.
- **SAPI-GQL-4** Disable introspection in production OR allowlist clients that can introspect.
- **SAPI-GQL-5** Aliases counted toward complexity (else `a: thing b: thing c: thing ...` is unbounded).
- **SAPI-GQL-6** Persisted queries used where clients are first-party — eliminates the entire arbitrary-query attack surface.
- **SAPI-GQL-7** Authorization checked per field, not just per root query. See `saas-code-security-review/references/idor-bola-patterns.md`.

#### REST specifics

- **SAPI-REST-1** Methods restricted (GET / POST / PUT / DELETE / PATCH) — no TRACE, no CONNECT, no random methods.
- **SAPI-REST-2** Idempotency keys supported on POST endpoints with side effects (`Idempotency-Key` header).
- **SAPI-REST-3** Strict content-type checking on POST/PUT (`application/json`; reject `text/plain` injection vectors).
- **SAPI-REST-4** Pagination caps maximum page size to prevent enumeration of entire dataset in one call.
- **SAPI-REST-5** Field filtering / sparse fieldsets validated to prevent over-fetching internal columns.

#### API key management — see `references/api-key-management.md`

- **SAPI-AK-1** Keys generated with CSPRNG, ≥ 256 bits of entropy.
- **SAPI-AK-2** Keys prefixed with a recognizable identifier (`sk_live_`, `cb_test_`) for secret scanning.
- **SAPI-AK-3** Keys hashed server-side (HMAC or hash) at rest — never stored in plaintext.
- **SAPI-AK-4** Keys can be scoped to specific permissions (least privilege).
- **SAPI-AK-5** Keys have last-used timestamps and inactive keys are flagged.
- **SAPI-AK-6** Key revocation is immediate (no caching delays).
- **SAPI-AK-7** Test/sandbox keys can't be used against production resources.

#### Authentication & session

- **SAPI-AUTH-1** Bearer tokens validated on every request (no session caching that misses revocation).
- **SAPI-AUTH-2** OAuth flows use PKCE for public clients.
- **SAPI-AUTH-3** Refresh tokens rotate on use; reuse triggers session-family revocation.
- **SAPI-AUTH-4** Cookie-based session: SameSite=Lax (or Strict), Secure, HttpOnly.

#### Response hygiene

- **SAPI-RESP-1** No internal server details in error responses (stack traces, DB schema names, file paths).
- **SAPI-RESP-2** Consistent error format; 401/403/404 don't leak existence vs permission.
- **SAPI-RESP-3** Sensitive fields (password hashes, internal IDs) not in any API response, even by accident in admin endpoints.
- **SAPI-RESP-4** Pagination cursors are opaque (signed/encrypted) if they encode sensitive state.

### Phase 4: Triage

Critical class examples:
- No rate limiting on auth endpoints
- Webhook signature verification missing or broken (replay possible)
- CORS reflects any origin with credentials
- GraphQL with no depth/cost limit + introspection enabled
- API keys stored in plaintext in the database

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `SAPI-`.

## References

- `references/rate-limiting.md` — Strategies (token bucket, sliding window), gateway vs app layer, per-tenant quotas
- `references/cors-patterns.md` — Allowlist patterns, credentials gotchas, subdomain wildcards
- `references/webhook-security.md` — HMAC patterns, replay protection, idempotency
- `references/api-key-management.md` — Generation, storage, scoping, rotation
