---
name: cloudflare-workers-security
description: Security audit for Cloudflare Workers applications covering bindings (KV, D1, R2, Durable Objects, Queues, Vectorize), secrets vs vars in wrangler.toml, Worker routes and zones, request origin validation, CORS, mTLS to origin, Smart Placement, and Workers-specific runtime concerns. Use this skill whenever the user mentions Cloudflare Workers, wrangler, wrangler.toml, KVNamespace, D1Database, R2Bucket, DurableObjectNamespace, Env bindings, c.env, env.MY_KV, or asks "audit my Cloudflare Worker", "Workers security review", "wrangler secrets". Trigger when the codebase contains `wrangler` or `@cloudflare/workers-types` in package.json.
---

# Cloudflare Workers Security Audit

Audit a Cloudflare Workers application. Workers run in V8 isolates with specific platform bindings — security surface is partly app code, partly Cloudflare configuration.

## When this skill applies

- Reviewing `wrangler.toml` / `wrangler.jsonc` config
- Auditing binding usage (KV, D1, R2, Durable Objects, Queues)
- Reviewing secret vs var declarations
- Checking Worker routes and zone configuration
- Auditing request handling for SSRF / data leakage

## Workflow

Follow `../_shared/audit-workflow.md`. Companion: framework skill (`hono-security`, `nextjs-security`) for code-level concerns.

### Phase 1: Stack detection

```bash
ls wrangler.toml wrangler.jsonc 2>/dev/null
cat wrangler.toml wrangler.jsonc 2>/dev/null
wrangler --version 2>/dev/null
```

### Phase 2: Inventory

```bash
# Bindings declared in wrangler.toml
grep -nE 'kv_namespaces|d1_databases|r2_buckets|durable_objects|queues|vars|secrets' wrangler.toml 2>/dev/null

# Binding usage in code
grep -rn 'env\.\|c\.env\.' src/

# Fetch calls (potential SSRF if URLs are user-controlled)
grep -rn 'fetch(' src/ | head
```

### Phase 3: Detection — the checks

#### Secrets vs vars

`wrangler.toml` `[vars]` section is committed and visible in the dashboard. Secrets go via `wrangler secret put`.

- **CFW-SEC-1** No production secrets in `[vars]`. Audit `wrangler.toml`:
  ```toml
  [vars]
  API_BASE_URL = "https://api.example.com"   # OK, public
  STRIPE_SECRET_KEY = "sk_live_..."           # NEVER — use secret
  ```
- **CFW-SEC-2** Secrets set via `wrangler secret put SECRET_NAME` (encrypted at rest, never displayed).
- **CFW-SEC-3** Different environments (`[env.production.vars]`, `[env.staging.vars]`) have appropriate scoping.
- **CFW-SEC-4** No secrets logged via `console.log(env.SECRET)`.

#### Bindings — KV

- **CFW-KV-1** KV namespaces are global across the Worker. Keys not namespaced by tenant → tenant collision risk.
  ```js
  // BAD
  await env.MY_KV.put(`session-${sessionId}`, data);
  
  // GOOD
  await env.MY_KV.put(`tenant:${tenantId}:session:${sessionId}`, data);
  ```
- **CFW-KV-2** Sensitive data in KV considered: KV is eventually-consistent, replicated globally; check data residency requirements.
- **CFW-KV-3** TTLs (`expirationTtl`) on session-like keys; without expiry, stale data accumulates.

#### Bindings — D1

- **CFW-D1-1** D1 (SQLite-based) — prepared statements parameterize values:
  ```js
  // GOOD
  await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
  
  // BAD
  await env.DB.exec(`SELECT * FROM users WHERE id = ${userId}`);
  ```
- **CFW-D1-2** Schema includes proper foreign keys and indexes; D1 supports them.
- **CFW-D1-3** D1 has size limits; queries returning large result sets handled with pagination.

#### Bindings — R2

- **CFW-R2-1** R2 buckets accessed via binding, not via public URL by default. Public access via Custom Domain or Public Bucket explicitly opted in.
- **CFW-R2-2** Worker-generated signed URLs for time-limited public access (rather than making the whole bucket public).
- **CFW-R2-3** Bucket lifecycle rules configured (object expiration for temporary data).
- **CFW-R2-4** Object naming includes tenant scope; cross-tenant key collision avoided.

#### Bindings — Durable Objects

- **CFW-DO-1** Durable Object IDs derived from server-side context (not from client-supplied IDs that could let a user reach another's DO).
- **CFW-DO-2** DO state migrations handled with versioning; corrupted state on schema change prevented.
- **CFW-DO-3** DO methods callable only via Worker — no direct external access.

#### Bindings — Queues, Vectorize

- **CFW-QU-1** Queue producers and consumers in separate Workers; no cross-tenant message contamination via shared queue.
- **CFW-VEC-1** Vectorize index access scoped — querying by user/tenant filter.

#### Service bindings

If using Service bindings (Worker A → Worker B):

- **CFW-SB-1** Internal Workers (called only via service binding) marked as such; not exposed via routes.
- **CFW-SB-2** Service-to-service auth: the calling Worker authenticates to the called Worker via signed request or shared secret in headers.

#### Routes / zones

- **CFW-RT-1** Worker route patterns specific (`example.com/api/*`), not wildcards that catch unrelated subdomains.
- **CFW-RT-2** `workers.dev` subdomain disabled for production Workers if you don't want it directly reachable.
- **CFW-RT-3** Per-environment routes (production vs staging) separated.

#### Headers and CORS

- **CFW-HDR-1** Security headers applied via Worker code (or `hono/secure-headers` middleware).
- **CFW-HDR-2** CORS allows specific origins; not `*` for credentialed APIs.

#### SSRF protection

```js
// BAD — user controls fetch target
async fetch(request, env) {
  const url = new URL(request.url);
  const target = url.searchParams.get('proxy');
  return fetch(target);
}
```

- **CFW-SSRF-1** Worker fetching URLs based on user input → SSRF risk. Workers can reach internal Cloudflare Tunnels and (depending on config) other private resources.
- **CFW-SSRF-2** Allowlist target hostnames; reject `internal.`, RFC1918, metadata endpoints.

#### Origin protection (mTLS)

If the Worker proxies to an origin server:

- **CFW-OR-1** Worker uses mTLS to origin via Cloudflare's certificate; origin requires the cert.
- **CFW-OR-2** Origin firewall allows only Cloudflare IPs.
- **CFW-OR-3** `cf-connecting-ip` header trusted (sent by CF); `x-forwarded-for` not (spoofable upstream).

#### Smart Placement

- **CFW-SP-1** If enabled, verify it doesn't move Workers to regions that violate data residency.

#### Logs and observability

- **CFW-LOG-1** Workers Logs / Logpush configured; sensitive data not logged.
- **CFW-LOG-2** Tail mode (`wrangler tail`) access limited; can expose request data live.

#### Rate limiting

- **CFW-RL-1** Cloudflare Rate Limiting rules at the zone level for known abuse vectors (login, signup endpoints).
- **CFW-RL-2** Worker-level rate limiting (`cf.rateLimit`) for granular per-IP / per-user limits.

#### `wrangler.toml` env tree

- **CFW-CFG-1** `[env.production]` and `[env.staging]` clearly separated; bindings don't cross.
- **CFW-CFG-2** `workers_dev = false` in production environment.
- **CFW-CFG-3** Account ID hardcoded in `wrangler.toml` not a secret but verifiable.

#### Local development

- **CFW-DEV-1** `.dev.vars` (local secrets) in `.gitignore`.
- **CFW-DEV-2** Wrangler dev mode (`wrangler dev`) on `127.0.0.1` only; not exposed to LAN/internet.

#### Workers AI / Workers KV / D1 specific CVEs

- **CFW-CVE-1** Wrangler version current — past versions had localdev permission issues.
- **CFW-CVE-2** `compatibility_date` set to a recent date so platform security improvements are picked up.

#### Auth on Worker endpoints

- **CFW-AUTH-1** Every Worker endpoint that should require auth checks JWT / session / API key.
- **CFW-AUTH-2** Cloudflare Access (Zero Trust) used in front of internal Workers when appropriate.

### Phase 4: Triage

Critical: secrets in `[vars]`; KV keys not tenant-scoped; D1 with raw SQL concatenation; SSRF via user-controlled fetch target.

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `CFW-`.
