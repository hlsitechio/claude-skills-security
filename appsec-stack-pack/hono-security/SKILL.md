---
name: hono-security
description: Security audit for Hono applications running on Cloudflare Workers, Bun, Deno, Node, or AWS Lambda — covering middleware setup, JWT helper safety, environment binding handling (c.env), CORS, secret management across runtimes, and Hono-specific patterns. Use this skill whenever the user mentions Hono, hono framework, c.req, c.json, c.env, Hono middleware, Hono on Cloudflare/Bun/Node, or asks "audit my Hono app", "Hono security". Trigger when the codebase contains `hono` in package.json.
---

# Hono Security Audit

Audit Hono apps. Hono is a small, fast framework targeting Workers/Bun/Deno/Node/Lambda — each runtime has its own security context.

## When this skill applies

- Reviewing Hono route handlers and middleware
- Auditing JWT and auth helpers
- Reviewing env bindings across runtimes
- Checking CORS, helmet-equivalent setup
- Confirming runtime-specific concerns (Workers, Lambda, etc.)

## Workflow

Follow `../_shared/audit-workflow.md`.

### Phase 1: Stack detection

```bash
grep -E '"hono":' package.json
grep -nE 'import.*hono' src/ | head -5
# Detect runtime
grep -E '"wrangler"|"@cloudflare/workers-types"' package.json && echo "Cloudflare Workers"
grep -E '"@types/bun"|"bun"' package.json && echo "Bun"
grep -E '"@types/aws-lambda"' package.json && echo "AWS Lambda"
```

### Phase 2: Inventory

```bash
# Routes and handlers
grep -rn 'app\.\(get\|post\|put\|delete\|use\)' src/ | head -50

# Middleware imports
grep -rn 'from .hono/(jwt|cors|csrf|secure-headers|logger|cache)' src/

# Env access
grep -rn 'c\.env\.' src/

# Variables (per-request context)
grep -rn 'c\.set\|c\.var' src/
```

### Phase 3: Detection — the checks

#### Middleware setup

- **HNO-MW-1** `secureHeaders()` middleware from `hono/secure-headers` applied — Hono's equivalent of helmet.
- **HNO-MW-2** `cors()` from `hono/cors` configured with specific `origin` allowlist, not `*` for credentialed requests.
- **HNO-MW-3** `logger()` middleware doesn't log sensitive headers/bodies.
- **HNO-MW-4** Order: secureHeaders → cors → auth → routes.

```ts
import { Hono } from 'hono';
import { secureHeaders } from 'hono/secure-headers';
import { cors } from 'hono/cors';
import { jwt } from 'hono/jwt';

const app = new Hono();

app.use('*', secureHeaders());
app.use('*', cors({
  origin: ['https://app.yourorg.com'],
  credentials: true,
}));

// Auth on /api/* except /api/auth/*
app.use('/api/*', async (c, next) => {
  if (c.req.path.startsWith('/api/auth/')) return next();
  return jwt({ secret: c.env.JWT_SECRET })(c, next);
});
```

#### JWT middleware

- **HNO-JWT-1** `c.env.JWT_SECRET` (or per-runtime equivalent) used, not hardcoded.
- **HNO-JWT-2** Algorithm specified (`alg: 'HS256'` or `'RS256'`); never `none`.
- **HNO-JWT-3** `c.get('jwtPayload')` accessed in downstream handlers; trust scoped to verified claims only.
- **HNO-JWT-4** Token expiry validated by the middleware (Hono's JWT helper does this by default; verify).

#### Environment bindings (Cloudflare Workers)

```ts
type Bindings = {
  JWT_SECRET: string;
  DATABASE_URL: string;
  KV: KVNamespace;
  R2: R2Bucket;
};

const app = new Hono<{ Bindings: Bindings }>();

app.get('/api/data', (c) => {
  const value = c.env.JWT_SECRET;   // ← typed; server-side only
});
```

- **HNO-ENV-1** Bindings types declared so `c.env.X` is type-checked.
- **HNO-ENV-2** Secrets bound via `wrangler secret put`, not in `wrangler.toml` plaintext.
- **HNO-ENV-3** See `cloudflare-workers-security` for binding-level concerns.

#### Validators

- **HNO-VAL-1** Input validated via `@hono/zod-validator` or similar:
  ```ts
  import { zValidator } from '@hono/zod-validator';
  import { z } from 'zod';
  
  const schema = z.object({ name: z.string().min(1).max(100), email: z.string().email() });
  
  app.post('/users', zValidator('json', schema), async (c) => {
    const data = c.req.valid('json');   // validated, typed
    // ...
  });
  ```
- **HNO-VAL-2** Path params and query strings also validated when used.

#### CSRF

- **HNO-CSRF-1** If cookies are used for auth: `csrf()` middleware from `hono/csrf` applied. Hono's CSRF protection uses origin check by default.
- **HNO-CSRF-2** For pure Bearer token APIs (no auth cookies), CSRF not needed.

#### Cookie handling

- **HNO-CK-1** Cookies set via `setCookie(c, name, value, { httpOnly: true, secure: true, sameSite: 'Lax' })` — secure defaults explicit.
- **HNO-CK-2** Cookie reading via Hono's `getCookie(c)` — handles parsing safely.

#### Error handling

- **HNO-ERR-1** `app.onError((err, c) => ...)` handler returns generic errors in production; logs detail server-side.
- **HNO-ERR-2** `app.notFound((c) => ...)` returns minimal info.

#### Runtime-specific

**Cloudflare Workers:**
- See `cloudflare-workers-security` for binding/KV/Durable Object concerns.

**Node:**
- See `nodejs-express-security` for body parser limits, prototype pollution, etc.
- Hono on Node uses `@hono/node-server` — confirm version current.

**Bun:**
- Bun runtime concerns: keep Bun version current; verify `bun.lockb` reflects intended packages.

**Lambda:**
- See `aws-lambda-security` for cold start, env, IAM concerns.

#### Dependencies

- **HNO-DEP-1** Hono version current (4.x line).
- **HNO-DEP-2** `@hono/*` companion packages match Hono major.

### Phase 4: Triage

Critical: missing auth on routes that should be protected; secrets in `wrangler.toml`; JWT verification accepting `none`; CORS open with credentials.

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `HNO-`.
