---
name: clerk-security
description: Security audit for applications using Clerk authentication including session management, webhook signature verification, JWT template configuration, organization/role setup, publishable vs secret keys, allowed origins/redirect URLs, custom session claims, and Clerk-specific patterns. Use this skill whenever the user mentions Clerk, @clerk/nextjs, @clerk/clerk-sdk-node, ClerkProvider, useUser, useAuth, clerkClient, Clerk webhooks, svix, or asks "audit my Clerk setup", "Clerk security", "is my Clerk webhook safe". Trigger when the codebase contains `@clerk/*` packages or `CLERK_*` environment variables.
---

# Clerk Authentication Security Audit

Audit a Clerk-powered application for misconfigurations and integration vulnerabilities. Clerk handles the heavy auth lifting; the security surface is mostly integration.

## When this skill applies

- Reviewing Clerk middleware and route protection
- Auditing Clerk webhook handlers
- Reviewing publishable vs secret key handling
- Checking organization / role configuration
- Auditing custom session claims and JWT templates

## Workflow

Follow `../_shared/audit-workflow.md`.

### Phase 1: Stack detection

```bash
grep -E '"@clerk/' package.json
# Look for SDK
grep -E '"(@clerk/nextjs|@clerk/clerk-sdk-node|@clerk/backend|@clerk/clerk-react|@clerk/clerk-expo)":' package.json
```

### Phase 2: Inventory

```bash
# Middleware (Next.js)
find . -name 'middleware.ts' -o -name 'middleware.js' | xargs grep -l 'clerk' 2>/dev/null

# Server-side calls
grep -rn 'clerkClient\|auth()\|currentUser()\|getAuth(' src/ app/ | head

# Webhook handlers
grep -rn 'svix\|verifyWebhook\|WebhookEvent' src/ app/ | head

# Env vars
grep -rn 'CLERK_' .env* 2>/dev/null
```

### Phase 3: Detection — the checks

#### Key handling

Clerk has multiple keys:
- `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` (or equivalent) — public, ships to client. Safe.
- `CLERK_SECRET_KEY` — server-only. Never in `NEXT_PUBLIC_` / `VITE_` / similar prefix.
- `CLERK_WEBHOOK_SECRET` (svix-style) — server-only. Used to verify webhooks.

- **CLK-KEY-1** Secret key NOT prefixed with `NEXT_PUBLIC_` / `VITE_`. Build inspection clean.
- **CLK-KEY-2** Secret key sourced from secrets manager / env, not committed.
- **CLK-KEY-3** Test keys and production keys not interchanged across environments (`pk_test_` vs `pk_live_`).

#### Middleware / route protection

For Next.js with `@clerk/nextjs`:

- **CLK-MW-1** `clerkMiddleware()` (v5+) or `authMiddleware()` (older) configured in `middleware.ts`.
- **CLK-MW-2** Public routes explicitly listed; everything else protected.
  ```ts
  import { clerkMiddleware, createRouteMatcher } from '@clerk/nextjs/server';
  
  const isPublicRoute = createRouteMatcher([
    '/', '/sign-in(.*)', '/sign-up(.*)', '/api/webhooks/(.*)',
  ]);
  
  export default clerkMiddleware((auth, req) => {
    if (!isPublicRoute(req)) auth().protect();
  });
  ```
- **CLK-MW-3** Webhook routes in public matcher (Clerk's middleware shouldn't gate them; they have their own auth via signature).
- **CLK-MW-4** Server Actions / Route Handlers still check `auth()` themselves — middleware is not the only line of defense.

#### Server-side auth checks

- **CLK-SS-1** `auth()` called in server-side code (Server Component, Route Handler, Server Action) for ANY operation needing user identity.
- **CLK-SS-2** `userId` from `auth()` used to scope DB queries — never trust IDs from request body.
- **CLK-SS-3** `currentUser()` calls minimized (it fetches from Clerk API); use `auth()` for ID-only needs.

```ts
// app/api/posts/route.ts
import { auth } from '@clerk/nextjs/server';

export async function POST(req: Request) {
  const { userId } = auth();
  if (!userId) return new Response('Unauthorized', { status: 401 });
  
  const data = await req.json();
  // Use userId from auth(), NOT from data
  return db.posts.create({ ...data, authorId: userId });
}
```

#### Webhook signature verification

Clerk sends webhooks via Svix. Verification is mandatory.

- **CLK-WH-1** Webhook handler verifies the `svix-id`, `svix-timestamp`, `svix-signature` headers using `CLERK_WEBHOOK_SECRET`.
  ```ts
  import { Webhook } from 'svix';
  
  const wh = new Webhook(process.env.CLERK_WEBHOOK_SECRET!);
  const evt = wh.verify(payload, headers) as WebhookEvent;  // throws on invalid
  ```
- **CLK-WH-2** Raw body used for verification (not parsed JSON). In Next.js App Router, `await req.text()`; in Express, use `express.raw()` middleware for the webhook route.
- **CLK-WH-3** Webhook handler is idempotent — replays don't double-process.
- **CLK-WH-4** Webhook secret rotation procedure documented.

#### Organizations / roles

- **CLK-ORG-1** If using Organizations: role checks via `has({ role: 'org:admin' })` not via string comparison on claims.
  ```ts
  const { has } = auth();
  if (!has({ role: 'org:admin' })) return Response('Forbidden', { status: 403 });
  ```
- **CLK-ORG-2** Custom roles defined in Clerk Dashboard, not invented client-side.
- **CLK-ORG-3** Per-resource authz still done — role check alone doesn't verify "this user owns this resource".

#### Custom session claims / JWT templates

Clerk allows JWT templates that add claims. Used when handing tokens to other services.

- **CLK-JWT-1** Tokens issued for external services have appropriate `aud` (audience) and limited TTL.
- **CLK-JWT-2** External service verifies tokens against Clerk's JWKS endpoint, validates `iss` (issuer) and `aud`.
- **CLK-JWT-3** Custom claims don't expose internal/sensitive data — they ship to whatever service consumes the token.
- **CLK-JWT-4** Networkless verification with `authorizedParties` set on `@clerk/backend` `verifyToken`.

#### Allowed origins / redirect URLs

In Clerk Dashboard:

- **CLK-CFG-1** Allowed origins listed are production + staging; no `*` or test domains in production.
- **CLK-CFG-2** OAuth redirect URLs specific.
- **CLK-CFG-3** Sign-in / sign-up redirect URLs validated — no open-redirect via `redirect_url` query param exploitation.

#### Client-side `useUser` / `useAuth`

- **CLK-CL-1** Client-side checks are UX, not security. Backend still enforces.
- **CLK-CL-2** Sensitive UI hidden from non-admins via `useUser()` but server enforces too.
- **CLK-CL-3** Tokens from `getToken()` not stored in localStorage; pass directly to API calls.

#### Multi-session and impersonation

- **CLK-MS-1** If Clerk's "impersonation" feature is used (admin signs in as user), audit logs capture the impersonator.
- **CLK-MS-2** Multi-session enabled only if needed; if not, restrict to single session.

#### Password and 2FA policy

- **CLK-PW-1** Password policy in Clerk Dashboard set to reasonable minimums.
- **CLK-PW-2** MFA available; required for admin roles.
- **CLK-PW-3** Magic link / SMS / OAuth providers reviewed; enable only what's needed.

#### Session lifetime

- **CLK-SES-1** Session lifetime configured in Clerk Dashboard for the sensitivity of the app.
- **CLK-SES-2** Idle timeout configured.

#### Logging

- **CLK-LOG-1** Don't log full JWT tokens or session tokens server-side.
- **CLK-LOG-2** `userId` logged in app logs for traceability (not PII unless user emails are PII-relevant in your context).

#### Dependencies

- **CLK-DEP-1** Clerk SDK versions current; v5+ for Next.js App Router; SDK majors aligned across packages.

### Phase 4: Triage

Critical: `CLERK_SECRET_KEY` exposed in client bundle; webhook handler skipping signature verification; `auth().protect()` missing from sensitive routes; allowed origins includes `*`.

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `CLK-`.
