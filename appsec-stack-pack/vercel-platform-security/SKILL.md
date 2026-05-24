---
name: vercel-platform-security
description: Security audit for applications deployed on Vercel covering environment variable scoping (Production/Preview/Development), Deployment Protection, Edge Config secrets, Vercel Cron auth, Image Optimization SSRF, custom headers via vercel.json, branch/deployment URL exposure, and Vercel-specific platform concerns. Use this skill whenever the user mentions Vercel, vercel.json, vercel deploy, Edge Config, Vercel Cron, Deployment Protection, preview deployments, or asks "audit my Vercel deployment", "Vercel security review". Trigger when the codebase contains `vercel.json`, `.vercel/`, or Vercel is the deployment target.
---

# Vercel Platform Security Audit

Audit the Vercel deployment configuration. Application-level concerns covered in framework skills; this skill is about Vercel-specific surface.

## When this skill applies

- Reviewing `vercel.json` configuration
- Auditing environment variable scoping across Production / Preview / Development
- Reviewing Deployment Protection settings
- Checking Vercel Cron and webhook setups
- Auditing Edge Config and Edge Network usage

## Workflow

Follow `../_shared/audit-workflow.md`.

### Phase 1: Stack detection

```bash
ls vercel.json .vercel/ 2>/dev/null
# Vercel CLI
vercel --version 2>/dev/null
```

### Phase 2: Inventory

```bash
cat vercel.json 2>/dev/null
ls -la .env* 2>/dev/null
# Cron config
grep -nE 'crons:' vercel.json 2>/dev/null
```

### Phase 3: Detection — the checks

#### Environment variables

Vercel scopes env vars to Production / Preview / Development.

- **VRC-ENV-1** Production secrets NOT replicated to Preview. Preview deployments are accessible to anyone with the URL (unless Deployment Protection is on); preview env having production DB credentials = breach.
- **VRC-ENV-2** Preview deployments either use a separate (preview) database OR have access controls that prevent leaking.
- **VRC-ENV-3** Sensitive variables marked "Sensitive" in Vercel UI (mask the value from team members without specific perms).
- **VRC-ENV-4** Variables prefixed `NEXT_PUBLIC_` / `VITE_` / etc. truly public — see framework-specific skills.
- **VRC-ENV-5** No env vars in `vercel.json` (they get committed). Use the dashboard or `vercel env`.

#### Deployment Protection

By default, Vercel makes every preview URL public. For private apps, this is data exposure.

- **VRC-DP-1** Deployment Protection enabled for Preview deployments. Options:
  - **Standard Protection**: only team members can access preview URLs (recommended).
  - **Password Protection**: shared password (lower-friction sharing with non-team).
  - **Vercel Authentication**: SSO via Vercel.
- **VRC-DP-2** Production also protected for staff-only apps (admin dashboards, internal tools).
- **VRC-DP-3** Trusted IPs / bypass tokens reviewed; not shared widely.
- **VRC-DP-4** OPTIONS preflight allowed through protection so APIs work cross-origin from protected URLs.

#### Branch / deployment URLs

- **VRC-URL-1** Branch URLs (`<project>-git-<branch>-<team>.vercel.app`) and commit URLs known to leak in PRs, logs, monitoring. Treat all as semi-public.
- **VRC-URL-2** Custom domains for production; alias-only deployments not used for sensitive data.
- **VRC-URL-3** robots.txt prevents indexing of preview URLs (Vercel default does this; verify if customized).

#### `vercel.json` configuration

Headers, rewrites, redirects, cron all live here:

- **VRC-CFG-1** Custom headers (CSP, HSTS, etc.) defined in `headers` section for static assets that aren't handled by the framework's middleware:
  ```json
  {
    "headers": [
      { "source": "/(.*)",
        "headers": [
          { "key": "Strict-Transport-Security", "value": "max-age=63072000; includeSubDomains; preload" },
          { "key": "X-Content-Type-Options", "value": "nosniff" }
        ]
      }
    ]
  }
  ```
- **VRC-CFG-2** Rewrites don't accept user-controllable destinations (open redirect class via rewrite source patterns).
- **VRC-CFG-3** Redirects with `source: "/(.*)/"` patterns vetted.

#### Vercel Cron

```json
{
  "crons": [{
    "path": "/api/cron/cleanup",
    "schedule": "0 0 * * *"
  }]
}
```

- **VRC-CR-1** Cron endpoints verify the request comes from Vercel — use `Authorization: Bearer ${CRON_SECRET}` header. Vercel sends this when you set the `CRON_SECRET` env var.
- **VRC-CR-2** Without CRON_SECRET, ANY HTTP request to `/api/cron/cleanup` would trigger the job — attacker can run it arbitrarily.
- **VRC-CR-3** Cron endpoints idempotent; multiple invocations don't double-process.

```ts
// app/api/cron/cleanup/route.ts
export const GET = async (req: Request) => {
  if (req.headers.get('authorization') !== `Bearer ${process.env.CRON_SECRET}`) {
    return new Response('Unauthorized', { status: 401 });
  }
  // ... job
};
```

#### Edge Config

Edge Config is a fast read-only store. Treat data as semi-public (low-sensitivity).

- **VRC-EC-1** Edge Config token (`EDGE_CONFIG`) is a secret — keep server-only.
- **VRC-EC-2** Data in Edge Config is feature flags, configuration — not secrets or per-user data.
- **VRC-EC-3** Writes to Edge Config go through Vercel API with separate auth; not exposed to runtime code.

#### Image Optimization (next/image, etc.)

- **VRC-IMG-1** `images.remotePatterns` (Next.js) specific; see `nextjs-security`.
- **VRC-IMG-2** Vercel's edge image service blocks RFC1918 IPs for SSRF; verified by default.

#### Functions runtime

- **VRC-FN-1** Serverless Functions: cold-start state not leaking across invocations (don't write per-request data to module-level variables).
- **VRC-FN-2** Edge Functions: secrets accessed via `process.env` are bound at deploy time. Don't compute secrets dynamically based on user input.
- **VRC-FN-3** Function regions appropriate for data residency requirements.

#### Logs

- **VRC-LOG-1** Vercel Log Drains configured for production observability; logs centralized.
- **VRC-LOG-2** Logs don't include full request bodies with PII / secrets — sanitize before logging.
- **VRC-LOG-3** Vercel's default log retention is short; long-term storage configured separately.

#### Webhooks

- **VRC-WH-1** Vercel deployment webhooks (sent to your endpoints on deploy events) verified via signature.
- **VRC-WH-2** GitHub / GitLab integration webhooks (used internally by Vercel) — verify the GitHub App permissions if you've adjusted defaults.

#### Project membership

- **VRC-PM-1** Vercel team access reviewed periodically. Stale developer access removed.
- **VRC-PM-2** Production deployment permissions limited (require approval).
- **VRC-PM-3** Integrations (Slack, GitHub, etc.) scope minimized.

#### Custom domains and DNS

- **VRC-DNS-1** Custom domain SSL auto-renewed.
- **VRC-DNS-2** DNS records use CNAME to Vercel; not direct A records that lock the domain to a specific IP (less flexible).
- **VRC-DNS-3** Subdomain takeover risk: removed projects with custom subdomain pointers cleaned up.

#### Build configuration

- **VRC-BLD-1** Build command and install command match local; no overrides allowing arbitrary commands.
- **VRC-BLD-2** Build cache scope appropriate; don't share build cache across unrelated projects.
- **VRC-BLD-3** Environment variables exposed during build (vs runtime) reviewed — build-time vars baked into static assets are effectively public.

#### Analytics and Speed Insights

- **VRC-AN-1** Vercel Analytics enabled doesn't conflict with privacy regulations (GDPR consent flow, etc.).
- **VRC-AN-2** Speed Insights script (`@vercel/speed-insights`) doesn't capture sensitive URL paths in metrics.

### Phase 4: Triage

Critical: production secrets in Preview env; Cron endpoint without CRON_SECRET check; Deployment Protection off for sensitive Preview URLs.

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `VRC-`.
