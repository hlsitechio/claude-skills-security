---
name: nextauth-security
description: Security audit for NextAuth.js / Auth.js applications including provider configuration, JWT vs database session strategy, callback safety (jwt, session, signIn, redirect), CSRF, NEXTAUTH_SECRET handling, OAuth client secrets, custom adapters, and Auth.js-specific patterns. Use this skill whenever the user mentions NextAuth, NextAuth.js, Auth.js, next-auth, @auth/core, authjs, NEXTAUTH_SECRET, [...nextauth].ts, providers, callbacks, signIn/signOut, or asks "audit my NextAuth setup", "Auth.js security review". Trigger when the codebase contains `next-auth` or `@auth/*` packages.
---

# NextAuth.js / Auth.js Security Audit

Audit applications using NextAuth.js (now Auth.js). Covers v4 (next-auth) and v5 (Auth.js).

## When this skill applies

- Reviewing the auth configuration object (providers, callbacks, pages)
- Auditing JWT vs database session setup
- Reviewing callbacks for safety (jwt, session, signIn, redirect)
- Checking OAuth client credentials and provider config
- Auditing custom adapters

## Workflow

Follow `../_shared/audit-workflow.md`. Companion: `nextjs-security` for Next-specific concerns.

### Phase 1: Stack detection

```bash
grep -E '"(next-auth|@auth/.+)":' package.json
# Find the auth config file
find . -path '*/api/auth/[*nextauth*].ts*' 2>/dev/null
find . -name 'auth.ts' -o -name 'auth.config.ts' 2>/dev/null | head
```

Detect: v4 (`next-auth`) vs v5 (`@auth/*` modular). API differs.

### Phase 2: Inventory

```bash
# Auth config
cat src/auth.ts auth.config.ts app/api/auth/\[...nextauth\]/route.ts 2>/dev/null

# Callbacks
grep -rn 'callbacks:\|async jwt\|async session\|async signIn\|async redirect' . --include='*.ts' --include='*.js'

# Providers
grep -rn 'GoogleProvider\|GitHubProvider\|CredentialsProvider\|EmailProvider' .

# Env vars
grep -E '^NEXTAUTH_|^AUTH_' .env* 2>/dev/null
```

### Phase 3: Detection — the checks

#### Environment / secrets

- **NXA-SEC-1** `NEXTAUTH_SECRET` (v4) or `AUTH_SECRET` (v5) set — required for JWT signing and cookie encryption. Generate with `openssl rand -base64 32`.
- **NXA-SEC-2** `NEXTAUTH_URL` (v4) set in production to actual URL — without it, callback redirects break or behave unexpectedly.
- **NXA-SEC-3** OAuth client secrets (`GITHUB_SECRET`, `GOOGLE_CLIENT_SECRET`, etc.) in env, never committed.
- **NXA-SEC-4** Production and dev clients separate (different OAuth apps with different secrets, different callback URLs).

#### Session strategy

- **NXA-SS-1** Strategy explicitly set (`session: { strategy: 'jwt' }` or `'database'`). Default behavior changes between versions.
- **NXA-SS-2** JWT strategy: sessions are stateless; logout doesn't immediately invalidate tokens (token lifetime trade-off). Acceptable for most apps; not for high-sensitivity (banking, admin tools) where revocation matters.
- **NXA-SS-3** Database strategy: session row deleted on signOut; revocation works immediately.
- **NXA-SS-4** `maxAge` reasonable (default 30 days; reduce for sensitive apps).

#### Callbacks — `jwt`

```ts
callbacks: {
  async jwt({ token, user, account, profile }) {
    if (user) {
      token.id = user.id;
      token.role = user.role;
    }
    return token;
  },
}
```

- **NXA-CB-JWT-1** Initial sign-in copies safe claims to token. Don't store secrets (refresh tokens may be stored but encrypted by NextAuth in v4 / handled in v5).
- **NXA-CB-JWT-2** Token NOT used to store mutable user state — DB lookups in subsequent requests for role changes.
- **NXA-CB-JWT-3** Returning data unaltered when no refresh needed.

#### Callbacks — `session`

```ts
async session({ session, token }) {
  session.user.id = token.id;
  session.user.role = token.role;
  return session;
}
```

- **NXA-CB-SES-1** Session callback projects safe fields. Don't expose raw `token` to the client — `session` is what the browser sees via `useSession()`.
- **NXA-CB-SES-2** Sensitive fields (e.g., `accessToken` for downstream API calls) included only if the client truly needs them. Better: client uses cookie session, server makes downstream calls with stored token.

#### Callbacks — `signIn`

```ts
async signIn({ user, account, profile, credentials }) {
  // Run checks before allowing sign-in
  if (account.provider === 'github' && !profile.email_verified) return false;
  if (!isAllowedEmail(user.email)) return false;
  return true;
}
```

- **NXA-CB-SIG-1** signIn callback used to reject specific accounts (banned users, unallowed email domains).
- **NXA-CB-SIG-2** Don't return `true` unconditionally for security-sensitive apps that should restrict sign-ups.
- **NXA-CB-SIG-3** Email-based signups verify `profile.email_verified` (some providers don't verify).

#### Callbacks — `redirect`

```ts
async redirect({ url, baseUrl }) {
  // Default behavior is to only allow relative URLs or same-origin
  if (url.startsWith('/')) return `${baseUrl}${url}`;
  if (new URL(url).origin === baseUrl) return url;
  return baseUrl;
}
```

- **NXA-CB-RED-1** redirect callback returns to base URL or relative paths only. Without the callback, default allows same-origin only — fine. But custom callbacks must preserve the restriction; common bug returns `url` unchanged → open redirect.

#### Providers

- **NXA-PR-CRD-1** `CredentialsProvider` (username/password) — authorize function uses constant-time password comparison (`bcrypt.compare`), not string equality.
- **NXA-PR-CRD-2** `CredentialsProvider` returns `null` on failed auth — never throws with sensitive details that propagate to client.
- **NXA-PR-CRD-3** Email enumeration: same response time for "user doesn't exist" vs "wrong password". Adding a sleep or always running bcrypt comparison helps.

- **NXA-PR-OAUTH-1** OAuth providers configured with `prompt: 'consent'` for sensitive permissions (forces re-consent).
- **NXA-PR-OAUTH-2** Scopes minimized — request only what's needed.
- **NXA-PR-OAUTH-3** Provider-specific gotchas: GitHub requires explicit `email` scope; Google's `prompt: 'consent'` to refresh tokens.

- **NXA-PR-EML-1** EmailProvider (magic link): SMTP credentials in env. Email content uses templates that don't reveal user data.
- **NXA-PR-EML-2** Magic link tokens have short TTL (10-15 min); single-use enforced.

#### Pages

- **NXA-PG-1** Custom sign-in page (if defined) preserves CSRF token and uses Auth.js's API correctly.
- **NXA-PG-2** Custom error pages don't echo back arbitrary query parameters (XSS risk).

#### CSRF

- **NXA-CSRF-1** NextAuth applies CSRF protection on credential sign-in (double-submit cookie). Verify not disabled.
- **NXA-CSRF-2** Custom routes that act as sign-in pages include `csrfToken` from `getCsrfToken()` (v4) or equivalent (v5).

#### Database adapter

If using a database adapter (Prisma, Drizzle, etc.):

- **NXA-ADP-1** Adapter's tables (`User`, `Account`, `Session`, `VerificationToken`) protected by RLS or app-level scoping. No raw user list endpoint shipping these tables.
- **NXA-ADP-2** Adapter version matches NextAuth/Auth.js version.

#### Cookie configuration

- **NXA-CK-1** Cookie config sets `secure: true, httpOnly: true, sameSite: 'lax'`. Defaults are usually right; verify not overridden.
- **NXA-CK-2** Production deployment serves over HTTPS so the `secure` flag is effective.

#### Webhook / event handlers

If using `events: { signIn, signOut, ... }`:

- **NXA-EV-1** Event handlers don't throw errors that interrupt the auth flow — wrap in try/catch.
- **NXA-EV-2** Event handlers don't perform synchronous I/O that delays auth response.

#### Client-side patterns

- **NXA-CL-1** `useSession()` calls in components don't leak session data to third parties.
- **NXA-CL-2** Server-side `getServerSession()` used in Server Components / API routes; not relying on client session for security.

#### Dependencies

- **NXA-DEP-1** NextAuth v4 (next-auth) or Auth.js v5 (@auth/* packages). v5 is current.
- **NXA-DEP-2** Adapter version matches NextAuth major.

### Phase 4: Triage

Critical: `NEXTAUTH_SECRET` empty / default; redirect callback returning unchecked `url`; CredentialsProvider with string equality on password; OAuth client secret committed.

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `NXA-`.
