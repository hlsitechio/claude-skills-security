# Cookie Configuration Reference

Load this when auditing how the app sets cookies — especially session and auth cookies.

## The flags

| Flag | What it does | When to use |
|------|--------------|-------------|
| `HttpOnly` | Inaccessible to JavaScript | Always for session/auth cookies |
| `Secure` | Sent only over HTTPS | Always in production |
| `SameSite=Strict` | Sent only on same-site requests, never on cross-site (including top-level GET) | High-value sessions (banking-style) |
| `SameSite=Lax` | Sent on top-level GET to your site, blocked on most cross-site requests | Default for most app sessions |
| `SameSite=None` | Sent on all cross-site requests; requires `Secure` | Third-party embeds, OAuth callbacks needing it |
| `Path=/...` | Cookie only sent for paths matching | Scope cookies narrowly |
| `Domain=.example.com` | Cookie sent to all subdomains | Only when needed (SSO across subdomains) |
| `__Secure-` prefix | Browser refuses to set unless Secure flag is present | Defense-in-depth on Secure |
| `__Host-` prefix | Browser refuses unless: Secure, Path=/, no Domain | Strongest scoping; use for session cookies |
| `Max-Age` / `Expires` | Persist beyond session | Refresh tokens, "remember me" |

## Recommended session cookie config

```http
Set-Cookie: __Host-session=opaque-random-256-bit-value;
            HttpOnly;
            Secure;
            SameSite=Lax;
            Path=/;
            Max-Age=3600
```

Why each:
- `__Host-` prefix: browser enforces no Domain attribute, Path=/, Secure. Prevents subdomain takeover from setting your session cookie.
- `HttpOnly`: JS can't read it. XSS no longer steals sessions directly.
- `Secure`: never sent over HTTP. Network attacker on HTTP can't pick it up.
- `SameSite=Lax`: blocks most cross-site requests from sending the cookie. CSRF mitigated for most flows.
- `Path=/`: cookie applies to the whole app.
- `Max-Age=3600`: 1 hour. Refresh token (separately) for longer sessions.

## SameSite specifics

### SameSite=Lax default behavior

Since Chrome 80 (and others followed), cookies default to `SameSite=Lax` if not specified. Practical implications:

- Cross-origin POST/PUT/DELETE/PATCH requests do NOT send the cookie.
- Cross-origin iframes do NOT send the cookie.
- Top-level GET navigation TO your site DOES send the cookie (so users following an external link still get logged in).

For most apps, Lax is correct. CSRF is largely mitigated by Lax alone for non-GET state-changing operations. Combine with a CSRF token for additional defense.

### SameSite=Strict trade-offs

Strict blocks even top-level GET — so a user clicking a link to `https://app.yourorg.com/dashboard` from email arrives logged out. Use cases:
- High-value sessions where re-auth on entry is acceptable.
- Pair with a "browser-aware login" UX (show login if no session, redirect to where they wanted).

### SameSite=None — when needed

Required for:
- Third-party iframes that need authenticated cookies (analytics embeds, support widgets).
- OAuth flows where the IdP redirects back via a top-level navigation that requires the cookie.

When using None, the cookie is sent on every cross-site request. Pair with CSRF tokens and short expiry.

## __Host- prefix specifics

```http
Set-Cookie: __Host-session=value; Secure; Path=/; SameSite=Lax; HttpOnly
```

Browser refuses if:
- `Secure` flag missing.
- `Path` not `/`.
- `Domain` attribute present.

This means the cookie is only valid for the exact origin (no subdomains can read or write it). A compromised subdomain can't steal or replace your main app's session.

## CSRF protection — defense in depth beyond SameSite

SameSite=Lax/Strict mitigates most CSRF. Where you still need explicit tokens:

- Login forms (you don't have a session yet, so SameSite doesn't apply).
- API endpoints accepting top-level GET that modify state (these shouldn't exist, but if they do).
- Apps supporting older browsers without SameSite enforcement.

Double-submit pattern:
1. Server sets a random token in a cookie (`csrf=...; SameSite=Strict`).
2. JS reads it and sends as `X-CSRF-Token` header on each state-changing request.
3. Server verifies header matches cookie.

Synchronizer token pattern (more secure but stateful):
1. Server generates a token per session, stores it server-side.
2. Returns it in a meta tag or via API to the frontend.
3. Frontend includes it in every state-changing request.

Either works. SameSite + a token is the standard.

## Multi-cookie patterns

Common SaaS auth: an access token (short-lived, frequently rotated) + a refresh token (longer-lived, less frequent use).

```http
Set-Cookie: __Host-access=jwt...; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=900
Set-Cookie: __Host-refresh=opaque...; HttpOnly; Secure; SameSite=Strict; Path=/auth/refresh; Max-Age=2592000
```

Notes:
- Refresh cookie scoped to `Path=/auth/refresh` — only sent on refresh calls. Other endpoints don't see it.
- Refresh is `SameSite=Strict` — never sent cross-site. Refresh endpoint is internal-only.
- Both `__Host-` for max scoping protection.

## Anti-patterns

### Anti-pattern A — Session cookie without HttpOnly

```http
Set-Cookie: session=...; Secure; SameSite=Lax
```

JS can read `document.cookie` and steal the session via XSS. With HttpOnly, XSS can still impersonate by making requests, but can't exfiltrate the cookie itself.

### Anti-pattern B — Session in localStorage

```js
localStorage.setItem('jwt', token);  // readable by any script
```

Any XSS reads localStorage. Use a cookie with HttpOnly. The "localStorage is convenient for SPAs" argument is a XSS-amplifier argument.

### Anti-pattern C — `Domain=.example.com` unnecessarily

If only `app.example.com` needs the cookie, don't set `Domain=.example.com`. Any subdomain (legitimate or compromised) can then read it. The default (no Domain attribute = host-only cookie) is more secure.

### Anti-pattern D — Long Max-Age on access tokens

Access cookies with `Max-Age=2592000` (30 days) — if leaked, the attacker has a month of access. Keep access short (5-60 minutes); use refresh for the long horizon.

### Anti-pattern E — No invalidation on logout

```js
// Logout endpoint:
res.clearCookie('session');
// But the JWT inside is still valid until expiry
```

Logout must invalidate server-side: maintain a session table, remove the entry; or maintain a "tokens issued after timestamp X" rule per user.

### Anti-pattern F — Logging cookies in error reports

Sentry/Datadog/raygun can include request headers in error reports. If `Cookie` header is included, the session token leaks to the error tracking provider.

Configure error reporting to strip `Cookie`, `Authorization`, `X-CSRF-Token` headers. Most SDKs have an option.

## Audit checklist

For each cookie set by the app:
1. Is it HttpOnly?
2. Is it Secure (in production)?
3. What SameSite value? Is it appropriate for the cookie's purpose?
4. Is it scoped tightly (Path, no unnecessary Domain)?
5. Is the prefix `__Host-` or `__Secure-` where applicable?
6. Is Max-Age appropriate (short for sensitive)?
7. Can it be invalidated server-side on logout / password change / suspicious activity?
8. Is it stripped from error reports?

## Verification

```bash
# Pull cookie config from a real session
curl -sI -c /dev/null -b /dev/null https://app.yourorg.com/dashboard | grep -i set-cookie
```

Manually log in and check:
- Devtools → Application → Cookies — confirm HttpOnly column shows ✓, Secure ✓, SameSite value, Domain field empty (or precise).
- Reload, navigate around, confirm cookie not exposed in any JS-accessible context (try `document.cookie` in console — should not show HttpOnly cookies).
