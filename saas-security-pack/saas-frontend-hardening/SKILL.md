---
name: saas-frontend-hardening
description: Audit web frontend security including Content Security Policy (CSP), Subresource Integrity (SRI), XSS prevention, clickjacking protection, secure cookies (SameSite/HttpOnly/Secure), postMessage origin validation, Trusted Types, and security headers. Use this skill whenever the user asks about CSP, XSS, frontend security, secure cookies, clickjacking, security headers, SRI, sandbox iframes, Trusted Types, or "audit my web app security". Trigger on phrases like "audit my CSP", "review my security headers", "XSS protection", "secure cookies", "clickjacking", "frontend hardening", "CORB", "report-uri". Use this even when only one header or topic is mentioned.
---

# SaaS Frontend Hardening

Audit the browser-side security surface of a SaaS application: headers, cookies, CSP, third-party scripts, postMessage flows, and DOM XSS sinks. Defensive find-and-fix focus.

## When this skill applies

- Reviewing HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)
- Designing or hardening a Content Security Policy
- Reviewing cookie configurations
- Auditing inline scripts, dynamic eval, and DOM XSS sinks
- Reviewing iframe / postMessage flows for cross-origin trust
- Checking third-party script inclusions for SRI

Use other skills for: backend code XSS sinks in templates (`saas-code-security-review`), CORS on API endpoints (`saas-api-security`).

## Workflow

Follow `../_shared/audit-workflow.md`. Frontend-specific notes below.

### Phase 1: Scope confirmation

- Which framework (React/Vue/Svelte/Angular/plain)?
- Server-rendered, static, or SPA?
- Which CDN / edge layer (Vercel, Netlify, Cloudflare, custom)?
- Are there embedded customer apps or iframes (white-label, embedded widgets)?

### Phase 2: Inventory

```bash
# Pull headers for a known URL
curl -sI -H 'Accept: text/html' https://app.yourorg.com/ | grep -iE \
  'content-security-policy|strict-transport-security|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|cross-origin-opener-policy|cross-origin-embedder-policy|cross-origin-resource-policy|set-cookie'

# Scan loaded resources from a representative page
# (use https://securityheaders.com or https://csp-evaluator.withgoogle.com)
```

Identify:
- All security headers currently set
- All third-party scripts loaded (CDN, analytics, ads, embeds)
- All iframes embedded in the app and their origins
- All cookies set (especially session)
- All postMessage handlers (grep `addEventListener('message'`)

### Phase 3: Detection — the checks

#### Content Security Policy — see `references/csp-design.md`

- **SFH-CSP-1** CSP header present on every HTML response (`Content-Security-Policy`, not just `report-only`).
- **SFH-CSP-2** No `'unsafe-inline'` in `script-src` (or use nonces/hashes).
- **SFH-CSP-3** No `'unsafe-eval'` in `script-src` (or document why and limit).
- **SFH-CSP-4** No wildcard hosts (`https:`, `*`) in `script-src` or `object-src`.
- **SFH-CSP-5** `object-src 'none'` to block Flash/applet legacy plugins.
- **SFH-CSP-6** `base-uri 'self'` (or stricter) to prevent base-tag injection.
- **SFH-CSP-7** `frame-ancestors 'self'` (or specific origins) — replaces X-Frame-Options.
- **SFH-CSP-8** `form-action 'self'` (or specific) to prevent form-submission hijacking.
- **SFH-CSP-9** `report-uri` or `report-to` configured to catch violations in production.
- **SFH-CSP-10** Strict-Dynamic + nonces preferred over allowlists where script load patterns allow.

#### Other security headers

- **SFH-HDR-1** `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` on production HTTPS sites. Submit to HSTS preload list.
- **SFH-HDR-2** `X-Content-Type-Options: nosniff` to prevent MIME sniffing.
- **SFH-HDR-3** `Referrer-Policy: strict-origin-when-cross-origin` (or stricter) — controls Referer header leakage.
- **SFH-HDR-4** `Permissions-Policy` denying unused features (camera, microphone, geolocation, payment, etc.).
- **SFH-HDR-5** `Cross-Origin-Opener-Policy: same-origin` (COOP) to isolate browsing context.
- **SFH-HDR-6** `Cross-Origin-Embedder-Policy: require-corp` (COEP) if cross-origin isolation is needed (SharedArrayBuffer, etc.).
- **SFH-HDR-7** `Cross-Origin-Resource-Policy` set on API responses (`same-origin` or `same-site`).

#### Cookies — see `references/cookie-config.md`

- **SFH-COOK-1** Session cookies: `HttpOnly`, `Secure`, `SameSite=Lax` (or `Strict` for high-value sessions).
- **SFH-COOK-2** Cookie scoped to path / domain — no `Domain=.example.com` if you don't need subdomain access.
- **SFH-COOK-3** Cookies with sensitive data prefixed with `__Host-` (no Domain, requires Secure, Path=/).
- **SFH-COOK-4** No long-lived authentication cookies — short access, rotated refresh.
- **SFH-COOK-5** Logout invalidates session server-side, not just clears cookie.
- **SFH-COOK-6** CSRF token cookie marked SameSite=Strict and double-submit pattern in place if cookie-based session.

#### XSS prevention

- **SFH-XSS-1** Templating engine auto-escapes by default; manual unescape calls (`dangerouslySetInnerHTML`, `v-html`, `{@html ...}`, `[innerHTML]`) reviewed individually.
- **SFH-XSS-2** User-supplied URLs sanitized before use in `href`, `src`, `srcdoc` (no `javascript:` scheme).
- **SFH-XSS-3** DOM sinks identified: `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout(string)`, `Function()`, `setInterval(string)`. Each use reviewed.
- **SFH-XSS-4** Trusted Types policy active (Chrome/Edge) — converts DOM sink violations into errors.
- **SFH-XSS-5** Markdown rendering uses a safe library (DOMPurify after parse, or a parser that never produces dangerous output).
- **SFH-XSS-6** Rich-text editors (Quill, TipTap, Tiptap, Slate) sanitize HTML on save AND on render.
- **SFH-XSS-7** User-supplied SVG sanitized — SVG can contain `<script>`.

#### Clickjacking

- **SFH-CJ-1** `Content-Security-Policy: frame-ancestors 'self'` (or specific origins) — modern equivalent of X-Frame-Options.
- **SFH-CJ-2** Legacy: `X-Frame-Options: DENY` or `SAMEORIGIN` for browsers without CSP frame-ancestors.
- **SFH-CJ-3** Sensitive actions (payment confirmation, account deletion) confirmed via secondary mechanism (re-auth or modal that breaks iframes via frame-busting JS).
- **SFH-CJ-4** OAuth consent flows don't frame.

#### Third-party scripts

- **SFH-3P-1** Inventory all third-party scripts loaded (analytics, ads, A/B testing, error tracking).
- **SFH-3P-2** Each third-party script either: (a) loaded from a host listed in CSP `script-src`, or (b) loaded with a nonce (preferred).
- **SFH-3P-3** SRI (Subresource Integrity) used for scripts from `cdnjs`, `unpkg`, `jsdelivr` etc.: `<script src="..." integrity="sha384-..." crossorigin="anonymous"></script>`.
- **SFH-3P-4** Tag managers (GTM) restricted to vetted tags via tag manager workspace permissions.
- **SFH-3P-5** Customer-facing apps don't load attacker-controllable third-party scripts based on tenant config.

#### postMessage / cross-frame trust

- **SFH-PM-1** Every `addEventListener('message')` handler validates `event.origin`.
- **SFH-PM-2** Wildcard origin (`*`) in `postMessage` calls only when payload contains no sensitive data.
- **SFH-PM-3** Message handlers validate payload shape (schema check) before acting.
- **SFH-PM-4** Iframes hosting third-party content have `sandbox` attribute restricting capabilities.

#### Service worker

- **SFH-SW-1** Service worker scope limited (default scope is too broad if app is at root).
- **SFH-SW-2** Service worker doesn't cache sensitive responses (Authorization headers, user-specific data).
- **SFH-SW-3** Service worker update path tested; old SW can be unregistered.
- **SFH-SW-4** Service worker source served with appropriate `Cache-Control` to allow updates.

#### Authentication redirects

- **SFH-RED-1** OAuth/SSO redirect URLs validated against an allowlist — no open redirect.
- **SFH-RED-2** Login flow doesn't accept `?redirect=` parameter that could redirect off-domain.
- **SFH-RED-3** `target="_blank"` links include `rel="noopener noreferrer"` (or use modern defaults).

#### File handling

- **SFH-FILE-1** Uploaded files served from a separate origin OR with `Content-Disposition: attachment` to prevent XSS via HTML upload.
- **SFH-FILE-2** Filename sanitized in display (no `<script>` in filename rendered raw).
- **SFH-FILE-3** Avatar/image upload doesn't accept SVG (or sanitizes if needed).

### Phase 4: Triage

Critical class examples:
- CSP missing or only `report-only` in production
- `script-src 'unsafe-inline' 'unsafe-eval' *` (effectively no CSP)
- Session cookie without `HttpOnly` (stolen via XSS)
- HSTS missing on production HTTPS
- Open redirect on auth flow
- `dangerouslySetInnerHTML` with user content unescaped

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `SFH-`.

## References

- `references/csp-design.md` — Designing CSP from scratch, nonce vs hash, strict-dynamic
- `references/cookie-config.md` — Session cookies, SameSite gotchas, __Host- prefix
- `references/xss-sinks.md` — Framework-specific dangerous patterns (React, Vue, Angular)
