# CSP Design Reference

Load this when designing or auditing a Content Security Policy.

## What CSP does

CSP is a browser-enforced policy declaring which resources a page is allowed to load and what scripts are allowed to execute. It primarily mitigates:

- **XSS** by restricting which inline scripts and which external scripts can run.
- **Clickjacking** via `frame-ancestors`.
- **Data exfiltration** via `connect-src` limiting where the page can send data.
- **Mixed content** via `upgrade-insecure-requests`.

CSP doesn't prevent XSS bugs from being introduced — it prevents them from being exploited successfully.

## Strict CSP — the modern recommended approach

Google's [Strict CSP](https://web.dev/articles/strict-csp) guide is the current best practice. Two flavors:

### Nonce-based (preferred for server-rendered apps)

Every HTML response includes a fresh random nonce, and every `<script>` tag includes that nonce:

```html
<script nonce="r4nd0m-per-request">/* your inline script */</script>
<script src="/app.js" nonce="r4nd0m-per-request"></script>
```

CSP:

```
Content-Security-Policy:
  script-src 'nonce-r4nd0m-per-request' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
  frame-ancestors 'none';
  require-trusted-types-for 'script';
  report-uri /csp-report;
```

Key parts:
- `'nonce-...'` allows only scripts with that exact nonce.
- `'strict-dynamic'` allows scripts loaded by nonced scripts to load further scripts. This lets dynamic loading work without an allowlist.
- `object-src 'none'` and `base-uri 'none'` close two common XSS escape hatches.
- `frame-ancestors 'none'` prevents framing (clickjacking).
- `require-trusted-types-for 'script'` enforces Trusted Types — DOM sinks (innerHTML, eval) must accept a TrustedType object, not a string.

Server generates a new nonce per request (CSPRNG, ~128 bits), passes it to the template engine, and the template injects it into each `<script>` tag. Nonce is single-use.

### Hash-based (for static apps)

If you can't generate nonces (fully static site), hash each inline script:

```
script-src 'sha256-Q5...';
```

Hash all inline scripts at build time. Drawback: any edit changes the hash. Works well for builds with stable inline scripts, less well for sites with frequent inline edits.

## Starting from scratch

If the app has no CSP today, follow this rollout:

### Phase 1 — Observation (report-only)

```
Content-Security-Policy-Report-Only:
  script-src 'self';
  object-src 'none';
  base-uri 'none';
  report-uri /csp-report;
```

This doesn't block anything; it reports violations. Run for 1-2 weeks, collect violation reports, identify legitimate sources you need to add.

### Phase 2 — Strict CSP (enforcing)

Switch from `Report-Only` to enforcing. Keep `report-uri` to catch regressions.

```
Content-Security-Policy:
  script-src 'nonce-{NONCE}' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
  frame-ancestors 'self';
  upgrade-insecure-requests;
  report-uri /csp-report;
```

### Phase 3 — Tighten

Over time:
- Remove `'unsafe-eval'` (audit and refactor any code that needs it).
- Add `require-trusted-types-for 'script'`.
- Restrict `connect-src` to known API hosts.
- Restrict `img-src`, `style-src`, `font-src` to specific origins.
- Test on legacy browser cohort if you support them (older browsers don't understand `'strict-dynamic'` — provide a fallback allowlist).

## Common mistakes

### Mistake 1 — `script-src 'unsafe-inline'` everywhere

Defeats CSP's main purpose. The most common cause: inline event handlers (`onclick="..."`) in legacy code.

Fix: move to `addEventListener` in external/nonced scripts.

### Mistake 2 — `script-src 'self'` only

`'self'` allows scripts from your own origin. If your site hosts user uploads under the same origin, those uploads might be served as scripts. Either:
- Host uploads on a separate origin (subdomain on a different host).
- Or ensure uploads have `Content-Disposition: attachment` and a non-script Content-Type.

### Mistake 3 — Allowlist with risky origins

`script-src 'self' https://cdn.jsdelivr.net` — anyone who can publish on jsdelivr can run scripts on your site. Avoid broad CDNs in `script-src`; if you must, use SRI to pin specific file hashes.

### Mistake 4 — Forgetting `object-src` and `base-uri`

Common XSS bypasses use `<object>` or `<base>`:
- `<base href="https://attacker.com/">` reroutes relative URLs to attacker.
- `<object data="...">` can execute Flash/applet legacy.

Both need explicit closure: `object-src 'none'; base-uri 'none'`.

### Mistake 5 — `frame-ancestors` set to `*`

Allows anyone to embed your site in an iframe — clickjacking. Set to `'self'` (only your own pages can frame you) or specific origins.

### Mistake 6 — `report-uri` without monitoring

A `report-uri` that nobody watches catches nothing useful. Pipe to your alerting (Datadog, Sentry, custom). Filter out browser-extension noise (a lot of violation reports come from Adblock-style extensions injecting scripts).

### Mistake 7 — Different policies per route

Maintaining per-route CSP is fragile. Aim for one strict policy applied at the edge / middleware to every HTML response. Static asset responses can omit CSP (they're not HTML and don't load scripts contextually).

### Mistake 8 — `report-only` left in production "temporarily"

`report-only` doesn't block. If you forgot to remove it, you have observation-mode CSP and no protection. Send both headers during transition only; remove report-only as soon as you're confident.

## Worked example — Next.js app

```ts
// middleware.ts (Next.js)
import { NextResponse } from 'next/server';
import { randomBytes } from 'crypto';

export function middleware(request: Request) {
  const nonce = randomBytes(16).toString('base64');
  const csp = `
    default-src 'self';
    script-src 'nonce-${nonce}' 'strict-dynamic';
    style-src 'self' 'nonce-${nonce}';
    img-src 'self' data: blob: https://images.yourorg.com;
    font-src 'self' data:;
    connect-src 'self' https://api.yourorg.com wss://realtime.yourorg.com https://*.supabase.co;
    object-src 'none';
    base-uri 'self';
    form-action 'self';
    frame-ancestors 'self';
    upgrade-insecure-requests;
    report-uri /api/csp-report;
  `.replace(/\s{2,}/g, ' ').trim();

  const response = NextResponse.next();
  response.headers.set('Content-Security-Policy', csp);
  response.headers.set('x-nonce', nonce);  // server components read this
  return response;
}
```

Then in your layout, propagate the nonce to inline scripts:

```tsx
import { headers } from 'next/headers';

export default async function RootLayout({ children }) {
  const nonce = (await headers()).get('x-nonce') ?? '';
  return (
    <html>
      <head>
        <Script nonce={nonce} src="/analytics.js" />
      </head>
      <body>{children}</body>
    </html>
  );
}
```

## Verifying a CSP

Tools:
- [csp-evaluator.withgoogle.com](https://csp-evaluator.withgoogle.com) — paste your policy, see weaknesses.
- [securityheaders.com](https://securityheaders.com) — grades your headers overall.
- DevTools → Console — CSP violations log here in real time.

Manual test:
- Open the deployed page.
- DevTools → Console → check for `Refused to execute inline script because it violates the following Content Security Policy directive`.
- DevTools → Network → click an HTML response → look at the `Content-Security-Policy` response header.

## Trusted Types — the extra step

Modern CSP can require Trusted Types:

```
require-trusted-types-for 'script';
trusted-types default;
```

Once enforced, code like `element.innerHTML = userInput` throws. To assign, code must first wrap the string in a `TrustedHTML` produced by a policy:

```js
const policy = trustedTypes.createPolicy('default', {
  createHTML: (input) => DOMPurify.sanitize(input),
});
element.innerHTML = policy.createHTML(userInput);  // now allowed
```

This eliminates entire classes of DOM XSS at runtime. Worth pursuing for high-value SaaS.

## Reporting endpoint sketch

```ts
// /api/csp-report
export async function POST(req: Request) {
  const report = await req.json();
  // CSP reports come as {"csp-report": {...}} or new "report-to" format
  await logger.warn({ msg: 'csp_violation', report });
  return new Response(null, { status: 204 });
}
```

Filter noise: extension-injected scripts, `https://chrome-extension://`, `safari-extension://`, `moz-extension://` are common and not your concern.

## Audit checklist

1. CSP header present and enforcing (not just report-only).
2. `script-src` uses nonces or hashes; no `'unsafe-inline'`.
3. No `'unsafe-eval'` (or documented exception).
4. `object-src 'none'`, `base-uri 'none'|'self'`.
5. `frame-ancestors` restricting framing.
6. `report-uri` connected to monitoring.
7. Same policy applied to all HTML responses.
8. No legacy `X-XSS-Protection` header (deprecated; remove).
9. HSTS, X-Content-Type-Options also set.
