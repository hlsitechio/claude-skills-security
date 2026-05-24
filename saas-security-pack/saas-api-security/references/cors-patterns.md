# CORS Patterns Reference

Cross-Origin Resource Sharing is the browser's mechanism for permitting requests across origins. Misconfigurations turn it from a safety net into an open door.

## The model in one paragraph

Browsers block cross-origin requests by default. The server opts in via response headers (`Access-Control-Allow-Origin`, etc.). For requests carrying credentials (cookies, HTTP auth), the rules are stricter: `Allow-Origin` must echo a specific origin (not `*`), and `Access-Control-Allow-Credentials: true` must be present. Get either wrong and you create a vulnerability or break the API.

## The four critical headers

| Header | Purpose | Bad value |
|--------|---------|-----------|
| `Access-Control-Allow-Origin` | Which origins may read responses | `*` with credentials; reflected `Origin` |
| `Access-Control-Allow-Credentials` | Allow cookies / auth headers | `true` with reflected origin |
| `Access-Control-Allow-Methods` | Which HTTP verbs allowed | `*` |
| `Access-Control-Allow-Headers` | Which custom headers accepted | `*` |

## Allowlist pattern (recommended)

Maintain a literal list of allowed origins. Compare exact strings.

```ts
const ALLOWED_ORIGINS = new Set([
  'https://app.yourorg.com',
  'https://staging.yourorg.com',
  'https://admin.yourorg.com',
]);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');  // critical for caches
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,PATCH,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
    res.setHeader('Access-Control-Max-Age', '86400');
    return res.status(204).end();
  }
  next();
});
```

Key points:
- `Vary: Origin` prevents cached responses from serving the wrong Allow-Origin to other origins.
- `Allow-Credentials: true` ONLY when the origin matched the allowlist. Don't blanket-set it.
- `Max-Age` caches preflight; reasonable values (1h–24h) reduce overhead without locking the policy in too long.

## Anti-patterns

### Anti-pattern 1 — `*` with credentials

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

Browsers reject this combination by spec — your API just stops working for cookie-auth scenarios. But the *intent* (wanting both) is the smell: it usually means the developer doesn't understand the model.

### Anti-pattern 2 — reflected Origin

```js
// BAD
res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
res.setHeader('Access-Control-Allow-Credentials', 'true');
```

Echoes whatever the attacker sets as Origin. Combined with credentials, any site can read your authenticated user's data via fetch. **Critical** finding.

### Anti-pattern 3 — sloppy regex

```js
const isAllowed = /yourorg\.com$/.test(origin);
```

Matches `https://evil-yourorg.com`. Use exact string compare against an allowlist.

```js
// Subdomain wildcard done safely
const ALLOWED_HOST_SUFFIXES = ['.yourorg.com'];
function isAllowed(origin) {
  try {
    const u = new URL(origin);
    if (u.protocol !== 'https:') return false;
    return ALLOWED_HOST_SUFFIXES.some(suffix => 
      u.hostname === suffix.slice(1) || u.hostname.endsWith(suffix)
    );
  } catch {
    return false;
  }
}
```

### Anti-pattern 4 — including localhost in production

```ts
const ALLOWED = ['https://app.yourorg.com', 'http://localhost:3000'];
```

Localhost as Origin can be set by any attacker (it's a string the browser provides; no validation). In production, never trust `http://localhost:*` as a special case.

### Anti-pattern 5 — preflight allow-all

```
Access-Control-Allow-Methods: *
Access-Control-Allow-Headers: *
```

Wildcard methods + headers were added to the spec in recent years but DON'T apply to credentialed requests. For credentialed APIs, list explicitly.

## CORS vs CSRF

CORS controls who can read responses; CSRF protects against state changes triggered by unwanted requests. They overlap but solve different problems:

- A locked-down CORS policy doesn't replace CSRF tokens for cookie-based auth.
- A correctly-implemented CSRF defense (SameSite cookies + tokens) reduces but doesn't eliminate the need for CORS care.

For Bearer-token APIs (Authorization header), CORS is the primary defense — there's no ambient cookie, so the attacker needs to read responses to do harm.

## Audit checklist

For every API endpoint with auth:

1. Confirm `Allow-Origin` is set per request to a specific origin (from allowlist), or absent if the origin isn't allowed.
2. Confirm `Vary: Origin` is set on responses that may have CORS headers.
3. Confirm `Allow-Credentials: true` only appears alongside a specific origin.
4. Test with `curl -H 'Origin: https://evil.com'` — response should NOT include CORS headers.
5. Test with `curl -H 'Origin: https://app.yourorg.com'` — response should include matching CORS headers.
6. Preflight (`OPTIONS`) returns 204 with appropriate methods/headers; not 200 with body.
7. No `*` for credentialed APIs anywhere.

## Special cases

- **Public APIs (no auth)** — `Allow-Origin: *` is OK; don't add `Allow-Credentials`.
- **Single-page apps with cookie auth** — strict allowlist + Vary + Credentials.
- **Mobile apps (no Origin header)** — Origin absent for non-browser clients; auth via headers, no CORS needed.
- **Internal services behind VPN** — still use allowlist; the network boundary is not a substitute.

## Quick test

```bash
# Should succeed
curl -I -X OPTIONS \
  -H 'Origin: https://app.yourorg.com' \
  -H 'Access-Control-Request-Method: POST' \
  https://api.yourorg.com/api/users

# Should fail (no CORS headers in response)
curl -I -X OPTIONS \
  -H 'Origin: https://attacker.example.com' \
  -H 'Access-Control-Request-Method: POST' \
  https://api.yourorg.com/api/users
```

If the second curl returns CORS headers, you have a CORS misconfiguration finding.
