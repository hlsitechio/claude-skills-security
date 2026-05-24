# JWT Validation Reference

Load this when reviewing JWT issuance or verification code, or when the user asks if their JWT handling is safe.

## The classic bugs

### Bug 1 — `alg: none`

JWT spec allows `"alg": "none"` (unsigned token). If the verifier doesn't pin the algorithm, an attacker can craft a token with `alg: none`, no signature, arbitrary claims — and the verifier accepts it.

```js
// VULNERABLE
const decoded = jwt.verify(token, secret);  // uses alg from header

// SAFE
const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });
```

Every JWT library has an `algorithms` allowlist parameter. Every JWT verification must use it.

### Bug 2 — Algorithm confusion (HS256 / RS256)

A token is supposed to be signed with RS256 (asymmetric, server has private key, client knows public). Attacker rewrites the header to `HS256`, uses the *public key* as the HMAC secret, and signs the token themselves. If the verifier picks the algorithm from the header, it'll verify against the public key (now used as HMAC secret).

Same fix: pin the algorithm in the verification call.

### Bug 3 — Missing claim validation

A correctly-signed JWT can still be wrong:
- Issued by a different service (`iss`)
- For a different audience (`aud`)
- Expired (`exp`)
- Not yet valid (`nbf`)

```js
const decoded = jwt.verify(token, key, {
  algorithms: ['RS256'],
  issuer: 'https://auth.yourorg.com',
  audience: 'api.yourorg.com',
  // exp, nbf, iat are validated by default in most libs — verify
});
```

### Bug 4 — Trust before verify

```js
// VULNERABLE
const decoded = jwt.decode(token);                // parses, doesn't verify
if (decoded.role === 'admin') { ... }             // attacker controls decoded
const verified = jwt.verify(token, key);          // verification too late
```

`decode` (not `verify`) returns the payload without checking the signature. The pattern above is common: someone wanted to read the user ID before doing some setup, then verify. Attackers craft a token with their own claims, the lookup uses attacker-controlled values, then verify rejects — but the lookup already happened.

Always verify first, then trust.

### Bug 5 — Weak HMAC secrets

HS256 secret strength = the secret's entropy. A 12-character password is brute-forceable offline. HMAC secrets should be ≥ 256 bits of CSPRNG output, base64-encoded for ergonomics.

```bash
openssl rand -base64 64   # 512 bits, plenty
```

### Bug 6 — Static secret per environment

If all environments share the secret (or staging's secret leaks), tokens forged in one environment work in another. Per-environment secrets, rotated periodically.

### Bug 7 — No key rotation path

When a secret leaks or a key is compromised, you need to rotate. RS256/ES256 support multiple kid in the JWKS during rotation; HS256 doesn't natively, but you can verify against (current_secret, previous_secret) for a grace period.

```js
function verifyWithRotation(token, secrets) {
  for (const s of secrets) {
    try { return jwt.verify(token, s, { algorithms: ['HS256'] }); }
    catch { /* try next */ }
  }
  throw new Error('invalid token');
}
```

### Bug 8 — JWT as session token without revocation

JWT is stateless: a token is valid until it expires. If a user logs out, changes password, gets terminated — the token is still valid. For high-value flows (banking, admin operations), pair JWT with:

- A short expiry (5-15 minutes)
- A refresh token with server-side revocation
- A check against a "revoked tokens" / "user version" table on each request

For lower-value flows, JWT's stateless property is fine.

### Bug 9 — Refresh token reuse not detected

Refresh tokens should be single-use. If a refresh token is presented twice, that almost always means theft: legitimate user used it, attacker also used it (or vice versa). Detect refresh reuse and invalidate the entire session family.

```ts
// Server-side: on every refresh
const session = await db.sessions.findByRefreshToken(token);
if (!session) throw new Error('invalid refresh token');
if (session.refresh_used_at) {
  // Reuse detected — assume theft, kill the whole session family
  await db.sessions.invalidateAllForUser(session.user_id);
  throw new Error('refresh reuse detected');
}
await db.sessions.markRefreshUsed(token);
// issue new access + new refresh
```

### Bug 10 — Sensitive data in JWT payload

JWT payload is base64, not encrypted. Don't put PII, internal IDs, or anything you wouldn't print in logs. If you must, use JWE (JSON Web Encryption) — but for most SaaS, just keep the JWT minimal: subject, audience, issuer, expiry, maybe role.

## Cross-language examples

### Node — `jose` library (recommended over `jsonwebtoken`)

```ts
import { jwtVerify } from 'jose';

const { payload } = await jwtVerify(token, publicKey, {
  algorithms: ['RS256'],
  issuer: 'https://auth.yourorg.com',
  audience: 'api.yourorg.com',
});
```

### Python — `PyJWT`

```python
import jwt
decoded = jwt.decode(
    token,
    key=public_key,
    algorithms=["RS256"],
    audience="api.yourorg.com",
    issuer="https://auth.yourorg.com",
    options={"require": ["exp", "iat", "aud", "iss"]},
)
```

### Go — `golang-jwt/jwt`

```go
parser := jwt.NewParser(
    jwt.WithValidMethods([]string{"RS256"}),
    jwt.WithAudience("api.yourorg.com"),
    jwt.WithIssuer("https://auth.yourorg.com"),
    jwt.WithExpirationRequired(),
)
token, err := parser.Parse(tokenString, func(t *jwt.Token) (any, error) {
    return publicKey, nil
})
```

### Java — `nimbus-jose-jwt`

```java
ConfigurableJWTProcessor<SecurityContext> proc = new DefaultJWTProcessor<>();
proc.setJWSKeySelector(new JWSVerificationKeySelector<>(
    JWSAlgorithm.RS256, new ImmutableJWKSet<>(jwkSet)));
proc.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
    new JWTClaimsSet.Builder().issuer("https://auth.yourorg.com")
        .audience("api.yourorg.com").build(),
    Set.of("exp", "iat")));
JWTClaimsSet claims = proc.process(jwt, null);
```

## Review checklist

For each JWT verification call:
1. Algorithm is allowlisted explicitly.
2. Issuer is checked.
3. Audience is checked.
4. Expiry is enforced (not optional).
5. Signature is verified before any claim is read or used.
6. Key rotation path exists (JWKS endpoint with kid, or HMAC dual-secret).
7. Sensitive operations have additional revocation check.
8. Refresh tokens rotate and reuse detection is wired up.

For each JWT issuance call:
1. Reasonable expiry (≤ 1 hour for access tokens; longer is fine for refresh with revocation).
2. Minimal payload — no PII or secrets.
3. Distinct keys per environment.
4. Issuer/audience set correctly so other services can validate.
