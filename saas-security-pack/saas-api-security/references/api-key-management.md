# API Key Management Reference

API keys are long-lived bearer tokens. Done well, they're a usable security primitive; done poorly, they leak everywhere and never get rotated.

## Generation

Use a CSPRNG. Length should give ≥128 bits of entropy.

```ts
// Node
import { randomBytes } from 'crypto';
function generateApiKey(): string {
  return randomBytes(32).toString('base64url');  // ~256 bits
}

// Python
import secrets
def generate_api_key() -> str:
    return secrets.token_urlsafe(32)
```

Format prefixes (e.g., `sk_live_...`, `pk_test_...`) help with two things:
- Identifying the key type in logs / leak detection
- Allowing automated revocation (GitHub secret scanning, gitleaks, TruffleHog detect known prefixes)

```
yourorg_live_<random>     # production
yourorg_test_<random>     # test
yourorg_admin_<random>    # admin/master
```

## Storage

**Never** store keys in plaintext in the database. Hash them like passwords (single-pass SHA-256 is acceptable since keys are high-entropy, but bcrypt/argon2 also fine and future-proofs against weak human-derived keys).

```sql
CREATE TABLE api_keys (
  id           UUID PRIMARY KEY,
  user_id      UUID NOT NULL REFERENCES users(id),
  key_hash     TEXT NOT NULL,         -- sha256(key) hex or argon2 hash
  key_prefix   TEXT NOT NULL,         -- first 8-12 chars for UI display
  name         TEXT NOT NULL,         -- user-supplied label
  scopes       TEXT[] NOT NULL,       -- ['read:users', 'write:posts']
  last_used_at TIMESTAMPTZ,
  expires_at   TIMESTAMPTZ,
  revoked_at   TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ON api_keys (key_hash) WHERE revoked_at IS NULL;
```

Show the full key to the user **exactly once** at creation, then never again. Display only the prefix afterward (e.g., `yourorg_live_a1b2****`).

## Verification (constant-time)

When validating an incoming key:

1. Compute the hash of the presented key.
2. Look up by hash.
3. Use **constant-time comparison** if comparing the candidate hash to a stored hash (or look up by indexed hash and use a constant-time DB lookup).

```ts
import { createHash, timingSafeEqual } from 'crypto';

function hashKey(key: string): Buffer {
  return createHash('sha256').update(key).digest();
}

async function verify(key: string) {
  const hash = hashKey(key);
  const record = await db.apiKeys.findFirst({
    where: { keyHash: hash.toString('hex'), revokedAt: null },
  });
  if (!record) return null;
  
  // Optional: extra defense-in-depth comparison
  // (lookup by indexed hash is already constant time at the DB level)
  
  if (record.expiresAt && record.expiresAt < new Date()) return null;
  return record;
}
```

## Scoping

Keys carry capabilities. Don't issue admin-equivalent keys for read-only integrations.

- **Read vs write** — `read:posts`, `write:posts`
- **Resource scope** — `org:acme:*`, `project:xyz:read`
- **Time-bound** — `expires_at` for short-lived keys
- **IP-bound** (optional) — restrict to specific source IPs for high-value keys

The scopes are stored alongside the hash and checked on every request.

## Rotation

- Keys never auto-rotate (they're long-lived by design), but the system supports rotation:
  - User can generate a new key alongside the old.
  - Both work for an overlap period.
  - Old key revoked when user confirms migration.
- Document the rotation cadence (e.g., 90 days for production keys).
- Send reminders before keys are 30/7/1 days from expiry.

## Revocation

- `revoked_at` column with timestamp; queries filter by `revokedAt IS NULL`.
- Don't delete revoked keys — preserve for audit logs.
- Bulk revocation supported (revoke all keys for a user, all keys for an org).
- Emergency: rotate the hashing pepper / signing secret to invalidate all keys at once if the system is compromised.

## Transit

- Keys sent ONLY over HTTPS. Reject keys on HTTP unless localhost.
- Standard header: `Authorization: Bearer <key>` or `X-API-Key: <key>`.
- Don't accept keys in URL query strings — they get logged in access logs, browser history, server logs.

## Logging

- Don't log full keys. Log prefix only (`yourorg_live_a1b2`).
- Failed auth attempts logged with prefix + IP — useful for detecting brute force or leak exploitation.
- Successful auth logged at debug level only; info level captures rate.

## Leak response

When a key leaks (committed to git, posted in a chat, found in a paste site):
1. Revoke immediately.
2. Audit logs for unauthorized use during the exposure window.
3. Notify the user/account owner.
4. Document the incident.

Use GitHub Secret Scanning (free for public repos) — register your prefix pattern with GitHub via the partner program OR scan with TruffleHog/gitleaks in your own CI on commits.

## UI conventions

Industry-standard UX:
- **Creation** — show the full key in a modal with "Copy" button; warn it won't be shown again.
- **List** — show `name`, `prefix` (`yourorg_live_a1b2****`), `scopes`, `last_used_at`, `created_at`, `expires_at`.
- **Revoke** — single click with confirmation.
- **Audit** — last 30 days of usage per key.

## Multi-tenant considerations

- Keys belong to a tenant + user. Verifying a key resolves both — every downstream check uses the resolved tenant.
- A user with access to multiple tenants has separate keys per tenant (or the key explicitly scopes to one tenant). Don't issue keys that span tenants.

## Service-to-service vs user keys

User-generated keys (above) ≠ service-to-service keys. For S2S:
- Prefer short-lived OAuth client_credentials tokens.
- If using long-lived service keys, treat them with extra scrutiny: encrypted at rest, separate secret storage (Vault, AWS Secrets Manager), tighter scope.

## Audit checklist

For an API key implementation:

1. Keys generated with CSPRNG, ≥128 bits entropy.
2. Stored hashed, never plaintext.
3. Shown to user only once at creation.
4. Scopes enforced on every request.
5. Revocation works and is logged.
6. Last-used timestamp updated (with care — avoid write contention).
7. Expiry supported.
8. HTTPS only; rejected on plain HTTP.
9. Not accepted via URL query string.
10. Logs don't contain full keys.
11. Documented rotation procedure.
12. Leak response procedure documented.
