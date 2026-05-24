---
name: saas-code-security-review
description: "Application-code security review for SaaS backends focusing on authentication, authorization, IDOR/BOLA, SSRF, JWT handling, injection (SQL/NoSQL/command/template), deserialization, mass assignment, and SAST findings. Multi-stack (Node/TypeScript, Python, Go, Java, Ruby). Use this skill whenever the user asks to review code for security bugs, find IDOR or BOLA vulnerabilities, audit auth flows, check JWT validation, look for SSRF, hunt for injection, review session management, or interpret SAST output from CodeQL/Semgrep/Snyk Code. Trigger on phrases like 'review this code for security', 'find IDOR', 'is my JWT validation safe', 'SSRF check', 'SAST report', 'auth bypass', 'BOLA', 'audit my auth', 'session security'. Use this when the user shares a code file and security context."
---

# SaaS Code Security Review

Find application-layer vulnerabilities in SaaS backend code: authentication flows, authorization checks, request handling, and trust boundaries. Defensive (find & fix) focus.

## When this skill applies

- Reviewing source code (a PR diff, a specific file, or a directory) for security bugs
- Interpreting and triaging SAST output (CodeQL, Semgrep, Snyk Code, Sonar)
- Walking an auth flow looking for bypass paths
- Checking JWT issuance and validation correctness
- Hunting for IDOR / BOLA in REST or GraphQL endpoints

Use other skills for: backend RLS/database (`supabase-security-audit`), API surface concerns like rate limiting and CORS (`saas-api-security`), tenant-isolation focus (`saas-tenant-isolation`).

## Workflow

Follow `../_shared/audit-workflow.md`. Skill-specific notes below.

### Phase 1: Scope confirmation

- Language and framework (informs which patterns to look for)
- Auth model (sessions? JWT? both?)
- Database tech (informs injection patterns)
- Whether this is a PR review (smaller scope, recent diff) or a directory audit (broader)

### Phase 2: Inventory

- Identify entry points: HTTP route handlers, GraphQL resolvers, gRPC services, message queue consumers, CLI commands, scheduled jobs.
- Identify trust boundaries: where user input enters, where it crosses to the database, where it leaves to other services.
- Identify auth/authz code: middleware, decorators, policy functions, RBAC tables.
- Note any auto-generated boilerplate (often skipped in human review, sometimes vulnerable).

### Phase 3: Detection — the categories

Categories below are not exhaustive but cover the high-value classes for SaaS backends.

#### Authentication

- **SCSR-AUTH-1** Password storage uses Argon2id (preferred) or bcrypt with cost ≥ 12. No SHA-256, MD5, or PBKDF2-SHA1 with low iteration counts.
- **SCSR-AUTH-2** Authentication endpoints are rate-limited per-account and per-IP independently.
- **SCSR-AUTH-3** No user enumeration via response timing, status code, or message ("user not found" vs "wrong password" reveals which).
- **SCSR-AUTH-4** Account lockout or progressive delay after N failed attempts, with safe lockout reset.
- **SCSR-AUTH-5** Password reset tokens are single-use, time-limited (≤ 1 hour), and invalidated on use.
- **SCSR-AUTH-6** Email change requires confirmation at both old and new addresses.
- **SCSR-AUTH-7** Session fixation prevented: regenerate session ID on login.

#### Authorization — see `references/idor-bola-patterns.md`

This is the most common SaaS vulnerability class. Every endpoint that takes an ID parameter needs an authorization check.

- **SCSR-AZ-1** Every endpoint that accepts a resource ID checks the requester owns/has-access-to that resource before returning it.
- **SCSR-AZ-2** Authorization checks happen in the data-access layer, not just the route handler (defense in depth).
- **SCSR-AZ-3** Bulk endpoints (list, search, batch update) filter by tenant/owner in the database query, not after the fact in memory.
- **SCSR-AZ-4** GraphQL resolvers check authorization on each field that exposes another user's data, not just the root.
- **SCSR-AZ-5** Admin actions verify the requester's admin role AND that the target is within the admin's scope (an org admin can't modify another org).
- **SCSR-AZ-6** Indirect references (UUIDs, sequential IDs) don't bypass the check — the check is on the relationship, not on the unguessability.

#### JWT handling — see `references/jwt-validation.md`

- **SCSR-JWT-1** Algorithm is allowlisted to a specific value, never `alg: none` or `alg` taken from the token.
- **SCSR-JWT-2** Signature verification happens before any claim is read.
- **SCSR-JWT-3** `iss`, `aud`, and `exp` validated; `nbf` if used.
- **SCSR-JWT-4** Key rotation supported via `kid`; old keys revoked.
- **SCSR-JWT-5** No JWT used as session token for high-value flows without server-side revocation (use opaque session IDs in Redis instead, or pair JWT with revocation list).
- **SCSR-JWT-6** Secrets are random, ≥ 256 bits for HMAC; never reused across services.
- **SCSR-JWT-7** Refresh tokens are rotated on use; reuse triggers a revocation cascade.

#### Injection

- **SCSR-INJ-SQL** SQL queries use parameterized statements; no string concatenation with user input.
- **SCSR-INJ-NOSQL** MongoDB queries don't accept operator-shaped objects from user input (`{$ne: null}` attack). Sanitize or use strict schema validation.
- **SCSR-INJ-CMD** No `exec`/`spawn`/`system` with user-controlled arguments. If shelling out is needed, use array form (not shell string) and validate.
- **SCSR-INJ-TMPL** Template engines (Jinja, ERB, Handlebars with helpers) don't render user input as template, only as data.
- **SCSR-INJ-LDAP** LDAP filters escape user input; no string concat into filter expressions.
- **SCSR-INJ-XPATH** Same as LDAP, applied to XPath.

#### SSRF — see `references/ssrf-patterns.md`

- **SCSR-SSRF-1** Outbound HTTP fetches from user-supplied URLs use an allowlist OR a DNS resolver that blocks RFC1918, link-local, and cloud metadata IPs.
- **SCSR-SSRF-2** Redirects followed only if the redirect target also passes the allowlist (re-validate each hop).
- **SCSR-SSRF-3** Webhooks and image fetches both apply the protection — not just user-facing "make request" endpoints.
- **SCSR-SSRF-4** Cloud metadata endpoint (`169.254.169.254`, AWS IMDSv1) blocked at the network or HTTP layer.

#### Mass assignment / parameter binding

- **SCSR-MA-1** Frameworks that auto-bind request body to model objects (Rails, Spring, ASP.NET, NestJS class-transformer) explicitly allow-list assignable fields.
- **SCSR-MA-2** Admin-only fields (`isAdmin`, `role`, `tenant_id`, `verified`) never assignable from user-controlled input.
- **SCSR-MA-3** GraphQL inputs use specific input types, not the same object as the read model.

#### Deserialization

- **SCSR-DESER-1** No `pickle.load`, `yaml.load` (without `SafeLoader`), `unserialize` (PHP), or Java native deserialization on untrusted bytes.
- **SCSR-DESER-2** JSON parsers configured to reject unknown fields or prototype-pollution-shaped keys.

#### Cryptography

- **SCSR-CRY-1** No homegrown crypto. Use platform primitives (AES-GCM, ChaCha20-Poly1305, X25519, Ed25519).
- **SCSR-CRY-2** Random values from a CSPRNG (`crypto.randomBytes`, `secrets.token_bytes`, `crypto/rand`), never `Math.random` / `random.randint`.
- **SCSR-CRY-3** Timing-safe comparison for secrets (token equality, MAC verification).
- **SCSR-CRY-4** No ECB mode. No CBC without HMAC-then-encrypt.

#### File and upload handling

- **SCSR-FILE-1** Uploaded filenames sanitized (path traversal, null bytes).
- **SCSR-FILE-2** Content type validated by magic-byte inspection, not just `Content-Type` header.
- **SCSR-FILE-3** Storage path doesn't combine user-provided segments with `os.path.join`-like calls without validation.
- **SCSR-FILE-4** Image processing libraries (ImageMagick, sharp) running on uploads have CVE patches applied.
- **SCSR-FILE-5** Served from a separate origin or with `Content-Disposition: attachment` to prevent XSS-via-upload.

#### Error handling and information disclosure

- **SCSR-ERR-1** Stack traces never returned to the client in production.
- **SCSR-ERR-2** Error messages distinguish user-facing (safe) from log-only (full detail).
- **SCSR-ERR-3** Debug endpoints (e.g., `/debug`, `/__debug__`, `/_status`) gated by auth or removed from production builds.

### Phase 4: Triage

Critical class examples:
- Auth bypass via missing check on any state-changing endpoint
- SQL injection on any endpoint
- SSRF reaching cloud metadata
- IDOR returning another tenant's data
- RCE via deserialization, template injection, or command injection

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `SCSR-`. For each finding, include the file path and line number, plus a 2-3 line patch where feasible.

## Output style

- For PR-scoped reviews, structure the report by file rather than by severity (matches how the developer reads the diff).
- For directory audits, structure by severity then category.

## References

- `references/idor-bola-patterns.md` — Authorization patterns across REST, GraphQL, batch endpoints
- `references/jwt-validation.md` — Common JWT bugs with example fixes per language
- `references/ssrf-patterns.md` — Allowlists, DNS rebinding, cloud metadata protection
- `references/sast-triage.md` — How to read CodeQL/Semgrep/Snyk output and prioritize
