---
name: prisma-orm-security
description: Security audit specific to Prisma ORM usage including raw query escape hatches ($queryRaw, $executeRaw, $queryRawUnsafe), mass assignment via spreading user input into create/update, missing tenant scoping on findFirst/findMany, IDOR through Prisma query construction, schema-level access control gaps, and Prisma Accelerate/Pulse security considerations. Use this skill whenever the user mentions Prisma, prisma/client, schema.prisma, $queryRaw, prisma.<model>.create/update/findMany, or asks "audit my Prisma queries", "Prisma security review", "raw query safety", "Prisma mass assignment". Trigger when the codebase contains `@prisma/client`, `schema.prisma`, or any `prisma.` query calls.
---

# Prisma ORM Security Audit

Audit Prisma ORM usage for vulnerabilities specific to its query model, raw query escape hatches, and common patterns developers get wrong.

## When this skill applies

- Reviewing code using `@prisma/client`
- Auditing `$queryRaw` / `$executeRaw` / `$queryRawUnsafe` calls
- Reviewing mass assignment patterns in `create` / `update` / `upsert`
- Checking tenant scoping across queries
- Reviewing `schema.prisma` for missing constraints or indexes that have security implications

Use other skills for: generic IDOR/BOLA patterns (`saas-security-pack/saas-code-security-review/references/idor-bola-patterns.md`), tenant isolation (`saas-security-pack/saas-tenant-isolation`), backend framework specifics (`nestjs-security`, `nodejs-express-security`, `nextjs-security`).

## Workflow

Follow `../_shared/audit-workflow.md`. Prisma-specific notes below.

### Phase 1: Stack detection

```bash
grep -E '"@prisma/client":' package.json
find . -name 'schema.prisma' -not -path '*/node_modules/*'
prisma --version 2>/dev/null
```

### Phase 2: Inventory

```bash
# Raw query usage
grep -rnE '\$queryRaw|\$executeRaw|\$queryRawUnsafe|\$executeRawUnsafe' src/

# Model accesses
grep -rnE 'prisma\.[a-zA-Z]+\.(create|update|upsert|delete|findFirst|findMany|findUnique)' src/ | head -50

# Spread patterns (mass assignment risk)
grep -rnE 'data:\s*{?\s*\.\.\.' src/ | head -30

# Transaction / interactiveTransaction
grep -rnE '\$transaction|interactiveTransaction' src/

# Soft-delete or middleware
grep -rnE 'prisma\.\$(use|extends)' src/
```

### Phase 3: Detection — the checks

#### Raw query injection

Prisma's parameterized queries are safe; the escape hatches are not.

- **PRI-SQL-1** `$queryRaw\`...\`` (tagged template) — safe when used as designed: `prisma.$queryRaw\`SELECT * FROM users WHERE id = ${userId}\``. The tagged template parameterizes `${...}`.
- **PRI-SQL-2** `$queryRawUnsafe(...)` and `$executeRawUnsafe(...)` — NOT safe with user input. These accept a string + separate args; the string is concatenated. Audit every call:
  ```ts
  // BAD
  await prisma.$queryRawUnsafe(`SELECT * FROM ${tableName} WHERE id = ${userId}`);
  
  // GOOD
  await prisma.$queryRaw`SELECT * FROM "Posts" WHERE id = ${userId}`;
  // or, if table name truly dynamic:
  const allowed = ['posts', 'comments', 'tags'];
  if (!allowed.includes(tableName)) throw new Error('invalid table');
  await prisma.$queryRawUnsafe(`SELECT * FROM "${tableName}" WHERE id = $1`, userId);
  ```
- **PRI-SQL-3** Dynamic ORDER BY / LIMIT / column names in raw queries — Prisma's parameterization doesn't cover those; allowlist explicitly.
- **PRI-SQL-4** `Prisma.sql` template literal helper — safe for composition: ``Prisma.sql`WHERE id = ${id}`` composed into larger queries.

```ts
// Composing safely
import { Prisma } from '@prisma/client';

const filters = [];
if (status) filters.push(Prisma.sql`status = ${status}`);
if (userId) filters.push(Prisma.sql`user_id = ${userId}`);
const whereClause = filters.length
  ? Prisma.sql`WHERE ${Prisma.join(filters, ' AND ')}`
  : Prisma.empty;

await prisma.$queryRaw`SELECT * FROM "Posts" ${whereClause}`;
```

#### Mass assignment

Spreading user input into Prisma's `data` object is mass assignment.

- **PRI-MA-1** `data: { ...req.body }` patterns — User can set any column they want, including `role: 'admin'`, `tenantId: 'other-tenant'`, `verified: true`, `createdAt: '1970-01-01'`.
- **PRI-MA-2** Even with strict-typed inputs, if the input type matches the model type, user fields override server expectations.

```ts
// BAD
await prisma.user.create({ data: { ...req.body } });

// BAD even with parsing
const parsed = UserSchema.parse(req.body);  // schema includes role, verified, ...
await prisma.user.create({ data: parsed });

// GOOD — explicit allow-list at the boundary
const { displayName, email, bio } = UserSchema.pick({
  displayName: true, email: true, bio: true,
}).parse(req.body);

await prisma.user.create({
  data: {
    displayName,
    email,
    bio,
    role: 'user',                  // server-controlled
    tenantId: session.tenantId,    // from session
  },
});
```

- **PRI-MA-3** Updates more dangerous than creates — an attacker can flip flags on their own record (e.g., `data: { isVerified: true }`).
- **PRI-MA-4** Nested writes via `create` and `connect` — `data: { posts: { create: { ... } } }` — also subject to mass assignment if user controls the nested object.

#### IDOR — missing scoping in queries

Prisma doesn't auto-scope. Every `findUnique` / `findFirst` / `findMany` / `update` / `delete` must include ownership check.

- **PRI-IDOR-1** `findUnique({ where: { id: req.params.id } })` — finds any record by id. If returned to user, IDOR.
- **PRI-IDOR-2** `update({ where: { id: req.params.id }, data: ... })` — same; updates any record.
- **PRI-IDOR-3** Correct pattern: compound where:
  ```ts
  // BAD
  await prisma.invoice.findUnique({ where: { id: invoiceId } });
  
  // GOOD
  await prisma.invoice.findFirst({
    where: { id: invoiceId, tenantId: session.tenantId },
  });
  ```
  Note: `findUnique` requires the where to be a unique identifier; if you need a compound where with non-unique fields, use `findFirst`. For Prisma 5+: use `findUniqueOrThrow` / `findFirstOrThrow` for safer error handling.

- **PRI-IDOR-4** `findMany` without where → returns all rows. Always pass a tenant filter at minimum.
- **PRI-IDOR-5** Bulk operations (`updateMany`, `deleteMany`) — same scoping rule. `prisma.post.updateMany({ where: { authorId: session.userId }, data: ... })`.

#### Soft delete and visibility

- **PRI-SD-1** Soft-delete columns (e.g., `deletedAt`) — queries don't automatically filter; add `deletedAt: null` to every where. Or use Prisma Client Extensions / middleware to apply globally.
- **PRI-SD-2** Tombstone records returned to clients leak existence of deleted resources.

#### Sensitive fields in responses

- **PRI-RES-1** `passwordHash`, `mfaSecret`, `apiKeyHash`, billing details, internal flags — never returned to clients. Use `select` to explicitly choose returned fields, or define DTO projections.
  ```ts
  // BAD — returns whole user including passwordHash
  const user = await prisma.user.findUnique({ where: { id } });
  return user;
  
  // GOOD
  const user = await prisma.user.findUnique({
    where: { id },
    select: { id: true, displayName: true, email: true, createdAt: true },
  });
  ```
- **PRI-RES-2** Prisma Client Extensions can define safe-by-default projections; check for an extension that filters sensitive fields on `findMany` / `findFirst`.

#### Database connection and secrets

- **PRI-DB-1** `DATABASE_URL` not in client-side code or `VITE_`/`NEXT_PUBLIC_` env vars.
- **PRI-DB-2** Connection pool limits set (`?connection_limit=N` in URL or via `datasource` config) — unbounded connections become DoS surface.
- **PRI-DB-3** SSL required in production (`?sslmode=require` or `?sslmode=verify-full`).
- **PRI-DB-4** Read replicas use the read-only role; not the migration-capable role.
- **PRI-DB-5** Prisma Migrate's shadow database not on the production cluster (separate db needed for migrate dev / migrate diff).

#### Schema-level concerns

Open `schema.prisma`:

- **PRI-SCH-1** Foreign keys defined (`onDelete: Cascade` / `Restrict` / `SetNull`) — orphaned records become security issues (e.g., a post for a deleted user with a stale `authorId`).
- **PRI-SCH-2** Required relations marked correctly — optional relations (`?`) often hide cases where the application assumed presence.
- **PRI-SCH-3** Indexes on columns used in WHERE — performance, but also DoS prevention (unindexed query on large table → table scan → resource exhaustion).
- **PRI-SCH-4** Unique constraints on identifier columns (`@unique` on `email`, `slug`, etc.) — without them, race conditions allow duplicates with security implications.
- **PRI-SCH-5** Multi-tenant schemas: tenant_id columns on every shared table; foreign-key composite indexes including `tenant_id`.
- **PRI-SCH-6** `@db.Text` / `@db.VarChar(N)` — large unbounded text columns enable DoS via huge writes.

#### Prisma extensions and middleware

Use of Client Extensions / deprecated `$use` middleware can implement cross-cutting controls:

- **PRI-EXT-1** Tenant-scoping extension that auto-injects `tenantId` filter — good defense-in-depth.
- **PRI-EXT-2** Logging extension that doesn't log sensitive fields (Prisma `log` levels include query and params — confirm not enabled in production for queries containing PII).
- **PRI-EXT-3** Soft-delete extension applied to all relevant models.

#### Prisma Accelerate / Data Proxy

- **PRI-ACC-1** Prisma Accelerate uses a connection string with API key. Treat as a secret; rotate periodically; restrict by project.
- **PRI-ACC-2** Accelerate caching — confirm cache strategy doesn't share between tenants. The `cacheStrategy` is opt-in per query; ensure tenant context is in cache key.
- **PRI-ACC-3** Edge runtime use (Vercel Edge, Cloudflare Workers) requires Accelerate or Data Proxy; verify the Edge bundle doesn't ship the direct DATABASE_URL.

#### Migrations

- **PRI-MIG-1** Migrations applied via CI/CD with limited credentials (not the runtime app credential).
- **PRI-MIG-2** Destructive migrations gated by approval; reviewed for accidental column drops on populated tables.
- **PRI-MIG-3** `prisma db push` for production = bad practice (skips migration history).

### Phase 4: Triage

Critical class examples:
- `$queryRawUnsafe` with user-concatenated input
- `data: { ...req.body }` on user-self updates including admin flags
- Every `findFirst` / `update` / `delete` missing tenant scope
- Returning whole user records including password hashes

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `PRI-`.

## References

- `references/raw-query-safety.md` — Detailed `$queryRaw` vs `$queryRawUnsafe` patterns and Prisma.sql composition
