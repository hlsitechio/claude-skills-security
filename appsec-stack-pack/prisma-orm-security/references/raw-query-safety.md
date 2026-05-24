# Prisma Raw Query Safety Reference

Load this when reviewing `$queryRaw` / `$executeRaw` / `$queryRawUnsafe` / `$executeRawUnsafe` calls in a Prisma codebase.

## The four functions

| Function | Safe? | Use for |
|----------|-------|---------|
| `prisma.$queryRaw\`...\`` (tagged template) | ✓ Safe | Reads with user input |
| `prisma.$executeRaw\`...\`` (tagged template) | ✓ Safe | Writes with user input |
| `prisma.$queryRawUnsafe(string, ...args)` | ⚠ Conditional | Reads where structure (table name, column) is dynamic |
| `prisma.$executeRawUnsafe(string, ...args)` | ⚠ Conditional | Writes where structure is dynamic |

The "Unsafe" suffix is honest: the function takes a plain string and concatenates whatever you give it. Args are passed separately and can be parameterized via `$1`, `$2` placeholders — but the burden is on you to use them correctly.

## Tagged template — the safe path

```ts
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

// SAFE — `${userId}` is automatically parameterized
const users = await prisma.$queryRaw<User[]>`
  SELECT id, email, display_name
  FROM "User"
  WHERE id = ${userId}
`;

// SAFE
await prisma.$executeRaw`
  UPDATE "Post"
  SET view_count = view_count + 1
  WHERE id = ${postId}
`;
```

Behind the scenes, Prisma converts the tagged template to a parameterized query: `SELECT ... WHERE id = $1` with `userId` as `$1`. No SQL injection possible from `${...}` interpolations.

## When tagged template can't do it

Tagged templates can only parameterize values, not identifiers (table names, column names, ORDER BY). For dynamic structure:

```ts
// CANNOT use tagged template for table name
const tableName = 'Post';   // attacker-controlled? danger
const rows = await prisma.$queryRaw`SELECT * FROM ${tableName}`;   // ⚠ this DOESN'T work as expected;
// Prisma will pass tableName as a parameter, but PostgreSQL won't accept a parameter for table name → error
```

You need `$queryRawUnsafe` for dynamic structure, BUT validate the structure strictly first:

```ts
const ALLOWED_TABLES = new Set(['Post', 'Comment', 'Tag']);

if (!ALLOWED_TABLES.has(tableName)) {
  throw new Error('Invalid table name');
}

const rows = await prisma.$queryRawUnsafe(
  `SELECT * FROM "${tableName}" WHERE id = $1`,
  rowId   // parameterized
);
```

The unsafe call concatenates `tableName` (which you've allowlisted), and parameterizes `rowId` via `$1`.

## Composition with `Prisma.sql` and `Prisma.join`

For dynamic WHERE clauses, ORDER BY, or other composed SQL:

```ts
import { Prisma } from '@prisma/client';

// Build a dynamic WHERE
const conditions: Prisma.Sql[] = [];

if (filters.status) {
  conditions.push(Prisma.sql`status = ${filters.status}`);
}
if (filters.authorId) {
  conditions.push(Prisma.sql`author_id = ${filters.authorId}`);
}
if (filters.createdAfter) {
  conditions.push(Prisma.sql`created_at > ${filters.createdAfter}`);
}

const whereClause = conditions.length
  ? Prisma.sql`WHERE ${Prisma.join(conditions, ' AND ')}`
  : Prisma.empty;

const posts = await prisma.$queryRaw<Post[]>`
  SELECT * FROM "Post"
  ${whereClause}
  ORDER BY created_at DESC
  LIMIT 100
`;
```

`Prisma.sql` returns a typed SQL fragment. `Prisma.join` concatenates with a separator. Both keep values parameterized.

## Dynamic ORDER BY safely

```ts
const ALLOWED_SORT_FIELDS = ['createdAt', 'updatedAt', 'title'] as const;
type SortField = typeof ALLOWED_SORT_FIELDS[number];

function safeSort(field: string, dir: string) {
  if (!ALLOWED_SORT_FIELDS.includes(field as SortField)) {
    throw new Error('Invalid sort field');
  }
  const sortDir = dir.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';
  // Note: we're using `Prisma.raw` which IS unsafe but with strictly validated input
  return Prisma.raw(`"${field}" ${sortDir}`);
}

const posts = await prisma.$queryRaw<Post[]>`
  SELECT * FROM "Post"
  ORDER BY ${safeSort(req.query.sort, req.query.dir)}
`;
```

`Prisma.raw` inserts a string literally — only use with allowlisted values.

## Dynamic LIMIT / OFFSET

These ARE parameterizable in Postgres:

```ts
const limit = Math.min(parseInt(req.query.limit ?? '20', 10), 100);
const offset = Math.max(parseInt(req.query.offset ?? '0', 10), 0);

const posts = await prisma.$queryRaw<Post[]>`
  SELECT * FROM "Post"
  ORDER BY created_at DESC
  LIMIT ${limit}
  OFFSET ${offset}
`;
```

But always coerce to int and cap at a sensible max. Unbounded LIMIT can be a DoS.

## Common bugs to flag

### Bug 1 — String interpolation in `$queryRawUnsafe`

```ts
// CRITICAL — full SQL injection
const search = req.query.q;
await prisma.$queryRawUnsafe(
  `SELECT * FROM "Post" WHERE title LIKE '%${search}%'`
);
```

Fix: parameterize.

```ts
await prisma.$queryRawUnsafe(
  `SELECT * FROM "Post" WHERE title LIKE $1`,
  `%${search}%`
);
// or use tagged template
await prisma.$queryRaw`SELECT * FROM "Post" WHERE title LIKE ${`%${search}%`}`;
```

### Bug 2 — Trusting Prisma to escape what it can't

```ts
const direction = req.query.dir;   // 'ASC' / 'DESC' / arbitrary
await prisma.$queryRaw`SELECT * FROM "Post" ORDER BY created_at ${direction}`;
```

Prisma parameterizes `${direction}` as a value, which won't work in this position. Result: query fails, OR (in older Prisma versions / different setups) raw injection.

Fix: allowlist direction explicitly (see "Dynamic ORDER BY safely" above).

### Bug 3 — Missing tenant scope in raw query

```ts
// Code uses raw query and forgets the tenant filter that the ORM would normally enforce
const projects = await prisma.$queryRaw<Project[]>`
  SELECT * FROM "Project" WHERE id = ${projectId}
`;
```

Raw queries bypass any Prisma extensions that auto-scope. Add the tenant clause:

```ts
const projects = await prisma.$queryRaw<Project[]>`
  SELECT * FROM "Project"
  WHERE id = ${projectId}
    AND tenant_id = ${session.tenantId}
`;
```

### Bug 4 — Using raw queries to bypass RLS in Postgres

If the database has Row-Level Security policies, `prisma.$queryRaw` runs with the application's connection user. If that user has BYPASSRLS, the raw query also bypasses. If you're using Postgres RLS as a security layer, the application connection should NOT have BYPASSRLS (use a separate migration user with privileges).

### Bug 5 — Mixed parameter and string concat

```ts
await prisma.$queryRawUnsafe(
  `SELECT * FROM "Post" WHERE author_id = ${userId} AND status = $1`,
  status
);
```

`userId` is concatenated; `status` is parameterized. Inconsistent. The `userId` opens injection.

Fix: parameterize both.

```ts
await prisma.$queryRawUnsafe(
  `SELECT * FROM "Post" WHERE author_id = $1 AND status = $2`,
  userId, status
);
```

## Return types

Prisma `$queryRaw` returns rows as `unknown` by default. The generic parameter `<T>` is a TYPE assertion — Prisma doesn't validate at runtime.

```ts
const result = await prisma.$queryRaw<User[]>`SELECT * FROM "User"`;
// result is typed as User[] but Prisma does no runtime check
```

If the SQL returns columns that don't match `User`, runtime errors happen later. Use Zod or similar to validate the shape:

```ts
const UserRowSchema = z.array(z.object({
  id: z.string().uuid(),
  email: z.string().email(),
  display_name: z.string(),
}));

const raw = await prisma.$queryRaw`SELECT id, email, display_name FROM "User"`;
const result = UserRowSchema.parse(raw);
```

Type assertion + runtime validation = safe.

## Audit checklist for raw queries

For each call to `$queryRaw*` / `$executeRaw*`:

1. Is it tagged template or `Unsafe` variant?
2. If `Unsafe`, are all user-controlled values passed via `$1, $2, ...` parameters?
3. If structure is dynamic (table name, column, ORDER BY direction), is it allowlisted from a closed set?
4. Is the tenant / ownership filter present?
5. Are sensitive columns (passwords, secrets) excluded from SELECT?
6. Is the return type validated at runtime via Zod / similar?

If any answer is "no", document the finding.
