# Tenant Query Scoping Reference

Load this when reviewing how application code constructs queries against a multi-tenant database.

## The fundamental rule

Every query against a tenant-scoped table includes a `WHERE tenant_id = $X` clause where `$X` originates from the authenticated session. Not from the request body. Not from a URL parameter. Not from a JWT claim that the user could rotate.

This rule applies to:
- Direct SQL
- ORM queries
- GraphQL resolvers
- Stored procedure calls
- Materialized view reads

## Patterns to enforce the rule

### Pattern 1 — Repository layer wraps the filter

Best for codebases that use a repository / data-access object pattern.

```ts
class ProjectRepository {
  constructor(private tenantId: string) {
    if (!tenantId) throw new Error('TenantId required for repository');
  }

  async findById(id: string) {
    return db.query(
      `SELECT * FROM projects WHERE id = $1 AND tenant_id = $2`,
      [id, this.tenantId]
    );
  }

  async list(filter: ProjectFilter) {
    return db.query(
      `SELECT * FROM projects WHERE tenant_id = $1 AND status = $2 LIMIT 100`,
      [this.tenantId, filter.status]
    );
  }
}

// In the request pipeline:
const repo = new ProjectRepository(req.session.tenantId);
const project = await repo.findById(projectId);
```

The repository constructor refuses to operate without a tenant ID. No method exposes a way to bypass.

### Pattern 2 — ORM default scope

For ORMs that support hooks (Sequelize, TypeORM, Rails ActiveRecord, Django, SQLAlchemy with events):

```python
# SQLAlchemy event listener
@event.listens_for(Session, "do_orm_execute")
def _tenant_filter(state):
    if state.is_select and not state.is_relationship_load:
        tenant_id = get_current_tenant()
        if tenant_id is None and not state.execution_options.get('admin'):
            raise RuntimeError("No tenant context set")
        state.statement = state.statement.options(
            with_loader_criteria(TenantScoped, lambda cls: cls.tenant_id == tenant_id)
        )
```

```ruby
# Rails default_scope
class Project < ApplicationRecord
  default_scope { where(tenant_id: Current.tenant_id) if Current.tenant_id }
end
```

Default scopes apply automatically to every query. Code that needs admin/cross-tenant access uses `.unscoped` explicitly — which the audit greps for to find every cross-tenant code path.

### Pattern 3 — Database-side enforcement (RLS)

In Postgres, set a session variable per request and let RLS enforce it:

```sql
-- One-time policy setup
CREATE POLICY "tenant_isolation" ON projects
  FOR ALL TO app_user
  USING (tenant_id = current_setting('app.tenant_id')::uuid);
```

```ts
// Per-request, set the variable
await db.query(`SET LOCAL app.tenant_id = $1`, [req.session.tenantId]);
// All subsequent queries in this transaction are RLS-filtered
```

Critical: use `SET LOCAL` (transaction-scoped) not `SET` (session-scoped). Connection pools reuse connections; a non-LOCAL setting leaks to the next request.

This is the strongest defense — even if app code forgets the filter, the DB refuses to return cross-tenant rows. But it requires careful pool management. See `supabase-security-audit/references/rls-patterns.md`.

### Pattern 4 — Schema-per-tenant

Each tenant has a Postgres schema (or MySQL database). Set search_path per connection.

```ts
await db.query(`SET search_path TO ${escapedTenantSchema}, public`);
```

Risks:
- Connection pool poisoning if search_path persists.
- Schema name validation must be strict (else SQL injection via tenant identifier).
- Admin tooling that lists all tenants must enumerate schemas carefully.

This model scales worse than shared-schema once you exceed ~1000 tenants but offers very strong isolation.

## Anti-patterns to flag

### Anti-pattern A — Tenant ID from request body

```ts
app.post('/projects', async (req, res) => {
  const { tenantId, ...data } = req.body;        // ⚠ client-controlled
  await db.query(
    'INSERT INTO projects (tenant_id, ...) VALUES ($1, ...)',
    [tenantId, ...]
  );
});
```

User can pass any tenant ID and write into other tenants. Always derive tenant ID from the session.

### Anti-pattern B — Tenant ID from URL but not verified

```ts
app.get('/tenants/:tenantId/projects', requireAuth, async (req, res) => {
  // ⚠ uses req.params.tenantId without checking the session is in that tenant
  const projects = await db.query(
    'SELECT * FROM projects WHERE tenant_id = $1',
    [req.params.tenantId]
  );
});
```

URL-scoped routes (`/tenants/:tenantId/...`) are common and useful, but the handler must verify `req.session.tenantId === req.params.tenantId` (or that the user has access to that tenant).

### Anti-pattern C — Forgotten WHERE on a list endpoint

```sql
-- Returns ALL projects, not just the user's tenant
SELECT * FROM projects ORDER BY created_at DESC LIMIT 50;
```

Easy to write, devastating in production. The default-scope pattern (Pattern 2) prevents this.

### Anti-pattern D — Cross-tenant join

```sql
-- Tenant filter on projects, but the join to comments isn't scoped
SELECT p.*, c.*
FROM projects p
LEFT JOIN comments c ON c.project_id = p.id
WHERE p.tenant_id = $1;
```

If `comments.project_id` references a different tenant's project (which shouldn't happen, but data integrity bugs do), comments leak across. Add `AND c.tenant_id = p.tenant_id` defensively.

### Anti-pattern E — `IN (subquery)` without scoping inner query

```sql
-- Inner query not tenant-scoped
SELECT * FROM tasks
WHERE project_id IN (SELECT id FROM projects WHERE active = true)
  AND tenant_id = $1;
```

The outer `tenant_id` filter restricts which tasks are returned, but the subquery returns all active projects' IDs across tenants. If any task's `project_id` matches another tenant's project, that task is included.

Fix: scope the subquery too.

```sql
SELECT * FROM tasks
WHERE project_id IN (SELECT id FROM projects WHERE active = true AND tenant_id = $1)
  AND tenant_id = $1;
```

### Anti-pattern F — Single connection across multiple requests

If a connection pool checks a connection out for request A, sets `SET app.tenant_id = A`, then checks it back in without resetting, the next request might inherit it. Use `SET LOCAL` (transaction-scoped) or explicitly RESET after the request.

### Anti-pattern G — Sequence ID reuse

If two tenants share an auto-incrementing ID space, knowing one tenant's record IDs hints at the existence of other tenants' records. Mitigation: UUIDs (don't enumerate), or per-tenant sequences (more complex).

## Cross-tenant admin paths

Some operations legitimately span tenants:
- Admin dashboards
- Customer support tooling
- Migrations and data backfills
- Cross-tenant analytics

For each such code path:
1. Require an admin role explicitly.
2. Log the access with `who, when, what, why`.
3. Use a distinct code path that doesn't share helpers with normal user code (so the user code can keep its strict tenant filter without exceptions).
4. Time-limit and rate-limit admin sessions.

```ts
// Distinct admin repository
class AdminProjectRepository {
  async findById(id: string) {
    await auditLog('admin_query', { resource: 'project', id });
    return db.query(`SELECT * FROM projects WHERE id = $1`, [id]);
  }
}
```

## Review checklist for each repo/service

1. Identify the tenant ID source for each request (claim, header, subdomain).
2. Identify every data-access layer (repository, ORM, raw queries).
3. Confirm tenant filter is applied at the layer, not at the call site.
4. Run grep for `tenant_id` filter in every query helper; review exceptions.
5. Search for `unscoped`, `bypass`, `raw query`, `.query(`, `db.query`, `client.query` — review each for tenant scoping.
6. Confirm RLS or DB-side equivalent is enabled.
7. Confirm connection pool resets tenant context between requests.
8. Confirm admin paths are separated and logged.
9. Run cross-tenant integration test in staging.
