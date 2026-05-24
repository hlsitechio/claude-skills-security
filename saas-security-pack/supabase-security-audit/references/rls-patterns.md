# RLS Patterns Reference

Load this when designing or auditing row-level security policies in Supabase / Postgres.

## The mental model

RLS in Postgres adds an implicit `WHERE` clause to every query that touches a table, based on the policies defined for the current role and operation. The clause is non-bypassable from SQL (except by table owner or `BYPASSRLS` role).

Two important things to internalize:

1. **RLS is enabled per-table** (`ALTER TABLE foo ENABLE ROW LEVEL SECURITY`) and **separately enforced** (`FORCE ROW LEVEL SECURITY` makes it apply even to the table owner). Without `FORCE`, the owner role bypasses.
2. **Policies are additive within "permissive" and AND-combined with "restrictive"**. Multiple permissive policies OR together. A restrictive policy must also pass.

```sql
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
-- Optional but recommended for sensitive tables:
ALTER TABLE invoices FORCE ROW LEVEL SECURITY;
```

## The "RLS enabled but no policies" gotcha

```sql
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
-- ... no policies defined
SELECT * FROM invoices;  -- returns 0 rows for non-owners
```

Once RLS is enabled, **the default is deny**. No policies = no access (for non-owners). The audit should flag tables in this state and confirm intent — often, the team enabled RLS and forgot to add policies, breaking the app for users.

## Good policies — by access pattern

### Self-ownership

```sql
-- Users can read their own profile
CREATE POLICY "self_read"
  ON profiles FOR SELECT
  TO authenticated
  USING (auth.uid() = id);

-- Users can update their own profile
CREATE POLICY "self_update"
  ON profiles FOR UPDATE
  TO authenticated
  USING (auth.uid() = id)
  WITH CHECK (auth.uid() = id);
```

`USING` filters which rows the operation sees (read access for SELECT/UPDATE/DELETE).
`WITH CHECK` validates rows after modification (write access for INSERT/UPDATE).
For UPDATE: both clauses matter — `USING` says which rows you can touch, `WITH CHECK` says what the result can look like.

### Team / shared resource

```sql
-- Read documents where I'm a team member
CREATE POLICY "team_member_read"
  ON documents FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM team_members tm
      WHERE tm.team_id = documents.team_id
        AND tm.user_id = auth.uid()
    )
  );
```

### Role-based

Store the user's role in JWT custom claims, then:

```sql
CREATE POLICY "admin_full_access"
  ON sensitive_table FOR ALL
  TO authenticated
  USING (auth.jwt()->>'role' = 'admin')
  WITH CHECK (auth.jwt()->>'role' = 'admin');
```

For Supabase, custom claims go in `raw_app_meta_data` (set server-side, read via JWT) — never `raw_user_meta_data` (user-controllable).

### Tenant scoping

```sql
-- The fundamental multi-tenant policy
CREATE POLICY "tenant_isolation"
  ON projects FOR ALL
  TO authenticated
  USING (tenant_id = (auth.jwt()->>'tenant_id')::uuid)
  WITH CHECK (tenant_id = (auth.jwt()->>'tenant_id')::uuid);
```

Every multi-tenant table should have this pattern (or equivalent). See also `saas-tenant-isolation/SKILL.md`.

## Common bad policies

### Bad: `using (true)` on user data

```sql
-- ⚠ This exposes everything to authenticated users
CREATE POLICY "any_authenticated"
  ON invoices FOR SELECT
  TO authenticated
  USING (true);
```

Sometimes used as a placeholder, sometimes "we'll add the check later". Either way: finding.

### Bad: forgetting `WITH CHECK` on INSERT/UPDATE

```sql
CREATE POLICY "owner_update"
  ON profiles FOR UPDATE
  TO authenticated
  USING (auth.uid() = id);
  -- missing WITH CHECK
```

The user can read only their own row (good), but the `UPDATE` can rewrite the `id` column to someone else's UUID — and the modified row no longer matches `USING`, so the user just transferred ownership. The audit should flag any UPDATE policy missing `WITH CHECK`.

### Bad: trusting client-controllable claims

```sql
-- ⚠ raw_user_meta_data is set by the user during signup; they control it
USING (auth.jwt()->'user_metadata'->>'role' = 'admin')
```

Use `raw_app_meta_data` (server-controlled) and JWT claim from server-set metadata. In Supabase, that's `auth.jwt()->>'role'` if you've set up app_metadata.role through admin tooling.

### Bad: subqueries bypassing RLS

```sql
-- If `teams` has RLS but this subquery is in a SECURITY DEFINER function,
-- the subquery may bypass `teams` RLS, leaking team membership.
USING (
  team_id IN (SELECT id FROM teams WHERE owner = auth.uid())
)
```

Subqueries inherit the current execution context. In a normal policy this is fine. In a `SECURITY DEFINER` function, it switches to the function owner's context — which usually bypasses RLS. Audit cross-referenced tables when policies use subqueries.

### Bad: same policy name across operations

```sql
-- Two separate policies, both permissive, OR-combined:
CREATE POLICY "p1" ON t FOR SELECT TO authenticated USING (auth.uid() = owner);
CREATE POLICY "p1_admin" ON t FOR SELECT TO authenticated USING (auth.jwt()->>'role' = 'admin');
-- Together: owner OR admin (intended)
```

That's fine. But:

```sql
CREATE POLICY "p1" ON t FOR ALL TO authenticated USING (auth.uid() = owner);
CREATE POLICY "p1_admin" ON t FOR ALL TO authenticated USING (true);
-- Together: any authenticated user, because p1_admin is permissive and = true
```

That's a bug. Either make `p1_admin` restrictive, or scope it (`role = 'admin'`).

### Bad: SELECT works, INSERT doesn't

```sql
-- The team enabled RLS, wrote a SELECT policy, never wrote INSERT
ALTER TABLE comments ENABLE ROW LEVEL SECURITY;
CREATE POLICY "read_own" ON comments FOR SELECT TO authenticated USING (auth.uid() = user_id);
-- No INSERT policy → INSERTs fail silently
```

The audit lists policy coverage per operation and flags tables where the app probably needs INSERT/UPDATE/DELETE but no policy exists.

## Verification queries

### List RLS status per table

```sql
SELECT
  n.nspname AS schema,
  c.relname AS table,
  c.relrowsecurity AS rls_enabled,
  c.relforcerowsecurity AS rls_forced,
  COUNT(p.polname) AS policy_count
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_policy p ON p.polrelid = c.oid
WHERE c.relkind = 'r'
  AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
GROUP BY n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity
ORDER BY n.nspname, c.relname;
```

### List policies per table

```sql
SELECT
  schemaname,
  tablename,
  policyname,
  permissive,        -- PERMISSIVE or RESTRICTIVE
  roles,
  cmd,               -- SELECT, INSERT, UPDATE, DELETE, ALL
  qual AS using_clause,
  with_check
FROM pg_policies
ORDER BY schemaname, tablename, policyname;
```

### Test a policy as a specific user

```sql
-- In SQL editor, switch role + impersonate a JWT
SET ROLE authenticated;
SET request.jwt.claims = '{"sub": "USER-UUID-HERE", "role": "authenticated"}';
SELECT * FROM invoices;   -- now scoped by RLS
RESET ROLE;
RESET request.jwt.claims;
```

## Performance notes — out of scope but worth knowing

RLS policies with subqueries can be expensive. Wrap functions used in policies with `STABLE` and consider `(SELECT auth.uid())` (subquery) instead of `auth.uid()` (function call) in performance-critical policies — Postgres optimizes the subquery once per query rather than per row in some configurations.

This is a perf concern, not a security concern, but the audit should mention it if the policy patterns look query-killer.

## Default-deny template

When adding a new table, start from this template (also in `assets/rls-template.sql`):

```sql
ALTER TABLE new_table ENABLE ROW LEVEL SECURITY;
ALTER TABLE new_table FORCE ROW LEVEL SECURITY;

-- Explicitly: no one accesses by default. Then add specific policies.
-- Example: owner-only read.
CREATE POLICY "owner_read"
  ON new_table FOR SELECT
  TO authenticated
  USING (auth.uid() = owner_id);

CREATE POLICY "owner_write"
  ON new_table FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "owner_update"
  ON new_table FOR UPDATE
  TO authenticated
  USING (auth.uid() = owner_id)
  WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "owner_delete"
  ON new_table FOR DELETE
  TO authenticated
  USING (auth.uid() = owner_id);

-- No grant to anon. Explicit grant to authenticated for the operations needed.
GRANT SELECT, INSERT, UPDATE, DELETE ON new_table TO authenticated;
```
