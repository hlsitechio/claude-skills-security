# Anon and Authenticated Role Grants Reference

Load this when reviewing what `anon` and `authenticated` roles can do in a Supabase project.

## The role model

Supabase exposes three Postgres roles to the outside world via PostgREST and the supabase-js client:

| Role | Identity | Use |
|------|----------|-----|
| `anon` | Unauthenticated requests (apikey only, no Authorization Bearer) | Public-read content, sign-up flows, public landing pages |
| `authenticated` | Requests with a valid JWT in `Authorization: Bearer ...` | Most application traffic |
| `service_role` | The service_role API key | Server-side admin tasks; bypasses RLS |

`postgres` and other internal roles exist but aren't exposed via the API.

`anon` and `authenticated` both go through PostgREST, which respects RLS. `service_role` bypasses RLS — never expose it to clients.

## What `anon` should have

In a typical SaaS:

- `SELECT` on tables explicitly intended for public read (e.g., a `posts` table with a `published = true` policy that doesn't otherwise leak PII).
- `EXECUTE` on functions designed for unauthenticated access (sign-up, public read, public form submissions).
- Nothing else.

Specifically, `anon` should **not** have:
- INSERT/UPDATE/DELETE on tables with user data (route through a `SECURITY DEFINER` function that performs validation).
- SELECT on user tables, audit logs, or anything containing PII even with RLS — defense in depth means revoking the grant entirely.
- Access to internal schemas (`auth`, `storage`, `pg_*`, `supabase_*`).

## What `authenticated` should have

- `SELECT, INSERT, UPDATE, DELETE` on user-data tables — but with RLS doing the actual filtering.
- `EXECUTE` on authenticated-only functions.
- `USAGE, SELECT` on sequences for tables they can INSERT into (otherwise INSERTs fail).

Grants here are coarse-grained intentionally; the fine-grained access control is RLS.

## Common findings

### Finding: `anon` has SELECT on a sensitive table

```sql
-- Inventory query
SELECT grantee, table_schema, table_name, privilege_type
FROM information_schema.role_table_grants
WHERE grantee IN ('anon')
  AND table_schema NOT IN ('information_schema', 'pg_catalog');
```

Each result that exposes user data, audit data, or PII is a finding. Severity:
- Anonymous access to PII/PHI/payment data → Critical
- Anonymous access to user emails (even hashed) → High
- Anonymous access to internal IDs (UUIDs of users) → Medium

Even if RLS is enabled and policies restrict to "published" rows, having the grant gives a much larger attack surface. Revoke the grant; add it back narrowly only if needed.

### Finding: grant to `PUBLIC` instead of specific role

```sql
GRANT EXECUTE ON FUNCTION public.do_thing() TO PUBLIC;
-- ⚠ "PUBLIC" means every current AND future role, including future internal Supabase roles
```

Should be:

```sql
REVOKE EXECUTE ON FUNCTION public.do_thing() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.do_thing() TO authenticated;
```

Inventory:

```sql
SELECT routine_schema, routine_name, grantee
FROM information_schema.routine_privileges
WHERE grantee = 'PUBLIC'
  AND routine_schema NOT IN ('pg_catalog', 'information_schema');
```

### Finding: `anon` has INSERT without intent

```sql
-- "We accept guest submissions"
GRANT INSERT ON public.contact_form TO anon;
-- But no RLS check; anon can write any row, including spoofing user_id, tenant_id
```

Two valid patterns:

**Pattern A** — RLS validates the insert:
```sql
CREATE POLICY "anon_can_insert_with_constraints"
  ON public.contact_form FOR INSERT
  TO anon
  WITH CHECK (
    user_id IS NULL         -- anon can't pretend to be a user
    AND length(message) <= 5000
    AND length(email) <= 320
  );
```

**Pattern B** — Route through a SECURITY DEFINER function:
```sql
CREATE FUNCTION public.submit_contact_form(p_email text, p_message text)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_id uuid;
BEGIN
  -- Validate
  IF p_email !~ '^[^@]+@[^@]+\.[^@]+$' THEN
    RAISE EXCEPTION 'invalid email';
  END IF;
  IF length(p_message) > 5000 THEN
    RAISE EXCEPTION 'message too long';
  END IF;
  -- Rate limit (illustrative; consider an external mechanism)
  -- ...
  INSERT INTO public.contact_form(email, message)
  VALUES (p_email, p_message)
  RETURNING id INTO v_id;
  RETURN v_id;
END;
$$;
REVOKE INSERT ON public.contact_form FROM anon;
GRANT EXECUTE ON FUNCTION public.submit_contact_form(text, text) TO anon;
```

Pattern B is preferable when the operation has validation logic, rate limiting, or side effects — it centralizes the policy and avoids hand-tuning RLS for write paths.

## Sequence grants — the silent failure

When granting `INSERT` to a role on a table with a `serial`/`bigserial`/`uuid_generate_v4()` default, the role also needs `USAGE` on the underlying sequence (for `serial`-class) — otherwise inserts fail with a permission error.

```sql
GRANT INSERT ON public.tickets TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE public.tickets_id_seq TO authenticated;
```

For UUID primary keys generated by `gen_random_uuid()` or `uuid_generate_v4()`, no sequence grant is needed. But for legacy schemas with `serial`, this is a frequent debugging trap.

## What `service_role` does

`service_role`:
- Bypasses RLS.
- Has all table privileges in `public` and most extension schemas.
- Should never appear in a browser, mobile bundle, or public repo.

Audit:

```bash
# In the codebase, search for any of these patterns:
grep -rE "SUPABASE_SERVICE_ROLE_KEY|service_role|sb_secret_" \
  --include="*.{ts,tsx,js,jsx,vue,svelte,py,go,rb,php}" \
  src/ public/ pages/ app/ 2>/dev/null
```

Any match in client-side files (anything bundled to the browser or shipped in a mobile binary) is a Critical finding.

Where service_role IS appropriate:
- Server-side API routes (Next.js API routes, Remix loaders, custom Node/Python servers).
- Supabase Edge Functions that explicitly need to bypass RLS (rare; document why).
- Backend admin tooling.
- CI/CD scripts that migrate or seed data.

## Reviewing grants holistically

Use this query to dump the entire grant surface for `anon` and `authenticated`:

```sql
-- See scripts/anon_grants_report.sql for the full version
SELECT grantee, table_schema, table_name, privilege_type
FROM information_schema.role_table_grants
WHERE grantee IN ('anon', 'authenticated')
  AND table_schema NOT IN ('information_schema', 'pg_catalog')
ORDER BY grantee, table_schema, table_name, privilege_type;
```

Then for each grant on `anon`, ask: "Is this table genuinely meant to be public?" Reject anything that looks like user data, audit data, billing data, or internal infrastructure.

## Migration template for an over-grant

When you find `anon` has too many grants:

```sql
BEGIN;

-- Step 1: revoke everything from anon
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM anon;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM anon;

-- Step 2: re-grant exactly what's intended
GRANT SELECT ON public.published_posts TO anon;
GRANT EXECUTE ON FUNCTION public.submit_contact_form(text, text) TO anon;

-- Step 3: test in a staging environment before COMMIT
-- ROLLBACK; -- if anything looks wrong

COMMIT;
```

Always do this in a transaction, test in staging first, and have a rollback plan. Revoking too much breaks the app; over-granting was the original problem.
