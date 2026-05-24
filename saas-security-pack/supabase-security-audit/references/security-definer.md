# SECURITY DEFINER Functions Reference

Load this when auditing Postgres functions in Supabase, especially when the user mentioned `SECURITY DEFINER`, anon role function access, or function-based RLS bypass.

## What SECURITY DEFINER means

A Postgres function can be declared with one of two execution contexts:

| Context | Runs as |
|---------|---------|
| `SECURITY INVOKER` (default) | The role of the caller |
| `SECURITY DEFINER` | The role that created the function |

`SECURITY DEFINER` lets you grant a low-privilege caller (e.g., `anon`) the ability to execute a function that does things they couldn't otherwise do — query tables they don't have grants on, bypass RLS on tables owned by the function's owner.

It is a powerful tool with two common abuse patterns:

1. **Accidental**: developer marks a function DEFINER without understanding the implications, and the function exposes data the caller shouldn't see.
2. **Hijack via search_path**: the function calls another function or operator by short name; an attacker overrides resolution to point to malicious code.

## When `SECURITY DEFINER` is justified

Reasonable use cases:

- A controlled write operation that audits, validates, then writes (e.g., `make_purchase` that checks balance and creates a transaction row atomically).
- Cross-table aggregation that the caller doesn't have grants on but needs read-only access through.
- Auth helper functions that read from `auth.users` (an internal schema).
- Webhook handlers that need to update tables the public role can't touch directly.

Unreasonable use cases:

- "It was easier than fixing the RLS policy" — fix the policy.
- "We didn't want the caller to need grants on the underlying table" — that's a feature of RLS; if grants are scoped right, no DEFINER needed.

## The audit checklist for every SECURITY DEFINER function

### 1. Inventory

```sql
SELECT
  n.nspname AS schema,
  p.proname AS function,
  pg_get_function_arguments(p.oid) AS args,
  CASE WHEN p.prosecdef THEN 'DEFINER' ELSE 'INVOKER' END AS sec,
  pg_get_userbyid(p.proowner) AS owner,
  p.proconfig AS config_settings,
  array_agg(DISTINCT a.privilege_type) FILTER (WHERE a.grantee = 'anon') AS anon_privs,
  array_agg(DISTINCT a.privilege_type) FILTER (WHERE a.grantee = 'authenticated') AS auth_privs
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
LEFT JOIN information_schema.routine_privileges a
  ON a.routine_schema = n.nspname AND a.routine_name = p.proname
WHERE p.prosecdef = true
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
GROUP BY n.nspname, p.proname, p.oid, p.prosecdef, p.proowner, p.proconfig
ORDER BY n.nspname, p.proname;
```

For each function returned:

### 2. Verify `search_path` is set

```sql
-- Inside the function definition, look for:
SET search_path = ''
-- or
SET search_path = pg_catalog, public
```

If absent, the function uses the caller's `search_path`, which the caller controls. An attacker can:

```sql
-- Create a schema "evil" with a function "now()" that drops a table
SET search_path = evil, pg_catalog;
SELECT vulnerable_definer_function();  -- the function calls now(), resolves to evil.now()
```

Every `SECURITY DEFINER` function must set `search_path` explicitly. Fix:

```sql
CREATE OR REPLACE FUNCTION public.do_thing()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''   -- ← critical
AS $$
BEGIN
  -- All references inside must use fully-qualified names from here on
  INSERT INTO public.audit_log(action) VALUES ('thing_done');
END;
$$;
```

With `search_path = ''`, every reference inside the function body must be schema-qualified (`public.table_name`, not `table_name`).

### 3. Verify input authorization

The function runs as a high-privilege role. It must therefore implement its own authorization:

```sql
CREATE OR REPLACE FUNCTION public.transfer_credits(to_user uuid, amount int)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_caller uuid := auth.uid();    -- always derive caller from JWT, not args
BEGIN
  IF v_caller IS NULL THEN
    RAISE EXCEPTION 'authentication required';
  END IF;
  IF amount <= 0 OR amount > 1000 THEN
    RAISE EXCEPTION 'invalid amount';
  END IF;
  IF (SELECT balance FROM public.wallets WHERE user_id = v_caller) < amount THEN
    RAISE EXCEPTION 'insufficient balance';
  END IF;
  -- ... atomic transfer
END;
$$;
```

Audit findings:
- Function doesn't check `auth.uid()` before privileged action → High or Critical
- Function accepts caller ID as an argument (`p_user_id uuid`) and trusts it → Critical (caller impersonation)
- Function does no input validation on amounts, IDs, paths → Medium to High depending on impact

### 4. Verify grants are minimal

```sql
-- Should typically be:
REVOKE ALL ON FUNCTION public.do_thing() FROM public;
GRANT EXECUTE ON FUNCTION public.do_thing() TO authenticated;
-- Or specifically to anon ONLY if it's intended to be publicly callable
```

Anti-patterns:
- `GRANT EXECUTE ... TO public` — grants to everyone forever, including future roles.
- `GRANT EXECUTE ... TO anon` on a function that does anything sensitive — anyone with the project URL can call it.

### 5. Verify return data scope

A DEFINER function that returns `SETOF some_table` effectively bypasses RLS on `some_table` for whoever can call the function. Document why and confirm the function constrains rows internally.

```sql
-- Suspicious: returns all rows of users to anon
CREATE FUNCTION public.list_all_users() RETURNS SETOF public.users
LANGUAGE sql SECURITY DEFINER
AS $$ SELECT * FROM public.users $$;
GRANT EXECUTE ON FUNCTION public.list_all_users() TO anon;

-- Better: returns only the public-facing fields, scoped
CREATE FUNCTION public.list_active_authors()
RETURNS TABLE(id uuid, display_name text)
LANGUAGE sql SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT id, display_name
  FROM public.users
  WHERE is_public = true AND is_active = true
$$;
GRANT EXECUTE ON FUNCTION public.list_active_authors() TO anon;
```

### 6. Side effects audit

If the function performs INSERT/UPDATE/DELETE, check:
- Is the operation idempotent or rate-limited?
- Can it be used as an amplifier (one cheap call → expensive backend op)?
- Does it log who called it (for incident response)?

## Triggers — a related category

Trigger functions also run with elevated privilege when fired by a SECURITY DEFINER context, or have implicit owner privileges in some configurations. Audit the same way: search_path set, no trust in NEW/OLD values for authorization, etc.

## Detection summary

For each SECURITY DEFINER function:

| Check | What you're confirming |
|-------|------------------------|
| `search_path` explicitly set | No function-resolution hijacking |
| `auth.uid()` checked at start (for caller-facing) | Authentication |
| Args validated | No injection / overflow |
| Caller ID derived from JWT, not args | No impersonation |
| Grants minimal (specific role, not public) | Limited attack surface |
| Return data scoped or filtered | No mass data leak |
| Side effects rate-limited/idempotent | No abuse amplifier |
| Audit log entry on sensitive actions | Incident response ready |
