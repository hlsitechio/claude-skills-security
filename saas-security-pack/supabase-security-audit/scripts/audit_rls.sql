-- audit_rls.sql
-- Lists every table in non-system schemas with RLS status, force flag, and policy count.
-- Run in Supabase SQL editor. Read-only.

SELECT
  n.nspname                                AS schema,
  c.relname                                AS table_name,
  c.relrowsecurity                         AS rls_enabled,
  c.relforcerowsecurity                    AS rls_forced,
  COUNT(p.polname)                         AS policy_count,
  COUNT(p.polname) FILTER (WHERE p.polcmd = 'r') AS select_policies,
  COUNT(p.polname) FILTER (WHERE p.polcmd = 'a') AS insert_policies,
  COUNT(p.polname) FILTER (WHERE p.polcmd = 'w') AS update_policies,
  COUNT(p.polname) FILTER (WHERE p.polcmd = 'd') AS delete_policies,
  COUNT(p.polname) FILTER (WHERE p.polcmd = '*') AS all_policies,
  CASE
    WHEN c.relrowsecurity = false                              THEN '⚠ RLS DISABLED'
    WHEN c.relrowsecurity = true AND COUNT(p.polname) = 0      THEN '⚠ RLS ENABLED, NO POLICIES (deny-all)'
    WHEN c.relrowsecurity = true AND COUNT(p.polname) > 0 AND c.relforcerowsecurity = false
                                                               THEN '~ RLS not forced (owner bypasses)'
    ELSE '✓ OK'
  END AS audit_status
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_policy p ON p.polrelid = c.oid
WHERE c.relkind = 'r'                            -- regular tables only
  AND n.nspname NOT IN (
    'pg_catalog', 'information_schema', 'pg_toast',
    'auth', 'storage', 'supabase_functions',
    'extensions', 'graphql', 'graphql_public',
    'net', 'pgsodium', 'pgsodium_masks', 'realtime', 'vault'
  )
GROUP BY n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity
ORDER BY
  CASE
    WHEN c.relrowsecurity = false THEN 0
    WHEN COUNT(p.polname) = 0     THEN 1
    ELSE 2
  END,
  n.nspname, c.relname;
