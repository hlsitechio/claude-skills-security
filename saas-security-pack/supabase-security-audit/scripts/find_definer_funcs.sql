-- find_definer_funcs.sql
-- Lists every SECURITY DEFINER function with owner, search_path config, and execute grants.
-- Run in Supabase SQL editor. Read-only.

WITH func_grants AS (
  SELECT
    rp.routine_schema,
    rp.routine_name,
    string_agg(DISTINCT rp.grantee, ', ' ORDER BY rp.grantee) AS grantees
  FROM information_schema.routine_privileges rp
  WHERE rp.privilege_type = 'EXECUTE'
  GROUP BY rp.routine_schema, rp.routine_name
)
SELECT
  n.nspname                                  AS schema,
  p.proname                                  AS function_name,
  pg_get_function_arguments(p.oid)           AS arguments,
  pg_get_userbyid(p.proowner)                AS owner,
  -- search_path config: NULL means caller-controlled (DANGEROUS for DEFINER)
  COALESCE(
    (SELECT cfg FROM unnest(p.proconfig) AS cfg WHERE cfg LIKE 'search_path=%'),
    '⚠ search_path NOT SET'
  )                                          AS search_path_setting,
  COALESCE(g.grantees, '(no explicit grants)') AS execute_grants,
  CASE
    WHEN g.grantees LIKE '%anon%' AND
         NOT EXISTS (SELECT 1 FROM unnest(p.proconfig) AS cfg WHERE cfg LIKE 'search_path=%')
      THEN '⚠ CRITICAL: anon-callable, no search_path'
    WHEN g.grantees LIKE '%PUBLIC%'
      THEN '⚠ HIGH: granted to PUBLIC'
    WHEN NOT EXISTS (SELECT 1 FROM unnest(p.proconfig) AS cfg WHERE cfg LIKE 'search_path=%')
      THEN '~ MEDIUM: search_path not set'
    ELSE '✓ Review individually'
  END                                        AS triage_flag,
  obj_description(p.oid, 'pg_proc')          AS comment
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
LEFT JOIN func_grants g
  ON g.routine_schema = n.nspname AND g.routine_name = p.proname
WHERE p.prosecdef = true
  AND n.nspname NOT IN (
    'pg_catalog', 'information_schema',
    'auth', 'storage', 'supabase_functions',
    'extensions', 'graphql', 'graphql_public',
    'net', 'pgsodium', 'pgsodium_masks', 'realtime', 'vault'
  )
ORDER BY
  CASE
    WHEN g.grantees LIKE '%anon%' THEN 0
    WHEN g.grantees LIKE '%PUBLIC%' THEN 1
    WHEN NOT EXISTS (SELECT 1 FROM unnest(p.proconfig) AS cfg WHERE cfg LIKE 'search_path=%') THEN 2
    ELSE 3
  END,
  n.nspname, p.proname;
