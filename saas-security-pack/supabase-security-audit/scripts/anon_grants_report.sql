-- anon_grants_report.sql
-- Reports everything granted to anon, authenticated, and PUBLIC in the public schema
-- (and any user schemas). Use this to find over-grants.
-- Run in Supabase SQL editor. Read-only.

\echo '=== TABLE GRANTS to anon, authenticated, PUBLIC ==='
SELECT
  grantee,
  table_schema,
  table_name,
  string_agg(privilege_type, ', ' ORDER BY privilege_type) AS privileges,
  CASE
    WHEN grantee = 'anon' AND privilege_type = ANY(ARRAY['INSERT','UPDATE','DELETE','TRUNCATE'])
      THEN '⚠ anon writes — verify intent'
    WHEN grantee = 'anon' AND privilege_type = 'SELECT'
      THEN '~ anon reads — verify table is public-safe'
    WHEN grantee = 'PUBLIC'
      THEN '⚠ granted to PUBLIC — should be specific role'
    ELSE NULL
  END AS triage
FROM information_schema.role_table_grants
WHERE grantee IN ('anon', 'authenticated', 'PUBLIC')
  AND table_schema NOT IN (
    'information_schema', 'pg_catalog',
    'auth', 'storage', 'supabase_functions',
    'extensions', 'graphql', 'graphql_public',
    'net', 'pgsodium', 'pgsodium_masks', 'realtime', 'vault'
  )
GROUP BY grantee, table_schema, table_name, privilege_type
ORDER BY
  CASE grantee WHEN 'anon' THEN 0 WHEN 'PUBLIC' THEN 1 ELSE 2 END,
  table_schema, table_name;

\echo ''
\echo '=== FUNCTION GRANTS to anon, authenticated, PUBLIC ==='
SELECT
  grantee,
  routine_schema,
  routine_name,
  pg_get_function_arguments(p.oid) AS arguments,
  CASE WHEN p.prosecdef THEN 'DEFINER' ELSE 'INVOKER' END AS sec_context,
  CASE
    WHEN grantee = 'PUBLIC' THEN '⚠ PUBLIC — too broad'
    WHEN grantee = 'anon' AND p.prosecdef THEN '⚠ anon-callable DEFINER — high-risk; review carefully'
    WHEN grantee = 'anon' THEN '~ anon-callable INVOKER — usually OK'
    ELSE NULL
  END AS triage
FROM information_schema.routine_privileges rp
JOIN pg_proc p ON p.proname = rp.routine_name
JOIN pg_namespace n ON n.oid = p.pronamespace AND n.nspname = rp.routine_schema
WHERE rp.grantee IN ('anon', 'authenticated', 'PUBLIC')
  AND rp.privilege_type = 'EXECUTE'
  AND rp.routine_schema NOT IN (
    'information_schema', 'pg_catalog',
    'auth', 'storage', 'supabase_functions',
    'extensions', 'graphql', 'graphql_public',
    'net', 'pgsodium', 'pgsodium_masks', 'realtime', 'vault'
  )
ORDER BY
  CASE rp.grantee WHEN 'PUBLIC' THEN 0 WHEN 'anon' THEN 1 ELSE 2 END,
  rp.routine_schema, rp.routine_name;

\echo ''
\echo '=== SEQUENCE GRANTS to anon, authenticated ==='
SELECT
  grantee,
  object_schema AS schema,
  object_name AS sequence,
  privilege_type
FROM information_schema.usage_privileges
WHERE grantee IN ('anon', 'authenticated', 'PUBLIC')
  AND object_type = 'SEQUENCE'
  AND object_schema NOT IN (
    'information_schema', 'pg_catalog',
    'auth', 'storage', 'supabase_functions',
    'extensions', 'graphql', 'graphql_public',
    'net', 'pgsodium', 'pgsodium_masks', 'realtime', 'vault'
  )
ORDER BY grantee, object_schema, object_name;

\echo ''
\echo '=== SCHEMA USAGE grants ==='
SELECT
  grantee,
  object_schema AS schema,
  privilege_type
FROM information_schema.usage_privileges
WHERE grantee IN ('anon', 'authenticated', 'PUBLIC')
  AND object_type = 'SCHEMA'
ORDER BY grantee, object_schema;
