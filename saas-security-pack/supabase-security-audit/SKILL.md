---
name: supabase-security-audit
description: Audit Supabase project security including Row-Level Security (RLS) policies, SECURITY DEFINER functions, anon/authenticated role grants, service_role key exposure, edge function authentication, and JWT verification on edge endpoints. Use this skill whenever the user mentions Supabase, RLS, row-level security, SECURITY DEFINER, anon role exposure, service_role leak, supabase-js client, edge functions auth, or asks "is my Supabase project safe". Trigger on phrases like "audit my Supabase", "review my RLS", "is RLS enabled", "SECURITY DEFINER risk", "anon role grants", "edge function security", "service role exposure", "Postgres function audit". Use this even if only one sub-topic is mentioned.
---

# Supabase Security Audit

Audit the security posture of a Supabase project across its three exposed surfaces: PostgREST (auto-API over Postgres), Storage, and Edge Functions. Defensive find-and-fix focus.

## When this skill applies

- Reviewing whether RLS is enabled and policies are correct
- Auditing SECURITY DEFINER functions exposed to anon or authenticated roles
- Checking grants on `anon` and `authenticated` roles
- Looking for `service_role` key exposure in client code
- Reviewing edge function code for missing JWT verification
- Investigating suspicious activity in a Supabase project (post-incident)

Use other skills for: general app-code review (`saas-code-security-review`), multi-tenant patterns (`saas-tenant-isolation`).

## Workflow

Follow `../_shared/audit-workflow.md`. Skill-specific notes below.

### Phase 1: Scope confirmation

Confirm with the user:
- Project ref (`xxxxx.supabase.co`)
- Do you have the service_role key available for read-only audits? (Some checks require it.)
- Are you the owner/admin of the project?
- Is this a production project or a staging/dev project?

Never request or store the service_role key in chat. Ask the user to run queries themselves using the SQL editor and paste results.

### Phase 2: Inventory

Run the queries in `scripts/inventory.sql` against the project. They produce:
- Every table with RLS status
- Every policy per table
- Every function with `security definer` status and grants
- Every grant on `anon` and `authenticated`
- Every storage bucket and its public/private status
- Edge function list (via CLI: `supabase functions list`)

### Phase 3: Detection — the checks

#### RLS coverage — see `references/rls-patterns.md`

- **SUPA-RLS-1** Every user-data table has RLS enabled (`relrowsecurity = true`).
- **SUPA-RLS-2** Every user-data table has at least one policy (RLS enabled with no policies = nothing is allowed; usually a config error).
- **SUPA-RLS-3** Policies use `auth.uid()` / `auth.jwt()` for identity, not `current_user` (which is the Postgres role, not the app user).
- **SUPA-RLS-4** Policies cover all four operations (SELECT, INSERT, UPDATE, DELETE) — a permissive SELECT with no UPDATE policy means no UPDATE is allowed (often intended), but the audit should confirm intent.
- **SUPA-RLS-5** Restrictive policies (`AS RESTRICTIVE`) used where multiple permissive policies could otherwise OR together unsafely.
- **SUPA-RLS-6** `USING` clauses don't have subqueries that bypass RLS on referenced tables (recursive RLS pitfall).
- **SUPA-RLS-7** Junction/audit/log tables also have RLS — not just the obvious user-facing tables.

#### Bypass paths — see `references/security-definer.md`

- **SUPA-SD-1** Every `SECURITY DEFINER` function inventoried with its grants.
- **SUPA-SD-2** SECURITY DEFINER functions called by anon or authenticated have explicit authorization checks at the top.
- **SUPA-SD-3** `search_path` set explicitly in every SECURITY DEFINER function (`SET search_path = ''` or a hardened path), to prevent function-resolution hijacking.
- **SUPA-SD-4** No SECURITY DEFINER function returns data from tables the caller couldn't otherwise reach via RLS, unless that's the explicit intent and authorization is enforced inside.
- **SUPA-SD-5** SECURITY DEFINER functions revoked from `public` by default; grants only to specific roles.

#### Role grants — see `references/anon-role-exposure.md`

- **SUPA-AR-1** `anon` has SELECT only on tables intended for public access. Any table exposing PII to anon → finding.
- **SUPA-AR-2** `anon` has no INSERT/UPDATE/DELETE on user-data tables (use functions or authenticated grants).
- **SUPA-AR-3** `authenticated` grants are minimal — RLS does the policy work, but grants must allow it.
- **SUPA-AR-4** No grants directly to `public` (covers everyone including future roles).
- **SUPA-AR-5** Sequence usage grants align with table grants (else INSERTs fail oddly or succeed by accident).

#### Service role exposure

- **SUPA-SR-1** No client code (browser bundle, mobile app, public repo) imports the service_role key. Grep the codebase for the key prefix.
- **SUPA-SR-2** Service role used only in server-side code, edge functions with explicit auth, or admin tooling.
- **SUPA-SR-3** Service role key rotated in last 12 months and after any suspected exposure.
- **SUPA-SR-4** No service_role key in environment variables of client-facing services (Vercel/Netlify "preview" environments that may leak).

#### Edge functions — see `references/edge-functions-auth.md`

- **SUPA-EF-1** Every edge function that handles authenticated user data calls `supabase.auth.getUser(jwt)` to verify and identify the caller.
- **SUPA-EF-2** Functions don't trust client-supplied user IDs; always derive from JWT.
- **SUPA-EF-3** `Verify JWT` flag enabled in function settings unless explicitly intended to be public (webhook receivers).
- **SUPA-EF-4** Webhook receivers verify signatures (Stripe, Resend, custom) — see `saas-api-security/references/webhook-security.md`.
- **SUPA-EF-5** Service role key not used inside edge function for queries that should respect RLS — use the user's JWT with the supabase client.
- **SUPA-EF-6** Outbound HTTP requests from edge functions follow SSRF protections (see `saas-code-security-review/references/ssrf-patterns.md`).

#### Storage

- **SUPA-ST-1** Buckets marked public only when intent is public; default to private.
- **SUPA-ST-2** Storage policies (RLS-style) defined for private buckets.
- **SUPA-ST-3** Signed URL TTLs reasonable for use case (short for one-time access, longer for embedded content).
- **SUPA-ST-4** No path-traversal-style key construction from user input without sanitization.

#### Auth configuration

- **SUPA-AUTH-1** Email confirmation required (don't allow unconfirmed accounts to act).
- **SUPA-AUTH-2** Rate limits configured on auth endpoints.
- **SUPA-AUTH-3** Redirect URLs allowlist explicit (no wildcards that could allow OAuth redirect to attacker).
- **SUPA-AUTH-4** Custom SMTP configured for production (Supabase's shared SMTP has reputation limits).
- **SUPA-AUTH-5** MFA enabled on Supabase dashboard for project owners.

### Phase 4: Triage

Critical class examples:
- RLS disabled on any table containing user data
- service_role key in a public repo or browser bundle
- SECURITY DEFINER function exposed to anon that returns all rows from a sensitive table
- Edge function performing privileged operations without JWT verification

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `SUPA-`. Include the table/function name and grant context in evidence.

## Scripts

- `scripts/audit_rls.sql` — Lists every table with RLS status and policy count
- `scripts/find_definer_funcs.sql` — Lists SECURITY DEFINER functions and their grants
- `scripts/anon_grants_report.sql` — Lists everything granted to `anon` and `authenticated`

Run these in the Supabase SQL editor.

## References

- `references/rls-patterns.md` — Common RLS policies (good and bad), recursion pitfalls
- `references/security-definer.md` — When to use SECURITY DEFINER, how to harden it
- `references/anon-role-exposure.md` — What `anon` should and shouldn't have
- `references/edge-functions-auth.md` — JWT verification patterns for Deno edge functions

## Assets

- `assets/rls-template.sql` — Default-deny policy template for new tables
