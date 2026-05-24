---
name: saas-tenant-isolation
description: Audit multi-tenant SaaS applications for cross-tenant data leakage including query scoping, tenant_id enforcement, cache key isolation, file storage path scoping, search index isolation, and tenant binding across billing, analytics, and background jobs. Use this skill whenever the user mentions multi-tenant, tenant isolation, cross-tenant leak, tenant_id, organization scoping, workspace isolation, B2B isolation, "are my tenants isolated", shared database with tenant column, schema-per-tenant, or database-per-tenant. Trigger on phrases like "audit my multi-tenancy", "check tenant isolation", "cross-tenant data leak", "tenant_id scoping", "are my orgs isolated". Use this even when only one isolation surface is mentioned.
---

# SaaS Tenant Isolation Audit

Audit a multi-tenant SaaS for cross-tenant data leakage paths. The single most dangerous class of bug in B2B SaaS — one breach exposes every customer.

## When this skill applies

- Reviewing query patterns in a shared-database multi-tenant architecture
- Checking that every data-access path enforces `tenant_id` / `org_id` / `workspace_id` scoping
- Auditing cache key construction (Redis, in-memory, CDN)
- Reviewing file storage path conventions
- Reviewing search indices (Elasticsearch, Algolia, Meilisearch) for cross-tenant filters
- Reviewing background jobs and queues for tenant binding

Use other skills for: row-level enforcement in Postgres (`supabase-security-audit`), auth checks per object (`saas-code-security-review`), API rate limits per tenant (`saas-api-security`).

## Tenancy models

Identify which model the app uses; the audit approach differs.

| Model | Description | Primary risk |
|-------|-------------|--------------|
| **Shared DB, shared schema, tenant column** | One DB, one schema, `tenant_id` column on every table | Missing WHERE clause on any query |
| **Shared DB, schema per tenant** | One DB, schema named per tenant; connect to that schema | Wrong schema selected; cross-schema query |
| **DB per tenant** | One DB per customer | Connection string mix-up; admin tooling crossing tenants |
| **Hybrid (sharded)** | Tenant maps to a specific shard | Misrouted query lands on wrong shard |

Most SaaS use shared DB + tenant column. This skill primarily covers that pattern; notes call out the others.

## Workflow

Follow `../_shared/audit-workflow.md`. Tenant-isolation-specific notes below.

### Phase 1: Scope confirmation

- Which tenancy model?
- Where does the tenant identifier originate (JWT claim, session, subdomain, header)?
- Is the tenant ID validated on every request, or set once at session start?

### Phase 2: Inventory

- List every table — does each user-data table have a `tenant_id` (or equivalent) column?
- List every query helper / repository function in the codebase.
- List every cache key construction site.
- List every storage bucket / path prefix convention.
- List every search index and how documents are filtered.
- List every background job entry point and how it receives tenant context.

### Phase 3: Detection — the checks

#### Database query scoping — see `references/query-scoping.md`

- **STI-DB-1** Every query against a tenant-scoped table includes a `WHERE tenant_id = $X` filter. The "X" must come from the authenticated session, not the request body.
- **STI-DB-2** ORM default scopes / global hooks apply tenant filter automatically. Manual queries that bypass the ORM are reviewed individually.
- **STI-DB-3** No query uses a `tenant_id` value extracted from a URL parameter or request body without server-side verification against the session.
- **STI-DB-4** Joins between tables both carry tenant filter, or are joined on `tenant_id` to prevent cross-tenant joins.
- **STI-DB-5** Admin-only queries that span tenants are clearly marked, require admin role, and log the cross-tenant access.
- **STI-DB-6** Postgres RLS or equivalent in DB layer provides defense-in-depth on top of application filters.
- **STI-DB-7** Database connection pools don't carry tenant context across requests (no session-level `SET app.tenant_id` that leaks if a connection is reused).

#### Cache key scoping

- **STI-CACHE-1** Every cache key includes the tenant ID as part of the key, not just user ID. `user:123` collides across tenants; `tenant:abc:user:123` doesn't.
- **STI-CACHE-2** CDN cache keys vary by tenant (e.g., subdomain in cache key; or `Vary: X-Tenant-Id` header).
- **STI-CACHE-3** Memoization caches keyed by tenant context where the cached value depends on tenant.
- **STI-CACHE-4** Cache invalidation cascades on tenant deletion to avoid stale data resurfacing.

Common bug: a list page caches results per user, but the user can switch tenants in the same session and see the previous tenant's cached list.

#### File storage scoping

- **STI-FILE-1** Object storage paths include the tenant ID as a prefix: `tenants/abc/users/123/file.pdf`, not `users/123/file.pdf`.
- **STI-FILE-2** Signed URL generation validates that the requesting user has access to the path's tenant.
- **STI-FILE-3** Bucket policies (S3, GCS, Azure Blob) enforce path-prefix-by-IAM where possible (defense in depth).
- **STI-FILE-4** Uploaded files don't preserve attacker-controlled paths verbatim — sanitize and prefix server-side.

#### Search index scoping

- **STI-SEARCH-1** Every search query against Elasticsearch/Algolia/Meilisearch includes a tenant filter clause.
- **STI-SEARCH-2** For Algolia, use [secured API keys](https://www.algolia.com/doc/guides/security/api-keys/) that embed the tenant filter — client-side filtering is bypassable.
- **STI-SEARCH-3** Index documents include the tenant ID field, indexed and filterable.
- **STI-SEARCH-4** Cross-tenant queries (analytics, admin) use a separate code path and require admin role.

#### Background jobs and queues

- **STI-JOB-1** Job payloads include the tenant ID; the job handler re-loads the tenant context and applies it to every DB query.
- **STI-JOB-2** Jobs don't reuse a global tenant context (e.g., a worker that processed tenant A's job leaves `SET app.tenant_id` set when it picks up tenant B's job).
- **STI-JOB-3** Job rate limits applied per tenant, not globally (one tenant shouldn't be able to starve another's jobs).
- **STI-JOB-4** Scheduled jobs that operate on multiple tenants iterate explicitly and pass tenant context per iteration.

#### Analytics, logs, and metrics

- **STI-OBS-1** Analytics events tagged with tenant ID for proper segmentation.
- **STI-OBS-2** Application logs include tenant ID context (correlation; also helps incident response).
- **STI-OBS-3** Customer-facing usage dashboards filtered by tenant — never expose another tenant's usage.
- **STI-OBS-4** PostHog / Mixpanel / Segment configurations don't leak tenant identifiers in client-side configs to other tenants.

#### Billing and subscription

- **STI-BILL-1** Stripe/Paddle customer ID stored per tenant; billing operations always verify the operating tenant matches the customer record.
- **STI-BILL-2** Webhook handlers (Stripe events) resolve to a tenant via a lookup, then apply changes only to that tenant.
- **STI-BILL-3** No code path lets a user change another tenant's billing.

#### Auth and impersonation

- **STI-AUTH-1** If users belong to multiple tenants, switching tenants creates a new session/JWT — not a context flip on the same session.
- **STI-AUTH-2** Admin impersonation (support-tooling) generates a clearly-marked session, logs the impersonation, and is time-limited.
- **STI-AUTH-3** SSO mappings (SAML, OIDC) resolve to a specific tenant; no path lets an SSO assertion from one IdP land a user in a different tenant.

### Phase 4: Triage

Critical class examples:
- A query without tenant_id filter on any user-data table
- Search index without tenant filter
- Storage bucket without per-tenant path enforcement
- Cache key not including tenant context
- Job worker leaking tenant context across jobs

These are all Critical: one such bug can leak all tenants' data.

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `STI-`. Include the file path and the specific query/path/key construction in evidence.

## Detection techniques

### Static — grep patterns

```bash
# Queries lacking 'tenant_id' or equivalent (heuristic)
grep -rn "SELECT.*FROM" src/ \
  | grep -v "tenant_id\|org_id\|workspace_id" \
  | grep -v "/* admin */"

# Cache keys lacking tenant prefix
grep -rn "cache.set\|redis.set" src/ \
  | grep -v "tenant:\|org:"

# Storage paths
grep -rn "bucket.upload\|s3.putObject\|storage.from" src/ \
  | grep -v "tenants/\|orgs/"
```

These are heuristics, not proof. Use them to surface code paths for human review.

### Runtime — request fuzzing in staging

In staging with two test tenants and two test users (one per tenant):
1. Log in as user A from tenant A; get an object ID.
2. Log in as user B from tenant B; try to access user A's object ID.
3. Try every CRUD operation. Each should 404 (not 403 — don't leak existence).

A scriptable test harness for this is high-leverage; running it on every release catches regressions.

### Dynamic — Postgres RLS as canary

If the app should have tenant filters in code AND RLS in the DB, you can enable a log-only mode where RLS is set to deny by default and any code that tries to bypass logs a warning. The audit can recommend this as a verification mechanism.

## References

- `references/query-scoping.md` — Patterns for ORM defaults, raw query review, cross-tenant admin paths
- `references/cross-tenant-leaks.md` — Cache, storage, search, and observability isolation patterns

## Assets

- `assets/tenant-test-harness.md` — Template for the runtime fuzzing approach
