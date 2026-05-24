# Cross-Tenant Leaks: Cache, Storage, Search, Observability

Load this when reviewing isolation surfaces beyond the database — caches, object storage, search indices, analytics, and queues.

## Cache key isolation

### The pattern

Every cache key includes the tenant scope:

```
GOOD: tenant:abc/user:123/preferences
BAD:  user:123/preferences
```

### Common bugs

**Bug 1 — User scoped but not tenant scoped**

A user account that belongs to two tenants. The cache key `user:123:dashboard` returns whichever tenant's data was cached first, regardless of which tenant the user is currently acting in.

**Bug 2 — CDN/edge cache without Vary**

A CDN caches HTML responses keyed by URL only. If `https://app.example.com/dashboard` returns tenant-A data when accessed by a tenant-A user, the CDN may serve that same response to a tenant-B user requesting the same URL.

Fix: include tenant in URL (`https://tenant-a.example.com/dashboard`), or use `Vary: X-Tenant-Id` (with explicit Cache-Control), or set `private`/`no-store` on tenant-data responses.

**Bug 3 — Memoization across requests**

```python
@lru_cache(maxsize=1000)
def get_settings(user_id: str):  # ⚠ no tenant in cache key
    return db.query("SELECT * FROM settings WHERE user_id = ?", [user_id])
```

Same user, multiple tenants → wrong result.

Fix:

```python
@lru_cache(maxsize=1000)
def get_settings(user_id: str, tenant_id: str):
    return db.query(
        "SELECT * FROM settings WHERE user_id = ? AND tenant_id = ?",
        [user_id, tenant_id]
    )
```

**Bug 4 — Redis MULTI without tenant prefix**

A pipelined Redis script that uses keys like `count:project:123` will collide across tenants. Prefix every key.

### Verification

Run a script that scans Redis keys and groups by tenant prefix:

```bash
redis-cli --scan --pattern '*' | awk -F: '{print $1}' | sort -u
```

If any keys don't start with a tenant prefix (or other tenant-scoping convention), investigate.

## Object storage paths

### Path conventions

Use a deterministic, tenant-prefixed path:

```
tenants/<tenant_id>/users/<user_id>/<resource_type>/<resource_id>.<ext>
```

Examples:
```
tenants/abc-123/users/u-456/avatars/profile.png
tenants/abc-123/projects/p-789/attachments/draft.pdf
```

### Bucket-level enforcement

Where possible, push enforcement into the bucket policy (defense in depth). AWS S3 example using IAM session tags:

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::my-app/tenants/${aws:PrincipalTag/TenantId}/*"
}
```

Combine with STS AssumeRoleWithWebIdentity that sets the `TenantId` tag from the user's JWT, and the bucket policy prevents cross-tenant reads even if app code is buggy.

For GCS, use [Tenant API](https://cloud.google.com/iam/docs/principal-identifiers) or signed URL generation that's tenant-scoped at the application layer.

### Signed URL pitfalls

When generating signed URLs:
- Validate the requested object's path includes the user's tenant prefix.
- Set short TTLs (5-15 min for read; longer only if needed).
- Use signed URL paths that don't include redirects — a redirect target with different access can leak.

### Path sanitization

If any path component comes from user input (filename, attachment ID), sanitize:
- Strip `/`, `\`, `..`, null bytes
- Limit length
- Apply a canonical lowercase / collation
- Never trust the extension; verify content-type by magic bytes

```ts
function safePath(tenantId: string, userId: string, userFilename: string): string {
  const cleanName = userFilename
    .replace(/[^a-zA-Z0-9.\-_]/g, '_')
    .substring(0, 100);
  return `tenants/${tenantId}/users/${userId}/uploads/${randomUUID()}-${cleanName}`;
}
```

## Search indices

### Elasticsearch / OpenSearch

Two patterns:

**Pattern A — Tenant field on every document, filter at query time**

```json
{
  "query": {
    "bool": {
      "must": [
        { "match": { "title": "search term" } }
      ],
      "filter": [
        { "term": { "tenant_id": "abc-123" } }
      ]
    }
  }
}
```

Apply the tenant filter in a query helper that wraps every call. Never let raw user-facing queries reach Elasticsearch unfiltered.

**Pattern B — Index per tenant**

`tenant-abc-123-projects`, `tenant-def-456-projects`, etc. Stronger isolation but operationally complex past ~100 tenants.

### Algolia — secured API keys

Client-side filtering in Algolia is bypassable. Use [secured API keys](https://www.algolia.com/doc/guides/security/api-keys/#secured-api-keys) generated server-side with a filter embedded:

```ts
import algoliasearch from 'algoliasearch';

const adminKey = process.env.ALGOLIA_ADMIN_KEY!;
const searchKey = algoliasearch.generateSecuredApiKey(adminKey, {
  filters: `tenant_id:${user.tenantId}`,
  validUntil: Math.floor(Date.now() / 1000) + 3600,
});
// Send searchKey to the client; it's tenant-scoped and time-limited.
```

The filter is embedded in the key; clients can't override it.

### Meilisearch — multi-tenant tokens

Similar pattern, [tenant tokens](https://www.meilisearch.com/docs/learn/security/tenant_tokens) embed a search rule.

### Detection

For each search backend:
1. Every search call goes through a server-side helper that injects the tenant filter — never a direct client SDK call from the browser.
2. The tenant filter cannot be overridden by user input.
3. Index documents have a tenant ID field; field is indexed and filterable.

## Observability and analytics

### Application logs

Include the tenant ID in every log line:

```ts
logger.info({
  msg: 'project_created',
  tenant_id: ctx.tenantId,
  user_id: ctx.userId,
  project_id: project.id,
});
```

This enables:
- Per-tenant alerting and quotas
- Incident response (filter logs to a specific tenant)
- Customer-facing audit log (filter by their own tenant_id)

### Customer-facing dashboards

If you expose usage metrics, request volumes, or activity feeds to customers:
- Query backends filter by tenant ID server-side.
- Frontend doesn't accept tenant IDs as parameters that bypass the filter.
- BI tools (Metabase, Looker) embedded for customers use row-level security on the data warehouse side.

### Third-party analytics in client bundles

PostHog / Mixpanel / Segment installed in the frontend send events with whatever you tell them. Common bug: a unified workspace identifier across all tenants makes you visible to your competitors via the analytics provider's misconfigured access.

Audit:
- Are tenant IDs sent as event properties?
- Are the third-party project/workspace settings such that one customer's data isn't queryable by another? (Most analytics SaaS isolate per "project"; one project per app is fine.)
- Are event names tenant-prefixed if the analytics provider can be queried by anyone with read access in your org?

## Background jobs

### Job payload includes tenant

```ts
queue.add('process-export', {
  tenantId: ctx.tenantId,
  userId: ctx.userId,
  exportId: export.id,
});
```

The handler resolves the tenant context first:

```ts
async function processExport(job: Job<ExportPayload>) {
  const ctx = await loadTenantContext(job.data.tenantId);
  const repo = new ExportRepository(ctx);
  // ... all queries are tenant-scoped
}
```

### Worker context bleed

If your worker process uses a thread-local / async-context-local for the tenant ID, ensure it's reset between jobs:

```ts
queue.process(async (job) => {
  await tenantContext.run(job.data.tenantId, async () => {
    await processExport(job);
  });
  // tenantContext is reset after run() exits
});
```

Without the explicit run/reset, the next job might inherit the previous tenant's context.

### Cron / scheduled jobs over all tenants

A "for every tenant, do X" loop:

```ts
for (const tenant of await listAllTenants()) {
  await tenantContext.run(tenant.id, async () => {
    await runDailyTask(tenant);
  });
}
```

Each iteration explicitly enters and exits the tenant context. Don't share the outer scope.

### Rate limiting per tenant

A single tenant should not be able to monopolize the worker pool. Implement per-tenant concurrency limits:

```ts
const queue = new Queue('exports', {
  limiter: {
    max: 100,           // 100 jobs per minute total
    duration: 60000,
    bounceBack: false,
  },
  // Plus per-tenant: process groupKey: 'tenantId' with max 10 concurrent
});
```

## Email and notifications

- Notifications include only the recipient's tenant data in the body.
- Email "from" addresses don't reveal other tenants (no `noreply-tenant-abc@example.com` if subdomains are sensitive).
- Tenant-A's webhook URLs aren't called when Tenant-B's events fire (verify in delivery layer).

## Checklist for the audit

1. Cache keys all include tenant.
2. Storage paths all include tenant prefix; bucket policy enforces it if possible.
3. Search filters applied server-side, embedded in tokens for client-side search.
4. Logs include tenant ID on every line.
5. Customer dashboards filter by tenant ID, never accept tenant parameter from client.
6. Third-party analytics scoped per project/tenant where applicable.
7. Job payloads include tenant ID; handlers re-establish tenant context.
8. Worker context resets between jobs.
9. Scheduled jobs iterate tenants explicitly.
10. Email/webhooks routed correctly per tenant.
