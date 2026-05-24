# IDOR / BOLA Authorization Patterns

Load this when reviewing endpoints that take resource IDs, when searching for IDOR/BOLA, or when the user asks how to structure auth checks.

## Vocabulary

- **IDOR** (Insecure Direct Object Reference): Generic term for an endpoint that returns or modifies an object based on an ID without confirming the caller has access to that object.
- **BOLA** (Broken Object Level Authorization): OWASP API Security Top-10 term for the same class, with explicit framing as an API issue. BOLA #1 in the API top-10.
- **BFLA** (Broken Function Level Authorization): Similar but at the function/endpoint level — e.g., a non-admin can call an admin-only endpoint. Audit both.

In this reference "IDOR" covers both BOLA and IDOR.

## The mental model

Every endpoint that handles an object has two distinct authorization questions:

1. **Can this user use this function?** (e.g., is the caller authenticated; do they have the `read:invoice` permission)
2. **Can this user use this function on this specific object?** (does the caller own/share/admin this invoice)

Question 1 is usually handled by route-level middleware. Question 2 is per-object and almost always where bugs live.

## Anti-patterns

### Anti-pattern A — "trust the URL"

```js
app.get('/invoices/:id', requireAuth, async (req, res) => {
  const invoice = await db.invoices.findById(req.params.id);
  res.json(invoice);
});
```

No check that `req.user` owns the invoice. Any logged-in user can read any invoice by guessing IDs (sequential) or scraping IDs (leaked via referrer, share links, etc.).

### Anti-pattern B — "filter in memory"

```python
@app.get("/api/projects")
def list_projects():
    all_projects = db.query(Project).all()
    return [p for p in all_projects if p.owner_id == current_user.id]
```

Database returns everyone's projects; app filters in memory. With millions of rows this both leaks data (via timing) and is a DoS vector. Filter in the query, not after.

### Anti-pattern C — "UUIDs are safe"

```js
app.get('/users/:uuid', requireAuth, async (req, res) => {
  // We use UUIDs so people can't guess each other's IDs, so we skip the check
  const user = await db.users.findByUuid(req.params.uuid);
  res.json(user);
});
```

UUIDs reduce *bruteforce* risk but don't eliminate IDOR. UUIDs leak through referrer headers, share links, logs, support tickets, mobile app analytics, and social engineering. Always check the relationship.

### Anti-pattern D — "the frontend hides it"

The frontend doesn't render a delete button for non-owners, so the team assumes the delete endpoint doesn't need an owner check. Frontend is not security boundary.

### Anti-pattern E — "we check on POST, not on GET"

Read endpoints leak data just as badly as write endpoints — often worse, because reads scale. Audit GETs with the same rigor as POSTs.

### Anti-pattern F — "tenant ID in the body"

```js
app.post('/invoices', requireAuth, async (req, res) => {
  await db.invoices.create({
    tenant_id: req.body.tenantId,  // ← attacker-controlled
    ...req.body
  });
});
```

`tenant_id` should come from the authenticated session, not from the request body.

## Correct patterns

### Pattern 1 — Authorization at the data layer

```ts
// Repository function does the check itself; route handlers cannot bypass.
async function getInvoiceForUser(invoiceId: string, userId: string) {
  const row = await db.query(`
    SELECT i.*
    FROM invoices i
    WHERE i.id = $1
      AND (i.user_id = $2 OR EXISTS (
        SELECT 1 FROM invoice_shares s
        WHERE s.invoice_id = i.id AND s.user_id = $2
      ))
  `, [invoiceId, userId]);
  return row;  // null if not authorized OR not found — same response
}

// Route handler never queries directly.
app.get('/invoices/:id', requireAuth, async (req, res) => {
  const invoice = await getInvoiceForUser(req.params.id, req.user.id);
  if (!invoice) return res.status(404).end();  // 404, not 403 — don't reveal existence
  res.json(invoice);
});
```

### Pattern 2 — Centralized policy layer

Tools: [Cerbos](https://cerbos.dev), [OpenFGA](https://openfga.dev), Casbin, custom Oso-style. Define authorization rules in one place, enforce everywhere.

```ts
// Pseudocode using a centralized policy check
const decision = await authz.check({
  principal: req.user,
  action: 'read',
  resource: { type: 'invoice', id: invoiceId },
});
if (!decision.allowed) return res.status(404).end();
```

The win is auditability: every endpoint reads from the same policy source, and the policy can be tested independently.

### Pattern 3 — Database-enforced (RLS)

Push the check into the database via row-level security. See `supabase-security-audit/references/rls-patterns.md` — even outside Postgres, the principle of "database enforces ownership" carries over to SQL Server, MySQL with views, MongoDB with `$match` in aggregation views, etc.

### Pattern 4 — GraphQL field-level authorization

```ts
// Resolver checks per-field, not just per-root-query
const resolvers = {
  Invoice: {
    // Always check the parent invoice belongs to user before returning fields
    amount: (parent, _args, ctx) => ensureOwnsInvoice(parent, ctx) && parent.amount,
    customer: (parent, _args, ctx) => ensureOwnsInvoice(parent, ctx) && loadCustomer(parent.customer_id),
  },
};
```

For larger GraphQL APIs, use a directive-based approach (`@auth(rule: "owns(invoice)")`) so the rule lives with the schema.

### Pattern 5 — Bulk-endpoint scoping

```sql
-- GOOD: scope in the query
SELECT * FROM projects WHERE tenant_id = $1 LIMIT 100;

-- BAD: scope in code after the query
SELECT * FROM projects LIMIT 100;  -- and then filter in app
```

For ORMs, set up a default scope (Rails `default_scope`, Sequelize global hook, Prisma extensions) that always applies the tenant filter unless explicitly opted out for admin queries.

## Detection checklist for review

For each route/handler/resolver:

1. Does it accept an object ID (path param, query param, body field)?
2. Does it check the relationship between the caller and that object?
3. Where does the check live — handler, service, repository, database? Defense-in-depth means more than one layer.
4. For batch endpoints: is the filter in the query, not after?
5. For GraphQL: does each field that exposes related data re-check, or rely on the root check?
6. For admin endpoints: is "is admin" checked AND "admin of the target"?
7. Are responses for "not authorized" indistinguishable from "doesn't exist"? (Avoid leaking existence.)

## Triage notes

- IDOR returning *another tenant's* data → Critical. Multi-tenant breach.
- IDOR returning *another user's* data in same tenant → High.
- IDOR allowing modification (PUT/DELETE) → Critical or High depending on what's modified.
- IDOR on internal/admin endpoints not normally exposed → still High (defense in depth, internal pivot).
