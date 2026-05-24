---
name: mongoose-mongodb-security
description: Security audit for MongoDB and Mongoose-based applications including NoSQL operator injection ($where, $ne, $gt), mass assignment via spreading into Model.create, schema validation bypass, aggregation pipeline safety, lean() vs hydrated query exposure, missing tenant scoping, and MongoDB connection string handling. Use this skill whenever the user mentions MongoDB, Mongoose, mongoose.Schema, Model.create, Model.findOne, aggregate pipeline, $where, $regex, MongoClient, or asks "audit my MongoDB queries", "Mongoose security", "NoSQL injection". Trigger when the codebase contains `mongoose`, `mongodb`, or `@mongodb/*` in package.json.
---

# MongoDB / Mongoose Security Audit

Audit MongoDB usage (raw driver and Mongoose ODM) for NoSQL-specific vulnerabilities.

## When this skill applies

- Reviewing Mongoose schemas and model usage
- Auditing raw MongoDB driver queries
- Checking for NoSQL operator injection
- Reviewing aggregation pipelines for safety
- Auditing tenant scoping across queries

## Workflow

Follow `../_shared/audit-workflow.md`. Companion: `prisma-orm-security` for IDOR/mass-assignment patterns generally.

### Phase 1: Stack detection

```bash
grep -E '"(mongoose|mongodb|@mongodb)":' package.json
mongosh --version 2>/dev/null
```

### Phase 2: Inventory

```bash
# Mongoose schemas
grep -rn 'new mongoose.Schema\|new Schema(' src/ | head

# Model queries
grep -rnE 'Model\.(find|findOne|findById|create|update|delete|aggregate)' src/ | head -30

# Operator-bearing queries (potential injection)
grep -rn '\$where\|\$ne\|\$gt\|\$lt\|\$regex' src/

# Aggregation pipelines
grep -rn '\.aggregate(' src/ | head

# Connection strings
grep -rn 'mongodb://\|mongodb+srv://' src/
```

### Phase 3: Detection — the checks

#### NoSQL operator injection

The classic attack: user submits `{ "$gt": "" }` for a password field; query matches any document.

```js
// BAD — accepts arbitrary operator objects
app.post('/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email, password: req.body.password });
  // Attacker: { email: { $ne: "" }, password: { $ne: "" } } — finds any user
});

// GOOD — cast to expected primitive
const email = String(req.body.email);
const password = String(req.body.password);
const user = await User.findOne({ email, password: hashPassword(password) });
```

- **MNG-INJ-1** Inputs cast to expected primitives (`String(x)`, `Number(x)`) before being used in queries.
- **MNG-INJ-2** Or use a validator (Zod, Joi) that enforces primitive types — rejects objects.
- **MNG-INJ-3** `express-mongo-sanitize` or equivalent middleware applied to strip `$`-prefixed keys from request bodies — defense in depth.

#### `$where` and JavaScript injection

`$where` runs JavaScript on the server. Never use with user input:

```js
// CRITICAL — JS injection on the server
db.collection.find({ $where: `this.name == '${userInput}'` });

// CRITICAL too — $where with function from user
db.collection.find({ $where: req.body.predicate });
```

- **MNG-WHERE-1** No `$where` in production code, or only with hardcoded strings.
- **MNG-WHERE-2** `$expr` with `$function` (MongoDB 4.4+) similarly dangerous; allowlist if used.

#### `$regex` denial of service

```js
// User input as regex without sanitization → ReDoS
collection.find({ name: { $regex: req.query.search } });
```

- **MNG-REGEX-1** User-provided regex strings escaped first (escape `.\+*?[](){}^$|` etc.) OR matched via text indexes (`$text`) instead.
- **MNG-REGEX-2** Anchored search with limit: `{ name: { $regex: `^${escape(input)}`, $options: 'i' } }`.

#### Mass assignment (Mongoose)

```js
// BAD
const user = await User.create({ ...req.body });
// Attacker includes: { role: 'admin', isVerified: true }
```

- **MNG-MA-1** Don't spread `req.body` into `Model.create` / `Model.findOneAndUpdate`. Pick fields explicitly.
- **MNG-MA-2** Mongoose schema has `strict: true` (default) — extra fields rejected. But fields DECLARED on the schema can still be set if you spread. The schema doesn't auto-filter "admin only" fields.
- **MNG-MA-3** For updates, use `$set: { specificField: value }` rather than `Model.updateOne({ id }, req.body)`.

```js
// GOOD
const { name, bio } = CreateUserSchema.parse(req.body);
const user = await User.create({
  name,
  bio,
  role: 'user',                   // server-controlled
  tenantId: req.user.tenantId,    // session-derived
});
```

#### IDOR — missing tenant scope

- **MNG-IDOR-1** Every `findById`, `findOne`, `updateOne`, `deleteOne` includes a tenant or owner filter.
  ```js
  // BAD
  const doc = await Doc.findById(req.params.id);
  
  // GOOD
  const doc = await Doc.findOne({ _id: req.params.id, tenantId: req.user.tenantId });
  ```
- **MNG-IDOR-2** Custom static methods on models that fetch documents enforce scoping at the method level.

#### Sensitive fields in responses

- **MNG-RES-1** Schema fields like `password`, `mfaSecret`, `apiKeyHash` have `select: false` so they're excluded by default.
- **MNG-RES-2** Or use explicit projection in queries: `User.findOne({...}, 'name email').lean()`.
- **MNG-RES-3** `toJSON` transform configured to strip internal fields:
  ```js
  schema.set('toJSON', {
    transform: (doc, ret) => {
      delete ret.password;
      delete ret.__v;
      return ret;
    },
  });
  ```

#### Aggregation pipeline safety

- **MNG-AGG-1** User input embedded in pipeline stages parameterized via `$` references or pre-validated. Don't construct pipeline objects from raw request data.
- **MNG-AGG-2** `$lookup` / `$graphLookup` stages preserve tenant scope in matching documents.
- **MNG-AGG-3** `allowDiskUse: false` by default in production (limits resource use); enable selectively for known-large pipelines.

#### Connection strings

- **MNG-CONN-1** Connection string from env, never hardcoded.
- **MNG-CONN-2** SRV connection string with TLS in production (`mongodb+srv://...`).
- **MNG-CONN-3** Connection string doesn't have superuser credentials; use a role with minimum needed privileges.
- **MNG-CONN-4** Connection pool size capped.

#### MongoDB authentication and roles

- **MNG-DB-1** No `--noauth` in production. Authentication enabled.
- **MNG-DB-2** Roles: app user has `readWrite` on the specific database, not `root` / `dbAdmin`.
- **MNG-DB-3** Network: MongoDB not bound to `0.0.0.0` without firewall; Atlas IP allowlist configured.
- **MNG-DB-4** TLS required.

#### Atlas-specific

- **MNG-ATL-1** Network access list specific (not `0.0.0.0/0`).
- **MNG-ATL-2** Database user separate from Atlas org user.
- **MNG-ATL-3** Atlas Audit Logs enabled.
- **MNG-ATL-4** Encryption-at-rest using customer-managed keys for sensitive datasets.

#### Soft delete and tombstones

- **MNG-SD-1** Soft-delete flag (`deletedAt`) queries don't return tombstones to clients.
- **MNG-SD-2** Indexes on tenant + deletedAt for performance.

#### Indexes

- **MNG-IDX-1** Indexes on filter columns used in WHERE — unindexed queries on large collections enable DoS.
- **MNG-IDX-2** Unique indexes on identifiers (email, slug).
- **MNG-IDX-3** Compound indexes include tenant_id first for multi-tenant collections.

#### Logging

- **MNG-LOG-1** Profiling logs (slow query log) don't leak query contents with PII.
- **MNG-LOG-2** Sensitive collections not logged at query level.

#### Dependencies

- **MNG-DEP-1** Mongoose and MongoDB driver current. Old `mongodb < 4.x` had bugs in BSON parsing.
- **MNG-DEP-2** `express-mongo-sanitize` or alternative sanitizer present if input ever flows into queries.

### Phase 4: Triage

Critical: login endpoint accepting object inputs (operator injection); `$where` with user input; queries without tenant scope; password field returned in responses.

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `MNG-`.
