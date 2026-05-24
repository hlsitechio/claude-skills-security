---
name: graphql-security
description: Security audit for GraphQL APIs covering query depth and complexity limits, introspection exposure, field-level authorization, mutation auth, persisted queries, batching abuse, error message leakage, subscription auth, and Apollo/urql/graphql-yoga/Mercurius/Hasura/PostGraphile-specific patterns. Use this skill whenever the user mentions GraphQL, Apollo Server, Apollo Client, urql, graphql-yoga, Mercurius, Hasura, PostGraphile, Strawberry (Python), gqlgen (Go), resolvers, schema.graphql, .gql files, query depth, query complexity, or asks "audit my GraphQL", "GraphQL security review", "depth limit", "persisted queries". Trigger when the codebase contains `.graphql`/`.gql` files, `apollo-server`, `@apollo/server`, `graphql-yoga`, `mercurius`, or `graphql` packages.
---

# GraphQL Security Audit

Audit GraphQL APIs for vulnerabilities specific to the query language and protocol: complexity attacks, introspection leaks, field-level auth bypass, mutation gaps.

## When this skill applies

- Reviewing GraphQL schemas and resolvers
- Auditing depth / complexity / cost limits
- Reviewing field-level authorization
- Checking introspection exposure in production
- Auditing persisted queries setup
- Reviewing GraphQL subscriptions and WebSocket auth

Use other skills for: REST API patterns (`saas-security-pack/saas-api-security`), backend framework auth wiring (`nodejs-express-security`, `nestjs-security`, `fastapi-security`), IDOR patterns generally (`saas-security-pack/saas-code-security-review`).

## Workflow

Follow `../_shared/audit-workflow.md`. GraphQL-specific notes below.

### Phase 1: Stack detection

```bash
# Find the GraphQL server library
grep -E '"(apollo-server|@apollo/server|graphql-yoga|mercurius|express-graphql|@nestjs/graphql|graphql-tools)":' package.json

# Schema files
find . \( -name '*.graphql' -o -name '*.gql' -o -name 'schema.ts' \) -not -path '*/node_modules/*' | head -10

# Resolver locations
grep -rln 'Query:\|Mutation:\|Subscription:\|resolvers\s*=' src/ | head -10
```

### Phase 2: Inventory

```bash
# Endpoint configuration
grep -rnE 'graphqlPath|graphqlMiddleware|playground|introspection' src/

# Auth context setup
grep -rn 'context:\s*\(' src/ | head

# Subscriptions (often a separate auth flow)
grep -rn 'Subscription\|subscribe\|WebSocketServer\|graphql-ws' src/

# Federation (gateway / subgraph patterns)
grep -rn '@apollo/gateway\|buildSubgraphSchema' src/
```

### Phase 3: Detection — the checks

#### Introspection in production

- **GQL-INTRO-1** Introspection disabled in production OR access-controlled.
  ```ts
  // Apollo Server 4
  const server = new ApolloServer({
    schema,
    introspection: process.env.NODE_ENV !== 'production',
  });
  ```
- **GQL-INTRO-2** Even if "disabled", schema can sometimes be inferred via error messages. Sanitize error responses (see GQL-ERR-1).
- **GQL-INTRO-3** Persisted queries + introspection-disabled = strong stance; client doesn't need introspection if queries are pre-registered.

If introspection must stay on (internal tooling), gate by auth — only authenticated admins.

#### Query depth and complexity

GraphQL queries can recurse via cyclic schema references. Without limits, a single query can cost megabytes of work:

```graphql
query Evil {
  user(id: "1") {
    friends { friends { friends { friends { ... } } } }
  }
}
```

- **GQL-DEPTH-1** Depth limit configured (typical: 10-15). Libraries: `graphql-depth-limit`, built-in to graphql-yoga, configurable in Apollo.
- **GQL-COMP-1** Complexity / cost analysis configured. Libraries: `graphql-query-complexity`, GraphQL Armor.
- **GQL-COMP-2** Per-field cost annotations applied to expensive fields (search, full-text, pagination over large sets).
- **GQL-COMP-3** Alias attack mitigated: counting aliases toward complexity (`a: thing b: thing c: thing` should count as 3, not 1).
- **GQL-COMP-4** Directives like `@stream` and `@defer` (newer specs) have their own cost accounting if enabled.

```ts
import { createComplexityLimitRule } from 'graphql-validation-complexity';
import depthLimit from 'graphql-depth-limit';

const server = new ApolloServer({
  schema,
  validationRules: [
    depthLimit(10),
    createComplexityLimitRule(1000, {
      scalarCost: 1,
      objectCost: 2,
      listFactor: 10,
    }),
  ],
});
```

GraphQL Armor combines all these defaults in one plugin and is the lowest-friction way to deploy them.

#### Field-level authorization

REST has one auth check per endpoint; GraphQL has one auth surface per field. The mistake is checking at the root query and trusting the rest.

- **GQL-AZ-1** Resolvers for fields exposing other users' data check authorization on the parent object, not just the root.
  ```ts
  // BAD — root checks auth but `users` resolver doesn't
  const resolvers = {
    Query: {
      currentUser: requireAuth((parent, args, ctx) => ctx.user),
    },
    User: {
      // Wide-open: anyone who reaches a User can ask for any field
      email: (parent) => parent.email,
      paymentMethods: (parent) => db.paymentMethods.findMany({ where: { userId: parent.id } }),
    },
  };
  ```
  An attacker who navigates to a User from elsewhere (e.g., via a comment's `author` field) gets their email and payment methods.

- **GQL-AZ-2** Use directives or middleware for declarative field authz:
  ```graphql
  directive @auth(requires: Role = USER) on FIELD_DEFINITION
  
  type User {
    id: ID!
    displayName: String!
    email: String! @auth(requires: SELF_OR_ADMIN)
    paymentMethods: [PaymentMethod!]! @auth(requires: SELF)
  }
  ```
  Implement the directive to check `ctx.user` against the parent object on every field.

- **GQL-AZ-3** Tools: GraphQL Shield (rule-based authz), Apollo Connectors with auth context, custom middleware. Don't roll your own per-resolver if you have more than ~20 resolvers — the surface is too large to maintain manually.

#### Mutations

- **GQL-MUT-1** Every mutation checks auth + authz. Sensitive mutations (delete account, change billing, admin actions) require additional verification (MFA, re-auth).
- **GQL-MUT-2** Mutations don't trust input IDs — derive `userId` / `tenantId` from `ctx`, not from arguments.
- **GQL-MUT-3** Mutations idempotent or rate-limited where appropriate.
- **GQL-MUT-4** Input validation via schema or in resolver (use zod / yup / ajv at the resolver boundary; GraphQL types don't validate ranges or formats).

#### Persisted queries

Persisted queries dramatically reduce attack surface: clients send a query hash, server looks up the actual query. Attackers can't send arbitrary queries.

- **GQL-PQ-1** Persisted queries enabled for first-party clients (web, mobile).
- **GQL-PQ-2** Public/external clients (third-party developers, partners) — either allow arbitrary queries with strict depth/complexity, or define a partner API with persisted queries.
- **GQL-PQ-3** Persisted query registry write access restricted to CI/CD pipeline; not writeable from production.
- **GQL-PQ-4** Apollo Persisted Query Manifest workflow or equivalent in use.

#### Batching abuse

```graphql
# Single request, 1000 mutations
mutation BatchEvil {
  m1: addCredit(userId: "self", amount: 1000)
  m2: addCredit(userId: "self", amount: 1000)
  m3: addCredit(userId: "self", amount: 1000)
  # ...
}
```

- **GQL-BAT-1** Limit alias count and operation count per request.
- **GQL-BAT-2** Rate limit mutations server-side per user/tenant — within a single request and across requests.
- **GQL-BAT-3** Idempotency keys for mutations that should not be repeatable.

#### Subscriptions

Subscriptions typically use WebSocket; auth model differs from regular HTTP:

- **GQL-SUB-1** WebSocket connection initialization receives auth token (typically in `connection_params`); validated before subscription is established.
- **GQL-SUB-2** Subscription resolvers re-check auth on every emit — long-running subscription with stale auth that was revoked but never re-checked = security hole.
- **GQL-SUB-3** Subscription topic filters scoped to the authenticated user — never let a client subscribe to "all events" with a server-side filter that may have bugs.

#### Error messages

- **GQL-ERR-1** Production errors don't reveal internal details (stack traces, DB schema, internal IDs).
- **GQL-ERR-2** Apollo Server's `formatError` / yoga's `maskedErrors` configured to strip detail from non-known errors.
- **GQL-ERR-3** Error codes (`extensions.code`) don't leak existence vs permission. Same advice as REST: 404 not 403 for "not authorized to read this resource you can't know exists".
- **GQL-ERR-4** Schema syntax errors in production don't echo back the query verbatim (could log it server-side though).

#### CSRF on GraphQL endpoints

The GraphQL endpoint `/graphql` accepts POST with `application/json`. Combined with CORS misconfig, this can be a CSRF vector for mutations.

- **GQL-CSRF-1** GraphQL endpoint requires a non-form-submittable Content-Type (`application/json`) — most servers do by default, but verify the server enforces this (Apollo Server 4 enforces by default; older versions or custom integrations may not).
- **GQL-CSRF-2** Apollo CSRF Prevention enabled (`csrfPrevention: true` — default in v4).
- **GQL-CSRF-3** SameSite cookies for session — same as REST.

#### Federation / gateway

If using Apollo Federation or similar:

- **GQL-FED-1** Subgraph endpoints not directly reachable from the public internet — only via the gateway.
- **GQL-FED-2** Each subgraph applies auth/authz itself (don't trust the gateway to filter).
- **GQL-FED-3** Federation context propagation (auth claims) signed or otherwise verifiable between gateway and subgraph.

#### Specific library notes

**Apollo Server 4+:**
- Defaults are good: introspection off in production via NODE_ENV, CSRF prevention on, landing page disabled in production.
- Use `ApolloServerPluginUsageReporting` carefully — it sends query data to Apollo Studio; ensure no PII in queries (or anonymize).

**graphql-yoga:**
- Built-in `maskedErrors`, `useResponseCache`. Verify `useGraphqlArmor` plugin enabled for production.
- Yoga 4+ includes GraphQL Armor by default.

**Mercurius (Fastify):**
- `graphiql: true` in production = bad. Check the config.
- `ide: 'graphiql' | 'playground' | false`.

**Hasura:**
- Permissions configured per role per table — review every role's permissions.
- Webhook / JWT auth setup verified.
- `HASURA_GRAPHQL_ADMIN_SECRET` only used for admin operations, never exposed.

**PostGraphile:**
- Built on Postgres RLS for permission — see `saas-security-pack/supabase-security-audit/references/rls-patterns.md` (same patterns).

### Phase 4: Triage

Critical class examples:
- No depth/complexity limits → DoS via single query
- Introspection on in production → schema fully discovered by attacker
- Field-level auth missing on PII-bearing fields
- Mutation accepting userId argument without verifying caller
- Persisted queries advertised but bypass route accepting arbitrary queries

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `GQL-`.

## References

- `references/field-level-auth.md` — Patterns for declarative field authorization (directives, GraphQL Shield, middleware)
