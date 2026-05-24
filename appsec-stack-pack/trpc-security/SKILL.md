---
name: trpc-security
description: Security audit for tRPC applications covering procedure auth via middleware, input validation with Zod, protectedProcedure vs publicProcedure patterns, router composition, context creation, batching abuse, output sanitization, and tRPC-specific patterns across Next.js, Express, Fastify, and standalone adapters. Use this skill whenever the user mentions tRPC, @trpc/server, @trpc/client, @trpc/react-query, createTRPCRouter, protectedProcedure, publicProcedure, t.procedure, ctx, or asks "audit my tRPC app", "tRPC security", "tRPC middleware safe". Trigger when the codebase contains `@trpc/server` or `@trpc/client` in package.json.
---

# tRPC Security Audit

Audit tRPC applications. tRPC procedures are RPC endpoints — every procedure is a public surface even if not documented.

## When this skill applies

- Reviewing tRPC router and procedure definitions
- Auditing middleware chains (`use(...)`) for auth
- Reviewing input/output schemas (Zod)
- Checking context creation for auth resolution
- Reviewing protected vs public procedure patterns

## Workflow

Follow `../_shared/audit-workflow.md`.

### Phase 1: Stack detection

```bash
grep -E '"@trpc/(server|client|react-query|next)":' package.json
# Detect adapter
grep -nE 'fetchRequestHandler|createNextApiHandler|createExpressMiddleware|createHTTPServer' src/
```

### Phase 2: Inventory

```bash
# Router definitions
grep -rn 'createTRPCRouter\|router(\|t\.router' src/ | head

# Procedures
grep -rnE 'publicProcedure|protectedProcedure|t\.procedure' src/ | head -50

# Middleware
grep -rn 't\.middleware\|\.use(' src/

# Context creation
grep -rn 'createContext\|createInnerTRPCContext' src/

# Input validation
grep -rn '\.input(' src/ | head -30
```

### Phase 3: Detection — the checks

#### Context creation

The context is where auth resolution happens. Every procedure sees this.

- **TRP-CTX-1** `createContext` reads auth token/cookie and resolves user once per request.
- **TRP-CTX-2** Context doesn't leak secrets (DB password, internal IDs) — only resolved primitives needed by procedures.
- **TRP-CTX-3** Context creation errors don't expose stack traces to client.

```ts
export const createContext = async ({ req }: CreateContextOptions) => {
  const session = await getSessionFromRequest(req);
  return {
    db,
    user: session?.user ?? null,
    // NOT: req (raw request object — leaks too much), env secrets, etc.
  };
};
```

#### Protected vs public procedures

- **TRP-PROC-1** `publicProcedure` reserved for genuinely public endpoints (sign-up, login, public catalog). Everything else uses `protectedProcedure`.
- **TRP-PROC-2** `protectedProcedure` defined via middleware that throws if `ctx.user` is null:
  ```ts
  const isAuthed = t.middleware(({ ctx, next }) => {
    if (!ctx.user) throw new TRPCError({ code: 'UNAUTHORIZED' });
    return next({ ctx: { ...ctx, user: ctx.user } });
  });
  export const protectedProcedure = t.procedure.use(isAuthed);
  ```
- **TRP-PROC-3** No `publicProcedure` doing user-specific reads or mutations. Audit each public procedure: would it make sense for an anonymous attacker to call?

#### Input validation

- **TRP-IN-1** Every procedure has `.input(z.object({ ... }))`. Procedures without `.input` accept anything.
- **TRP-IN-2** Input schemas use strict constraints (min/max length, format, enum). No `z.any()` or `z.unknown()`.
- **TRP-IN-3** `z.object({...}).strict()` (rejects extras) or default strip — never `.passthrough()`.
- **TRP-IN-4** No `userId`/`tenantId` in inputs — derive from `ctx.user`.

```ts
// BAD
export const updateProfile = protectedProcedure
  .input(z.object({ userId: z.string(), name: z.string() }))
  .mutation(({ input, ctx }) => {
    return ctx.db.user.update({ where: { id: input.userId }, data: { name: input.name } });
    // Attacker: { userId: 'someone-else', name: 'pwned' }
  });

// GOOD
export const updateProfile = protectedProcedure
  .input(z.object({ name: z.string().min(1).max(50) }))
  .mutation(({ input, ctx }) => {
    return ctx.db.user.update({ where: { id: ctx.user.id }, data: { name: input.name } });
  });
```

#### Authorization (per-resource)

- **TRP-AZ-1** Procedures touching specific resources verify ownership/role on that resource:
  ```ts
  export const deletePost = protectedProcedure
    .input(z.object({ postId: z.string().uuid() }))
    .mutation(async ({ input, ctx }) => {
      const post = await ctx.db.post.findUnique({ where: { id: input.postId } });
      if (!post) throw new TRPCError({ code: 'NOT_FOUND' });
      if (post.authorId !== ctx.user.id) throw new TRPCError({ code: 'FORBIDDEN' });
      return ctx.db.post.delete({ where: { id: input.postId } });
    });
  ```
- **TRP-AZ-2** Role checks via middleware: `adminProcedure = protectedProcedure.use(requireAdmin)`.
- **TRP-AZ-3** No procedure trusts an input field to determine "whose data" to read/write.

#### Output filtering

- **TRP-OUT-1** Procedures returning DB entities project to safe DTOs — no `passwordHash`, `mfaSecret`, internal flags.
- **TRP-OUT-2** Optional `.output(schema)` validates response shape; useful to catch accidental field leakage in code review.

#### Error handling

- **TRP-ERR-1** `TRPCError` codes used appropriately (UNAUTHORIZED 401, FORBIDDEN 403, NOT_FOUND 404, BAD_REQUEST 400).
- **TRP-ERR-2** Error messages don't leak internal details. Custom `errorFormatter` strips stack traces in production.
- **TRP-ERR-3** Avoid revealing existence: return NOT_FOUND when user is not authorized to see a resource exists (vs. FORBIDDEN, which confirms existence).

```ts
const t = initTRPC.context<Context>().create({
  errorFormatter({ shape, error }) {
    return {
      ...shape,
      data: {
        ...shape.data,
        // strip stack in production
        stack: process.env.NODE_ENV === 'production' ? undefined : shape.data.stack,
      },
    };
  },
});
```

#### Batching

tRPC batches multiple procedure calls into one HTTP request by default.

- **TRP-BAT-1** Batch size limits configured (`maxBatchSize` on the link). Default has no hard limit at server; an attacker can send 1000s of calls per request.
- **TRP-BAT-2** Rate limiting per user accounts for batched calls (count procedures, not HTTP requests).

#### Rate limiting

- **TRP-RL-1** Procedures (especially mutations) have rate limiting. Middleware-based limiter using Redis/Upstash:
  ```ts
  const rateLimited = t.middleware(async ({ ctx, next, path }) => {
    const key = `rl:${ctx.user?.id ?? ctx.ip}:${path}`;
    const { success } = await ratelimit.limit(key);
    if (!success) throw new TRPCError({ code: 'TOO_MANY_REQUESTS' });
    return next();
  });
  ```

#### CSRF / origin handling

When tRPC procedures are called via HTTP from a browser:
- **TRP-CSRF-1** If using cookie auth, origin check applied on the handler (most adapters allow custom request inspection).
- **TRP-CSRF-2** Bearer/JWT auth doesn't need CSRF.

#### Subscriptions

If using tRPC subscriptions (WebSocket):
- **TRP-SUB-1** WebSocket upgrade authenticated. Subscription handlers re-check auth on emit.
- **TRP-SUB-2** Subscription topics scoped to the user; no shared global topics carrying per-user data.

#### Logging

- **TRP-LOG-1** Procedure input/output logging excludes sensitive fields (passwords, tokens, PII).
- **TRP-LOG-2** Slow-procedure logging captures path + duration, not full payloads.

#### Dependencies

- **TRP-DEP-1** tRPC v10 or v11. v9 is legacy.
- **TRP-DEP-2** Companion packages (`@trpc/server`, `@trpc/client`, `@trpc/react-query`) on same major version.

### Phase 4: Triage

Critical: `publicProcedure` doing sensitive operations; procedure accepting `userId` from input; missing input schema; batch DoS surface.

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `TRP-`.
