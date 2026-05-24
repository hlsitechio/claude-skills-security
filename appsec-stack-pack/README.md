# AppSec Stack Pack

A collection of 30 defensive security audit skills for Claude, organized by technology stack. Designed to complement `saas-security-pack` (which is organized by audit domain).

The two packs answer different questions:

- **`saas-security-pack`** — "What audit domain do I want to look at?" (supply chain, RLS, tenant isolation, compliance…)
- **`appsec-stack-pack` (this pack)** — "What's the stack I'm reviewing?" (Next.js, Prisma, Clerk, Cloudflare Workers…)

Together they let Claude pick the right skill automatically based on the user's question. For a typical "audit my SaaS" request on a modern stack, both packs activate skills that work together.

## When Claude picks skills from this pack

Each SKILL.md has triggers tuned to its stack. Claude routes based on:

- Direct mentions in the request ("audit my Next.js app", "review my Prisma queries")
- Codebase signals (presence of `next.config.js`, `@clerk/nextjs` in `package.json`, `wrangler.toml`, etc.)
- Stack-specific terminology in the conversation (`use server`, `@PreAuthorize`, `bypassSecurityTrust*`, …)

For a project that uses Next.js + Prisma + Clerk + GraphQL on Vercel, Claude will activate `nextjs-security`, `prisma-orm-security`, `clerk-security`, `graphql-security`, and `vercel-platform-security` — five skills running in parallel.

## The 30 skills

### Frontend (7)

| Skill | Triggers on |
|-------|-------------|
| `react-security` | React, JSX, hooks, `dangerouslySetInnerHTML`, RSC |
| `nextjs-security` | Next.js, App Router, Server Actions, middleware, `NEXT_PUBLIC_` |
| `vite-security` | Vite, `vite.config.ts`, `VITE_*` env vars, Vite plugins |
| `vue-nuxt-security` | Vue 3, Nuxt 3, `v-html`, runtime config, server routes |
| `svelte-sveltekit-security` | Svelte, SvelteKit, `{@html}`, load functions, form actions |
| `angular-security` | Angular, `bypassSecurityTrust*`, route guards, interceptors |
| `electron-security` | Electron, BrowserWindow, IPC, contextBridge, preload scripts |

### Backend — Node ecosystem (4)

| Skill | Triggers on |
|-------|-------------|
| `nodejs-express-security` | Express, Koa, Hapi, middleware ordering, helmet |
| `nestjs-security` | NestJS, Guards, Interceptors, ValidationPipe |
| `fastify-security` | Fastify, schemas, hooks, plugin scopes |
| `hono-security` | Hono on Workers / Bun / Node / Lambda |

### Backend — Python (3)

| Skill | Triggers on |
|-------|-------------|
| `django-security` | Django, settings.py, DRF, ORM, templates |
| `fastapi-security` | FastAPI, Pydantic, Starlette, DI, OAuth2 |
| `flask-security` | Flask, Jinja2, Flask-Login, Flask-WTF |

### Backend — other (5)

| Skill | Triggers on |
|-------|-------------|
| `go-security` | Go, `net/http`, Gin, Echo, Chi, Fiber |
| `rails-security` | Rails, ActiveRecord, ERB, Devise, Pundit |
| `laravel-security` | Laravel, Eloquent, Blade, Sanctum |
| `spring-boot-security` | Spring Boot, Spring Security, JPA, Actuator |
| `dotnet-aspnetcore-security` | ASP.NET Core, EF Core, `[Authorize]`, antiforgery |

### API protocols (3)

| Skill | Triggers on |
|-------|-------------|
| `graphql-security` | GraphQL, Apollo, urql, yoga, Mercurius, Hasura |
| `trpc-security` | tRPC, `protectedProcedure`, `t.middleware` |
| `websocket-security` | WebSocket, ws, socket.io, Phoenix Channels, SignalR |

### Data layer (3)

| Skill | Triggers on |
|-------|-------------|
| `prisma-orm-security` | Prisma, `$queryRaw`, `$queryRawUnsafe`, mass assignment |
| `mongoose-mongodb-security` | MongoDB, Mongoose, NoSQL injection, aggregation |
| `redis-security` | Redis, ioredis, node-redis, ACLs, EVAL |

### Auth providers (2)

| Skill | Triggers on |
|-------|-------------|
| `clerk-security` | Clerk, `@clerk/*`, webhooks (svix), organizations |
| `nextauth-security` | NextAuth, Auth.js, providers, callbacks, JWT vs DB session |

### Edge / Cloud (3)

| Skill | Triggers on |
|-------|-------------|
| `vercel-platform-security` | Vercel, `vercel.json`, env scoping, Deployment Protection, Cron |
| `cloudflare-workers-security` | Workers, `wrangler.toml`, KV, D1, R2, Durable Objects |
| `aws-lambda-security` | Lambda, IAM, Function URLs, layers, VPC config |

## Skill format

Each skill follows the same five-phase workflow (see `_shared/audit-workflow.md`):

1. **Stack detection** — confirm the technology in scope
2. **Inventory** — enumerate the surface
3. **Detection** — apply checks, each tagged with a finding ID (e.g., `NXT-SA-1`)
4. **Triage** — sort by severity
5. **Report** — emit findings using the shared schema (see `_shared/findings-schema.md`)

Finding ID prefixes are locked in `_shared/findings-schema.md` so multi-skill audits produce non-colliding IDs across all 30 skills.

## Installation

These skills live in Claude's skills directory. For Claude Code (local):

```bash
# Clone or download this pack
cd ~/.claude/skills
git clone <this-repo> appsec-stack-pack
```

For Claude Desktop or claude.ai, follow the platform's skill installation flow with this repo's content.

## Per-skill installation (zips)

Run `scripts/package_skills.sh` to produce individual `.zip` files in `dist/` — one per skill. Install just the skills relevant to a given stack.

## Defensive-only

All skills are find-and-fix audits. No skill produces offensive content, exploit code, weaponized payloads, or attack tooling. All findings include remediations.

## Companion pack

Pair with `saas-security-pack` for domain-keyed audits (supply chain, RLS, tenant isolation, code review, API security, frontend hardening, IaC/container, compliance, GitHub repo hardening). Both packs share the same finding schema and triage rubric.

## License

MIT — see `LICENSE`.

## Author

Hubert (rainkode) / HLSI Tech.

Part of the broader Crowbyte / Methora ecosystem.
