<p align="center">
  <img src="docs/banner.png" alt="claude-skills-security — 39 Defensive Security Audit Skills for SaaS Apps" width="100%">
</p>

# claude-skills-security

A collection of **39 defensive security audit skills for Claude**, organized as two complementary packs.

The packs answer different questions, and Claude picks skills from either (or both) based on what the user is asking:

| Pack | Organized by | Activates when |
|------|--------------|----------------|
| **[saas-security-pack](./saas-security-pack)** (9 skills) | Audit domain | "Review my supply chain", "Audit our RLS", "Check tenant isolation", "Compliance review" |
| **[appsec-stack-pack](./appsec-stack-pack)** (30 skills) | Technology stack | "Audit my Next.js app", "Review my Prisma queries", "Is my Clerk webhook safe", "Cloudflare Workers security" |

For a typical "audit my SaaS" request on a modern stack, both packs activate skills that work together — domain-keyed audits (RLS, supply chain) running alongside stack-keyed audits (Next.js, Prisma, Clerk).

## Quick example

User asks: *"Audit my Next.js + Prisma + Clerk app on Vercel for security issues."*

Claude activates:
- `nextjs-security` (NXT-) — App Router, Server Actions, env exposure
- `prisma-orm-security` (PRI-) — raw queries, mass assignment, IDOR
- `clerk-security` (CLK-) — webhook signatures, key handling, middleware
- `vercel-platform-security` (VRC-) — env scoping, Deployment Protection, Cron
- `saas-code-security-review` (SCSR-) — generic auth/IDOR/SSRF patterns
- `saas-frontend-hardening` (SFH-) — CSP, cookies, headers
- `saas-tenant-isolation` (STI-) — multi-tenant data partitioning

Seven skills run, each emitting findings with its own prefix. The combined report is severity-sorted and de-duplicated.

## The 39 skills

### saas-security-pack — domain-keyed (9)

| Skill | Prefix | Covers |
|-------|--------|--------|
| `github-supply-chain` | GHSC | Actions pinning, dependabot, secret scanning, SBOM |
| `github-repo-hardening` | GHRH | Branch protection, environments, CODEOWNERS, signed commits |
| `saas-code-security-review` | SCSR | Auth, AuthZ, IDOR, SSRF, JWT, secrets, sinks, deserialization |
| `supabase-security-audit` | SUPA | RLS policies, SECURITY DEFINER, anon role exposure, storage policies |
| `saas-tenant-isolation` | STI | Per-tenant scoping across DB, cache, search, files, queues |
| `saas-api-security` | SAPI | REST conventions, rate limits, webhooks, idempotency, CORS |
| `saas-frontend-hardening` | SFH | CSP, cookies, CORS, headers, secrets in bundle |
| `iac-container-security` | IACS | Terraform, Dockerfile, Kubernetes manifests, image scanning |
| `saas-compliance-audit` | SCMP | SOC 2, GDPR/CCPA, evidence collection, audit logs |

### appsec-stack-pack — tech-keyed (30)

**Frontend (7)**: react · nextjs · vite · vue-nuxt · svelte-sveltekit · angular · electron

**Backend Node (4)**: nodejs-express · nestjs · fastify · hono

**Backend Python (3)**: django · fastapi · flask

**Other backends (5)**: go · rails · laravel · spring-boot · dotnet-aspnetcore

**API protocols (3)**: graphql · trpc · websocket

**Data layer (3)**: prisma-orm · mongoose-mongodb · redis

**Auth providers (2)**: clerk · nextauth

**Edge/Cloud (3)**: vercel-platform · cloudflare-workers · aws-lambda

See [`appsec-stack-pack/README.md`](./appsec-stack-pack/README.md) for the full table with triggers.

## Skill format

Every skill follows the same shape:

```
<skill-name>/
├── SKILL.md            # YAML frontmatter + 5-phase audit workflow
├── references/         # Optional deep-dive companion docs
│   └── <topic>.md
└── assets/             # Optional scripts / fixtures
```

Every audit emits findings using the shared schema in each pack's `_shared/findings-schema.md`. Finding IDs are prefixed with a 3-letter skill code so combined reports don't collide.

## Installation

Each pack is independently installable. For Claude Code:

```bash
cd ~/.claude/skills
git clone https://github.com/hlsitechio/claude-skills-security.git
# Use a specific pack:
cp -r claude-skills-security/saas-security-pack ./saas-security-pack
cp -r claude-skills-security/appsec-stack-pack ./appsec-stack-pack
```

For Claude Desktop or claude.ai, follow the platform's skill installation flow.

Each pack also has a `scripts/package_skills.sh` that produces per-skill `.zip` files in `dist/` for selective installation.

## Design principles

- **Defensive only.** Every skill is find-and-fix. No offensive content, no weaponized payloads.
- **One question per skill.** Skills don't try to cover the universe — each has a narrow trigger surface so Claude can route accurately.
- **Multi-skill orchestration.** A real audit often activates 5+ skills. Finding ID prefixes prevent collision; the combined report is severity-sorted.
- **Reproducible evidence.** Every finding has a file:line reference and a copy-pasteable remediation.

## Companion projects

- **[Crowbyte](https://crowbyte.io)** — Offensive security platform (red team / blue team / purple team modes)
- **[Methora](https://methora.com)** — Reference implementation of the Interpretation Contract Layer

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for skill format, triggers, and contribution flow.

## License

MIT — see [`LICENSE`](./LICENSE).

## Author

**Hubert (rainkode) / HLSI Tech** — Longueuil, QC.
