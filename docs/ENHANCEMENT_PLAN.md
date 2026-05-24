# Enhancement Plan — claude-skills-security

Generated 2026-05-23 from a multi-agent review of all 40 skills (9 sub-agents working in parallel, one per skill category, each researching upstream sources online and producing per-skill findings).

This document is the canonical backlog the daily Copilot review draws from. Each per-skill block lists tier, gaps, version drift, recommended new references, new checks to add, and citations.

## Methodology

A baseline audit found three tiers:

| Tier | Count | Definition |
|------|-------|------------|
| Rich | 10 | ≥3 reference files (the 9 saas-security-pack skills + `web-platform-security`) |
| Partial | 7 | 1–2 reference files (`react`, `nextjs`, `vite`, `nodejs-express`, `prisma-orm`, `graphql`, `django`, `fastapi`, `flask`) |
| Thin | 23 | SKILL.md only |

Each category was reviewed by an agent with web access. Agents focused on: current upstream versions, security-relevant changes since the SKILL.md was authored, and recent CVEs (2024–May 2026).

## Top drift findings (priority — ship now)

Surfaced across multiple skills, ranked by exploitability:

| # | Item | Severity | Affected skills |
|---|------|----------|------------------|
| 1 | **CVE-2025-49844 RediShell** (Redis Lua UAF → RCE, CVSS 10.0) | CRITICAL | `redis-security` |
| 2 | **CVE-2025-29927** (Next.js middleware bypass via `x-middleware-subrequest`) | CRITICAL | `nextjs-security`, `nextauth-security`, `vercel-platform-security`, `clerk-security` |
| 3 | **React Server Components CVE-2025-55182 cluster** (Dec 2025, CVSS 10.0 RCE) | CRITICAL | `react-security`, `nextjs-security` |
| 4 | **CVE-2025-55315** (.NET Kestrel request smuggling, CVSS 9.9 — Microsoft's highest-ever) | CRITICAL | `dotnet-aspnetcore-security` |
| 5 | **CVE-2026-40372** (ASP.NET Core DataProtection HMAC bypass — forgeable auth cookies) | CRITICAL | `dotnet-aspnetcore-security` |
| 6 | **CVE-2025-49844 / CVE-2025-21605** Redis cluster | CRITICAL | `redis-security` |
| 7 | **Mongoose CVE-2024-53900 + CVE-2025-23061** (`$where` via `populate.match`, CVSS 9.0) | CRITICAL | `mongoose-mongodb-security` |
| 8 | **CVE-2025-41248 / 41232** (Spring Security generic / private-method annotation authz bypass) | HIGH | `spring-boot-security` |
| 9 | **CVE-2026-39363** (Vite dev-server WebSocket arbitrary file read) | HIGH | `vite-security` |
| 10 | **GHSA-w332-q679-j88p** (Hono `serve-static` path traversal pre-4.11.7 on Workers) | HIGH | `hono-security` |
| 11 | **CVE-2026-32635** (Angular i18n attribute binding XSS — v17/v18 unpatched) | HIGH | `angular-security` |
| 12 | **CVE-2026-34769** (Electron commandLineSwitches injection) | HIGH | `electron-security` |
| 13 | **SvelteKit Jan/Apr 2026 advisory cluster** (CVE-2025-67647 SSRF + DoS + 5 more) | HIGH | `svelte-sveltekit-security` |
| 14 | **Multer CVE-2025-47944 / 47935 / 7338** (DoS / RCE class) | HIGH | `nodejs-express-security` |
| 15 | **Starlette CVE-2025-62727** (Range-header DoS) | HIGH | `fastapi-security` |
| 16 | **Werkzeug 3.0.6 cluster** (CVE-2024-49766 safe_join, CVE-2024-49767 multipart DoS, CVE-2024-34069 debugger CSRF) | HIGH | `flask-security` |
| 17 | **Jinja2 CVE-2024-22195 / CVE-2025-27516** (xmlattr HTML injection, attr-sandbox escape) | HIGH | `flask-security`, `django-security` |
| 18 | **Django Feb 2026 SQLi cluster** | HIGH | `django-security` |
| 19 | **Laravel Reverb CVE GHSA-m27r-m6rx-mhm4** (CVSS 9.8 deser RCE via Redis adapter) | HIGH | `laravel-security` |
| 20 | **Active Storage CVE-2025-24293** (Rails RCE) | HIGH | `rails-security` |

## Per-pack priority order (deepest gaps first)

1. **redis-security** — RediShell CVE 10.0 affects every Redis version pre-Oct 2025; zero references
2. **mongoose-mongodb-security** — Multiple CVSS 9.0+ CVEs unaddressed; zero references
3. **electron-security** — Modern fuses model not covered; recent CVEs missing
4. **react-security** + **nextjs-security** — December 2025 RSC CVE cluster, May 2026 13-CVE patch wave
5. **svelte-sveltekit-security** — Major Jan/Apr 2026 CVE wave; zero references
6. **dotnet-aspnetcore-security** — Two 2025 CVSS 9.0+ CVEs missing
7. **rails-security** — Pre-Rails-8 mental model; built-in auth gen + AR Encryption missing
8. **laravel-security** — Pre-Laravel-11 app structure; Octane state-leak class missing
9. **spring-boot-security** — 2025 authz-bypass CVEs missing
10. **django-security** — 4.2 LTS reaches EOL today (2026-05-23); 5.x changes uncovered
11. **vite-security** — April 2026 CVE-2026-39363 missing
12. **angular-security** — v20 zoneless / signals not covered; i18n XSS CVE unaddressed
13. **vue-nuxt-security** — Nuxt 4 missing entirely; vue-i18n CVEs absent
14. **clerk-security** — Core 3 (Mar 2026) breaking changes; M2M tokens missing
15. **nextauth-security** — v5 still beta; CVE-2025-29927 weaponizes middleware
16. **websocket-security** — ws / socket.io / engine.io CVE chain missing
17. **trpc-security** — v11 (async-gen subscriptions, SSE) not covered
18. **graphql-security** — Apollo Server 5, GraphQL Armor v3, persisted-vs-APQ confusion
19. **prisma-orm-security** — TypedSQL, RLS-with-`$extends`, operator injection missing
20. **nodejs-express-security** — Express 5 stable, Multer cluster
21. **nestjs-security** — v11 lifecycle order reversal
22. **fastify-security** — v5 + `@fastify/multipart` CVEs
23. **hono-security** — GHSA-w332 + CVE-2024-48913
24. **fastapi-security** — Pydantic v2 / `Annotated` / `lifespan` modernization
25. **flask-security** — Werkzeug + Jinja2 CVE cluster
26. **go-security** — 1.22 routing, FIPS 140-3, CVE-2025-22871
27. **vercel-platform-security** — Vercel Firewall, Blob, OIDC federation
28. **cloudflare-workers-security** — Secrets Store, `nodejs_compat`, Workers AI
29. **aws-lambda-security** — SnapStart, Response Streaming, Lambda@Edge, layer foothold
30. (saas-security-pack) — All 9 are rich but each has 2026 standard drift (HIPAA NPRM, EU AI Act, Cosign v3, EKS Pod Identity, Cilium NetworkPolicy v2, Supabase asymmetric JWT)

---

# Frontend (7)

## react-security
**Tier**: partial. 183-line SKILL.md, ~33 checks, 1 reference (`jsx-xss-sinks.md`).

**Gaps**: Only 1 ref. No coverage of Dec 2025 RSC CVE cluster (CVE-2025-55182 RCE CVSS 10.0, CVE-2025-55183 source exposure, CVE-2025-55184, CVE-2025-67779, CVE-2026-23864). React 19 Actions / `useActionState` / `useFormStatus` not in checks. `experimental_taintObjectReference` / `taintUniqueValue` absent. React 19.2 `<Activity>` not addressed.

**Version drift**: React implied 16/17/18/19, current **19.2.6** (Oct 2025), severity **HIGH** — Dec 2025 RCE (CVSS 10.0) requires 19.0.1 / 19.1.2 / 19.2.1+.

**Recommended new references**:
- `references/rsc-flight-protocol-security.md` (~250 lines) — Server/Client boundary, Flight deserialization sinks, CVE-2025-55182 explained, `'use server'` endpoint surface, taint APIs.
- `references/react-19-actions-and-forms.md` (~200 lines) — Actions lifecycle, CSRF in Server Actions, Zod validation, auth-check placement.
- `references/taint-apis-and-secret-boundaries.md` (~150 lines) — `experimental_taintObjectReference`, `experimental_taintUniqueValue`, transformation laundering.

**New checks**:
- `RCT-RSC-5` — React/react-server-dom-* on patched line (≥19.0.4/19.1.5/19.2.4) — CVE-2025-55182.
- `RCT-RSC-6` — Server Functions rate-limited + WAF rule for malformed Flight payloads.
- `RCT-RSC-7` — No hardcoded secrets in Server Function module scope (CVE-2025-55183 source exposure).
- `RCT-ACT-1` — Every Server Action invoked via `useActionState` validates session before reading FormData.
- `RCT-TNT-1` — `experimental_taintObjectReference` applied to user DB records before client-bound projection.
- `RCT-ACT-2` — Optimistic updates reconcile failures don't expose server error details.

**Citations**: react.dev/blog/2025/12/03 advisory, react.dev/blog/2025/12/11 DoS advisory, GHSA-9qr9-h5gf-34mp, react.dev/blog/2025/10/01/react-19-2, react.dev/reference/react/experimental_taintUniqueValue.

---

## nextjs-security
**Tier**: partial. 191-line SKILL.md, ~30 checks, 1 reference (`app-router-patterns.md`).

**Gaps**: Only 1 ref. May 2026 13-CVE patch wave missing. CVE-2025-49826 (204 cache poisoning) not covered. `/_next/image` 4GB OOM (CVE-2025-59471) absent. WebSocket-upgrade SSRF (GHSA-c4j6-fc7j-m34r) missing. Server Action Flight RCE (CVE-2025-66478) not covered. Next 15.x experimental taint config not surfaced.

**Version drift**: Next implied 15.x pre-15.2.3, current **16.2.6 / 15.5.18** (May 2026), severity **HIGH** — May 2026 patch wave landed 13 CVEs.

**Recommended new references**:
- `references/next-image-and-ssrf.md` (~200 lines) — `remotePatterns` strict patterns, self-hosted vs Vercel-hosted differences, 4GB OOM, WebSocket-upgrade SSRF, blind-SSRF detection.
- `references/server-actions-rce-and-csrf.md` (~250 lines) — Flight protocol RCE, Action-ID enumeration, CSRF model, rate limiting.
- `references/cache-and-revalidation-security.md` (~150 lines) — `cache: 'no-store'`, per-user cache tags, CVE-2025-49826, `revalidateTag` auth.
- `references/middleware-and-edge.md` (~150 lines) — CVE-2025-29927 deep dive, matcher correctness, defense-in-depth, Edge-vs-Node crypto.

**New checks**:
- `NXT-DEP-2` — Next ≥15.5.18 / 16.2.6 (May 2026 wave) AND react-server-dom-* patched.
- `NXT-SA-7` — No hardcoded secrets in Server Action module scope (CVE-2025-55183).
- `NXT-IMG-5` — Image optimizer has request-size cap (CVE-2025-59471).
- `NXT-IMG-6` — Self-hosted `/_next/image` not reachable for upstream WebSocket upgrade.
- `NXT-CACHE-1` — Static pages with auth-gated content set `dynamic = 'force-dynamic'` (CVE-2025-49826 mitigation).
- `NXT-CACHE-2` — `revalidateTag` callers re-check auth before invalidating user-scoped tags.
- `NXT-TNT-1` — `next.config.js` `experimental.taint: true` set when handling user records in RSC.

**Citations**: vercel.com/changelog/next-js-may-2026-security-release, nextjs.org/blog/security-update-2025-12-11, securityonline.info CVE-2025-49826, dev.to CVE-2025-59471, nextjs.org/docs/app/api-reference/config/next-config-js/taint, GHSA-9qr9-h5gf-34mp.

---

## vite-security
**Tier**: partial. 157-line SKILL.md, ~32 checks, 1 reference (`env-vite-config.md`).

**Gaps**: Only 1 ref. **CVE-2026-39363** (dev-server WebSocket arbitrary file read, April 2026) missing. Vite 7 release behavior (`allowedHosts: 'auto'`, OAuth-style WebSocket origin) absent. `vite preview` security model not detailed. `optimizeDeps` supply chain risk not covered.

**Version drift**: Vite implied ≤6.x, current **8.0.5 / 7.3.2 / 6.4.2** (April 2026), severity **HIGH** — GHSA-p9ff-h696-f583 affects 6.x/7.x/8.x.

**Recommended new references**:
- `references/dev-server-attack-surface.md` (~250 lines) — `server.host`, `server.fs`, `server.origin`, `allowedHosts`, WebSocket transport, CVE timeline 2024-2026.
- `references/plugin-supply-chain.md` (~150 lines) — plugin permission model, `transformIndexHtml` injection, typosquatting cases.
- `references/build-output-hardening.md` (~150 lines) — sourcemap strategies, `define`/`envPrefix` interaction.

**New checks**:
- `VIT-DEV-8` — Vite ≥6.4.2 / 7.3.2 / 8.0.5 (CVE-2026-39363).
- `VIT-DEV-9` — When `server.host` set, `server.ws: false` OR explicit Origin allowlist.
- `VIT-DEV-10` — `server.origin` set when dev server reachable; DNS rebinding guarded.
- `VIT-PLG-5` — Build-time plugins audited for outbound network calls.
- `VIT-BLD-5` — `optimizeDeps.exclude` audited; pre-bundled deps pinned.
- `VIT-PRV-1` — `vite preview` not exposed to public internet.

**Citations**: github.com/vitejs/vite/security/advisories/GHSA-p9ff-h696-f583, advisories.gitlab.com CVE-2026-39363, securityonline.info CVE-2026-39364, offsec.com CVE-2025-30208, app.opencve.io vitejs.

---

## vue-nuxt-security
**Tier**: thin. 162-line SKILL.md, ~25 checks, **0 references**.

**Gaps**: Zero refs. Nuxt 4 (July 2025) not covered. `vue-i18n` prototype-pollution XSS (CVE-2024-52809, CVE-2025-53892) absent. Nuxt HMAC-signed proxy endpoints (Nuxt 4.x) not in checks. `payload.json` cache-poisoning DoS class (zhero-web-sec, 2025) absent.

**Version drift**: Nuxt implied <3.13, current **4.x** (4.4.x), severity **MEDIUM** — Nuxt 4 reorganized `app/` and added HMAC for proxy endpoints. Vue 3.5.x.

**Recommended new references**:
- `references/template-xss-and-prototype-pollution.md` (~200 lines) — `v-html`, CVE-2024-6783 prototype-pollution, `vue-i18n` advisories.
- `references/nuxt-server-routes-and-h3.md` (~250 lines) — defineEventHandler, `requireUserSession`, h3 utilities, Nuxt 4 HMAC proxy signing.
- `references/runtime-config-and-payload-leakage.md` (~180 lines) — `runtimeConfig` vs `.public`, `__NUXT__` payload, payload.json caching.

**New checks**:
- `VUE-XSS-4` — `vue-i18n` ≥9 patched (CVE-2024-52809, CVE-2025-53892).
- `VUE-PP-1` — `Object.freeze(Object.prototype)` to mitigate CVE-2024-6783 class.
- `VUE-DEP-4` — Nuxt ≥4.x (or 3.x patched).
- `NXT-SR-5` — Nuxt server routes use `getValidatedRouterParams` / `readValidatedBody` with Zod.
- `NXT-SR-6` — Proxy endpoints use HMAC signing (Nuxt 4).
- `NXT-PL-1` — `__NUXT__` payload contains no per-user data on prerendered routes.
- `NXT-PL-2` — `payload.json` auth-gated or disabled when carrying per-user state.

**Citations**: nuxt.com/blog/v4, nuxt.com/docs/4.x/guide/going-further/runtime-config, sentinelone.com CVE-2024-6783, GHSA-9r9m-ffp6-9x4v, security.snyk.io SNYK-JS-VUEI18N-10771082, zhero-web-sec.github.io/research-and-things/nuxt-show-me-your-payload.

---

## svelte-sveltekit-security
**Tier**: thin. 188-line SKILL.md, ~24 checks, **0 references**.

**Gaps**: Five CVEs Jan 2026 + April 2026 (CVE-2025-67647 SSRF/DoS, CVE-2026-22803 crash, BODY_SIZE_LIMIT bypass, handle-hook redirect DoS, query.batch cross-talk, Remote Functions type-coercion memory amp) — none referenced. Remote Functions (`.remote.ts`) not covered. `adapter-node` ORIGIN env-var requirement absent.

**Version drift**: SvelteKit implied 1.x/2.x patched, current **2.49.5+** (Jan 2026), severity **HIGH** — CVE-2025-67647 affects 2.19.0–2.49.4.

**Recommended new references**:
- `references/sveltekit-2025-cve-cluster.md` (~250 lines) — Full timeline of Jan/Apr 2026 advisory wave with per-CVE root cause, fix versions, audit query.
- `references/remote-functions-security.md` (~200 lines) — `.remote.ts` model, `query.batch`, Standard Schema validation, type-coercion attack, batch cross-talk.
- `references/load-actions-and-csrf.md` (~150 lines) — universal vs server load, form actions CSRF, `csrf.checkOrigin`, `+server.ts`, `handle` hook auth.

**New checks**:
- `SVK-DEP-3` — SvelteKit ≥2.49.5 AND adapter-node ORIGIN env-var set.
- `SVK-RF-1` — Remote Functions validate inputs with Standard Schema; explicit number coercion (GHSA-vrhm-gvg7-fpcf).
- `SVK-RF-2` — Remote Functions check `event.locals.user` before DB access.
- `SVK-RF-3` — `query.batch` callsites don't share state across batched requests (GHSA-hgv7-v322-mmgr).
- `SVK-HK-4` — `handle` hook redirect targets validated against allowlist.
- `SVK-ADP-1` — `@sveltejs/adapter-node` BODY_SIZE_LIMIT enforced at adapter + proxy (GHSA-2crg-3p73-43xp).
- `SVK-PRE-1` — Prerendered routes don't embed per-user data; `ORIGIN` env set.
- `SVK-XSS-2` — `+page.ts` doesn't render unescaped `search_params` (CVE-2025-32388).

**Citations**: svelte.dev/blog/cves-affecting-the-svelte-ecosystem, GHSA-j62c-4x62-9r35, zhero-web-sec.github.io paradox-SSR research, dev.to GHSA-VRHM-GVG7-FPCF post, svelte.dev/docs/kit/remote-functions, GHSA-6q87-84jw-cjhp.

---

## angular-security
**Tier**: thin. 165-line SKILL.md, ~24 checks, **0 references**.

**Gaps**: Zero refs. Angular 20 (May 2025) — signals stable, zoneless, new template syntax — not addressed. CVE-2026-32635 (i18n attribute binding XSS, affects v17–v22, NO patch for 17/18) absent. CVE-2025-66412 (Template Compiler XSS) missing. Zoneless mode security baseline not covered.

**Version drift**: Angular implied 14+, current **20.x / 21.x LTS**, severity **HIGH** — CVE-2026-32635 affects 17.0.0–18.2.14 unpatched; only 19.2.20 / 20.3.18 / 21.2.4 fixed.

**Recommended new references**:
- `references/sanitizer-and-xss-sinks.md` (~200 lines) — DomSanitizer model, `bypassSecurityTrust*` taxonomy, i18n-attribute bypass, template compiler XSS, Trusted Types in Angular 18+.
- `references/route-guards-and-lazy-loading.md` (~180 lines) — functional guards (`canActivate`, `canMatch`), pre-fetch leak via `loadComponent`, `@defer`.
- `references/csp-trusted-types-and-headers.md` (~150 lines) — Angular CLI CSP integration, Trusted Types policies, `provideRouter` URL serialization.

**New checks**:
- `ANG-XSS-5` — No `i18n-href`/`i18n-src`/`i18n-action` on user-controlled values (CVE-2026-32635).
- `ANG-DEP-4` — Angular core ≥19.2.20 / 20.3.18 / 21.2.4; v17–v18 unpatched, schedule upgrade.
- `ANG-DEP-5` — `@angular/compiler` patched against CVE-2025-66412.
- `ANG-CSP-1` — Trusted Types policy registered with `require-trusted-types-for 'script'`.
- `ANG-RG-5` — Functional guards used over class-based `Injectable` guards (Angular 17+).
- `ANG-ZL-1` — Zoneless apps: manual `markForCheck` in security-sensitive components after async ops.
- `ANG-LAZY-2` — `@defer` blocks with auth-gated content don't load bundle until guard resolves.

**Citations**: herodevs.com/blog-posts/cve-2026-32635, sentinelone.com CVE-2025-66412, cyberpress.org angular-xss-vulnerability, grazitti.com/blog/whats-new-in-angular-20, angular.dev/best-practices/security.

---

## electron-security
**Tier**: thin. 211-line SKILL.md, ~35 checks, **0 references**.

**Gaps**: Zero refs. Electron Fuses model gets one indirect mention — needs dedicated coverage (`runAsNode`, `cookieEncryption`, `embeddedAsarIntegrityValidation`, etc.). CVE-2025-55305 (ASAR Integrity Bypass) absent. CVE-2026-34769 (commandLineSwitches injection) absent. UtilityProcess API (Electron 22+) not covered. Code signing / notarization checks absent.

**Version drift**: Electron implied ≥12, current **38.8.6 / 41.x beta**, severity **HIGH** — CVE-2026-34769 requires 38.8.6 / 39.8.0 / 40.7.0 / 41.0.0-beta.8.

**Recommended new references**:
- `references/fuses-and-asar-integrity.md` (~250 lines) — Every Electron fuse with recommended value, `@electron/fuses` usage, CVE-2025-55305 / CVE-2024-46992 timeline.
- `references/ipc-and-preload-hardening.md` (~200 lines) — contextBridge patterns, `event.senderFrame` validation, UtilityProcess API.
- `references/electron-cve-timeline.md` (~150 lines) — Chronological list of major Electron CVEs 2024-2026.
- `references/auto-updater-and-code-signing.md` (~150 lines) — electron-updater, signed installer (Windows EV, macOS notarization), HTTPS-only update channel.

**New checks**:
- `ELC-FUSE-1` — `runAsNode` fuse disabled.
- `ELC-FUSE-2` — `cookieEncryption` fuse enabled.
- `ELC-FUSE-3` — `embeddedAsarIntegrityValidation` + `onlyLoadAppFromAsar` both enabled.
- `ELC-FUSE-4` — `loadBrowserProcessSpecificV8Snapshot` enabled.
- `ELC-FUSE-5` — `grantFileProtocolExtraPrivileges` disabled.
- `ELC-FUSE-6` — `nodeOptions` and `nodeCliInspect` disabled in production.
- `ELC-WP-8` — No spreading of untrusted config into `webPreferences` (CVE-2026-34769).
- `ELC-ASAR-1` — `app.asar` integrity validated; installer-time write protection (CVE-2025-55305).
- `ELC-IPC-6` — `event.senderFrame.url` checked against allowlist.
- `ELC-VER-2` — Electron ≥38.8.6 / 39.8.0 / 40.7.0 (CVE-2026-34769).
- `ELC-UP-1` — UtilityProcess instances follow main-process IPC rules.

**Citations**: electronjs.org/docs/latest/tutorial/fuses, electronjs.org/docs/latest/tutorial/asar-integrity, GHSA-vmqv-hx8q-j7mg, cvefeed.io CVE-2026-34769, electronjs.org/blog/statement-run-as-node-cves, electronjs.org/blog/breach-to-barrier.

---

# Backend Node (4)

## nodejs-express-security
**Tier**: partial. 238 lines, ~50 checks, 1 reference (`middleware-order-pitfalls.md`).

**Gaps**: 1 ref vs 4. **No Express 5 migration coverage** (path-to-regexp 8.x, removed regex sub-expressions, query-parser changes) despite Express 5 stable since 2025. **May 2025 Multer cluster** (CVE-2025-47944, CVE-2025-47935, CVE-2025-7338) — major real-world risk not flagged by name. Koa/Hapi mentioned in description but Phase 3 is Express-only. No reference for prototype-pollution / ReDoS.

**Version drift**: Express implied 4.x, current **5.1.x stable** (5.0.0 released 2024-10-15), severity **MEDIUM**. Multer not pinned; current safe line is **≥2.0.0** (May 2025), severity **HIGH**.

**Recommended new references**:
- `references/express-5-migration.md` (~200 lines) — path-to-regexp 8 syntax (`*splat`, `{/:name}`), removed regex, query parser changes, async error propagation.
- `references/multer-upload-hardening.md` (~180 lines) — CVE-2025-47944/47935/7338 detail, magic-byte validation, tmpfile cleanup, busboy stream-error handling.
- `references/prototype-pollution-redos.md` (~200 lines) — qs CVE-2022-24999, lodash sinks, safe-regex / re2, body-parser xml CVE-2021-3666.

**New checks**:
- `NDE-EX5-1` — No bare `'*'`, no `:name?`, no regex sub-expressions in route definitions.
- `NDE-EX5-2` — `path-to-regexp ≥8.x` resolved (no transitive 0.1.x).
- `NDE-UPL-8` — `multer ≥2.0.0` (CVE-2025-47944/47935 patched).
- `NDE-UPL-9` — multipart error handler closes busboy streams; no orphan tmp files.
- `NDE-PP-4` — `body-parser ≥1.20.5` / `qs ≥6.13.0`.
- `NDE-DEP-4` — `npm audit` re-run; Express 4.21.2+ if still on v4.
- `NDE-CP-4` — `node:vm` not used as trust boundary; `isolated-vm` if isolation required.

**Citations**: expressjs.com/2024/10/15/v5-release.html, GHSA-4pg4-qvpc-4q3h, expressjs.com/2025/05/19/security-releases.html, GHSA-9wv6-86v2-598j, github.com/expressjs/express/issues/6216.

---

## nestjs-security
**Tier**: thin. 184 lines, ~36 checks, **0 references**.

**Gaps**: Zero refs. **NestJS 11 changes (Jan 2025)**: reversed lifecycle hook order (silently breaks shutdown-order security assumptions), CacheModule v6/Keyv (cross-user cache risk), IntrinsicException, platform-express bumps to Express 5. `class-validator` / `class-transformer` deprecation discussion not flagged. Microservices auth depth absent.

**Version drift**: NestJS implied 10.x/11.x, current **11.1.23+**, severity **MEDIUM**. class-validator has CVE history; deprecation ongoing.

**Recommended new references**:
- `references/validation-pipe-deep-dive.md` (~220 lines) — `whitelist`/`forbidNonWhitelisted`/`transform`, `stripProtoKeys`, `@Type(() => Nested)` requirement, class-validator CVE history, alternatives (zod-pipe).
- `references/guards-and-metadata.md` (~200 lines) — CanActivate contract, global guard + `@Public()` opt-out, Reflector.getAllAndOverride vs Merge, GraphQL ExecutionContext pitfall.
- `references/nestjs-11-and-platform-changes.md` (~180 lines) — v10→v11 security implications, reversed shutdown hooks, IntrinsicException, CacheModule v6.

**New checks**:
- `NST-V11-1` — Shutdown hook order reviewed; auditors flush BEFORE DB/queue close.
- `NST-V11-2` — CacheModule keys include user/tenant scope.
- `NST-V11-3` — Routes audited against Express 5 path syntax (NestJS 11 platform-express).
- `NST-PIPE-5` — DTOs don't use `@Allow()` on user-controlled keys.
- `NST-PIPE-6` — `forbidUnknownValues: true` set explicitly (default false silently accepts non-objects).
- `NST-EX-4` — IntrinsicException used only for non-sensitive errors.
- `NST-MS-4` — Microservice `@MessagePattern` handlers wrap input in DTO + ValidationPipe.
- `NST-GQL-4` — GraphQL guards use `GqlExecutionContext.create(ctx)`, not `ctx.switchToHttp()`.

**Citations**: trilon.io/blog/announcing-nestjs-11-whats-new, nestjs.com/releases, docs.nestjs.com/techniques/validation, nestjs/nest issue #8390, docs.nestjs.com/security/csrf.

---

## fastify-security
**Tier**: thin. 168 lines, ~28 checks, **0 references**.

**Gaps**: Zero refs. No Fastify v5 specifics (dropped Node <20, removed JSON Schema shorthands, stricter AJV defaults, ~20 breaking changes). `@fastify/multipart` CVE-2023-25576 (unlimited parts DoS) and CVE-2025-24033 (tmpfile leak) not mentioned by ID. AJV configuration (`removeAdditional`, `coerceTypes`, `useDefaults`) security implications not covered.

**Version drift**: Fastify implied v4/v5, current **v5.x** (5.0 GA 2024-09-17), severity **MEDIUM**. `@fastify/multipart` not pinned; **≥8.x** (Fastify 5) / **≥7.4.1** (Fastify 4), severity **HIGH**.

**Recommended new references**:
- `references/schema-driven-validation.md` (~220 lines) — JSON Schema patterns, `additionalProperties: false`, response-schema serialization filtering (and risks), AJV `removeAdditional`/`coerceTypes` security implications, `$ref` resolution risks.
- `references/plugin-encapsulation.md` (~180 lines) — scope graph, `fastify-plugin` semantics, hook propagation, encapsulation bugs causing unprotected routes.
- `references/fastify-v5-and-multipart.md` (~200 lines) — v5 breaking changes, `@fastify/multipart` CVE-2023-25576 / CVE-2025-24033 detail, `saveRequestFiles` cleanup.

**New checks**:
- `FST-V5-1` — Node.js ≥20 in `engines` (Fastify v5).
- `FST-V5-2` — No removed shorthand JSON-schema patterns from v4.
- `FST-SCH-6` — AJV `removeAdditional: 'all'` not used without `additionalProperties: false`.
- `FST-SCH-7` — AJV `coerceTypes` audited; don't coerce on security-sensitive fields.
- `FST-MP-1` — `@fastify/multipart ≥8.x` / `≥7.4.1` (CVE-2023-25576).
- `FST-MP-2` — `saveRequestFiles` handles req-abort (CVE-2025-24033).
- `FST-MP-3` — `limits` block explicit: `files`, `fileSize`, `fields`, `parts`.
- `FST-HK-4` — `preParsing` not used to read body (drains stream).

**Citations**: fastify.dev/blog/2024/09/17/fastify-v5/, GHSA-hgmh-h26r-hgg5, vulert.com/vuln-db/CVE-2025-24033, encore.dev/blog/fastify-v5, ostif.org Fastify audit.

---

## hono-security
**Tier**: thin. 165 lines, ~24 checks, **0 references**.

**Gaps**: Zero refs. **GHSA-w332-q679-j88p** (Jan 2026): arbitrary key read in `serve-static` Cloudflare Workers adapter pre-4.11.7 — contradicts current runtime-specific guidance. **CVE-2024-48913** (CSRF middleware bypass via missing Content-Type) absent. Runtime-divergent guidance shallow. Hono's "validator" stack not deeply covered.

**Version drift**: Hono implied 4.x line, current **4.12.22** (May 2026), severity **HIGH** for pre-4.11.7. CSRF middleware pre-patch versions vulnerable to CVE-2024-48913, severity **MEDIUM**.

**Recommended new references**:
- `references/runtime-specific-hardening.md` (~220 lines) — Workers vs Bun vs Node vs Lambda env-binding patterns, `c.env` lifetime, secret rotation across runtimes.
- `references/validators-and-zod.md` (~200 lines) — `@hono/zod-validator` modes, `c.req.valid()` vs `c.req.json()`, error response shape leakage.
- `references/hono-cves-and-middleware.md` (~200 lines) — GHSA-w332-q679-j88p, CVE-2024-48913, secureHeaders config, jwt verifier `none` rejection.

**New checks**:
- `HNO-CVE-1` — `hono ≥4.11.7` if running serve-static on Cloudflare Workers (GHSA-w332-q679-j88p).
- `HNO-CVE-2` — CSRF middleware post-CVE-2024-48913.
- `HNO-CSRF-3` — Dynamic `origin` validator anchored (`/^https:\/\/[^.]+\.example\.com$/`).
- `HNO-VAL-3` — Handlers use `c.req.valid('json')`, never `c.req.json()` for validated routes.
- `HNO-VAL-4` — Validator failure responses don't echo full schema path.
- `HNO-CK-3` — `getSignedCookie` / `setSignedCookie` secret rotated via key list.
- `HNO-ENV-4` — Code portability: `c.env` not assumed defined on Node/Bun; `getRuntimeKey()` used.
- `HNO-MW-5` — `secureHeaders()` CSP set explicitly (default omits CSP).

**Citations**: GHSA-w332-q679-j88p, miggo.io CVE-2024-48913, hono.dev/docs/middleware/builtin/csrf, npmjs.com/package/hono, github.com/honojs/hono/releases.

---

# Backend Python (3)

## django-security
**Tier**: partial. Strong check list (~30), but zero references. Django 4-era mental model.

**Gaps**: Zero refs. **Django 5.1 `LoginRequiredMiddleware`** (default-deny inversion) absent. Async-ORM hazards (`aget`/`aupdate`, `transaction.atomic()` is sync-only). `CSRF_TRUSTED_ORIGINS` vs `CORS_ALLOWED_ORIGINS` confusion. **No recent CVE inventory** (CVE-2024-45230 urlize, CVE-2024-53907 strip_tags, CVE-2024-56374 IPv6, **Feb 2026 SQLi cluster**, CVE-2024-53908).

**Version drift**: Django implied 4.x, current **5.2 LTS** (Apr 2025, supported to Apr 2028) and 5.x stable, severity **MEDIUM** — 4.2 LTS reaches EOL Apr 2026 (today).

**Recommended new references**:
- `references/django5-settings-and-middleware.md` (~250 lines) — Django 5 secure-defaults walkthrough, `LoginRequiredMiddleware` + `@login_not_required`, `SECRET_KEY_FALLBACKS`, `CSRF_TRUSTED_ORIGINS` vs CORS.
- `references/orm-injection-and-async.md` (~200 lines) — Raw SQL safety in 5.x, `RawSQL`/`extra`/`annotate(RawSQL(...))`, async ORM without transactions, Feb-2026 SQLi cluster root cause.
- `references/drf-and-api-surface.md` (~220 lines) — Permission-class precedence, queryset scoping, drf-spectacular exposure, JWT (simplejwt) blacklist & rotation.
- `references/django-cve-inventory.md` (~120 lines) — 2024–2026 patch cadence.

**New checks**:
- `DJG-MID-1` — `LoginRequiredMiddleware` audit; every public view has `@login_not_required` explicitly.
- `DJG-SET-9` — `SECRET_KEY_FALLBACKS` oldest→newest; current `SECRET_KEY` not duplicated.
- `DJG-SET-10` — `STORAGES` config not pointing at unauthenticated public buckets.
- `DJG-ASYNC-1` — `aget`/`aupdate` not used where `select_for_update()` semantics needed.
- `DJG-CSRF-4` — `CSRF_TRUSTED_ORIGINS` is host-allowlist for Origin/Referer, NOT CORS.
- `DJG-DRF-6` — drf-spectacular / Swagger / Redoc gated by `IsAdminUser` or disabled in prod.
- `DJG-DRF-7` — `SessionAuthentication` views serve CSRF via `ensure_csrf_cookie`.
- `DJG-DEP-3` — Django pinned to supported series (4.2 EOL Apr 2026, 5.1 EOL Dec 2025, 5.2 LTS to Apr 2028).
- `DJG-DEP-4` — Recent CVE check: CVE-2024-45230, CVE-2024-53907, CVE-2024-53908 (SQLi), CVE-2024-56374, 2025/2026.
- `DJG-CPK-1` — Composite PK views validate ALL tuple components against requesting user's scope.
- `DJG-AUTH-5` — `PASSWORD_HASHERS` first entry uses Scrypt or Argon2; PBKDF2 fallback only.

**Citations**: docs.djangoproject.com/en/5.2/releases/5.1/, 5.2, security/, djangoproject.com/weblog/2026/feb/03/security-releases/, djangoproject.com/weblog/2026/may/05/security-releases/, NVD CVE-2024-45230, CVE-2024-53907, CVE-2024-56374, OWASP DRF cheatsheet.

---

## fastapi-security
**Tier**: partial. ~30 checks, zero references. Pydantic v1/v2 dual hint, no concrete migration audit. Modern features absent.

**Gaps**: Zero refs. No Pydantic v1→v2 migration audit. **No `Annotated[..., Depends(...)]` pattern** (the 0.95+ canonical form). No `Security(...)` scopes drill-down. **No Starlette CVE-2025-62727** (Range-header DoS). No `BackgroundTasks` data-leak gotcha (closure capture of auth tokens). No `lifespan` migration. No JWT library guidance (**python-jose CVE-2024-33663**). **No fastapi-sso CVE-2025-14546**.

**Version drift**: FastAPI implied ~0.100, current **0.118+** (Pydantic v1 dropped at 0.113), severity **MEDIUM**. Starlette implied <0.40, current **0.49.1+** (CVE-2025-62727 fix), severity **HIGH**. python-jose 3.3.0 last release with CVE-2024-33663, severity **HIGH**.

**Recommended new references**:
- `references/pydantic-v2-validation.md` (~220 lines) — `model_config = ConfigDict(extra='forbid', strict=True)`, `SecretStr`, `field_validator` vs `model_validator`, `model_dump(mode='json')`.
- `references/auth-and-jwt.md` (~250 lines) — `OAuth2PasswordBearer` vs `OAuth2AuthorizationCodeBearer`, `Security(dep, scopes=[...])` enforcement, PyJWT preferred over python-jose, fastapi-users patterns.
- `references/starlette-and-lifespan.md` (~180 lines) — `lifespan` context manager, middleware ordering, `BackgroundTasks` failure modes, CVE-2025-62727.
- `references/cors-csrf-and-docs.md` (~180 lines) — `CORSMiddleware` regex pitfalls, `TrustedHostMiddleware`, `/docs` gating.

**New checks**:
- `FAP-PYD-8` — `Annotated[T, Depends(...)]` form used (not legacy default-arg).
- `FAP-PYD-9` — `SecretStr` for password/secret fields; `model_dump(mode='json')` redacts.
- `FAP-AUTH-6` — `Security(dep, scopes=[...])` reads `security_scopes.scopes`.
- `FAP-AUTH-7` — JWT library is PyJWT≥2.10 or Authlib≥1.3.1; python-jose flagged with CVE-2024-33663.
- `FAP-LIFE-1` — `lifespan` context manager (not `@app.on_event`).
- `FAP-BG-3` — `BackgroundTasks` callable doesn't close over request-scoped auth tokens.
- `FAP-RANGE-1` — Starlette ≥0.49.1 (CVE-2025-62727).
- `FAP-RL-1` — Rate limiting via slowapi / limits / nginx for login/reset/signup.
- `FAP-SSO-1` — If fastapi-sso, ≥0.19.0 (CVE-2025-14546).
- `FAP-CORS-4` — `allow_origin_regex` anchored (`\.example\.com$`).
- `FAP-DEP-3` — `fastapi≥0.118`, `starlette≥0.49.1`, `pydantic≥2.7`; `pip-audit` clean.

**Citations**: fastapi.tiangolo.com/release-notes/, GHSA-7f5h-v6xp-fcq8 (Starlette), GHSA-hp6r-r9vc-q8wx (fastapi-sso CVE-2025-14546), GHSA-5j53-63w8-8625 (fastapi-users CVE-2025-68481), sentinelone.com CVE-2024-33663, docs.pydantic.dev/latest/migration/.

---

## flask-security
**Tier**: partial. ~30 checks. Correctly flags `render_template_string` SSTI and Werkzeug debugger RCE; zero references. **Werkzeug 3.0.6 cluster** (CVE-2024-49766 safe_join, CVE-2024-49767 multipart-DoS) and **Jinja2 CVE-2024-22195** (xmlattr HTML injection) and **CVE-2025-27516** (attr sandbox escape) absent.

**Gaps**: Zero refs. No CVE inventory for Werkzeug / Jinja2. No `SECRET_KEY_FALLBACKS` rotation pattern + **Flask 3.1.0 ordering bug** (GHSA-4grg-w6v8-c28g). No Flask-Login `SESSION_PROTECTION='strong'` audit, remember-me cookie revocation, `login_fresh()`. No Flask-Talisman deep dive.

**Version drift**: Flask implied 3.x (correct); `SECRET_KEY_FALLBACKS` shipped with a bug in 3.1.0. Werkzeug implied "matches Flask," current **3.0.6+** (or 3.1.x), severity **HIGH**. Jinja2 unspecified, current **3.1.6+**, severity **HIGH**.

**Recommended new references**:
- `references/jinja2-ssti-and-xss.md` (~220 lines) — Autoescape-by-extension trap, `render_template_string` SSTI, `xmlattr` (CVE-2024-22195) and `|attr` (CVE-2025-27516) escapes.
- `references/werkzeug-and-debugger.md` (~180 lines) — Werkzeug 3.0.6 baseline (CVE-2024-49766, CVE-2024-49767, CVE-2024-34069), `safe_join`/`send_from_directory`, `MAX_CONTENT_LENGTH`.
- `references/flask3-config-and-sessions.md` (~200 lines) — `SECRET_KEY_FALLBACKS` + 3.1.0 ordering bug (GHSA-4grg-w6v8-c28g), signed-cookie vs server-side sessions, Flask-Talisman CSP nonces.
- `references/flask-login-and-csrf.md` (~180 lines) — `SESSION_PROTECTION='strong'`, fresh-login, remember-me revocation, Flask-WTF CSRFProtect ordering.

**New checks**:
- `FLK-CFG-6` — `SECRET_KEY_FALLBACKS` ordered oldest→newest; not on Flask 3.1.0 exactly.
- `FLK-XSS-5` — Jinja `select_autoescape(['html', 'xml'])` for non-`.html` templates; user input never used as `xmlattr` key (CVE-2024-22195).
- `FLK-XSS-6` — Sandboxed environments on Jinja2 ≥3.1.6 (CVE-2025-27516).
- `FLK-AUTH-7` — `SESSION_PROTECTION='strong'`; `login_fresh()` for sensitive actions.
- `FLK-AUTH-8` — Remember-me alternative token, revocable, max age ≤30 days.
- `FLK-UP-5` — Werkzeug ≥3.0.6 (CVE-2024-49767); `MAX_CONTENT_LENGTH` set.
- `FLK-PATH-1` — `safe_join` callers on Windows Python ≥3.11 OR Werkzeug ≥3.0.6 (CVE-2024-49766).
- `FLK-DBG-4` — Werkzeug ≥3.0.3 (CVE-2024-34069 debugger CSRF); debugger never in production.
- `FLK-HDR-2` — Flask-Talisman CSP uses nonces via `csp_nonce()`, no `'unsafe-inline'`.
- `FLK-DEP-4` — `werkzeug≥3.0.6`, `jinja2≥3.1.6`, `flask≥3.1.1` (avoid 3.1.0), `markupsafe≥2.1`.

**Citations**: flask.palletsprojects.com/en/stable/changes/, GHSA-4grg-w6v8-c28g (Flask 3.1.0 inversion), NVD CVE-2024-49767, GHSA-f9vj-2wh5-fj8j (CVE-2024-49766), sentinelone.com CVE-2024-34069, GHSA-h5c8-rqwp-cp95 (Jinja xmlattr), GHSA-cpwx-vrp4-4pq7 (Jinja attr-sandbox), sploitus.com PACKETSTORM:212501 (Flask 3.0.0 RCE chain).

---

# Other backends (5)

## go-security
**Tier**: thin. Solid baseline checks for stdlib `net/http`, frameworks, SQL, path-traversal, CORS, JWT.

**Gaps**: Zero refs. No Go 1.22+ `ServeMux` method/wildcard routing. **CVE-2025-22871** (net/http chunked LF request smuggling) absent. **FIPS 140-3 native mode** (`GODEBUG=fips140=on`) — replaces `GOEXPERIMENT=boringcrypto` — not covered. Concurrency checks shallow.

**Version drift**: Go implied 1.18+, current **Go 1.25** (Aug 2025), severity **MEDIUM**.

**Recommended new references**:
- `references/net-http-modern.md` (~220 lines) — Go 1.22 ServeMux security, `MaxBytesReader`, `ReadHeaderTimeout`, smuggling defenses post-CVE-2025-22871.
- `references/crypto-and-fips.md` (~180 lines) — `crypto/tls` MinVersion, FIPS 140-3 native mode, boringcrypto deprecation, `crypto/rand` vs `math/rand/v2`.
- `references/concurrency-and-context.md` (~190 lines) — `r.Context()` propagation, goroutine leaks, race-detector in CI, `errgroup` cancellation.

**New checks**:
- `GOL-HTTP-1` — Server has `ReadHeaderTimeout`/`ReadTimeout`/`WriteTimeout` set (Slowloris).
- `GOL-HTTP-2` — Go runtime ≥1.23.8 or 1.24.2 (CVE-2025-22871).
- `GOL-HTTP-3` — `ServeMux` patterns use explicit method (`GET /path`) for 405 semantics.
- `GOL-CRYPTO-4` — If FIPS required, `GODEBUG=fips140=on`; `GOEXPERIMENT=boringcrypto` migrated.
- `GOL-CRYPTO-5` — `math/rand` v1 not used for security; `math/rand/v2` non-security only.
- `GOL-CTX-4` — Goroutines spawned in handlers receive context derived from `r.Context()`.
- `GOL-JSON-1` — `json.Decoder.DisallowUnknownFields()` + bounded reader before unmarshal.

**Citations**: go.dev/blog/routing-enhancements, wiz.io CVE-2025-22871, go.dev/doc/security/fips140, github.com/securego/gosec.

---

## rails-security
**Tier**: thin. Strong Devise/Pundit/strong-params coverage but pre-Rails-8.

**Gaps**: Zero refs. **Rails 8 native authentication generator** (sessions table, `has_secure_password`, password_reset_token expiry) missing — most users use this now over Devise. **Active Record Encryption** entirely absent. **CVE-2025-24293** (Active Storage RCE via unsafe transformation) and **CVE-2025-55193** (ANSI escape injection in AR logging) absent. `host_authorization` middleware, Propshaft, Rails 8's no-Node default not covered.

**Version drift**: Rails implied 6/7/8, current **8.0.2.1** (Aug 2025), severity **MEDIUM**.

**Recommended new references**:
- `references/rails-8-authentication.md` (~210 lines) — Built-in auth generator schema, `has_secure_password` + 15-min token expiry, Devise migration considerations.
- `references/active-record-encryption.md` (~200 lines) — `encrypts :attr`, deterministic vs non-deterministic, key derivation, key rotation, Rails 7.1+ migration.
- `references/rails-cves-and-defaults.md` (~190 lines) — CVE-2025-24293, CVE-2025-55193, `host_authorization`, modern CSP nonce + importmaps.

**New checks**:
- `RLS-AUTH-6` — If Rails 8 auth gen: session table indexed on token; `terminate_session` invalidates server-side row.
- `RLS-ENC-1` — Sensitive PII uses `encrypts :col`; deterministic only where equality lookup required.
- `RLS-ENC-2` — Encryption keys in credentials, not env vars committed.
- `RLS-HOST-1` — `config.hosts` allowlist set in production.
- `RLS-DEP-4` — Rails ≥7.1.5.2 / 7.2.2.2 / 8.0.2.1 (CVE-2025-24293, CVE-2025-55193).
- `RLS-CSP-1` — Nonce-based CSP with importmaps inline script tag using nonce.

**Citations**: blog.saeloun.com/2025/05/12/rails-8-adds-built-in-authentication-generator/, rubyonrails.org/2025/8/13 release notes, opswat.com CVE-2025-24293, guides.rubyonrails.org/active_record_encryption.html.

---

## laravel-security
**Tier**: thin. Pre-Laravel-11 mental model — no `bootstrap/app.php`, no Reverb advisory, no Octane state-leak class.

**Gaps**: Zero refs. **Laravel 11 slim app structure**: `bootstrap/app.php` `withMiddleware`/`withRouting` replaces HTTP Kernel — current checks reference obsolete structure. **Octane runtime**: long-lived workers leak request state across requests (singletons holding user data, static caches, `Auth::user()` bleed) — classic foot-gun, missing entirely. **Laravel Reverb CVE GHSA-m27r-m6rx-mhm4** (CVSS 9.8) — Redis horizontal-scaling `unserialize()` insecure deserialization, fixed in v1.7.0. Sanctum vs Passport modernization absent. Pulse/Telescope auth gates missing.

**Version drift**: Laravel implied 9-12, current **12.x + 13.x in early release**, severity **HIGH** — middleware registration moved, Sanctum is default API stack.

**Recommended new references**:
- `references/laravel-11-12-app-structure.md` (~220 lines) — `bootstrap/app.php` walkthrough, `withMiddleware`, route caching, `env()` use only in config.
- `references/octane-and-long-lived-runtimes.md` (~190 lines) — Worker state leak class, container reset, `Auth::forgetUser` per request, FrankenPHP worker mode.
- `references/sanctum-passport-reverb.md` (~210 lines) — Sanctum personal tokens, SPA mode CSRF flow, Reverb GHSA-m27r-m6rx-mhm4 fix (≥1.7.0).

**New checks**:
- `LRV-MW-1` — `bootstrap/app.php` `validateCsrfTokens(except:)` reviewed; webhook entries paired with signature middleware.
- `LRV-OCT-1` — Under Octane, no per-request data in `bind`/`singleton`; `Auth::user()` not cached across requests.
- `LRV-OCT-2` — `RefreshDatabase`-style assumptions don't leak in workers.
- `LRV-REV-1` — `laravel/reverb ≥1.7.0` (CVE deser fix).
- `LRV-PULSE-1` — Pulse `viewPulse` Gate restricts production access.
- `LRV-SEC-1` — `config:cache` re-run after `.env` changes; `env()` only inside `config/`.

**Citations**: laravel.com/docs/11.x/releases, /12.x/releases, GHSA-m27r-m6rx-mhm4, securinglaravel.com Laravel 11 middleware.

---

## spring-boot-security
**Tier**: thin. SecurityFilterChain/`@PreAuthorize`/actuator/Spring4Shell coverage — but misses 2025 CVE wave.

**Gaps**: Zero refs. **CVE-2025-41248** (Spring Security 6.4.0–6.4.9, 6.5.0–6.5.3: method-security on generic super-types/interfaces not detected → authorization bypass). **CVE-2025-41232** (private-method annotation bypass). OAuth2 DPoP support in 6.5 absent. Modern lambda-DSL idioms only implicit. Jackson polymorphic deserialization mitigation pattern missing. **CVE-2025-53864** (nimbus-jose-jwt DoS).

**Version drift**: Spring Boot implied 2.7/3.x, current **3.4 / 3.5 milestone**, severity **HIGH**. Spring Security ≥**6.5.4** for CVE-2025-41248.

**Recommended new references**:
- `references/spring-security-6-5-config.md` (~220 lines) — `SecurityFilterChain` lambda DSL, `authorizeHttpRequests` + `requestMatchers`, multi-chain `securityMatcher`, DPoP.
- `references/spring-cves-2025.md` (~180 lines) — CVE-2025-41248, CVE-2025-41232, CVE-2025-53864 (nimbus-jose-jwt), Spring4Shell recap.
- `references/jackson-deserialization.md` (~190 lines) — `BasicPolymorphicTypeValidator.builder().allowIfBaseType(...)`, `@JsonTypeInfo` patterns, Jackson 3 stricter defaults.

**New checks**:
- `SPR-DEP-4` — Spring Security ≥6.4.10 or 6.5.4 (CVE-2025-41248); nimbus-jose-jwt ≥10.x (CVE-2025-53864).
- `SPR-AZ-5` — `@PreAuthorize` on concrete classes/methods OR Spring Security ≥6.4.10/6.5.4; no security on private methods.
- `SPR-AZ-6` — When app is OAuth2 client + Resource Server, separate `SecurityFilterChain` beans with explicit `securityMatcher`.
- `SPR-JKS-4` — Polymorphic deserialization uses `PolymorphicTypeValidator`; default typing without validator forbidden.
- `SPR-AUTH-5` — DPoP enabled for high-value APIs where supported.
- `SPR-SC-4` — `mvcMatchers`/`antMatchers` migrated to `requestMatchers`.

**Citations**: spring.io/security/cve-2025-41248/, spring.io/security/cve-2025-41232/, spring-projects/spring-security issue #17583, docs.spring.io authorize-http-requests.

---

## dotnet-aspnetcore-security
**Tier**: thin. Middleware/Authorize/EF Core coverage, but misses the two most important 2025 incidents.

**Gaps**: Zero refs. **CVE-2025-55315** (Kestrel request smuggling via Transfer-Encoding chunk extensions, **CVSS 9.9 — Microsoft's highest-ever score**) — patched .NET 8.0.21 / 9.0.10 / 10.0-rc.2. **CVE-2026-40372** (ASP.NET Core DataProtection HMAC tag computed over wrong payload slice → forgeable auth cookies, antiforgery, OIDC state) — patched .NET 10.0.7. Minimal API antiforgery (.NET 8+) `AddAntiforgery()` + `UseAntiforgery()` placement absent. DataProtection key-ring rotation only one check. Kestrel limits absent.

**Version drift**: .NET implied 6-9, current **.NET 9 STS + .NET 10 GA**, severity **HIGH** — both 2025 CVEs unaddressed.

**Recommended new references**:
- `references/kestrel-and-request-smuggling.md` (~210 lines) — Kestrel limits, CVE-2025-55315 root cause, patch matrix, reverse-proxy hardening, HTTP/2 frame limits.
- `references/data-protection-and-keyring.md` (~200 lines) — Key-ring backends (Azure Blob + Key Vault, Redis), rotation, `SetApplicationName`, CVE-2026-40372 patch.
- `references/minimal-api-and-antiforgery.md` (~190 lines) — `AddAntiforgery`/`UseAntiforgery` placement, `[IFormFile]` breaking change, `RequireAuthorization()`.

**New checks**:
- `DNC-DEP-4` — .NET runtime ≥8.0.21 / 9.0.10 / 10.0-rc.2 (CVE-2025-55315); DataProtection ≥.NET 10.0.7 (CVE-2026-40372).
- `DNC-KES-1` — Kestrel limits set: `MaxRequestHeadersTotalSize`, `MaxRequestLineSize`, `MaxConcurrentConnections`, `MinRequestBodyDataRate`.
- `DNC-DP-4` — DataProtection key ring persisted to durable backend, encrypted at rest, rotated ≤90d, `SetApplicationName` in multi-app deploys.
- `DNC-CSRF-4` — Minimal API: `AddAntiforgery()` registered, `UseAntiforgery()` placed after Routing/Auth/Authz, before endpoints.
- `DNC-MA-3` — Minimal API endpoints requiring auth call `.RequireAuthorization()` (or global fallback policy).
- `DNC-SQL-4` — System.Text.Json polymorphic deser uses `[JsonDerivedType]` allowlist.

**Citations**: microsoft.com/en-us/msrc/blog/2025/10/understanding-cve-2025-55315, andrewlock.net worst-dotnet-vulnerability, startdebugging.net/2026/04/dotnet-10-0-7-oob-cve-2026-40372, learn.microsoft.com aspnetcore antiforgery.

---

# API protocols (3)

## graphql-security
**Tier**: partial. 50+ checks, 1 reference. Solid coverage, dated in places.

**Gaps**: Only 1 ref. **Apollo Server 5 unmentioned** (header-only DoS, CSRF Content-Type tightening). **Federation directive-based authz** (`@authenticated`, `@requiresScopes`) requires v2.5+ and only works with GraphOS Router. **GHSA-m8jr-fxqx-8xx6** (federation transitive-field authz bypass) missing. **GraphQL Armor v3** plugin-level guidance incomplete. **Persisted queries vs APQ** confusion (APQ is perf, not security). graphql-shield effectively unmaintained since 2022.

**Version drift**: Apollo Server implied 4.x, current **5.x GA 2025**, severity **HIGH**. GraphQL Yoga 4+, current **5.x**. graphql-shield deprecated.

**Recommended new references**:
- `references/complexity-and-armor.md` (~180 lines) — Depth/cost math, alias counting, GraphQL Armor v3 plugin matrix, Apollo `validationRules` vs Yoga Envelop wiring.
- `references/persisted-queries-vs-trusted-documents.md` (~140 lines) — APQ ≠ security; trusted-documents/safelisting workflow.
- `references/federation-authz.md` (~120 lines) — `@authenticated`/`@requiresScopes`/`@policy` directives, GraphOS Router vs `@apollo/gateway` gap, GHSA-m8jr-fxqx-8xx6.
- `references/apollo-server-5-migration.md` (~80 lines) — AS4→AS5 security-relevant deltas.

**New checks**:
- `GQL-INTRO-4` — Block field suggestions enabled (Armor `blockFieldSuggestions`).
- `GQL-PQ-5` — Trusted documents enforced, not APQ.
- `GQL-PQ-6` — No bypass route in production (`?query=...`, `Apollo-Require-Preflight: false`).
- `GQL-FED-4` — Federation directive composition; gateway is GraphOS Router.
- `GQL-FED-5` — Transitive field authz tested for GHSA-m8jr-fxqx-8xx6 class.
- `GQL-DEP-1` — Apollo Server ≥5.5, Yoga ≥5, graphql-js ≥16.10 (CVE-2024-50312).
- `GQL-DEP-2` — `graphql-shield` not in use (deprecated since 2022).
- `GQL-CSRF-4` — Apollo Server 5 charset/Content-Type tightening verified in custom integrations.
- `GQL-COMP-5` — `@defer` / `@stream` cost accounting includes deferred fragments.

**Citations**: github.com/apollographql/apollo-server CHANGELOG, benjie.dev/graphql/trusted-documents, escape.tech/graphql-armor, the-guild.dev/graphql/yoga-server, apollographql.com federation directives, GHSA-m8jr-fxqx-8xx6, GHSA-7f25-p8gc-hxqh (CVE-2024-50312).

---

## trpc-security
**Tier**: thin. ~25 checks, zero references. Workflow stops at SKILL.md.

**Gaps**: Zero refs. **v11** changed subscriptions from observables to **async generators**, added **SSE subscription transport** (httpSubscriptionLink), removed `.interop()`, made inputs lazy. **superjson vs devalue** transformer risk (devalue is "insecure to use on the server" per trpc#6092). File uploads via `fetchAdapter` not covered. Edge-runtime caveats absent. `maxBatchSize` not concretely set. `responseMeta` cache-control guidance absent.

**Version drift**: tRPC implied v10/v11, current **v11.x GA 2025**, severity **MEDIUM**.

**Recommended new references**:
- `references/v11-migration-security-deltas.md` (~120 lines) — Async-generator subscription auth re-check, SSE vs WS subscription differences, lazy input materialization.
- `references/transformers-and-serialization.md` (~90 lines) — superjson safe; devalue NOT (trpc#6092); prototype-pollution surface.
- `references/batching-and-rate-limits.md` (~110 lines) — `httpBatchLink`'s `maxURLLength`/`maxBatchSize`, GET batching, CDN caching of GET batch URLs.
- `references/edge-runtime-caveats.md` (~70 lines) — Cloudflare/Vercel edge cookie/IP/limiter patterns.

**New checks**:
- `TRP-V11-1` — Async-generator subscriptions re-check auth on each `yield`.
- `TRP-V11-2` — `httpSubscriptionLink` (SSE) origin/CORS configured.
- `TRP-TRX-1` — Transformer is `superjson` (or known-safe); `devalue` not used server-side (trpc#6092).
- `TRP-TRX-2` — Custom transformer audited for prototype pollution.
- `TRP-BAT-3` — `maxBatchSize` and `maxURLLength` explicitly set on adapter.
- `TRP-BAT-4` — GET-batched queries with auth-sensitive output have `Cache-Control: private, no-store`.
- `TRP-UP-1` — File upload procedures enforce size + MIME at procedure layer.
- `TRP-EDGE-1` — Edge-runtime context derives client IP from platform headers (`CF-Connecting-IP`).
- `TRP-EDGE-2` — Rate limiter backed by Upstash/KV (not in-memory) on edge.
- `TRP-PROC-4` — Method override (`allowMethodOverride`) not enabled, or explicitly intentional.
- `TRP-DEP-3` — `@trpc/server` and `@trpc/client ≥11.x`.

**Citations**: trpc.io/docs/migrate-from-v10-to-v11, trpc.io/blog/announcing-trpc-v11, trpc/trpc issue #6092, issue #5825, trpc.io/docs/client/links/httpSubscriptionLink.

---

## websocket-security
**Tier**: thin. ~30 checks, zero references.

**Gaps**: Zero refs. **ws CVE chain not enumerated**: CVE-2024-37890 (header-flood DoS, fixed 8.17.1) and uninitialized-memory disclosure (fixed 8.20.1). **Socket.IO/engine.io CVE chain**: CVE-2024-38355, CVE-2026-33151 (unbounded binary attachments, fixed 4.8.x), engine.io 6.6.6/6.6.7 hardening. CSWSH modern browser landscape (partitioned cookies) not covered. WebTransport / HTTP/3 not on radar.

**Version drift**: ws implied ≥8.x, current **≥8.20.1**, severity **HIGH**. socket.io implied ≥4.x, current **≥4.8.x** (CVE-2026-33151), severity **HIGH**.

**Recommended new references**:
- `references/cswsh-defense.md` (~130 lines) — Origin header allowlist per library, Sec-WebSocket-Protocol token pattern, partitioned cookies as defense-in-depth.
- `references/ws-library-cves.md` (~90 lines) — Annotated table of ws/socket.io/engine.io CVEs.
- `references/message-validation-and-backpressure.md` (~110 lines) — Schema validation per message, `maxPayload` math, `bufferedAmount` slow-consumer detection.
- `references/socketio-and-engineio-internals.md` (~100 lines) — Engine.IO transport upgrade, polling-to-WS auth carry-over, WebTransport in 4.8.

**New checks**:
- `WSC-DEP-2` — `ws ≥8.20.1` (CVE-2024-37890, uninitialized-memory).
- `WSC-DEP-3` — `socket.io ≥4.8.x`, `engine.io ≥6.6.7`, `socket.io-parser ≥4.2.4`.
- `WSC-AUTH-4` — Token never carried in URL query string in production.
- `WSC-ORI-4` — Origin allowlist enforced even with SameSite=Lax/Strict cookies.
- `WSC-VAL-4` — Each handler enumerates expected message shapes; unknown messages disconnect/rate-limit.
- `WSC-SIZE-4` — `bufferedAmount` monitored; slow consumers disconnected.
- `WSC-SIZE-5` — Inactivity / handshake-completion timeout configured.
- `WSC-LC-3` — Authorization revocation propagates to existing connections within bounded TTL.
- `WSC-SIO-5` — Socket.IO `maxHttpBufferSize` sane; binary attachment count bound (CVE-2026-33151).
- `WSC-SIO-6` — Redis/cluster adapter rooms namespaced with tenant prefix.
- `WSC-WT-1` — WebTransport: engine.io 6.6.7 fixes middleware-bypass.

**Citations**: nvd.nist.gov CVE-2024-37890, snyk.io SNYK-JS-WS-7266574, GHSA-25hc-qcg6-38wj (CVE-2024-38355), github.com/socketio/socket.io/security, blog.includesecurity.com 2025 CSWSH, OWASP WebSocket cheatsheet.

---

# Data layer (3)

## prisma-orm-security
**Tier**: partial. 35-check coverage; 1 reference.

**Gaps**: Only 1 ref. No coverage of **TypedSQL** (GA Prisma 5.19+). No **Prisma Postgres** + `pool=true` (6.19) or PgBouncer transactional pooling implications. No nested-write authorization (`connect`, `connectOrCreate`). **Operator injection** in Prisma's `where` filter (attacker passes `{gt: ""}` into a string field) absent. Log-level/PII guidance for `log: ['query']` missing.

**Version drift**: Prisma implied ~5.x, current **6.19.0** (Nov 2025), severity **MEDIUM**.

**Recommended new references**:
- `references/operator-injection.md` (~120 lines) — Prisma+Postgres NoSQL-style filter injection; Zod/Valibot typing at boundary; `Prisma.validator`.
- `references/rls-with-prisma.md` (~150 lines) — `$extends`-based per-request client, `SET LOCAL app.tenant_id`, transaction-pool vs session-pool for Prisma Postgres/Accelerate.
- `references/typedsql-and-safeql.md` (~80 lines) — When TypedSQL replaces `$queryRawUnsafe`, SafeQL ESLint integration.
- `references/nested-writes-authz.md` (~80 lines) — `connect`/`connectOrCreate`/`createMany` authorization patterns.

**New checks**:
- `PRI-OPI-1` — Where-clause operator injection — Parse bodies with strict primitives before passing to `where`.
- `PRI-OPI-2` — `Prisma.validator` boundaries — Don't accept arbitrary `Prisma.UserWhereInput` from clients.
- `PRI-RLS-1` — Per-request extended client, `SET LOCAL` inside `$transaction`; never `SET SESSION` on pooled connections.
- `PRI-RLS-2` — Accelerate/PgBouncer pool mode invalidates `SET SESSION`; verify RLS uses `SET LOCAL` only.
- `PRI-TSQL-1` — Prefer TypedSQL over `$queryRawUnsafe` when dynamic columns aren't truly needed.
- `PRI-NW-1` — Nested-write authorization — `connect: { id: x }` checks ownership of `x`.
- `PRI-MA-5` — `createMany`/`updateMany` per-row authz inside `$transaction`.
- `PRI-LOG-1` — `log: ['query']` not in prod; redact via middleware if enabled.
- `PRI-DEP-1` — Pin Prisma ≥6.x.

**Citations**: prisma.io/blog/announcing-prisma-6-19-0, prisma.io/changelog/2025-10-08, aikido.dev/blog/prisma-and-postgresql-vulnerable-to-nosql-injection, nodejs-security.com/blog/prisma-raw-query-sql-injection, prisma.io/docs/orm/prisma-client/using-raw-sql/typedsql, github.com/prisma/prisma-client-extensions/tree/main/row-level-security.

---

## mongoose-mongodb-security
**Tier**: thin. ~40 checks, zero references.

**Gaps**: Zero refs. **CVE-2024-53900 + CVE-2025-23061** (`$where` via `populate.match`, CVSS 9.0) and **2025 `$nor` sanitizeFilter bypass** missing. **`populate()` IDOR** (populated documents return regardless of caller authz; `match` is filter, not authz) absent. `sanitizeFilter` option limits not covered. `lean()` ObjectId-string equivalence pitfall missing. `strictQuery` mentioned absent. **Atlas Search `$search` injection** absent.

**Version drift**: Mongoose implied 6/7, current **8.x** (≥**8.9.5** for CVE-2025-23061, ≥**8.22.1** for `$nor` bypass), severity **HIGH** — exploit-in-the-wild RCE-class.

**Recommended new references**:
- `references/operator-injection-deep.md` (~140 lines) — Full taxonomy of `$ne`/`$gt`/`$where`/`$expr`/`$function`/`$accumulator`, `sanitizeFilter`+`$nor` bypass history.
- `references/populate-authz.md` (~100 lines) — `populate({path, match, select})` is not authz; pre-load through authorized query.
- `references/atlas-search-safety.md` (~80 lines) — `$search.text.query`, Lucene-syntax escaping.
- `references/objectid-and-casting.md` (~80 lines) — `isObjectIdOrHexString()`, `lean()`+ObjectId equality.

**New checks**:
- `MNG-CVE-1` — Mongoose ≥8.9.5 / 7.8.4 / 6.13.6 (CVE-2025-23061); ideally ≥8.22.1.
- `MNG-POP-1` — `populate({match})` includes tenant filter; populated docs through authz.
- `MNG-POP-2` — No `populate` of user-supplied path strings.
- `MNG-SAN-1` — `mongoose.set('sanitizeFilter', true)` or per-query opt-in; effective post-bypass fix.
- `MNG-STQ-1` — `strictQuery: true` explicitly.
- `MNG-ATL-5` — Atlas Search `$search` strings escaped; tenant filter via `compound.filter`.
- `MNG-OID-1` — ObjectId inputs validated with `isValidObjectId`; cast errors caught.
- `MNG-AGG-4` — `$expr`/`$function`/`$accumulator` flagged for review; no user input.
- `MNG-WRT-1` — `findOneAndUpdate({upsert:true})` with `{new:true}` includes tenant in filter.

**Citations**: GHSA-vg7j-7cwx-8wgw, opswat.com CVE-2025-23061, nsfocusglobal.com mongodb-mongoose-search-injection, dailycve.com mongoose-sanitizefilter-bypass, mongoosejs.com docs.

---

## redis-security
**Tier**: thin. Broad surface (network/auth/TLS/ACL/Lua/pubsub/persistence) but zero refs.

**Gaps**: Zero refs. **CVE-2025-49844 "RediShell" (CVSS 10.0)** — Lua use-after-free → RCE in all versions until 6.2.20 / 7.2.11 / 7.4.6 / 8.0.4 / 8.2.2 (Oct 2025). Highest-impact Redis CVE in years — absent. **CVE-2025-21605** (output-buffer DoS, unauth) absent. **Redis 8 ACL category changes** — modules now built-in (Search/JSON/TimeSeries/Bloom) with new ACL categories. **ACL selectors** (Redis 7.2+) absent. `acl-pubsub-default resetchannels` absent. `MODULE LOAD` restriction absent. Client-library TLS specifics absent.

**Version drift**: Redis server implied 7.x, current **8.2.x** (Aug 2025 GA), severity **HIGH**. Lua sandbox: all versions had RediShell until Oct 2025 patches, severity **CRITICAL**.

**Recommended new references**:
- `references/acl-deep.md` (~180 lines) — ACL syntax, Redis 8 module categories, selectors, channel patterns, default-user disable, `ACL WHOAMI`/`ACL LOG`.
- `references/lua-and-redishell.md` (~120 lines) — CVE-2025-49844 timeline + patched versions, mitigation via `-eval -evalsha` on non-admin users.
- `references/clients-and-tls.md` (~120 lines) — ioredis Sentinel TLS, node-redis 4+ TLS, redis-py SSL params, Upstash REST vs TCP, AWS ElastiCache IAM auth.
- `references/modules-and-search.md` (~80 lines) — RedisJSON path expressions with user input, FT.SEARCH query escape.

**New checks**:
- `RDS-CVE-1` — Redis ≥6.2.20 / 7.2.11 / 7.4.6 / 8.0.4 / 8.2.2 (CVE-2025-49844); if not patchable, `-eval -evalsha` for non-admin users.
- `RDS-CVE-2` — Patched against CVE-2025-21605 and 8.2 XACKDEL/HGETEX stack overflow.
- `RDS-ACL-1` — Redis 8: ACL audited for module categories (`@search`, `@json`, etc.).
- `RDS-ACL-2` — Selectors used for least-privilege; `&channel` patterns set; `acl-pubsub-default resetchannels`.
- `RDS-ACL-3` — `MODULE LOAD`/`MODULE LOADEX` denied to all but bootstrap admin.
- `RDS-LUA-4` — Non-admin users have `-eval -evalsha -function` until proven needed.
- `RDS-CLI-1` — Client TLS verified (`rejectUnauthorized:true`, `ssl_cert_reqs='required'`); Sentinel TLS with `sentinelPassword`.
- `RDS-MOD-1` — RedisJSON paths not user-built without escape; FT.SEARCH user queries escaped.
- `RDS-CLU-1` — Cluster mode: cross-slot operations don't leak topology.

**Citations**: redis.io/blog/security-advisory-cve-2025-49844/, wiz.io/blog/wiz-research-redis-rce-cve-2025-49844, sysdig.com/blog/cve-2025-49844-redishell, thehackernews.com 13-year-redis-flaw, redis.io/docs/latest/operate/oss_and_stack/stack-with-enterprise/release-notes/redisce/redisos-8.0-release-notes/, support.redislabs.com ACL category changes, ioredis.com TLS docs.

---

# Auth providers (2)

## clerk-security
**Tier**: thin. ~30 checks, no references.

**Gaps**: Zero refs. **Clerk Core 3** (released 2026-03-03) breaking changes not covered: async `auth()` (was sync), `auth.protect()` → 401 (was 404), satellite `satelliteAutoSync` default flipped to false. **Machine auth / M2M tokens** (Feb 2026 release) absent. **Networkless JWT verification** with `verifyToken({ jwtKey, authorizedParties })` absent. **Actor Tokens / impersonation** shallow. Webhook handling lacks svix replay tolerance, signature rotation. `ClerkProvider dynamic` (v6+) regression not addressed.

**Version drift**: `@clerk/nextjs` implied v5/v6, current **v7.3.7 + Core 3 (Mar 2026)**, severity **HIGH**. `auth()` shown as sync — wrong on current install.

**Recommended new references**:
- `references/clerk-core3-migration.md` (~200 lines) — Core 2 → Core 3 deltas, async `auth()`/`auth.protect()`, satellite changes, codemod via `@clerk/upgrade`.
- `references/clerk-token-verification.md` (~220 lines) — `verifyToken()` networkless mode, JWKS rotation, `iss`/`aud`/`azp`, `act` impersonation claim.
- `references/clerk-webhooks-svix.md` (~180 lines) — Raw-body per framework, svix replay tolerance, secret rotation cutover, idempotency.
- `references/clerk-machine-auth.md` (~180 lines) — M2M token model, machine secret keys, opaque vs JWT.

**New checks**:
- `CLK-MW-5` — Async `auth()` migration — All `auth()` calls in App Router are `await auth()`.
- `CLK-MW-6` — `clerkMiddleware` runtime — On Next.js 16, middleware renamed to proxy.ts/Node runtime.
- `CLK-JWT-5` — `authorizedParties` set on `authenticateRequest`/`verifyToken`.
- `CLK-JWT-6` — Networkless verification uses pinned `jwtKey`, rotates with JWKS.
- `CLK-WH-5` — Svix timestamp tolerance enforced (default 5 min).
- `CLK-WH-6` — Webhook handler responds 2xx only after persisting idempotency record.
- `CLK-M2M-1` — Machine secret keys stored separately; per-machine scope.
- `CLK-M2M-2` — JWT M2M tokens carry `aud` matching consumer; opaque M2M where revocation matters.
- `CLK-ACT-1` — Actor tokens: `act.sub` logged alongside `sub`; admin audit trail captures impersonation.
- `CLK-DEP-2` — `@clerk/nextjs ≥7.x`; Next ≥15.2.3 (CVE-2025-29927) or ≥16.x.
- `CLK-DEP-3` — Next dev dep ≥15.5.15 / 16.2.3 (CVE-2026-23869 RSC DoS).
- `CLK-CFG-4` — Satellite domains: `satelliteAutoSync` explicitly set (Core 3 default false).
- `CLK-PRV-1` — `ClerkProvider dynamic` set where SSR client components rely on `useAuth()`.
- `CLK-PSK-1` — Passkey RP ID matches production origin; no wildcard.

**Citations**: clerk.com/changelog/2026-03-03-core-3, clerk.com/docs/guides/development/upgrading/upgrade-guides/core-3, nextjs-v6, clerk.com/docs/reference/backend/verify-token, clerk.com/docs/guides/sessions/manual-jwt-verification, clerk.com/docs/guides/development/machine-auth/m2m-tokens, clerk.com/docs/reference/backend-api/tag/Actor-Tokens, npmjs.com/package/@clerk/nextjs, docs.svix.com.

---

## nextauth-security
**Tier**: thin. ~30 checks, no references.

**Gaps**: Zero refs. **CVE-2025-29927** (Next.js middleware bypass) directly weaponizes NextAuth middleware protection — absent. **Split-config / edge adapter** pattern absent (central operational concern in v5). **OAuth state/PKCE/nonce** posture absent. Mention that **Auth.js v5 is still beta** (still beta May 2026) and consolidated into **Better Auth** (Sep 2025). **CredentialsProvider** lacks account-lockout/rate-limit/brute-force coverage; maintainers explicitly recommend against using it. **AUTH_TRUST_HOST** required on non-Vercel hosts in v5 — common silent misconfiguration.

**Version drift**: v5 framed as "current" — accurate but **2+ years beta**. `NEXTAUTH_URL`/`AUTH_SECRET` correct, missing `AUTH_TRUST_HOST`. No Next floor for CVE-2025-29927.

**Recommended new references**:
- `references/nextauth-v5-config.md` (~220 lines) — Split config (`auth.config.ts` edge-safe vs `auth.ts` with adapter), `AUTH_TRUST_HOST`, beta status caveat, Better Auth migration.
- `references/nextauth-middleware-cve.md` (~180 lines) — CVE-2025-29927 mechanics, `x-middleware-subrequest` exploitation, mitigation (upgrade + duplicate auth check + reject header at edge).
- `references/nextauth-callbacks-redirect.md` (~190 lines) — Open-redirect history (GHSA-f9wg-5f46-cjmw, GHSA-q2mx-j4x2-2h74), safe redirect callback, refresh-token rotation.
- `references/nextauth-providers.md` (~200 lines) — Provider-by-provider gotchas, Email TTL, OIDC `nonce`/PKCE, CredentialsProvider hardening.

**New checks**:
- `NXA-MW-1` — Next ≥15.2.3 / 14.2.25 / 13.5.9 / 12.3.5 (CVE-2025-29927).
- `NXA-MW-2` — `x-middleware-subrequest` rejected at edge/CDN as defense-in-depth.
- `NXA-MW-3` — Route handlers / Server Actions re-check `auth()` even when middleware claims protection.
- `NXA-MW-4` — On Next 16, `proxy.ts` runtime migration verified.
- `NXA-SEC-5` — `AUTH_TRUST_HOST=true` set on non-Vercel hosts in v5.
- `NXA-SS-5` — Cookie name prefix change v4→v5 doesn't leak old sessions.
- `NXA-CB-RED-2` — Redirect callback returns `baseUrl` on non-relative URLs (GHSA-f9wg-5f46-cjmw).
- `NXA-CB-JWT-4` — Refresh token rotation handled in `jwt` callback with failure→signout (returns `null`).
- `NXA-PR-CRD-4` — Account lockout / rate limit on `authorize()`.
- `NXA-PR-CRD-5` — Maintainers' caution about CredentialsProvider documented; compensating controls or migration plan.
- `NXA-PR-OIDC-1` — OIDC built-in PKCE/state/nonce; custom OAuth verifies explicitly.
- `NXA-ADP-3` — Adapter package on `@auth/*-adapter` scope (v5), matches major.
- `NXA-DEP-3` — Auth.js v5 beta status documented; Better Auth migration plan.
- `NXA-EV-3` — `events.signIn`/`signOut` failure doesn't block auth response.

**Citations**: GHSA-f82v-jwr5-mffw, securitylabs.datadoghq.com nextjs-middleware-auth-bypass, projectdiscovery.io nextjs-middleware-authorization-bypass, authjs.dev/getting-started/migrating-to-v5, authjs.dev/guides/edge-compatibility, GHSA-f9wg-5f46-cjmw, GHSA-q2mx-j4x2-2h74, nextauthjs/next-auth discussion 13252 (Better Auth merge), discussion 13382 (v5 still beta).

---

# Edge / Cloud (3)

## vercel-platform-security
**Tier**: thin. 32 inline checks, no references.

**Gaps**: No coverage of **Vercel Firewall / WAF** — major surface that landed since this skill was written. `VERCEL_AUTOMATION_BYPASS_SECRET` rotation, multi-secret, header-vs-query absent. ISR / cache poisoning class entirely missing. Edge Middleware vs Edge Functions vs Node runtime trust model not explained. **Vercel Blob** storage absent (public vs private, signed payloads, WAF gap). **OIDC federation** (deploy-time `VERCEL_OIDC_TOKEN`) absent.

**Version drift**: Edge Functions / Edge Middleware now run on **unified Vercel Functions** (2025), severity **MEDIUM**. CVE-2025-29927 — Vercel auto-mitigates but self-hosted Next on Vercel-adjacent infra doesn't, severity **HIGH**. April 2026 multi-tenant env exposure incident argues for tighter env scoping.

**Recommended new references**:
- `references/firewall-and-waf.md` (~180 lines) — Vercel Firewall layers, managed rulesets (OWASP CRS), custom rules DSL, IP/ASN allow-deny, system bypass rules, Attack Challenge Mode.
- `references/deployment-protection-and-bypass.md` (~150 lines) — Standard/Password/SSO, `VERCEL_AUTOMATION_BYPASS_SECRET` rotation, multi-secret, header-vs-query, Shareable Links scope.
- `references/blob-and-data-cache.md` (~140 lines) — Blob public vs private, OIDC vs static token, client-upload signed payloads, WAF gap workaround, ISR poisoning.

**New checks**:
- `VRC-WAF-1` — WAF managed ruleset (OWASP CRS) enabled.
- `VRC-WAF-2` — Custom WAF rules deny abuse patterns; rate-limit auth endpoints.
- `VRC-WAF-3` — System Bypass Rules narrow (path + IP / header).
- `VRC-DP-5` — Bypass secret rotated on team changes, transmitted as header (not query string).
- `VRC-DP-6` — Multiple bypass secrets for per-workflow scopes.
- `VRC-OIDC-1` — Workload identity (`VERCEL_OIDC_TOKEN`) replaces long-lived cloud keys where supported.
- `VRC-MW-1` — Next ≥15.2.3 (CVE-2025-29927) and ≥15.5.18 / 16.2.6 for May 2026 advisories.
- `VRC-MW-2` — Middleware not sole-line-of-defense; route-level auth duplicated.
- `VRC-BLB-1` — Sensitive content in private Blob store (require `BLOB_READ_WRITE_TOKEN`).
- `VRC-BLB-2` — Client uploads use server-issued signed payloads with constraints.
- `VRC-BLB-3` — Long-lived `BLOB_READ_WRITE_TOKEN` replaced by OIDC where available.
- `VRC-BLB-4` — Blob URLs proxied through Vercel Function when WAF coverage required.
- `VRC-CR-4` — `CRON_SECRET` rotated; cron endpoints rate-limited at WAF.
- `VRC-ISR-1` — On-demand revalidation requires auth header / signed token.
- `VRC-ISR-2` — Per-request data not implicitly captured in ISR/data cache.
- `VRC-FN-4` — Edge Middleware unified-functions migration confirmed.

**Citations**: vercel.com/docs/vercel-firewall, /vercel-waf/managed-rulesets, /system-bypass-rules, /docs/deployment-protection, changelog/protection-bypass-for-automation-multiple-secrets, /docs/vercel-blob/security, /private-storage, changelog edge-middleware-vercel-functions, changelog next-js-may-2026-security-release, GHSA-f82v-jwr5-mffw.

---

## cloudflare-workers-security
**Tier**: thin. ~36 checks, no references.

**Gaps**: `nodejs_compat` flag risk surface absent — flag changes global scope semantics, affects which built-ins are exposed (`node:vm` since 2025-10-01, `node:child_process` from 2026-03-17). **Cloudflare Secrets Store** absent. **Pages Functions / Workers Static Assets** path not addressed. **Workers AI prompt injection / AI Gateway** absent. Cache API key collisions / cache pollution absent. Cloudflare **Zero Trust / Access** in front of Workers — mentioned once but unverified. **Workers for Platforms** tenant isolation absent.

**Version drift**: Wrangler implied 3.x, current **Wrangler 4.x**, severity **MEDIUM**. `compatibility_date` check has no specific recommendation; current minimum useful date ≥2024-09-23 (`nodejs_compat`) and ≥2026-03-17 (full Node built-in set).

**Recommended new references**:
- `references/secrets-and-bindings.md` (~180 lines) — Secrets vs vars, Secrets Store (account-scoped, RBAC, audit), `.dev.vars`, service bindings, queue/D1/R2/KV/DO/Vectorize/Hyperdrive.
- `references/nodejs-compat-and-runtime.md` (~140 lines) — `nodejs_compat` flag staged rollout, dangerous-API list, `compatibility_date` cadence.
- `references/zero-trust-and-access.md` (~150 lines) — Cloudflare Access JWT verification (JWKS, aud, iss), Service Tokens, mTLS to origin.
- `references/workers-ai-and-cache.md` (~140 lines) — Workers AI input/output sanitization, AI Gateway logging and PII redaction, Cache API key construction.

**New checks**:
- `CFW-SEC-5` — Sensitive secrets migrated to **Cloudflare Secrets Store** (account-scoped, RBAC).
- `CFW-SEC-6` — Wrangler ≥4.x; `wrangler.jsonc` schema validated.
- `CFW-CD-1` — `compatibility_date` ≥2024-09-23 if `nodejs_compat`; ≥2026-03-17 for newer Node built-ins.
- `CFW-CD-2` — `nodejs_compat` only when needed; review exposed Node built-ins.
- `CFW-AI-1` — Workers AI: user input concatenated into prompts is bounded and instruction-isolated.
- `CFW-AI-2` — AI Gateway logging masks PII.
- `CFW-CACHE-1` — `cache.put`/`match` keys include user/tenant scope where response is user-specific.
- `CFW-CACHE-2` — `Vary` header and cache key normalization audited.
- `CFW-ZT-1` — If Access in front of Worker, Worker verifies `Cf-Access-Jwt-Assertion` against Access JWKS, validates `aud` and `iss`.
- `CFW-ZT-2` — Service Tokens narrow-scoped, rotated, stored as Worker secrets.
- `CFW-RL-3` — Per-Worker rate-limiting binding (`ratelimit`) — replace stale `cf.rateLimit`.
- `CFW-PG-1` — Pages Functions: `_routes.json` excludes static asset paths; `_headers` sets baseline security headers.
- `CFW-WFP-1` — Workers for Platforms: tenant Workers isolated; dispatch namespace API token tight scope; outbound Worker enforces shared policy.
- `CFW-DO-4` — Durable Object alarms and storage cleanup on tenant deletion.
- `CFW-DEV-3` — `.dev.vars` and `.dev.vars.<env>` in `.gitignore`.

**Citations**: developers.cloudflare.com/workers/runtime-apis/nodejs/, /compatibility-dates/, /compatibility-flags/, /secrets-store/integrations/workers/, /workers/configuration/secrets/, blog.cloudflare.com nodejs-workers-2025, changelog 2026-02-15 workers-best-practices, /workers/runtime-apis/cache/.

---

## aws-lambda-security
**Tier**: thin. ~38 checks, no references.

**Gaps**: **SnapStart security model not addressed** — snapshot determinism (randomness, UUIDs, crypto seeds) and stale-secret-in-snapshot risks. **Response Streaming** security implications missing. **Lambda@Edge** distinct constraints not covered (no env vars, no VPC, 5s viewer-response, log location). Lambda Powertools / Parameters & Secrets Extension caching pattern absent. **Inspector for Lambda** continuous CVE scanning absent. Layer **persistence-as-foothold** pattern missing. Code-signing config doesn't cover `WARN` vs `ENFORCE`. **RecursiveLoop detection** absent. No `references/`.

**Version drift**: SnapStart now supported on Python 3.12+, .NET 8, others (originally Java-only), severity **MEDIUM**. Inspector for Lambda + Lambda Layers GA, severity **MEDIUM**.

**Recommended new references**:
- `references/iam-least-privilege.md` (~180 lines) — Per-function role, IAM Access Analyzer for Lambda, condition keys (`aws:SourceArn`, `aws:SourceAccount`), `iam:PassRole` scoping, `lambda:InvokeFunctionUrl` vs `lambda:InvokeFunction`.
- `references/secrets-and-snapstart.md` (~160 lines) — Secrets Manager vs Parameter Store, Lambda Extension caching, **SnapStart snapshot determinism**, stale-secret-in-snapshot mitigation, snapshot KMS keys, Code Signing `ENFORCE`.
- `references/function-url-streaming-and-edge.md` (~160 lines) — Function URL auth modes, CORS, response streaming, Lambda@Edge constraints.
- `references/supply-chain-and-scanning.md` (~150 lines) — Layer supply-chain attacks (account-wide persistence), Inspector for Lambda + Layers, signed deploy packages (AWS Signer), CI/CD assume-role with OIDC.

**New checks**:
- `AWL-SS-1` — SnapStart: initialization code does not generate cryptographic seeds, UUIDs, session tokens reused across invocations. Use `afterRestore` hook to re-randomize.
- `AWL-SS-2` — Secrets fetched in init are re-fetched in `afterRestore`.
- `AWL-SS-3` — SnapStart snapshot encrypted with CMK (not AWS-managed key) for compliance.
- `AWL-STR-1` — Response streaming: partial response on mid-stream error doesn't leak stack trace.
- `AWL-STR-2` — Streaming Function URL CORS: no `*` with credentials; preflight handled before stream open.
- `AWL-EDG-1` — Lambda@Edge: no env vars; secrets via Secrets Manager with cross-region replication.
- `AWL-EDG-2` — Viewer-request/response ≤5s timeout, ≤1 MB body; never call out-of-region services sync.
- `AWL-EDG-3` — Logs reviewed across all CloudFront edge regions.
- `AWL-LY-4` — Account-level "all functions using this layer" inventory reviewed for rogue layers.
- `AWL-LY-5` — Layer ARN owned by your org or vetted publisher; `*` wildcards audited.
- `AWL-SCAN-1` — Amazon Inspector enabled for Lambda functions and layers; findings triaged within SLO.
- `AWL-URL-5` — `lambda:InvokeFunctionUrl` separated from `lambda:InvokeFunction` in resource policy.
- `AWL-IAM-7` — Resource policy includes `aws:SourceArn` + `aws:SourceAccount` for cross-service invokers.
- `AWL-IAM-8` — IAM Access Analyzer findings reviewed for function role.
- `AWL-EXT-1` — Lambda Extensions audited like layers; extension's permissions inherit function role.
- `AWL-RL-1` — Recursive Loop Detection enabled.
- `AWL-SIG-3` — Code Signing uses `UntrustedArtifactOnDeployment: Enforce` (not `Warn`); signing profile rotated.

**Citations**: docs.aws.amazon.com/lambda/latest/dg/snapstart-security.html, /snapstart.html, /urls-auth.html, /configuration-response-streaming.html, /security-configuration.html, zestsecurity.io malicious-aws-lambda-layers, aws.amazon.com/blogs/compute/securely-retrieving-secrets-with-aws-lambda/.

---

# SaaS Security Pack (9 rich skills — drift + depth gaps)

## github-supply-chain
**Tier**: rich. 4-ref set; correctly references tj-actions/changed-files.

**Gaps**: No coverage of GitHub-native **immutable actions / immutable releases** (released 2025). SHA-pinning org-level policy (Aug 2025) and immutable subject claims (Apr 2026) absent. `reviewdog/action-setup` CVE-2025-30154 not called out. No `harden-runner` mention. Self-hosted runner detection shallow.

**Version / standard drift**: `actions/attest-build-provenance` implied v1, current **v2.x** (Oct 2025), severity **MEDIUM**. Cosign implied v2, **Cosign v3 GA** (mid-2025) flips `--new-bundle-format` and `--trusted-root` defaults, severity **MEDIUM**.

**Recommended new references**:
- `references/runner-hardening.md` (~120 lines) — harden-runner / step-security egress, ephemeral runners, self-hosted isolation.
- `references/immutable-actions-and-releases.md` (~100 lines) — SHA-pinning org policy (Aug 2025), immutable releases, immutable subject claims.
- Extend `sbom-generation.md` (+60 lines) — Cosign v3 transition, SLSA L3 path with reusable workflows.

**New checks**:
- `GHSC-PIN-5` — Org-level SHA-pinning policy enabled.
- `GHSC-RUN-1` — Egress firewall / harden-runner on every workflow handling secrets.
- `GHSC-OIDC-5` — Immutable subject claim — new-repo trust policies use `repository_id`-augmented sub.
- `GHSC-SBOM-5` — Cosign v3 readiness — signing pipeline tested with `--new-bundle-format` / Rekor v2.
- `GHSC-REL-1` — Immutable releases — production tags marked immutable via release ruleset.

**Citations**: cisa.gov tj-actions compromise alert, github.blog/changelog/2025-08-15-github-actions-policy SHA-pinning, /changelog/2026-04-23-immutable-subject-claims, blog.sigstore.dev/cosign-3-0-available/, github.blog/security/supply-chain-security/slsa-3-compliance.

---

## github-repo-hardening
**Tier**: rich. Solid 3-ref set; Rulesets vs legacy branch protection covered.

**Gaps**: **Code-scanning merge protection via rulesets** (released 2025) absent. **Custom Repository Roles** (org-admin alternative to outside-collaborator) absent. Push protection **delegated bypass** (Nov 2024+) absent. **Copilot generic-secret detection** (LLM-based) absent.

**Version / standard drift**: Required code scanning rule type (key 2025 addition) missing, severity **MEDIUM**. Copilot generic-secret detection rolled GA 2025, severity **LOW**.

**Recommended new references**:
- `references/rulesets-advanced.md` (~120 lines) — Required code scanning, org-level rulesets, bypass actors fine-grained, repository property targeting, ruleset insights API.
- Extend `secret-scanning.md` (+50 lines) — Copilot generic-secret detection, validity check expansion, delegated bypass.
- `references/custom-roles-and-access.md` (~80 lines) — Custom repository roles, fine-grained PATs vs GitHub App.

**New checks**:
- `GHRH-BP-11` — Code scanning merge protection — at least one ruleset blocks PR merge on Critical/High alerts.
- `GHRH-SS-7` — Copilot secret scanning enabled.
- `GHRH-SS-8` — Delegated bypass workflow — push-protection bypass requires approver.
- `GHRH-AC-5` — Custom repository roles split admin into "settings" + "secrets".
- `GHRH-AC-6` — Fine-grained PAT policy — classic PATs blocked in favor of fine-grained / GitHub Apps.

**Citations**: docs.github.com code-scanning merge protection, /managing-rulesets/available-rules-for-rulesets, /code-security/secret-scanning/copilot-secret-scanning.

---

## saas-code-security-review
**Tier**: rich. 4-ref set, JWT and SSRF refs detailed.

**Gaps**: **OWASP API Top 10 2023** reframed BOLA + introduced **BOPLA (Broken Object Property Level Authorization)** as a top risk — current skill folds this under "mass assignment" without using current vocabulary. **Prototype pollution** absent as distinct class. **AI/LLM-injection app vulns** (prompt injection, SSRF via LLM tool use) absent. **HTTP/2 request smuggling** absent.

**Version / standard drift**: OWASP API3:2023 (BOPLA) consolidation missing, severity **MEDIUM**.

**Recommended new references**:
- `references/bopla-and-mass-assignment.md` (~120 lines) — OWASP API3:2023 framing, framework-specific patterns, allowlist generation.
- `references/llm-app-security.md` (~140 lines) — Prompt injection, SSRF via LLM tool use, secret leakage via function-call args, embedding-store poisoning.
- Extend `sast-triage.md` (+40 lines) — Copilot Autofix policy, Semgrep CE vs Pro vs Opengrep fork (Jan 2025).

**New checks**:
- `SCSR-BOPLA-1` — Endpoints return only authorized fields (output allowlist, not just input).
- `SCSR-BOPLA-2` — User-controlled property paths (`req.body.user.role`) blocked.
- `SCSR-PP-1` — JSON merge / clone / lodash.set protected against `__proto__` / `constructor.prototype` keys.
- `SCSR-LLM-1` — LLM tool-call surfaces validate URLs, redact secrets from args, enforce per-tool allowlists.
- `SCSR-LLM-2` — Prompt-injection: user content quoted, tool outputs treated as untrusted.
- `SCSR-HTTP-1` — HTTP/2 desync / request smuggling: reverse-proxy and origin agree on CL/TE handling.

**Citations**: owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/, ssojet.com JWT-security-2025, github.blog/news-insights/copilot-autofix.

---

## supabase-security-audit
**Tier**: rich. 4-ref set is excellent; RLS ref deep.

**Gaps**: **Supabase asymmetric JWT migration** (default ES256 on new projects from May 2025) — directly relevant, missing. `pg_net` and `pg_cron` mentioned only in passing — both `SECURITY DEFINER`-heavy, need separate guidance. **Storage RLS** covered as 4 checks but no dedicated reference. **Realtime channel authorization** (channel-level RLS late 2024) absent. New API key model (`sb_publishable_*` / `sb_secret_*` rollout 2025) not in checks.

**Version / standard drift**: Supabase Auth implied HS256-symmetric, current **ES256 asymmetric** for new projects from 2025-05-01, severity **MEDIUM**. New API key prefixes severity **MEDIUM**.

**Recommended new references**:
- `references/storage-rls.md` (~140 lines) — Bucket vs object policies, path templates, MIME validation, signed-URL TTL, transformation pipeline.
- `references/realtime-channels.md` (~100 lines) — Channel-level authorization, broadcast vs postgres_changes vs presence, JWT claim usage.
- `references/pg-net-pg-cron.md` (~80 lines) — Both privileged extensions; SSRF via `pg_net.http_post`; pg_cron job auditing.
- Extend `edge-functions-auth.md` (+40 lines) — ES256 JWT validation, JWKS endpoint, new API key model.

**New checks**:
- `SUPA-AUTH-6` — Asymmetric JWT — project on ES256 OR documented HS256 with rotation plan.
- `SUPA-AUTH-7` — New API key model — `sb_secret_*` keys not in client bundles; legacy `service_role` rotated.
- `SUPA-PGNET-1` — `pg_net.http_*` callable only by `service_role` or via SECURITY DEFINER with target-URL allowlist (SSRF guard).
- `SUPA-CRON-1` — `cron.schedule` jobs reviewed quarterly; caller identity documented.
- `SUPA-RT-1` — Realtime channel authorization — RLS on `realtime.messages`; no permissive `using (true)`.
- `SUPA-ST-5` — Storage object policy uses path-prefix scoping (tenant/user segment), not name LIKE wildcard.

**Citations**: github.com/supabase/supabase/issues/44530, supabase.com/docs/guides/storage/security/access-control, /database/extensions/pg_net, /functions/auth.

---

## saas-tenant-isolation
**Tier**: rich. 2 references but `cross-tenant-leaks.md` is 295 lines and exceptionally thorough.

**Gaps**: Only 2 references vs 3-4 bar. **AWS S3 ABAC for general-purpose buckets** (late 2025) absent. **Amazon Verified Permissions / Cedar policy stores** (Cedar 4.5 GA 2025) absent. **Prisma extensions / Drizzle / Kysely** ORM patterns missing. Algolia syntax shown is v4 API; current is v5+.

**Version / standard drift**: Algolia implied v4 SDK, current **v5+**, severity **LOW**. S3 ABAC GA, severity **MEDIUM**.

**Recommended new references**:
- `references/orm-tenant-filters.md` (~150 lines) — Prisma extension-based RLS, Drizzle middleware patterns, Kysely with async-local-storage.
- `references/aws-abac-tenant-isolation.md` (~100 lines) — S3 ABAC (2025), session-tag IAM patterns, Verified Permissions / Cedar policy stores per tenant.
- Extend `cross-tenant-leaks.md` (+30 lines) — Update Algolia snippet to v5 SDK; add Meilisearch token rotation; CDN tenant routing via signed cookies.

**New checks**:
- `STI-DB-8` — ORM tenant-enforcement middleware — Prisma extension, Drizzle wrapper, ActiveRecord default_scope.
- `STI-FILE-5` — S3 ABAC native — bucket policy uses `aws:PrincipalTag/TenantId` ABAC pattern (2025+).
- `STI-AUTHZ-1` — Per-tenant Cedar policy store — each tenant has its own; no cross-tenant policy reuse.

**Citations**: aws.amazon.com/blogs/aws/abac-amazon-s3-general-purpose-buckets/, aws.amazon.com/about-aws/whats-new/2025/08/amazon-verified-permissions-cedar-4-5/, algolia.com/doc/guides/security/api-keys/.

---

## saas-api-security
**Tier**: rich. 4-ref set is broad; webhook-security.md is gold-standard.

**Gaps**: **GraphQL Armor** library not referenced — SKILL lists 7 GQL checks but no concrete enforcement. **Persisted Queries vs APQ** distinction not surfaced — APQ does NOT provide security. **API key prefix conventions** for secret-scanning partners — GitHub Secret Scanning Partner program list. **Rate-limit headers RFC 9331** absent.

**Version / standard drift**: Rate-limit headers implied custom `Retry-After`, current standard **RFC 9331**, severity **LOW**. GraphQL APQ vs persisted queries conflation, severity **MEDIUM**.

**Recommended new references**:
- `references/graphql-hardening.md` (~130 lines) — GraphQL Armor setup, persisted-queries safelist (NOT APQ), introspection disable, field-level cost weights.
- Extend `rate-limiting.md` (+40 lines) — RFC 9331 RateLimit headers, token-bucket libraries.
- Extend `api-key-management.md` (+30 lines) — GitHub Secret Scanning Partner program (canonical prefix list).

**New checks**:
- `SAPI-GQL-8` — APQ is NOT a security control; persisted-query safelisting enforced separately.
- `SAPI-GQL-9` — GraphQL Armor middleware active with depth/cost/alias/directive/circular-fragment caps.
- `SAPI-RL-8` — RFC 9331 RateLimit headers returned with 429.
- `SAPI-AK-8` — API key prefix registered with GitHub Secret Scanning Partner program OR matched by org custom pattern.
- `SAPI-WH-OUT-6` — mTLS support offered for enterprise customers receiving high-trust webhooks.

**Citations**: github.com/Escape-Technologies/graphql-armor, apollographql.com/docs/graphos/platform/security/persisted-queries, docs.stripe.com/webhooks/signature.

---

## saas-frontend-hardening
**Tier**: rich. 3-ref set; csp-design.md excellent.

**Gaps**: **Drift vs `appsec-stack-pack/web-platform-security`** — risk of duplication; recommend cross-reference notes. **`report-uri` is deprecated** by CSP3; current is **Reporting API** (`Reporting-Endpoints` header) + `report-to`. **Iframe credentialless** (2024+) and **fenced frames** absent. **CHIPS Partitioned cookies** absent — critical for embedded-widget SaaS in third-party cookie phaseout era.

**Version / standard drift**: `report-uri` implied primary, current is `Reporting-Endpoints` + `report-to`, severity **LOW**. `Partitioned` (CHIPS) absent, severity **MEDIUM** for embed-heavy SaaS.

**Recommended new references**:
- `references/embedded-saas-isolation.md` (~120 lines) — Embedded widget patterns (Stripe-style), CHIPS `Partitioned` cookies, fenced frames, iframe credentialless.
- Extend `csp-design.md` (+30 lines) — Reporting API replacing report-uri; CSP nonce propagation in Next 15.
- Extend `cookie-config.md` (+40 lines) — `Partitioned` attribute (CHIPS), browser matrix.
- Cross-reference appendix — explicit mapping of SFH-* checks vs `web-platform-security` to avoid duplication.

**New checks**:
- `SFH-CSP-11` — Reporting-Endpoints + `report-to` (not just legacy `report-uri`).
- `SFH-COOK-7` — Embedded contexts use `Partitioned` cookies (CHIPS).
- `SFH-EMBED-1` — Embedded customer widgets sandboxed via `fenced-frame` or `iframe[credentialless]`.
- `SFH-PM-5` — postMessage origin validation accepts tenant-allowlist URLs only.

**Citations**: web.dev/articles/strict-csp, developer.mozilla.org/Web/Privacy/Privacy_sandbox/Partitioned_cookies, w3.org/TR/CSP3.

---

## iac-container-security
**Tier**: rich. 3-ref set; k8s-hardening.md comprehensive.

**Gaps**: **EKS Pod Identity** (default 2025+) not differentiated from IRSA. **Cilium NetworkPolicy v2** and `CiliumClusterwideNetworkPolicy` (FQDN egress) absent. **Pod Security Standards 1.30+ updates** (AppArmor GA in 1.31) absent. **Cosign v3** image signing absent. **eBPF runtime tools** (Tetragon, Falco eBPF) beyond Falco mention absent.

**Version / standard drift**: Cosign implied v2, **v3 GA**; flags differ (`--new-bundle-format`), severity **MEDIUM**. PSS 1.31 promotes AppArmor to GA + `procMount`, severity **LOW**. IRSA → Pod Identity, severity **MEDIUM**.

**Recommended new references**:
- `references/cloud-workload-identity.md` (~140 lines) — AWS IRSA vs EKS Pod Identity decision matrix, GCP Workload Identity Federation, Azure Workload Identity, pitfalls.
- `references/network-policy-advanced.md` (~120 lines) — Cilium v2 NetworkPolicy, FQDN egress, ClusterWide policies, IMDS block patterns.
- Extend `k8s-hardening.md` (+50 lines) — PSS 1.31 (AppArmor GA, `procMount`), Kyverno + Gatekeeper coexistence.
- Extend `dockerfile-hardening.md` (+30 lines) — Cosign v3 signing, OCI 1.1 attestations, multi-arch SBOM.

**New checks**:
- `IACS-K8S-13` — EKS clusters use Pod Identity (not IRSA) for new workloads.
- `IACS-K8S-14` — Cilium FQDN egress policy blocks IMDS (169.254.169.254) cluster-wide via `CiliumClusterwideNetworkPolicy`.
- `IACS-K8S-15` — AppArmor applied via field (1.31+ GA), not deprecated annotation.
- `IACS-COS-1` — Container images signed with Cosign v3 bundle format; verification step in admission controller.
- `IACS-RUN-1` — Runtime detection (Falco / Tetragon / KubeArmor) active with default rules.
- `IACS-IAM-7` — KEV-listed CVEs (CISA Known Exploited) tracked separately with shorter patch SLA.

**Citations**: aws.amazon.com/blogs/containers/amazon-eks-pod-identity, docs.cilium.io/en/stable/security/policy/, kubernetes.io/docs/concepts/security/pod-security-admission/, cisa.gov known-exploited-vulnerabilities-catalog.

---

## saas-compliance-audit
**Tier**: rich. SKILL.md detailed with 9 control categories; 3 references; framework cross-mapping strong.

**Gaps**: **HIPAA Security Rule NPRM** (published Federal Register Jan 6, 2025; final rule expected May 2026) — major change set: mandatory encryption, MFA, asset inventory, network segmentation, vulnerability scanning every 6 months, pen-test annually. **SOC 2 2022 revision** (effective Dec 2022) — added Points of Focus emphasis. **EU AI Act** (GPAI obligations from Aug 2025) absent. **DORA** (Digital Operational Resilience Act, Jan 2025 effective) absent. **NIS2** EU directive (Oct 2024) absent. No continuous-compliance evidence automation reference.

**Version / standard drift**: SOC 2 implied 2017 TSC, current **2022 revision**, severity **MEDIUM**. HIPAA implied 2013 Security Rule, **NPRM Jan 2025** introduces mandatory MFA + encryption + 72h breach, severity **HIGH**. PCI-DSS implied generic, **v4.0 / 4.0.1** effective March 2024/2025, severity **MEDIUM**.

**Recommended new references**:
- `references/hipaa-nprm-2025.md` (~140 lines) — NPRM proposed changes (mandatory MFA, encryption, asset inventory, segmentation, vuln-scan cadence, pen-test annually), gap-analysis template.
- `references/eu-regulations-overlap.md` (~120 lines) — EU AI Act GPAI obligations, DORA ICT risk management, NIS2 classification, SCC modules 2021.
- Extend `audit-logging.md` (+30 lines) — PCI-DSS 4.0.1 logging, continuous-compliance evidence feeds.
- Extend `gdpr-dsar.md` (+30 lines) — 2021 SCC modules, EDPB transfer guidance post-Schrems II.

**New checks**:
- `SCMP-HIPAA-NPRM-1` — Asset inventory documented and updated annually (NPRM proposed).
- `SCMP-HIPAA-NPRM-2` — MFA required on all ePHI access including admin.
- `SCMP-HIPAA-NPRM-3` — Vulnerability scan every 6 months + pen-test annually documented.
- `SCMP-AI-1` — AI Act GPAI compliance: model documentation, downstream notice, training-data summary.
- `SCMP-DORA-1` — DORA-applicable SaaS register ICT third-party providers, exit strategies, resilience tests.
- `SCMP-NIS2-1` — NIS2 essential/important entity classification; incident reporting to national CSIRT.
- `SCMP-PCI4-1` — PCI-DSS 4.0.1 future-dated controls (effective March 31, 2025) — targeted risk analysis.

**Citations**: federalregister.gov/documents/2025/01/06/hipaa-security-rule, hhs.gov/hipaa/for-professionals/security/hipaa-security-rule-nprm/factsheet, sprinto.com/blog/soc-2-updates/, forvismazars.us/forsights/2024/05/2024-soc-2-updates.

---

# Execution priorities

## Wave 1 — Ship now (CVSS ≥9.0 / EOL / no patch path)

Each becomes a one-line PR per affected file:

1. **Bump `redis-server`** in tech-inventory + add RDS-CVE-1 / RDS-CVE-2 / RDS-ACL-1 / RDS-LUA-4 (CVE-2025-49844)
2. **Add NXT-DEP-2** + bump nextjs-framework to 16.2.6/15.5.18 (May 2026 wave + middleware bypass)
3. **Add RCT-RSC-5/6/7** for React Server Component RCE patches
4. **Add MNG-CVE-1** for mongoose ≥8.9.5
5. **Add DNC-DEP-4 / DNC-KES-1 / DNC-DP-4** for .NET Kestrel smuggling + DataProtection HMAC bypass
6. **Add SPR-DEP-4 / SPR-AZ-5** for Spring Security 6.4.10/6.5.4 (CVE-2025-41248)
7. **Add VIT-DEV-8** for Vite ≥6.4.2/7.3.2/8.0.5 (CVE-2026-39363)
8. **Add HNO-CVE-1** for Hono ≥4.11.7 (GHSA-w332)
9. **Add ANG-DEP-4** for Angular ≥19.2.20/20.3.18/21.2.4 (CVE-2026-32635)
10. **Add ELC-VER-2** for Electron ≥38.8.6 (CVE-2026-34769)

## Wave 2 — Add reference files (top 10 thin-tier skills)

Roughly 30 reference files. Priority order: redis-security, mongoose, electron, react+nextjs (clear ROI), svelte-sveltekit, dotnet, rails, laravel, spring-boot, django.

## Wave 3 — Standard drift updates (saas-security-pack)

Each saas-security-pack skill has 3–6 new check IDs to add and 1–3 new references to add or extend. Total ~40 new check IDs across the 9 skills.

## Wave 4 — Cross-pack consistency

- Decide canonical home for browser primitives (CORS, CSP, cookies): probably `web-platform-security` as the deep dive, with `saas-frontend-hardening` becoming the SaaS-specific subset.
- Avoid duplication; cross-link.

---

# Daily Copilot review

The `.github/copilot-instructions.md` already specifies version drift as the primary mandate. This document supplements it with the depth backlog: when Copilot runs the daily review, drift findings from `.github/tech-inventory.yml` are Wave 1; depth recommendations from this document populate Waves 2–4. Each entry above can become its own PR with the listed file paths and finding IDs as the body.
