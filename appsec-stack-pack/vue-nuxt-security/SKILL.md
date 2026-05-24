---
name: vue-nuxt-security
description: Security audit specific to Vue.js and Nuxt applications including v-html XSS, template injection, useFetch/$fetch SSR patterns, Nuxt server routes (server/api), runtime config vs public runtime config, useState SSR leakage, Pinia/Vuex store exposure, and Vue 2 vs 3 differences. Use this skill whenever the user mentions Vue, Vue 3, Vue 2, Nuxt, Nuxt 3, Nuxt 2, v-html, useFetch, useState, Pinia, Vuex, defineNuxtConfig, server/api routes, useRuntimeConfig, or asks "audit my Vue app", "Nuxt security", "v-html safe". Trigger when the codebase contains `vue` in package.json, `.vue` files, `nuxt.config.ts`, or `defineNuxtConfig`.
---

# Vue / Nuxt Security Audit

Audit Vue.js (2 and 3) and Nuxt (2 and 3) applications for framework-specific vulnerabilities.

## When this skill applies

- Reviewing Vue components for XSS sinks
- Auditing Nuxt server routes and `useFetch` / `$fetch` patterns
- Reviewing runtime config (public vs private) for env leakage
- Checking SSR state hydration for data exposure
- Auditing Pinia / Vuex store exposure

Use other skills for: Vite build (`vite-security`), backend services (`nodejs-express-security` etc.), auth providers, generic patterns (`saas-security-pack/saas-code-security-review`).

## Workflow

Follow `../_shared/audit-workflow.md`.

### Phase 1: Stack detection

```bash
grep -E '"(vue|nuxt|@nuxt/.*|pinia|vuex)":' package.json
find . -name 'nuxt.config.*' -not -path '*/node_modules/*'
find . -name '*.vue' -not -path '*/node_modules/*' | head
```

Confirm: Vue 2 vs 3, Nuxt 2 vs 3, Vite vs Webpack (Nuxt 3 = Vite default; Nuxt 2 = Webpack).

### Phase 2: Inventory

```bash
# XSS sinks in templates
grep -rn 'v-html\|innerHTML' src/ pages/ components/ layouts/ 2>/dev/null

# Nuxt 3 server routes
find server/api server/routes -type f 2>/dev/null

# Runtime config
grep -nE 'runtimeConfig|publicRuntimeConfig|privateRuntimeConfig' nuxt.config.* 2>/dev/null

# Fetch patterns
grep -rn 'useFetch\|\$fetch\|useAsyncData' src/ pages/ components/ 2>/dev/null | head -30

# Stores
grep -rn 'defineStore\|createStore' src/ stores/ 2>/dev/null | head
```

### Phase 3: Detection — the checks

#### v-html XSS

- **VUE-XSS-1** Every `v-html` reviewed. The directive sets `innerHTML` — content must be trusted or sanitized.
- **VUE-XSS-2** Markdown rendering through `v-html` requires sanitization (DOMPurify or `@nuxt/content` with default safe config).
- **VUE-XSS-3** `{{ }}` (double-brace) interpolation IS auto-escaped — safe by default.

```vue
<!-- BAD -->
<div v-html="userContent" />

<!-- GOOD -->
<div v-html="DOMPurify.sanitize(userContent)" />

<!-- BETTER — don't accept HTML at all -->
<div>{{ userContent }}</div>
```

#### URL-bearing attributes

- **VUE-URL-1** `:href`, `:src` bound to user input validated against `javascript:` and other dangerous schemes — same as React (see `react-security/references/jsx-xss-sinks.md`).
- **VUE-URL-2** `<a target="_blank" :href="...">` includes `rel="noopener noreferrer"`.

#### Nuxt 3 runtime config

Nuxt 3 has two config buckets:

```ts
// nuxt.config.ts
export default defineNuxtConfig({
  runtimeConfig: {
    // Server-only (private)
    apiSecret: process.env.API_SECRET,
    
    // Available client-side via useRuntimeConfig().public
    public: {
      apiBase: process.env.API_BASE_URL,
    },
  },
});
```

- **NXT-RC-1** Server-only values are NOT under `public:`. The `public` object is serialized into the client bundle.
- **NXT-RC-2** `useRuntimeConfig()` on the client returns ONLY the `public` subset (server values are `undefined` — but the keys must not have been listed under `public` by mistake).
- **NXT-RC-3** No secret in `public`, even if "obfuscated" or "harmless looking" — `public` ships verbatim.
- **VUE-RC-4** Inspect built bundle:
  ```bash
  npm run build
  grep -rhoE 'apiSecret|.*SECRET.*|.*PRIVATE_KEY.*' .output/public/ | sort -u
  ```
  Any matches = leak.

#### Nuxt server routes (`server/api/*`)

Nuxt 3 server routes run on the server (Nitro). Treat as full HTTP endpoints.

- **NXT-SR-1** Every server route checks auth. Nuxt provides no implicit auth.
  ```ts
  // server/api/users/[id].get.ts
  export default defineEventHandler(async (event) => {
    const session = await requireUserSession(event);   // ← do it
    const id = getRouterParam(event, 'id');
    // ... + authz: can session.user access user `id`?
  });
  ```
- **NXT-SR-2** Input validated via Zod / valibot / similar; never trust `getQuery(event)` or `readBody(event)` directly.
- **NXT-SR-3** CORS / origin checks for routes that should not be reachable cross-origin.
- **NXT-SR-4** Server routes accessing the database use the private runtime config, not public.

#### useFetch / $fetch SSR

`useFetch` runs on server during SSR, then re-runs on client during hydration. Bugs:

- **VUE-SSR-1** API calls during SSR using credentials that aren't safe for the client to see. `useFetch('/api/admin/users', { headers: { 'X-Admin-Token': config.adminToken } })` — if `adminToken` is in `public`, leak. If it's server-only, but the response data ships to the client via NuxtState, the data leak still happens.
- **VUE-SSR-2** Hydration data (`window.__NUXT__`) inspected — anything in there is visible to the user.
- **VUE-SSR-3** Per-request user data not cached in a way that bleeds across users (Nitro caching with per-user data needs a key including user id).

#### useState SSR leakage

```ts
// Nuxt 3 useState is SSR-shared — fine for shared state, bad for per-user
const userPrefs = useState('userPrefs', () => fetchPrefs());
```

If `fetchPrefs` reads server-side per-user data and stores in `useState`, that state serializes to client. Per-user data should fetch on the client, or be properly scoped.

#### Pinia / Vuex stores

- **VUE-STORE-1** Stores hydrating from server state don't include secrets — same SSR data leak class as above.
- **VUE-STORE-2** `nuxt-i18n` or similar plugins reading user locale don't expose user roles, IDs, internal flags.

#### Vue 2 specifics (legacy)

- **VUE2-1** Vue 2 reached EOL Dec 31, 2023. Audit for unpatched CVEs; recommend migration to Vue 3 (Nuxt 2 → Nuxt 3).
- **VUE2-2** `Vue.compile` with user input is the equivalent of `eval` — never use with untrusted templates.

#### Dependencies

- **VUE-DEP-1** `vue-router` and `vue` versions current.
- **VUE-DEP-2** `nuxt < 3.13` had several Critical CVEs (server-side prototype pollution, RCE in DevTools). Bump to current.
- **VUE-DEP-3** UI libraries (Vuetify, PrimeVue, Element Plus) reviewed for known issues.

### Phase 4: Triage

Critical: secrets in `public` runtime config; unauthenticated server route doing sensitive ops; `v-html` with raw user input.

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `VUE-`.
