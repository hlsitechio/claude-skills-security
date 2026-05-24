---
name: svelte-sveltekit-security
description: Security audit for Svelte and SvelteKit applications including {@html} XSS, server load functions vs universal load, form actions security, +server.ts route handlers, hooks.server.ts middleware patterns, $env/static/private vs $env/dynamic, and store reactivity leakage. Use this skill whenever the user mentions Svelte, SvelteKit, Svelte 5 runes, {@html}, load functions, +page.server.ts, +server.ts, hooks.server.ts, $env/static/private, $env/dynamic/private, form actions, or asks "audit my SvelteKit app", "Svelte security". Trigger when the codebase contains `svelte` in package.json, `.svelte` files, or `svelte.config.js`.
---

# Svelte / SvelteKit Security Audit

Audit Svelte and SvelteKit apps. Covers Svelte 3/4/5 and SvelteKit 1/2.

## When this skill applies

- Reviewing Svelte components for XSS sinks
- Auditing SvelteKit server load functions, form actions, `+server.ts` routes
- Reviewing `hooks.server.ts` middleware
- Checking `$env` module usage for accidental leaks
- Auditing form actions for auth and CSRF

## Workflow

Follow `../_shared/audit-workflow.md`.

### Phase 1: Stack detection

```bash
grep -E '"(svelte|@sveltejs/kit)":' package.json
find . -name 'svelte.config.*' -name '*.svelte' -not -path '*/node_modules/*' | head
```

### Phase 2: Inventory

```bash
# XSS sinks
grep -rn '@html' src/ 2>/dev/null

# Server load functions (run on server)
find src -name '+page.server.ts' -o -name '+layout.server.ts' 2>/dev/null

# Universal load (runs both server and client)
find src -name '+page.ts' -o -name '+layout.ts' 2>/dev/null

# Endpoint handlers
find src -name '+server.ts' 2>/dev/null

# Form actions
grep -rn 'export const actions' src/ 2>/dev/null

# Hooks (middleware)
find src -name 'hooks.server.ts' -o -name 'hooks.client.ts' 2>/dev/null

# Env modules
grep -rn '\$env/static/private\|\$env/static/public\|\$env/dynamic/private\|\$env/dynamic/public' src/ 2>/dev/null
```

### Phase 3: Detection — the checks

#### `{@html}` XSS

- **SVK-XSS-1** Every `{@html foo}` reviewed. Same sink as `dangerouslySetInnerHTML`. Sanitize with DOMPurify or use a safe Markdown renderer.

```svelte
<!-- BAD -->
{@html post.content}

<!-- GOOD -->
<script>
  import DOMPurify from 'isomorphic-dompurify';
  $: clean = DOMPurify.sanitize(post.content);
</script>
{@html clean}
```

#### Server vs universal load functions

`+page.server.ts` runs ONLY on server. `+page.ts` runs on server during SSR AND on client during navigation.

- **SVK-LOAD-1** Code in `+page.ts` (universal load) must not import server-only modules (database, secret env). Use `$env/static/private` → will fail at build if a universal load imports it.
- **SVK-LOAD-2** Data returned from server load serializes to the client during hydration. Don't return secrets in the load function's return object.
- **SVK-LOAD-3** Universal load returning data fetched via authenticated API: the fetch on the client uses the user's cookies (good), but the server-side fetch during SSR uses no cookies by default — need to forward.

```ts
// +page.ts (universal)
export const load = async ({ fetch, params }) => {
  // SvelteKit's fetch forwards cookies during SSR — verify
  const res = await fetch(`/api/posts/${params.id}`);
  return { post: await res.json() };
};
```

#### `+server.ts` route handlers

API endpoints. Same scrutiny as any REST endpoint.

- **SVK-API-1** Every handler checks auth. SvelteKit provides no implicit auth.
- **SVK-API-2** Input validation via Zod / valibot on request body and URL params.
- **SVK-API-3** CORS configured if endpoint is cross-origin reachable.
- **SVK-API-4** No accidental data exposure — return only what caller is authorized to see.

```ts
// +server.ts
import { json, error } from '@sveltejs/kit';

export const GET = async ({ locals, params }) => {
  if (!locals.user) throw error(401);
  
  const item = await db.items.findFirst({
    where: { id: params.id, tenantId: locals.user.tenantId },
  });
  if (!item) throw error(404);
  
  return json(item);
};
```

#### Form actions

Form actions are POST endpoints generated from `actions` exports in `+page.server.ts`.

- **SVK-FA-1** Every action checks auth.
- **SVK-FA-2** Input validated; don't trust `formData.get(...)` directly.
- **SVK-FA-3** Authz on the resource being mutated.
- **SVK-FA-4** Actions return data that ships to the client — don't return secrets or other-user data.
- **SVK-FA-5** SvelteKit has built-in CSRF protection (Origin header check); verify it's not disabled via `csrf: false` in svelte.config.js.

```ts
// +page.server.ts
import { fail, redirect } from '@sveltejs/kit';
import { z } from 'zod';

const DeleteSchema = z.object({ postId: z.string().uuid() });

export const actions = {
  delete: async ({ request, locals }) => {
    if (!locals.user) throw redirect(303, '/login');
    
    const formData = await request.formData();
    const parsed = DeleteSchema.safeParse({ postId: formData.get('postId') });
    if (!parsed.success) return fail(400, { error: 'Invalid input' });
    
    const post = await db.posts.findFirst({ where: { id: parsed.data.postId } });
    if (!post || post.authorId !== locals.user.id) throw error(403);
    
    await db.posts.delete({ where: { id: post.id } });
    return { success: true };
  },
};
```

#### `hooks.server.ts`

Runs before every request. Place for auth resolution + global headers.

- **SVK-HK-1** Auth resolution in `handle` sets `event.locals.user` — every downstream load/action/route should use `locals.user`, not re-read cookies.
- **SVK-HK-2** Global headers (CSP, HSTS, etc.) set here via `event.setHeaders` or response transformation.
- **SVK-HK-3** Errors caught in `handleError` don't leak details in client response; log server-side.

#### `$env` module usage

SvelteKit splits env vars into 4 modules:

| Module | Where | Risk |
|--------|-------|------|
| `$env/static/private` | Server only, bundled at build | Safe |
| `$env/static/public` | Both (must start with `PUBLIC_`) | Public, treat as ships to client |
| `$env/dynamic/private` | Server only, at runtime | Safe |
| `$env/dynamic/public` | Both (must start with `PUBLIC_`) | Public |

- **SVK-ENV-1** Server-only secrets imported from `$env/static/private` or `$env/dynamic/private`. Never `PUBLIC_*`.
- **SVK-ENV-2** Variables prefixed with `PUBLIC_` (required for `$env/*/public`) are NOT secrets. Same trap as `NEXT_PUBLIC_`.
- **SVK-ENV-3** SvelteKit refuses to bundle `$env/static/private` imports into client code — build will fail. So the prefix model is enforced. But check that no one tried `PUBLIC_DATABASE_URL` to "make it work".

#### Svelte 5 runes

Svelte 5 introduced runes (`$state`, `$derived`, `$effect`). Security implications:
- **SVK-R5-1** `$state` synced to localStorage / sessionStorage doesn't store secrets.
- **SVK-R5-2** `$effect` running on the client doesn't accidentally execute server-side intent (legacy code mixing Svelte 4 `onMount` with `$effect`).

#### Dependencies

- **SVK-DEP-1** SvelteKit version current. SvelteKit 1.x had a CSRF disable issue (CVE-2023-44389 class); ensure 2.x or patched 1.x.
- **SVK-DEP-2** Adapters (`@sveltejs/adapter-node`, `@sveltejs/adapter-vercel`, etc.) current.

### Phase 4: Triage

Critical: `{@html}` with raw user input; form action without auth; data with secrets returned from load.

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `SVK-`.
