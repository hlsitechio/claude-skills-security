# Edge Functions Authentication Reference

Load this when reviewing Supabase Edge Functions (Deno runtime) for authentication and authorization issues.

## The default behavior

Every Supabase Edge Function has a "Verify JWT" toggle in the dashboard.

- **Verify JWT ON** (default for new functions): Supabase's gateway rejects requests without a valid JWT in the `Authorization` header before the function code runs. Inside the function, `req.headers.get('Authorization')` contains the JWT.
- **Verify JWT OFF**: Anyone can hit the function. Use this only for public endpoints (webhook receivers, public APIs).

The toggle is set per-function. Audit the dashboard or the function config in `supabase/config.toml`:

```toml
[functions.public-webhook]
verify_jwt = false   # ⚠ ensure this is intentional

[functions.user-action]
verify_jwt = true
```

## What "Verify JWT ON" gives you (and doesn't)

Verify JWT confirms that:
- The token is signed by your project's auth.
- The token is not expired.
- The token has a valid format.

It does NOT confirm:
- Which user the token belongs to (you have to read claims).
- Whether the user has permission for this specific action (that's your job).
- That the user actually wants to do this (CSRF — not usually a concern for Bearer tokens, but for cookie auth it would be).

## The correct pattern — function uses the user's JWT

```typescript
// supabase/functions/secure-action/index.ts
import { serve } from 'https://deno.land/std@0.224.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

serve(async (req) => {
  // 1. Extract the user's JWT from the Authorization header
  const authHeader = req.headers.get('Authorization');
  if (!authHeader) {
    return new Response('Unauthorized', { status: 401 });
  }

  // 2. Create a supabase client that forwards the user's JWT
  // This makes RLS apply to every query the client runs.
  const supabase = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_ANON_KEY')!,    // anon key, not service role
    {
      global: {
        headers: { Authorization: authHeader }
      }
    }
  );

  // 3. Resolve the user from the JWT (server-side, never trust client claims)
  const { data: { user }, error: userError } = await supabase.auth.getUser();
  if (userError || !user) {
    return new Response('Unauthorized', { status: 401 });
  }

  // 4. Now every supabase.from(...) call runs as this user with RLS
  const { data, error } = await supabase
    .from('protected_table')
    .select('*');

  return new Response(JSON.stringify({ data, error }), {
    headers: { 'Content-Type': 'application/json' }
  });
});
```

Key points:
- Use the **anon key** in the client, not the service role.
- Pass the user's JWT via `global.headers.Authorization`.
- Resolve the user via `supabase.auth.getUser()` — this validates the JWT server-side.
- All subsequent queries respect RLS for that user.

## Anti-patterns to flag

### Anti-pattern 1 — Using service_role with user input

```typescript
// ⚠ This bypasses RLS entirely; user input determines what gets returned
const supabase = createClient(URL, SERVICE_ROLE_KEY);
const { data } = await supabase
  .from('invoices')
  .select('*')
  .eq('user_id', req.body.userId);   // client controls userId
```

Equivalent to no auth. If you need service_role for one specific operation (e.g., logging that bypasses RLS), use it for that operation only, and explicitly check authorization elsewhere.

### Anti-pattern 2 — Trusting client-supplied user ID

```typescript
const { userId, action } = await req.json();
// ⚠ userId comes from the request body
await doActionFor(userId, action);
```

User ID must come from `supabase.auth.getUser()`, never from the request body. The audit grep:

```bash
grep -rn 'req.json()\|body.userId\|body.user_id' supabase/functions/
```

Each match should derive `userId` from the verified JWT instead.

### Anti-pattern 3 — Returning the service_role key

```typescript
// Yes, this happens in real code, often as "debug"
return new Response(JSON.stringify({
  message: 'ok',
  env: Deno.env.toObject()  // ⚠ leaks SERVICE_ROLE_KEY
}));
```

Audit: grep functions for `Deno.env.toObject`, `process.env` (wrong runtime but appears), `console.log(env)`, etc.

### Anti-pattern 4 — Skipping JWT verification "for performance"

```typescript
// ⚠ "We verified it on the frontend"
const userId = jwtDecode(authHeader.replace('Bearer ', '')).sub;
```

Decoding (not verifying) a JWT is trivial — an attacker can craft any payload. Always call `supabase.auth.getUser()` (which verifies) or use the gateway's "Verify JWT" feature.

### Anti-pattern 5 — Missing rate limiting

Edge functions are billed per invocation and can be called without limit if Verify JWT is off. Any public function (webhook receiver, public API) should have rate limiting — at the Supabase project level (project-wide), or via a custom check using Redis/database counters.

## Webhook receivers

Webhook endpoints from external services (Stripe, Resend, GitHub) need:

1. **Verify JWT OFF** (the sender doesn't have a user JWT).
2. **Signature verification** using the provider's signing secret.

### Stripe example

```typescript
import { serve } from 'https://deno.land/std@0.224.0/http/server.ts';
import Stripe from 'https://esm.sh/stripe@14';

const stripe = new Stripe(Deno.env.get('STRIPE_SECRET_KEY')!, {
  apiVersion: '2024-06-20',
  httpClient: Stripe.createFetchHttpClient(),
});

serve(async (req) => {
  const signature = req.headers.get('stripe-signature');
  const body = await req.text();   // raw body, NOT json

  let event;
  try {
    event = await stripe.webhooks.constructEventAsync(
      body,
      signature!,
      Deno.env.get('STRIPE_WEBHOOK_SECRET')!,
      undefined,
      Stripe.createSubtleCryptoProvider(),
    );
  } catch (err) {
    return new Response(`Webhook Error: ${err.message}`, { status: 400 });
  }

  // event is verified; process it
  // ...

  return new Response(JSON.stringify({ received: true }));
});
```

Audit checklist for webhooks:
- Reads raw body, not parsed JSON (signature is over raw bytes).
- Uses the provider's library for verification, not a custom HMAC.
- Webhook secret stored in Supabase Function secrets, not in code.
- Rejects events older than ~5 minutes (replay window).
- Handles idempotency (provider may retry; ensure double-processing is safe).

For non-Stripe webhooks, see `saas-api-security/references/webhook-security.md` for the general HMAC verification pattern.

## Outbound HTTP from edge functions

Edge functions can call external URLs. If the URL is user-controlled, this is an SSRF surface — see `saas-code-security-review/references/ssrf-patterns.md`.

Particularly dangerous in edge functions because:
- They run in Supabase's infrastructure and can potentially reach internal services.
- They have access to project secrets via environment.

## CORS

If the edge function is called from a browser, CORS headers matter. Reflecting `Origin` is rarely safe; allowlist explicitly.

```typescript
const ALLOWED_ORIGINS = ['https://app.yourorg.com', 'https://staging.yourorg.com'];

function corsHeaders(req: Request) {
  const origin = req.headers.get('Origin');
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    return {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Headers': 'Authorization, Content-Type',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Max-Age': '86400',
    };
  }
  return {};
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders(req) });
  }
  // ... actual handler
});
```

See `saas-api-security/references/cors-patterns.md` for the detailed CORS rules.

## Function inventory query

To list all functions and their JWT verification status, you need to use the Supabase CLI:

```bash
supabase functions list --project-ref <ref>
```

Or via the Management API:

```bash
curl -s "https://api.supabase.com/v1/projects/$PROJECT_REF/functions" \
  -H "Authorization: Bearer $SUPABASE_ACCESS_TOKEN" \
  | jq '.[] | {slug, verify_jwt, status, version}'
```

For each function with `verify_jwt: false`, confirm it's intentional (webhook, public API) and that signature verification or other auth is implemented in the function body.
