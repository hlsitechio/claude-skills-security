# Webhook Security Reference

Load this when reviewing webhook endpoints — either receiving from external providers or sending to customers.

## Inbound webhooks: you receive

### Provider-specific verification

For major providers, use their SDK. Manual HMAC is error-prone.

#### Stripe

```ts
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

app.post('/webhook/stripe', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'] as string;
  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,   // raw Buffer, NOT parsed JSON
      sig,
      process.env.STRIPE_WEBHOOK_SECRET!
    );
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  // event is verified; process
});
```

Two critical details:
- `express.raw()` middleware preserves the body as a Buffer. The default `express.json()` would parse and re-stringify, breaking the signature.
- The Stripe SDK checks the timestamp inside the signature header (max 5 minutes) — replay protection built in.

#### GitHub

```ts
import crypto from 'crypto';

app.post('/webhook/github', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['x-hub-signature-256'] as string;
  const expected = 'sha256=' + crypto
    .createHmac('sha256', process.env.GITHUB_WEBHOOK_SECRET!)
    .update(req.body)
    .digest('hex');

  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
    return res.status(401).send('Invalid signature');
  }
  // process
});
```

Use `timingSafeEqual`. A regular `===` comparison leaks bytes via timing.

GitHub doesn't include a timestamp; replay protection requires you to track delivery IDs (`X-GitHub-Delivery`) and reject duplicates.

### Manual HMAC pattern (for providers without SDK)

Common HMAC-based webhook scheme:

```
HMAC-SHA256(secret, f"{timestamp}.{raw_body}")
```

Sent as:
```
X-Webhook-Signature: t=1716499200,v1=<hex>
```

Verification:

```python
import hmac, hashlib, time
from flask import request, abort

def verify_webhook():
    sig_header = request.headers.get('X-Webhook-Signature', '')
    parts = dict(p.split('=', 1) for p in sig_header.split(','))
    timestamp = int(parts['t'])
    received_sig = parts['v1']

    # Replay protection: reject if older than 5 minutes
    if abs(time.time() - timestamp) > 300:
        abort(400, "stale timestamp")

    body = request.get_data()   # raw bytes
    signed_payload = f"{timestamp}.".encode() + body
    expected = hmac.new(
        SECRET.encode(),
        signed_payload,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected, received_sig):
        abort(401, "invalid signature")
```

Note `hmac.compare_digest` for timing-safe comparison.

### Common inbound-webhook bugs

1. **Parsing JSON before verifying** — re-serializing changes byte representation, breaks signature.
2. **Body middleware order** — body parsed by middleware before signature check.
3. **No replay protection** — provider doesn't include timestamp and you didn't add delivery ID dedup.
4. **Logging the raw body** — webhook payloads often contain secrets (Stripe payment data, GitHub tokens); careful with log retention.
5. **Webhook secret in env in client-side build** — Next.js/Nuxt: API route in pages/api or app/api gets the secret; client code does NOT.
6. **`/webhook` endpoint requires auth** — broken if the provider doesn't send your auth headers. Webhooks use their own signature, not your app's auth.

### Idempotency

Providers retry failed deliveries. Your handler must be safe to call twice for the same event.

```ts
async function handleWebhook(event: StripeEvent) {
  // Dedup by event ID
  const seen = await db.query(
    'INSERT INTO processed_webhooks (id, source) VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING id',
    [event.id, 'stripe']
  );
  if (seen.rows.length === 0) return; // already processed

  // Now safe to process side effects
  await processEvent(event);
}
```

Idempotency table can use a TTL (e.g., 7 days) to bound growth.

## Outbound webhooks: you send

### Customer-facing webhook delivery

Customers configure URLs in your dashboard. Your service POSTs events. They verify the signature.

#### Generate per-customer signing secrets

```ts
// At customer onboarding / webhook URL configuration
const webhookSecret = crypto.randomBytes(32).toString('hex'); // 256 bits
// Show ONCE to the customer (like a password reveal); store HMAC hash server-side
const secretHash = crypto
  .createHmac('sha256', process.env.SECRET_KEY!)
  .update(webhookSecret)
  .digest();
await db.query(
  'INSERT INTO webhook_endpoints (customer_id, url, secret_hash) VALUES ($1, $2, $3)',
  [customerId, url, secretHash]
);
```

Or — like Stripe — let customers retrieve/rotate the secret in your dashboard (still hashed at rest).

#### Sign every event

```ts
function signPayload(secret: string, payload: string, timestamp: number): string {
  const signed = `${timestamp}.${payload}`;
  return crypto.createHmac('sha256', secret).update(signed).digest('hex');
}

async function deliverWebhook(endpoint: WebhookEndpoint, event: Event) {
  const body = JSON.stringify(event);
  const ts = Math.floor(Date.now() / 1000);
  const sig = signPayload(endpoint.secret, body, ts);

  await fetch(endpoint.url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Webhook-Signature': `t=${ts},v1=${sig}`,
      'User-Agent': 'YourApp-Webhook/1.0',
      'X-Webhook-Id': event.id,
    },
    body,
    signal: AbortSignal.timeout(10_000),  // 10s timeout
  });
}
```

#### Retry and DLQ

```
attempt 1 → wait 1 min
attempt 2 → wait 5 min
attempt 3 → wait 30 min
attempt 4 → wait 2 hours
attempt 5 → wait 12 hours
attempt 6 → wait 24 hours
→ dead-letter queue, alert customer
```

Total ~40 hours of retries. The exact pattern is a product decision; the audit just confirms retries exist, backoff is exponential, and DLQ is monitored.

#### SSRF protection on URLs

Customer-provided URLs can point to internal services or cloud metadata. See `saas-code-security-review/references/ssrf-patterns.md`. At a minimum:

- HTTPS-only.
- Resolve hostname, reject RFC1918 / loopback / link-local IPs.
- Disallow `localhost` and any internal hostnames.
- Connect to the resolved IP (not re-resolve) to mitigate DNS rebinding.
- No redirect following (or re-validate each redirect target).

```ts
async function validateAndDeliver(url: string, payload: string) {
  // Pre-checks
  const u = new URL(url);
  if (u.protocol !== 'https:') throw new Error('https required');
  const ips = await dns.resolve4(u.hostname);
  if (ips.some(isPrivateIp)) throw new Error('private IP blocked');
  // Connect to resolved IP, deliver
  // ...
}
```

#### Document for customers

Provide:
- A signed example payload they can copy to test verification.
- The signature algorithm (HMAC-SHA256, the exact byte composition).
- The retry policy.
- A way to rotate the secret without missing events (overlap window where both old and new secrets verify).

### Common outbound-webhook bugs

1. **Same signing secret across customers** — one customer's leak compromises everyone's verification.
2. **No SSRF protection** — customer configures `http://169.254.169.254/...`, your service hits cloud metadata.
3. **No timeout** — slow customer endpoints block worker pool.
4. **Sync delivery in request path** — customer events delivered during your API response delay your own API.
5. **No retry visibility** — customer can't see what failed and why.
6. **Logs include the signing secret** — never log the secret, even in debug.
7. **Webhook payload includes sensitive data customer didn't earn the right to see** — apply the same authorization to webhook payloads as to API responses.

## Verification

For inbound:
- Replay a captured webhook body with an old timestamp → expect 400.
- Tamper one byte of body → expect 401.
- Send same delivery ID twice → expect dedup (no double processing).

For outbound:
- Configure a test endpoint that logs received signatures; verify they match the documented scheme.
- Configure a URL that resolves to 127.0.0.1 → expect rejection.
- Disable the test endpoint, watch for retry sequence in your delivery logs.
