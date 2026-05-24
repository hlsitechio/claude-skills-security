# SSRF (Server-Side Request Forgery) Reference

Load this when reviewing code that fetches URLs (webhooks, image proxies, "fetch from URL" features) or when scoping SSRF risk.

## Why SSRF is high-leverage in cloud SaaS

When a backend can be tricked into fetching an attacker-controlled URL, that backend's network position becomes the attacker's network position. In cloud SaaS, that often means:

- Reading the **cloud metadata endpoint** (`http://169.254.169.254/`) to steal IAM credentials.
- Reaching **internal services** that aren't exposed publicly (admin panels, Redis, Elasticsearch, internal APIs).
- Triggering **internal RPCs** with attacker-controlled payloads (port scanning, exploiting internal services).
- **Reading local files** via `file://` URLs if the HTTP client allows scheme switching.

## Vulnerable patterns to flag

### Pattern 1 — Plain URL fetch

```js
app.post('/api/import', async (req, res) => {
  const response = await fetch(req.body.url);   // ← anything goes
  res.json(await response.json());
});
```

### Pattern 2 — Image proxy / thumbnail

```python
@app.get("/thumb")
def thumb(url: str):
    img = requests.get(url).content   # ← same problem
    return process_image(img)
```

### Pattern 3 — Webhook delivery

```go
http.Post(webhook.URL, "application/json", body)   // ← if URL is user-set, SSRF
```

### Pattern 4 — RSS / OPML / OG metadata fetcher

Any "give us a URL, we'll fetch it and show you something" feature is a SSRF surface.

### Pattern 5 — PDF / HTML rendering

Headless browsers (Puppeteer, Playwright) rendering attacker-controlled HTML can fetch internal URLs via `<img src>`, `<iframe>`, `<link>`, etc.

## What "validation" usually fails

Common but insufficient mitigations:

| Attempt | Why it fails |
|---------|--------------|
| Block `localhost` / `127.0.0.1` | `127.1`, `0.0.0.0`, `[::1]`, IPv6 mapped, decimal encoding (`2130706433`), hex (`0x7f000001`) all bypass |
| Block private IPv4 ranges | DNS rebinding: attacker domain resolves public for the first lookup, private for the second |
| URL parsing then string match | `http://evil.com#@127.0.0.1/`, `http://evil.com@127.0.0.1/`, redirects |
| Allowlist by hostname suffix | Attacker controls `attackeryourorg.com` if you match `*yourorg.com` |
| Check `Host` header on response | Attacker controls their server's Host header |

## What actually works

### Defense 1 — Strict allowlist

If the feature only needs to fetch from a known set of providers (Stripe webhook URLs, customer-configured S3 buckets, etc.), allowlist:

```python
ALLOWED_HOSTS = {"hooks.stripe.com", "api.yourorg.com"}

def fetch_safe(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("https",):
        raise ValueError("scheme not allowed")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return requests.get(url, timeout=5, allow_redirects=False)
```

If allowlist is feasible, use it. Most "import from any URL" features can be redesigned to "upload the file directly" instead.

### Defense 2 — DNS-resolution-time blocklist with re-resolution control

When allowlist isn't possible:

```python
import socket, ipaddress, requests
from urllib.parse import urlparse

BLOCKED_NETWORKS = [
    ipaddress.ip_network(n) for n in [
        "127.0.0.0/8",       # loopback
        "10.0.0.0/8",        # RFC1918
        "172.16.0.0/12",     # RFC1918
        "192.168.0.0/16",    # RFC1918
        "169.254.0.0/16",    # link-local + AWS/GCP metadata
        "100.64.0.0/10",     # CGN
        "192.0.0.0/24",      # IETF
        "192.0.2.0/24",      # TEST-NET-1
        "198.18.0.0/15",     # benchmark
        "224.0.0.0/4",       # multicast
        "240.0.0.0/4",       # reserved
        "::1/128",           # IPv6 loopback
        "fc00::/7",          # IPv6 ULA
        "fe80::/10",         # IPv6 link-local
        # AWS metadata IPv6: fd00:ec2::254
        "fd00:ec2::/64",
    ]
]

def is_blocked(ip_str):
    ip = ipaddress.ip_address(ip_str)
    return any(ip in net for net in BLOCKED_NETWORKS)

def safe_fetch(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("https",):
        raise ValueError("scheme")
    # Resolve once, validate
    ips = {ai[4][0] for ai in socket.getaddrinfo(parsed.hostname, None)}
    if any(is_blocked(ip) for ip in ips):
        raise ValueError("blocked address")
    # Bind requests to the resolved IP to avoid re-resolution drift
    # (DNS rebinding mitigation — pin the IP for this request)
    session = requests.Session()
    # ... use a custom adapter that connects to the resolved IP with the original Host header
    return session.get(url, timeout=5, allow_redirects=False)
```

The DNS rebinding problem deserves explicit handling: validate the resolved IP, then connect to that IP (not re-resolve). Libraries: [`safeurl`](https://github.com/jamesabe/safeurl-py), [`ssrf-protected-requests`](https://github.com/zerodayfind/ssrf-protected-requests) in Python; [`safe-curl`](https://github.com/peercast/safe-curl) in PHP; in Node, build with a custom `lookup` function on `http.Agent`.

### Defense 3 — Network-layer egress filter

Run the application in a network namespace / VPC / container that can't reach `169.254.169.254` or RFC1918 ranges. Defense in depth — even if app-layer protection has a bug, the kernel/network blocks it.

For AWS: enforce IMDSv2 (`http_tokens: required` on instance metadata options), which requires a PUT with a token header — most SSRF can't supply that.

### Defense 4 — Redirects

Disable redirect-following entirely (`allow_redirects=False`). If redirects are needed, re-apply the allowlist/blocklist on every hop. Many SSRF protections forget that `https://allowed.com` can redirect to `http://169.254.169.254/`.

### Defense 5 — Limit response size and time

Cap fetched response size (e.g., 10 MB) and total time (e.g., 10 s). Limits don't prevent SSRF but reduce blast radius.

## Cloud metadata specifics

| Cloud | Endpoint | Mitigation |
|-------|----------|------------|
| AWS | `http://169.254.169.254/latest/meta-data/` (IMDSv1) | Enforce IMDSv2 + block 169.254.169.254 at app layer |
| GCP | `http://metadata.google.internal/` (resolves to 169.254.169.254) | Requires `Metadata-Flavor: Google` header — but if app forwards user headers, this is bypassable |
| Azure | `http://169.254.169.254/metadata/` | Requires `Metadata: true` header |
| DO | `http://169.254.169.254/metadata/v1/` | No protective header — block at network |
| Alibaba | `http://100.100.100.200/` | Block at network |

Block all of those at the application layer regardless of which cloud you're on (avoids surprises during cloud migrations).

## Review checklist

For each outbound HTTP call from user-controlled URL:

1. Is there an allowlist of acceptable hosts/schemes?
2. If not, is there a blocklist applied at DNS resolution time?
3. Is the blocklist on resolved IP, not on string match of hostname?
4. Is DNS rebinding mitigated (connect to resolved IP, not re-resolve)?
5. Are redirects disabled or re-validated?
6. Is response size and time capped?
7. Is the cloud metadata endpoint blocked at both app and network layer?
8. Is IMDSv2 enforced (AWS) / equivalent (others)?
9. Are webhook URLs validated at config time AND at delivery time?
10. For headless browsers, are URL allowlists applied to the launcher (`--disable-web-security` should never be set)?
