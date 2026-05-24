---
name: redis-security
description: Security audit for Redis usage including ACL configuration, network exposure (bind, protected-mode), TLS, command restrictions, key namespacing across tenants, EVAL/Lua sandbox safety, pub/sub leakage, persistence file protection, and client library patterns (ioredis, node-redis, redis-py). Use this skill whenever the user mentions Redis, redis client, ioredis, node-redis, redis-py, Lettuce, redis-cli, redis.conf, Lua scripts, EVAL, or asks "audit my Redis setup", "Redis security", "Redis ACL". Trigger when the codebase contains Redis client libraries or `redis://` connection strings.
---

# Redis Security Audit

Audit Redis deployment and application usage. Redis security has historically been weak in defaults (no auth, plain TCP); current versions are better but require explicit configuration.

## When this skill applies

- Reviewing Redis server configuration (`redis.conf`)
- Auditing client library usage and connection handling
- Reviewing key naming/namespacing for tenant isolation
- Checking Lua scripts (EVAL) for safety
- Reviewing pub/sub channel scoping

## Workflow

Follow `../_shared/audit-workflow.md`.

### Phase 1: Stack detection

```bash
# Client libraries
grep -E '"(ioredis|redis|redis-py|@upstash/redis)":' package.json
grep -E '^redis|^ioredis' requirements.txt 2>/dev/null

# Connection strings
grep -rn 'redis://\|rediss://' src/ . --include='*.js' --include='*.ts' --include='*.py' 2>/dev/null
```

### Phase 2: Inventory

```bash
# Key patterns
grep -rnE '"[a-zA-Z]+:[^"]*"' src/ | grep -iE 'set\(|get\(|hset|hget|lpush|rpush' | head -20

# Lua scripts
grep -rn 'EVAL\|eval(\|evalsha' src/ | head

# Pub/sub
grep -rn 'subscribe\|publish\|psubscribe' src/

# redis.conf if present
ls **/redis.conf 2>/dev/null
```

### Phase 3: Detection — the checks

#### Network exposure

- **RDS-NET-1** Redis bound to localhost or VPN-only interface; `bind 0.0.0.0` only with firewall enforcing isolation.
- **RDS-NET-2** `protected-mode yes` (default in modern versions). Refuses connections without auth from external interfaces.
- **RDS-NET-3** Port not exposed to public internet. Verify with `nmap -p 6379 <host>` from outside.

#### Authentication

- **RDS-AUTH-1** `requirepass` set (long random string) OR ACL users configured. No anonymous access.
- **RDS-AUTH-2** Application uses ACL user with minimum privileges (read-only for cache reads, write for cache writes; no `FLUSHDB`/`FLUSHALL`/`CONFIG`).
- **RDS-AUTH-3** Default user (`default`) either disabled or password-protected.
- **RDS-AUTH-4** Connection string with password in env var, not committed.

```
# redis.conf example
requirepass <random>
user default off
user app on >appPassword ~app:* +@read +@write +@list -@dangerous
user readonly on >roPassword ~app:* +@read -@write -@dangerous
```

#### TLS

- **RDS-TLS-1** Production Redis uses TLS (`rediss://`, port 6380, or TLS port). Client validates server cert.
- **RDS-TLS-2** Self-managed Redis: `tls-port`, `tls-cert-file`, `tls-key-file`, `tls-ca-cert-file` configured.
- **RDS-TLS-3** Managed Redis (Upstash, AWS ElastiCache with encryption in transit, Redis Cloud) — verify TLS option enabled.

#### Command restrictions

Dangerous commands disabled or restricted:

- **RDS-CMD-1** `FLUSHALL`, `FLUSHDB`, `CONFIG`, `DEBUG`, `KEYS`, `SHUTDOWN` restricted to admin user only. App user denied via ACL `-@dangerous` or `rename-command` in older configs.
- **RDS-CMD-2** `KEYS *` not used in app code (blocks Redis on large datasets). Use `SCAN`.
- **RDS-CMD-3** `EVAL` requires `@scripting` category in ACL; consider restricting if not used.

#### Key namespacing

- **RDS-KEY-1** Multi-tenant apps namespace keys with tenant: `tenant:{tid}:session:{sid}`. Without namespace, one tenant can guess/scan another's keys.
- **RDS-KEY-2** ACL key patterns enforce namespace: `~tenant:abc123:*` for tenant-scoped users.
- **RDS-KEY-3** Random keys (session IDs, cache busters) use cryptographic random, not sequential IDs.

#### Lua scripts (EVAL)

- **RDS-LUA-1** Scripts don't accept arbitrary code from request bodies. Hardcoded scripts loaded with SCRIPT LOAD; EVALSHA used.
- **RDS-LUA-2** Scripts validate input within the script (Lua-side type checks).
- **RDS-LUA-3** Scripts don't run for too long (default timeout 5s); long scripts can cause cluster-wide pauses.

#### Pub/sub

- **RDS-PS-1** Channel names namespaced by tenant. `psubscribe('*')` reveals all activity.
- **RDS-PS-2** Subscribers don't receive other tenants' messages — enforced via channel naming convention + ACL channel pattern.
- **RDS-PS-3** ACL channel patterns: `&tenant:abc123:*` (Redis 6.2+).

#### Cache poisoning

- **RDS-CP-1** Cache keys derived from request include user context (user ID, tenant ID) where the cached value is per-user.
- **RDS-CP-2** Cache values validated on read; corrupted/unexpected types treated as cache miss, not bubbled to app.

#### Connection handling

- **RDS-CONN-1** Connection pool capped; no unbounded `new Redis()` per request.
- **RDS-CONN-2** Connection retries with exponential backoff; not tight loop.
- **RDS-CONN-3** Sentinel / Cluster client config has fail-over without leaking data across nodes.

#### Persistence files

If Redis is configured with RDB or AOF:

- **RDS-PER-1** Persistence files (`dump.rdb`, `appendonly.aof`) not in web-accessible directories.
- **RDS-PER-2** File permissions restrict to redis user.
- **RDS-PER-3** Backups encrypted at rest, transferred over TLS.

#### Managed Redis specifics

**Upstash:**
- **RDS-UPS-1** REST token (used for HTTP API) treated as secret. Separate read/write tokens if available.
- **RDS-UPS-2** Database scope (single-region vs global) matches data sensitivity.

**AWS ElastiCache:**
- **RDS-AWS-1** Encryption at rest enabled.
- **RDS-AWS-2** Encryption in transit enabled.
- **RDS-AWS-3** Authentication via Redis AUTH token OR IAM (newer).
- **RDS-AWS-4** Subnet group in private subnets; SG restricts ingress.

**Redis Cloud / Redis Enterprise:**
- **RDS-RC-1** Default user disabled; per-app ACL user.
- **RDS-RC-2** Source IP allowlist or VPC peering.

#### Memory limits and eviction

- **RDS-MEM-1** `maxmemory` set; without it, OOM can crash the host.
- **RDS-MEM-2** `maxmemory-policy` set appropriately (`allkeys-lru` for cache, `noeviction` for source-of-truth).
- **RDS-MEM-3** Eviction of session keys planned for; lost sessions handled gracefully (log out, not crash).

#### Slow log

- **RDS-LOG-1** `slowlog-log-slower-than` configured; reviewed periodically. Slow log can contain sensitive data — restrict access.

#### Application patterns

- **RDS-APP-1** Sensitive data (passwords, full PII) NOT cached. Use Redis for tokens, session IDs, derived caches — not the primary store of secrets.
- **RDS-APP-2** Set TTLs on session keys; idle sessions expire.
- **RDS-APP-3** Rate limit counters use atomic operations (INCR with EXPIRE) to avoid race conditions.

#### Dependencies

- **RDS-DEP-1** Redis server version current (7.x or later). Older versions had Lua sandbox escapes.
- **RDS-DEP-2** Client library current; ioredis 5+, node-redis 4+.

### Phase 4: Triage

Critical: Redis exposed to internet without auth; default password / no `requirepass`; `EVAL` of user-supplied scripts; app user has `FLUSHALL`.

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `RDS-`.
