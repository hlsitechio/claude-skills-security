# Audit Logging Reference

Load this when designing the audit log system or reviewing what's currently captured.

## The two log streams

Distinguish from the outset:

| Stream | Purpose | Retention | Format |
|--------|---------|-----------|--------|
| **Application logs** | Debugging, observability | 30-90 days typical | Structured JSON, mutable storage |
| **Audit log** | Compliance, security forensics, customer-facing | 1+ years, often 7 years | Append-only, signed/hashed, schema-stable |

Audit log is NOT the same as application log. Auditors will look for the audit log specifically. Some orgs collapse them; if you do, the audit-relevant subset must still meet audit-log requirements.

## Event schema

Every audit event has a stable schema:

```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2026-05-23T17:42:31.219Z",
  "tenant_id": "abc-123",
  "actor": {
    "type": "user",
    "id": "u-456",
    "ip": "203.0.113.45",
    "user_agent": "Mozilla/5.0 ...",
    "session_id": "sess-789"
  },
  "action": "user.password.changed",
  "target": {
    "type": "user",
    "id": "u-456"
  },
  "outcome": "success",
  "metadata": {
    "previous_value_hash": "sha256:abc...",
    "auth_method": "password+totp"
  },
  "correlation_id": "req-xyz",
  "schema_version": "1.0"
}
```

Stable fields auditors care about:
- `timestamp` — UTC, millisecond precision, ISO 8601.
- `actor` — who did it.
- `action` — verb (canonical name).
- `target` — what was acted on.
- `outcome` — success / failure / partial.

Variable fields go in `metadata`. Schema versioning matters — auditors sample old events, schema must remain readable.

## What events to capture

### Always

- Authentication: login, logout, MFA challenge, MFA success/failure, password change, password reset, session creation/termination.
- Authorization: privilege grants/revocations, role changes, permission delegation.
- User lifecycle: account creation, deletion, email change, suspension, reactivation.
- Admin: impersonation start/end, settings changes, billing changes.
- Data access (sensitive): reads of PII/PHI/payment data (HIPAA requires).
- Data mutation: create/update/delete on sensitive tables (settings, billing, compliance-scope data).
- Security events: failed login bursts, rate limit triggers, suspicious activity detection.
- Configuration: changes to security-relevant settings (MFA requirements, allowlists, integrations).
- API key: creation, rotation, revocation, usage.
- Data export: large exports, DSAR fulfillment, backup downloads.

### Discretionary (by framework)

- HIPAA: every read of PHI (treatment, payment, operations) — see `§164.312(b)`.
- PCI: every access to cardholder data + every system component login.
- SOC 2: depends on declared controls; logical access is the floor.

## What NOT to log

- Passwords (cleartext or hashed — don't log the hash either, it's still a brute force target).
- Session tokens, API keys, JWT contents (log a reference / fingerprint instead).
- Full payloads on data-mutation events (log "what changed" or hashes of values, not raw values, especially for PII).
- Authentication failure password attempts (could let an attacker probe via log access).
- Personal data beyond what's needed for the audit purpose (GDPR data minimization).

## Storage and immutability

Auditors want assurance the log can't be tampered with. Options:

### Option A — WORM storage

Write-Once-Read-Many:
- AWS S3 Object Lock in compliance mode.
- GCP Cloud Storage Bucket Lock.
- Azure Blob immutable storage.

Once written with a retention period, even root can't delete before the period elapses. Strongest control.

### Option B — Append-only database + cryptographic chaining

Each event includes the hash of the previous event (Merkle chain). Tampering with any event breaks the chain.

```ts
async function appendAudit(event: AuditEvent) {
  const last = await db.query('SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1');
  const prevHash = last.rows[0]?.hash ?? null;
  const eventHash = sha256(JSON.stringify({...event, prev_hash: prevHash}));
  await db.query(
    'INSERT INTO audit_log (event, prev_hash, hash) VALUES ($1, $2, $3)',
    [event, prevHash, eventHash]
  );
}
```

Periodically publish the current chain head externally (Sigstore, blockchain anchor, signed timestamp) — provides external verification.

### Option C — SIEM / dedicated log service

Datadog Audit Trail, Sumo Logic, Splunk, AWS Security Lake, GCP Chronicle. They store immutably, enable query, and most provide tamper-evidence certificates.

For SOC 2 small teams: AWS S3 Object Lock + Athena queries is the cheapest credible path.

## Access to the audit log

- Read access: security team, compliance officer, designated SREs. Not the general engineering team.
- Write access: application service accounts only — never humans directly. Humans can append via instrumented APIs.
- Access to the audit log is itself audited (audit-of-audit).

For B2B SaaS, customers often need to read their tenant's audit events:

```ts
// Customer-facing audit API — scope by tenant
app.get('/api/v1/audit-events', requireAuth, async (req, res) => {
  const events = await auditStore.query({
    tenant_id: req.user.tenantId,    // never accept tenant_id from client
    since: req.query.since,
    until: req.query.until,
    actions: req.query.actions,
    limit: Math.min(parseInt(req.query.limit) ?? 100, 1000),
  });
  res.json({ events });
});
```

Export to CSV/JSON is often a customer requirement for their own compliance.

## Retention

| Framework | Audit log retention |
|-----------|---------------------|
| SOC 2 | Depends on audit scope; 1 year typical for sample period coverage |
| GDPR | "As long as necessary"; courts often interpret 6 years for activity logs |
| HIPAA | 6 years from creation or last effective date (§164.530(j)(2)) |
| PCI-DSS | 1 year, 3 months online (Requirement 10.7) |
| ISO 27001 | Depends on risk assessment; 3 years common |

Default to the longest applicable. After expiry, deletion is itself audited.

## Time accuracy

Auditors check that timestamps are trustworthy:
- All log producers sync clock to NTP (Chrony, systemd-timesyncd).
- Drift monitored; alert on clock skew > 1 second.
- Cloud services typically handle this; on-prem requires explicit setup.
- Use UTC throughout; convert for display only, never for storage.

## Common audit findings

### Finding 1 — Logs in stdout only

Application logs everything to stdout, captured by Datadog/CloudWatch, retained 14 days. No separate audit log; no immutability. SOC 2 auditor will not accept this for the technical control evidence.

Fix: define an audit-event stream that writes to immutable storage. Application logs can stay where they are.

### Finding 2 — No correlation across services

Login event in auth service, data mutation in API service — no shared ID. When investigating an incident, can't correlate.

Fix: propagate a `correlation_id` through every service call (header, message attribute, span context).

### Finding 3 — Sensitive data in log values

`audit.log("password_changed", { new_password: req.body.password })` — the audit log itself becomes a target.

Fix: log metadata only. For password changes, log `auth_method`, success/failure, IP — never the password or its hash.

### Finding 4 — No customer-facing audit log

Customer asks "what happened on our account last week"; the answer requires engineering involvement.

Fix: build a per-tenant audit feed accessible via UI and API.

### Finding 5 — Logs not retained past 90 days

App logs 90 days; SOC 2 audit window is 12 months. The previous 9 months are gone.

Fix: audit-relevant events go to immutable storage with the right retention; app logs can stay at 90 days.

### Finding 6 — Audit log writes can fail silently

```ts
await api.doThing();         // succeeds
await audit.log(event);       // fails — silently swallowed
```

If the write fails, the action happened with no audit. For high-value actions, fail closed: don't complete the action if the audit can't be recorded. For lower value: at least surface the failure and reconcile later.

## Audit checklist

1. Audit-event stream distinct from application logs.
2. Schema stable, versioned, contains actor/action/target/outcome/timestamp/correlation.
3. Sensitive values not in event payload.
4. Storage immutable or chain-hashed.
5. Retention meets the strictest applicable framework.
6. Access to log restricted and itself audited.
7. Time source synced (NTP); drift monitored.
8. Customer-facing audit endpoint (B2B SaaS).
9. Failure-mode for audit writes documented and acceptable.
10. Sample queries documented for common audit questions ("who accessed X in date range").
