# GDPR DSAR (Data Subject Access Requests) Reference

Load this when designing or auditing endpoints for data access, data portability, and data deletion under GDPR.

## The three rights, technically

| Right | GDPR Article | What the system must do |
|-------|--------------|--------------------------|
| Access | Art 15 | Provide a copy of all personal data held about the subject |
| Portability | Art 20 | Provide the data in a structured, machine-readable, commonly-used format |
| Erasure | Art 17 | Delete the data, including from backups (or document why retained) |

Plus: rectification (Art 16), restriction (Art 18), objection (Art 21). Most automatable through the same data-access infrastructure.

## Endpoint design

### Triggering a DSAR

Three common patterns, increasing in friction:

1. **Self-service in account settings**: "Download my data" / "Delete my account" buttons. Lowest friction, highest scale, most legally clear.
2. **Email-based**: subject emails `privacy@yourco.com`; ticket workflow. Requires identity verification; common in B2B.
3. **Form-based**: web form that creates a ticket. Middle ground.

GDPR doesn't mandate self-service, but for consumer-facing services, regulators increasingly expect it. For B2B, the DPA with the controller may shift the responsibility — the customer (controller) usually handles DSARs themselves and uses your tooling to fulfill them.

### Identity verification

Before fulfilling a DSAR, verify the requester IS the subject:

- **Logged-in user, recent strong auth**: typically sufficient. Add a step-up MFA for irreversible actions (deletion).
- **Email-only**: NOT sufficient. Email is forgeable; could be stolen.
- **Account email + something else**: account email + last 4 of payment method, or + secret answer, or + recent transaction details.

Don't ask for ID documents unless necessary; collecting more PII to verify a privacy request defeats the purpose.

### Response time

- GDPR: 1 month from receipt. Can extend by 2 months for complex requests, with notice.
- Time starts at receipt — don't lose days on triage.

For automated self-service, response is immediate. For tickets, instrument SLAs.

## Access (Art 15) — what to include

Personal data of the subject across all systems:

- Profile: account info (name, email, settings, preferences).
- Activity: posts, comments, uploads, transactions.
- Metadata: created_at, last_login, IPs, devices, location data if collected.
- Inferred / derived data: tags, segments, recommendations, ML features.
- Communications: support tickets, in-app messages.
- Audit log entries about the subject.

Provide context too:
- Purposes of processing for each category.
- Retention period applicable.
- Recipients (subprocessors who saw the data).

### Format

JSON or CSV per category, packaged in a ZIP. Document the schema briefly so the subject (or their tech support) can understand it.

```
my-data-export-2026-05-23.zip
├── README.md          # what's in each file, formats, contacts
├── profile.json
├── posts.json
├── comments.json
├── transactions.json
├── audit-events.csv
├── support-tickets.json
└── files/             # any uploaded media
```

### Things to exclude

- Other people's data even when intertwined (e.g., other parties to a transaction — redact).
- Internal scoring or trade secrets that aren't strictly the subject's personal data (debatable; lean toward inclusion to avoid disputes).
- Aggregated statistics that don't identify the subject.

## Portability (Art 20)

Subset of Art 15 covering data the subject provided OR generated through activity (NOT data inferred about them). Typically same export package, with portability scope often broader for consumer expectation reasons.

Use widely-adopted formats: JSON, CSV. Avoid proprietary binary formats.

## Erasure (Art 17) — the hard one

Deletion across all storage:

### Primary database

```sql
-- For each table containing the subject's data:
DELETE FROM users WHERE id = $1;
DELETE FROM user_settings WHERE user_id = $1;
DELETE FROM posts WHERE author_id = $1;
-- ... (or set author_id = NULL if posts should persist anonymized)
```

If posts should remain (other users replied to them, comments depend on them), anonymize:

```sql
UPDATE posts
SET author_id = NULL,
    author_name = 'Deleted user',
    metadata = jsonb_strip_nulls(metadata - 'author_ip')
WHERE author_id = $1;
```

Document this in the response: "Your account is deleted; your public posts are anonymized and retained because deletion would harm other users who replied."

### Caches

Redis, Memcached, in-process LRU. Each user-keyed cache entry for the subject must be purged. Easy to forget; many DSAR failures find the subject's data resurfacing from cache hours after "deletion".

```ts
async function purgeUserCaches(userId: string) {
  for (const key of await redis.scan(0, `MATCH`, `*${userId}*`)) {
    await redis.del(key);
  }
}
```

(Scan-and-delete is slow; better is to design caches with tenant/user prefixes for batch removal.)

### Search indices

Elasticsearch / Algolia / Meilisearch / Postgres FTS — delete or update documents.

```ts
await algolia.deleteObject(`user-${userId}`);
await algolia.deleteBy({ filters: `author_id:${userId}` });
```

### File storage

Delete uploaded files; remove signed-URL caches.

```ts
const files = await db.query('SELECT s3_key FROM uploads WHERE user_id = $1', [userId]);
await Promise.all(files.rows.map(f => s3.deleteObject({ Bucket: B, Key: f.s3_key }).promise()));
```

### Analytics and third-party processors

Each subprocessor that received personal data needs deletion too:

- PostHog, Mixpanel, Segment: API call to delete user.
- Customer.io / Intercom / HubSpot: API or sync.
- Sentry / Rollbar: data minimization at source, but also their delete-user APIs.

Document each subprocessor's deletion mechanism in your runbook.

### Backups

Backups contain copies of the deleted data. Options:

- **Periodic rotation**: backups eventually rotate out. Document the maximum window (e.g., 30 days). Inform the subject that their data may persist in backups up to that period and will not be restored to production.
- **Selective backup purge**: hard, expensive, only for high-value cases.
- **Encryption-based**: encrypt user data with per-user keys; "delete" by destroying the key. Data in backups becomes unrecoverable. Strong privacy property, complex to implement.

Most SaaS use the rotation approach + clear documentation in their privacy policy.

### Logs

Application logs containing the subject's data should rotate per retention policy. Audit logs may need to retain a record of the DSAR fulfillment itself — but the personal data within historical audit events may need redaction.

Some auditors accept "the audit log records the deletion happened, but historical events retain personal data per audit retention requirements" — confirm with your compliance counsel.

## DSAR verification chain

Every DSAR has:
1. **Receipt** (timestamp, channel, identity).
2. **Verification** (method, outcome).
3. **Scope determination** (what data subjects across systems).
4. **Fulfillment** (extraction, anonymization, deletion).
5. **Response to subject** (what was done, what wasn't and why).
6. **Audit record** (above five steps logged with timestamps).

The audit record is what proves compliance during an audit. Without it, even if the system did the right thing technically, the auditor can't verify.

## Endpoint sketch

```ts
// Self-service export
app.post('/api/v1/me/data-export', requireAuth, requireMfa, async (req, res) => {
  await auditLog('dsar.export.requested', {
    user_id: req.user.id,
    request_id: req.id,
  });

  // Async job — exports can be large
  const job = await jobs.queue('dsar-export', {
    user_id: req.user.id,
    delivery_email: req.user.email,
    request_id: req.id,
  });

  res.json({
    status: 'queued',
    job_id: job.id,
    expected_delivery: '24h',
  });
});

// Self-service deletion
app.post('/api/v1/me/delete-account', requireAuth, requireMfa, async (req, res) => {
  // Require user to type a confirmation phrase
  if (req.body.confirmation !== `delete-${req.user.email}`) {
    return res.status(400).json({ error: 'Confirmation mismatch' });
  }

  await auditLog('dsar.deletion.requested', {
    user_id: req.user.id,
    request_id: req.id,
  });

  // 30-day grace period (per common practice; some products immediate)
  await db.query(
    'UPDATE users SET deletion_scheduled_at = NOW() + INTERVAL \'30 days\' WHERE id = $1',
    [req.user.id]
  );

  res.json({
    status: 'scheduled',
    completes_at: '...',
    cancellable_until: '...',
  });
});
```

## Audit checklist

1. Self-service or documented manual workflow for each of the three rights.
2. Identity verification step appropriate to the action's irreversibility.
3. Export covers all personal data across all systems and subprocessors.
4. Deletion cascades to caches, search indices, backups (with documented policy), and subprocessors.
5. SLA tracked (1 month default).
6. Audit log records every DSAR with all five lifecycle stages.
7. Privacy policy clearly explains the rights and how to invoke them.
8. Per-subprocessor deletion mechanism documented and tested.
9. Anonymization for retained data (posts, transactions) is verified — no path back to identity.
10. Annual review of DSAR mechanism (volumes, SLA adherence, failure modes).
