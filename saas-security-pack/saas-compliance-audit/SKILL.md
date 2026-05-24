---
name: saas-compliance-audit
description: Audit SaaS applications against common compliance frameworks (SOC2, GDPR, HIPAA, PCI-DSS) with focus on technically-verifiable controls including audit logging, data retention, encryption at rest and in transit, DSAR (Data Subject Access Request) endpoints, breach notification readiness, vendor risk, and access reviews. Use this skill whenever the user asks about SOC2, GDPR, HIPAA, PCI-DSS, compliance audit, audit logging, data retention, DSAR, "right to be forgotten", erasure requests, evidence collection, ISO 27001, or "are we compliant". Trigger on phrases like "audit my compliance posture", "SOC2 readiness", "GDPR controls", "do we have the right logs", "data retention policy", "DSAR endpoint", "data deletion", "compliance evidence". Use this even when only one framework or control is mentioned.
---

# SaaS Compliance Audit

Audit the technical surface of a SaaS application against common compliance frameworks. This is NOT a substitute for a qualified auditor — it's a pre-audit gap analysis that finds the technical controls auditors will look for.

## When this skill applies

- Pre-audit readiness checks (SOC2 Type 1/2, ISO 27001, GDPR, HIPAA, PCI-DSS)
- Designing the audit logging system
- Setting up DSAR / "right to erasure" endpoints
- Reviewing data retention policies and implementation
- Vendor risk assessment of subprocessors
- Evidence collection for an upcoming audit

This skill focuses on **technically verifiable controls**. Policy-only items (org chart, signed agreements, training records) are out of scope — the auditor will collect those separately.

Use other skills for: data-layer controls (`supabase-security-audit`, `saas-tenant-isolation`), application-layer controls (`saas-code-security-review`).

## Workflow

Follow `../_shared/audit-workflow.md`. Compliance-specific notes below.

### Phase 1: Scope confirmation

- Which framework(s)?
  - **SOC 2 Type 1**: point-in-time; technical controls exist.
  - **SOC 2 Type 2**: operating effectiveness over a 3-12 month window; need evidence of consistent operation.
  - **GDPR**: EU personal data; data subject rights are technical features.
  - **HIPAA**: US healthcare data; specific encryption + access logging requirements.
  - **PCI-DSS**: payment card data; segmentation + key management.
  - **ISO 27001**: management system; technical controls map to Annex A.
- Which Trust Service Criteria (SOC 2): Security (always), Availability, Confidentiality, Processing Integrity, Privacy?
- Audit window if Type 2 (need backward-looking evidence).
- Which subprocessors are in scope?

### Phase 2: Inventory

For each framework, list:
- The technical controls the auditor will sample.
- The evidence sources for each (logs, screenshots, configurations, code).
- The current implementation status.

### Phase 3: Detection — the checks

#### Audit logging — see `references/audit-logging.md`

- **SCMP-LOG-1** Audit log captures user-initiated actions: auth events (login, logout, MFA), account changes (email, password, role), data access (read of PII), data mutation (create, update, delete on sensitive tables), admin actions (impersonation, settings changes).
- **SCMP-LOG-2** Each event includes: timestamp (UTC, ISO 8601), actor (user ID, IP, user agent), action, target (resource type + ID), outcome (success/failure), correlation ID.
- **SCMP-LOG-3** Logs immutable in the storage layer (append-only; cryptographic hashing or write-once storage).
- **SCMP-LOG-4** Logs retained for the required period (typically 1 year for SOC 2; 6 years for HIPAA; 3 years for PCI).
- **SCMP-LOG-5** Log storage access restricted; access to logs itself logged.
- **SCMP-LOG-6** Log timestamps from a trusted clock source (NTP synced).
- **SCMP-LOG-7** Customer-facing audit log available for B2B SaaS (their own actions, exported on demand).

#### Data retention and deletion

- **SCMP-RET-1** Documented retention policy per data category.
- **SCMP-RET-2** Implementation deletes data after retention period (not just hides it from UI).
- **SCMP-RET-3** Cascading deletes verified — closing an account removes related data across all tables, caches, backups (with documented backup retention separate from primary).
- **SCMP-RET-4** Deletion verified in logs, search indices, analytics, third-party processors.
- **SCMP-RET-5** Backups have their own retention; old backups deleted on schedule.
- **SCMP-RET-6** Soft-deleted records (tombstones) eventually hard-deleted unless legal hold applies.

#### Data Subject Access Requests (DSAR) — GDPR Articles 15, 17, 20

- **SCMP-DSAR-1** Endpoint or workflow for "give me my data" (Article 15 right of access).
- **SCMP-DSAR-2** Endpoint or workflow for "delete my data" (Article 17 right to erasure).
- **SCMP-DSAR-3** Endpoint or workflow for "give me my data in machine-readable form" (Article 20 portability) — typically JSON or CSV export.
- **SCMP-DSAR-4** Response time tracked; ≤ 30 days (GDPR), with documented extensions when justified.
- **SCMP-DSAR-5** Identity verification before fulfilling — can't just trust an email address.
- **SCMP-DSAR-6** DSAR audit log records every request and outcome.

#### Encryption

- **SCMP-ENC-AT-REST-1** Database encrypted at rest (RDS/CloudSQL/Azure DB encryption enabled).
- **SCMP-ENC-AT-REST-2** Object storage encrypted at rest (S3 SSE, GCS, Azure Blob).
- **SCMP-ENC-AT-REST-3** Backups encrypted at rest.
- **SCMP-ENC-AT-REST-4** Field-level encryption for highly sensitive columns (SSN, payment cards, health data) — additional layer beyond disk encryption.
- **SCMP-ENC-IN-TRANSIT-1** TLS 1.2+ everywhere; TLS 1.3 preferred; TLS 1.0/1.1 disabled.
- **SCMP-ENC-IN-TRANSIT-2** Strong cipher suites (no RC4, no 3DES, no CBC-only modes for new connections).
- **SCMP-ENC-IN-TRANSIT-3** Internal service-to-service communication encrypted (mTLS or VPC + encrypted inter-zone).
- **SCMP-ENC-IN-TRANSIT-4** HSTS with `includeSubDomains; preload` for public sites.
- **SCMP-ENC-KEYS-1** Encryption keys managed in KMS/HSM, not application code.
- **SCMP-ENC-KEYS-2** Key rotation policy documented and implemented.

#### Access management — see `references/access-reviews.md`

- **SCMP-ACC-1** SSO enforced for employee access to production systems.
- **SCMP-ACC-2** MFA required for all admin/privileged accounts.
- **SCMP-ACC-3** Onboarding/offboarding process triggers IAM provisioning/deprovisioning.
- **SCMP-ACC-4** Quarterly access review with evidence (signed-off list of who has what).
- **SCMP-ACC-5** Privileged access just-in-time elevated, not standing.
- **SCMP-ACC-6** Shared accounts eliminated (every action traceable to a person).
- **SCMP-ACC-7** Production access from approved devices (MDM, posture check) where required.

#### Vendor / subprocessor management

- **SCMP-VEN-1** List of subprocessors maintained and published (GDPR requirement).
- **SCMP-VEN-2** Each subprocessor has DPA (Data Processing Agreement) signed.
- **SCMP-VEN-3** Each subprocessor's compliance posture documented (SOC 2 report on file, etc.).
- **SCMP-VEN-4** Customers notified before adding a new subprocessor (typical commitment: 30 days).
- **SCMP-VEN-5** Subprocessor access reviewed quarterly.

#### Backup and disaster recovery

- **SCMP-BDR-1** Backups taken at documented frequency (typical: daily incremental, weekly full).
- **SCMP-BDR-2** Backup integrity verified (test restore at least quarterly).
- **SCMP-BDR-3** Backups stored in a different region/account than primary.
- **SCMP-BDR-4** RPO (Recovery Point Objective) and RTO (Recovery Time Objective) documented and tested.
- **SCMP-BDR-5** Disaster recovery plan documented and exercised annually.

#### Incident response

- **SCMP-IR-1** Documented incident response plan with roles and escalation.
- **SCMP-IR-2** Breach notification process meets jurisdictional timelines (GDPR 72h, others vary).
- **SCMP-IR-3** Postmortem template requires root cause + remediation + recurrence prevention.
- **SCMP-IR-4** On-call rotation with documented handoff.
- **SCMP-IR-5** Tabletop exercises run at least annually.

#### Change management

- **SCMP-CM-1** All production changes go through PR review (covered by `github-repo-hardening`).
- **SCMP-CM-2** Production deploys logged with approver, what changed, when.
- **SCMP-CM-3** Rollback capability tested.
- **SCMP-CM-4** Emergency change process documented (still needs post-hoc review).

#### Monitoring and alerting

- **SCMP-MON-1** Security-relevant events trigger alerts (failed login spikes, IAM changes, security group changes, key access).
- **SCMP-MON-2** Alerts routed to people, not just dashboards.
- **SCMP-MON-3** Alert response time tracked; SLA documented.

### Phase 4: Triage

Critical class examples:
- No audit log at all on a SOC 2 candidate system
- DSAR-deletion endpoint that doesn't actually delete (just soft-deletes forever)
- Backups not encrypted
- TLS 1.0/1.1 still accepted
- No quarterly access review evidence

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `SCMP-`.

For compliance audits, the report should map findings to the relevant framework controls:

| Finding | SOC 2 CC | GDPR | HIPAA | PCI |
|---------|----------|------|-------|-----|
| SCMP-LOG-1 missing | CC7.2 | Art 32 | §164.312(b) | 10.1-10.7 |
| SCMP-RET-2 broken | CC6.5 | Art 5(1)(e), 17 | §164.530(j) | 3.2 |
| ...     |        |      |       |     |

The cross-framework table makes the gap analysis useful for organizations pursuing multiple certifications.

## Framework mapping snapshot

**SOC 2 Trust Service Criteria** (Security is mandatory; others optional):
- CC (Common Criteria): all auditees.
- A1: Availability.
- C1: Confidentiality.
- PI1: Processing Integrity.
- P1-P8: Privacy.

**GDPR articles most relevant to this audit:**
- Art 5 (principles), 25 (privacy by design), 30 (records of processing), 32 (security of processing), 33 (breach notification), 35 (DPIA), Chapter III (data subject rights).

**HIPAA Security Rule:**
- Administrative safeguards (§164.308), Physical (§164.310), Technical (§164.312).

**PCI-DSS:**
- Requirements 1-12; technical controls largely cluster around 1 (firewall), 3-4 (data), 6 (secure dev), 7-8 (access), 10 (logging), 11 (testing).

## Outputs

1. Audit report with findings cross-mapped to frameworks.
2. Evidence collection checklist for the auditor (per finding: what document / log query / screenshot is evidence of compliance).
3. Remediation roadmap with prioritization by audit timeline.

## References

- `references/audit-logging.md` — Schema, retention, immutability, customer-facing logs
- `references/gdpr-dsar.md` — DSAR endpoint design, identity verification, deletion verification
