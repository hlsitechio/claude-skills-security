# Access Reviews Reference

Periodic access reviews are an explicit SOC 2 control (CC6.1, CC6.2, CC6.3) and a fundamental hygiene practice regardless of compliance. The cadence is more important than the depth — quarterly reviews with light scrutiny beat annual reviews with deep scrutiny.

## What gets reviewed

For each system that stores or processes customer data:

1. **Human users** with access (employees, contractors, vendors).
2. **Service accounts** (CI/CD, integrations, monitoring).
3. **Roles / groups** and the permissions they grant.
4. **Standing access** vs **just-in-time** elevation.

## Cadence

| System sensitivity | Review frequency |
|--------------------|------------------|
| Production data stores (PII, secrets) | Quarterly |
| Production infrastructure (cloud, k8s) | Quarterly |
| Source code repos | Semi-annually |
| Internal tools (BI, support) | Semi-annually |
| Vendor / third-party access | Annually (or on each renewal) |
| Privileged accounts (root, owner) | Continuously (alerted on any change) |

## The process

### 1. Generate the list

Pull current access from each system:

```bash
# GitHub org members and team memberships
gh api -X GET 'orgs/{org}/members' --paginate
gh api -X GET 'orgs/{org}/teams' --paginate
# Per team:
gh api -X GET 'orgs/{org}/teams/{slug}/members' --paginate

# AWS IAM users + console access
aws iam list-users --query 'Users[*].[UserName,PasswordLastUsed,CreateDate]' --output table

# Supabase / Postgres roles
psql -c "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin FROM pg_roles ORDER BY rolname;"

# Google Workspace
gcloud identity groups memberships list --group-email=team@yourorg.com
```

### 2. Compare against the "should be" list

Source of truth: HR system (active employees) + project memberships + vendor contracts.

For each user:
- Still active employee/contractor? — if not, REVOKE.
- Still in a role that requires this access? — if not, REVOKE or DOWNGRADE.
- Last activity within review window? — if not, consider REVOKE.

### 3. Decisions

For each entry, decide:
- **Keep** — still needed at current level. Document rationale if non-obvious.
- **Modify** — downgrade or rescope (e.g., from admin to read-only).
- **Revoke** — no longer needed.

The reviewer for each system is typically the system owner (engineering manager for code; ops for infra; security for cross-cutting).

### 4. Execute revocations

Within 7 days of review completion. Track via tickets.

### 5. Evidence

For SOC 2 and similar audits:
- The list as of the review date.
- Decisions captured (CSV with columns: user, system, current_access, decision, decided_by, decided_at).
- Revocation tickets linked.
- Reviewer sign-off (signed PDF or signed git commit).

Store in an evidence folder with date stamps.

## Privileged accounts

These need continuous (not periodic) oversight:

- **AWS root account** — never used in normal operation; alerted on any login.
- **Database superusers** — alerted on creation, login, query patterns.
- **GitHub org owner** — alerts on member additions, OAuth app installations, secret rotations.
- **Service accounts with broad scope** — credential rotation cadence (90 days max).

Approach: ticket + approval (4-eye principle) for any use; auto-revoke after a session window.

## Stale-account criteria

Common policies:
- No login in 90 days → revoke (with notice).
- Inactive employees → revoke at termination + 0 days.
- Vendor access beyond contract end date → revoke automatically.

Track these via automation, not manual review.

## Just-in-time access

For high-risk systems, prefer JIT over standing access:
- Engineer requests elevated access via PR / ticket.
- Approver grants for N hours.
- Access auto-revokes.

Tools: AWS IAM Identity Center session policies, Okta Workflows, custom scripts.

## Common findings

| Finding | Severity | Example |
|---------|----------|---------|
| Former employee with active access | High | Engineer left 6 months ago, still in GitHub org |
| Service account with admin role | High | CI bot has `iam:*` instead of needed write actions only |
| Vendor with permanent access | Medium | One-time auditor still has read access 2 years later |
| Standing root / admin for daily use | Medium | DBA logs in daily with superuser role |
| No documented review process | Medium | Compliance gap; SOC 2 CC6.1 finding |
| Stale shared accounts | Medium | `ops@yourorg.com` shared inbox with 8 sessions |
| Inconsistent role grants | Low | Same job title has different access across people |

## Audit checklist

For each review cycle:

1. List of systems-in-scope updated since last review (new systems added).
2. Source-of-truth for "should have access" is current (HR up to date).
3. For each system, current access list pulled and dated.
4. Reviewer assigned and identified.
5. Decisions documented in writing.
6. Revocations executed within SLA.
7. Evidence archived.
8. Next review date scheduled.

## Tooling

- **Vanta / Drata / Secureframe** — automate evidence collection for SOC 2.
- **GitHub Actions cron** — schedule monthly access list pulls into a private repo for diff.
- **AWS Config / GuardDuty** — alert on privileged role changes.
- **Custom script** — pull from all sources, render diff vs last review, post to Slack for sign-off.

The point is repeatability. A manual quarterly review with consistent process beats automated tooling that gets abandoned after the first integration.
