# Shared Findings Schema

All skills in this pack emit findings using this unified schema. This makes outputs aggregatable, comparable across audits, and exportable to ticketing or SIEM systems.

## Severity rubric

| Level | Use when |
|-------|----------|
| **Critical** | Unauthenticated RCE, mass data exfiltration vector, tenant breach, hardcoded production secret in public source, auth bypass with no MFA. Exploitable today, no special conditions. |
| **High** | Authenticated privilege escalation, IDOR exposing other tenants' data, SSRF reaching internal services, missing RLS on sensitive table, JWT validation bypass. Exploitable with low effort. |
| **Medium** | XSS requiring user interaction, CSRF on state-changing endpoints, weak rate limiting, missing audit log on sensitive action, outdated dep with known CVE but no public exploit, permissive CORS. |
| **Low** | Missing security header that has compensating control, verbose error message, unpinned non-critical action, expired/unused IAM credential, hygiene issue. |
| **Info** | Best-practice deviation with no direct exploitability, observability gap, recommendation for hardening. |

If a finding spans multiple severities depending on configuration, document each scenario.

## Finding template

Use exactly this Markdown structure for each finding. Skills produce a report file with N findings concatenated.

```markdown
### [SEV] Short finding title

- **ID**: `<skill-prefix>-<NNN>` (e.g., `SUPA-001`, `GHSC-014`)
- **Severity**: Critical | High | Medium | Low | Info
- **Category**: <domain tag, e.g., RLS, OIDC, CORS, IDOR>
- **CWE**: CWE-XXX (when applicable)
- **Affected**: `<file:line>` or `<resource identifier>`
- **Evidence**:
  ```
  <minimal code/config snippet, query result, or log excerpt
  that demonstrates the issue — never include real secrets>
  ```
- **Why it matters**: 1-3 sentences explaining the concrete risk in this context. Avoid generic CWE definitions; tie to the affected resource.
- **Remediation**:
  ```
  <copy-pasteable fix: code patch, SQL, config snippet, or
  step-by-step if structural>
  ```
- **Verification**: How to confirm the fix worked (a query, a curl, a unit test).
- **References**: Links to vendor docs, CWE, OWASP, RFC.
```

## Report header

Every skill produces a report that starts with this header:

```markdown
# <Skill Name> — Audit Report

- **Target**: <repo/project/resource>
- **Scope**: <what was reviewed, what was excluded>
- **Date**: YYYY-MM-DD
- **Auditor**: <skill name + version>

## Summary

| Severity | Count |
|----------|-------|
| Critical | N     |
| High     | N     |
| Medium   | N     |
| Low      | N     |
| Info     | N     |

## Findings
```

## Skill ID prefixes

| Skill | Prefix |
|-------|--------|
| github-supply-chain | GHSC |
| github-repo-hardening | GHRH |
| saas-code-security-review | SCSR |
| supabase-security-audit | SUPA |
| saas-tenant-isolation | STI  |
| saas-api-security | SAPI |
| saas-frontend-hardening | SFH  |
| iac-container-security | IACS |
| saas-compliance-audit | SCMP |

Use sequential numbers within a single report (001, 002, ...). Do not try to allocate globally unique IDs across reports.

## Triage advice

When a report contains both Critical and High findings, the Critical block must be remediable independently — never block a Critical fix on a structural High that takes weeks. If a Critical finding depends on a structural change, split it into (a) immediate mitigation (e.g., disable the endpoint, rotate the secret) and (b) the structural fix as a separate High.
