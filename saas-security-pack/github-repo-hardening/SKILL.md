---
name: github-repo-hardening
description: Audit GitHub repository governance and access control settings including branch protection rules, ruleset configuration, secret scanning, push protection, CODEOWNERS, signed commits, required reviews, and admin bypass policies. Use this skill whenever the user asks about branch protection, "is my main branch safe", required reviews, force-push prevention, CODEOWNERS, signed commits, gitsign, Sigstore, secret scanning, push protection, custom secret patterns, repo settings, ruleset vs branch protection, or merge queue. Trigger on phrases like "harden my repo", "audit my branch rules", "secret scanning", "CODEOWNERS review", "are my settings safe", "lock down main". Use this even when the user only mentions one of these sub-topics.
---

# GitHub Repository Hardening

Audit the governance surface of a GitHub repository: who can push what, who reviews, what secrets are scanned, and what bypasses exist. Distinct from `github-supply-chain` (which covers Actions and dependencies); this skill covers repo settings and human workflow controls.

## When this skill applies

- Reviewing branch protection rules or rulesets on the default branch and any release branches
- Confirming CODEOWNERS coverage matches sensitive paths
- Checking secret scanning and push protection are enabled with appropriate patterns
- Reviewing signed-commit enforcement and the underlying signing setup
- Identifying admin bypass paths that defeat the controls above

Use a different skill for Actions/workflow security (`github-supply-chain`), code-level bugs (`saas-code-security-review`).

## Workflow

Follow `../_shared/audit-workflow.md`. Skill-specific notes below.

### Phase 1: Scope confirmation

- Single repo, set of repos, or org?
- Does the org have GitHub Advanced Security?
- Is the org on Enterprise Cloud or Server?
- Is the user a repo admin or org admin? (affects which API calls work)

### Phase 2: Inventory

Use the `gh` CLI for everything below (read-only):

```bash
# Repo basics
gh repo view <owner/repo> --json defaultBranchRef,isPrivate,visibility,squashMergeAllowed,mergeCommitAllowed,rebaseMergeAllowed,deleteBranchOnMerge,hasIssuesEnabled,hasWikiEnabled

# Branch protection (legacy API; some orgs use Rulesets instead)
gh api "repos/<owner/repo>/branches/<default>/protection" 2>/dev/null || echo "No legacy branch protection"

# Rulesets (newer API; takes precedence in many setups)
gh api "repos/<owner/repo>/rulesets" --jq '.[] | {id, name, enforcement, target}'

# CODEOWNERS file
gh api "repos/<owner/repo>/contents/.github/CODEOWNERS" --jq .content 2>/dev/null \
  | base64 -d 2>/dev/null \
  || echo "No CODEOWNERS file at .github/CODEOWNERS"
# also check /CODEOWNERS and docs/CODEOWNERS

# Secret scanning + push protection status
gh api "repos/<owner/repo>" \
  --jq '.security_and_analysis | {secret_scanning, secret_scanning_push_protection, secret_scanning_non_provider_patterns}'

# Webhooks
gh api "repos/<owner/repo>/hooks" --jq '.[] | {id, config: {url, content_type, insecure_ssl}, events, active}'

# Deploy keys
gh api "repos/<owner/repo>/keys"

# Collaborators (outside of org teams)
gh api "repos/<owner/repo>/collaborators"
```

### Phase 3: Detection — the checks

#### Branch protection / rulesets — see `references/branch-protection.md`

- **GHRH-BP-1** Default branch has either branch protection rule OR an active ruleset targeting it. Both fine; neither is a Critical finding.
- **GHRH-BP-2** Force pushes blocked.
- **GHRH-BP-3** Deletion blocked.
- **GHRH-BP-4** Required reviews ≥ 1 (≥ 2 for production-critical repos).
- **GHRH-BP-5** "Dismiss stale reviews on new commits" enabled.
- **GHRH-BP-6** "Require review from Code Owners" enabled when CODEOWNERS exists.
- **GHRH-BP-7** Required status checks listed and "Require branches to be up to date" enabled.
- **GHRH-BP-8** "Restrict who can push" set; admin bypass disabled OR explicitly justified.
- **GHRH-BP-9** Linear history required (no merge commits) if the project policy is squash/rebase-only.
- **GHRH-BP-10** Release branches (`release/*`, `hotfix/*`) covered by equivalent protection.

#### CODEOWNERS — see `references/codeowners-review.md`

- **GHRH-CO-1** CODEOWNERS file exists in one of the canonical locations.
- **GHRH-CO-2** File parses without errors (`gh api repos/.../codeowners/errors`).
- **GHRH-CO-3** Sensitive paths covered: `.github/`, `Dockerfile*`, `terraform/`, `infra/`, `migrations/`, anything touching auth/billing/secrets.
- **GHRH-CO-4** Owners are teams (`@yourorg/team`) not individuals where possible — handles turnover.
- **GHRH-CO-5** No catch-all `*` owned by a single individual or an `@everyone` group that defeats reviewer requirements.

#### Secret scanning — see `references/secret-scanning.md`

- **GHRH-SS-1** Secret scanning enabled (free on public, GHAS-licensed on private).
- **GHRH-SS-2** Push protection enabled — blocks commits containing known secret patterns at `git push`.
- **GHRH-SS-3** Non-provider patterns enabled (catches generic high-entropy strings).
- **GHRH-SS-4** Custom patterns defined for org-specific secrets (internal token formats, API key prefixes).
- **GHRH-SS-5** Push protection bypass requires justification; bypass events reviewed regularly.
- **GHRH-SS-6** Validity checks enabled where supported (calls provider to confirm whether the secret is active).

#### Signed commits

- **GHRH-SC-1** Default branch requires signed commits.
- **GHRH-SC-2** Team has functional signing setup: GPG, SSH signing, or Sigstore keyless (gitsign).
- **GHRH-SC-3** Commit signatures verified by GitHub (green "Verified" badge) — not just signed locally with unimported key.
- **GHRH-SC-4** Bot commits (Dependabot, Renovate) included in the signing requirement (they sign by default).

#### Webhook security

- **GHRH-WH-1** Every active webhook uses HTTPS, never HTTP.
- **GHRH-WH-2** Webhook secret set (used to HMAC-sign payloads).
- **GHRH-WH-3** `insecure_ssl` not set to "1" (skips cert validation).
- **GHRH-WH-4** Webhook URL points to a legitimate endpoint, not a stale/external service.

#### Access surface

- **GHRH-AC-1** No outside collaborators on private repos unless justified.
- **GHRH-AC-2** Deploy keys reviewed; each one tied to a known integration.
- **GHRH-AC-3** No personal access tokens (PATs) used where a GitHub App or fine-grained PAT could replace them.
- **GHRH-AC-4** SSO required for the org; SAML enforced on commits where applicable.

#### Merge hygiene

- **GHRH-MH-1** "Automatically delete head branches" enabled (housekeeping, also limits stale-PR ambiguity).
- **GHRH-MH-2** "Allow merge commits" disabled if policy is squash/rebase only.
- **GHRH-MH-3** Merge queue configured for high-churn default branches.

### Phase 4: Triage

Critical class examples:
- Default branch has no protection at all on a production repo
- Admin bypass enabled and admins push directly to main without review
- Webhook leaking secrets to an HTTP endpoint
- Push protection disabled while secret scanning shows active leaked secret alerts

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `GHRH-`.

## Outputs

1. Markdown audit report
2. (Optional) Terraform / `gh` script to apply recommended settings
3. (Optional) CODEOWNERS draft

## References

- `references/branch-protection.md` — Rulesets vs legacy protection, recommended config matrix
- `references/codeowners-review.md` — CODEOWNERS syntax, common mistakes, sensitive-path checklist
- `references/secret-scanning.md` — Provider patterns, custom patterns, push protection workflow

## Scripts

- `scripts/audit_repo_settings.sh` — Wraps the `gh api` calls and produces a one-page inventory
- `scripts/apply_baseline.sh` — Idempotent script that applies a recommended baseline (read it before running)
