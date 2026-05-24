# CODEOWNERS Review Reference

Load this when reviewing or designing a CODEOWNERS file.

## What CODEOWNERS does (and doesn't)

`CODEOWNERS` maps path patterns to GitHub users or teams. When combined with the branch protection rule "Require review from Code Owners", a PR touching a path requires approval from at least one of that path's owners.

It does **not**:
- Restrict who can push (push restrictions are a separate setting).
- Enforce ownership outside PR reviews (e.g., direct admin pushes bypass it if admin bypass is on).
- Validate that owners are still active. A team that no longer exists silently fails to require review.

## File location precedence

GitHub looks for CODEOWNERS in this order, first match wins:
1. `.github/CODEOWNERS`
2. `CODEOWNERS` (repo root)
3. `docs/CODEOWNERS`

Pick one location and stick with it across the org. `.github/CODEOWNERS` is the most common.

## Syntax essentials

```
# Comments start with #
# Pattern         Owner1 Owner2 ...
*                 @yourorg/all-engineers
*.js              @yourorg/frontend-team
/.github/         @yourorg/devops @yourorg/security
/infra/           @yourorg/sre
/migrations/      @yourorg/dba @yourorg/security
/billing/         @yourorg/billing-team @specific-person
docs/             @yourorg/docs-team
```

Rules:
- **Last matching pattern wins** (unlike `.gitignore`). Put broad patterns at the top, specifics at the bottom.
- Patterns follow gitignore-like glob syntax, but **directory matching requires a trailing slash** for directory semantics.
- Owners can be users (`@username`), teams (`@org/team`), or email addresses (less common, must be a verified GitHub email).
- Team must have **write access to the repo** to be a valid owner — otherwise the pattern is silently ignored.

## Validation

GitHub exposes a CODEOWNERS error endpoint:

```bash
gh api "repos/$OWNER/$REPO/codeowners/errors" --jq '.errors[] | {line, kind, source, message}'
```

Errors include: unknown user, team without write access, malformed pattern. Run this in CI on PRs touching CODEOWNERS.

## Sensitive-path checklist

Audit that CODEOWNERS covers at least:

| Path pattern | Reason |
|--------------|--------|
| `/.github/` | Workflow changes can exfiltrate secrets — needs security review |
| `/.github/workflows/` | Same as above, often called out separately |
| `Dockerfile`, `Dockerfile.*` | Image changes affect runtime security |
| `docker-compose*.yml` | Same |
| `/infra/`, `/terraform/`, `*.tf`, `*.tfvars` | Cloud config changes |
| `/k8s/`, `/kubernetes/`, `*.yaml` in deploy dirs | K8s manifests |
| `/migrations/`, `/db/migrate/` | Schema changes affect RLS/grants |
| `/auth/`, `/security/`, `/permissions/` | Auth/authorization code |
| `*.env.example`, `.env.template` | Config templates |
| `package.json`, `package-lock.json`, `requirements.txt`, `go.mod`, etc. | Dependency updates |
| `CODEOWNERS` itself | Changes to CODEOWNERS need review |
| `/.github/CODEOWNERS` | Same |

Patterns that look like CI/security but aren't covered → finding.

## Common mistakes

### Mistake 1 — Individual owners on critical paths

```
# Bad: critical path owned by one person; they go on vacation, PRs block
/auth/   @alice
```

Fix: own with a team, even if it's a team of one. Teams handle turnover.

```
/auth/   @yourorg/auth-team
```

### Mistake 2 — Catch-all defeats specifics

```
# Bad: with "last match wins", the catch-all isn't a problem here, but:
/security/   @yourorg/security
*            @yourorg/engineers
# This makes /security/ owned by @yourorg/engineers (last match wins)
```

Fix: specifics go AFTER the catch-all.

```
*                @yourorg/engineers
/security/       @yourorg/security
```

### Mistake 3 — Owning the entire repo with one team

```
*    @yourorg/security
```

If `@yourorg/security` owns everything, they get pinged on every PR, including typos in README. They'll start auto-approving or muting notifications. Pick a sensible default (the team most active in the codebase) and reserve security ownership for security-sensitive paths.

### Mistake 4 — Bot accounts as owners

A bot account that auto-approves defeats the purpose. Owners should be humans (or teams of humans). If automation needs to "approve" PRs (e.g., Dependabot auto-merge), use the merge-queue + required-status-check pattern, not CODEOWNERS.

### Mistake 5 — `**` for "everywhere"

```
**/Dockerfile   @yourorg/devops
```

This works but is verbose. Better:

```
Dockerfile      @yourorg/devops
**/Dockerfile   @yourorg/devops    # if there are nested ones
```

For paths-anywhere-in-tree, `**` is correct.

### Mistake 6 — Stale teams

A team that was renamed or deleted leaves a dangling reference. Run the errors API check (above) and treat any output as a finding.

## Required Code Owner review interaction with other settings

For CODEOWNERS to actually require review, the branch protection rule must have **"Require review from Code Owners"** enabled. Without it, CODEOWNERS only ping owners as reviewers (notification), not require approval.

Audit:
1. Does CODEOWNERS exist?
2. Does the branch protection rule have "Require review from Code Owners" enabled?
3. Does `gh api .../codeowners/errors` return empty?

All three must be true for CODEOWNERS to function as a control.

## Multi-team review

When a PR touches paths owned by multiple teams, at least one approval per team is required. This can slow PRs in a monorepo with many cross-cutting teams. Mitigations:

- Group related paths under the broadest sensible team (don't make every micro-path a separate ownership).
- Use the merge queue to batch reviews efficiently.
- For docs and trivial changes, exclude paths from review requirements with a separate ruleset, or use `documentation`-style labels with required-status checks instead of human reviews.

## Verification snippet

After updating CODEOWNERS:

```bash
# 1. No errors
gh api "repos/$OWNER/$REPO/codeowners/errors" --jq '.errors | length'   # → 0

# 2. List owners for a specific path
# (requires a recent gh; uses the `codeowners` subcommand if available)
git ls-files /infra/ | head -5 | xargs -I {} gh api \
  "repos/$OWNER/$REPO/contents/{}" --jq '.path' | xargs -I {} \
  gh api "repos/$OWNER/$REPO/codeowners?path={}"
```
