# Branch Protection and Rulesets Reference

Load this when reviewing branch protection settings or when the user asks about main-branch safety.

## Rulesets vs legacy branch protection

GitHub has two overlapping systems for branch governance:

| Feature | Legacy branch protection | Rulesets (newer) |
|---------|-------------------------|-------------------|
| Scope | Per-branch pattern, per-repo | Per-repo OR org-wide |
| Layering | One rule per pattern | Multiple rulesets stack |
| Visibility into bypass | Limited | Bypass list with logged events |
| Required workflows | Not supported | Supported (require specific workflows pass) |
| Tag protection | Limited | Full |

Both can be active simultaneously. Rulesets are the modern path; if you're starting fresh, use rulesets. If both exist, audit both.

## Recommended baseline for `main` on a production repo

```yaml
# Conceptual; expressed via API or UI.
target: branch
pattern: main

# Block destructive operations
allow_deletions: false
allow_force_pushes: false
require_linear_history: true   # squash or rebase only; no merge commits

# Review requirements
required_pull_request_reviews:
  required_approving_review_count: 2          # 1 minimum, 2 for prod-critical
  dismiss_stale_reviews_on_new_commits: true
  require_code_owner_reviews: true            # CODEOWNERS must be in CO file
  require_last_push_approval: true            # final pusher cannot self-approve

# Status checks
required_status_checks:
  strict: true                                 # branch must be up-to-date with base
  contexts:
    - "test"
    - "lint"
    - "codeql"
    - "dependency-review"

# Restrict who can push (must be in this list AND pass PR review)
restrictions:
  users: []
  teams: ["release-managers"]
  apps: []

# Block bypass
enforce_admins: true                           # admins must follow rules too

# Signed commits
required_signatures: true
```

## Detection workflow

For each branch under protection-worthy patterns (`main`, `master`, `release/*`, `production`, `prod`), fetch the protection state:

```bash
gh api "repos/$OWNER/$REPO/branches/$BRANCH/protection" 2>/dev/null
```

If the call 404s, that branch has no legacy protection. Then check rulesets:

```bash
gh api "repos/$OWNER/$REPO/rulesets" --jq '.[] | select(.target == "branch") | .id' \
  | while read rid; do
      gh api "repos/$OWNER/$REPO/rulesets/$rid"
    done
```

Cross-reference: does at least one ruleset apply to `main`? If no protection from either system, finding is at least High.

## Common failure modes

### Mode 1: "Protected" but bypassable

`enforce_admins: false` lets admins push directly to main, defeating reviews. Unless your team has a documented break-glass procedure with logging, this should be `true`.

### Mode 2: Required reviews but stale-review not dismissed

Reviewer approves at commit A. Author pushes commits B, C, D. If `dismiss_stale_reviews_on_new_commits` is false, the original A approval still counts and B/C/D are never reviewed.

### Mode 3: CODEOWNERS review required but file missing

The setting "require review from Code Owners" silently does nothing if CODEOWNERS doesn't exist or doesn't match the changed paths. Always cross-check.

### Mode 4: Status checks listed but not enforced strictly

If `strict: false`, the branch can merge with a passing status check from an older base — merge can introduce broken state. Recommend `strict: true` for production branches.

### Mode 5: Required status check name drift

A required check named `test` doesn't run if your workflow's job is now named `unit-tests`. The required check sits in "pending" forever, blocking every PR. Audits should confirm every required check name corresponds to a job that actually runs.

### Mode 6: Release branches unprotected

Teams often protect `main` and forget that `release/*` and `hotfix/*` deploy to production too. Apply equivalent protection.

### Mode 7: Linear history conflict with merge queue

Merge queue produces merge commits in some configurations. If you require linear history AND use merge queue, configure the queue for squash merges.

## Applying via Terraform (illustrative)

```hcl
resource "github_repository_ruleset" "main_protection" {
  name        = "main protection"
  repository  = "your-repo"
  target      = "branch"
  enforcement = "active"

  conditions {
    ref_name {
      include = ["~DEFAULT_BRANCH"]
      exclude = []
    }
  }

  rules {
    deletion = true
    non_fast_forward = true   # blocks force push
    required_linear_history = true
    required_signatures = true

    pull_request {
      required_approving_review_count   = 2
      dismiss_stale_reviews_on_push     = true
      require_code_owner_review         = true
      require_last_push_approval        = true
    }

    required_status_checks {
      strict_required_status_checks_policy = true
      required_check { context = "test" }
      required_check { context = "codeql" }
      required_check { context = "dependency-review" }
    }
  }

  bypass_actors {
    # Empty list = no one bypasses, even admins.
    # If you need a break-glass, list the team here and review logs regularly.
  }
}
```

## Verifying a fix

After applying changes, verify with:
```bash
gh api "repos/$OWNER/$REPO/branches/main/protection" --jq '{
  force_push: .allow_force_pushes.enabled,
  deletion: .allow_deletions.enabled,
  reviews: .required_pull_request_reviews.required_approving_review_count,
  enforce_admins: .enforce_admins.enabled,
  signed: .required_signatures.enabled
}'
```

All values should match the intent in the baseline above.
