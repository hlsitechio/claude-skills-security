# Secret Scanning and Push Protection Reference

Load this when reviewing GitHub secret scanning, push protection, or when designing custom patterns.

## What each control does

| Control | What it does | When it runs |
|---------|--------------|--------------|
| **Secret scanning** | Scans the repo for known secret patterns | On commit to any branch + nightly full-history scan |
| **Push protection** | Blocks the `git push` if it contains a known secret pattern | At push time, pre-acceptance |
| **Non-provider patterns** | Generic high-entropy / token-like strings | Same as above, but more false positives |
| **Custom patterns** | Org-defined regex + validation rule | Same as above, scoped to where you configure them |
| **Validity checks** | Calls the provider to test if the secret is currently active | After detection, periodically |

Push protection is the highest-leverage control: it prevents the secret from ever landing in Git history, which avoids the painful rewrite-history dance.

## Enabling on a repo

```bash
gh api -X PATCH "repos/$OWNER/$REPO" -f \
  'security_and_analysis[secret_scanning][status]=enabled' -f \
  'security_and_analysis[secret_scanning_push_protection][status]=enabled' -f \
  'security_and_analysis[secret_scanning_non_provider_patterns][status]=enabled' -f \
  'security_and_analysis[secret_scanning_validity_checks][status]=enabled'
```

For org-wide rollout, set defaults at the org level so new repos inherit.

## Custom patterns — what's worth defining

GitHub maintains hundreds of provider patterns (AWS, Stripe, Slack, etc.). Custom patterns add value for:

1. **Internal API keys** — your own service tokens with a recognizable prefix.
2. **Internal database connection strings** — corporate DB hostname pattern.
3. **Internal hostnames in URLs** — leaked internal endpoints in source.
4. **Legacy formats** that aren't covered by GitHub's catalog.

### Designing a custom pattern

```yaml
# Conceptual example
name: "Internal API Token"
secret_format: "^itk_[A-Za-z0-9]{40}$"
before_secret: ""
after_secret: ""
push_protection: true

# Optional validator — GitHub calls this URL with the candidate secret;
# if it returns 200, the secret is treated as valid and active.
validator:
  url: "https://internal-auth.yourorg.com/api/v1/validate-token"
  method: POST
  headers:
    Content-Type: application/json
  body: '{"token": "{{secret}}"}'
```

Two design rules:

- **Prefix-anchored**: secrets should have a fixed prefix (`itk_`, `cb_`, `methora_`). Random base64 without prefix has too many false positives to scan reliably.
- **Length-constrained**: anchor the length precisely so the regex doesn't match random text.

If you don't yet have prefixes, this is a great time to add them — even if it means a rotation. They make incident response, log scrubbing, and key revocation orders of magnitude easier.

## Push protection bypass workflow

When a developer pushes a commit containing a detected secret, push protection blocks the push and offers two paths:

1. **Remove the secret** (preferred): amend the commit, rotate the key, force-push the cleaned version.
2. **Bypass with justification**: developer selects one of "false positive", "used in tests", "will fix later". The bypass is logged.

The audit checks:
- Is bypass enabled for "will fix later"? (Strongly recommend disabling — defeats the purpose.)
- How many bypasses in the last 90 days? Each one is a finding to review.
- Are bypasses linked to actual remediation tickets?

```bash
# List bypass requests / events
gh api "repos/$OWNER/$REPO/secret-scanning/push-protection-bypasses" \
  --jq '.[] | {created_at, reason, requester, secret_type}'
```

## Existing alerts triage

When secret scanning finds historical leaks, each alert is a finding. Triage by:

1. **Severity** = how dangerous the secret is in this context (production API key → Critical, dev token → Medium).
2. **Validity** = if validity check confirms it's still active, escalate.
3. **Public exposure** = if the repo is or was ever public, escalate to Critical regardless.

Workflow per alert:
1. Rotate the secret at the provider.
2. Revoke the leaked one.
3. Search logs for any use of the leaked key (was it actually used?).
4. Close the alert with a remediation note.
5. Add the leaked key's pattern to push protection if it wasn't covered (so it can't happen again).

```bash
# List active alerts
gh api "repos/$OWNER/$REPO/secret-scanning/alerts?state=open" \
  --jq '.[] | {number, secret_type_display_name, validity, html_url}'
```

## .gitignore and dotenv discipline

Push protection catches *known patterns* but won't catch ad-hoc secrets pasted into a config file. Complementary controls:

- `.env`, `.env.local`, `*.pem`, `*.key`, `*.p12`, `id_rsa*` in `.gitignore`.
- `pre-commit` hook with [`detect-secrets`](https://github.com/Yelp/detect-secrets) or [`gitleaks`](https://github.com/gitleaks/gitleaks).
- Developers use a secret manager (1Password, doppler, vault) for local development; never `.env` files outside `.env.example`.

The audit checks `.gitignore` for the entries above and recommends a `pre-commit` config if missing.

## When something does leak

The right sequence after a confirmed leak:

1. **Rotate first**, scrub second. Removing a secret from history doesn't help if it was already cloned and scraped by bots — assume it's compromised the moment it touches a public mirror.
2. **Use `git filter-repo` or BFG** to remove the secret from history.
3. **Force-push the cleaned history**, then ask all collaborators to re-clone.
4. **Open an incident retrospective**: how did push protection miss it? Add the pattern.

The audit recommends but never executes destructive history rewrites without explicit authorization.
