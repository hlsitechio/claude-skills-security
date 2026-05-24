# Dependency Review Reference

Load this when checking dependency hygiene across ecosystems or when the user asks about Dependabot, Renovate, lockfiles, or dependency confusion.

## Lockfiles per ecosystem

A lockfile pins transitive dependency versions and their hashes. Without one, `install` resolves the latest matching range at every CI run — opening a window for malicious version drift.

| Manager | Lockfile | Notes |
|---------|----------|-------|
| npm | `package-lock.json` | Include `integrity` SHA-512 hashes |
| pnpm | `pnpm-lock.yaml` | Hashes for every resolved version |
| Yarn (classic) | `yarn.lock` | Deprecated for new projects; prefer Yarn Berry or pnpm |
| Yarn Berry | `yarn.lock` | With `enableHardenedMode: true` in `.yarnrc.yml` |
| Python (pip) | `requirements.txt` with hashes via `pip-compile --generate-hashes` | Plain `requirements.txt` without hashes is insufficient |
| Pipenv | `Pipfile.lock` | Has hashes by default |
| Poetry | `poetry.lock` | Has hashes by default |
| Go | `go.sum` | Mandatory since Go 1.16 |
| Cargo | `Cargo.lock` | Commit for binaries; libraries usually don't but it's debated |
| Bundler | `Gemfile.lock` | Mandatory in apps |
| Maven | `pom.xml` with explicit versions | Maven lacks a true lockfile; use `dependency:resolve-plugins` |
| Gradle | `gradle.lockfile` via `dependencyLocking { lockAllConfigurations() }` | Not on by default |
| Composer | `composer.lock` | Mandatory in apps |

Detection: any manifest without its lockfile committed → finding. Any lockfile present but `.gitignore`'d → finding.

## Dependabot vs Renovate

Both work. Pick one per repo to avoid PR noise.

### Dependabot — minimal config

`.github/dependabot.yml`:
```yaml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    groups:
      production-deps:
        dependency-type: "production"
        update-types: ["minor", "patch"]
      dev-deps:
        dependency-type: "development"
        update-types: ["minor", "patch"]

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

Notes:
- `github-actions` ecosystem must be listed separately to update SHA pins in workflows.
- Groups reduce PR noise. Major updates stay individual since they often need manual review.
- `open-pull-requests-limit` defaults to 5 — bump if your org wants more aggressive updating.

### Renovate — when to prefer

Prefer Renovate when:
- You need custom rules per dep (e.g., wait 7 days after publish before opening PR — mitigates malicious-publish windows)
- You manage many repos and want a shared config preset
- You want automerge for patch updates with passing CI

`renovate.json` baseline:
```json
{
  "extends": ["config:recommended", "schedule:weekly"],
  "minimumReleaseAge": "7 days",
  "packageRules": [
    {
      "matchUpdateTypes": ["patch"],
      "matchCurrentVersion": "!/^0/",
      "automerge": true
    }
  ],
  "vulnerabilityAlerts": {
    "enabled": true,
    "labels": ["security"]
  }
}
```

`minimumReleaseAge: 7 days` is one of Renovate's killer features for supply chain — most malicious-publish incidents are detected and yanked within days. Waiting catches them.

## `dependency-review-action`

This action runs on PRs and blocks merging when new dependencies have known vulnerabilities, incompatible licenses, or come from disallowed ecosystems. Requires GitHub Advanced Security on private repos; free on public.

```yaml
name: Dependency Review
on:
  pull_request:

permissions:
  contents: read

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>  # v4
      - uses: actions/dependency-review-action@<sha>  # v4
        with:
          fail-on-severity: high
          comment-summary-in-pr: always
          deny-licenses: AGPL-3.0, GPL-3.0  # adjust per your policy
```

## Dependency confusion

When an internal package and a public one share a name, package managers may resolve to the public one — letting an attacker who publishes a public package with the same name steal an install.

### Mitigations

1. **Scope all internal packages**. Use `@yourorg/internal-thing` (npm/yarn/pnpm) or equivalent (`yourorg.internal-thing` in Python via index priority).
2. **Hold the scope or name on the public registry**. Publish a placeholder at the same name to prevent squatting.
3. **Configure registries explicitly**. Never `--registry` from CLI flags only; commit `.npmrc` / `pip.conf` so resolution is deterministic.
4. **Use scope-to-registry mapping**:
   ```ini
   # .npmrc
   @yourorg:registry=https://npm.internal.yourorg.com/
   //npm.internal.yourorg.com/:_authToken=${INTERNAL_TOKEN}
   registry=https://registry.npmjs.org/
   ```
5. For Python, use `--index-url` (private) and `--extra-index-url` (public) carefully — order matters. Better: use `pip install --index-url <private>` only, and explicitly add public packages from the public mirror by hash.

### Detection

Audit:
- Every `package.json` or `pyproject.toml` for unscoped internal package names.
- Every CI config for `--registry`/`--index-url` flags that could be overridden.
- The public registry for collisions with internal package names.

## Install-time code execution

npm/pip both run lifecycle scripts at install (`postinstall`, `setup.py`). A malicious package can use these to exfiltrate secrets the moment `npm install` runs in CI.

### Mitigations

- **npm**: `npm ci --ignore-scripts` in CI. Only allowlist scripts via [`@lavamoat/allow-scripts`](https://github.com/LavaMoat/LavaMoat).
- **pnpm**: `pnpm install --ignore-scripts` plus configure `onlyBuiltDependencies` in `package.json`.
- **pip**: prefer wheels (no `setup.py` execution), use `pip install --only-binary :all:` where possible.
- Runtime detection: services like Socket, Snyk, or Phylum analyze packages pre-install for malicious patterns.

## Things to check in the report

Per ecosystem detected:
1. Lockfile present and committed
2. Update tooling (Dependabot or Renovate) configured
3. Lockfile contains integrity hashes
4. No unscoped internal-looking package names
5. CI uses install commands that disable lifecycle scripts (or has allowlist)
6. `dependency-review-action` runs on PRs
7. CodeQL or equivalent SAST runs on push and PR
