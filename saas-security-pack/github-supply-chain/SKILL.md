---
name: github-supply-chain
description: Audit GitHub repository supply chain security including GitHub Actions workflow hardening, third-party action pinning, dependency review, SBOM generation, and OIDC-based cloud authentication. Use this skill whenever the user asks about GitHub Actions security, workflow permissions, action pinning, Dependabot, Renovate, supply chain attacks, dependency confusion, typosquatting, SBOM (CycloneDX/SPDX), OIDC federation with AWS/GCP/Azure, or any concern about external code entering their CI/CD pipeline. Trigger on phrases like "audit my GitHub Actions", "are my workflows safe", "supply chain risk", "should I pin actions", "OIDC for cloud", "SBOM generation", "dependency review", and similar. Use this even if the user only mentions one sub-topic — coverage is broader than the trigger.
---

# GitHub Supply Chain Audit

Audit the external code and identity surface that GitHub Actions exposes: third-party actions, dependencies, build outputs, and the credentials workflows use to reach cloud providers. This is a defensive (find & fix) skill — find weaknesses and produce a remediation report.

## When this skill applies

- Reviewing `.github/workflows/*.yml` for hardening gaps
- Evaluating dependency hygiene (Dependabot config, Renovate, lockfiles, audit policies)
- Checking SBOM presence and quality
- Auditing how workflows authenticate to AWS/GCP/Azure (long-lived keys vs OIDC)
- Triage after a public Actions compromise (e.g., tj-actions/changed-files class of incidents)

Use a different skill for: repository governance like branch protection (see `github-repo-hardening`), application-code vulnerabilities (see `saas-code-security-review`).

## Workflow

Follow the 5-phase audit workflow defined in `../_shared/audit-workflow.md`. Skill-specific guidance below.

### Phase 1: Scope confirmation

Ask the user (or confirm from context):
- Single repo or org-wide?
- Public, internal, or private repo?
- Has GitHub Advanced Security (GHAS) license? (affects which features are available)
- Are workflows reaching cloud providers? Which?

### Phase 2: Inventory

Collect:
```bash
# List all workflow files
find .github/workflows -name '*.yml' -o -name '*.yaml'

# Extract every external action reference
grep -rEho 'uses:\s*[^@\s]+@[^\s]+' .github/workflows/ | sort -u

# List dependency manifests
find . -name 'package.json' -o -name 'package-lock.json' -o -name 'pnpm-lock.yaml' \
       -o -name 'requirements*.txt' -o -name 'Pipfile.lock' -o -name 'poetry.lock' \
       -o -name 'go.mod' -o -name 'go.sum' -o -name 'Gemfile.lock' -o -name 'Cargo.lock' \
       -o -name 'pom.xml' -o -name 'build.gradle*' | grep -v node_modules
```

Also check:
- `.github/dependabot.yml` presence and ecosystems covered
- `renovate.json` / `renovate.json5` if Renovate is used instead
- `.github/workflows/codeql.yml` for code scanning
- Repository settings for "Dependency graph" and "Dependabot alerts" (via API or `gh api`)

### Phase 3: Detection — the checks

Apply every check below. Reference the linked file when the check is non-trivial.

#### Action pinning and provenance — see `references/actions-hardening.md`

- **GHSC-PIN-1** Every third-party action pinned by full commit SHA, not by tag or branch. Tags are mutable.
- **GHSC-PIN-2** First-party `actions/*` may be pinned by major version (`@v4`) since GitHub owns them, but SHA is still preferred for high-security contexts.
- **GHSC-PIN-3** Comment next to each pin showing the human-readable version: `uses: foo/bar@<sha>  # v1.2.3`. Without it, future updates are blind.
- **GHSC-PIN-4** No use of `@main`, `@master`, `@latest`, or floating tags anywhere.

#### Workflow permissions — see `references/actions-hardening.md`

- **GHSC-PERM-1** `permissions: {}` declared at the workflow OR job level. Defaulting to `permissive` grants `GITHUB_TOKEN` write access to most scopes.
- **GHSC-PERM-2** When write permissions are needed, scoped narrowly (e.g., `contents: read, pull-requests: write`) not `write-all`.
- **GHSC-PERM-3** `pull_request_target` triggers reviewed carefully — they run with secrets and write tokens against PRs from forks. Cross-reference with any checkout of PR head SHA.

#### Secrets handling

- **GHSC-SEC-1** No secrets in plaintext in workflow files, even masked.
- **GHSC-SEC-2** Secrets not passed to third-party actions unless that action's source is reviewed and pinned.
- **GHSC-SEC-3** Environment secrets used for production (with required reviewers) rather than repo-level secrets.
- **GHSC-SEC-4** No `echo "$SECRET"` patterns — GitHub masks known secrets in logs but transformations (base64, JSON-wrap) break the mask.

#### Dependency hygiene — see `references/dependency-review.md`

- **GHSC-DEP-1** Dependabot or Renovate configured for every ecosystem present.
- **GHSC-DEP-2** Lockfile present for every package manager that supports one (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`, `Pipfile.lock`, `go.sum`, `Cargo.lock`).
- **GHSC-DEP-3** `dependency-review-action` runs on every PR to flag new vulnerable deps before merge.
- **GHSC-DEP-4** Internal packages scoped (`@yourorg/`) on a private registry, with namespace held on the public registry to prevent dependency confusion.
- **GHSC-DEP-5** Install commands use `--ignore-scripts` where feasible, OR malicious-package detection runs before install (Socket, Snyk, etc.).

#### SBOM and provenance — see `references/sbom-generation.md`

- **GHSC-SBOM-1** SBOM generated for every release artifact (CycloneDX or SPDX format).
- **GHSC-SBOM-2** SBOM stored as a release asset or in a queryable store, not just printed to logs.
- **GHSC-SBOM-3** For container images, SBOM attached as an OCI attestation (Cosign + Sigstore).
- **GHSC-SBOM-4** Build provenance (SLSA L2+) attested for production artifacts.

#### OIDC and cloud authentication — see `references/oidc-cloud-auth.md`

- **GHSC-OIDC-1** Long-lived cloud credentials (AWS access keys, GCP service account keys, Azure SP secrets) replaced by OIDC federation.
- **GHSC-OIDC-2** OIDC trust policy scoped to specific `repo`, `ref`, and `environment` claims — not just the org.
- **GHSC-OIDC-3** Audience claim set explicitly (default `sts.amazonaws.com` for AWS) rather than allowing any.
- **GHSC-OIDC-4** Wildcards in `sub` claim limited (e.g., `repo:org/repo:ref:refs/heads/main` not `repo:org/*`).

#### Build environment

- **GHSC-ENV-1** Self-hosted runners isolated (ephemeral, single-job, not on persistent VMs with secrets).
- **GHSC-ENV-2** Self-hosted runners not enabled on public repos without isolation.
- **GHSC-ENV-3** Workflow `defaults` block does not silently shell out to `bash -e -o pipefail` with unvalidated inputs.

### Phase 4: Triage

Critical class examples for this skill:
- Third-party action with write token access pinned by mutable tag (one upstream takeover = full repo compromise)
- Long-lived AWS access key with admin policy in repo secrets
- `pull_request_target` checking out PR head SHA then running PR code with secrets

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `GHSC-`.

## Outputs

The skill produces:
1. A Markdown report at `audits/github-supply-chain/<repo>/<date>.md`
2. (Optional, on request) A hardened workflow template based on `assets/hardened-workflow.yml`
3. (Optional, on request) A migration plan from long-lived keys to OIDC

## References

- `references/actions-hardening.md` — Pinning, permissions, `pull_request_target` patterns
- `references/dependency-review.md` — Dependabot vs Renovate, dependency-review-action, lockfile policy
- `references/sbom-generation.md` — CycloneDX/SPDX, Cosign attestations, SLSA levels
- `references/oidc-cloud-auth.md` — Trust policy templates for AWS, GCP, Azure
- `assets/hardened-workflow.yml` — Production-grade workflow template

## Scripts

- `scripts/extract_action_pins.sh` — Pulls every `uses:` reference and flags non-SHA pins
- `scripts/check_lockfiles.sh` — Verifies presence of lockfile for each detected ecosystem
