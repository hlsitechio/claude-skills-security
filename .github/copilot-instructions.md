# Copilot Instructions

These instructions ground GitHub Copilot (Coding Agent, Workspace, Chat) when working in this repository. Read this file in full before producing any code, review, or PR.

## What this repo is

A monorepo of **defensive security audit skills for Claude**, split into two packs:

- `saas-security-pack/` — 9 audit-domain skills (RLS, supply chain, tenant isolation, code review, API, frontend, IaC, compliance, GitHub repo hardening). Each emits findings with a 3-5 letter prefix (`SUPA-`, `GHSC-`, `STI-`, etc.).
- `appsec-stack-pack/` — 30 technology-stack skills (Next.js, Prisma, Clerk, Django, FastAPI, Go, Rails, Laravel, Spring Boot, .NET, GraphQL, tRPC, WebSocket, Redis, Vercel, Cloudflare Workers, AWS Lambda, …). Same finding-prefix model.

A typical real-world audit activates 5+ skills from both packs concurrently. Finding IDs must not collide across packs.

## PRIMARY review focus: version drift

**The single most important thing a scheduled review catches is version drift.**

These skills are security guidance. When upstream tech (Node, Next, Django, base images, GitHub Actions, scanners) ships a new release, the existing guidance can become silently insecure:

- Recommended runtime version goes past EOL → CVE feeds stop covering it.
- Framework changes default auth/cookie/cache behavior (Next 14 → 15, Django 4 → 5, React 18 → 19) → existing checks miss the new attack surface.
- Action SHAs in example workflows go stale → users copy outdated pins.
- Scanner tools (Trivy, Cosign, Checkov) change CLI flags → example commands fail.

**For every scheduled review:**

1. Load [`.github/tech-inventory.yml`](./tech-inventory.yml) (schema v3 — see field reference below).
2. For each entry, fetch the actual current state from `upstream.url` (see "Upstream lookups" below).
3. Compare against `current_pin` (what skills say) AND against `upstream_latest.version` (what the inventory THOUGHT was current at `upstream_latest.as_of`).
4. Two drift dimensions to report:
   - **Skill drift**: `current_pin` lags real upstream → propose file:line edits in the skills.
   - **Inventory drift**: `upstream_latest.version` (with `as_of` ≥ a few weeks old) no longer matches real upstream → propose updates to `upstream_latest.version`, `upstream_latest.as_of`, and `sources` (with fresh `accessed` dates).
5. Classify each result:
   - **CRITICAL** — pinned version is past EOL, or has known unpatched CVEs (CVSS ≥9.0).
   - **HIGH** — pinned version is ≥2 majors behind current, OR new major changed security-relevant defaults the skill doesn't cover.
   - **MEDIUM** — 1 major behind, or behind on a CVE-backport patch.
   - **LOW** — behind on patch only, no known CVE.
   - **INFO** — matches upstream / no change.
6. For each non-INFO finding, propose the specific edit: `file:line — old → new — rationale`.
7. **Always update `last_verified` and `upstream_latest.as_of`** to today's ISO date in the inventory entries you checked, and refresh each `source` entry's `accessed` date.
8. **Add new sources** when the original 404s or returns a soft error — link rot is treated as a finding, not silently tolerated.

**Inventory schema v3 field reference:**

```yaml
- id: <kebab>
  kind: runtime|base_image|action|framework|library|tool|protocol
  upstream:                              # how to look up latest
    type: github_releases|npm|pypi|docker_hub|official_endpoint
    url: <upstream URL>
    track: lts|latest|stable
  pinned_in:                             # files in this repo that mention this tech
    - <relative file path>
  current_pin: <string>                  # what the skill content actually says
  upstream_latest:                       # what's actually current upstream
    version: <string>
    as_of: <ISO date>                    # MUST be refreshed when inventory is reviewed
  drift_severity: critical|high|medium|low  # omit if matches upstream
  drift_risk: |                          # prose: why drift matters
    ...
  sources:                               # citations — every claim must be verifiable
    - url: <URL>
      title: <human title>
      accessed: <ISO date>               # MUST be refreshed when source is re-verified
  last_verified: <ISO date>              # MUST be refreshed at end of every review
```

Every entry MUST have `upstream_latest`, `sources` (non-empty), and `last_verified`. The validator in `.github/workflows/validate-all.yml` will refuse PRs that add an entry missing these fields.

**Upstream lookups (preferred, in order):**

| Source type | How to fetch latest |
|-------------|----------------------|
| `github_releases` | `gh api repos/<owner>/<repo>/releases/latest --jq .tag_name` |
| `npm` | `npm view <pkg> dist-tags.latest` |
| `pypi` | `curl -s https://pypi.org/pypi/<pkg>/json \| jq -r .info.version` |
| `docker_hub` | `curl -s 'https://hub.docker.com/v2/repositories/library/<image>/tags?page_size=20' \| jq -r '.results[].name'` |
| `official_endpoint` | Per the `url` in the inventory entry (Node uses `nodejs.org/dist/index.json`) |

**CVE corroboration:**

For each runtime/framework/library found behind, also check:
- `gh api graphql -f query='{ securityVulnerabilities(...) }'` for GHSA advisories.
- The NVD JSON feed for the version specifically pinned.

A version "1 patch behind" without a CVE is LOW; "1 patch behind" with a CVE that the patch fixes is HIGH.

**Inventory gaps:**

If a skill references a tech version that is not in `tech-inventory.yml`, propose adding it. New inventory entries are part of the review output, not a separate PR.

## SECONDARY review focus: depth backlog

[`docs/ENHANCEMENT_PLAN.md`](../docs/ENHANCEMENT_PLAN.md) is the per-skill depth backlog from a multi-agent review (2026-05-23). After resolving inventory drift findings, draw from this document for "Wave 2" reference-file additions:

- Skills classified `thin` (no references) get 2–4 new reference files each — the plan specifies file name, ~line count, outline, sources.
- Skills classified `partial` (1–2 references) get 1–3 additional reference files to reach the bar.
- Skills classified `rich` already have 3+ references; surface only standard-drift updates from the plan.

When proposing depth additions, use the file outlines in the plan verbatim — they specify which sub-topic each new reference covers and which authoritative sources to cite. The Wave 1 / Wave 2 / Wave 3 / Wave 4 priority order is defined in the plan's "Execution priorities" section.

## Hard constraints

- **Defensive only.** Reject any change that adds offensive content: exploit code, weaponized payloads, bypass techniques presented as attack chains, automated pentest tooling. The audit framing is *find-and-fix*, not *exploit*.
- **Every check ships with a remediation.** A SKILL.md check that says "look for X" without "here's how to fix X" is incomplete.
- **No secrets, no real customer data** in any file. Examples must use placeholders (`yourorg`, `<sha>`, `xxxxx.example.com`).
- **No new dependencies on proprietary tooling** unless the tool is already standard (Trivy, Checkov, Semgrep, CodeQL, etc.).
- **Multi-stack by default.** Avoid making a skill single-language unless it inherently is (e.g., `prisma-orm-security` is TypeScript).

## SKILL.md format (every skill)

```
<skill-name>/
├── SKILL.md          # YAML frontmatter + 5-phase workflow body
├── references/       # optional deep-dive companion docs
│   └── *.md
├── scripts/          # optional executables (read-only audit helpers)
└── assets/           # optional templates the skill produces or uses
```

Required YAML frontmatter:

```yaml
---
name: <kebab-case, must match folder name>
description: <triggers — proper nouns, file signatures, common user phrasings; ~3-6 sentences>
---
```

Required SKILL.md body sections, in order:

1. Title + one-paragraph intent
2. **When this skill applies** — explicit in-scope / out-of-scope
3. **Workflow** — reference `../_shared/audit-workflow.md` + skill-specific notes per phase (1: Scope, 2: Inventory, 3: Detection, 4: Triage, 5: Report)
4. **Detection checks** — numbered with the skill's ID prefix (e.g., `SUPA-RLS-1`)
5. **Triage notes** — what counts as Critical for this skill
6. **Outputs** — what artifacts the skill produces
7. **References** — links to each `references/*.md`
8. **Scripts / Assets** — if present

## CI requirements

`.github/workflows/validate-all.yml` runs on every push/PR and validates:

- YAML frontmatter parses
- `name:` matches folder name
- Every `` `references/foo.md` `` mentioned in SKILL.md resolves to a real file
- `_shared/findings-schema.md` and `_shared/audit-workflow.md` present in each pack

Run locally before pushing:

```bash
python -c "
import os, re, yaml, sys
err=[]; n=0
for pack in ['saas-security-pack', 'appsec-stack-pack']:
    for root, dirs, files in os.walk(pack):
        if any(x in root for x in ('_shared','scripts','.github','dist')): continue
        if 'SKILL.md' not in files: continue
        n+=1
        p = os.path.join(root,'SKILL.md')
        with open(p, encoding='utf-8') as f: c=f.read()
        m=re.match(r'^---\n(.*?)\n---\n', c, re.DOTALL)
        if not m: err.append(f'{p}: no frontmatter'); continue
        meta=yaml.safe_load(m.group(1))
        if meta.get('name')!=os.path.basename(root): err.append(f'{p}: name mismatch')
        for rm in re.finditer(r'\`references/([^\`]+\.md)\`', c):
            if not os.path.isfile(os.path.join(root,'references',rm.group(1))):
                err.append(f'{p}: missing references/{rm.group(1)}')
print(f'{n} skills, {len(err)} errors')
for e in err: print(' -', e)
sys.exit(1 if err else 0)
"
```

Expected: `39 skills, 0 errors`. Any deviation blocks the PR.

## Finding ID prefix registry

Each pack maintains its prefix table in `<pack>/_shared/findings-schema.md`. When adding a new skill, propose a 3-5 char uppercase prefix and add it there. Do NOT reuse a prefix that exists in either pack.

## What a daily / weekly review should produce

Reviews open an issue using `.github/ISSUE_TEMPLATE/daily-skill-review.md`. The review must cover:

1. **CI health** — last run status, flakiness, drift in validator output.
2. **New skills or major changes** — quality of frontmatter triggers, reference completeness, finding IDs, defensive-only check.
3. **Cross-skill consistency** — overlapping topics between packs (e.g., CSP appears in `saas-frontend-hardening` AND in stack-specific React/Vue/Svelte skills — should they cross-link?).
4. **Triggering risk** — descriptions that are too narrow (won't activate when needed) or too broad (false-trigger on unrelated queries).
5. **Drift between README claims and reality** — README says "39 skills"; if you add or remove one, the README, banner, and release notes must be updated in the same PR.
6. **Recommendations** — bucketed as `ship now` (clear, low-risk), `discuss` (needs maintainer input), `defer` (not worth doing this cycle).

Each finding in the review issue links to a file:line.

## What to avoid in PRs

- Renaming an existing skill folder (breaks finding-ID continuity and external installs).
- Removing a check ID without documenting the rationale — finding IDs are referenced in external audit reports.
- Adding "TODO" / "FIXME" comments to SKILL.md or references. If a check is incomplete, it shouldn't ship.
- Mass formatting changes mixed with content changes. Split them: one PR for whitespace/line-wrap, separate PRs for content.
- Marketing language. Tone is direct, imperative, technical.

## Tone for new content

- **Imperative** in checks ("Verify X", "Confirm Y"), not interrogative ("Is X verified?").
- **Concrete** in remediations — paste-able SQL / code / config, not "follow vendor docs."
- **No "must" / "should" / "MAY"** unless quoting an RFC. Use direct language: "X is checked," "X is required."

## Communication style for review comments and PRs

- Lead with the finding, then the evidence, then the fix.
- One sentence of impact per finding (why does this matter?).
- Don't hedge. If something is wrong, say it. If you're uncertain, say "low confidence" explicitly.
