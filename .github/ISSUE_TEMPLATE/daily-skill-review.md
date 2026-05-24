---
name: Daily skill review
about: Structured output for a scheduled (Copilot or human) review of the skill packs — version-drift focused
title: "Review YYYY-MM-DD — claude-skills-security"
labels: ["review", "version-drift"]
assignees: []
---

<!--
PRIMARY GOAL: detect version drift in the tech that skills reference.
A skill recommending Node 18 in 2026 is silently insecure, even if its
text is unchanged. See .github/copilot-instructions.md for the full
review mandate and .github/tech-inventory.yml for what's tracked.

Fill every section. If a section has nothing to report, write "No findings."
-->

## Scope

- **Reviewed commit**: `<sha>` on `main`
- **Window**: <YYYY-MM-DD HH:MM UTC> to <YYYY-MM-DD HH:MM UTC>
- **Prior review**: <link to previous review issue, or "first review">
- **Inventory schema version**: <value of `inventory.schema_version` in tech-inventory.yml>

---

## 1. Version drift (PRIMARY)

For each entry in `.github/tech-inventory.yml`, the result of comparing `current_pin` against upstream.

### 1.1 Summary table

| Severity | Count |
|----------|-------|
| Critical | <N>   |
| High     | <N>   |
| Medium   | <N>   |
| Low      | <N>   |
| Info / on latest | <N> |

### 1.2 Findings

For every entry that is not INFO, one block:

#### `<inventory.id>` — <severity>

- **Upstream latest**: `<version>` (queried via `<source.type>` on <YYYY-MM-DD>)
- **Currently pinned**: `<current_pin>`
- **Pinned in**:
  - `<file:line>` — quoted line
  - `<file:line>` — quoted line
- **CVE / advisory context**: <GHSA-xxxx or NVD link, or "no known CVE in delta">
- **Why it matters here**: <one sentence — what specifically becomes insecure or misleading in our guidance>
- **Proposed edits**:
  ```diff
  - <old line>
  + <new line>
  ```
- **Inventory update needed**: <yes — bump `current_pin` to X and `last_verified` to today / no>

### 1.3 Inventory gaps

Tech mentioned in skills but not yet tracked in `tech-inventory.yml`:

| Tech | Where it appears | Suggested inventory entry (id, kind, source) |
|------|------------------|----------------------------------------------|
| <e.g., `redis 7.x`> | <file:line> | id: `redis-runtime`, kind: runtime, source: docker_hub redis |

---

## 2. CI health

- Latest `validate-all-skills` run: <success / failure / link>
- Skills validated: <N> (expected: 39)
- Errors: <0 / list>
- Flakiness in window: <none / details>

---

## 3. New / changed skills since prior review

For each skill added or modified:

| Skill | Change | Frontmatter OK | Refs resolve | Defensive-only | Drift handled |
|-------|--------|----------------|--------------|----------------|---------------|
| `<name>` | <added/modified/removed> | ✓/✗ | ✓/✗ | ✓/✗ | ✓/✗ |

Detail per row:

### `<skill-name>`

- **What changed**: <short summary, link to commit>
- **Quality call**: <ship / refine / block>
- **Specific issues**: <file:line — issue — suggested fix>
- **Tech inventory impact**: <new tech to track? bumped a pin?>

---

## 4. Cross-skill consistency

Topics that appear in multiple skills and may need cross-linking, de-duplication, or version-aligned guidance:

| Topic | Skills covering it | Consistent across versions? | Recommendation |
|-------|--------------------|------------------------------|----------------|
| <CSP> | saas-frontend-hardening, nextjs-security | <yes/no — explain> | <cross-link / merge / keep separate> |

---

## 5. Triggering risk

Skills whose `description:` may be too narrow or too broad:

| Skill | Risk | Evidence | Recommendation |
|-------|------|----------|----------------|
| `<name>` | too narrow / too broad | <example query that should/shouldn't trigger> | <revised description draft> |

---

## 6. Drift between docs and reality

Claims in README, banner, release notes, or CONTRIBUTING that no longer match the repo:

- <e.g., "README claims 39 skills, repo has 40">

---

## 7. Defensive-only check

- New content that reads as offensive (exploit code, weaponized payload, attack chain)? <none / list>
- New dependency on commercial-only tooling? <none / list>

---

## 8. Recommendations

### Ship now (clear, low-risk; one-line PRs)

- [ ] Bump `<tech-id>` from `<old>` to `<new>` in `<file>` — link to inventory finding 1.2
- [ ] <action — file:line>

### Discuss (needs maintainer input)

- [ ] Major-version migration: `<skill>` covers <framework> v<N>; v<N+1> changed <X>. Add a new section, or split into v<N> / v<N+1> branches?

### Defer (not this cycle)

- [ ] <action — reason>

---

## 9. Summary

One paragraph: top drift risk, overall health, what the maintainer should look at first.
