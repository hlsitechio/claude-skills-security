---
name: Daily skill review
about: Structured output for a scheduled (Copilot or human) review of the skill packs
title: "Review YYYY-MM-DD — claude-skills-security"
labels: ["review"]
assignees: []
---

<!--
This template is the output format for daily / weekly reviews. Fill every section.
Skip a section ONLY if there is nothing to report and write "No findings."
A review with all sections blank is not a useful review.
-->

## Scope

- **Reviewed commit**: `<sha>` on `main`
- **Window**: <YYYY-MM-DD HH:MM UTC> to <YYYY-MM-DD HH:MM UTC>
- **Prior review**: <link to previous review issue, or "first review">

## 1. CI health

- Latest `validate-all-skills` run: <success / failure / link>
- Skills validated: <N> (expected: 39)
- Errors: <0 / list>
- Flakiness in window: <none / details>

## 2. New / changed skills

For each skill added or modified since the prior review:

| Skill | Change | Frontmatter OK | Refs resolve | Defensive-only |
|-------|--------|----------------|--------------|----------------|
| `<name>` | <added / modified / removed> | ✓/✗ | ✓/✗ | ✓/✗ |

Detail per row (one paragraph):

### `<skill-name>`

- **What changed**: <short summary, link to commit>
- **Quality call**: <ship / refine / block>
- **Specific issues**: <file:line — issue — suggested fix>

## 3. Cross-skill consistency

Topics that appear in multiple skills and may need cross-linking or de-duplication:

| Topic | Skills that cover it | Recommendation |
|-------|----------------------|----------------|
| <e.g., CSP> | saas-frontend-hardening, nextjs-security | <cross-link / merge / keep separate> |

## 4. Triggering risk

Skills whose `description:` may be too narrow (won't activate when it should) or too broad (false-triggers on unrelated queries):

| Skill | Risk | Evidence | Recommendation |
|-------|------|----------|----------------|
| `<name>` | too narrow / too broad | <example query> | <revised description draft> |

## 5. Drift between docs and reality

Claims in README, banner, PUSH_TO_GITHUB.md, or release notes that no longer match the repo:

- <e.g., "README claims 39 skills, repo has 40">
- <e.g., "Banner says 'AWS / GCP' but only AWS Lambda exists">

## 6. Defensive-only check

- Any new content that reads as offensive (exploit code, weaponized payload, attack chain)? <none / list>
- Any new dependency on commercial-only tooling? <none / list>

## 7. Recommendations

### Ship now (clear, low-risk)

- [ ] <action — file:line>

### Discuss (needs maintainer input)

- [ ] <action — open question>

### Defer (not this cycle)

- [ ] <action — reason for deferring>

## 8. Summary

One paragraph: overall health of the pack today, top risk, top opportunity.
