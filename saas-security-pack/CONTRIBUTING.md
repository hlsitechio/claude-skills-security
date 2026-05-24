# Contributing to SaaS Security Pack

Thanks for considering a contribution. This pack is intentionally focused on **defensive** SaaS security audits. PRs that fit that scope are welcome.

## What we accept

- **Additional stack-specific references** under existing skills (e.g., adding `references/django-orm-scoping.md` under `saas-tenant-isolation`).
- **New check categories** within existing skills, in the existing `SKILL.md` format with finding ID prefix.
- **Bug fixes** to scripts.
- **Schema improvements** to `_shared/findings-schema.md` — but discuss in an issue first; cross-skill impact.
- **New skills** for audit domains not yet covered — open an issue first to discuss scope.

## What we don't accept

- **Offensive tooling**: exploit code, weaponized payloads, control-bypass techniques, automated pen-testing.
- **Generic-AI-generated content** without verification. Submissions must be technically accurate — auditors and security engineers will rely on them.
- **Marketing for paid tools**. Mentions of commercial tools are fine when they're the standard answer (Snyk, Trivy, Checkov, etc.); promotional content is not.
- **Skills that depend on a specific proprietary platform** unless that platform is widely used (Supabase, Vercel, AWS qualify; an internal tool used by ten companies does not).

## Format requirements

Every skill must follow the structure:

```
skill-name/
├── SKILL.md          # YAML frontmatter (name, description) + body
├── references/       # 2-5 markdown files for deep-dive content
├── scripts/          # Optional executables (bash, sql, python)
└── assets/           # Optional templates produced or used by the skill
```

### SKILL.md frontmatter

```yaml
---
name: skill-name              # lowercase-kebab, must match folder name
description: <pushy description with explicit triggers; see existing skills>
---
```

The description is the primary triggering mechanism. Include both **what the skill does** and **when to use it**, with explicit phrases users might say.

### SKILL.md body

Sections expected (in order):

1. **Title and one-line summary**
2. **When this skill applies** — explicit "use this for / don't use this for" guidance
3. **Workflow** — reference `_shared/audit-workflow.md` and add skill-specific Phase 1-5 notes
4. **Detection checks** — numbered with the skill's ID prefix (see findings-schema.md for prefix table)
5. **Triage notes** — what counts as Critical for this skill
6. **Outputs** — what artifacts the skill produces
7. **References** — links to each `references/*.md` with a one-line description
8. **Scripts / Assets** — if present, list them

### Reference file conventions

- Each reference is ~100-300 lines focused on one topic.
- Code examples are runnable and copy-paste correct (not pseudo-code unless explicitly labeled).
- When showing anti-patterns vs correct patterns, label clearly.
- Cross-reference to other skills using relative paths: `../other-skill/references/foo.md`.

### Finding IDs

Each skill has a prefix (see `_shared/findings-schema.md`). All findings emitted by the skill use that prefix:

- `SUPA-001`, `SUPA-002`, ... for supabase-security-audit
- `GHSC-001`, `GHSC-002`, ... for github-supply-chain
- etc.

When adding a new skill, propose a 3-5 character uppercase prefix and add it to the schema doc.

## Style

- **Imperative** in checks ("Verify X", "Confirm Y"), not interrogative.
- **Multi-stack** by default. If a check is stack-specific, say so explicitly.
- **No "must" / "should" / "MAY"** unless quoting an RFC. Use direct language: "X is checked" / "X is required" / "Skip X when Y".
- **No vendor preference** unless one is the clear standard. When recommending tools, list the main options (e.g., "Trivy, Snyk Container, Docker Scout") not just one.

## Testing a contribution

For changes to a skill:

1. Install the modified skill into Claude.ai or Claude Code.
2. Run a representative query that should trigger it.
3. Verify the skill activates and produces a sane report.
4. Test with at least one query that should NOT trigger the skill (false positive check).

Save the test transcripts in your PR description for reviewers.

## Issue templates

For a new skill proposal, include:
- The audit domain (one sentence).
- Why it's not covered by an existing skill.
- The check categories you'd include.
- The expected output format.

For a bug, include:
- The skill name.
- The triggering query.
- The wrong output and what you expected.

## Code of conduct

Be respectful. Security work is collaborative — credit reviewers, accept feedback, disagree productively. Discrimination, harassment, or bad-faith arguments result in PR closure without discussion.

## Maintainers

This pack is maintained as an open resource. Major direction questions go through GitHub issues. Routine PR review may take 1-2 weeks.

Thank you for contributing.
