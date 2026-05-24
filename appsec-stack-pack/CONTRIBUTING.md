# Contributing to AppSec Stack Pack

Thanks for your interest in improving this pack. These skills are intentionally narrow (one tech per skill) and dense (checks > prose). Contributions that preserve that shape are easiest to merge.

## Scope

This pack is **defensive only**. Each skill helps an auditor find issues and remediate them. PRs adding offensive techniques, exploit code, or weaponized payloads will be closed.

## Skill format

Every skill follows the same shape (see existing skills for examples):

```
<skill-name>/
├── SKILL.md          # Required
├── references/       # Optional, one or more deep-dive .md files
│   └── <topic>.md
└── assets/           # Optional, e.g., audit-script snippets
```

### `SKILL.md` structure

```markdown
---
name: <kebab-case-skill-name>
description: <triggers — what user phrases activate this skill>
---

# <Skill Title>

<One-paragraph intent statement>

## When this skill applies
- <bullet list of in-scope situations>

Use other skills for: <pointers to overlapping skills>

## Workflow

Follow `../_shared/audit-workflow.md`.

### Phase 1: Stack detection
<commands / signals to confirm the stack>

### Phase 2: Inventory
<grep commands / discovery techniques>

### Phase 3: Detection — the checks
<numbered checks with finding ID prefixes>

### Phase 4: Triage
<critical examples specific to this skill>

### Phase 5: Report
<reference to shared findings schema, ID prefix used>
```

### Finding IDs

Each skill reserves a 3-letter prefix in `_shared/findings-schema.md`. When you add a check, give it a stable ID:

```
- **NXT-SA-1** Every Server Action checks authentication.
```

`NXT` is the prefix (Next.js), `SA` is the category (Server Actions), `1` is the check number. Don't renumber existing checks — append.

### Triggers (description field)

The `description:` line in the YAML frontmatter is what Claude uses to decide whether to activate the skill. Be specific:

- Include the technology's proper noun ("Next.js", "Prisma", "Clerk")
- Include common file signatures (`next.config.js`, `schema.prisma`, `wrangler.toml`)
- Include the verbs users typically use ("audit my X", "X security review", "is my Y safe")
- Include both English and French phrasings where natural

A good description is ~3–6 sentences. Too short, and the skill won't trigger reliably; too long, and triggers get diluted.

## Style

- **Imperative** ("Every endpoint checks auth.") not declarative ("Endpoints should check auth.")
- **Code examples** small and runnable in context
- **Prose minimal** — checks > paragraphs
- **Cross-references** via relative paths (`../skill-name/references/foo.md`)
- **No reproduction of copyrighted material** in examples (no song lyrics, no library docs verbatim)

## Adding a new skill

1. Pick a kebab-case name following the pattern `<technology>-security`.
2. Reserve a 3-letter prefix in `_shared/findings-schema.md` (add a row to the table).
3. Create the folder + `SKILL.md` following the template above.
4. Add the skill to `README.md`'s table.
5. Verify the description triggers correctly — try to imagine how a user would phrase a request for this skill.

## Reporting issues

- Inaccurate checks (false positives/negatives): open an issue with a small reproducer.
- Missing checks: open an issue describing the vuln class + a reference to public guidance.
- Skill triggering on wrong context: include the user query that should/shouldn't have triggered.

## Validation

`scripts/package_skills.sh` produces zip files in `dist/` — useful for individual skill distribution. CI workflow `.github/workflows/validate-skills.yml` checks each SKILL.md for required YAML fields and reference link integrity.

## License

All contributions are accepted under the MIT license (see `LICENSE`).
