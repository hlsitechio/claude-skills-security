# Contributing to claude-skills-security

This monorepo houses two packs. Contributions to either follow the same conventions, summarized below. Per-pack details:

- [saas-security-pack/CONTRIBUTING.md](./saas-security-pack/CONTRIBUTING.md)
- [appsec-stack-pack/CONTRIBUTING.md](./appsec-stack-pack/CONTRIBUTING.md)

## Scope

Defensive only. PRs adding offensive techniques, exploit code, or weaponized payloads will be closed.

## Which pack does my contribution belong in?

- **New audit domain** (e.g., "kubernetes-rbac-audit", "secrets-rotation-audit") → `saas-security-pack`
- **New technology coverage** (e.g., "remix-security", "deno-security", "dragonfly-security") → `appsec-stack-pack`

When in doubt, open an issue first to discuss.

## Skill format

Every skill follows the same shape:

```
<skill-name>/
├── SKILL.md         # required — YAML frontmatter + 5-phase workflow
├── references/      # optional — deep-dive companion docs
│   └── <topic>.md
└── assets/          # optional — scripts, schemas, sample fixtures
```

### `SKILL.md` skeleton

```markdown
---
name: <kebab-case-name>
description: <triggers — proper nouns, file signatures, common user phrasings>
---

# <Title>

<1-paragraph intent statement>

## When this skill applies
- <bullets of in-scope situations>

Use other skills for: <pointers to overlapping skills>

## Workflow

Follow `../_shared/audit-workflow.md`.

### Phase 1: Stack detection
### Phase 2: Inventory
### Phase 3: Detection — the checks
### Phase 4: Triage
### Phase 5: Report

## References (optional)
```

### Finding IDs

Each skill reserves a 3-letter prefix in its pack's `_shared/findings-schema.md`. Add new checks by appending — don't renumber existing IDs.

### Triggers

The `description:` is what Claude uses to route. Make it:
- Specific (proper nouns, file signatures, version markers)
- Action-oriented (include verbs like "audit my X")
- Bilingual where natural (English + French phrasings)
- ~3-6 sentences

## Validation

Both packs have a CI workflow (`.github/workflows/validate-skills.yml`) that checks:
- YAML frontmatter present and valid
- `name` matches folder name
- Referenced files in `references/` actually exist

Run locally:

```bash
cd saas-security-pack  # or appsec-stack-pack
python3 -c "$(cat <<'EOF'
import os, re, yaml
for root, dirs, files in os.walk('.'):
    if 'SKILL.md' not in files: continue
    with open(f'{root}/SKILL.md') as f: c = f.read()
    m = re.match(r'^---\n(.*?)\n---', c, re.DOTALL)
    meta = yaml.safe_load(m.group(1))
    assert meta['name'] == os.path.basename(root), root
print('OK')
EOF
)"
```

## Issue and PR templates

- **Inaccurate check (false positive/negative)** — include a small reproducer
- **Missing check** — link to public guidance (OWASP, CWE, vendor advisory)
- **Skill triggering on wrong context** — include the user query that should/shouldn't have triggered
- **New skill proposal** — describe scope, prefix, and 3-5 example user queries that would route to it

## License

All contributions accepted under MIT (see `LICENSE`).
