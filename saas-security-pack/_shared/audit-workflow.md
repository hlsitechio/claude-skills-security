# Common Audit Workflow

Every skill in this pack follows the same outer loop, even though the inner checks differ. Document this once here and reference it from each SKILL.md.

## The 5 phases

### 1. Scope confirmation

Before any checks, restate scope to the user:
- What is being audited (repo URL, specific path, Supabase project ref, deployment environment, etc.)
- What is explicitly **out of scope** (e.g., third-party SaaS the user can't fix, legacy module being decommissioned)
- Whether the audit is read-only (default) or whether the user authorizes mutating actions like creating issues, opening PRs, rotating secrets

Never run mutating actions without explicit user authorization in the conversation.

### 2. Inventory

Enumerate the surface before judging it. You can't audit what you haven't listed.

- Pull the relevant resource list (workflows, tables, policies, dependencies, etc.)
- Save the raw inventory output before applying any analysis — useful for diffing across audits
- If the inventory is too large to fit in context, summarize counts and sample representatively

### 3. Detection

Apply the skill-specific checks against the inventory. For each check:
- Note **what triggered it** (the rule, pattern, or anti-pattern)
- Capture **evidence** (minimal but sufficient excerpt — never paste secrets)
- Tag with **category** and **CWE** when applicable

### 4. Triage

Sort findings by severity (Critical → Info). Within each severity, group by category to help the reader fix related things together. If two findings have the same root cause, mark them as related rather than duplicating remediation.

### 5. Report

Emit a report following `_shared/findings-schema.md`. Save to:
```
audits/<skill-name>/<target>/<YYYY-MM-DD>.md
```

If the user requested a specific output location, honor it.

## Defaults that hold across skills

- **Read-only by default**: never modify code, settings, or data without explicit authorization.
- **Reproducible evidence**: every finding must include enough context that another auditor could verify it independently.
- **No phantom findings**: if a check can't be applied (missing access, missing tool, ambiguous target), say so in the report under "Not assessed" — don't omit silently.
- **Multi-stack**: when the target's stack differs from defaults, adapt examples. The skill's references include stack-specific variants.
- **Bilingual user**: if the user's last message is in French, write the report in French. If in English, write in English. If mixed, follow the framing language of the question. Keep technical terms (CWE names, header names, function names) in their canonical form regardless of language.

## When to halt

Stop and ask the user mid-audit when:
- A Critical finding suggests active exploitation (e.g., audit logs show suspicious activity, secrets are already exposed publicly). In that case, surface the finding immediately and propose containment before continuing.
- The scope turns out to be 10x larger than expected (e.g., user said "audit one workflow" and you found 200 workflows). Confirm before exploding effort.
- Required access is missing and the user has not authorized you to skip those checks.
