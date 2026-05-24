# SaaS Security Pack

A bundle of 9 atomic [Claude Skills](https://docs.claude.com/en/docs/agents-and-tools/agent-skills/overview) for auditing the security of a SaaS application end-to-end. Defensive (find-and-fix, blue-team) focus across application code, infrastructure, identity, and compliance.

Each skill is independent. Install the ones relevant to your stack; skip the rest.

## What's in the pack

| Skill | What it audits |
|-------|----------------|
| `github-supply-chain` | GitHub Actions hardening, action pinning, dependency review, SBOM, OIDC to cloud |
| `github-repo-hardening` | Branch protection, rulesets, CODEOWNERS, secret scanning, push protection, signed commits |
| `saas-code-security-review` | App-code review: auth, JWT, IDOR/BOLA, SSRF, injection, mass assignment, SAST triage |
| `supabase-security-audit` | Postgres RLS, SECURITY DEFINER hardening, anon/authenticated grants, edge function auth, service_role exposure |
| `saas-tenant-isolation` | Multi-tenant query scoping, cache/storage/search isolation, job context, cross-tenant leak hunt |
| `saas-api-security` | Rate limiting, CORS, webhook signatures, GraphQL depth/cost, API key management |
| `saas-frontend-hardening` | CSP, security headers, cookie config, XSS sinks, clickjacking, postMessage |
| `iac-container-security` | Terraform/Dockerfile/k8s hardening, IAM least privilege, IaC scanning |
| `saas-compliance-audit` | SOC 2 / GDPR / HIPAA technical controls, audit logging, DSAR, retention |

Every skill emits findings in a unified schema (`_shared/findings-schema.md`) so reports across skills are comparable and aggregatable.

## Stack coverage

Skills are written multi-stack:
- **Backend**: Node/TypeScript, Python, Go, Java, Ruby
- **Database**: Postgres (with Supabase specifics), MySQL — RLS patterns apply to both
- **Frontend**: React/Vue/Svelte/Angular, generic browser
- **Cloud**: AWS, GCP, Azure (with stack-specific sections in references)
- **Container**: Docker, Kubernetes, Cloud Run, ECS, App Runner

When a check has different incarnations per stack, the SKILL.md routes to the right `references/*.md` for that variant.

## Installing into Claude.ai

Each skill is a self-contained folder. To install one in Claude.ai:

1. Zip the skill folder (the one containing `SKILL.md`).
2. In Claude.ai: **Settings → Capabilities → Skills → Upload Skill**.
3. Upload the `.zip`.
4. The skill becomes available in conversations once the description matches your query.

The helper script `scripts/package_skills.sh` zips every skill in one pass:

```bash
./scripts/package_skills.sh
# → ./dist/*.zip — one zip per skill, ready to upload
```

## Installing into Claude Code

Skills work in [Claude Code](https://docs.claude.com/en/docs/claude-code) too. Place each skill folder under `.claude/skills/` in your repo, or globally under `~/.claude/skills/`.

```bash
# Per-repo
mkdir -p .claude/skills
cp -r supabase-security-audit .claude/skills/

# Global
mkdir -p ~/.claude/skills
cp -r supabase-security-audit ~/.claude/skills/
```

## Using a skill

Once installed, Claude will activate the skill when your query matches its description triggers. Examples:

- *"Audit my Supabase project for RLS gaps"* → `supabase-security-audit`
- *"Review my Dockerfile for security issues"* → `iac-container-security`
- *"Are my GitHub Actions safe from supply chain attacks?"* → `github-supply-chain`
- *"Check tenant isolation in this codebase"* → `saas-tenant-isolation`
- *"SOC 2 readiness audit"* → `saas-compliance-audit`

The skill prompts Claude to follow a 5-phase workflow (see `_shared/audit-workflow.md`): scope → inventory → detect → triage → report. The output is a Markdown report following the unified findings schema.

## Repository structure

```
saas-security-pack/
├── _shared/                          # Shared workflow + finding schema
│   ├── audit-workflow.md
│   └── findings-schema.md
├── <skill-name>/
│   ├── SKILL.md                      # The entry point (YAML frontmatter + body)
│   ├── references/                   # Deep-dive docs loaded as needed
│   │   └── *.md
│   ├── scripts/                      # Executable helpers (audit scripts, SQL)
│   │   └── *.sh|*.sql
│   └── assets/                       # Templates, configs the skill produces or uses
│       └── *
├── scripts/
│   └── package_skills.sh             # Zips each skill folder for Claude.ai upload
└── .github/workflows/
    └── validate-skills.yml           # CI: validate SKILL.md frontmatter
```

## Defensive posture

Every skill is read-only and find-and-fix oriented. The pack does not include:
- Exploit code or weaponized payloads
- Offensive penetration-testing tooling
- Bypass techniques for security controls

If you need offensive-side coverage (red team simulation, pentest enablement), this is not the pack. The defensive scope is intentional — these skills produce findings and remediation, not attack chains.

## Customizing for your org

The skills are templates. To adapt:

1. Edit `_shared/findings-schema.md` to add internal severity-mapping (e.g., your JIRA priority levels).
2. Edit `_shared/audit-workflow.md` to add your reporting destination (Slack channel, ticket queue).
3. Edit individual `references/*.md` to encode your team's known-safe baselines.
4. Add your own scripts under each `scripts/` folder.

Re-package and re-upload after edits.

## Compliance disclaimer

This pack helps with technical controls that auditors verify. It is NOT a substitute for:
- A qualified compliance auditor or counsel
- An independent penetration test
- A SOC 2 / ISO 27001 / HIPAA-certified attestation

Use the output as input to those engagements, not as a replacement.

## License

MIT — see `LICENSE`.

## Contributing

See `CONTRIBUTING.md` for guidelines. PRs welcome for:
- Additional stack-specific reference files (e.g., Django-specific patterns)
- New check categories within existing skills
- Bug fixes to scripts
- Improvements to the findings schema

For new skills (covering an audit domain not in the pack), open an issue first to discuss scope.
