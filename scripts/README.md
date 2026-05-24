# scripts/

Repo-level scripts. Per-pack scripts live in `saas-security-pack/scripts/` and `appsec-stack-pack/scripts/`.

## `methora_upload.py`

Bulk-uploads every skill in this repo (both packs) to a [Methora](https://methora.com) skills library via its MCP HTTP endpoint.

**Inputs:**
- `METHORA_TOKEN` env var (a `lit_pat_…` personal access token issued by Methora). Never persisted or committed.

**Behavior:**
- Discovers all `*/SKILL.md` files in both packs.
- For each one, builds the `create_skill` payload:
  - `directive` = the SKILL.md body (YAML frontmatter stripped), with `../_shared/` rewritten to `_shared/`.
  - `references[]` = files under `references/`, `scripts/`, `assets/`, plus an inlined copy of the pack's `_shared/`.
  - `triggers[]` = quoted phrases extracted from the YAML `description:` (capped at 12).
  - `category` = `saas-security` or `appsec-stack` based on the pack.
- POSTs to `https://qletndspniubnyrogiax.supabase.co/functions/v1/skills-mcp` via JSON-RPC.
- Writes `methora_upload_manifest.json` recording each `(skill name, Methora id, slug)`.

**Usage:**
```bash
METHORA_TOKEN=lit_pat_... python scripts/methora_upload.py            # full bulk upload
METHORA_TOKEN=lit_pat_... python scripts/methora_upload.py --dry-run  # build payloads, skip POST
METHORA_TOKEN=lit_pat_... python scripts/methora_upload.py --only nextjs-security
```

**Known issue:** Cloudflare's OWASP Core Rule Set in front of Methora occasionally blocks payloads whose content contains exploit-pattern strings (`ELECTRON_RUN_AS_NODE`, `child_process`, etc.). For those skills, use the Methora MCP connector inside Claude Code/Desktop instead of this script.

## `methora_upload_manifest.json`

Source-of-truth record of the 40 skills uploaded to Methora — `{ name, category, id, slug, updated_at }` per skill. Used by future `update_skill` operations to target the right Methora row when a skill is updated in this repo.

## Per-pack scripts

- [`saas-security-pack/scripts/`](../saas-security-pack/scripts/README.md) — `package_skills.sh`.
- [`appsec-stack-pack/scripts/`](../appsec-stack-pack/scripts/README.md) — `package_skills.sh`.
