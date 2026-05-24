# appsec-stack-pack/scripts/

Pack-level scripts for the AppSec Stack Pack.

## `package_skills.sh`

Produces one self-contained `.zip` per skill in `./dist/` ready to upload to Claude.ai or copy into `~/.claude/skills/`.

**Behavior:**
- Discovers every `*/SKILL.md` folder in this pack via glob (no hardcoded list — `web-platform-security` and any future additions are picked up automatically).
- For each skill:
  - Stages the skill folder in a temp dir.
  - Inlines `_shared/` *inside* the skill folder so the resulting zip is self-contained.
  - Rewrites `../_shared/` references in `SKILL.md` to `_shared/` so the paths resolve after extraction.
  - Zips with a single top-level folder = the skill name (the layout Claude.ai expects).

**Usage:**
```bash
./scripts/package_skills.sh                      # writes to ./dist/
./scripts/package_skills.sh /tmp/my-skills-out   # custom output dir
```

**Requires:** `zip` (pre-installed on macOS; `sudo apt install zip` on Debian/Ubuntu).

**Install in Claude.ai:** Settings → Capabilities → Skills → Upload Skill → choose a `.zip`.

**Install in Claude Code:**
```bash
mkdir -p ~/.claude/skills
cp -r <skill-folder> ~/.claude/skills/
```
