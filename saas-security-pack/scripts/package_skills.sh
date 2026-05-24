#!/usr/bin/env bash
# package_skills.sh
# Zips each skill folder into a .skill / .zip file ready to upload to Claude.ai
# (Settings → Capabilities → Skills → Upload Skill).
#
# Usage: ./scripts/package_skills.sh [output_dir]
# Default output_dir: ./dist

set -euo pipefail

# Repo root = parent of this script's directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
OUTPUT_DIR="${1:-$REPO_ROOT/dist}"

mkdir -p "$OUTPUT_DIR"

# Find every skill folder (those containing a SKILL.md)
SKILLS=$(find "$REPO_ROOT" -mindepth 2 -maxdepth 2 -name 'SKILL.md' -type f \
  | xargs -n1 dirname \
  | sort)

if [[ -z "$SKILLS" ]]; then
  echo "No skills found (no */SKILL.md files in $REPO_ROOT)." >&2
  exit 1
fi

echo "Packaging skills to: $OUTPUT_DIR"
echo ""

# Check zip is available
if ! command -v zip >/dev/null 2>&1; then
  echo "ERROR: 'zip' is not installed." >&2
  echo "  macOS: pre-installed; reinstall via 'brew install zip'" >&2
  echo "  Ubuntu/Debian: sudo apt install zip" >&2
  echo "  Alpine: apk add zip" >&2
  exit 1
fi

PACKAGED=0
for skill_path in $SKILLS; do
  skill_name=$(basename "$skill_path")
  zip_path="$OUTPUT_DIR/${skill_name}.zip"

  # Validate the skill has a SKILL.md with frontmatter
  if ! head -1 "$skill_path/SKILL.md" | grep -q '^---$'; then
    echo "  ⚠  $skill_name: SKILL.md missing YAML frontmatter; skipping"
    continue
  fi

  # Validate the name in frontmatter matches the folder name
  name_in_frontmatter=$(sed -n 's/^name: //p' "$skill_path/SKILL.md" | head -1 | tr -d '"' | tr -d "'")
  if [[ "$name_in_frontmatter" != "$skill_name" ]]; then
    echo "  ⚠  $skill_name: frontmatter name '$name_in_frontmatter' != folder name; skipping"
    continue
  fi

  # Clean up old zip if present
  rm -f "$zip_path"

  # Zip the folder content; exclude OS junk, version control, IDE files
  (
    cd "$REPO_ROOT" && \
    zip -qr "$zip_path" "$skill_name" \
      -x '*.DS_Store' \
      -x '*/__pycache__/*' \
      -x '*/.pytest_cache/*' \
      -x '*/node_modules/*' \
      -x '*/.git/*' \
      -x '*/.vscode/*' \
      -x '*/.idea/*'
  )

  size=$(du -h "$zip_path" | cut -f1)
  files=$(unzip -l "$zip_path" | tail -1 | awk '{print $2}')
  printf "  ✓ %-32s %6s, %s files\n" "$skill_name" "$size" "$files"
  PACKAGED=$((PACKAGED + 1))
done

echo ""
echo "Packaged $PACKAGED skill(s) to $OUTPUT_DIR/"
echo ""
echo "To install in Claude.ai:"
echo "  Settings → Capabilities → Skills → Upload Skill"
echo "  → choose any .zip from $OUTPUT_DIR/"
echo ""
echo "To install in Claude Code:"
echo "  mkdir -p ~/.claude/skills"
echo "  cp -r <skill-folder> ~/.claude/skills/"
