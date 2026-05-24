#!/usr/bin/env bash
# package_skills.sh — produce one self-contained zip per skill in ./dist/.
#
# Each zip has a single top-level folder (the skill name) containing
# SKILL.md, references/, scripts/, assets/, AND a copy of the pack's
# _shared/ inlined inside the skill folder. References from SKILL.md
# to `../_shared/...` are rewritten to `_shared/...` so the zip is
# fully self-contained when uploaded to Claude.ai / Claude Code.
#
# Usage: ./scripts/package_skills.sh [output_dir]

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT="${1:-$ROOT/dist}"
rm -rf "$OUT"
mkdir -p "$OUT"

# Pre-flight: zip must be available
if ! command -v zip >/dev/null 2>&1; then
  echo "ERROR: 'zip' is not installed" >&2
  echo "  macOS: pre-installed; reinstall via 'brew install zip'" >&2
  echo "  Ubuntu/Debian: sudo apt install zip" >&2
  echo "  Alpine: apk add zip" >&2
  exit 1
fi

# Discover skills: directories containing SKILL.md (excluding meta dirs)
SKILLS=()
for d in */; do
  d="${d%/}"
  [[ "$d" == "_shared" || "$d" == "scripts" ]] && continue
  [[ -f "$d/SKILL.md" ]] && SKILLS+=("$d")
done

if [[ ${#SKILLS[@]} -eq 0 ]]; then
  echo "ERROR: no skills found (no */SKILL.md)" >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PACKAGED=0
for skill in "${SKILLS[@]}"; do
  # Per-skill frontmatter sanity check
  if ! head -1 "$skill/SKILL.md" | grep -q '^---$'; then
    echo "  warn: $skill: SKILL.md missing YAML frontmatter; skipping"
    continue
  fi

  name_in_fm=$(sed -n 's/^name: //p' "$skill/SKILL.md" | head -1 | tr -d '"' | tr -d "'")
  if [[ "$name_in_fm" != "$skill" ]]; then
    echo "  warn: $skill: frontmatter name '$name_in_fm' != folder name; skipping"
    continue
  fi

  staging="$TMP/$skill"
  mkdir -p "$staging"

  # Copy skill contents
  cp -R "$skill"/. "$staging"/

  # Inline _shared/ INSIDE the skill folder
  if [[ -d "_shared" ]]; then
    cp -R _shared "$staging/_shared"
  fi

  # Rewrite `../_shared/` -> `_shared/` in SKILL.md
  if [[ -f "$staging/SKILL.md" ]]; then
    if [[ "$(uname)" == "Darwin" ]]; then
      sed -i '' 's|\.\./\_shared/|_shared/|g' "$staging/SKILL.md"
    else
      sed -i 's|\.\./\_shared/|_shared/|g' "$staging/SKILL.md"
    fi
  fi

  zip_path="$OUT/${skill}.zip"
  (
    cd "$TMP" && \
    zip -qr "$zip_path" "$skill" \
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
  printf "  ok %-32s %6s, %s files\n" "$skill" "$size" "$files"
  PACKAGED=$((PACKAGED + 1))
done

echo
echo "Packaged $PACKAGED skill(s) to $OUT/"
echo
echo "Install in Claude.ai:"
echo "  Settings -> Capabilities -> Skills -> Upload Skill -> choose a .zip"
echo
echo "Install in Claude Code (per repo or global):"
echo "  mkdir -p ~/.claude/skills"
echo "  cp -r <skill-folder> ~/.claude/skills/"
