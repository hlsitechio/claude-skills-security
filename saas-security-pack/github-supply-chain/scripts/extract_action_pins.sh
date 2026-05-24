#!/usr/bin/env bash
# Extract every `uses:` reference from .github/workflows and flag non-SHA pins.
# Usage: ./extract_action_pins.sh [path-to-repo]
# Exit 0 always; the report is on stdout. Pipe to grep for non-SHA findings.

set -euo pipefail

REPO_PATH="${1:-.}"
WORKFLOW_DIR="$REPO_PATH/.github/workflows"

if [[ ! -d "$WORKFLOW_DIR" ]]; then
  echo "No .github/workflows/ directory found at $REPO_PATH" >&2
  exit 0
fi

# A full SHA1 is 40 lowercase hex chars.
SHA_RE='^[0-9a-f]{40}$'

printf '%-60s | %-50s | %s\n' "WORKFLOW" "ACTION" "STATUS"
printf '%-60s-+-%-50s-+-%s\n' "$(printf '%0.s-' {1..60})" "$(printf '%0.s-' {1..50})" "$(printf '%0.s-' {1..10})"

shopt -s nullglob
for wf in "$WORKFLOW_DIR"/*.y*ml; do
  wf_rel=$(realpath --relative-to="$REPO_PATH" "$wf")
  # Capture every `uses:` reference, strip comments, extract action@ref
  grep -Eho '^\s*-?\s*uses:\s*[^#[:space:]]+' "$wf" \
    | sed -E 's/^\s*-?\s*uses:\s*//; s/[[:space:]]*$//' \
    | while read -r ref; do
        if [[ "$ref" != *"@"* ]]; then
          status="NO-PIN"
        else
          pin="${ref##*@}"
          if [[ "$pin" =~ $SHA_RE ]]; then
            status="SHA-PINNED"
          elif [[ "$pin" =~ ^v[0-9]+(\.[0-9]+){0,2}$ ]]; then
            status="TAG-PINNED ($pin)"
          elif [[ "$pin" == "main" || "$pin" == "master" || "$pin" == "latest" ]]; then
            status="FLOATING-REF ($pin)"
          else
            status="OTHER ($pin)"
          fi
        fi
        printf '%-60s | %-50s | %s\n' "$wf_rel" "${ref%@*}" "$status"
      done
done
