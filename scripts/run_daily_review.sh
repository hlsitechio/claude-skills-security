#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUMMARY_PATH="${1:-${REPO_ROOT}/artifacts/daily-review-summary.md}"

mkdir -p "$(dirname "${SUMMARY_PATH}")"

python3 "${REPO_ROOT}/scripts/review_skills_repo.py" \
  --repo-root "${REPO_ROOT}" \
  --summary "${SUMMARY_PATH}"

printf '\nDaily review summary written to: %s\n' "${SUMMARY_PATH}"
