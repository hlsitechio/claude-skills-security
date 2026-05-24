#!/usr/bin/env bash
# run_iac_scanners.sh
# Runs the standard set of IaC and container scanners against a target path.
# Produces consistent output suitable for piping into the audit report.
#
# Usage: ./run_iac_scanners.sh [path] [--severity HIGH,CRITICAL]
# Default path is current directory.
#
# Side effects: writes scanner output files to $REPORT_DIR.
# By default $REPORT_DIR is a fresh temp dir (path printed at the end) so the
# script does NOT mutate the target repository. To write to a specific
# location, set REPORT_DIR=/your/path before invoking.
#
# Requires: trivy, checkov, tfsec (installs hints printed if missing).

set -uo pipefail

TARGET="${1:-.}"
SEVERITY="${SEVERITY:-HIGH,CRITICAL}"
# Default to a temp dir outside the target so the audit stays read-only on $TARGET.
REPORT_DIR="${REPORT_DIR:-$(mktemp -d -t iac-audit-XXXXXX)}"

mkdir -p "$REPORT_DIR"

have() { command -v "$1" >/dev/null 2>&1; }

print_section() {
  echo ""
  echo "======================================================================"
  echo "== $1"
  echo "======================================================================"
}

# 1. Trivy — filesystem (deps, secrets, misconfig)
print_section "Trivy: filesystem scan ($TARGET)"
if have trivy; then
  trivy fs \
    --severity "$SEVERITY" \
    --scanners vuln,secret,misconfig \
    --skip-dirs node_modules,.git,vendor \
    --format table \
    "$TARGET" | tee "$REPORT_DIR/trivy-fs.txt"
else
  echo "trivy not installed. brew install trivy  |  https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
fi

# 2. Checkov — IaC misconfig (broad coverage; multi-framework)
print_section "Checkov: IaC scan ($TARGET)"
if have checkov; then
  checkov \
    --directory "$TARGET" \
    --quiet \
    --output cli \
    --skip-path 'node_modules,.git,vendor' \
    --compact \
    | tee "$REPORT_DIR/checkov.txt"
else
  echo "checkov not installed. pip install checkov  |  https://www.checkov.io/2.Basics/Installing%20Checkov.html"
fi

# 3. tfsec — Terraform-specific
print_section "tfsec: Terraform scan"
TF_FILES=$(find "$TARGET" -name '*.tf' -not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null | head -1)
if [[ -n "$TF_FILES" ]]; then
  if have tfsec; then
    tfsec "$TARGET" --soft-fail --format default \
      | tee "$REPORT_DIR/tfsec.txt"
  else
    echo "tfsec not installed (Terraform files detected). brew install tfsec  |  https://aquasecurity.github.io/tfsec/"
  fi
else
  echo "(no .tf files found; skipping)"
fi

# 4. Dockerfile-specific (hadolint)
print_section "hadolint: Dockerfile lint"
DOCKERFILES=$(find "$TARGET" -name 'Dockerfile*' -not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null)
if [[ -n "$DOCKERFILES" ]]; then
  if have hadolint; then
    for df in $DOCKERFILES; do
      echo "--- $df ---"
      hadolint "$df" || true
    done | tee "$REPORT_DIR/hadolint.txt"
  else
    echo "hadolint not installed. brew install hadolint  |  https://github.com/hadolint/hadolint"
  fi
else
  echo "(no Dockerfiles found; skipping)"
fi

# 5. Kubernetes-specific (kubesec via Docker if not native)
print_section "kubesec: Kubernetes manifest scan"
K8S_FILES=$(find "$TARGET" -path '*/k8s/*.yaml' -o -path '*/manifests/*.yaml' -o -path '*/kubernetes/*.yaml' 2>/dev/null | grep -v node_modules | head -20)
if [[ -n "$K8S_FILES" ]]; then
  if have kubesec; then
    for f in $K8S_FILES; do
      echo "--- $f ---"
      kubesec scan "$f" | jq -r '.[] | "Score: \(.score) | \(.message)"' 2>/dev/null
    done | tee "$REPORT_DIR/kubesec.txt"
  else
    echo "kubesec not installed. brew install kubesec  |  https://kubesec.io"
  fi
else
  echo "(no k8s manifests found; skipping)"
fi

print_section "Done"
echo "Reports written to: $REPORT_DIR/"
echo ""
echo "Summary (counts of HIGH/CRITICAL issues):"
[[ -f "$REPORT_DIR/trivy-fs.txt" ]] && \
  echo "  trivy:    $(grep -cE '(HIGH|CRITICAL)' $REPORT_DIR/trivy-fs.txt 2>/dev/null || echo 0)"
[[ -f "$REPORT_DIR/checkov.txt" ]] && \
  echo "  checkov:  $(grep -cE 'FAILED' $REPORT_DIR/checkov.txt 2>/dev/null || echo 0)"
[[ -f "$REPORT_DIR/tfsec.txt" ]] && \
  echo "  tfsec:    $(grep -cE 'HIGH|CRITICAL' $REPORT_DIR/tfsec.txt 2>/dev/null || echo 0)"

echo ""
echo "Next: triage findings using _shared/findings-schema.md severity rubric."
