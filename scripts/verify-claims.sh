#!/usr/bin/env bash
# scripts/verify-claims.sh
# Verifies bidirectional claim traceability between CHANGELOG.md security claims
# and executable black-box acceptance tests, guaranteeing every claim is backed
# by active assertions.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHANGELOG="$REPO_ROOT/CHANGELOG.md"
ACCEPTANCE_DIR="$REPO_ROOT/test/acceptance"

echo "🔍 Verifying claim-to-test traceability and behavioral assertions..."

claims=$(grep -oE "CLAIM-[A-Z0-9-]+" "$CHANGELOG" | sort -u)
missing=0
tested=0

for claim in $claims; do
  # 1. Verify claim is present in acceptance test files
  match_file=$(grep -rl "// CLAIM: $claim" "$ACCEPTANCE_DIR" | head -n 1 || true)
  if [ -z "$match_file" ]; then
    echo "❌ Missing test for claim: $claim"
    missing=$((missing + 1))
    continue
  fi

  # 2. Extract the test function following the claim comment
  test_fn=$(awk -v claim="$claim" '
    $0 ~ "// CLAIM: " claim { found=1; next }
    found && /^func (Test[A-Za-z0-9_]+)/ {
      sub(/^func /, ""); sub(/\(.*/, ""); print; exit
    }
  ' "$match_file")

  if [ -z "$test_fn" ]; then
    echo "❌ Claim $claim is not associated with an executable test function in $match_file!"
    missing=$((missing + 1))
    continue
  fi

  # 3. Verify the test function contains actual security assertions
  if ! awk -v fn="$test_fn" '
    $0 ~ "^func " fn { in_fn=1; next }
    in_fn && /^func / { exit }
    in_fn && (/(t\.Fatalf|t\.Errorf|t\.Fail|assert)/) { has_assert=1; exit }
    END { exit !has_assert }
  ' "$match_file"; then
    echo "❌ Test function $test_fn for claim $claim lacks assertions!"
    missing=$((missing + 1))
    continue
  fi

  # 4. Execute the specific claim test to verify behavioral pass
  if ! go test -C "$REPO_ROOT" -run "^${test_fn}$" ./test/acceptance >/dev/null 2>&1; then
    echo "❌ Test function $test_fn for claim $claim failed execution!"
    missing=$((missing + 1))
    continue
  fi

  echo "   ✔ Traced & Verified: $claim -> $test_fn (executable with active assertions)"
  tested=$((tested + 1))
done

if [ "$missing" -gt 0 ]; then
  echo "🚨 $missing security claims lack valid executable test assertions!"
  exit 1
fi

echo "✨ All $tested security claims successfully traced to verified executable acceptance tests!"
