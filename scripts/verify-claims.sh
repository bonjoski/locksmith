#!/usr/bin/env bash
set -euo pipefail

CHANGELOG="CHANGELOG.md"
ACCEPTANCE_DIR="test/acceptance"

echo "🔍 Verifying claim traceability between CHANGELOG.md and acceptance tests..."

claims=$(grep -oE "CLAIM-[A-Z0-9-]+" "$CHANGELOG" | sort -u)
missing=0

for claim in $claims; do
  if ! grep -rq "// CLAIM: $claim" "$ACCEPTANCE_DIR"; then
    echo "❌ Missing test for claim: $claim"
    missing=$((missing + 1))
  else
    echo "✅ Verified claim: $claim"
  fi
done

if [ "$missing" -gt 0 ]; then
  echo "🚨 $missing security claims lack acceptance test traceability!"
  exit 1
fi

echo "✨ All security claims successfully traced to acceptance tests!"
