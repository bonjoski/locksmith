#!/usr/bin/env bash
# scripts/verify-fails-before.sh
# Verifies that acceptance tests fail on previously vulnerable release tags (fails-before)
# and pass on current HEAD (passes-after).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d -t locksmith-fails-before-XXXXXX)"

cleanup() {
  rm -rf "$TMP_DIR"
  git -C "$REPO_ROOT" worktree prune >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "🔍 Verifying fails-before / passes-after against vulnerable tags..."

VULN_TAG="v3.2.1"
WORKTREE_DIR="$TMP_DIR/v321-wt"
VULN_BIN="$TMP_DIR/locksmith-v321"

if ! git -C "$REPO_ROOT" rev-parse "$VULN_TAG" >/dev/null 2>&1; then
  echo "⚠️  Tag $VULN_TAG not found locally, skipping fails-before verification."
  exit 0
fi

# 1. Build vulnerable tag in temporary worktree
git -C "$REPO_ROOT" worktree add --detach "$WORKTREE_DIR" "$VULN_TAG" >/dev/null 2>&1
(cd "$WORKTREE_DIR" && go build -tags "locksmith_admin" -o "$VULN_BIN" ./cmd/locksmith >/dev/null 2>&1)
git -C "$REPO_ROOT" worktree remove --force "$WORKTREE_DIR" >/dev/null 2>&1

# 2. Assert acceptance suite FAILS on vulnerable binary
echo "   Checking that acceptance tests fail on $VULN_TAG..."
if LOCKSMITH_BIN="$VULN_BIN" go test -C "$REPO_ROOT" ./test/acceptance >/dev/null 2>&1; then
  echo "❌ Fails-before violation: acceptance tests unexpectedly passed on vulnerable tag $VULN_TAG!"
  exit 1
fi
echo "   ✔ Verified: acceptance tests correctly FAIL on $VULN_TAG."

# 3. Assert acceptance suite PASSES on current HEAD
echo "   Checking that acceptance tests pass on current HEAD..."
if ! go test -C "$REPO_ROOT" ./test/acceptance >/dev/null 2>&1; then
  echo "❌ Passes-after violation: acceptance tests failed on current HEAD!"
  exit 1
fi
echo "   ✔ Verified: acceptance tests correctly PASS on current HEAD."

echo "✨ Fails-before / passes-after verification complete: test suite rejects vulnerable implementations and accepts hardened release."
