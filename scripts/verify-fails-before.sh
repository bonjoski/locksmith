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

ensure_tag() {
  local tag="$1"
  if ! git -C "$REPO_ROOT" rev-parse "$tag" >/dev/null 2>&1; then
    echo "   Fetching missing tag $tag from origin..."
    git -C "$REPO_ROOT" fetch origin tag "$tag" --no-tags >/dev/null 2>&1 || true
  fi
  if ! git -C "$REPO_ROOT" rev-parse "$tag" >/dev/null 2>&1; then
    echo "❌ Required tag $tag is missing and could not be fetched."
    exit 1
  fi
}

echo "🔍 Verifying fails-before / passes-after against vulnerable tags..."

# 1. Verify against v3.2.5 (residual mock seam & sealing failure gaps)
echo "   Verifying fails-before against intermediate release v3.2.5..."
ensure_tag "v3.2.5"
WT_325="$TMP_DIR/v325-wt"
BIN_325="$TMP_DIR/locksmith-v325"

git -C "$REPO_ROOT" worktree add --detach "$WT_325" "v3.2.5" >/dev/null 2>&1
(cd "$WT_325" && go build -tags "locksmith_admin" -o "$BIN_325" ./cmd/locksmith >/dev/null 2>&1)
git -C "$REPO_ROOT" worktree remove --force "$WT_325" >/dev/null 2>&1

# 1a. TestAcceptance_ProductionBinaryNoMockBackendSeam MUST fail on v3.2.5 because v3.2.5 compiled MockBackend into production builds
set +e
OUT_SEAM=$(LOCKSMITH_BIN="$BIN_325" go test -C "$REPO_ROOT" -v ./test/acceptance -run="^TestAcceptance_ProductionBinaryNoMockBackendSeam$" 2>&1)
EXIT_SEAM=$?
set -e

if [ "$EXIT_SEAM" -eq 0 ]; then
  echo "❌ Fails-before violation: TestAcceptance_ProductionBinaryNoMockBackendSeam unexpectedly passed on v3.2.5!"
  exit 1
fi
if ! echo "$OUT_SEAM" | grep -q "contains test harness mock symbols in symbol table"; then
  echo "❌ Fails-before violation: TestAcceptance_ProductionBinaryNoMockBackendSeam failed on v3.2.5 for unexpected reason:"
  echo "$OUT_SEAM"
  exit 1
fi
echo "   ✔ Verified: TestAcceptance_ProductionBinaryNoMockBackendSeam correctly FAILS on v3.2.5 (mock symbols detected)."

# 1b. TestAcceptance_SealingFailureRejectsPlaintextDiskWrite MUST fail on v3.2.5 because v3.2.5 did not fail closed on seal error
set +e
OUT_SEAL=$(LOCKSMITH_BIN="$BIN_325" go test -C "$REPO_ROOT" -v ./test/acceptance -run="^TestAcceptance_SealingFailureRejectsPlaintextDiskWrite$" 2>&1)
EXIT_SEAL=$?
set -e

if [ "$EXIT_SEAL" -eq 0 ]; then
  echo "❌ Fails-before violation: TestAcceptance_SealingFailureRejectsPlaintextDiskWrite unexpectedly passed on v3.2.5!"
  exit 1
fi
if ! echo "$OUT_SEAL" | grep -q "expected ca init to fail when enclave sealing fails"; then
  echo "❌ Fails-before violation: TestAcceptance_SealingFailureRejectsPlaintextDiskWrite failed on v3.2.5 for unexpected reason:"
  echo "$OUT_SEAL"
  exit 1
fi
echo "   ✔ Verified: TestAcceptance_SealingFailureRejectsPlaintextDiskWrite correctly FAILS on v3.2.5 (ignored seal error detected)."

# 2. Verify against v3.2.1 (original vulnerable baseline)
echo "   Verifying fails-before against original vulnerable tag v3.2.1..."
ensure_tag "v3.2.1"
WT_321="$TMP_DIR/v321-wt"
BIN_321="$TMP_DIR/locksmith-v321"

git -C "$REPO_ROOT" worktree add --detach "$WT_321" "v3.2.1" >/dev/null 2>&1
(cd "$WT_321" && go build -tags "locksmith_admin" -o "$BIN_321" ./cmd/locksmith >/dev/null 2>&1)
git -C "$REPO_ROOT" worktree remove --force "$WT_321" >/dev/null 2>&1

set +e
LOCKSMITH_BIN="$BIN_321" go test -C "$REPO_ROOT" ./test/acceptance >/dev/null 2>&1
EXIT_321=$?
set -e

if [ "$EXIT_321" -eq 0 ]; then
  echo "❌ Fails-before violation: acceptance tests unexpectedly passed on vulnerable tag v3.2.1!"
  exit 1
fi
echo "   ✔ Verified: acceptance tests correctly FAIL on v3.2.1."

# 3. Assert acceptance suite PASSES on current HEAD
echo "   Checking that full acceptance tests pass on current HEAD..."
if ! go test -C "$REPO_ROOT" ./test/acceptance >/dev/null 2>&1; then
  echo "❌ Passes-after violation: acceptance tests failed on current HEAD!"
  exit 1
fi
echo "   ✔ Verified: all acceptance tests correctly PASS on current HEAD."

echo "✨ Fails-before / passes-after verification complete: test suite rejects vulnerable implementations and accepts hardened release."
