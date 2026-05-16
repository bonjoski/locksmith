#!/usr/bin/env bash
# update_homebrew_sha.sh
# Run this AFTER the GitHub release artifacts are published.
# It fetches the arm64 and amd64 binaries, computes their SHA256,
# and patches Formula/locksmith.rb in place.
#
# Usage: bash update_homebrew_sha.sh

set -euo pipefail

# Read version from pkg/locksmith/version.go
VERSION=$(grep 'const Version =' pkg/locksmith/version.go | sed -E 's/.*"(.+)".*/\1/')
REPO="bonjoski/locksmith"
FORMULA="Formula/locksmith.rb"
TAP_DIR="../homebrew-locksmith"
TMPDIR=$(mktemp -d)

echo "==> Updating to version ${VERSION}..."

echo "==> Downloading binaries..."
ARM64_URL="https://github.com/${REPO}/releases/download/v${VERSION}/locksmith-darwin-arm64"
AMD64_URL="https://github.com/${REPO}/releases/download/v${VERSION}/locksmith-darwin-amd64"
SUMMON_ARM64_URL="https://github.com/${REPO}/releases/download/v${VERSION}/summon-locksmith-darwin-arm64"
SUMMON_AMD64_URL="https://github.com/${REPO}/releases/download/v${VERSION}/summon-locksmith-darwin-amd64"

curl -fsSL -o "${TMPDIR}/locksmith-darwin-arm64" "${ARM64_URL}"
curl -fsSL -o "${TMPDIR}/locksmith-darwin-amd64" "${AMD64_URL}"
curl -fsSL -o "${TMPDIR}/summon-locksmith-darwin-arm64" "${SUMMON_ARM64_URL}"
curl -fsSL -o "${TMPDIR}/summon-locksmith-darwin-amd64" "${SUMMON_AMD64_URL}"

LOCKSMITH_ARM64_SHA=$(shasum -a 256 "${TMPDIR}/locksmith-darwin-arm64" | awk '{print $1}')
LOCKSMITH_AMD64_SHA=$(shasum -a 256 "${TMPDIR}/locksmith-darwin-amd64" | awk '{print $1}')
SUMMON_ARM64_SHA=$(shasum -a 256 "${TMPDIR}/summon-locksmith-darwin-arm64" | awk '{print $1}')
SUMMON_AMD64_SHA=$(shasum -a 256 "${TMPDIR}/summon-locksmith-darwin-amd64" | awk '{print $1}')

echo "  Locksmith arm64 SHA256: ${LOCKSMITH_ARM64_SHA}"
echo "  Locksmith amd64 SHA256: ${LOCKSMITH_AMD64_SHA}"
echo "  Summon arm64 SHA256: ${SUMMON_ARM64_SHA}"
echo "  Summon amd64 SHA256: ${SUMMON_AMD64_SHA}"

echo "==> Patching ${FORMULA}..."
sed -i '' "s/version \".*\"/version \"${VERSION}\"/" "${FORMULA}"

# --- ARM64 Updates (locksmith & summon) ---
# Update hashes
sed -i '' "/locksmith-darwin-arm64/ { N; s/sha256 \".*\"/sha256 \"${LOCKSMITH_ARM64_SHA}\"/; }" "${FORMULA}"
sed -i '' "/summon-locksmith-darwin-arm64/ { N; s/sha256 \".*\"/sha256 \"${SUMMON_ARM64_SHA}\"/; }" "${FORMULA}"
# Update download paths
sed -i '' "s/download\/v.*\/locksmith-darwin-arm64/download\/v${VERSION}\/locksmith-darwin-arm64/" "${FORMULA}"
sed -i '' "s/download\/v.*\/summon-locksmith-darwin-arm64/download\/v${VERSION}\/summon-locksmith-darwin-arm64/" "${FORMULA}"

# --- AMD64 Updates (locksmith & summon) ---
# Update hashes
sed -i '' "/locksmith-darwin-amd64/ { N; s/sha256 \".*\"/sha256 \"${LOCKSMITH_AMD64_SHA}\"/; }" "${FORMULA}"
sed -i '' "/summon-locksmith-darwin-amd64/ { N; s/sha256 \".*\"/sha256 \"${SUMMON_AMD64_SHA}\"/; }" "${FORMULA}"
# Update download paths
sed -i '' "s/download\/v.*\/locksmith-darwin-amd64/download\/v${VERSION}\/locksmith-darwin-amd64/" "${FORMULA}"
sed -i '' "s/download\/v.*\/summon-locksmith-darwin-amd64/download\/v${VERSION}\/summon-locksmith-darwin-amd64/" "${FORMULA}"

rm -rf "${TMPDIR}"

echo "==> Done. ${FORMULA} updated."

if [ -d "${TAP_DIR}" ]; then
    echo "==> Syncing to local tap repo: ${TAP_DIR}"
    cp "${FORMULA}" "${TAP_DIR}/Formula/locksmith.rb"
    
    # --- README Updates ---
    TAP_README="${TAP_DIR}/README.md"
    if [ -f "${TAP_README}" ]; then
        echo "==> Syncing version reference in ${TAP_README}..."
        sed -i '' "s/Both should return the active version (e.g., \`v.*\`)/Both should return the active version (e.g., \`v${VERSION}\`)/" "${TAP_README}"
    fi
    
    echo "  Success. Run 'git -C ${TAP_DIR} commit -am \"feat: update to v${VERSION}\" && git -C ${TAP_DIR} push' to publish."
else
    echo "==> Local tap repo not found at ${TAP_DIR}. Skipping sync."
fi
