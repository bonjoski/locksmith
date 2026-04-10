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

curl -fsSL -o "${TMPDIR}/locksmith-darwin-arm64" "${ARM64_URL}"
curl -fsSL -o "${TMPDIR}/locksmith-darwin-amd64" "${AMD64_URL}"

ARM64_SHA=$(shasum -a 256 "${TMPDIR}/locksmith-darwin-arm64" | awk '{print $1}')
AMD64_SHA=$(shasum -a 256 "${TMPDIR}/locksmith-darwin-amd64" | awk '{print $1}')

echo "  arm64 SHA256: ${ARM64_SHA}"
echo "  amd64 SHA256: ${AMD64_SHA}"

echo "==> Patching ${FORMULA}..."
sed -i '' "s/version \".*\"/version \"${VERSION}\"/" "${FORMULA}"

# Update ARM64 block using specific pattern matching
sed -i '' "/locksmith-darwin-arm64/ { N; s/sha256 \".*\"/sha256 \"${ARM64_SHA}\"/; }" "${FORMULA}"
sed -i '' "s/download\/v.*\/locksmith-darwin-arm64/download\/v${VERSION}\/locksmith-darwin-arm64/" "${FORMULA}"

# Update AMD64 block
sed -i '' "/locksmith-darwin-amd64/ { N; s/sha256 \".*\"/sha256 \"${AMD64_SHA}\"/; }" "${FORMULA}"
sed -i '' "s/download\/v.*\/locksmith-darwin-amd64/download\/v${VERSION}\/locksmith-darwin-amd64/" "${FORMULA}"

rm -rf "${TMPDIR}"

echo "==> Done. ${FORMULA} updated."

if [ -d "${TAP_DIR}" ]; then
    echo "==> Syncing to local tap repo: ${TAP_DIR}"
    cp "${FORMULA}" "${TAP_DIR}/Formula/locksmith.rb"
    echo "  Success. Run 'git -C ${TAP_DIR} commit -am \"feat: update to v${VERSION}\" && git -C ${TAP_DIR} push' to publish."
else
    echo "==> Local tap repo not found at ${TAP_DIR}. Skipping sync."
fi
