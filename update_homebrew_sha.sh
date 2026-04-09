#!/usr/bin/env bash
# update_homebrew_sha.sh
# Run this AFTER the v2.2.5 GitHub release artifacts are published.
# It fetches the arm64 and amd64 binaries, computes their SHA256,
# and patches Formula/locksmith.rb in place.
#
# Usage: bash update_homebrew_sha.sh

set -euo pipefail

VERSION="2.2.5"
REPO="bonjoski/locksmith"
FORMULA="Formula/locksmith.rb"
TMPDIR=$(mktemp -d)

echo "==> Downloading locksmith ${VERSION} binaries..."

ARM64_URL="https://github.com/${REPO}/releases/download/v${VERSION}/locksmith-darwin-arm64"
AMD64_URL="https://github.com/${REPO}/releases/download/v${VERSION}/locksmith-darwin-amd64"

curl -fsSL -o "${TMPDIR}/locksmith-darwin-arm64" "${ARM64_URL}"
curl -fsSL -o "${TMPDIR}/locksmith-darwin-amd64" "${AMD64_URL}"

ARM64_SHA=$(shasum -a 256 "${TMPDIR}/locksmith-darwin-arm64" | awk '{print $1}')
AMD64_SHA=$(shasum -a 256 "${TMPDIR}/locksmith-darwin-amd64" | awk '{print $1}')

echo "  arm64 SHA256: ${ARM64_SHA}"
echo "  amd64 SHA256: ${AMD64_SHA}"

echo "==> Patching ${FORMULA}..."

sed -i '' "s/REPLACE_WITH_ARM64_SHA256/${ARM64_SHA}/" "${FORMULA}"
sed -i '' "s/REPLACE_WITH_AMD64_SHA256/${AMD64_SHA}/" "${FORMULA}"

rm -rf "${TMPDIR}"

echo "==> Done. ${FORMULA} updated with real SHA256 hashes."
echo ""
echo "Next steps:"
echo "  1. Copy Formula/locksmith.rb to your homebrew-tap repo"
echo "  2. git add Formula/locksmith.rb && git commit -m 'feat: add locksmith v${VERSION}' && git push"
echo "  3. Users can then: brew tap bonjoski/locksmith && brew install locksmith"
