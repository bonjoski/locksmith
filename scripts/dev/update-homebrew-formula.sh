#!/bin/bash
# Script to auto-update Homebrew formula with latest release checksums
# Usage: ./scripts/dev/update-homebrew-formula.sh <version>

set -euo pipefail

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    exit 1
fi

# Remove leading 'v' if present
VERSION="${VERSION#v}"
FORMULA_FILE="contrib/homebrew/locksmith.rb"

echo "Updating Homebrew formula to version $VERSION..."

# Download the release checksums
TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

echo "Fetching checksums from GitHub..."
gh release download "v$VERSION" --pattern "checksums.txt" --dir "$TMP_DIR" --repo bonjoski/locksmith || {
    echo "ERROR: Failed to download checksums for v$VERSION"
    exit 1
}

CHECKSUMS_FILE="$TMP_DIR/checksums.txt"

# Extract the checksums we need
LOCKSMITH_ARM64_SHA=$(grep "locksmith-darwin-arm64" "$CHECKSUMS_FILE" | awk '{print $1}')
LOCKSMITH_AMD64_SHA=$(grep "locksmith-darwin-amd64" "$CHECKSUMS_FILE" | awk '{print $1}')
SUMMON_ARM64_SHA=$(grep "summon-locksmith-darwin-arm64" "$CHECKSUMS_FILE" | awk '{print $1}')
SUMMON_AMD64_SHA=$(grep "summon-locksmith-darwin-amd64" "$CHECKSUMS_FILE" | awk '{print $1}')

if [ -z "$LOCKSMITH_ARM64_SHA" ] || [ -z "$LOCKSMITH_AMD64_SHA" ] || [ -z "$SUMMON_ARM64_SHA" ] || [ -z "$SUMMON_AMD64_SHA" ]; then
    echo "ERROR: Could not extract all checksums from release"
    exit 1
fi

echo "Checksums extracted:"
echo "  locksmith-darwin-arm64: $LOCKSMITH_ARM64_SHA"
echo "  locksmith-darwin-amd64: $LOCKSMITH_AMD64_SHA"
echo "  summon-darwin-arm64: $SUMMON_ARM64_SHA"
echo "  summon-darwin-amd64: $SUMMON_AMD64_SHA"

# Update the formula file with sed
echo "Updating $FORMULA_FILE..."

# Update version
sed -i '' "s/version \"[^\"]*\"/version \"$VERSION\"/" "$FORMULA_FILE"

# Update download URLs and checksums for locksmith-darwin-arm64
sed -i '' "s|download/v[^/]*/locksmith-darwin-arm64|download/v$VERSION/locksmith-darwin-arm64|" "$FORMULA_FILE"
sed -i '' "/url.*locksmith-darwin-arm64/ { N; s/sha256 \"[^\"]*\"/sha256 \"$LOCKSMITH_ARM64_SHA\"/; }" "$FORMULA_FILE"

# Update download URLs and checksums for locksmith-darwin-amd64
sed -i '' "s|download/v[^/]*/locksmith-darwin-amd64|download/v$VERSION/locksmith-darwin-amd64|" "$FORMULA_FILE"
sed -i '' "/url.*locksmith-darwin-amd64/ { N; s/sha256 \"[^\"]*\"/sha256 \"$LOCKSMITH_AMD64_SHA\"/; }" "$FORMULA_FILE"

# Update download URLs and checksums for summon-locksmith-darwin-arm64
sed -i '' "s|download/v[^/]*/summon-locksmith-darwin-arm64|download/v$VERSION/summon-locksmith-darwin-arm64|" "$FORMULA_FILE"
sed -i '' "/url.*summon-locksmith-darwin-arm64/ { N; s/sha256 \"[^\"]*\"/sha256 \"$SUMMON_ARM64_SHA\"/; }" "$FORMULA_FILE"

# Update download URLs and checksums for summon-locksmith-darwin-amd64
sed -i '' "s|download/v[^/]*/summon-locksmith-darwin-amd64|download/v$VERSION/summon-locksmith-darwin-amd64|" "$FORMULA_FILE"
sed -i '' "/url.*summon-locksmith-darwin-amd64/ { N; s/sha256 \"[^\"]*\"/sha256 \"$SUMMON_AMD64_SHA\"/; }" "$FORMULA_FILE"

echo "✅ Homebrew formula updated successfully"
