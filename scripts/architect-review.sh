#!/usr/bin/env bash
# scripts/architect-review.sh
# Dual-Layer Review Agent: Combines Architectural Gating and Deep Security Analysis.
# Designed to run in pre-commit hooks and fail the commit/push on violations.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}==> [Architect Review Agent] Initializing Deep Analysis...${NC}"

# Define tool paths
GOBIN=$(/opt/homebrew/bin/go env GOPATH)/bin
GOCYCLO=$GOBIN/gocyclo
ENTROPY_CHECKER="go run scripts/entropy-checker/main.go"

# 1. Project Governance: Go Version consistency
GO_VERSION_EXPECTED="1.25.4"
GO_MOD_VERSION=$(grep -E "^go [0-9.]+" go.mod | awk '{print $2}')
if [[ "$GO_MOD_VERSION" != "$GO_VERSION_EXPECTED" ]]; then
    echo -e "${RED}[Architect Error]${NC} go.mod specifies Go $GO_MOD_VERSION, but project standard is $GO_VERSION_EXPECTED."
    exit 1
fi

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep ".go$" || true)
STAGED_NATIVE=$(git diff --cached --name-only --diff-filter=ACM | grep -E "(\.m|\.h)$" || true)

# 2. [Senior Architect] Internal Path Enforcement
if [[ -n "$STAGED_FILES" ]]; then
    for file in $STAGED_FILES; do
        if grep -q "github.com/bonjoski/locksmith/pkg" "$file" && ! grep -q "github.com/bonjoski/locksmith/v2/pkg" "$file"; then
            echo -e "${RED}[Architect Error]${NC} $file contains non-v2 locksmith import. All internal imports must use /v2 path."
            exit 1
        fi
    done
fi

# 3. [Security Architect] Memory Safety & Zeroing
# Heuristic check for sensitive data handling without cleanup markers
if [[ -n "$STAGED_FILES" ]]; then
    for file in $STAGED_FILES; do
        if grep -q "\[\]byte" "$file" && ! grep -E -q "defer|C.free|zero|SecureClear|memzero" "$file" && [[ "$file" == *"pkg/locksmith"* || "$file" == *"pkg/native"* ]]; then
             # Excluding simple model files that don't handle the raw key logic
             if ! grep -qE "type Secret struct|type SecretMetadata struct" "$file"; then
                echo -e "${RED}[Security Architect Error]${NC} $file handles raw []byte but no memory cleanup pattern (defer/free/zero) was detected."
                echo "Critical secrets MUST be zeroed out after use."
                exit 1
             fi
        fi
    done
fi

# 4. [Deep Agent] Native Logic Protection
# Ensure native bridge complexity stays low; complex logic belongs in Go.
if [[ -n "$STAGED_NATIVE" ]]; then
    for file in $STAGED_NATIVE; do
        LINE_COUNT=$(wc -l < "$file")
        if [ "$LINE_COUNT" -gt 350 ]; then
            echo -e "${RED}[Architect Error]${NC} Native component $file is too large ($LINE_COUNT lines). PR Policy: Keep native bridges simple; move complex logic to Go."
            exit 1
        fi
    done
fi

# 6. [Senior Architect] Cyclomatic Complexity Gate
if [[ -L "$GOCYCLO" ]] || [[ -f "$GOCYCLO" ]]; then
    if [[ -n "$STAGED_FILES" ]]; then
        echo -e "${YELLOW}==> Checking cyclomatic complexity...${NC}"
        for file in $STAGED_FILES; do
            if ! $GOCYCLO -over 15 "$file" > /dev/null; then
                echo -e "${RED}[Architect Error]${NC} $file contains functions with cyclomatic complexity > 15. Simplify the logic."
                $GOCYCLO -over 15 "$file"
                exit 1
            fi
        done
    fi
else
    echo -e "${YELLOW}[Architect Warning]${NC} gocyclo not found at $GOCYCLO. Skipping complexity gate."
fi

# 7. [Security Architect] Entropy Gate (Secret Leak Detection)
if [[ -n "$STAGED_FILES" ]]; then
    echo -e "${YELLOW}==> Scanning for high-entropy strings...${NC}"
    for file in $STAGED_FILES; do
        # Extract potential tokens (strings of chars > 20) and check entropy
        SUSPICIOUS_STRINGS=$(grep -oE "[a-zA-Z0-9+/]{20,}" "$file" || true)
        if [[ -n "$SUSPICIOUS_STRINGS" ]]; then
            if ! $ENTROPY_CHECKER 4.5 $SUSPICIOUS_STRINGS; then
                echo -e "${RED}[Security Architect Error]${NC} $file contains high-entropy strings. Possible leaked secret detected."
                exit 1
            fi
        fi
    done
fi

echo -e "${GREEN}✓ All Architectural & Security Gates Passed.${NC}"
exit 0
