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

# 5. [Deep Agent] Biometric Bypass Check
# Scans for sensitive calls that might have bypassed the 'useBiometrics' flag
if [[ -n "$STAGED_FILES" ]]; then
    for file in $STAGED_FILES; do
        if grep -q "native.Get" "$file" && grep -q "false" "$file" && [[ "$file" == *"pkg/locksmith"* ]]; then
             echo -e "${YELLOW}[Architect Warning]${NC} $file uses a non-biometric Get() call. Ensure this is NOT for sensitive secret retrieval."
        fi
    done
fi

echo -e "${GREEN}✓ All Architectural & Security Gates Passed.${NC}"
exit 0
