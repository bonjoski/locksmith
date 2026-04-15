#!/usr/bin/env bash
# scripts/update-context.sh
# Automates the synchronization of the codebase state with the .memory documentation.

set -e

MEMORY_DIR=".memory"
TECH_STACK="$MEMORY_DIR/tech-stack.md"
CONTEXT="$MEMORY_DIR/context.md"

echo "==> [Context Agent] Updating technical documentation..."

# 1. Update Versions from go.mod and version.go
GO_VERSION=$(grep -E "^go [0-9.]+" go.mod | awk '{print $2}')
PROJ_VERSION=$(grep "Version =" pkg/locksmith/version.go | cut -d '"' -f 2)

echo "Go Version: $GO_VERSION"
echo "Project Version: $PROJ_VERSION"

if [ -n "$GO_VERSION" ]; then
    # Update Tech Stack
    sed -i '' "s/Go (v.*)/Go (v$GO_VERSION)/" "$TECH_STACK"
    
    # Update README.md
    sed -i '' "s/Go [0-9.]*\./Go $GO_VERSION./g" README.md
    sed -i '' "s/Go v[0-9.]*+/Go v$GO_VERSION+/g" CONTRIBUTING.md
    sed -i '' "s/Go [0-9.]*\./Go $GO_VERSION./g" SETUP.md
    
    # Update Architect Review Gate
    sed -i '' "s/GO_VERSION_EXPECTED=\".*\"/GO_VERSION_EXPECTED=\"$GO_VERSION\"/" scripts/architect-review.sh
fi

# 2. Extract top-level dependencies (excluding indirects)
DEPENDENCIES=$(grep -E "^\t[a-zA-Z0-9./-]+" go.mod | grep -v "indirect" | awk '{print "- **" $1 "**"}' | sort | uniq)
echo "Found dependencies: $DEPENDENCIES"

# 3. Update Context from Git History (from main branch)
# We skip this if --structural-only is passed (used for CI freshness checks)
if [[ "$1" == "--structural-only" ]]; then
    echo "Skipping git history update (structural-only mode)..."
else
    # Always pull recent changes from the main branch history
    RECENT_COMMITS=$(git log main -n 5 --pretty=format:"- %s" || echo "- No recent commits found on main")
    # Update the "Recent Changes" section in context.md
    perl -0777 -i -pe 's/(## Recent Changes\n)(.*?\n)(##)/$1 . "'"$RECENT_COMMITS"'" . "\n\n$3"/se' "$CONTEXT"
fi

# 4. Stage synchronization changes
echo "==> Staging documentation updates..."
git add README.md SETUP.md CONTRIBUTING.md scripts/architect-review.sh .memory/

echo "✓ Documentation sync complete."
