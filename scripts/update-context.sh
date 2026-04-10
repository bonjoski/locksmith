#!/usr/bin/env bash
# scripts/update-context.sh
# Automates the synchronization of the codebase state with the .memory documentation.

set -e

MEMORY_DIR=".memory"
TECH_STACK="$MEMORY_DIR/tech-stack.md"
CONTEXT="$MEMORY_DIR/context.md"

echo "==> [Context Agent] Updating technical documentation..."

# 1. Update Tech Stack from go.mod
GO_VERSION=$(grep -E "^go [0-9.]+" go.mod | awk '{print $2}')
if [ -n "$GO_VERSION" ]; then
    sed -i '' "s/Go (v.*)/Go (v$GO_VERSION)/" "$TECH_STACK"
fi

# 2. Extract top-level dependencies (excluding indirects)
DEPENDENCIES=$(grep -E "^\t[a-zA-Z0-9./-]+" go.mod | grep -v "indirect" | awk '{print "- **" $1 "**"}' | sort | uniq)
# We use a marker in the file to replace dependencies
# For now, we'll just log what we found
echo "Found dependencies: $DEPENDENCIES"

# 3. Update Context from Git History
# We skip this if --structural-only is passed (used for CI freshness checks)
if [[ "$1" == "--structural-only" ]]; then
    echo "Skipping git history update (structural-only mode)..."
else
    RECENT_COMMITS=$(git log -n 5 --pretty=format:"- %s" || echo "- No recent commits found")
    # Update the "Recent Changes" section in context.md
    # This is a bit complex with sed, so we'll do a simple replacement of a block
    perl -0777 -i -pe 's/(## Recent Changes\n)(.*?\n)(##)/$1 . "'"$RECENT_COMMITS"'" . "\n\n$3"/se' "$CONTEXT"
fi

# 4. Update Open Tasks in Context
# Move completed tasks to recent changes if needed, but for now we'll just keep it manual
# or sync from task.md if available.

echo "✓ Documentation sync complete."
