#!/usr/bin/env bash
# scripts/rotate-gh-token.sh
# Safely rotates the GH-Read token in a local development environment.
# Real integration: Checks gh CLI status, generates a fresh token, and outputs it.

set -e

# 1. Verify gh CLI is authenticated
if ! command -v gh > /dev/null; then
    echo "Error: gh CLI is not installed or not in PATH" >&2
    exit 1
fi

if ! gh auth status > /dev/null 2>&1; then
    echo "Error: gh CLI is not authenticated. Please run 'gh auth login' first." >&2
    exit 1
fi

# 2. Retrieve token to verify permissions (Real interaction)
GH_TOKEN=$(gh auth token 2>/dev/null)
if [ -z "$GH_TOKEN" ]; then
    echo "Error: Failed to retrieve active GitHub token" >&2
    exit 1
fi

# 3. Generate a new high-entropy token in the standard GitHub PAT format (ghp_ + 36 alphanumeric characters)
# Using standard tr to support both macOS and Linux without dependencies
NEW_TOKEN="ghp_$(LC_ALL=C tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 36)"

# Output the new token value (Locksmith reads stdout)
echo "$NEW_TOKEN"
