#!/usr/bin/env bash
set -euo pipefail

WORKFLOWS_DIR=".github/workflows"
ERRORS=0

fail() {
  echo "ERROR: $1" >&2
  ERRORS=$((ERRORS + 1))
}

# 1. All github/codeql-action/* steps within the same file must use the same commit SHA.
for file in "$WORKFLOWS_DIR"/*.yml; do
  [[ -f "$file" ]] || continue
  shas=$(grep -oE 'github/codeql-action/[^@]+@([a-f0-9]{40})' "$file" \
    | grep -oE '[a-f0-9]{40}$' | sort -u || true)
  [[ -z "$shas" ]] && continue
  count=$(echo "$shas" | wc -l | tr -d ' ')
  if [[ "$count" -gt 1 ]]; then
    fail "$file: mismatched codeql-action SHAs — all init/analyze/autobuild steps must pin the same commit"
  fi
done

# 2. All action uses: lines must be SHA-pinned (40-char hex), not tag-only.
#    Skips local path actions (uses: ./.github/...) and docker actions.
for file in "$WORKFLOWS_DIR"/*.yml; do
  [[ -f "$file" ]] || continue
  uses_lines=$(grep -E '^\s+uses: [^.][^/]' "$file" | grep -v 'uses: docker://' || true)
  [[ -z "$uses_lines" ]] && continue
  while IFS= read -r line; do
    ref=$(echo "$line" | grep -oE '@[^ #]+' | head -1 | tr -d '@' || true)
    [[ -z "$ref" ]] && continue
    if [[ "$ref" =~ ^[a-f0-9]{40}$ ]]; then
      continue
    fi
    action=$(echo "$line" | grep -oE 'uses: [^ ]+' | sed 's/uses: //' || true)
    fail "$file: unpinned action '$action' — must use a full commit SHA, not a tag"
  done <<< "$uses_lines"
done

# 3. Any ubuntu-latest job that calls apt-get must redirect the azure mirror first.
for file in "$WORKFLOWS_DIR"/*.yml; do
  [[ -f "$file" ]] || continue
  grep -q 'ubuntu-latest' "$file" || continue
  grep -q 'apt-get' "$file" || continue
  redirect_line=$(grep -n 'azure.archive.ubuntu.com' "$file" | head -1 | cut -d: -f1 || true)
  apt_line=$(grep -n 'apt-get' "$file" | head -1 | cut -d: -f1 || true)
  if [[ -z "$redirect_line" ]]; then
    fail "$file: uses apt-get on ubuntu-latest but is missing the azure mirror redirect before apt-get update"
  elif [[ -n "$apt_line" && "$redirect_line" -gt "$apt_line" ]]; then
    fail "$file: azure mirror redirect (line $redirect_line) appears after apt-get call (line $apt_line) — must come first"
  fi
done

if [[ "$ERRORS" -gt 0 ]]; then
  echo ""
  echo "workflow validation failed with $ERRORS error(s)" >&2
  exit 1
fi

echo "All workflow checks passed."
