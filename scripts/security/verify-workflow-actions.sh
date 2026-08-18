#!/usr/bin/env bash
set -euo pipefail

echo "Verifying GitHub Actions commit SHAs..."

# Check if curl is available
if ! command -v curl >/dev/null 2>&1; then
  echo "curl not found, skipping remote SHA validation"
  exit 0
fi

# Check for internet connectivity by pinging/curling github.com briefly
if ! curl -I -s --connect-timeout 2 "https://github.com" >/dev/null 2>&1; then
  echo "Offline or github.com unreachable, skipping remote SHA validation"
  exit 0
fi

FAILED=0

# Find all workflow files
for workflow in .github/workflows/*.yml; do
  [ -e "$workflow" ] || continue
  
  # Find all uses: statements
  # Format: uses: owner/repo@sha
  # Exclude local actions (starting with ./)
  while read -r line; do
    # Extract owner/repo@sha
    action=$(echo "$line" | sed -E 's/.*uses:[[:space:]]*//; s/[[:space:]]*#.*//')
    
    # Skip local actions or docker actions
    if [[ "$action" =~ ^\./ ]] || [[ "$action" =~ ^docker:// ]]; then
      continue
    fi
    
    # Check if it has a @
    if [[ "$action" != *@* ]]; then
      continue
    fi
    
    repo_part="${action%%@*}"
    sha_part="${action##*@}"
    
    # Only verify 40-character hex SHAs
    if [[ ! "$sha_part" =~ ^[0-9a-fA-F]{40}$ ]]; then
      continue
    fi
    
    echo "Checking $repo_part @ $sha_part..."
    
    # Query GitHub commit page to verify the commit exists
    STATUS_CODE=$(curl -s -o /dev/null -I -w "%{http_code}" --connect-timeout 5 "https://github.com/${repo_part}/commit/${sha_part}")
    
    if [ "$STATUS_CODE" -ne 200 ]; then
      echo "❌ Invalid SHA: $sha_part does not exist in repository $repo_part (HTTP status: $STATUS_CODE)"
      FAILED=1
    else
      echo "✅ Valid"
    fi
  done < <(grep -E '^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+@' "$workflow")
done

if [ "$FAILED" -ne 0 ]; then
  echo "Error: One or more GitHub Actions commit SHAs are invalid."
  exit 1
fi

echo "All action commit SHAs verified successfully!"
