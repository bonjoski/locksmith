#!/usr/bin/env bash
set -euo pipefail

# CI policy:
# - Fail on any symbol-level vulnerabilities (code is affected).
# - Fail on any package-level vulnerabilities (imported package affected).
# - Allow known module-only advisories that are not called by code.

ALLOWLISTED_SYMBOL_VULNS=(
  "GO-2026-6218"
  "GO-2026-6090"
  "GO-2026-5972"
  "GO-2026-5026"
)

ALLOWLISTED_PACKAGE_VULNS=(
  "GO-2026-6089"
  "GO-2026-5942"
)

ALLOWLISTED_MODULE_VULNS=(
  "GO-2026-5932"
  "GO-2026-6091"
  "GO-2026-6088"
)

GOVULNCHECK_BIN="${GOVULNCHECK_BIN:-govulncheck}"
SCAN_ARGS=("-show" "verbose" "-tags" "locksmith_admin" "./...")

echo "Running govulncheck guard..."
# Capture govulncheck output without tripping `set -e` on non-zero exits.
set +e
output="$(${GOVULNCHECK_BIN} "${SCAN_ARGS[@]}" 2>&1)"
status=$?
set -e

# Always print scanner output for debugging in CI logs.
printf '%s\n' "$output"

# Allow exit status 3 (vulnerabilities found), but fail on other non-zero exits
if [[ $status -ne 0 && $status -ne 3 ]]; then
  echo "govulncheck exited with error status: ${status}"
  exit $status
fi

# Function to extract vulnerability IDs for a section
extract_vulns_for_section() {
  local section="$1"
  (
    set +o pipefail
    printf '%s\n' "$output" | awk -v sec="$section" '
      $0 ~ "^=== " sec " ===$" {in_sec=1; next}
      /^=== / {in_sec=0}
      /^Your code is affected by/ {in_sec=0}
      in_sec {print}
    ' | grep -Eo 'GO-[0-9]{4}-[0-9]+' | sort -u
  )
}

check_disallowed() {
  local ids=($1)
  shift
  local allowlist=("$@")
  local disallowed=()
  for id in "${ids[@]}"; do
    local allowed=0
    for allowed_id in "${allowlist[@]}"; do
      if [[ "$id" == "$allowed_id" ]]; then
        allowed=1
        break
      fi
    done
    if [[ $allowed -eq 0 ]]; then
      disallowed+=("$id")
    fi
  done
  if [[ ${#disallowed[@]} -gt 0 ]]; then
    echo "${disallowed[@]}"
  fi
}

# Extract vulnerabilities per section
symbol_ids=$(extract_vulns_for_section "Symbol Results")
package_ids=$(extract_vulns_for_section "Package Results")
module_ids=$(extract_vulns_for_section "Module Results")

disallowed_symbols=$(check_disallowed "$symbol_ids" "${ALLOWLISTED_SYMBOL_VULNS[@]}")
disallowed_packages=$(check_disallowed "$package_ids" "${ALLOWLISTED_PACKAGE_VULNS[@]}")
disallowed_modules=$(check_disallowed "$module_ids" "${ALLOWLISTED_MODULE_VULNS[@]}")

failed=0

if [[ -n "$disallowed_symbols" ]]; then
  echo "Failing: disallowed symbol vulnerabilities found: $disallowed_symbols"
  failed=1
fi

if [[ -n "$disallowed_packages" ]]; then
  echo "Failing: disallowed package vulnerabilities found: $disallowed_packages"
  failed=1
fi

if [[ -n "$disallowed_modules" ]]; then
  echo "Failing: disallowed module vulnerabilities found: $disallowed_modules"
  failed=1
fi

if [[ $failed -eq 1 ]]; then
  exit 1
fi

echo "govulncheck guard passed: all reported vulnerabilities are allowlisted."
exit 0
