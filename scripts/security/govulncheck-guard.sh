#!/usr/bin/env bash
set -euo pipefail

# CI policy:
# - Fail on any symbol-level vulnerabilities (code is affected).
# - Fail on any package-level vulnerabilities (imported package affected).
# - Allow known module-only advisories that are not called by code.

ALLOWLISTED_MODULE_VULNS=(
  "GO-2026-5932"
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

if [[ $status -ne 0 ]]; then
  echo "govulncheck exited with non-zero status: ${status}"
  exit $status
fi

symbol_count="$(printf '%s\n' "$output" | awk '/^Your code is affected by [0-9]+ vulnerabilities\./ {print $6; exit}')"
if [[ -z "$symbol_count" ]]; then
  symbol_count=0
fi

summary_line="$(printf '%s\n' "$output" | grep -E '^This scan also found [0-9]+ vulnerabilities? in packages you import and [0-9]+ vulnerabilities? in modules you require' || true)"
package_count=0
if [[ -n "$summary_line" ]]; then
  package_count="$(printf '%s\n' "$summary_line" | awk '{print $5}')"
fi

if [[ "$symbol_count" -gt 0 ]]; then
  echo "Failing: actionable symbol vulnerabilities found: ${symbol_count}"
  exit 1
fi

if [[ "$package_count" -gt 0 ]]; then
  echo "Failing: package vulnerabilities found in imported packages: ${package_count}"
  exit 1
fi

module_section="$(printf '%s\n' "$output" | awk '
  /^=== Module Results ===$/ {in_module=1; next}
  /^Your code is affected by/ {in_module=0}
  in_module {print}
')"

module_ids=()
while IFS= read -r id; do
  if [[ -n "$id" ]]; then
    module_ids+=("$id")
  fi
done < <(printf '%s\n' "$module_section" | grep -Eo 'GO-[0-9]{4}-[0-9]+' | sort -u || true)

if [[ ${#module_ids[@]} -eq 0 ]]; then
  echo "govulncheck guard passed: no module vulnerabilities reported."
  exit 0
fi

disallowed=()
for id in "${module_ids[@]}"; do
  allowed=0
  for allowed_id in "${ALLOWLISTED_MODULE_VULNS[@]}"; do
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
  echo "Failing: disallowed module vulnerabilities found: ${disallowed[*]}"
  exit 1
fi

echo "govulncheck guard passed: only allowlisted module-only advisories remain: ${module_ids[*]}"
