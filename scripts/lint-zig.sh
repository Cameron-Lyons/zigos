#!/usr/bin/env bash
set -euo pipefail

if ! command -v zlint >/dev/null 2>&1; then
  if [[ "${ZIGOS_REQUIRE_ZLINT:-0}" == "1" ]]; then
    echo "zlint is required but was not found. Install zlint or unset ZIGOS_REQUIRE_ZLINT." >&2
    exit 1
  fi
  echo "zlint not found; skipping optional Zig lint. Set ZIGOS_REQUIRE_ZLINT=1 to make this mandatory." >&2
  exit 0
fi

set +e
lint_output="$(zlint -f github --deny-warnings src 2>&1)"
lint_status=$?
set -e

if [[ "${lint_status}" -eq 0 ]]; then
  printf '%s\n' "${lint_output}"
  exit 0
fi

if grep -q 'flag provided but not defined: -f' <<<"${lint_output}"; then
  if [[ "${ZIGOS_REQUIRE_ZLINT:-0}" == "1" ]]; then
    echo "zlint is required, but $(command -v zlint) is not the Zig source linter expected by this repo." >&2
    printf '%s\n' "${lint_output}" >&2
    exit "${lint_status}"
  fi
  echo "zlint at $(command -v zlint) is not the Zig source linter; skipping optional Zig lint. Set ZIGOS_REQUIRE_ZLINT=1 to make this mandatory." >&2
  exit 0
fi

printf '%s\n' "${lint_output}" >&2
exit "${lint_status}"
