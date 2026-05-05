#!/usr/bin/env bash
set -euo pipefail

if ! command -v actionlint >/dev/null 2>&1; then
  if [[ "${ZIGOS_REQUIRE_ACTIONLINT:-0}" == "1" ]]; then
    echo "actionlint is required but was not found. Install actionlint or unset ZIGOS_REQUIRE_ACTIONLINT." >&2
    exit 1
  fi
  echo "actionlint not found; skipping optional GitHub workflow lint. Set ZIGOS_REQUIRE_ACTIONLINT=1 to make this mandatory." >&2
  exit 0
fi

actionlint
