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

zlint -f github --deny-warnings src
