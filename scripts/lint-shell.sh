#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v shellcheck >/dev/null 2>&1; then
  echo "shellcheck is required. Install it locally or run this in CI." >&2
  exit 1
fi

shell_files=()
while IFS= read -r shell_file; do
  shell_files+=("$shell_file")
done < <(
  {
    find scripts -type f -name '*.sh' -print
    printf '%s\n' run.sh test_kernel.sh
  } | sort -u
)

shellcheck --shell=bash "${shell_files[@]}"
