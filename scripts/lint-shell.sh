#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v shellcheck >/dev/null 2>&1; then
  echo "shellcheck is required. Install it locally or run this in CI." >&2
  exit 1
fi

shell_files=(
  "run.sh"
  "test_kernel.sh"
  "scripts/build-native-store.sh"
  "scripts/lint-shell.sh"
  "scripts/check-kernel-benchmark-baseline.sh"
  "scripts/check-kernel-benchmark-thresholds.sh"
  "scripts/render-kernel-benchmark-summary.sh"
  "scripts/run-host-tests.sh"
  "scripts/run-kernel-benchmark.sh"
  "scripts/run-spec-conformance.sh"
  "scripts/run-zigos-native-smoke.sh"
  "scripts/zig.sh"
)

shellcheck --shell=bash "${shell_files[@]}"
