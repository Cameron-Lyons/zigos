#!/usr/bin/env bash
set -eu

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

python3 tools/check_spec_coverage.py
ZIG="${ROOT_DIR}/scripts/zig.sh"

mkdir -p build/zig-cache-spec build/zig-global-cache-spec
export ZIG_LOCAL_CACHE_DIR="build/zig-cache-spec"
export ZIG_GLOBAL_CACHE_DIR="build/zig-global-cache-spec"

"$ZIG" test src/zigos_spec_test.zig

KERNEL_PATH="${1:-${ROOT_DIR}/zig-out/bin/kernel-zigos-native.elf}"
LOG_PATH="${2:-build/zigos-native-spec.log}"
NATIVE_STORE_IMAGE="${3:-build/native-store-smoke.img}"

if [ ! -f "$KERNEL_PATH" ]; then
  echo "Missing native kernel for freestanding spec verification: $KERNEL_PATH" >&2
  echo "Build \`kernel-zigos-native\` first or pass the kernel path explicitly." >&2
  exit 1
fi

bash "${ROOT_DIR}/scripts/run-zigos-native-smoke.sh" "$KERNEL_PATH" "$LOG_PATH" "$NATIVE_STORE_IMAGE"
