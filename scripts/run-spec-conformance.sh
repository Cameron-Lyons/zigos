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
