#!/usr/bin/env bash
set -eu

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

ZIG="${ROOT_DIR}/scripts/zig.sh"

mkdir -p build/zig-cache-host-tests build/zig-global-cache-host-tests
export ZIG_LOCAL_CACHE_DIR="build/zig-cache-host-tests"
export ZIG_GLOBAL_CACHE_DIR="build/zig-global-cache-host-tests"

"$ZIG" test src/native_host_test.zig
