#!/usr/bin/env bash

set -euo pipefail

echo "Running native smoke boot..."
exec "$(dirname "$0")/scripts/zig.sh" build -Doptimize=ReleaseFast zigos-native-smoke-test "$@"
