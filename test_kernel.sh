#!/usr/bin/env bash

set -euo pipefail

echo "Running native smoke boot..."
zig build -Doptimize=ReleaseFast zigos-native-smoke-test
