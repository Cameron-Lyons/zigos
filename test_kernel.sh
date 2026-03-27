#!/usr/bin/env bash

set -euo pipefail

echo "Running native smoke boot..."
zig build zigos-native-smoke-test
