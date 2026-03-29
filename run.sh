#!/usr/bin/env bash

set -euo pipefail

exec "$(dirname "$0")/scripts/zig.sh" build run "$@"
