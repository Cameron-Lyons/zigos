#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"

# shellcheck source=scripts/qemu-harness.sh
source "$ROOT_DIR/scripts/qemu-harness.sh"

kernel_path="${1:?kernel path required}"
memory_size="${2:-$(qemu_harness_profile_memory)}"
serial_target="${3:-${QEMU_SERIAL_TARGET:-stdio}}"

qemu_harness_run_kernel "$kernel_path" "$serial_target" "$memory_size"
