#!/usr/bin/env bash

set -euo pipefail

readonly qemu_debug_exit_device="isa-debug-exit,iobase=0xf4,iosize=0x04"
readonly qemu_binary="${QEMU_BIN:-qemu-system-x86_64}"
readonly qemu_success_status=0x10
readonly qemu_success_exit=$(((qemu_success_status << 1) | 1))

kernel_path="${1:?kernel path required}"
memory_size="${2:-128M}"
serial_target="${3:-stdio}"
extra_args=()

if [ -n "${QEMU_EXTRA_ARGS:-}" ]; then
    read -r -a extra_args <<< "${QEMU_EXTRA_ARGS}"
fi

set +e
"$qemu_binary" \
    -kernel "$kernel_path" \
    -m "$memory_size" \
    -display none \
    -serial "$serial_target" \
    -monitor none \
    -no-reboot \
    -device "$qemu_debug_exit_device" \
    "${extra_args[@]}"
qemu_exit_code=$?
set -e

case "$qemu_exit_code" in
    0|"$qemu_success_exit")
        exit 0
        ;;
    *)
        exit "$qemu_exit_code"
        ;;
esac
