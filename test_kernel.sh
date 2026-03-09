#!/usr/bin/env bash

set -euo pipefail

readonly serial_log="serial.log"
readonly qemu_success=33
readonly qemu_failure=35

required_markers=(
    "BOOT:START"
    "BOOT:PROFILE:ci_smoke"
    "BOOT:CORE_READY"
    "BOOT:SHELL_READY"
    "BOOT:PASS"
)

echo "Building CI smoke kernel..."
zig build kernel-ci-smoke

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "Smoke boot failed: qemu-system-x86_64 is not installed"
    exit 1
fi

rm -f "$serial_log"

echo "Running QEMU smoke boot..."
set +e
timeout 20 qemu-system-x86_64 \
    -kernel zig-out/bin/kernel-ci-smoke.elf \
    -m 128M \
    -display none \
    -serial "file:$serial_log" \
    -monitor none \
    -no-reboot \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04
qemu_exit_code=$?
set -e

if [ ! -s "$serial_log" ]; then
    echo "Smoke boot failed: no serial output captured"
    exit 1
fi

echo "Serial output:"
cat "$serial_log"

if grep -Eqi "KERNEL PANIC|panic|System halted" "$serial_log"; then
    echo "Smoke boot failed: panic marker found"
    exit 1
fi

for marker in "${required_markers[@]}"; do
    if ! grep -Fq "$marker" "$serial_log"; then
        echo "Smoke boot failed: missing marker '$marker'"
        exit 1
    fi
done

case "$qemu_exit_code" in
    0)
        echo "Smoke boot passed"
        ;;
    "$qemu_success")
        echo "Smoke boot passed"
        ;;
    "$qemu_failure")
        echo "Smoke boot failed: kernel reported failure"
        exit 1
        ;;
    124)
        echo "Smoke boot failed: QEMU timed out"
        exit 1
        ;;
    *)
        echo "Smoke boot passed with QEMU exit code $qemu_exit_code"
        ;;
esac
