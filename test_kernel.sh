#!/usr/bin/env bash

set -euo pipefail

readonly serial_log="serial.log"

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
timeout 20 bash scripts/run-headless-qemu.sh \
    zig-out/bin/kernel-ci-smoke.elf \
    128M \
    "file:$serial_log"
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
    124)
        echo "Smoke boot failed: QEMU timed out"
        exit 1
        ;;
    *)
        echo "Smoke boot failed: QEMU exited with code $qemu_exit_code"
        exit 1
        ;;
esac
