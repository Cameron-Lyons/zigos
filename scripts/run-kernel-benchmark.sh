#!/usr/bin/env bash
set -eu

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

KERNEL_PATH="${1:?kernel path required}"
LOG_PATH="${2:?serial log path required}"

mkdir -p "$(dirname "$LOG_PATH")"
rm -f "$LOG_PATH"

QEMU_SERIAL_TARGET="file:$LOG_PATH" bash "$ROOT_DIR/scripts/run-headless-qemu.sh" "$KERNEL_PATH"

if [ ! -s "$LOG_PATH" ]; then
  echo "Kernel benchmark test failed: no serial output captured" >&2
  exit 1
fi

for marker in \
  "BOOT:START" \
  "BOOT:PROFILE:benchmark" \
  "BOOT:CORE_READY" \
  "BENCH:START" \
  "BENCH:QUALITY_SUMMARY" \
  "BENCH:SUMMARY" \
  "BENCH:PASS"
do
  if ! grep -Fq "$marker" "$LOG_PATH"; then
    echo "Kernel benchmark test failed: missing marker '$marker'" >&2
    cat "$LOG_PATH" >&2
    exit 1
  fi
done

if grep -Eqi "panic|KERNEL PANIC|System Halted|BENCH:FAIL" "$LOG_PATH"; then
  echo "Kernel benchmark test failed: panic or benchmark failure marker found" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

bash "$ROOT_DIR/scripts/check-kernel-benchmark-thresholds.sh" "$LOG_PATH"
bash "$ROOT_DIR/scripts/check-kernel-benchmark-quality-gates.sh" "$LOG_PATH"
bash "$ROOT_DIR/scripts/check-kernel-benchmark-baseline.sh" "$LOG_PATH"
echo "Kernel benchmark run passed. Log: $LOG_PATH"
