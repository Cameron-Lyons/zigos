#!/usr/bin/env bash
set -eu

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

KERNEL_PATH="${1:?kernel path required}"
LOG_PATH="${2:?serial log path required}"
SUMMARY_PATH="${3:-}"

mkdir -p "$(dirname "$LOG_PATH")"
rm -f "$LOG_PATH"
if [ -n "$SUMMARY_PATH" ]; then
  rm -f "$SUMMARY_PATH"
fi

QEMU_SERIAL_TARGET="file:$LOG_PATH" bash "$ROOT_DIR/scripts/run-headless-qemu.sh" "$KERNEL_PATH"

if [ ! -s "$LOG_PATH" ]; then
  echo "Kernel benchmark capture failed: no serial output captured" >&2
  exit 1
fi

for marker in \
  "BOOT:START" \
  "BOOT:PROFILE:benchmark" \
  "BOOT:ROLE:verification" \
  "ZIGOS:CPU:BASELINE:MODERN_X86_64:READY" \
  "BOOT:CORE_READY" \
  "BENCH:START" \
  "BENCH:QUALITY_SUMMARY" \
  "BENCH:SUMMARY" \
  "BENCH:PASS"
do
  if ! grep -Fq "$marker" "$LOG_PATH"; then
    echo "Kernel benchmark capture failed: missing marker '$marker'" >&2
    cat "$LOG_PATH" >&2
    exit 1
  fi
done

if grep -Eqi "panic|KERNEL PANIC|System Halted|BENCH:FAIL" "$LOG_PATH"; then
  echo "Kernel benchmark capture failed: panic or failure marker found" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

echo "Kernel benchmark capture complete. Run the typed benchmark gate through './scripts/zig.sh build benchmark'. Log: $LOG_PATH"
