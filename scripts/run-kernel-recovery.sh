#!/usr/bin/env bash
set -eu

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
ZIG="${ROOT_DIR}/scripts/zig.sh"
MARKER_TOOL="${ROOT_DIR}/src/print_native_smoke_markers.zig"

KERNEL_PATH="${1:?kernel path required}"
LOG_PATH="${2:?serial log path required}"

mkdir -p "$(dirname "$LOG_PATH")"
rm -f "$LOG_PATH"

QEMU_SERIAL_TARGET="file:$LOG_PATH" bash "$ROOT_DIR/scripts/run-headless-qemu.sh" "$KERNEL_PATH"

if [ ! -s "$LOG_PATH" ]; then
  echo "Kernel recovery test failed: no serial output captured" >&2
  exit 1
fi

while IFS= read -r marker; do
  [ -n "$marker" ] || continue
  if ! grep -Fq "$marker" "$LOG_PATH"; then
    echo "Kernel recovery test failed: missing marker '$marker'" >&2
    cat "$LOG_PATH" >&2
    exit 1
  fi
done < <("$ZIG" run "$MARKER_TOOL" -- recovery)

if grep -Eqi "panic|KERNEL PANIC|System Halted|RECOVERY:FAIL" "$LOG_PATH"; then
  echo "Kernel recovery test failed: panic or recovery failure marker found" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

echo "Kernel recovery run passed. Log: $LOG_PATH"
