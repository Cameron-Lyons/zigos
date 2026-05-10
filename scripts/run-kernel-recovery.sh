#!/usr/bin/env bash
set -eu

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
ZIG="${ROOT_DIR}/scripts/zig.sh"
MARKER_TOOL="${ROOT_DIR}/src/print_native_smoke_markers.zig"

KERNEL_PATH="${1:?kernel path required}"
LOG_PATH="${2:?serial log path required}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"

if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
  echo "QEMU binary '$QEMU_BIN' not found. Set QEMU_BIN or install QEMU." >&2
  exit 1
fi

mkdir -p "$(dirname "$LOG_PATH")"
rm -f "$LOG_PATH"

QEMU_BIN="$QEMU_BIN" bash "$ROOT_DIR/scripts/run-headless-qemu.sh" "$KERNEL_PATH" "128M" "file:$LOG_PATH"

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
