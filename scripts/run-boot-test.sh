#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"

# shellcheck source=scripts/qemu-harness.sh
source "$ROOT_DIR/scripts/qemu-harness.sh"

ISO_PATH="${1:?iso path required}"
LOG_PATH="${2:?serial log path required}"
BOOT_TEST_SECONDS="${BOOT_TEST_SECONDS:-12}"

mkdir -p "$(dirname "$LOG_PATH")"
rm -f "$LOG_PATH"

qemu_harness_run_cdrom_for_seconds "$ISO_PATH" "$LOG_PATH" "$BOOT_TEST_SECONDS"

if [ ! -s "$LOG_PATH" ]; then
  echo "Boot test failed: no serial output at $LOG_PATH" >&2
  exit 1
fi

for marker in "Welcome to Zigos" "A minimal operating system written in Zig" "Initializing GDT"; do
  if ! grep -Fq "$marker" "$LOG_PATH"; then
    echo "Boot test failed: missing marker '$marker'" >&2
    cat "$LOG_PATH" >&2
    exit 1
  fi
done

WELCOME_LINE="$(grep -n "Welcome to Zigos" "$LOG_PATH" | head -n1 | cut -d: -f1)"
MINIMAL_LINE="$(grep -n "A minimal operating system written in Zig" "$LOG_PATH" | head -n1 | cut -d: -f1)"
GDT_LINE="$(grep -n "Initializing GDT" "$LOG_PATH" | head -n1 | cut -d: -f1)"
if [ "$MINIMAL_LINE" -le "$WELCOME_LINE" ] || [ "$GDT_LINE" -le "$MINIMAL_LINE" ]; then
  echo "Boot test failed: boot markers are out of order" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

if grep -Eqi "panic|KERNEL PANIC|System Halted" "$LOG_PATH"; then
  echo "Boot test failed: panic marker found in boot log" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

echo "Boot test passed. Log: $LOG_PATH"
