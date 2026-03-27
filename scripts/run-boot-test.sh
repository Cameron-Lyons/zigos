#!/usr/bin/env bash
set -eu

ISO_PATH="${1:?iso path required}"
LOG_PATH="${2:?serial log path required}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
BOOT_TEST_SECONDS="${BOOT_TEST_SECONDS:-12}"

if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
  echo "QEMU binary '$QEMU_BIN' not found. Set QEMU_BIN or install QEMU." >&2
  exit 1
fi

mkdir -p "$(dirname "$LOG_PATH")"
rm -f "$LOG_PATH"

"$QEMU_BIN" \
  -cdrom "$ISO_PATH" \
  -boot d \
  -m 256M \
  -display none \
  -serial "file:$LOG_PATH" \
  -monitor none \
  -no-reboot \
  -no-shutdown \
  >/dev/null 2>&1 &
QEMU_PID=$!

sleep "$BOOT_TEST_SECONDS"
if kill -0 "$QEMU_PID" >/dev/null 2>&1; then
  kill -TERM "$QEMU_PID" >/dev/null 2>&1 || true
  sleep 1
  kill -KILL "$QEMU_PID" >/dev/null 2>&1 || true
fi
wait "$QEMU_PID" >/dev/null 2>&1 || true

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
