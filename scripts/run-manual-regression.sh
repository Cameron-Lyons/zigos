#!/usr/bin/env bash
set -eu

KERNEL_PATH="${1:?kernel path required}"
IMAGE_PATH="${2:?rootfs image path required}"
LOG_PATH="${3:?serial log path required}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
MANUAL_REGRESSION_SECONDS="${MANUAL_REGRESSION_SECONDS:-30}"

if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
  echo "QEMU binary '$QEMU_BIN' not found. Set QEMU_BIN or install QEMU." >&2
  exit 1
fi

mkdir -p "$(dirname "$LOG_PATH")"
rm -f "$LOG_PATH"

QEMU_BIN="$QEMU_BIN" \
QEMU_EXTRA_ARGS="-drive file=$IMAGE_PATH,if=ide,format=raw,id=disk0" \
  bash scripts/run-headless-qemu.sh "$KERNEL_PATH" "256M" "file:$LOG_PATH" >/dev/null 2>&1 &
QEMU_PID=$!

TIMED_OUT=0
ELAPSED=0
while kill -0 "$QEMU_PID" >/dev/null 2>&1; do
  if [ "$ELAPSED" -ge "$MANUAL_REGRESSION_SECONDS" ]; then
    TIMED_OUT=1
    kill -TERM "$QEMU_PID" >/dev/null 2>&1 || true
    sleep 1
    kill -KILL "$QEMU_PID" >/dev/null 2>&1 || true
    break
  fi
  sleep 1
  ELAPSED=$((ELAPSED + 1))
done
wait "$QEMU_PID" >/dev/null 2>&1 || true

if [ ! -s "$LOG_PATH" ]; then
  echo "Manual regression test failed: no serial output captured" >&2
  exit 1
fi

if [ "$TIMED_OUT" -eq 1 ] && ! grep -Fq "MANUAL:PASS" "$LOG_PATH"; then
  echo "Manual regression test failed: QEMU timed out after ${MANUAL_REGRESSION_SECONDS}s before MANUAL:PASS" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

for marker in \
  "BOOT:START" \
  "BOOT:PROFILE:manual_regression" \
  "Disk root mounted at /" \
  "BOOT:CORE_READY" \
  "MANUAL:START" \
  "MANUAL:FILEIO:START" \
  "MANUAL:FILEIO:PASS" \
  "MANUAL:TCP:START" \
  "MANUAL:TCP:PASS" \
  "MANUAL:SYNC:START" \
  "MANUAL:SYNC:PASS" \
  "MANUAL:IPC:START" \
  "MANUAL:IPC:PASS" \
  "MANUAL:PASS"
do
  if ! grep -Fq "$marker" "$LOG_PATH"; then
    echo "Manual regression test failed: missing marker '$marker'" >&2
    cat "$LOG_PATH" >&2
    exit 1
  fi
done

if grep -Eqi "panic|KERNEL PANIC|System Halted|MANUAL:FAIL|MANUAL:FILEIO:FAIL|MANUAL:TCP:FAIL|MANUAL:SYNC:FAIL|MANUAL:IPC:FAIL" "$LOG_PATH"; then
  echo "Manual regression test failed: panic or failure marker found" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

echo "Manual regression test passed. Log: $LOG_PATH"
