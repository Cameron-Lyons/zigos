#!/usr/bin/env bash
set -eu

KERNEL_PATH="${1:?kernel path required}"
LOG_PATH="${2:?serial log path required}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
SCHEDULER_REGRESSION_SECONDS="${SCHEDULER_REGRESSION_SECONDS:-20}"

if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
  echo "QEMU binary '$QEMU_BIN' not found. Set QEMU_BIN or install QEMU." >&2
  exit 1
fi

mkdir -p "$(dirname "$LOG_PATH")"
rm -f "$LOG_PATH"

QEMU_BIN="$QEMU_BIN" bash scripts/run-headless-qemu.sh "$KERNEL_PATH" "128M" "file:$LOG_PATH" >/dev/null 2>&1 &
QEMU_PID=$!

TIMED_OUT=0
ELAPSED=0
while kill -0 "$QEMU_PID" >/dev/null 2>&1; do
  if [ "$ELAPSED" -ge "$SCHEDULER_REGRESSION_SECONDS" ]; then
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
  echo "Scheduler regression test failed: no serial output captured" >&2
  exit 1
fi

if [ "$TIMED_OUT" -eq 1 ] && ! grep -Fq "SCHEDREG:PASS" "$LOG_PATH"; then
  echo "Scheduler regression test failed: QEMU timed out after ${SCHEDULER_REGRESSION_SECONDS}s before SCHEDREG:PASS" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

for marker in \
  "BOOT:START" \
  "BOOT:PROFILE:scheduler_regression" \
  "BOOT:CORE_READY" \
  "SCHEDREG:START" \
  "SCHEDREG:DEMO:START" \
  "SCHEDREG:DEMO:PASS" \
  "SCHEDREG:PROCMON:START" \
  "SCHEDREG:PROCMON:PASS" \
  "SCHEDREG:PASS"
do
  if ! grep -Fq "$marker" "$LOG_PATH"; then
    echo "Scheduler regression test failed: missing marker '$marker'" >&2
    cat "$LOG_PATH" >&2
    exit 1
  fi
done

if grep -Eqi "panic|KERNEL PANIC|System Halted|SCHEDREG:FAIL|SCHEDREG:DEMO:FAIL|SCHEDREG:PROCMON:FAIL" "$LOG_PATH"; then
  echo "Scheduler regression test failed: panic or failure marker found" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

echo "Scheduler regression test passed. Log: $LOG_PATH"
