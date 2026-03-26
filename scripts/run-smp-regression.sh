#!/usr/bin/env bash
set -eu

KERNEL_PATH="${1:?kernel path required}"
LOG_PATH="${2:?serial log path required}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
SMP_REGRESSION_SECONDS="${SMP_REGRESSION_SECONDS:-20}"

if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
  echo "QEMU binary '$QEMU_BIN' not found. Set QEMU_BIN or install QEMU." >&2
  exit 1
fi

mkdir -p "$(dirname "$LOG_PATH")"
rm -f "$LOG_PATH"

QEMU_BIN="$QEMU_BIN" QEMU_EXTRA_ARGS="-cpu qemu64 -smp 2" \
  bash scripts/run-headless-qemu.sh "$KERNEL_PATH" "256M" "file:$LOG_PATH" >/dev/null 2>&1 &
QEMU_PID=$!

TIMED_OUT=0
ELAPSED=0
while kill -0 "$QEMU_PID" >/dev/null 2>&1; do
  if [ "$ELAPSED" -ge "$SMP_REGRESSION_SECONDS" ]; then
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
  echo "SMP regression test failed: no serial output captured" >&2
  exit 1
fi

if [ "$TIMED_OUT" -eq 1 ] && ! grep -Fq "SMPREG:PASS" "$LOG_PATH"; then
  echo "SMP regression test failed: QEMU timed out after ${SMP_REGRESSION_SECONDS}s before SMPREG:PASS" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

for marker in \
  "BOOT:START" \
  "BOOT:PROFILE:smp_regression" \
  "BOOT:CORE_READY" \
  "SMPREG:START" \
  "SMPREG:ACTIVE_CPUS:" \
  "SMPREG:PASS"
do
  if ! grep -Fq "$marker" "$LOG_PATH"; then
    echo "SMP regression test failed: missing marker '$marker'" >&2
    cat "$LOG_PATH" >&2
    exit 1
  fi
done

if grep -Eqi "panic|KERNEL PANIC|System Halted|SMPREG:FAIL|SMPREG:SUITE:FAIL" "$LOG_PATH"; then
  echo "SMP regression test failed: panic or failure marker found" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

echo "SMP regression test passed. Log: $LOG_PATH"
