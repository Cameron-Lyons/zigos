#!/usr/bin/env bash
set -eu

KERNEL_PATH="${1:?kernel path required}"
LOG_PATH="${2:?serial log path required}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
SMP_STRESS_SECONDS="${SMP_STRESS_SECONDS:-15}"

if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
  echo "QEMU binary '$QEMU_BIN' not found. Set QEMU_BIN or install QEMU." >&2
  exit 1
fi

mkdir -p "$(dirname "$LOG_PATH")"
rm -f "$LOG_PATH"

QEMU_BIN="$QEMU_BIN" QEMU_EXTRA_ARGS="-cpu qemu64 -smp 2" \
  bash scripts/run-headless-qemu.sh "$KERNEL_PATH" "256M" "file:$LOG_PATH" >/dev/null 2>&1 &
QEMU_PID=$!

sleep "$SMP_STRESS_SECONDS"
if kill -0 "$QEMU_PID" >/dev/null 2>&1; then
  kill -TERM "$QEMU_PID" >/dev/null 2>&1 || true
  sleep 1
  kill -KILL "$QEMU_PID" >/dev/null 2>&1 || true
  echo "SMP stress test failed: QEMU timed out" >&2
  exit 1
fi
wait "$QEMU_PID"

if [ ! -s "$LOG_PATH" ]; then
  echo "SMP stress test failed: no serial output captured" >&2
  exit 1
fi

for marker in \
  "BOOT:START" \
  "BOOT:PROFILE:smp_stress" \
  "BOOT:CORE_READY" \
  "SMP:START" \
  "SMP:ACTIVE_CPUS:" \
  "SMP:TASKS_CREATED" \
  "SMP:TASKS_DONE" \
  "SMP:STATS:" \
  "SMP:PASS"
do
  if ! grep -Fq "$marker" "$LOG_PATH"; then
    echo "SMP stress test failed: missing marker '$marker'" >&2
    cat "$LOG_PATH" >&2
    exit 1
  fi
done

if grep -Eqi "panic|KERNEL PANIC|System Halted|SMP:FAIL|SMP:TIMEOUT" "$LOG_PATH"; then
  echo "SMP stress test failed: panic or failure marker found" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

echo "SMP stress test passed. Log: $LOG_PATH"
