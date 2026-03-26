#!/usr/bin/env bash
set -eu

KERNEL_PATH="${1:?kernel path required}"
LOG_PATH="${2:?serial log path required}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
SERVICE_REGRESSION_SECONDS="${SERVICE_REGRESSION_SECONDS:-20}"

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
  if [ "$ELAPSED" -ge "$SERVICE_REGRESSION_SECONDS" ]; then
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
  echo "Service regression test failed: no serial output captured" >&2
  exit 1
fi

if [ "$TIMED_OUT" -eq 1 ] && ! grep -Fq "SERVREG:PASS" "$LOG_PATH"; then
  echo "Service regression test failed: QEMU timed out after ${SERVICE_REGRESSION_SECONDS}s before SERVREG:PASS" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

for marker in \
  "BOOT:START" \
  "BOOT:PROFILE:service_regression" \
  "BOOT:CORE_READY" \
  "SERVREG:START" \
  "SERVREG:MEMORY:START" \
  "SERVREG:MEMORY:PASS" \
  "SERVREG:SYSCALL:START" \
  "SERVREG:SYSCALL:PASS" \
  "SERVREG:NETWORK:START" \
  "SERVREG:NETWORK:PASS" \
  "SERVREG:RTL8139:START" \
  "SERVREG:RTL8139:PASS" \
  "SERVREG:E1000:START" \
  "SERVREG:E1000:PASS" \
  "SERVREG:VIRTIO:START" \
  "SERVREG:VIRTIO:PASS" \
  "SERVREG:PASS"
do
  if ! grep -Fq "$marker" "$LOG_PATH"; then
    echo "Service regression test failed: missing marker '$marker'" >&2
    cat "$LOG_PATH" >&2
    exit 1
  fi
done

if grep -Eqi "panic|KERNEL PANIC|System Halted|SERVREG:FAIL|SERVREG:MEMORY:FAIL|SERVREG:SYSCALL:FAIL|SERVREG:NETWORK:FAIL|SERVREG:RTL8139:FAIL|SERVREG:E1000:FAIL|SERVREG:VIRTIO:FAIL" "$LOG_PATH"; then
  echo "Service regression test failed: panic or failure marker found" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

echo "Service regression test passed. Log: $LOG_PATH"
