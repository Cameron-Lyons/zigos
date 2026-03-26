#!/usr/bin/env bash
set -eu

KERNEL_PATH="${1:?kernel path required}"
LOG_PATH="${2:?serial log path required}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
E1000_INGRESS_SECONDS="${E1000_INGRESS_SECONDS:-25}"
FORWARD_PORT="${E1000_INGRESS_FORWARD_PORT:-18082}"

if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
  echo "QEMU binary '$QEMU_BIN' not found. Set QEMU_BIN or install QEMU." >&2
  exit 1
fi

mkdir -p "$(dirname "$LOG_PATH")"
rm -f "$LOG_PATH"

cleanup() {
  if [ -n "${QEMU_PID:-}" ]; then
    kill -TERM "$QEMU_PID" >/dev/null 2>&1 || true
    sleep 1
    kill -KILL "$QEMU_PID" >/dev/null 2>&1 || true
  fi
  if [ -n "${SENDER_PID:-}" ]; then
    kill "$SENDER_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

python3 - <<PY >/dev/null 2>&1 &
import socket, time
host = ('127.0.0.1', int(${FORWARD_PORT}))
payload = b'HELLO_ZIGOS'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
time.sleep(1)
for _ in range(60):
    s.sendto(payload, host)
    time.sleep(0.5)
s.close()
PY
SENDER_PID=$!

QEMU_BIN="$QEMU_BIN" \
QEMU_EXTRA_ARGS="-nic none -netdev user,id=n0,hostfwd=udp:127.0.0.1:${FORWARD_PORT}-10.0.2.15:8081 -device e1000,netdev=n0" \
  bash scripts/run-headless-qemu.sh "$KERNEL_PATH" "256M" "file:$LOG_PATH" >/dev/null 2>&1 &
QEMU_PID=$!

TIMED_OUT=0
ELAPSED=0
while kill -0 "$QEMU_PID" >/dev/null 2>&1; do
  if [ "$ELAPSED" -ge "$E1000_INGRESS_SECONDS" ]; then
    TIMED_OUT=1
    cleanup
    break
  fi
  sleep 1
  ELAPSED=$((ELAPSED + 1))
done
wait "$QEMU_PID" >/dev/null 2>&1 || true

if [ ! -s "$LOG_PATH" ]; then
  echo "E1000 live ingress failed: no serial output captured" >&2
  exit 1
fi

if [ "$TIMED_OUT" -eq 1 ] && ! grep -Fq "E1000INGRESS:PASS" "$LOG_PATH"; then
  echo "E1000 live ingress failed: QEMU timed out after ${E1000_INGRESS_SECONDS}s before E1000INGRESS:PASS" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

for marker in \
  "BOOT:START" \
  "BOOT:PROFILE:e1000_ingress" \
  "BOOT:CORE_READY" \
  "E1000INGRESS:START" \
  "E1000INGRESS:DRIVER:PASS" \
  "E1000INGRESS:SOCKET:PASS" \
  "E1000INGRESS:PACKET:PASS" \
  "E1000INGRESS:PASS"
do
  if ! grep -Fq "$marker" "$LOG_PATH"; then
    echo "E1000 live ingress failed: missing marker '$marker'" >&2
    cat "$LOG_PATH" >&2
    exit 1
  fi
done

if grep -Eqi "panic|KERNEL PANIC|System Halted|E1000INGRESS:FAIL|E1000INGRESS:DRIVER:FAIL|E1000INGRESS:SOCKET:FAIL|E1000INGRESS:PACKET:FAIL" "$LOG_PATH"; then
  echo "E1000 live ingress failed: panic or failure marker found" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

echo "E1000 live ingress passed. Log: $LOG_PATH"
