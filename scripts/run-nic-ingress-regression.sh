#!/usr/bin/env bash
set -eu

KERNEL_PATH="${1:?kernel path required}"
LOG_PATH="${2:?serial log path required}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
NIC_INGRESS_SECONDS="${NIC_INGRESS_SECONDS:-25}"
HOST_UDP_PORT="${NIC_INGRESS_HOST_PORT:-15345}"
GUEST_UDP_PORT="${NIC_INGRESS_GUEST_PORT:-15346}"

if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
  echo "QEMU binary '$QEMU_BIN' not found. Set QEMU_BIN or install QEMU." >&2
  exit 1
fi

mkdir -p "$(dirname "$LOG_PATH")"
rm -f "$LOG_PATH"
rm -f build/nic-ingress.pcap

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
host = ('127.0.0.1', int(${GUEST_UDP_PORT}))
frame = bytes([
    0xff,0xff,0xff,0xff,0xff,0xff,
    0x02,0xaa,0xbb,0xcc,0xdd,0x55,
    0x08,0x06,
    0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x02,
    0x02,0xaa,0xbb,0xcc,0xdd,0x55,
    0x0a,0x00,0x00,0x01,
    0x00,0x00,0x00,0x00,0x00,0x00,
    0x0a,0x00,0x00,0x02,
])
if len(frame) < 60:
    frame = frame + bytes(60 - len(frame))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', int(${HOST_UDP_PORT})))
time.sleep(1)
for _ in range(60):
    s.sendto(frame, host)
    time.sleep(0.5)
s.close()
PY
SENDER_PID=$!

QEMU_BIN="$QEMU_BIN" \
QEMU_EXTRA_ARGS="-nic none -netdev socket,id=n0,udp=127.0.0.1:${HOST_UDP_PORT},localaddr=127.0.0.1:${GUEST_UDP_PORT} -object filter-dump,id=f1,netdev=n0,file=build/nic-ingress.pcap -device rtl8139,netdev=n0" \
  bash scripts/run-headless-qemu.sh "$KERNEL_PATH" "256M" "file:$LOG_PATH" >/dev/null 2>&1 &
QEMU_PID=$!

TIMED_OUT=0
ELAPSED=0
while kill -0 "$QEMU_PID" >/dev/null 2>&1; do
  if [ "$ELAPSED" -ge "$NIC_INGRESS_SECONDS" ]; then
    TIMED_OUT=1
    cleanup
    break
  fi
  sleep 1
  ELAPSED=$((ELAPSED + 1))
done
wait "$QEMU_PID" >/dev/null 2>&1 || true

if [ ! -s "$LOG_PATH" ]; then
  echo "NIC ingress regression failed: no serial output captured" >&2
  exit 1
fi

if [ "$TIMED_OUT" -eq 1 ] && ! grep -Fq "NICINGRESS:PASS" "$LOG_PATH"; then
  echo "NIC ingress regression failed: QEMU timed out after ${NIC_INGRESS_SECONDS}s before NICINGRESS:PASS" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

for marker in \
  "BOOT:START" \
  "BOOT:PROFILE:nic_ingress" \
  "BOOT:CORE_READY" \
  "NICINGRESS:START" \
  "NICINGRESS:DRIVER:PASS" \
  "NICINGRESS:PACKET:PASS" \
  "NICINGRESS:ARP:PASS" \
  "NICINGRESS:PASS"
do
  if ! grep -Fq "$marker" "$LOG_PATH"; then
    echo "NIC ingress regression failed: missing marker '$marker'" >&2
    cat "$LOG_PATH" >&2
    exit 1
  fi
done

if grep -Eqi "panic|KERNEL PANIC|System Halted|NICINGRESS:FAIL|NICINGRESS:DRIVER:FAIL|NICINGRESS:ARP:FAIL" "$LOG_PATH"; then
  echo "NIC ingress regression failed: panic or failure marker found" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

echo "NIC ingress regression passed. Log: $LOG_PATH"
