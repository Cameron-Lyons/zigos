#!/usr/bin/env bash
set -eu

KERNEL_PATH="${1:?kernel path required}"
IMAGE_PATH="${2:?rootfs image path required}"
LOG_PATH="${3:?serial log path required}"
ROOTFS_LISTING_PATH="${4:?rootfs listing path required}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
USERLAND_SH_SMOKE_SECONDS="${USERLAND_SH_SMOKE_SECONDS:-20}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$2" >&2
    exit 1
  fi
}

require_cmd "$QEMU_BIN" "QEMU binary '$QEMU_BIN' not found. Set QEMU_BIN or install QEMU."
require_cmd mdir "mdir not found. Install mtools."

mkdir -p "$(dirname "$LOG_PATH")"
rm -f "$LOG_PATH"
mdir -i "$IMAGE_PATH" ::/bin > "$ROOTFS_LISTING_PATH"

"$QEMU_BIN" \
  -kernel "$KERNEL_PATH" \
  -m 128M \
  -display none \
  -serial "file:$LOG_PATH" \
  -monitor none \
  -no-reboot \
  -no-shutdown \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -drive "file=$IMAGE_PATH,if=ide,format=raw,id=disk0" \
  >/dev/null 2>&1 &
QEMU_PID=$!

TIMED_OUT=0
ELAPSED=0
while kill -0 "$QEMU_PID" >/dev/null 2>&1; do
  if [ "$ELAPSED" -ge "$USERLAND_SH_SMOKE_SECONDS" ]; then
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
  echo "Userland sh smoke test failed: no serial output captured" >&2
  exit 1
fi

if ! grep -Fq "sh" "$ROOTFS_LISTING_PATH"; then
  echo "Userland sh smoke test failed: rootfs image is missing /bin/sh" >&2
  cat "$ROOTFS_LISTING_PATH" >&2
  exit 1
fi

if [ "$TIMED_OUT" -eq 1 ] && ! grep -Fq "USERLAND_SH:PASS" "$LOG_PATH"; then
  echo "Userland sh smoke test failed: QEMU timed out after ${USERLAND_SH_SMOKE_SECONDS}s before USERLAND_SH:PASS" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

for marker in \
  "BOOT:START" \
  "BOOT:PROFILE:userland_sh_smoke" \
  "BOOT:SHELL_READY" \
  "USERLAND_SH:START" \
  "USERLAND_SH:SIMPLE_OK" \
  "USERLAND_SH:PWD_OK" \
  "USERLAND_SH:TRUE_OK" \
  "USERLAND_SH:SIMPLE" \
  "USERLAND_SH:PASS"
do
  if ! grep -Fq "$marker" "$LOG_PATH"; then
    echo "Userland sh smoke test failed: missing marker '$marker'" >&2
    cat "$LOG_PATH" >&2
    exit 1
  fi
done

if grep -Eqi "panic|KERNEL PANIC|System Halted|USERLAND_SH:FAIL" "$LOG_PATH"; then
  echo "Userland sh smoke test failed: panic or failure marker found" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

echo "Userland sh smoke test passed. Log: $LOG_PATH"
