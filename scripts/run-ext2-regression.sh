#!/usr/bin/env bash
set -eu

KERNEL_PATH="${1:?kernel path required}"
ROOTFS_IMAGE="${2:?rootfs image path required}"
EXT2_IMAGE="${3:?ext2 image path required}"
LOG_PATH="${4:?serial log path required}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
EXT2_REGRESSION_SECONDS="${EXT2_REGRESSION_SECONDS:-30}"

if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
  echo "QEMU binary '$QEMU_BIN' not found. Set QEMU_BIN or install QEMU." >&2
  exit 1
fi

mkdir -p "$(dirname "$LOG_PATH")"
rm -f "$LOG_PATH"

QEMU_BIN="$QEMU_BIN" \
QEMU_EXTRA_ARGS="-drive file=$ROOTFS_IMAGE,if=ide,format=raw,index=0,id=disk0 -drive file=$EXT2_IMAGE,if=ide,format=raw,index=1,id=disk1" \
  bash scripts/run-headless-qemu.sh "$KERNEL_PATH" "256M" "file:$LOG_PATH" >/dev/null 2>&1 &
QEMU_PID=$!

TIMED_OUT=0
ELAPSED=0
while kill -0 "$QEMU_PID" >/dev/null 2>&1; do
  if [ "$ELAPSED" -ge "$EXT2_REGRESSION_SECONDS" ]; then
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
  echo "ext2 regression test failed: no serial output captured" >&2
  exit 1
fi

if [ "$TIMED_OUT" -eq 1 ] && ! grep -Fq "EXT2:PASS" "$LOG_PATH"; then
  echo "ext2 regression test failed: QEMU timed out after ${EXT2_REGRESSION_SECONDS}s before EXT2:PASS" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

for marker in \
  "BOOT:START" \
  "BOOT:PROFILE:ext2_regression" \
  "Disk root mounted at /" \
  "BOOT:CORE_READY" \
  "EXT2:START" \
  "EXT2:MOUNT:PASS" \
  "EXT2:PASS"
do
  if ! grep -Fq "$marker" "$LOG_PATH"; then
    echo "ext2 regression test failed: missing marker '$marker'" >&2
    cat "$LOG_PATH" >&2
    exit 1
  fi
done

if grep -Eqi "panic|KERNEL PANIC|System Halted|EXT2:FAIL|EXT2:MOUNTPOINT:FAIL|EXT2:MOUNT:FAIL|EXT2:SUITE:FAIL" "$LOG_PATH"; then
  echo "ext2 regression test failed: panic or failure marker found" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

echo "ext2 regression test passed. Log: $LOG_PATH"
