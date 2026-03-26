#!/usr/bin/env bash
set -eu

KERNEL_PATH="${1:?kernel path required}"
IMAGE_PATH="${2:?rootfs image path required}"
LOG_PATH="${3:?serial log path required}"
ROOTFS_LISTING_PATH="${4:?rootfs listing path required}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
USERLAND_SMOKE_SECONDS="${USERLAND_SMOKE_SECONDS:-20}"

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
  if [ "$ELAPSED" -ge "$USERLAND_SMOKE_SECONDS" ]; then
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
  echo "Userland smoke test failed: no serial output captured" >&2
  exit 1
fi

if ! grep -Fq "echo" "$ROOTFS_LISTING_PATH"; then
  echo "Userland smoke test failed: rootfs image is missing /bin/echo" >&2
  cat "$ROOTFS_LISTING_PATH" >&2
  exit 1
fi

if [ "$TIMED_OUT" -eq 1 ] && ! grep -Fq "USERLAND:PASS" "$LOG_PATH"; then
  echo "Userland smoke test failed: QEMU timed out after ${USERLAND_SMOKE_SECONDS}s before USERLAND:PASS" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

for marker in \
  "BOOT:START" \
  "BOOT:PROFILE:userland_smoke" \
  "Disk root mounted at /" \
  "BOOT:SHELL_READY" \
  "USERLAND:HELLO" \
  "USERLAND:ECHO" \
  "USERLAND:ENV" \
  "USERLAND:CMDSUB" \
  "USERLAND:QUOTED" \
  "USERLAND:ESCAPED" \
  "USERLAND:GLOB" \
  "USERLAND:UNAME" \
  "USERLAND:PWD" \
  "USERLAND:LS" \
  "USERLAND:CAT" \
  "USERLAND:ENV_STANDALONE" \
  "USERLAND:ENV_BIN" \
  "USERLAND:WHICH" \
  "USERLAND:HEAD" \
  "USERLAND:TAIL" \
  "USERLAND:WC" \
  "USERLAND:SORT" \
  "USERLAND:UNIQ" \
  "USERLAND:HEXDUMP" \
  "USERLAND:TEST" \
  "USERLAND:TRUE" \
  "USERLAND:FALSE_OK" \
  "USERLAND:CP" \
  "USERLAND:MV" \
  "USERLAND:MKDIR" \
  "USERLAND:TOUCH" \
  "USERLAND:GREP" \
  "USERLAND:CHMOD" \
  "USERLAND:CHOWN" \
  "USERLAND:RM" \
  "USERLAND:LN" \
  "USERLAND:CAT_HARD" \
  "USERLAND:CAT_HARD_CI" \
  "USERLAND:LNS" \
  "USERLAND:CAT_LINK" \
  "USERLAND:CAT_LINK_CI" \
  "USERLAND:PS" \
  "USERLAND:PING" \
  "USERLAND:WHOAMI" \
  "USERLAND:ID" \
  "USERLAND:DATE" \
  "USERLAND:HOSTNAME" \
  "USERLAND:TTY" \
  "USERLAND:MOUNT_DIR" \
  "USERLAND:MOUNT" \
  "USERLAND:MOUNT_TOUCH" \
  "USERLAND:UMOUNT" \
  "USERLAND:LOGIN" \
  "USERLAND:GETTY" \
  "USERLAND:PROC_VERSION" \
  "USERLAND:PROC_MOUNTS" \
  "USERLAND:SYS_HOSTNAME" \
  "USERLAND:PIPE_OK" \
  "USERLAND:PIPE_CHAIN_WRITE" \
  "USERLAND:PIPE_CHAIN_READ" \
  "USERLAND:REDIRECT_WRITE" \
  "USERLAND:REDIRECT_READ" \
  "USERLAND:INIT_START" \
  "USERLAND:INIT_KILL" \
  "USERLAND:BG_START" \
  "USERLAND:JOBS_RUNNING" \
  "USERLAND:JOBS_STOPPED" \
  "USERLAND:BG_RESUME" \
  "USERLAND:JOBS_RESUMED" \
  "USERLAND:KILL_BG" \
  "user:root home:/home/user" \
  "shell-ZigOS" \
  "USERLAND QUOTED" \
  "USERLAND ESCAPED" \
  "Welcome to ZigOS userspace smoke test." \
  "PATH=/bin:/usr/bin:/mnt/bin" \
  "00000000" \
  "uid=0(root) gid=0(root) euid=0(root) egid=0(root)" \
  "zigos" \
  "/dev/tty" \
  "Welcome user" \
  "ZigOS console login" \
  "USERLAND:PIPE" \
  "Welcome to ZigOS userspace smoke test." \
  "USERLAND:REDIRECT" \
  "[1] Running /bin/sleep 3" \
  "[1] Stopped /bin/sleep 3" \
  "USERLAND:PASS"
do
  if ! grep -Fq "$marker" "$LOG_PATH"; then
    echo "Userland smoke test failed: missing marker '$marker'" >&2
    cat "$LOG_PATH" >&2
    exit 1
  fi
done

for path_marker in /bin/cat /bin/chmod /bin/chown /bin/cp /bin/ln /bin/ls; do
  if ! grep -Fq "$path_marker" "$LOG_PATH"; then
    echo "Userland smoke test failed: missing path marker '$path_marker'" >&2
    cat "$LOG_PATH" >&2
    exit 1
  fi
done

if grep -Eqi "panic|KERNEL PANIC|System Halted|USERLAND:FAIL" "$LOG_PATH"; then
  echo "Userland smoke test failed: panic or failure marker found" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

echo "Userland smoke test passed. Log: $LOG_PATH"
