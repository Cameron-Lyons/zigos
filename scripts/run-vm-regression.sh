#!/usr/bin/env bash
set -eu

KERNEL_PATH="${1:?kernel path required}"
PROFILE_NAME="${2:?profile name required}"
SUITE_PREFIX="${3:?suite prefix required}"
LOG_PATH="${4:?serial log path required}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
VM_REGRESSION_SECONDS="${VM_REGRESSION_SECONDS:-20}"

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
  if [ "$ELAPSED" -ge "$VM_REGRESSION_SECONDS" ]; then
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
  echo "VM regression test failed: no serial output captured" >&2
  exit 1
fi

pass_marker="${SUITE_PREFIX}:PASS"
fail_marker="${SUITE_PREFIX}:FAIL"
start_marker="${SUITE_PREFIX}:START"

case_markers=''
case "$SUITE_PREFIX" in
  VMCORE)
    case_markers='
VMCORE:CASE:PASS:memory_allocation
VMCORE:CASE:PASS:page_mapping
VMCORE:CASE:PASS:memory_stats
VMCORE:CASE:PASS:page_flags
VMCORE:CASE:PASS:range_operations
VMCORE:CASE:PASS:process_local_state
VMCORE:CASE:PASS:file_backed_mmap
VMCORE:CASE:PASS:tty_surface'
    ;;
  VMREADY)
    case_markers='
VMREADY:CASE:PASS:tcp_accept_recv_wakeup
VMREADY:CASE:PASS:tcp_select_readiness
VMREADY:CASE:PASS:udp_poll_readiness
VMREADY:CASE:PASS:unix_select_readiness
VMREADY:CASE:PASS:unix_read_write_dispatch
VMREADY:CASE:PASS:eventfd_poll_dispatch
VMREADY:CASE:PASS:timerfd_poll_dispatch
VMREADY:CASE:PASS:signalfd_poll_dispatch
VMREADY:CASE:PASS:inotify_poll_dispatch
VMREADY:CASE:PASS:inotify_fd_event_dispatch
VMREADY:CASE:PASS:inotify_internal_vnode_dispatch'
    ;;
  VMMEM)
    case_markers='
VMMEM:CASE:PASS:memory_allocation
VMMEM:CASE:PASS:page_mapping
VMMEM:CASE:PASS:memory_stats
VMMEM:CASE:PASS:page_flags
VMMEM:CASE:PASS:range_operations'
    ;;
  VMSTATE)
    case_markers='
VMSTATE:CASE:PASS:process_local_state
VMSTATE:CASE:PASS:file_backed_mmap'
    ;;
  VMTTY)
    case_markers='
VMTTY:CASE:PASS:tty_surface'
    ;;
  VMSOCK)
    case_markers='
VMSOCK:CASE:PASS:tcp_accept_recv_wakeup
VMSOCK:CASE:PASS:tcp_select_readiness
VMSOCK:CASE:PASS:udp_poll_readiness
VMSOCK:CASE:PASS:unix_select_readiness
VMSOCK:CASE:PASS:unix_read_write_dispatch'
    ;;
  VMEVT)
    case_markers='
VMEVT:CASE:PASS:eventfd_poll_dispatch
VMEVT:CASE:PASS:timerfd_poll_dispatch
VMEVT:CASE:PASS:signalfd_poll_dispatch'
    ;;
  VMINOTIFY)
    case_markers='
VMINOTIFY:CASE:PASS:inotify_poll_dispatch
VMINOTIFY:CASE:PASS:inotify_fd_event_dispatch
VMINOTIFY:CASE:PASS:inotify_internal_vnode_dispatch'
    ;;
esac

if [ "$TIMED_OUT" -eq 1 ] && ! grep -Fq "$pass_marker" "$LOG_PATH"; then
  echo "VM regression test failed: QEMU timed out after ${VM_REGRESSION_SECONDS}s before ${pass_marker}" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

for marker in \
  "BOOT:START" \
  "BOOT:PROFILE:${PROFILE_NAME}" \
  "BOOT:CORE_READY" \
  "$start_marker" \
  "$pass_marker"
do
  if ! grep -Fq "$marker" "$LOG_PATH"; then
    echo "VM regression test failed: missing marker '$marker'" >&2
    cat "$LOG_PATH" >&2
    exit 1
  fi
done

if [ -n "$case_markers" ]; then
  while IFS= read -r marker; do
    [ -n "$marker" ] || continue
    if ! grep -Fq "$marker" "$LOG_PATH"; then
      echo "VM regression test failed: missing case marker '$marker'" >&2
      cat "$LOG_PATH" >&2
      exit 1
    fi
  done <<EOF
$case_markers
EOF
fi

if grep -Eqi "panic|KERNEL PANIC|System Halted|${fail_marker}|${SUITE_PREFIX}:CASE:FAIL:" "$LOG_PATH"; then
  echo "VM regression test failed: panic or failure marker found" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

echo "VM regression test passed. Log: $LOG_PATH"
