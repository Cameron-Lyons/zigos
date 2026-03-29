#!/usr/bin/env bash
set -eu

KERNEL_PATH="${1:?kernel path required}"
LOG_PATH="${2:?serial log path required}"
NATIVE_STORE_IMAGE="${3:?native store image path required}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
ZIGOS_NATIVE_SECONDS="${ZIGOS_NATIVE_SECONDS:-120}"
ZIGOS_READY_MARKER="ZIGOS:NATIVE:READY"

BASE_LOG_PATH="${LOG_PATH%.log}"
BOOT1_LOG="${BASE_LOG_PATH}.boot1.log"
BOOT2_LOG="${BASE_LOG_PATH}.boot2.log"

if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
  echo "QEMU binary '$QEMU_BIN' not found. Set QEMU_BIN or install QEMU." >&2
  exit 1
fi

mkdir -p "$(dirname "$LOG_PATH")"
rm -f "$LOG_PATH" "$BOOT1_LOG" "$BOOT2_LOG"

run_boot() {
  log_path="$1"
  reset_store="$2"

  if [ "$reset_store" = "reset" ]; then
    bash scripts/build-native-store.sh "$NATIVE_STORE_IMAGE" 8 reset
  else
    bash scripts/build-native-store.sh "$NATIVE_STORE_IMAGE" 8 preserve
  fi

  rm -f "$log_path"
  qemu_error_log="${log_path%.log}.qemu.log"
  rm -f "$qemu_error_log"
  "$QEMU_BIN" \
    -kernel "$KERNEL_PATH" \
    -m 128M \
    -display none \
    -serial "file:$log_path" \
    -monitor none \
    -no-reboot \
    -device "isa-debug-exit,iobase=0xf4,iosize=0x04" \
    -drive "file=$NATIVE_STORE_IMAGE,if=ide,format=raw,index=1,id=disk1" \
    >"$qemu_error_log" 2>&1 &
  QEMU_PID=$!

  timed_out=0
  ready_seen=0
  elapsed=0
  while kill -0 "$QEMU_PID" >/dev/null 2>&1; do
    if [ -s "$log_path" ] && grep -Fq "$ZIGOS_READY_MARKER" "$log_path"; then
      ready_seen=1
      sleep 1
      kill -TERM "$QEMU_PID" >/dev/null 2>&1 || true
      break
    fi
    if [ "$elapsed" -ge "$ZIGOS_NATIVE_SECONDS" ]; then
      timed_out=1
      kill -TERM "$QEMU_PID" >/dev/null 2>&1 || true
      sleep 1
      kill -KILL "$QEMU_PID" >/dev/null 2>&1 || true
      break
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  wait "$QEMU_PID" >/dev/null 2>&1 || true

  if [ ! -s "$log_path" ]; then
    echo "Zigos native smoke test failed: no serial output captured for $log_path" >&2
    if [ -s "$qemu_error_log" ]; then
      cat "$qemu_error_log" >&2
    fi
    exit 1
  fi

  if grep -Eqi "panic|KERNEL PANIC|System Halted|FAIL" "$log_path"; then
    echo "Zigos native smoke test failed: panic or failure marker found in $log_path" >&2
    cat "$log_path" >&2
    if [ -s "$qemu_error_log" ]; then
      cat "$qemu_error_log" >&2
    fi
    exit 1
  fi

  if [ "$timed_out" -eq 1 ]; then
    echo "Timed idle after validation boot: $log_path" >/dev/null
  fi

  if [ "$ready_seen" -eq 0 ] && ! grep -Fq "$ZIGOS_READY_MARKER" "$log_path"; then
    echo "Zigos native smoke test failed: ready marker '$ZIGOS_READY_MARKER' not observed in $log_path" >&2
    cat "$log_path" >&2
    if [ -s "$qemu_error_log" ]; then
      cat "$qemu_error_log" >&2
    fi
    exit 1
  fi
}

assert_log_contains() {
  log_path="$1"
  shift
  for needle in "$@"; do
    if ! grep -Fq "$needle" "$log_path"; then
      echo "Zigos native smoke test failed: missing '$needle' in $log_path" >&2
      cat "$log_path" >&2
      exit 1
    fi
  done
}

assert_boot_markers() {
  log_path="$1"
  assert_log_contains "$log_path" \
    "BOOT:START" \
    "BOOT:PROFILE:zigos_native" \
    "BOOT:CORE_READY" \
    "ZIGOS:PHASE3:KERNEL_NETWORK:DEFERRED" \
    "ZIGOS:NATIVE:BOOTSTRAP" \
    "ZIGOS:TCB:DEFINED" \
    "ZIGOS:USERSPACE:SCHEDULER:READY" \
    "ZIGOS:USERSPACE:EXEC_PROBE:OK" \
    "ZIGOS:PHASE1:NATIVE_KERNEL:READY" \
    "ZIGOS:PHASE1:NO_ROOT" \
    "ZIGOS:PHASE1:COMPONENT_ABI:READY" \
    "ZIGOS:PHASE1:TASK_CREATE:OK" \
    "ZIGOS:PHASE1:SERVICE_CONNECT:OK" \
    "ZIGOS:PHASE1:CAP_PASS:OK" \
    "ZIGOS:SUPERVISOR:READY" \
    "ZIGOS:POLICY:READY" \
    "ZIGOS:PHASE2:MANIFEST:VALID" \
    "ZIGOS:PHASE2:UI:REVIEW_RENDERED" \
    "ZIGOS:PHASE2:ZERO_AUTHORITY:DENY_NETWORK" \
    "ZIGOS:PHASE2:ZERO_AUTHORITY:DENY_CLIPBOARD" \
    "ZIGOS:PHASE2:GRANT:OBJECT_LOCAL" \
    "ZIGOS:PHASE2:GRANT:NETWORK_LOCAL" \
    "ZIGOS:PHASE2:DENY:CLIPBOARD" \
    "ZIGOS:PHASE2:ELF_SUBSTRATE:OK" \
    "ZIGOS:PHASE2:GRANT:DEVICE_LOCAL" \
    "ZIGOS:PHASE2:GRANT:CAMERA" \
    "ZIGOS:PHASE2:DENY:MIC" \
    "ZIGOS:PHASE2:GRANT:SENSOR_LOCAL" \
    "ZIGOS:PHASE2:GRANT:PEER_IPC_LOCAL" \
    "ZIGOS:PHASE2:LEASE:EXPIRED" \
    "ZIGOS:PHASE3:DRIVER_SERVICE:NIC_READY" \
    "ZIGOS:PHASE3:SERVICE_CONTRACTS:READY" \
    "ZIGOS:PHASE3:IPC_CONNECT:ALL_OK" \
    "ZIGOS:PHASE3:SUPERVISOR:RESTART_OK" \
    "ZIGOS:PHASE4:OBJECT_STORE:READY" \
    "ZIGOS:PHASE4:WORKSPACE:TRANSACTION_OK" \
    "ZIGOS:PHASE4:STORAGE_SERVICE:RECOVERED" \
    "ZIGOS:PHASE4:FILE_BRIDGE:DERIVED" \
    "ZIGOS:PHASE4:PATH_AUTHORITY:DEPRECATED" \
    "ZIGOS:PHASE5:DEVICE_GRAPH:ROOTED" \
    "ZIGOS:PHASE6:IMMUTABLE_BASE:ACTIVE" \
    "ZIGOS:PHASE6:ACTIVATION:ROLLBACK_OK" \
    "ZIGOS:PHASE6:MEASURED_BOOT:RECORDED" \
    "ZIGOS:PHASE6:RECOVERY:VERIFY_REINSTALL" \
    "ZIGOS:PHASE6:UX:RECOVER_SYSTEM" \
    "ZIGOS:TASK:SESSION_READY" \
    "ZIGOS:NATIVE:READY"
}

assert_review_text() {
  log_path="$1"
  assert_log_contains "$log_path" \
    "Permission review for Notes [app.notes]" \
    "Permission review for Sync [app.sync]" \
    "Permission review for Capture [app.capture]" \
    "command: allow [local] [lease=<ticks>] | deny" \
    "input> allow local lease=400" \
    "input> allow local lease=50" \
    "input> deny" \
    "input> allow lease=10" \
    "input> allow local lease=30" \
    "input> allow local lease=35" \
    "input> allow local lease=25" \
    "input> allow local lease=15" \
    "decision: allow local_only=yes lease=400 ticks" \
    "decision: allow local_only=yes lease=50 ticks" \
    "decision: deny"
}

run_boot "$BOOT1_LOG" reset
assert_boot_markers "$BOOT1_LOG"
assert_review_text "$BOOT1_LOG"

run_boot "$BOOT2_LOG" preserve
assert_boot_markers "$BOOT2_LOG"
assert_review_text "$BOOT2_LOG"

{
  cat "$BOOT1_LOG"
  printf '\n=== COLD REBOOT ===\n'
  cat "$BOOT2_LOG"
} >"$LOG_PATH"

echo "Zigos native smoke test passed across cold reboot. Logs: $LOG_PATH"
