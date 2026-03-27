#!/usr/bin/env bash
set -eu

KERNEL_PATH="${1:?kernel path required}"
LOG_PATH="${2:?serial log path required}"
NATIVE_STORE_IMAGE="${3:?native store image path required}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
ZIGOS_NATIVE_SECONDS="${ZIGOS_NATIVE_SECONDS:-10}"

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
  elapsed=0
  while kill -0 "$QEMU_PID" >/dev/null 2>&1; do
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
    "ZIGOS:PHASE1:NATIVE_KERNEL:READY" \
    "ZIGOS:PHASE1:NO_ROOT" \
    "ZIGOS:PHASE1:COMPONENT_ABI:READY" \
    "ZIGOS:PHASE1:TASK_CREATE:OK" \
    "ZIGOS:PHASE1:ENDPOINT_CREATE:OK" \
    "ZIGOS:PHASE1:SERVICE_REGISTER:OK" \
    "ZIGOS:PHASE1:SERVICE_CONNECT:OK" \
    "ZIGOS:PHASE1:SHM:MAP_OK" \
    "ZIGOS:PHASE1:CAP_PASS:OK" \
    "ZIGOS:PHASE1:RESOURCE_QUERY:OK" \
    "ZIGOS:PHASE1:ACCOUNTING_QUERY:OK" \
    "ZIGOS:PHASE1:TIME_QUERY:OK" \
    "ZIGOS:PHASE1:CAP_MINT:OK" \
    "ZIGOS:PHASE1:CAP_QUERY:OK" \
    "ZIGOS:PHASE1:CAP_DERIVE:OK" \
    "ZIGOS:PHASE1:CAP_REVOKE:OK" \
    "ZIGOS:PHASE1:TASK_TERMINATE:OK" \
    "ZIGOS:SUPERVISOR:READY" \
    "ZIGOS:POLICY:READY" \
    "ZIGOS:PHASE2:MANIFEST:VALID" \
    "ZIGOS:PHASE2:UI:SERVICE_READY" \
    "ZIGOS:PHASE2:UI:SERVICE_TASK_READY" \
    "ZIGOS:PHASE2:REVIEW_PORT:READY" \
    "ZIGOS:PHASE2:POLICY_PORT:READY" \
    "ZIGOS:PHASE2:UI:REVIEW_READY" \
    "ZIGOS:PHASE2:UI:INPUT_LOOP" \
    "ZIGOS:PHASE2:UI:REVIEW_RENDERED" \
    "ZIGOS:PHASE2:UI:APPROVE_OBJECT" \
    "ZIGOS:PHASE2:UI:APPROVE_NETWORK" \
    "ZIGOS:PHASE2:UI:DENY_CLIPBOARD" \
    "ZIGOS:PHASE2:UI:REVIEW_SYNC" \
    "ZIGOS:PHASE2:ZERO_AUTHORITY:DENY_NETWORK" \
    "ZIGOS:PHASE2:ZERO_AUTHORITY:DENY_CLIPBOARD" \
    "ZIGOS:PHASE2:GRANT:OBJECT_LOCAL" \
    "ZIGOS:PHASE2:GRANT:NETWORK_LOCAL" \
    "ZIGOS:PHASE2:DENY:CLIPBOARD" \
    "ZIGOS:PHASE2:DENY:BACKGROUND" \
    "ZIGOS:PHASE2:ELF_SUBSTRATE:OK" \
    "ZIGOS:PHASE2:UI:APPROVE_DEVICE" \
    "ZIGOS:PHASE2:UI:APPROVE_CAMERA" \
    "ZIGOS:PHASE2:UI:DENY_MIC" \
    "ZIGOS:PHASE2:UI:APPROVE_SENSOR" \
    "ZIGOS:PHASE2:UI:APPROVE_PEER_IPC" \
    "ZIGOS:PHASE2:GRANT:DEVICE_LOCAL" \
    "ZIGOS:PHASE2:GRANT:CAMERA" \
    "ZIGOS:PHASE2:DENY:MIC" \
    "ZIGOS:PHASE2:GRANT:SENSOR_LOCAL" \
    "ZIGOS:PHASE2:GRANT:PEER_IPC_LOCAL" \
    "ZIGOS:PHASE2:LEASE:EXPIRED" \
    "ZIGOS:PHASE3:CONTRACT_MAP:READY" \
    "ZIGOS:PHASE3:DRIVER_SERVICE:NIC_READY" \
    "ZIGOS:PHASE3:SERVICE_CONTRACTS:READY" \
    "ZIGOS:PHASE3:IPC_CONNECT:ALL_OK" \
    "ZIGOS:PHASE3:SUPERVISOR:CRASH_RECORDED" \
    "ZIGOS:PHASE3:SUPERVISOR:RESTART_OK" \
    "ZIGOS:PHASE4:OBJECT_STORE:READY" \
    "ZIGOS:PHASE4:OBJECT_TYPES:READY" \
    "ZIGOS:PHASE4:WORKSPACE:SHARING_OK" \
    "ZIGOS:PHASE4:WORKSPACE:TRANSACTION_OK" \
    "ZIGOS:PHASE4:SNAPSHOT:OK" \
    "ZIGOS:PHASE4:RESTORE:OK" \
    "ZIGOS:PHASE4:DELETE_RECOVERY:OK" \
    "ZIGOS:PHASE4:EXPORT_IMPORT:OK" \
    "ZIGOS:PHASE4:STORAGE_SERVICE:RECOVERED" \
    "ZIGOS:PHASE4:FILE_BRIDGE:DERIVED" \
    "ZIGOS:PHASE4:PATH_AUTHORITY:DEPRECATED" \
    "ZIGOS:PHASE5:DEVICE_GRAPH:ROOTED" \
    "ZIGOS:PHASE5:DEVICE_ENROLL:OK" \
    "ZIGOS:PHASE5:KEY_ROTATION:OK" \
    "ZIGOS:PHASE5:DEVICE_REVOKE:OK" \
    "ZIGOS:PHASE5:NETWORK_POLICY:NONE" \
    "ZIGOS:PHASE5:NETWORK_POLICY:LOCAL" \
    "ZIGOS:PHASE5:NETWORK_POLICY:SERVICE" \
    "ZIGOS:PHASE5:NETWORK_POLICY:DOMAIN" \
    "ZIGOS:PHASE5:NETWORK_POLICY:INTERNET" \
    "ZIGOS:PHASE5:SYNC_POLICY:OFFLINE_FIRST" \
    "ZIGOS:PHASE5:SYNC_POLICY:E2EE_PERSONAL" \
    "ZIGOS:PHASE5:SYNC_POLICY:SELECTIVE" \
    "ZIGOS:PHASE5:SYNC:DEVICE_TO_DEVICE" \
    "ZIGOS:PHASE5:SYNC:RELAY" \
    "ZIGOS:PHASE5:SYNC:CONFLICT_REPORT" \
    "ZIGOS:PHASE5:SEMANTICS:CRDT" \
    "ZIGOS:PHASE5:SEMANTICS:SNAPSHOT" \
    "ZIGOS:PHASE5:SEMANTICS:SECRET_TRANSFER" \
    "ZIGOS:PHASE5:SEMANTICS:TRANSACTIONAL" \
    "ZIGOS:PHASE5:DEVICE_REVOKE:ENFORCED" \
    "ZIGOS:PHASE5:OVERLAY:READY" \
    "ZIGOS:PHASE5:SYNC_SERVICE:RECOVERED" \
    "ZIGOS:PHASE6:HEALTHCHECK:BOOT_ROLLBACK" \
    "ZIGOS:PHASE6:HEALTHCHECK:CORE_ROLLBACK" \
    "ZIGOS:PHASE6:HEALTHCHECK:UI_ROLLBACK" \
    "ZIGOS:PHASE6:HEALTHCHECK:STORAGE_ROLLBACK" \
    "ZIGOS:PHASE6:HEALTHCHECK:NETWORK_ROLLBACK" \
    "ZIGOS:PHASE6:IMMUTABLE_BASE:ACTIVE" \
    "ZIGOS:PHASE6:ACTIVATION:ROLLBACK_OK" \
    "ZIGOS:PHASE6:MEASURED_BOOT:RECORDED" \
    "ZIGOS:PHASE6:RECOVERY:VERIFY_REINSTALL" \
    "ZIGOS:PHASE6:RECOVERY:RESTORE_SNAPSHOT" \
    "ZIGOS:PHASE6:RECOVERY:REPAIR_SYNC" \
    "ZIGOS:PHASE6:RECOVERY:ROTATE_KEYS" \
    "ZIGOS:PHASE6:RECOVERY:REVOKE_TRUST" \
    "ZIGOS:PHASE6:UX:START_TASK" \
    "ZIGOS:PHASE6:UX:OPEN_WORKSPACE" \
    "ZIGOS:PHASE6:UX:PAIR_DEVICE" \
    "ZIGOS:PHASE6:UX:REVIEW_PERMISSION" \
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
