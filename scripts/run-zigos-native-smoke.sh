#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
ZIG="${ROOT_DIR}/scripts/zig.sh"
MARKER_TOOL="${ROOT_DIR}/src/print_native_smoke_markers.zig"

KERNEL_PATH="${1:?kernel path required}"
LOG_PATH="${2:?serial log path required}"
NATIVE_STORE_IMAGE="${3:?native store image path required}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
ZIGOS_NATIVE_SECONDS="${ZIGOS_NATIVE_SECONDS:-180}"
ZIGOS_READY_MARKER="$("$ZIG" run "$MARKER_TOOL" -- ready)"
PHASE4_RELOADED_MARKER="$("$ZIG" run "$MARKER_TOOL" -- boot2_reloaded_phase4 | head -n 1)"

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
  local log_path="$1"
  local reset_store="$2"
  local wait_group="${3:-}"
  local qemu_error_log
  local qemu_pid
  local timed_out=0
  local ready_seen=0
  local elapsed=0

  if [ "$reset_store" = "reset" ]; then
    bash "$ROOT_DIR/scripts/build-native-store.sh" "$NATIVE_STORE_IMAGE" 8 reset
  else
    bash "$ROOT_DIR/scripts/build-native-store.sh" "$NATIVE_STORE_IMAGE" 8 preserve
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
  qemu_pid=$!

  while kill -0 "$qemu_pid" >/dev/null 2>&1; do
    if [ -s "$log_path" ] && grep -Fq "$ZIGOS_READY_MARKER" "$log_path"; then
      ready_seen=1
      if [ -z "$wait_group" ] || marker_group_present "$log_path" "$wait_group"; then
        sleep 1
        kill -TERM "$qemu_pid" >/dev/null 2>&1 || true
        break
      fi
    fi
    if [ "$elapsed" -ge "$ZIGOS_NATIVE_SECONDS" ]; then
      timed_out=1
      kill -TERM "$qemu_pid" >/dev/null 2>&1 || true
      sleep 1
      kill -KILL "$qemu_pid" >/dev/null 2>&1 || true
      break
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  wait "$qemu_pid" >/dev/null 2>&1 || true

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

marker_group_present() {
  local log_path="$1"
  local group="$2"
  local needle

  while IFS= read -r needle; do
    [ -n "$needle" ] || continue
    if ! grep -Fq "$needle" "$log_path"; then
      return 1
    fi
  done < <("$ZIG" run "$MARKER_TOOL" -- "$group")

  return 0
}

assert_marker_group() {
  local log_path="$1"
  local group="$2"
  local needle

  while IFS= read -r needle; do
    [ -n "$needle" ] || continue
    if ! grep -Fq "$needle" "$log_path"; then
      echo "Zigos native smoke test failed: missing '$needle' in $log_path" >&2
      cat "$log_path" >&2
      exit 1
    fi
  done < <("$ZIG" run "$MARKER_TOOL" -- "$group")
}

assert_log_contains() {
  local log_path="$1"
  local needle
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
  local log_path="$1"
  assert_marker_group "$log_path" cold_boot
  assert_marker_group "$log_path" post_ready
}

assert_boot2_phase4_markers() {
  local log_path="$1"
  if grep -Fq "$PHASE4_RELOADED_MARKER" "$log_path"; then
    assert_marker_group "$log_path" boot2_reloaded_phase4
    return
  fi

  assert_marker_group "$log_path" boot2_fresh_phase4
}

assert_review_text() {
  local log_path="$1"
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
    "decision: deny" \
    "UI window: id=1 surface=3 type=app_panel modal=yes title=Notes permission review bundle=app.notes" \
    "UI window: id=2 surface=4 type=app_panel modal=yes title=Sync permission review bundle=app.sync" \
    "UI window: id=3 surface=5 type=app_panel modal=yes title=Capture permission review bundle=app.capture" \
    "UI card: window=1 kind=object_access label=Object access resource=workspace:notes" \
    "UI card update: window=1 kind=clipboard resource=clipboard decision=deny" \
    "UI card update: window=2 kind=background_execution resource=sync decision=allow decision_local_only=no decision_lease=10" \
    "UI card update: window=3 kind=mic resource=mic.array decision=deny" \
    "UX review: task=" \
    "bundle=app.notes kind=object_access resource=workspace:notes decision=allow required=yes requested_local_only=yes decision_local_only=yes lease=400" \
    "bundle=app.notes kind=network_egress resource=lan.sync decision=allow required=no requested_local_only=yes decision_local_only=yes lease=50" \
    "bundle=app.notes kind=clipboard resource=clipboard decision=deny required=no requested_local_only=no" \
    "bundle=app.sync kind=background_execution resource=sync decision=allow required=yes requested_local_only=no decision_local_only=no lease=10" \
    "bundle=app.capture kind=device_access resource=capture.card0 decision=allow required=no requested_local_only=yes decision_local_only=yes lease=30" \
    "bundle=app.capture kind=camera resource=camera.front decision=allow required=no requested_local_only=yes decision_local_only=yes lease=35" \
    "bundle=app.capture kind=mic resource=mic.array decision=deny required=no requested_local_only=yes" \
    "bundle=app.capture kind=sensor resource=sensor.lid decision=allow required=no requested_local_only=yes decision_local_only=yes lease=25" \
    "bundle=app.capture kind=peer_ipc resource=zigos.peer.share decision=allow required=no requested_local_only=yes decision_local_only=yes lease=15"
}

run_boot "$BOOT1_LOG" reset post_ready
assert_boot_markers "$BOOT1_LOG"
assert_review_text "$BOOT1_LOG"

run_boot "$BOOT2_LOG" preserve post_ready
assert_boot_markers "$BOOT2_LOG"
assert_boot2_phase4_markers "$BOOT2_LOG"
assert_review_text "$BOOT2_LOG"

{
  cat "$BOOT1_LOG"
  printf '\n=== COLD REBOOT ===\n'
  cat "$BOOT2_LOG"
} >"$LOG_PATH"

echo "Zigos native smoke test passed across cold reboot. Logs: $LOG_PATH"
