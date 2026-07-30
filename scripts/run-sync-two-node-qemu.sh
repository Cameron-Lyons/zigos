#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
ZIG="${ROOT_DIR}/scripts/zig.sh"
MARKER_TOOL="${ROOT_DIR}/src/print_native_smoke_markers.zig"

source "$ROOT_DIR/scripts/qemu-harness.sh"

KERNEL_PATH="${1:?kernel path required}"
LOG_PATH="${2:?combined serial log path required}"
NODE_A_STORE="${3:?node A native store image path required}"
NODE_B_STORE="${4:?node B native store image path required}"
SYNC_TWO_NODE_SECONDS="${SYNC_TWO_NODE_SECONDS:-180}"
NATIVE_STORE_SIZE_MIB="${NATIVE_STORE_SIZE_MIB:-8}"
SYNC_TWO_NODE_PORT="${SYNC_TWO_NODE_PORT:-$((40000 + ($$ % 10000)))}"
READY_MARKER="ZIGOS:NATIVE:READY"

BASE_LOG_PATH="${LOG_PATH%.log}"
NODE_A_LOG="${BASE_LOG_PATH}.node-a.log"
NODE_B_LOG="${BASE_LOG_PATH}.node-b.log"
NODE_A_QEMU_LOG="${BASE_LOG_PATH}.node-a.qemu.log"
NODE_B_QEMU_LOG="${BASE_LOG_PATH}.node-b.qemu.log"
NODE_A_PID=""
NODE_B_PID=""

cleanup() {
  if [ -n "$NODE_A_PID" ]; then
    qemu_harness_stop_qemu "$NODE_A_PID"
  fi
  if [ -n "$NODE_B_PID" ]; then
    qemu_harness_stop_qemu "$NODE_B_PID"
  fi
}
trap cleanup EXIT

mkdir -p "$(dirname "$LOG_PATH")"
rm -f "$LOG_PATH" "$NODE_A_LOG" "$NODE_B_LOG" "$NODE_A_QEMU_LOG" "$NODE_B_QEMU_LOG"
bash "$ROOT_DIR/scripts/build-native-store.sh" "$NODE_A_STORE" "$NATIVE_STORE_SIZE_MIB" reset
bash "$ROOT_DIR/scripts/build-native-store.sh" "$NODE_B_STORE" "$NATIVE_STORE_SIZE_MIB" reset

build_node_command() {
  local store_image="$1"
  local serial_log="$2"
  local socket_mode="$3"

  qemu_harness_build_kernel_command \
    "$KERNEL_PATH" \
    "$(qemu_harness_native_smoke_memory)" \
    "file:$serial_log" \
    yes \
    no \
    -netdev "socket,id=syncnet,$socket_mode" \
    -device "e1000,netdev=syncnet"
  qemu_harness_append_native_store_drive "$store_image"
}

build_node_command "$NODE_A_STORE" "$NODE_A_LOG" "listen=127.0.0.1:${SYNC_TWO_NODE_PORT}"
NODE_A_COMMAND=("${QEMU_HARNESS_COMMAND[@]}")
"${NODE_A_COMMAND[@]}" >"$NODE_A_QEMU_LOG" 2>&1 &
NODE_A_PID=$!

sleep 1

build_node_command "$NODE_B_STORE" "$NODE_B_LOG" "connect=127.0.0.1:${SYNC_TWO_NODE_PORT}"
NODE_B_COMMAND=("${QEMU_HARNESS_COMMAND[@]}")
"${NODE_B_COMMAND[@]}" >"$NODE_B_QEMU_LOG" 2>&1 &
NODE_B_PID=$!

elapsed=0
while true; do
  node_a_ready=0
  node_b_ready=0
  if [ -s "$NODE_A_LOG" ] && grep -Fq "$READY_MARKER" "$NODE_A_LOG"; then
    node_a_ready=1
  fi
  if [ -s "$NODE_B_LOG" ] && grep -Fq "$READY_MARKER" "$NODE_B_LOG"; then
    node_b_ready=1
  fi
  if [ "$node_a_ready" -eq 1 ] && [ "$node_b_ready" -eq 1 ]; then
    break
  fi
  if [ "$elapsed" -ge "$SYNC_TWO_NODE_SECONDS" ]; then
    echo "Two-node sync QEMU test failed: readiness marker not observed on both nodes" >&2
    break
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done

qemu_harness_stop_qemu "$NODE_A_PID"
qemu_harness_stop_qemu "$NODE_B_PID"
NODE_A_PID=""
NODE_B_PID=""
trap - EXIT

assert_log_healthy() {
  local log_path="$1"
  local label="$2"

  if [ ! -s "$log_path" ]; then
    echo "Two-node sync QEMU test failed: no serial output captured for $label" >&2
    qemu_harness_print_qemu_log "${log_path%.log}.qemu.log"
    exit 1
  fi
  if ! grep -Fq "$READY_MARKER" "$log_path"; then
    echo "Two-node sync QEMU test failed: missing '$READY_MARKER' in $label" >&2
    cat "$log_path" >&2
    exit 1
  fi
  if grep -Eqi "panic|KERNEL PANIC|System Halted|FAIL" "$log_path"; then
    echo "Two-node sync QEMU test failed: panic or failure marker found in $label" >&2
    cat "$log_path" >&2
    exit 1
  fi
}

assert_marker_group() {
  local log_path="$1"
  local label="$2"
  local needle

  while IFS= read -r needle; do
    [ -n "$needle" ] || continue
    if ! grep -Fq "$needle" "$log_path"; then
      echo "Two-node sync QEMU test failed: missing '$needle' in $label" >&2
      cat "$log_path" >&2
      exit 1
    fi
  done < <("$ZIG" run "$MARKER_TOOL" -- sync_two_node)
}

assert_log_healthy "$NODE_A_LOG" "node A"
assert_log_healthy "$NODE_B_LOG" "node B"
assert_marker_group "$NODE_A_LOG" "node A"
assert_marker_group "$NODE_B_LOG" "node B"

{
  printf '=== SYNC TWO NODE: NODE A listen=127.0.0.1:%s ===\n' "$SYNC_TWO_NODE_PORT"
  cat "$NODE_A_LOG"
  printf '\n=== SYNC TWO NODE: NODE B connect=127.0.0.1:%s ===\n' "$SYNC_TWO_NODE_PORT"
  cat "$NODE_B_LOG"
} >"$LOG_PATH"

echo "Zigos two-node sync QEMU test passed. Logs: $LOG_PATH"
