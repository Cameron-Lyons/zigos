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
SYNC_TWO_NODE_DROP_CONFIRMATIONS="${SYNC_TWO_NODE_DROP_CONFIRMATIONS:-2}"
case "$SYNC_TWO_NODE_DROP_CONFIRMATIONS" in 0|2) ;; *) echo 'Confirmation losses must be 0 or 2' >&2; exit 2 ;; esac
READY_MARKER="ZIGOS:NATIVE:READY"

BASE_LOG_PATH="${LOG_PATH%.log}"
NODE_A_LOG="${BASE_LOG_PATH}.node-a.log"
NODE_B_LOG="${BASE_LOG_PATH}.node-b.log"
NODE_A_QEMU_LOG="${BASE_LOG_PATH}.node-a.qemu.log"
NODE_B_QEMU_LOG="${BASE_LOG_PATH}.node-b.qemu.log"
RELAY_LOG="${BASE_LOG_PATH}.relay.log"
NODE_A_PID=""
NODE_B_PID=""
RELAY_PID=""

stop_relay() {
  if [ -n "$RELAY_PID" ]; then
    kill "$RELAY_PID" 2>/dev/null || true
    wait "$RELAY_PID" 2>/dev/null || true
    RELAY_PID=""
  fi
}

cleanup() {
  if [ -n "$NODE_A_PID" ]; then
    qemu_harness_stop_qemu "$NODE_A_PID"
  fi
  if [ -n "$NODE_B_PID" ]; then
    qemu_harness_stop_qemu "$NODE_B_PID"
  fi
  stop_relay
}
trap cleanup EXIT

mkdir -p "$(dirname "$LOG_PATH")"
rm -f "$LOG_PATH" "$NODE_A_LOG" "$NODE_B_LOG" "$NODE_A_QEMU_LOG" "$NODE_B_QEMU_LOG" "$RELAY_LOG"
python3 "$SCRIPT_DIR/qemu_peer_relay_test.py"
bash "$ROOT_DIR/scripts/build-native-store.sh" "$NODE_A_STORE" "$NATIVE_STORE_SIZE_MIB" reset
bash "$ROOT_DIR/scripts/build-native-store.sh" "$NODE_B_STORE" "$NATIVE_STORE_SIZE_MIB" reset

build_node_command() {
  local store_image="$1"
  local serial_log="$2"
  local socket_mode="$3"
  local mac="$4"
  local irqchip_args=()
  if [[ "$(qemu_harness_accelerator)" == kvm* ]]; then
    irqchip_args=(-machine kernel-irqchip=split)
  fi

  qemu_harness_build_kernel_command \
    "$KERNEL_PATH" \
    "$(qemu_harness_native_smoke_memory)" \
    "file:$serial_log" \
    yes \
    no \
    "${irqchip_args[@]}" \
    -netdev "socket,id=syncnet,$socket_mode" \
    -device "intel-iommu,intremap=on,eim=on,aw-bits=48" \
    -device "virtio-net-pci,netdev=syncnet,disable-legacy=on,packed=off,iommu_platform=on,mac=$mac" \
    -object "filter-dump,id=sync_capture,netdev=syncnet,file=${serial_log%.log}.pcap"
  qemu_harness_append_native_store_drive "$store_image"
}

build_node_command "$NODE_A_STORE" "$NODE_A_LOG" "listen=127.0.0.1:${SYNC_TWO_NODE_PORT}" "02:5a:47:00:00:01"
NODE_A_COMMAND=("${QEMU_HARNESS_COMMAND[@]}")
"${NODE_A_COMMAND[@]}" >"$NODE_A_QEMU_LOG" 2>&1 &
NODE_A_PID=$!

# The relay drops two identical final confirmations after the sender's driver
# accepts them. A successful transfer must retain and retransmit the ciphertext
# across handshake promotion; extending a boot timeout cannot satisfy this gate.
python3 "$SCRIPT_DIR/qemu-peer-relay.py" --upstream-port "$SYNC_TWO_NODE_PORT" \
  --drop-confirmations "$SYNC_TWO_NODE_DROP_CONFIRMATIONS" >"$RELAY_LOG" 2>&1 &
RELAY_PID=$!
RELAY_PORT=""
for ((attempt = 0; attempt < 150; attempt++)); do
  if ! kill -0 "$RELAY_PID" 2>/dev/null; then break; fi
  RELAY_PORT="$(sed -n 's/^SYNC_RELAY:READY //p' "$RELAY_LOG")"
  if [[ "$RELAY_PORT" =~ ^[0-9]+$ ]]; then break; fi
  sleep 0.1
done
if [[ ! "$RELAY_PORT" =~ ^[0-9]+$ ]]; then
  cat "$RELAY_LOG" >&2
  echo 'Two-node sync relay did not become ready' >&2
  exit 1
fi

build_node_command "$NODE_B_STORE" "$NODE_B_LOG" "connect=127.0.0.1:${RELAY_PORT}" "02:5a:47:00:00:02"
NODE_B_COMMAND=("${QEMU_HARNESS_COMMAND[@]}")
"${NODE_B_COMMAND[@]}" >"$NODE_B_QEMU_LOG" 2>&1 &
NODE_B_PID=$!

elapsed=0
while true; do
  if ! kill -0 "$NODE_A_PID" 2>/dev/null || ! kill -0 "$NODE_B_PID" 2>/dev/null || ! kill -0 "$RELAY_PID" 2>/dev/null; then
    cat "$RELAY_LOG" >&2
    echo "Two-node sync QEMU test failed: a guest or relay exited before readiness" >&2
    break
  fi
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
stop_relay
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
if [ "$SYNC_TWO_NODE_DROP_CONFIRMATIONS" -eq 2 ]; then
  test "$(grep -c '^SYNC_RELAY:DROPPED_CONFIRMATION ' "$RELAY_LOG" || true)" -eq 2
  grep -Fxq 'SYNC_RELAY:RETRIED_CONFIRMATION' "$RELAY_LOG"
fi
for peer_log in "$NODE_A_LOG" "$NODE_B_LOG"; do
  grep -Fq 'ZIGOS:SYNC:PEER_CHANNEL:ADMITTED' "$peer_log"
  grep -Fq 'ZIGOS:SYNC:PEER_CHANNEL:COMPLETED' "$peer_log"
  grep -Fq 'ZIGOS:SYNC:PEER_CHANNEL:SUSPENDED_RETIRED' "$peer_log"
  grep -Fq 'ZIGOS:SYNC:PEER_CONNECTION:PROMOTED' "$peer_log"
  grep -Fq 'ZIGOS:SYNC:PEER_CONNECTION:OWNER_RETIRED' "$peer_log"
done
grep -Fq 'ZIGOS:SYNC:PEER_OBJECT:ACKNOWLEDGED' "$NODE_A_LOG"
grep -Fq 'ZIGOS:SYNC:PEER_OBJECT:SENDER_ADMITTED' "$NODE_A_LOG"
grep -Fq 'ZIGOS:SYNC:PEER_OBJECT:SENDER_RETIRED' "$NODE_A_LOG"
grep -Fq 'ZIGOS:SYNC:PEER_OBJECT:REOPENED' "$NODE_B_LOG"
grep -Fq 'ZIGOS:SYNC:PEER_OBJECT:ADMITTED' "$NODE_B_LOG"
grep -Fq 'ZIGOS:SYNC:PEER_OBJECT:RETIRED' "$NODE_B_LOG"

{
  printf '=== SYNC TWO NODE: NODE A listen=127.0.0.1:%s ===\n' "$SYNC_TWO_NODE_PORT"
  cat "$NODE_A_LOG"
  printf '\n=== SYNC TWO NODE: NODE B connect=127.0.0.1:%s ===\n' "$RELAY_PORT"
  cat "$NODE_B_LOG"
} >"$LOG_PATH"

echo "Zigos two-node sync QEMU test passed. Logs: $LOG_PATH"
